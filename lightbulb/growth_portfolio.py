"""Portfolio layer: N stores that learn as a fleet, not as strangers.

The Growth Engine's single-scope modules (funnel, experiments, learnings,
demand-gen, cockpit) each operate on one store/project. This module is what
makes a *portfolio* compound:

- :func:`build_portfolio_funnel_rollup` — verify each member store's sealed
  funnel snapshot against that member's own scope, then aggregate a fleet
  view: per-basis totals, per-rate store distributions, laggards and leaders.
- :func:`derive_sibling_reference_rates` — fleet medians become each store's
  benchmark (``portfolio_sibling`` quality, provenance pinned to the rollup
  digest), replacing labeled default heuristics with real peer references.
- :func:`transfer_learning` — a win proven in one store records into a
  sibling's ledger as **observational** grade (never experimental across
  scopes: the experiment did not run there), with provenance back to the
  original sealed entry.
- :func:`diagnose_portfolio` — cluster stores by their verified bottleneck,
  select K representative test stores deterministically (closest to the
  cluster median, so extremes don't distort the readout), and rank the fleet
  moves: one experiment per cluster, transfer, then roll out.

Custody rules match the rest of the engine: members must share the
portfolio's tenant and company but keep their own project scopes; member
snapshots are verified against their *member* scope; portfolio artifacts are
sealed under the *portfolio* scope; raw member scope fields never persist —
only a scope *digest* travels. In the verified path that digest is the host
keyed (HMAC) ``exact_scope_digest``; in the keyless path it is an unkeyed
content hash of the scope (a weaker, guessable fingerprint) — one more reason
the unverified rollup is honestly labeled ``caller_supplied_unverified`` and
cannot mint sibling references (peer benchmarks from unverified data would
poison every store).
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping, Sequence
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
from .growth_funnel import (
    CurrencyCode,
    FunnelReferenceRate,
    GrowthFunnelSnapshot,
    verify_growth_funnel_snapshot,
)
from .growth_learnings import (
    GrowthLearningEntry,
    GrowthLearningsLedger,
    verify_growth_learning_entry,
)

GROWTH_PORTFOLIO_ROLLUP_SCHEMA = "lightbulb.growth_portfolio_rollup.v2"
GROWTH_PORTFOLIO_DIAGNOSIS_SCHEMA = "lightbulb.growth_portfolio_diagnosis.v1"

_ROLLUP_HMAC_DOMAIN = GROWTH_PORTFOLIO_ROLLUP_SCHEMA

_RATE_QUANTUM = Decimal("0.000001")
_MONEY_QUANTUM = Decimal("0.01")
_COUNT_QUANTUM = Decimal("1")

_PORTABLE_REF_PATTERN = r"^[a-z][a-z0-9_-]{0,63}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"

_MAX_PORTFOLIO_MEMBERS = 500
_MIN_SIBLING_MEMBERS = 3
_MAX_TEST_STORES = 10

# The single-scope engine's canonical vocabulary, duplicated per repo
# convention (land-independent modules).
FunnelStage = Literal[
    "audience",
    "traffic",
    "engagement",
    "conversion",
    "revenue",
    "retention",
]
RateName = Literal[
    "reach_to_visit",
    "visit_to_engage",
    "visit_to_purchase",
    "lead_capture",
    "purchase_to_repeat",
]
_RATE_ORDER: tuple[str, ...] = (
    "reach_to_visit",
    "visit_to_engage",
    "visit_to_purchase",
    "lead_capture",
    "purchase_to_repeat",
)
FunnelBasis = Literal[
    "platform_reported",
    "site_measured",
    "commerce_recorded",
    "crm_recorded",
]
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
EvidenceScopeStatus = Literal["caller_supplied_unverified", "host_hmac_verified"]

_LAGGARD_THRESHOLD = Decimal("0.700000")


class GrowthPortfolioValidationError(ValueError):
    """Portfolio inputs violate the fleet custody or honesty contract."""


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


def _median(values: Sequence[Decimal]) -> Decimal:
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2 == 1:
        return ordered[middle]
    return ((ordered[middle - 1] + ordered[middle]) / 2).quantize(
        _RATE_QUANTUM, rounding=ROUND_HALF_UP
    )


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
    except GrowthPortfolioValidationError:
        raise
    except Exception as exc:
        raise GrowthPortfolioValidationError(
            "the portfolio signing key is unavailable"
        ) from exc


def _keyring_scope_digest(
    scope_keyring: ExactScopeDigestProvider,
    *,
    key_id: str,
    scope: DynamicWorkflowScope,
) -> str:
    try:
        return scope_keyring.exact_scope_digest(key_id=key_id, scope=scope)
    except GrowthPortfolioValidationError:
        raise
    except Exception as exc:
        raise GrowthPortfolioValidationError(
            "the portfolio signing key is unavailable"
        ) from exc


def _workflow_scope(
    scope: DynamicWorkflowScope | Mapping[str, Any],
) -> DynamicWorkflowScope:
    if isinstance(scope, DynamicWorkflowScope):
        return scope
    return DynamicWorkflowScope.model_validate(scope)


# ---------------------------------------------------------------------------
# Rollup artifacts
# ---------------------------------------------------------------------------


class PortfolioMemberInput(_StrictModel):
    """One member store: its ref, its own scope, its sealed snapshot."""

    member_ref: PortableRef
    scope: DynamicWorkflowScope
    funnel_snapshot: GrowthFunnelSnapshot


class MemberRateReading(_StrictModel):
    member_ref: PortableRef
    value: Decimal = Field(ge=0, multiple_of=_RATE_QUANTUM)

    @field_validator("value", mode="before")
    @classmethod
    def _rate_decimal(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_RATE_QUANTUM)


class PortfolioRateDistribution(_StrictModel):
    rate_name: RateName
    member_count: int = Field(ge=1)
    fleet_median: Decimal = Field(ge=0, multiple_of=_RATE_QUANTUM)
    best: MemberRateReading
    worst: MemberRateReading
    laggards: tuple[PortableRef, ...] = Field(default_factory=tuple)
    leaders: tuple[PortableRef, ...] = Field(default_factory=tuple)

    @field_validator("fleet_median", mode="before")
    @classmethod
    def _rate_decimal(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_RATE_QUANTUM)

    @field_validator("laggards", "leaders", mode="before")
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)


class PortfolioMetricTotal(_StrictModel):
    metric: MetricName
    basis: FunnelBasis
    unit: Literal["count", "money"]
    value: Decimal = Field(ge=0)
    member_count: int = Field(ge=1)

    @field_validator("value", mode="before")
    @classmethod
    def _value_decimal(cls, value: Any) -> Decimal:
        return _decimal(value)


class PortfolioMemberRecord(_StrictModel):
    member_ref: PortableRef
    member_scope_digest: Sha256Digest
    funnel_digest: Sha256Digest
    analysis_as_of: str
    bottleneck_rate: ShortText | None = None
    unknown_stages: tuple[ShortText, ...] = Field(default_factory=tuple)

    @field_validator("analysis_as_of")
    @classmethod
    def _valid_timestamp(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator("unknown_stages", mode="before")
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)


class PortfolioFunnelRollup(_StrictModel):
    """Sealed fleet view over verified member snapshots."""

    schema_id: Literal["lightbulb.growth_portfolio_rollup.v2"] = Field(
        default=GROWTH_PORTFOLIO_ROLLUP_SCHEMA,
        alias="schema",
    )
    portfolio_ref: PortableRef
    analysis_as_of: str
    currency: CurrencyCode | None = None
    evidence_scope_status: EvidenceScopeStatus
    members: tuple[PortfolioMemberRecord, ...] = Field(
        min_length=1, max_length=_MAX_PORTFOLIO_MEMBERS
    )
    fleet_totals: tuple[PortfolioMetricTotal, ...] = Field(default_factory=tuple)
    rate_distributions: tuple[PortfolioRateDistribution, ...] = Field(
        default_factory=tuple
    )
    rollup_digest: Sha256Digest = "0" * 64
    receipt_key_id: str | None = Field(
        default=None,
        min_length=8,
        max_length=80,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{7,79}$",
    )
    exact_scope_digest: Sha256Digest | None = None
    rollup_hmac: Sha256Digest | None = None

    @field_validator("analysis_as_of")
    @classmethod
    def _valid_timestamp(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator("members", "fleet_totals", "rate_distributions", mode="before")
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _sealed_shape(self) -> "PortfolioFunnelRollup":
        refs = [member.member_ref for member in self.members]
        if len(refs) != len(set(refs)):
            raise ValueError("portfolio member refs must be unique")
        carries_money = any(total.unit == "money" for total in self.fleet_totals)
        if carries_money and self.currency is None:
            raise ValueError("monetary portfolio rollups require currency")
        if not carries_money and self.currency is not None:
            raise ValueError("count-only portfolio rollups must not carry currency")
        rate_names = [item.rate_name for item in self.rate_distributions]
        if len(rate_names) != len(set(rate_names)):
            raise ValueError("rate distributions must be unique per rate")
        binding_fields = (
            self.receipt_key_id,
            self.exact_scope_digest,
            self.rollup_hmac,
        )
        if any(value is not None for value in binding_fields) and not all(
            value is not None for value in binding_fields
        ):
            raise ValueError(
                "portfolio rollup attestation fields must be supplied together"
            )
        if self.evidence_scope_status == "host_hmac_verified" and (
            self.rollup_hmac is None
        ):
            raise ValueError(
                "verified portfolio rollups require a complete host attestation"
            )
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"rollup_digest", "rollup_hmac"},
            exclude_none=True,
        )
        expected = _stable_digest(payload)
        if self.rollup_digest != "0" * 64 and self.rollup_digest != expected:
            raise ValueError("rollup_digest does not match the canonical payload")
        object.__setattr__(self, "rollup_digest", expected)
        return self

    def hmac_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"rollup_hmac", "rollup_digest"},
            exclude_none=True,
        )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def build_portfolio_funnel_rollup(
    portfolio_ref: str,
    members: Sequence[PortfolioMemberInput | Mapping[str, Any]],
    *,
    analysis_as_of: str,
    portfolio_scope: DynamicWorkflowScope | Mapping[str, Any] | None = None,
    scope_keyring: ExactScopeDigestProvider | None = None,
    scope_key_id: str | None = None,
) -> PortfolioFunnelRollup:
    """Aggregate verified member snapshots into one sealed fleet view.

    Every member snapshot is verified against its OWN member scope; members
    must share the portfolio's tenant and company. Without a keyring the
    rollup is labeled ``caller_supplied_unverified`` and cannot mint sibling
    references.
    """

    parsed_members = [
        member
        if isinstance(member, PortfolioMemberInput)
        else PortfolioMemberInput.model_validate(member)
        for member in members
    ]
    if not 1 <= len(parsed_members) <= _MAX_PORTFOLIO_MEMBERS:
        raise GrowthPortfolioValidationError(
            f"portfolios support 1 to {_MAX_PORTFOLIO_MEMBERS} members"
        )
    if (portfolio_scope is None) != (scope_keyring is None):
        raise GrowthPortfolioValidationError(
            "verified rollups require both portfolio_scope and scope_keyring"
        )
    workflow_scope = (
        _workflow_scope(portfolio_scope) if portfolio_scope is not None else None
    )
    analysis_at = _parse_timestamp(analysis_as_of)

    refs = [member.member_ref for member in parsed_members]
    if len(refs) != len(set(refs)):
        raise GrowthPortfolioValidationError("portfolio member refs must be unique")
    scopes = [
        (member.scope.tenant_id, member.scope.company_id, member.scope.project_ref)
        for member in parsed_members
    ]
    if len(scopes) != len(set(scopes)):
        raise GrowthPortfolioValidationError(
            "portfolio members must have distinct project scopes"
        )

    records: list[PortfolioMemberRecord] = []
    totals: dict[tuple[str, str], Decimal] = {}
    total_members: dict[tuple[str, str], set[str]] = {}
    rate_readings: dict[str, list[tuple[str, Decimal]]] = {}
    currencies: set[str] = set()
    all_verified = scope_keyring is not None

    for member in sorted(parsed_members, key=lambda item: item.member_ref):
        if workflow_scope is not None and (
            member.scope.tenant_id != workflow_scope.tenant_id
            or member.scope.company_id != workflow_scope.company_id
        ):
            raise GrowthPortfolioValidationError(
                "portfolio members must share the portfolio tenant and company"
            )
        snapshot = member.funnel_snapshot
        if scope_keyring is not None:
            snapshot = verify_growth_funnel_snapshot(
                snapshot, scope=member.scope, scope_keyring=scope_keyring
            )
            if snapshot.evidence_scope_status != "host_hmac_verified":
                all_verified = False
        if _parse_timestamp(snapshot.analysis_as_of) > analysis_at:
            raise GrowthPortfolioValidationError(
                "a member snapshot is from the future of the rollup analysis"
            )
        member_scope_digest = (
            _keyring_scope_digest(
                scope_keyring,
                key_id=scope_key_id or str(scope_keyring.active_key_id).strip(),
                scope=member.scope,
            )
            if scope_keyring is not None
            else _stable_digest(
                {
                    "tenant_id": member.scope.tenant_id,
                    "company_id": member.scope.company_id,
                    "user_id": member.scope.user_id,
                    "project_ref": member.scope.project_ref,
                }
            )
        )
        if snapshot.currency is not None:
            currencies.add(snapshot.currency)
            if len(currencies) > 1:
                raise GrowthPortfolioValidationError(
                    "member snapshots carry multiple revenue currencies; "
                    "portfolio money totals require one governed currency"
                )
        records.append(
            PortfolioMemberRecord(
                member_ref=member.member_ref,
                member_scope_digest=member_scope_digest,
                funnel_digest=snapshot.funnel_digest,
                analysis_as_of=snapshot.analysis_as_of,
                bottleneck_rate=(
                    snapshot.bottleneck.rate_name
                    if snapshot.bottleneck is not None
                    else None
                ),
                unknown_stages=tuple(
                    aggregate.stage
                    for aggregate in snapshot.stages
                    if aggregate.completeness == "unknown"
                ),
            )
        )
        for aggregate in snapshot.stages:
            for total in aggregate.totals:
                key = (total.metric, total.basis)
                totals[key] = totals.get(key, Decimal("0")) + total.value
                total_members.setdefault(key, set()).add(member.member_ref)
        for rate in snapshot.rates:
            if rate.anomalous:
                continue
            rate_readings.setdefault(rate.rate_name, []).append(
                (member.member_ref, rate.value)
            )

    fleet_totals = tuple(
        PortfolioMetricTotal(
            metric=metric,
            basis=basis,
            unit="money" if metric == "revenue" else "count",
            value=(
                value.quantize(_MONEY_QUANTUM)
                if metric == "revenue"
                else value.quantize(_COUNT_QUANTUM)
            ),
            member_count=len(total_members[(metric, basis)]),
        )
        for (metric, basis), value in sorted(totals.items())
    )

    distributions: list[PortfolioRateDistribution] = []
    for rate_name in _RATE_ORDER:
        readings = rate_readings.get(rate_name)
        if not readings:
            continue
        readings.sort(key=lambda item: (item[1], item[0]))
        values = [value for _, value in readings]
        median = _median(values).quantize(_RATE_QUANTUM, rounding=ROUND_HALF_UP)
        laggards = tuple(
            member_ref
            for member_ref, value in readings
            if median > 0 and value < median * _LAGGARD_THRESHOLD
        )
        leaders = tuple(
            member_ref
            for member_ref, value in readings
            if median > 0 and value * _LAGGARD_THRESHOLD > median
        )
        distributions.append(
            PortfolioRateDistribution(
                rate_name=rate_name,
                member_count=len(readings),
                fleet_median=median,
                best=MemberRateReading(
                    member_ref=readings[-1][0], value=readings[-1][1]
                ),
                worst=MemberRateReading(
                    member_ref=readings[0][0], value=readings[0][1]
                ),
                laggards=laggards,
                leaders=leaders,
            )
        )

    status: EvidenceScopeStatus = (
        "host_hmac_verified"
        if scope_keyring is not None and all_verified
        else "caller_supplied_unverified"
    )
    rollup_kwargs: dict[str, Any] = {
        "portfolio_ref": portfolio_ref,
        "analysis_as_of": _normalized_timestamp(analysis_as_of),
        "currency": next(iter(currencies), None),
        "evidence_scope_status": status,
        "members": tuple(records),
        "fleet_totals": fleet_totals,
        "rate_distributions": tuple(distributions),
    }
    if scope_keyring is None or workflow_scope is None:
        return PortfolioFunnelRollup(**rollup_kwargs)
    key_id = scope_key_id or str(scope_keyring.active_key_id).strip()
    exact_scope_digest = _keyring_scope_digest(
        scope_keyring, key_id=key_id, scope=workflow_scope
    )
    draft = PortfolioFunnelRollup(
        **rollup_kwargs,
        receipt_key_id=key_id,
        exact_scope_digest=exact_scope_digest,
        rollup_hmac="0" * 64,
    )
    signature = _keyring_signature(
        scope_keyring,
        key_id=key_id,
        domain=_ROLLUP_HMAC_DOMAIN,
        payload=draft.hmac_payload(),
    )
    sealed = draft.model_dump(
        mode="python",
        by_alias=True,
        exclude={"rollup_digest"},
        exclude_none=True,
    )
    sealed["rollup_hmac"] = signature
    return PortfolioFunnelRollup.model_validate(sealed)


def verify_portfolio_funnel_rollup(
    value: PortfolioFunnelRollup | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ExactScopeDigestProvider,
) -> PortfolioFunnelRollup:
    rollup = PortfolioFunnelRollup.model_validate(
        value.model_dump(mode="python", by_alias=True, exclude_none=True)
        if isinstance(value, PortfolioFunnelRollup)
        else value
    )
    if (
        rollup.receipt_key_id is None
        or rollup.exact_scope_digest is None
        or rollup.rollup_hmac is None
    ):
        raise GrowthPortfolioValidationError(
            "the portfolio rollup carries no host attestation"
        )
    workflow_scope = _workflow_scope(scope)
    expected_scope_digest = _keyring_scope_digest(
        scope_keyring,
        key_id=rollup.receipt_key_id,
        scope=workflow_scope,
    )
    if not hmac.compare_digest(rollup.exact_scope_digest, expected_scope_digest):
        raise GrowthPortfolioValidationError(
            "portfolio rollup attestation failed verification"
        )
    expected_hmac = _keyring_signature(
        scope_keyring,
        key_id=rollup.receipt_key_id,
        domain=_ROLLUP_HMAC_DOMAIN,
        payload=rollup.hmac_payload(),
    )
    if not hmac.compare_digest(rollup.rollup_hmac, expected_hmac):
        raise GrowthPortfolioValidationError(
            "portfolio rollup attestation failed verification"
        )
    return rollup


# ---------------------------------------------------------------------------
# Sibling references
# ---------------------------------------------------------------------------


def derive_sibling_reference_rates(
    rollup: PortfolioFunnelRollup | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ExactScopeDigestProvider,
    min_members: int = _MIN_SIBLING_MEMBERS,
) -> tuple[FunnelReferenceRate, ...]:
    """Turn fleet medians into per-store benchmark references.

    Requires a VERIFIED rollup: sibling references feed every store's
    bottleneck detection, so unverified fleet data would poison the whole
    portfolio. Rates observed by fewer than ``min_members`` stores yield no
    reference (a median of two stores is an anecdote, not a benchmark).
    """

    if min_members < _MIN_SIBLING_MEMBERS:
        raise GrowthPortfolioValidationError(
            f"sibling references require at least {_MIN_SIBLING_MEMBERS} members"
        )
    verified = verify_portfolio_funnel_rollup(
        rollup, scope=scope, scope_keyring=scope_keyring
    )
    if verified.evidence_scope_status != "host_hmac_verified":
        raise GrowthPortfolioValidationError(
            "sibling references require a fully verified rollup"
        )
    references: list[FunnelReferenceRate] = []
    for distribution in verified.rate_distributions:
        if distribution.member_count < min_members:
            continue
        if not 0 < distribution.fleet_median <= 1:
            continue
        references.append(
            FunnelReferenceRate(
                rate_name=distribution.rate_name,
                value=distribution.fleet_median,
                quality="portfolio_sibling",
                source_digest=verified.rollup_digest,
            )
        )
    return tuple(references)


# ---------------------------------------------------------------------------
# Learning transfer
# ---------------------------------------------------------------------------


def transfer_learning(
    entry: GrowthLearningEntry | Mapping[str, Any],
    *,
    from_scope: DynamicWorkflowScope | Mapping[str, Any],
    to_ledger: GrowthLearningsLedger,
    scope_keyring: ExactScopeDigestProvider,
    entry_ref: str,
    recorded_at: str,
    valid_until: str | None = None,
) -> GrowthLearningEntry:
    """Record a sibling store's verified learning into another store's ledger.

    Cross-scope transfers are ALWAYS observational: the experiment ran in the
    sibling's scope, not here. The transferred entry cites the original sealed
    entry digest as its evidence and prefixes the claim with its origin, so a
    later local experiment can supersede it with local causal proof.

    Transfer is a SIBLING move: origin and destination must share a tenant and
    company (only the project scope differs). Verifying the entry against
    ``from_scope`` authenticates its true origin (the seal binds the exact
    scope), and this gate then refuses any transfer that would carry one
    tenant's or company's learning into another's ledger — the engine's only
    cross-scope write path.
    """

    verified = verify_growth_learning_entry(
        entry, scope=from_scope, scope_keyring=scope_keyring
    )
    origin_scope = _workflow_scope(from_scope)
    destination_scope = to_ledger.scope
    if (
        origin_scope.tenant_id != destination_scope.tenant_id
        or origin_scope.company_id != destination_scope.company_id
    ):
        raise GrowthPortfolioValidationError(
            "learning transfer is a sibling move within one tenant and "
            "company; the origin and destination scopes differ in tenant or "
            "company"
        )
    if verified.grade == "heuristic":
        raise GrowthPortfolioValidationError(
            "heuristics are assumptions, not transferable evidence; state a "
            "local heuristic instead"
        )
    claim = f"Transferred from a sibling scope ({verified.grade}): " + (verified.claim)
    if len(claim) > 10_000:
        claim = claim[:9_997] + "..."
    return to_ledger.record_observational_learning(
        entry_ref=entry_ref,
        lever=verified.lever,
        metric_name=verified.metric_name,
        claim=claim,
        recorded_at=recorded_at,
        evidence_digests=(verified.entry_digest,),
        effect_estimate=verified.effect_estimate,
        audience=verified.audience,
        valid_until=valid_until,
    )


# ---------------------------------------------------------------------------
# Portfolio diagnosis
# ---------------------------------------------------------------------------


class BottleneckCluster(_StrictModel):
    rate_name: RateName
    member_refs: tuple[PortableRef, ...] = Field(min_length=1)
    fleet_median: Decimal | None = None
    test_stores: tuple[PortableRef, ...] = Field(min_length=1)

    @field_validator("fleet_median", mode="before")
    @classmethod
    def _rate_decimal(cls, value: Any) -> Decimal | None:
        if value is None:
            return None
        return _decimal(value, quantum=_RATE_QUANTUM)

    @field_validator("member_refs", "test_stores", mode="before")
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)


class PortfolioMove(_StrictModel):
    rank: int = Field(ge=1, le=100)
    kind: Literal[
        "cluster_experiment",
        "laggard_transfer",
        "collect_evidence",
    ]
    title: ShortText
    mechanism: ShortText
    member_refs: tuple[PortableRef, ...] = Field(min_length=1)
    next_action: ShortText
    argument_hints: dict[str, str] = Field(default_factory=dict)

    @field_validator("member_refs", mode="before")
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @field_validator("argument_hints", mode="before")
    @classmethod
    def _string_hints(cls, value: Any) -> Any:
        if isinstance(value, Mapping):
            return {str(key): str(item) for key, item in value.items()}
        return value


class PortfolioDiagnosis(_StrictModel):
    """Deterministic fleet moves: one experiment per cluster, then transfer."""

    schema_id: Literal["lightbulb.growth_portfolio_diagnosis.v1"] = Field(
        default=GROWTH_PORTFOLIO_DIAGNOSIS_SCHEMA,
        alias="schema",
    )
    portfolio_ref: PortableRef
    as_of: str
    rollup_digest: Sha256Digest
    evidence_scope_status: EvidenceScopeStatus
    member_count: int = Field(ge=1)
    clusters: tuple[BottleneckCluster, ...] = Field(default_factory=tuple)
    moves: tuple[PortfolioMove, ...] = Field(default_factory=tuple)
    diagnosis_digest: Sha256Digest = "0" * 64

    @field_validator("as_of")
    @classmethod
    def _valid_timestamp(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator("clusters", "moves", mode="before")
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _pinned_digest(self) -> "PortfolioDiagnosis":
        ranks = [move.rank for move in self.moves]
        if ranks != sorted(ranks) or len(ranks) != len(set(ranks)):
            raise ValueError("portfolio moves must carry unique ascending ranks")
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"diagnosis_digest"},
            exclude_none=True,
        )
        expected = _stable_digest(payload)
        if self.diagnosis_digest != "0" * 64 and self.diagnosis_digest != expected:
            raise ValueError("diagnosis_digest does not match the canonical payload")
        object.__setattr__(self, "diagnosis_digest", expected)
        return self

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def _select_test_stores(
    readings: Sequence[tuple[str, Decimal]],
    median: Decimal | None,
    *,
    max_stores: int,
) -> tuple[str, ...]:
    """Pick representative stores: closest to the cluster median.

    Extreme stores would distort a readout meant to transfer to the whole
    cluster. Ties break on member_ref for determinism.
    """

    if median is None:
        ordered = sorted(ref for ref, _ in readings)
        return tuple(ordered[:max_stores])
    ordered = sorted(
        readings,
        key=lambda item: (abs(item[1] - median), item[0]),
    )
    return tuple(ref for ref, _ in ordered[:max_stores])


def diagnose_portfolio(
    rollup: PortfolioFunnelRollup | Mapping[str, Any],
    member_snapshots: Sequence[PortfolioMemberInput | Mapping[str, Any]],
    *,
    as_of: str,
    max_test_stores: int = 3,
) -> PortfolioDiagnosis:
    """Rank the fleet moves from a rollup plus its member snapshots.

    Pure computation over already-built artifacts (verify them upstream);
    the diagnosis echoes the rollup's trust label and never upgrades it.
    """

    if not 1 <= max_test_stores <= _MAX_TEST_STORES:
        raise GrowthPortfolioValidationError(
            f"max_test_stores must be between 1 and {_MAX_TEST_STORES}"
        )
    parsed_rollup = (
        rollup
        if isinstance(rollup, PortfolioFunnelRollup)
        else PortfolioFunnelRollup.model_validate(rollup)
    )
    parsed_members = [
        member
        if isinstance(member, PortfolioMemberInput)
        else PortfolioMemberInput.model_validate(member)
        for member in member_snapshots
    ]
    as_of_at = _parse_timestamp(as_of)
    if _parse_timestamp(parsed_rollup.analysis_as_of) > as_of_at:
        raise GrowthPortfolioValidationError(
            "the rollup is from the future of the diagnosis as_of"
        )
    by_ref = {member.member_ref: member for member in parsed_members}
    rollup_refs = {record.member_ref for record in parsed_rollup.members}
    if set(by_ref) != rollup_refs:
        raise GrowthPortfolioValidationError(
            "member snapshots must cover exactly the rollup members"
        )
    for record in parsed_rollup.members:
        if by_ref[record.member_ref].funnel_snapshot.funnel_digest != (
            record.funnel_digest
        ):
            raise GrowthPortfolioValidationError(
                "a member snapshot does not match the rollup's funnel digest"
            )

    distributions = {item.rate_name: item for item in parsed_rollup.rate_distributions}

    # Cluster members by their own verified bottleneck.
    cluster_members: dict[str, list[str]] = {}
    for record in parsed_rollup.members:
        if record.bottleneck_rate is not None:
            cluster_members.setdefault(record.bottleneck_rate, []).append(
                record.member_ref
            )
    clusters: list[BottleneckCluster] = []
    for rate_name in _RATE_ORDER:
        members_in_cluster = sorted(cluster_members.get(rate_name, []))
        if not members_in_cluster:
            continue
        distribution = distributions.get(rate_name)
        readings: list[tuple[str, Decimal]] = []
        for member_ref in members_in_cluster:
            snapshot = by_ref[member_ref].funnel_snapshot
            for rate in snapshot.rates:
                if rate.rate_name == rate_name and not rate.anomalous:
                    readings.append((member_ref, rate.value))
        cluster_median = _median([value for _, value in readings]) if readings else None
        clusters.append(
            BottleneckCluster(
                rate_name=rate_name,
                member_refs=tuple(members_in_cluster),
                fleet_median=(distribution.fleet_median if distribution else None),
                test_stores=_select_test_stores(
                    readings or [(ref, Decimal("0")) for ref in members_in_cluster],
                    cluster_median,
                    max_stores=max_test_stores,
                ),
            )
        )

    moves: list[PortfolioMove] = []
    rank = 1
    for cluster in sorted(
        clusters, key=lambda item: (-len(item.member_refs), item.rate_name)
    ):
        moves.append(
            PortfolioMove(
                rank=rank,
                kind="cluster_experiment",
                title=(
                    f"One experiment on {cluster.rate_name} for "
                    f"{len(cluster.member_refs)} stores"
                ),
                mechanism=(
                    f"{len(cluster.member_refs)} stores share the "
                    f"{cluster.rate_name} bottleneck; run one preregistered "
                    "experiment on the representative test stores, then "
                    "transfer the learning to the rest"
                ),
                member_refs=cluster.member_refs,
                next_action="design_growth_experiment + transfer_learning",
                argument_hints={
                    "metric_name": cluster.rate_name,
                    "test_stores": ", ".join(cluster.test_stores),
                    "assignment_unit": "store or visitor within test stores",
                },
            )
        )
        rank += 1
    for distribution in parsed_rollup.rate_distributions:
        if not distribution.laggards or not distribution.leaders:
            continue
        moves.append(
            PortfolioMove(
                rank=rank,
                kind="laggard_transfer",
                title=(
                    f"Close the {distribution.rate_name} gap for "
                    f"{len(distribution.laggards)} laggards"
                ),
                mechanism=(
                    f"laggards run below {_LAGGARD_THRESHOLD} of the fleet "
                    f"median {distribution.fleet_median}; leaders exist, so "
                    "query their ledgers and transfer applicable learnings"
                ),
                member_refs=distribution.laggards,
                next_action="GrowthLearningsLedger.query + transfer_learning",
                argument_hints={
                    "metric_name": distribution.rate_name,
                    "leaders": ", ".join(distribution.leaders),
                },
            )
        )
        rank += 1
    evidence_gap_members = tuple(
        sorted(
            record.member_ref
            for record in parsed_rollup.members
            if record.unknown_stages
        )
    )
    if evidence_gap_members:
        moves.append(
            PortfolioMove(
                rank=rank,
                kind="collect_evidence",
                title=(f"Fill evidence gaps in {len(evidence_gap_members)} stores"),
                mechanism=(
                    "stores with unknown funnel stages cannot join fleet "
                    "benchmarks for those stages; measure them first"
                ),
                member_refs=evidence_gap_members,
                next_action="growth.build_funnel_snapshot per store",
                argument_hints={},
            )
        )

    return PortfolioDiagnosis(
        portfolio_ref=parsed_rollup.portfolio_ref,
        as_of=_normalized_timestamp(as_of),
        rollup_digest=parsed_rollup.rollup_digest,
        evidence_scope_status=parsed_rollup.evidence_scope_status,
        member_count=len(parsed_rollup.members),
        clusters=tuple(clusters),
        moves=tuple(moves),
    )


__all__ = [
    "GROWTH_PORTFOLIO_DIAGNOSIS_SCHEMA",
    "GROWTH_PORTFOLIO_ROLLUP_SCHEMA",
    "BottleneckCluster",
    "GrowthPortfolioValidationError",
    "MemberRateReading",
    "PortfolioDiagnosis",
    "PortfolioFunnelRollup",
    "PortfolioMemberInput",
    "PortfolioMemberRecord",
    "PortfolioMetricTotal",
    "PortfolioMove",
    "PortfolioRateDistribution",
    "build_portfolio_funnel_rollup",
    "derive_sibling_reference_rates",
    "diagnose_portfolio",
    "transfer_learning",
    "verify_portfolio_funnel_rollup",
]
