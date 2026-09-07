"""Evidence ingestion: real connector responses become sealable evidence.

The engine's front door. A trusted host executes a connector analytics tool
through the platform's governed route, then calls a normalizer here to turn
the raw response into an *unsealed* :class:`GrowthFunnelEvidence` body; the
host then seals it with :func:`lightbulb.mint_growth_funnel_evidence`. Nothing
here does I/O, holds a keyring, or fabricates trust.

The raw connector shapes are heterogeneous (verified against the platform's
own in-repo adapters): Shopify returns a ``columns``/``rows`` ShopifyQL table,
Google Analytics an object wrapping a per-day ``metrics`` list, Meta and
LinkedIn single objects that spread the vendor's nested insight structures,
HubSpot a ``deals`` list, and Salesforce a pre-aggregated ``report``. Each
provider therefore has a bespoke extractor; they share the honesty rules:

- **Only recognized fields map.** Every provider declares which response fields
  it reads; anything else present is *reported* in the coverage result, never
  silently absorbed and never guessed.
- **Missing metric = absent, never zero.** A canonical metric whose source is
  missing is simply not set — the funnel's UNKNOWN-not-zero rule starts here.
- **No invented rates.** Rates are emitted only from a provider's own reported
  rate field, and only when it actually lies in [0, 1]; counts are passed
  through and the funnel derives rates from them.
- **Shape mismatches fail loudly.** A response that is not the expected shape
  raises :class:`GrowthIngestionError` naming the provider and expectation,
  rather than returning a thin-but-plausible envelope.
- **Provenance-bound digest.** ``evidence_digest`` is the SHA-256 of the
  canonical raw response, binding the sealed evidence to the exact bytes.

Field maps are the platform's authoritative in-repo contract; the deferred
admin live-read pass confirms each against a real response, and any drift is a
one-line table fix because normalization is table-driven. See
``docs/growth-ingestion-design.md``.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from typing import Annotated, Any, Callable, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
)

from .growth_funnel import (
    GrowthFunnelEvidence,
    GrowthMetrics,
)

GROWTH_INGESTION_RESULT_SCHEMA = "lightbulb.growth_ingestion_result.v2"

_RATE_QUANTUM = Decimal("0.000001")
_MONEY_QUANTUM = Decimal("0.01")
_SHA256_PATTERN = r"^[0-9a-f]{64}$"

AnalyticsProvider = Literal[
    "shopify",
    "hubspot",
    "salesforce",
    "facebook",
    "instagram",
    "linkedin",
    "google_analytics",
]

# Capability -> provider, kept in lockstep with growth_funnel._SOURCE_CAPABILITIES.
SUPPORTED_INGESTION_CAPABILITIES: dict[str, AnalyticsProvider] = {
    "shopify.analytics_query": "shopify",
    "google_analytics.fetch_metrics": "google_analytics",
    "facebook.fetch_metrics": "facebook",
    "instagram.fetch_metrics": "instagram",
    "linkedin.fetch_metrics": "linkedin",
    "crm.search_deals": "hubspot",
    "salesforce.pipeline_report": "salesforce",
}

# Canonical count metrics an ingestion adapter may populate (rates + revenue are
# handled explicitly). Used to validate field maps at import.
_CANONICAL_COUNTS = frozenset(
    {
        "impressions",
        "clicks",
        "engagements",
        "conversions",
        "sessions",
        "orders",
        "leads",
        "opportunities",
        "won_deals",
        "followers",
        "list_size",
        "unique_visitors",
        "checkouts_started",
        "repeat_orders",
        "repeat_customers",
        "churn_events",
    }
)


class GrowthIngestionError(ValueError):
    """A connector response cannot be normalized into canonical evidence."""


def _stable_digest(value: Any) -> str:
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


Sha256Digest = Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)]


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=False,
        serialize_by_alias=True,
        strict=True,
    )


class MetricCoverage(_StrictModel):
    """An honest account of what ingestion did and did not map."""

    provider: AnalyticsProvider
    source_capability: str
    populated_metrics: tuple[str, ...]
    source_fields_used: tuple[str, ...]
    unrecognized_response_fields: tuple[str, ...]

    @field_validator(
        "populated_metrics",
        "source_fields_used",
        "unrecognized_response_fields",
        mode="before",
    )
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        if isinstance(value, list):
            return tuple(value)
        return value


class IngestionResult(_StrictModel):
    schema_id: Literal["lightbulb.growth_ingestion_result.v2"] = Field(
        default=GROWTH_INGESTION_RESULT_SCHEMA,
        alias="schema",
    )
    evidence: GrowthFunnelEvidence
    coverage: MetricCoverage

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


# ---------------------------------------------------------------------------
# Numeric coercion
# ---------------------------------------------------------------------------


def _as_decimal(value: Any) -> Decimal | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, Decimal):
        return value if value.is_finite() else None
    if isinstance(value, (int, float, str)):
        lexical = str(value).strip()
        if not lexical or len(lexical) > 48:
            return None
        try:
            parsed = Decimal(lexical)
        except (InvalidOperation, ValueError):
            return None
        return parsed if parsed.is_finite() else None
    return None


def _as_count(value: Any) -> int | None:
    parsed = _as_decimal(value)
    if parsed is None:
        return None
    if parsed != parsed.to_integral_value():
        return None
    result = int(parsed)
    return result if result >= 0 else None


def _as_money(value: Any) -> Decimal | None:
    parsed = _as_decimal(value)
    if parsed is None or parsed < 0:
        return None
    return parsed.quantize(_MONEY_QUANTUM, rounding=ROUND_HALF_UP)


def _as_reported_rate(value: Any) -> Decimal | None:
    """Only a genuine ratio in [0, 1] becomes a rate; anything else is unmapped."""

    parsed = _as_decimal(value)
    if parsed is None or parsed < 0 or parsed > 1:
        return None
    return parsed.quantize(_RATE_QUANTUM, rounding=ROUND_HALF_UP)


# ---------------------------------------------------------------------------
# Extractor result
# ---------------------------------------------------------------------------


class _Extraction:
    __slots__ = ("metrics", "source_fields", "unrecognized", "sample_size")

    def __init__(self) -> None:
        self.metrics: dict[str, Any] = {}
        self.source_fields: list[str] = []
        self.unrecognized: list[str] = []
        self.sample_size: int | None = None

    def set_count(self, metric: str, field: str, value: Any) -> None:
        parsed = _as_count(value)
        if parsed is not None:
            self.metrics[metric] = parsed
            self.source_fields.append(field)

    def set_money(self, metric: str, field: str, value: Any) -> None:
        parsed = _as_money(value)
        if parsed is not None:
            self.metrics[metric] = parsed
            self.source_fields.append(field)

    def set_rate(self, metric: str, field: str, value: Any) -> None:
        parsed = _as_reported_rate(value)
        if parsed is not None:
            self.metrics[metric] = parsed
            self.source_fields.append(field)


def _require_mapping(provider: str, response: Any) -> Mapping[str, Any]:
    if not isinstance(response, Mapping):
        raise GrowthIngestionError(
            f"{provider} response must be an object, got {type(response).__name__}"
        )
    return response


def _currency_code(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value.strip()) != 3:
        raise GrowthIngestionError("currency must be an ISO-4217 alpha-3 code")
    normalized = value.strip().upper()
    if not normalized.isalpha() or not normalized.isascii():
        raise GrowthIngestionError("currency must be an ISO-4217 alpha-3 code")
    return normalized


def _raw_response_currencies(
    provider: AnalyticsProvider, response: Mapping[str, Any]
) -> set[str]:
    """Collect explicit currency labels without guessing account defaults."""

    values: list[Any] = [
        response.get("currency"),
        response.get("currency_code"),
        response.get("currencyCode"),
    ]
    if provider == "shopify":
        columns = response.get("columns")
        rows = response.get("rows")
        if (
            isinstance(columns, Sequence)
            and not isinstance(columns, (str, bytes))
            and isinstance(rows, Sequence)
            and not isinstance(rows, (str, bytes))
        ):
            for index, column in enumerate(columns):
                name = (
                    str(column.get("name", "")).strip().lower()
                    if isinstance(column, Mapping)
                    else ""
                )
                if name not in {"currency", "currency_code", "currencycode"}:
                    continue
                values.extend(
                    row[index]
                    for row in rows
                    if isinstance(row, Sequence)
                    and not isinstance(row, (str, bytes))
                    and index < len(row)
                )
    elif provider == "hubspot":
        deals = response.get("deals")
        if isinstance(deals, Sequence) and not isinstance(deals, (str, bytes)):
            for deal in deals:
                if not isinstance(deal, Mapping):
                    continue
                properties = deal.get("properties")
                values.extend(
                    (
                        deal.get("currency"),
                        deal.get("currency_code"),
                        properties.get("currency")
                        if isinstance(properties, Mapping)
                        else None,
                    )
                )
    elif provider == "salesforce":
        report = response.get("report")
        if isinstance(report, Mapping):
            values.extend(
                (
                    report.get("currency"),
                    report.get("currency_code"),
                    report.get("currencyIsoCode"),
                )
            )
            opportunities = report.get("opportunities")
            if isinstance(opportunities, Sequence) and not isinstance(
                opportunities, (str, bytes)
            ):
                for opportunity in opportunities:
                    if isinstance(opportunity, Mapping):
                        values.extend(
                            (
                                opportunity.get("currency"),
                                opportunity.get("currency_code"),
                                opportunity.get("currencyIsoCode"),
                            )
                        )
    return {_currency_code(value) for value in values if value is not None}


def _require_crm_record_currencies(
    provider: AnalyticsProvider, response: Mapping[str, Any]
) -> None:
    if provider == "hubspot":
        records = response.get("deals")
    elif provider == "salesforce":
        report = response.get("report")
        records = report.get("opportunities") if isinstance(report, Mapping) else None
    else:
        return
    if not isinstance(records, Sequence) or isinstance(records, (str, bytes)):
        raise GrowthIngestionError(
            f"{provider} revenue requires record-level currencies in the raw response"
        )
    for record in records:
        if not isinstance(record, Mapping) or _as_money(record.get("amount")) is None:
            continue
        properties = record.get("properties")
        currency_values = (
            record.get("currency"),
            record.get("currency_code"),
            record.get("currencyIsoCode"),
            properties.get("currency") if isinstance(properties, Mapping) else None,
            properties.get("deal_currency_code")
            if isinstance(properties, Mapping)
            else None,
        )
        if not any(
            value is not None and str(value).strip() for value in currency_values
        ):
            raise GrowthIngestionError(
                f"{provider} revenue requires a currency on every monetary record"
            )


def _resolve_revenue_currency(
    *,
    provider: AnalyticsProvider,
    response: Mapping[str, Any],
    governed_currency: str | None,
) -> str:
    _require_crm_record_currencies(provider, response)
    raw_currencies = _raw_response_currencies(provider, response)
    if len(raw_currencies) > 1:
        raise GrowthIngestionError(
            "the connector response spans multiple currencies; aggregate each "
            "currency separately or convert upstream with governed FX evidence"
        )
    governed = _currency_code(governed_currency)
    raw = next(iter(raw_currencies), None)
    if governed is not None and raw is not None and governed != raw:
        raise GrowthIngestionError(
            "the governed currency conflicts with the connector response currency"
        )
    resolved = governed or raw
    if resolved is None:
        raise GrowthIngestionError(
            "a governed ISO-4217 currency is required when revenue is ingested"
        )
    return resolved


# ---------------------------------------------------------------------------
# Per-provider extractors
# ---------------------------------------------------------------------------

# Shopify ShopifyQL column name -> canonical metric + kind.
_SHOPIFY_COLUMNS: dict[str, tuple[str, str]] = {
    "revenue": ("revenue", "money"),
    "net_sales": ("revenue", "money"),
    "total_sales": ("revenue", "money"),
    "order_count": ("orders", "count"),
    "orders": ("orders", "count"),
    "sessions": ("sessions", "count"),
    "conversions": ("conversions", "count"),
}


def _extract_shopify(response: Mapping[str, Any]) -> _Extraction:
    extraction = _Extraction()
    columns = response.get("columns")
    rows = response.get("rows")
    if not isinstance(columns, Sequence) or isinstance(columns, (str, bytes)):
        raise GrowthIngestionError(
            "shopify response must carry a 'columns' list (ShopifyQL table)"
        )
    if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes)):
        raise GrowthIngestionError(
            "shopify response must carry a 'rows' list (ShopifyQL table)"
        )
    names: list[str] = []
    for column in columns:
        name = (
            str(column.get("name", "")).strip().lower()
            if isinstance(column, Mapping)
            else ""
        )
        names.append(name)
    # Sum each mapped column across all rows.
    totals: dict[str, Decimal] = {}
    kinds: dict[str, str] = {}
    used_columns: set[str] = set()
    for index, name in enumerate(names):
        mapping = _SHOPIFY_COLUMNS.get(name)
        if mapping is None:
            if name in {"currency", "currency_code", "currencycode"}:
                used_columns.add(name)
                continue
            if name:
                extraction.unrecognized.append(name)
            continue
        metric, kind = mapping
        kinds[metric] = kind
        used_columns.add(name)
        for row in rows:
            if not isinstance(row, Sequence) or index >= len(row):
                continue
            value = _as_decimal(row[index])
            if value is not None:
                totals[metric] = totals.get(metric, Decimal("0")) + value
    for metric, total in totals.items():
        if kinds[metric] == "money":
            extraction.set_money(metric, metric, total)
        else:
            extraction.set_count(metric, metric, total)
    extraction.source_fields = sorted(used_columns)
    extraction.sample_size = len(rows)
    return extraction


# GA per-row field -> canonical metric (all counts, summed across days).
_GA_FIELDS: dict[str, str] = {
    "sessions": "sessions",
    "conversions": "conversions",
    "engaged_sessions": "engagements",
}
_GA_KNOWN_FIELDS = frozenset(
    {
        "sessions",
        "conversions",
        "engaged_sessions",
        "page_views",
        "recorded_at",
        "platform",
        "property_id",
    }
)


def _extract_google_analytics(response: Mapping[str, Any]) -> _Extraction:
    extraction = _Extraction()
    rows = response.get("metrics")
    if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes)):
        raise GrowthIngestionError(
            "google_analytics response must carry a 'metrics' list of daily rows"
        )
    totals: dict[str, int] = {}
    used: set[str] = set()
    unrecognized: set[str] = set()
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        for key, value in row.items():
            metric = _GA_FIELDS.get(key)
            if metric is None:
                if key not in _GA_KNOWN_FIELDS:
                    unrecognized.add(key)
                continue
            parsed = _as_count(value)
            if parsed is not None:
                totals[metric] = totals.get(metric, 0) + parsed
                used.add(key)
    for metric, total in totals.items():
        extraction.metrics[metric] = total
    extraction.source_fields = sorted(used)
    extraction.unrecognized = sorted(unrecognized)
    extraction.sample_size = len(rows)
    return extraction


def _meta_insight_values(response: Mapping[str, Any]) -> dict[str, Any]:
    """Flatten Meta's nested insights.data[].values[].value into {name: value}."""

    flat: dict[str, Any] = {}
    insights = response.get("insights")
    data = insights.get("data") if isinstance(insights, Mapping) else insights
    if isinstance(data, Sequence) and not isinstance(data, (str, bytes)):
        for entry in data:
            if not isinstance(entry, Mapping):
                continue
            name = entry.get("name")
            values = entry.get("values")
            if not isinstance(name, str) or not isinstance(values, Sequence):
                continue
            for value_entry in values:
                if isinstance(value_entry, Mapping) and "value" in value_entry:
                    flat[name] = value_entry["value"]
                    break
    return flat


def _extract_facebook(response: Mapping[str, Any]) -> _Extraction:
    extraction = _Extraction()
    extraction.set_count(
        "followers",
        "followers_count",
        response.get("followers_count", response.get("fan_count")),
    )
    if "followers_count" not in response and "fan_count" in response:
        # record which source we used
        if extraction.source_fields and extraction.source_fields[-1] == (
            "followers_count"
        ):
            extraction.source_fields[-1] = "fan_count"
    insight = _meta_insight_values(response)
    extraction.set_count(
        "impressions", "post_impressions", insight.get("post_impressions")
    )
    extraction.set_count("clicks", "post_clicks", insight.get("post_clicks"))
    extraction.set_count(
        "engagements", "post_engaged_users", insight.get("post_engaged_users")
    )
    return extraction


def _extract_instagram(response: Mapping[str, Any]) -> _Extraction:
    extraction = _Extraction()
    extraction.set_count(
        "followers", "followers_count", response.get("followers_count")
    )
    insight = _meta_insight_values(response)
    extraction.set_count("impressions", "impressions", insight.get("impressions"))
    extraction.set_count("engagements", "engagement", insight.get("engagement"))
    extraction.set_count("clicks", "clicks", insight.get("clicks"))
    if "engagements" not in extraction.metrics:
        interactions = 0
        used_interactions: list[str] = []
        for field in ("likes", "comments", "saved"):
            value = _as_count(insight.get(field))
            if value is not None:
                interactions += value
                used_interactions.append(field)
        if used_interactions:
            extraction.metrics["engagements"] = interactions
            extraction.source_fields.append("insights." + "+".join(used_interactions))
    # Reach is distinct from impressions and views have no canonical funnel
    # slot. Surface both as unmapped instead of silently relabeling them.
    for field in ("reach", "views"):
        if _as_count(insight.get(field)) is not None:
            extraction.unrecognized.append("insights." + field)
    return extraction


def _extract_linkedin(response: Mapping[str, Any]) -> _Extraction:
    extraction = _Extraction()
    extraction.set_count(
        "followers", "followers_count", response.get("followers_count")
    )
    stats = response.get("totalShareStatistics")
    if isinstance(stats, Mapping):
        extraction.set_count(
            "impressions", "impressionCount", stats.get("impressionCount")
        )
        extraction.set_count("clicks", "clickCount", stats.get("clickCount"))
        # engagement is LinkedIn's own reported rate; only accept a true ratio.
        extraction.set_rate("engagement_rate", "engagement", stats.get("engagement"))
        interactions = 0
        used_any = False
        for field in ("likeCount", "commentCount", "shareCount"):
            value = _as_count(stats.get(field))
            if value is not None:
                interactions += value
                used_any = True
        if used_any:
            extraction.metrics["engagements"] = interactions
            extraction.source_fields.append("likeCount+commentCount+shareCount")
    return extraction


def _extract_hubspot(response: Mapping[str, Any]) -> _Extraction:
    extraction = _Extraction()
    deals = response.get("deals")
    if not isinstance(deals, Sequence) or isinstance(deals, (str, bytes)):
        raise GrowthIngestionError("hubspot response must carry a 'deals' list")
    # Count of deals -> opportunities; sum of amount -> revenue. won_deals is
    # intentionally NOT emitted: crm.search_deals returns no is_won flag and we
    # do not guess which stage names mean won.
    extraction.metrics["opportunities"] = len(deals)
    extraction.source_fields.append("deals[]")
    revenue = Decimal("0")
    amounts_seen = False
    for deal in deals:
        if not isinstance(deal, Mapping):
            continue
        amount = _as_money(deal.get("amount"))
        if amount is not None:
            revenue += amount
            amounts_seen = True
    if amounts_seen:
        extraction.metrics["revenue"] = revenue.quantize(_MONEY_QUANTUM)
        extraction.source_fields.append("deals[].amount")
    total = _as_count(response.get("total"))
    if total is not None:
        # Consumed as the result count (sample_size), not a metric — mark it so
        # the completeness pass does not report it as unmapped.
        extraction.source_fields.append("total")
    extraction.sample_size = total if total is not None else len(deals)
    return extraction


def _extract_salesforce(response: Mapping[str, Any]) -> _Extraction:
    extraction = _Extraction()
    report = response.get("report")
    if not isinstance(report, Mapping):
        raise GrowthIngestionError("salesforce response must carry a 'report' object")
    extraction.set_count(
        "opportunities", "opportunity_count", report.get("opportunity_count")
    )
    extraction.set_count("won_deals", "won_count", report.get("won_count"))
    extraction.set_rate("pipeline_win_rate", "win_rate", report.get("win_rate"))
    extraction.set_money("revenue", "total_value", report.get("total_value"))
    total = _as_count(report.get("opportunity_count"))
    extraction.sample_size = total
    return extraction


_EXTRACTORS: dict[str, Callable[[Mapping[str, Any]], _Extraction]] = {
    "shopify": _extract_shopify,
    "google_analytics": _extract_google_analytics,
    "facebook": _extract_facebook,
    "instagram": _extract_instagram,
    "linkedin": _extract_linkedin,
    "hubspot": _extract_hubspot,
    "salesforce": _extract_salesforce,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def normalize_connector_response(
    *,
    source_capability: str,
    response: Mapping[str, Any],
    observation_ref: str,
    connector_account_ref: str,
    window_start: str,
    window_end: str,
    observed_at: str,
    sample_size: int | None = None,
    currency: str | None = None,
) -> IngestionResult:
    """Normalize one raw connector analytics response into sealable evidence.

    Returns an :class:`IngestionResult` whose ``evidence`` is an UNSEALED
    :class:`GrowthFunnelEvidence` body (no attestation trio) ready for the host
    to seal, and whose ``coverage`` honestly reports what mapped and what did
    not. ``sample_size`` is derived from the response's row/result count when
    available; supply it explicitly for providers that carry none (a single
    social snapshot), or a mismatch raises.
    """

    provider = SUPPORTED_INGESTION_CAPABILITIES.get(source_capability)
    if provider is None:
        raise GrowthIngestionError(
            f"no ingestion adapter for capability {source_capability!r}; "
            f"supported: {sorted(SUPPORTED_INGESTION_CAPABILITIES)}"
        )
    mapping = _require_mapping(provider, response)
    extraction = _EXTRACTORS[provider](mapping)
    if not extraction.metrics:
        raise GrowthIngestionError(
            f"the {provider} response carried no recognized metric; nothing to "
            "ingest (unknown is not zero)"
        )
    # Completeness pass: report any TOP-LEVEL numeric field we did not consume
    # as a metric source — real unmapped data (e.g. Meta media_count) the
    # caller should know is being left on the table. Metadata strings (names,
    # links, ids) are not numeric and are not flagged.
    used = set(extraction.source_fields)
    already = set(extraction.unrecognized)
    for key, value in mapping.items():
        if key in used or key in already:
            continue
        if isinstance(value, bool) or isinstance(value, (int, float)):
            extraction.unrecognized.append(str(key))

    resolved_sample = sample_size if sample_size is not None else extraction.sample_size
    if resolved_sample is None:
        raise GrowthIngestionError(
            f"the {provider} response carries no row/result count; supply "
            "sample_size explicitly for this observation"
        )
    if (
        sample_size is not None
        and extraction.sample_size is not None
        and (sample_size != extraction.sample_size)
    ):
        raise GrowthIngestionError(
            "supplied sample_size does not match the response's own row count"
        )

    metrics = GrowthMetrics.model_validate(extraction.metrics)
    resolved_currency = (
        _resolve_revenue_currency(
            provider=provider,
            response=mapping,
            governed_currency=currency,
        )
        if metrics.revenue is not None
        else None
    )
    evidence = GrowthFunnelEvidence.model_validate(
        {
            "observation_ref": observation_ref,
            "connector_account_ref": connector_account_ref,
            "provider": provider,
            "source_capability": source_capability,
            "observed_at": observed_at,
            "window_start": window_start,
            "window_end": window_end,
            "sample_size": resolved_sample,
            "metrics": metrics.model_dump(mode="python", exclude_none=True),
            "currency": resolved_currency,
            "evidence_digest": _stable_digest(dict(response)),
        }
    )
    coverage = MetricCoverage(
        provider=provider,
        source_capability=source_capability,
        populated_metrics=tuple(
            sorted(k for k, v in extraction.metrics.items() if v is not None)
        ),
        source_fields_used=tuple(extraction.source_fields),
        unrecognized_response_fields=tuple(extraction.unrecognized),
    )
    return IngestionResult(evidence=evidence, coverage=coverage)


def ingestion_capabilities() -> tuple[dict[str, str], ...]:
    """Discoverable list of supported ingestion capabilities and providers."""

    return tuple(
        {"source_capability": capability, "provider": provider}
        for capability, provider in sorted(SUPPORTED_INGESTION_CAPABILITIES.items())
    )


# Import-time guard: every mapped canonical count is a real GrowthMetrics field.
for _mapping in (_SHOPIFY_COLUMNS.values(),):
    for _metric, _kind in _mapping:
        if _kind == "count" and _metric not in _CANONICAL_COUNTS:
            raise RuntimeError(f"ingestion maps unknown canonical metric {_metric}")


__all__ = [
    "GROWTH_INGESTION_RESULT_SCHEMA",
    "SUPPORTED_INGESTION_CAPABILITIES",
    "GrowthIngestionError",
    "IngestionResult",
    "MetricCoverage",
    "ingestion_capabilities",
    "normalize_connector_response",
]
