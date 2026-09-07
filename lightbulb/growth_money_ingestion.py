"""Money evidence ingestion: contribution ledgers and acquisition cohorts.

The front door for the engine's two money envelopes. A trusted host executes
a connector analytics tool through the platform's governed route, then calls
a normalizer here to turn the raw response into UNSEALED evidence bodies —
:class:`~lightbulb.growth_profit.ProfitContributionEvidence` for the profit
engine, :class:`~lightbulb.growth_customers.CustomerCohortEvidence` for the
customer value engine — which the host then seals with the respective
``mint_*`` functions. Nothing here does I/O, holds a keyring, or fabricates
trust.

Shares the funnel-ingestion honesty rules (see :mod:`lightbulb.growth_ingestion`):

- **Only recognized columns map.** Anything else numeric is *reported* in the
  coverage result, never silently absorbed and never guessed.
- **Missing metric = absent, never zero.** A cost the response does not carry
  is simply not set — Shopify cannot see ad spend, so ``acquisition_cost``
  never comes from a Shopify ledger response.
- **Shape mismatches fail loudly**, naming the provider and the expectation.
- **Provenance-bound digests.** Ledger evidence binds ``evidence_digest`` to
  the SHA-256 of the canonical raw response; each cohort binds to the
  response digest plus its cohort ref (one response yields many cohorts).

The canonical ``new_customer_cohort`` Shopify read is implemented by Spring's
ShopifyAdapter and exercised through its Rust request envelope. It normalizes
first-purchase counts, including verified zero, without inventing repeat-value
buckets. Real-account validation remains a separate deployment gate.

Legacy table producer status (mirrors the funnel-ingestion discipline of shipping the
table first, then confirming against a live read): the Shopify ShopifyQL
column maps below follow the documented producer contracts
(``docs/growth-engine-design.md`` slice 8 and the profit-engine ledger
vocabulary). They are UNVALIDATED against live responses until an admin
live-read pass runs on a connected Shopify store; any drift is a one-line
table fix. Finance-side capabilities (``stripe.financial_report``,
``xero.profit_and_loss_report``) have no pinned in-repo response shape yet
and are refused loudly rather than guessed at.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .growth_customers import CustomerCohortEvidence
from .growth_ingestion import MetricCoverage
from .growth_profit import ContributionMetrics, ProfitContributionEvidence

LEDGER_INGESTION_RESULT_SCHEMA = "lightbulb.growth_ledger_ingestion_result.v1"
COHORT_INGESTION_RESULT_SCHEMA = "lightbulb.growth_cohort_ingestion_result.v1"

_MONEY_QUANTUM = Decimal("0.01")

# Capability -> provider for the money envelopes. Finance capabilities are
# listed with producer=None so discovery is honest about what is refused.
SUPPORTED_LEDGER_CAPABILITIES: dict[str, str | None] = {
    "shopify.analytics_query": "shopify",
    "stripe.financial_report": None,
    "xero.profit_and_loss_report": None,
    "quickbooks.profit_and_loss_report": None,
}
SUPPORTED_COHORT_CAPABILITIES: dict[str, str | None] = {
    "shopify.analytics_query": "shopify",
    "stripe.financial_report": None,
}


class GrowthMoneyIngestionError(ValueError):
    """A connector response cannot be normalized into money evidence."""


def _stable_digest(value: Any) -> str:
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


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


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=False,
        serialize_by_alias=True,
        strict=True,
    )


class LedgerIngestionResult(_StrictModel):
    schema_id: Literal["lightbulb.growth_ledger_ingestion_result.v1"] = Field(
        default=LEDGER_INGESTION_RESULT_SCHEMA,
        alias="schema",
    )
    evidence: ProfitContributionEvidence
    coverage: MetricCoverage

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


class CohortIngestionResult(_StrictModel):
    schema_id: Literal["lightbulb.growth_cohort_ingestion_result.v1"] = Field(
        default=COHORT_INGESTION_RESULT_SCHEMA,
        alias="schema",
    )
    cohorts: tuple[CustomerCohortEvidence, ...] = Field(min_length=1)
    coverage: MetricCoverage

    @field_validator("cohorts", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        if isinstance(value, list):
            return tuple(value)
        return value

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


# ---------------------------------------------------------------------------
# ShopifyQL table plumbing (local per the land-independent module convention)
# ---------------------------------------------------------------------------


def _shopifyql_table(
    response: Mapping[str, Any],
) -> tuple[list[str], Sequence[Any]]:
    columns = response.get("columns")
    rows = response.get("rows")
    if not isinstance(columns, Sequence) or isinstance(columns, (str, bytes)):
        raise GrowthMoneyIngestionError(
            "shopify response must carry a 'columns' list (ShopifyQL table)"
        )
    if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes)):
        raise GrowthMoneyIngestionError(
            "shopify response must carry a 'rows' list (ShopifyQL table)"
        )
    names = [
        str(column.get("name", "")).strip().lower()
        if isinstance(column, Mapping)
        else ""
        for column in columns
    ]
    return names, rows


def _row_value(row: Any, index: int) -> Any:
    if not isinstance(row, Sequence) or isinstance(row, (str, bytes)):
        return None
    if index >= len(row):
        return None
    return row[index]


def _refuse_unpinned(capability: str, table: Mapping[str, str | None]) -> str:
    producer = table.get(capability)
    if capability not in table:
        raise GrowthMoneyIngestionError(
            f"no money-ingestion adapter for capability {capability!r}; "
            f"supported: {sorted(table)}"
        )
    if producer is None:
        raise GrowthMoneyIngestionError(
            f"the {capability!r} response shape is not pinned in-repo yet; "
            "refusing to guess at a money envelope (unknown is not zero) — "
            "pin the shape and add its column map"
        )
    return producer


# ---------------------------------------------------------------------------
# Contribution ledger (profit engine)
# ---------------------------------------------------------------------------

# ShopifyQL column -> (ledger metric, kind). Shopify's commerce view: sales,
# discounts, returns, costs it records. acquisition_cost / service_cost /
# payment_fees are deliberately ABSENT unless the shop's report carries them —
# ad spend and service costs live outside Shopify (unknown, never zero).
_SHOPIFY_LEDGER_COLUMNS: dict[str, tuple[str, str]] = {
    "gross_sales": ("gross_sales", "money"),
    "total_sales": ("gross_sales", "money"),
    "discounts": ("discounts", "money"),
    "returns": ("refunds", "money"),
    "refunds": ("refunds", "money"),
    "cogs": ("cogs", "money"),
    "cost_of_goods_sold": ("cogs", "money"),
    "shipping_cost": ("fulfillment_cost", "money"),
    "fulfillment_cost": ("fulfillment_cost", "money"),
    "payment_fees": ("payment_fees", "money"),
    "transaction_fees": ("payment_fees", "money"),
    "orders": ("orders", "count"),
    "order_count": ("orders", "count"),
    "units": ("units", "count"),
    "quantity": ("units", "count"),
    "net_quantity": ("units", "count"),
    "new_customers": ("new_customers", "count"),
    "first_time_customers": ("new_customers", "count"),
}


def normalize_contribution_ledger_response(
    *,
    source_capability: str,
    response: Mapping[str, Any],
    observation_ref: str,
    connector_account_ref: str,
    currency: str,
    window_start: str,
    window_end: str,
    observed_at: str,
) -> LedgerIngestionResult:
    """Normalize one raw ledger-shaped response into sealable profit evidence.

    Returns an UNSEALED :class:`ProfitContributionEvidence` body (no
    attestation trio) ready for
    :func:`lightbulb.mint_profit_contribution_evidence`, plus an honest
    coverage report. ``currency`` is caller-supplied: ShopifyQL reports in
    the shop currency, which the governed route knows and this module must
    not guess.
    """

    _refuse_unpinned(source_capability, SUPPORTED_LEDGER_CAPABILITIES)
    if not isinstance(response, Mapping):
        raise GrowthMoneyIngestionError(
            f"shopify response must be an object, got {type(response).__name__}"
        )
    names, rows = _shopifyql_table(response)

    totals: dict[str, Decimal] = {}
    kinds: dict[str, str] = {}
    used: set[str] = set()
    unrecognized: list[str] = []
    for index, name in enumerate(names):
        mapping = _SHOPIFY_LEDGER_COLUMNS.get(name)
        if mapping is None:
            if name:
                unrecognized.append(name)
            continue
        metric, kind = mapping
        kinds[metric] = kind
        used.add(name)
        for row in rows:
            value = _as_decimal(_row_value(row, index))
            if value is not None:
                totals[metric] = totals.get(metric, Decimal("0")) + value

    metrics: dict[str, Any] = {}
    for metric, total in totals.items():
        if kinds[metric] == "money":
            money = _as_money(total)
            if money is not None:
                metrics[metric] = money
        else:
            count = _as_count(total)
            if count is not None:
                metrics[metric] = count
    if not metrics:
        raise GrowthMoneyIngestionError(
            "the shopify response carried no recognized ledger column; "
            "nothing to ingest (unknown is not zero)"
        )

    evidence = ProfitContributionEvidence.model_validate(
        {
            "observation_ref": observation_ref,
            "connector_account_ref": connector_account_ref,
            "provider": "shopify",
            "source_capability": source_capability,
            "currency": currency,
            "observed_at": observed_at,
            "window_start": window_start,
            "window_end": window_end,
            "metrics": ContributionMetrics.model_validate(metrics).model_dump(
                mode="python", exclude_none=True
            ),
            "evidence_digest": _stable_digest(dict(response)),
        }
    )
    coverage = MetricCoverage(
        provider="shopify",
        source_capability=source_capability,
        populated_metrics=tuple(sorted(metrics)),
        source_fields_used=tuple(sorted(used)),
        unrecognized_response_fields=tuple(unrecognized),
    )
    return LedgerIngestionResult(evidence=evidence, coverage=coverage)


# ---------------------------------------------------------------------------
# Acquisition cohorts (customer value engine)
# ---------------------------------------------------------------------------

# ShopifyQL cohort-grouped query columns, per the producer contract in
# docs/growth-engine-design.md slice 8. One row per (cohort, age bucket).
_COHORT_KEY_COLUMNS = ("cohort_month", "acquisition_month", "cohort")
_COHORT_SIZE_COLUMNS = ("cohort_size", "customers", "new_customers")
_BUCKET_START_COLUMNS = ("age_days_start", "bucket_start")
_BUCKET_END_COLUMNS = ("age_days_end", "bucket_end")
_COHORT_VALUE_COLUMNS: dict[str, str] = {
    "orders": "orders",
    "order_count": "orders",
    "gross_sales": "gross_sales",
    "total_sales": "gross_sales",
    "discounts": "discounts",
    "refunds": "refunds",
    "returns": "refunds",
}
_KNOWN_COHORT_COLUMNS = frozenset(
    (*_COHORT_KEY_COLUMNS, *_COHORT_SIZE_COLUMNS, *_BUCKET_START_COLUMNS,
     *_BUCKET_END_COLUMNS, *_COHORT_VALUE_COLUMNS)
)


def _month_window(token: str) -> tuple[str, str, str]:
    """A YYYY-MM cohort token -> (cohort_ref, window_start, window_end)."""

    clean = token.strip()
    try:
        start = datetime.strptime(clean, "%Y-%m").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise GrowthMoneyIngestionError(
            f"cohort key {token!r} is not a YYYY-MM month token"
        ) from exc
    if start.month == 12:
        end = start.replace(year=start.year + 1, month=1)
    else:
        end = start.replace(month=start.month + 1)
    ref = f"cohort-{clean.replace('-', '')}"
    stamp = "%Y-%m-%dT%H:%M:%SZ"
    return ref, start.strftime(stamp), end.strftime(stamp)


def _normalize_host_acquisition(response, *, source_capability, connector_account_ref, currency, observed_at):
    """The canonical governed Shopify count needs no invented repeat-value bucket."""
    from lightbulb.company_engine_core import stable_digest, parsed
    required = {"schema","query_digest","window_start","window_end","currency","new_customers",
        "sample_size","cohort_basis","exhaustive_read","truncated","evidence_sha256"}
    if set(response) != required or response["cohort_basis"] != "shopify_first_purchase":
        raise GrowthMoneyIngestionError("ACQUISITION_SOURCE_INVALID: retain the exact canonical first-purchase observation")
    if response["evidence_sha256"] != stable_digest({k:v for k,v in response.items() if k != "evidence_sha256"}):
        raise GrowthMoneyIngestionError("ACQUISITION_DIGEST_MISMATCH")
    if response["currency"] != currency:
        raise GrowthMoneyIngestionError("ACQUISITION_CURRENCY_MISMATCH")
    if response["exhaustive_read"] is not True or response["truncated"] is not False:
        raise GrowthMoneyIngestionError("ACQUISITION_INCOMPLETE")
    count=response["new_customers"]
    if type(count) is not int or not 0 <= count <= 10_000_000_000 or response["sample_size"] != count or type(response["sample_size"]) is not int:
        raise GrowthMoneyIngestionError("ACQUISITION_COUNT_INVALID")
    start,end = response["window_start"],response["window_end"]
    expected_query = {"target_metric":"new_customer_cohort","window_start":start,"window_end":end,"currency":currency}
    if response["query_digest"] != stable_digest(expected_query):
        raise GrowthMoneyIngestionError("ACQUISITION_REQUEST_MISMATCH")
    if parsed(start) >= parsed(end) or parsed(observed_at) < parsed(end):
        raise GrowthMoneyIngestionError("ACQUISITION_WINDOW_INVALID")
    ref="cohort-"+stable_digest({"account":connector_account_ref,"start":start,"end":end})[:24]
    evidence=CustomerCohortEvidence.model_validate({"cohort_ref":ref,"connector_account_ref":connector_account_ref,
        "provider":"shopify","source_capability":source_capability,"currency":currency,
        "acquisition_window_start":start,"acquisition_window_end":end,"observed_at":observed_at,
        "cohort_size":count,"age_buckets":[],"evidence_digest":stable_digest({"response":stable_digest(response),"cohort_ref":ref})})
    return CohortIngestionResult(cohorts=(evidence,),coverage=MetricCoverage(provider="shopify",
        source_capability=source_capability,populated_metrics=("cohort_size",),
        source_fields_used=("new_customers","window_start","window_end","currency"),unrecognized_response_fields=()))


def normalize_customer_cohorts_response(
    *,
    source_capability: str,
    response: Mapping[str, Any],
    connector_account_ref: str,
    currency: str,
    observed_at: str,
) -> CohortIngestionResult:
    """Normalize one cohort-grouped response into sealable cohort evidence.

    Expects a ShopifyQL-style table with one row per (cohort month, age
    bucket): a cohort key column (``cohort_month``/``acquisition_month``/
    ``cohort`` as ``YYYY-MM``), a cohort-size column, ``age_days_start``/
    ``age_days_end`` bucket bounds, and per-bucket ``orders``/``gross_sales``
    /``discounts``/``refunds``. Returns UNSEALED
    :class:`CustomerCohortEvidence` bodies (one per cohort, buckets
    assembled and sorted) ready for
    :func:`lightbulb.mint_customer_cohort_evidence`. Every honesty law of
    the cohort envelope applies downstream: buckets that violate the
    observed-age or overlap rules make the evidence model itself refuse.
    """

    _refuse_unpinned(source_capability, SUPPORTED_COHORT_CAPABILITIES)
    if not isinstance(response, Mapping):
        raise GrowthMoneyIngestionError(
            f"shopify response must be an object, got {type(response).__name__}"
        )
    if response.get("schema") == "lightbulb.shopify_customer_acquisition_observation.v1":
        return _normalize_host_acquisition(response,source_capability=source_capability,
            connector_account_ref=connector_account_ref,currency=currency,observed_at=observed_at)
    names, rows = _shopifyql_table(response)

    def _find(candidates: tuple[str, ...]) -> int | None:
        for candidate in candidates:
            if candidate in names:
                return names.index(candidate)
        return None

    key_index = _find(_COHORT_KEY_COLUMNS)
    size_index = _find(_COHORT_SIZE_COLUMNS)
    start_index = _find(_BUCKET_START_COLUMNS)
    end_index = _find(_BUCKET_END_COLUMNS)
    missing = [
        label
        for label, index in (
            ("cohort key (cohort_month)", key_index),
            ("cohort size (cohort_size)", size_index),
            ("bucket start (age_days_start)", start_index),
            ("bucket end (age_days_end)", end_index),
        )
        if index is None
    ]
    if missing:
        raise GrowthMoneyIngestionError(
            "the cohort table is missing required column(s): "
            + "; ".join(missing)
        )
    value_indexes: dict[int, str] = {}
    used: set[str] = set()
    unrecognized: list[str] = []
    for index, name in enumerate(names):
        metric = _COHORT_VALUE_COLUMNS.get(name)
        if metric is not None:
            value_indexes[index] = metric
            used.add(name)
        elif name and name not in _KNOWN_COHORT_COLUMNS:
            unrecognized.append(name)
    used.update(
        names[index] for index in (key_index, size_index, start_index, end_index)
    )
    if not any(metric == "orders" for metric in value_indexes.values()):
        raise GrowthMoneyIngestionError(
            "the cohort table carries no orders column; a repeat curve "
            "cannot be measured without it"
        )

    raw_digest = _stable_digest(dict(response))
    grouped: dict[str, dict[str, Any]] = {}
    for position, row in enumerate(rows):
        key_value = _row_value(row, key_index)
        if key_value is None:
            raise GrowthMoneyIngestionError(
                f"cohort table row {position} carries no cohort key"
            )
        ref, window_start, window_end = _month_window(str(key_value))
        size = _as_count(_row_value(row, size_index))
        if size is None or size < 1:
            raise GrowthMoneyIngestionError(
                f"cohort table row {position} carries no positive cohort size"
            )
        bucket_start = _as_count(_row_value(row, start_index))
        bucket_end = _as_count(_row_value(row, end_index))
        if bucket_start is None or bucket_end is None:
            raise GrowthMoneyIngestionError(
                f"cohort table row {position} carries no bucket bounds"
            )
        bucket: dict[str, Any] = {
            "age_days_start": bucket_start,
            "age_days_end": bucket_end,
            "orders": 0,
            "gross_sales": Decimal("0.00"),
            "discounts": Decimal("0.00"),
            "refunds": Decimal("0.00"),
        }
        for index, metric in value_indexes.items():
            value = _row_value(row, index)
            if metric == "orders":
                parsed_count = _as_count(value)
                if parsed_count is not None:
                    bucket["orders"] = parsed_count
            else:
                parsed_money = _as_money(value)
                if parsed_money is not None:
                    bucket[metric] = parsed_money
        entry = grouped.setdefault(
            ref,
            {
                "window_start": window_start,
                "window_end": window_end,
                "size": size,
                "buckets": [],
            },
        )
        if entry["size"] != size:
            raise GrowthMoneyIngestionError(
                f"cohort {ref} reports inconsistent cohort sizes "
                f"({entry['size']} vs {size}); the table is not "
                "cohort-grouped the way the contract requires"
            )
        entry["buckets"].append(bucket)

    cohorts: list[CustomerCohortEvidence] = []
    for ref in sorted(grouped):
        entry = grouped[ref]
        buckets = sorted(entry["buckets"], key=lambda item: item["age_days_start"])
        cohorts.append(
            CustomerCohortEvidence.model_validate(
                {
                    "cohort_ref": ref,
                    "connector_account_ref": connector_account_ref,
                    "provider": "shopify",
                    "source_capability": source_capability,
                    "currency": currency,
                    "acquisition_window_start": entry["window_start"],
                    "acquisition_window_end": entry["window_end"],
                    "observed_at": observed_at,
                    "cohort_size": entry["size"],
                    "age_buckets": buckets,
                    # One response yields many cohorts: each digest binds the
                    # raw response AND the cohort it was carved from.
                    "evidence_digest": _stable_digest(
                        {"response": raw_digest, "cohort_ref": ref}
                    ),
                }
            )
        )

    coverage = MetricCoverage(
        provider="shopify",
        source_capability=source_capability,
        populated_metrics=tuple(
            sorted({metric for metric in value_indexes.values()})
        ),
        source_fields_used=tuple(sorted(used)),
        unrecognized_response_fields=tuple(unrecognized),
    )
    return CohortIngestionResult(cohorts=tuple(cohorts), coverage=coverage)


def money_ingestion_capabilities() -> tuple[dict[str, Any], ...]:
    """Discoverable list of money-ingestion capabilities and their status."""

    entries: list[dict[str, Any]] = []
    for capability, producer in sorted(SUPPORTED_LEDGER_CAPABILITIES.items()):
        entries.append(
            {
                "envelope": "contribution_ledger",
                "source_capability": capability,
                "producer": producer,
                "status": "available" if producer else "shape_not_pinned",
            }
        )
    for capability, producer in sorted(SUPPORTED_COHORT_CAPABILITIES.items()):
        entries.append(
            {
                "envelope": "customer_cohorts",
                "source_capability": capability,
                "producer": producer,
                "status": "available" if producer else "shape_not_pinned",
            }
        )
    return tuple(entries)


__all__ = [
    "COHORT_INGESTION_RESULT_SCHEMA",
    "LEDGER_INGESTION_RESULT_SCHEMA",
    "SUPPORTED_COHORT_CAPABILITIES",
    "SUPPORTED_LEDGER_CAPABILITIES",
    "CohortIngestionResult",
    "GrowthMoneyIngestionError",
    "LedgerIngestionResult",
    "money_ingestion_capabilities",
    "normalize_contribution_ledger_response",
    "normalize_customer_cohorts_response",
]
