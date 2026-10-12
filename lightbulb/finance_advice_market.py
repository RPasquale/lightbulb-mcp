"""Market tables: where every provider's cited price sits against the rest of a catalog.

A market table is a description of published prices with their citations, never a
recommendation. It ranks a cited figure, not a product, and it says on every row
whether the figure was quoted fact by fact or only at product level. Quote-dependent
pricing never enters a table because there is no published figure to place.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Mapping, Sequence
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.finance_advice_catalog import Confidence, PricingKind, Product, ProductCatalog, ResearchModel, VerticalRegistry, load_vertical_registry
from lightbulb.finance_advice_engine import RankingWeight, default_ranking
from lightbulb.company_engine_core import GENESIS_DIGEST, OpaqueRef, Sha256Digest, ShortText, detached, seal, sealed_digest, skip_digests

ADVICE_MARKET_KIND = "lightbulb.finance_advice_market.v1"
MARKET_TABLE_SCHEMA = "lightbulb.finance_advice_market_table.v1"
MARKET_REPORT_SCHEMA = "lightbulb.finance_advice_market_report.v1"
PROVIDER_POSITION_SCHEMA = "lightbulb.finance_advice_provider_position.v1"

Direction = Literal["lower_is_better", "higher_is_better"]
Support = Literal["fact_cited", "product_cited"]

_NUMBER = re.compile(r"^(?:[A-Z]{1,3}\$?|\$|€|£)?\s*(-?\d[\d,]*(?:\.\d+)?)(?:\s*(?:%|p\.a\.|per annum|per month|pa|bps))*\s*$", re.I)


class AdviceMarketError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise AdviceMarketError(code, message)


def cited_number(value: Any) -> Decimal | None:
    """One published number, or None: ranges, words and blanks never become a figure."""

    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float, Decimal)):
        try:
            return Decimal(str(value))
        except InvalidOperation:
            return None
    text = str(value).strip()
    if not text or re.search(r"\d\s*(?:-|–|to)\s*\d", text):
        return None
    match = _NUMBER.match(text)
    if not match:
        return None
    try:
        return Decimal(match.group(1).replace(",", ""))
    except InvalidOperation:
        return None


def _quantile(values: Sequence[Decimal], q: Decimal) -> Decimal:
    ordered = sorted(values)
    if not ordered:
        raise AdviceMarketError("EMPTY", "no values")
    position = (Decimal(len(ordered)) - 1) * q
    low = int(position)
    high = min(low + 1, len(ordered) - 1)
    fraction = position - low
    return (ordered[low] + (ordered[high] - ordered[low]) * fraction).quantize(Decimal("0.0001"), rounding=ROUND_HALF_UP)


class MarketRow(ResearchModel):
    provider_ref: OpaqueRef
    provider_name: str
    product_ref: OpaqueRef
    product_name: str
    taxonomy_class: str
    item: str
    value: Decimal
    unit: str | None = None
    support: Support
    confidence: Confidence
    pricing_kind: PricingKind
    retrieved_at: str | None = None
    note: str | None = None

    @field_validator("value", mode="before")
    @classmethod
    def _decimal(cls, value: Any) -> Decimal:
        return value if isinstance(value, Decimal) else Decimal(str(value))


class MarketTable(ResearchModel):
    """Every cited figure for one pricing item across a catalog, placed on one scale."""

    schema_id: str = Field(default=MARKET_TABLE_SCHEMA, alias="schema")
    vertical_id: str
    jurisdiction: str
    catalog_digest: Sha256Digest
    run_date: str
    label: ShortText
    patterns: tuple[str, ...]
    direction: Direction = "lower_is_better"
    classes: tuple[str, ...] = Field(default_factory=tuple)
    unit: str | None = None
    include_product_cited: bool = True
    rows: tuple[MarketRow, ...] = Field(default_factory=tuple)
    count: int = 0
    lenders: int = 0
    minimum: Decimal | None = None
    p25: Decimal | None = None
    median: Decimal | None = None
    p75: Decimal | None = None
    maximum: Decimal | None = None
    by_support: dict[str, int] = Field(default_factory=dict)
    by_confidence: dict[str, int] = Field(default_factory=dict)
    dropped: dict[str, int] = Field(default_factory=dict)
    disclosures: tuple[str, ...] = Field(default_factory=tuple)
    table_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("patterns", "classes", "rows", "disclosures", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("minimum", "p25", "median", "p75", "maximum", mode="before")
    @classmethod
    def _decimals(cls, value: Any) -> Decimal | None:
        return None if value is None else (value if isinstance(value, Decimal) else Decimal(str(value)))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> MarketTable:
        if self.count != len(self.rows):
            raise ValueError("count must equal the number of rows")
        if not skip_digests(info) and self.table_digest != sealed_digest(MarketTable, self, "table_digest"):
            raise ValueError("table_digest must commit the exact table")
        return self

    def rows_for(self, provider: str) -> tuple[MarketRow, ...]:
        wanted = provider.strip().lower()
        return tuple(row for row in self.rows if row.provider_ref == provider or row.provider_name.strip().lower() == wanted)


class ProviderPosition(ResearchModel):
    """Where one provider's best cited figure sits among the lenders in a table."""

    schema_id: str = Field(default=PROVIDER_POSITION_SCHEMA, alias="schema")
    table_digest: Sha256Digest
    label: ShortText
    provider_ref: OpaqueRef
    provider_name: str
    rows: int
    best_value: Decimal
    best_product_ref: OpaqueRef
    best_product_name: str
    best_support: Support
    rank: int = Field(ge=1)
    of_lenders: int = Field(ge=1)
    percentile: Decimal
    market_median: Decimal
    delta_to_median: Decimal
    basis: tuple[str, ...] = Field(default_factory=tuple)

    @field_validator("basis", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("best_value", "percentile", "market_median", "delta_to_median", mode="before")
    @classmethod
    def _decimals(cls, value: Any) -> Decimal:
        return value if isinstance(value, Decimal) else Decimal(str(value))


class MarketReport(ResearchModel):
    schema_id: str = Field(default=MARKET_REPORT_SCHEMA, alias="schema")
    vertical_id: str
    jurisdiction: str
    catalog_digest: Sha256Digest
    run_date: str
    completeness: str
    tables: tuple[MarketTable, ...] = Field(default_factory=tuple)
    disclosures: tuple[str, ...] = Field(default_factory=tuple)
    report_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("tables", "disclosures", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> MarketReport:
        if not skip_digests(info) and self.report_digest != sealed_digest(MarketReport, self, "report_digest"):
            raise ValueError("report_digest must commit the exact report")
        return self

    def table(self, label: str) -> MarketTable:
        for item in self.tables:
            if item.label == label:
                return item
        raise AdviceMarketError("TABLE_UNKNOWN", f"no table labelled {label!r}")


def _catalog(catalog: ProductCatalog | Mapping[str, Any]) -> ProductCatalog:
    return catalog if isinstance(catalog, ProductCatalog) else ProductCatalog.model_validate(dict(detached(catalog)))


def _matches(item: str, patterns: Sequence[str]) -> bool:
    lower = item.strip().lower()
    return any(lower == pattern or lower.startswith(pattern) for pattern in patterns)


def _latest(product: Product) -> str | None:
    return max((source.retrieved_at for source in product.sources if source.retrieved_at), default=None)


def market_table(
    catalog: ProductCatalog | Mapping[str, Any],
    *,
    label: str,
    patterns: Sequence[str],
    direction: Direction = "lower_is_better",
    classes: Sequence[str] = (),
    unit_prefix: str | None = None,
    include_product_cited: bool = True,
) -> MarketTable:
    """Every cited figure whose pricing item matches one of ``patterns``, on one unit, sorted from best to worst."""

    c = _catalog(catalog)
    wanted = tuple(dict.fromkeys(pattern.strip().lower() for pattern in patterns if pattern and pattern.strip()))
    _require(bool(wanted), "PATTERNS_MISSING", "name at least one pricing item to tabulate")
    class_filter = set(classes)
    dropped: Counter[str] = Counter()
    candidates: list[MarketRow] = []
    for product in c.products:
        if class_filter and product.taxonomy_class not in class_filter:
            continue
        if product.pricing_kind not in ("list", "quoted"):
            if any(_matches(fact.item, wanted) for fact in product.pricing):
                dropped["quote_dependent_or_unstated_pricing"] += 1
            continue
        for fact in product.pricing:
            if not _matches(fact.item, wanted):
                continue
            if fact.support == "unsupported":
                dropped["unsupported"] += 1
                continue
            if fact.support == "product_cited" and not include_product_cited:
                dropped["product_cited"] += 1
                continue
            if unit_prefix is not None and not (fact.unit or "").startswith(unit_prefix):
                dropped["other_unit"] += 1
                continue
            number = cited_number(fact.value)
            if number is None:
                dropped["not_a_single_figure"] += 1
                continue
            note = None
            if isinstance(fact.conditions, Mapping) and fact.conditions.get("note"):
                note = str(fact.conditions["note"])[:200]
            candidates.append(MarketRow(provider_ref=product.provider_ref, provider_name=product.provider_name, product_ref=product.product_ref, product_name=product.product_name, taxonomy_class=product.taxonomy_class, item=fact.item, value=number, unit=fact.unit, support=fact.support, confidence=product.confidence, pricing_kind=product.pricing_kind, retrieved_at=_latest(product), note=note))
    unit = None
    if candidates:
        unit = Counter(row.unit for row in candidates).most_common(1)[0][0]
        kept = [row for row in candidates if row.unit == unit]
        dropped["other_unit"] += len(candidates) - len(kept)
        candidates = kept
    reverse = direction == "higher_is_better"
    rows = sorted(candidates, key=lambda row: ((-row.value if reverse else row.value), row.provider_name, row.product_name))
    values = [row.value for row in rows]
    disclosures = [
        "Figures are the providers' published list prices as cited in the packs; a quote a client receives can differ.",
        "A table describes prices, it does not recommend a product; suitability sits with the adviser and the fact find.",
    ]
    if include_product_cited and any(row.support == "product_cited" for row in rows):
        disclosures.append("Rows marked product_cited were cited at product level rather than fact by fact; they are shown, never promoted.")
    if c.completeness != "census_complete":
        disclosures.append(f"The catalog is a {c.completeness.replace('_', ' ')}; providers not yet reviewed are absent from this table.")
    return seal(
        MarketTable,
        {
            "vertical_id": c.vertical_id, "jurisdiction": c.jurisdiction, "catalog_digest": c.catalog_digest, "run_date": c.run_date, "label": label, "patterns": wanted, "direction": direction, "classes": tuple(classes),
            "unit": unit, "include_product_cited": include_product_cited, "rows": [row.to_dict() for row in rows], "count": len(rows), "lenders": len({row.provider_ref for row in rows}),
            "minimum": min(values) if values else None, "p25": _quantile(values, Decimal("0.25")) if values else None, "median": _quantile(values, Decimal("0.5")) if values else None, "p75": _quantile(values, Decimal("0.75")) if values else None, "maximum": max(values) if values else None,
            "by_support": dict(sorted(Counter(row.support for row in rows).items())), "by_confidence": dict(sorted(Counter(row.confidence for row in rows).items())), "dropped": dict(sorted(dropped.items())), "disclosures": disclosures,
        },
        "table_digest",
    )


def provider_position(table: MarketTable | Mapping[str, Any], provider: str) -> ProviderPosition:
    """The provider's best figure ranked against every other lender's best figure in the table."""

    t = table if isinstance(table, MarketTable) else MarketTable.model_validate(dict(detached(table)))
    _require(t.rows and t.median is not None, "TABLE_EMPTY", "the table holds no figures")
    reverse = t.direction == "higher_is_better"
    best_by_lender: dict[str, MarketRow] = {}
    for row in t.rows:
        current = best_by_lender.get(row.provider_ref)
        if current is None or (row.value > current.value if reverse else row.value < current.value):
            best_by_lender[row.provider_ref] = row
    mine = t.rows_for(provider)
    _require(bool(mine), "PROVIDER_ABSENT", f"{provider!r} has no figure in this table")
    best = best_by_lender[mine[0].provider_ref]
    ordered = sorted(best_by_lender.values(), key=lambda row: (-row.value if reverse else row.value, row.provider_name))
    rank = next(index for index, row in enumerate(ordered, start=1) if row.provider_ref == best.provider_ref)
    of = len(ordered)
    percentile = (Decimal(rank - 1) / Decimal(max(of - 1, 1)) * Decimal("100")).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)
    delta = (best.value - t.median).quantize(Decimal("0.0001"), rounding=ROUND_HALF_UP)
    basis = [
        f"{t.label}: best cited figure {best.value} {t.unit or ''} on {best.product_name} ({best.support}, {best.confidence})".strip(),
        f"rank {rank} of {of} lenders by each lender's best figure; market median {t.median} {t.unit or ''}".strip(),
    ]
    return ProviderPosition(table_digest=t.table_digest, label=t.label, provider_ref=best.provider_ref, provider_name=best.provider_name, rows=len(mine), best_value=best.value, best_product_ref=best.product_ref, best_product_name=best.product_name, best_support=best.support, rank=rank, of_lenders=of, percentile=percentile, market_median=t.median, delta_to_median=delta, basis=basis)


def standard_items(sector: str) -> tuple[tuple[str, tuple[str, ...], Direction], ...]:
    """The sector's default decision fields, as the engine ranks them, so tables and ranking never disagree on what a figure means."""

    items: list[tuple[str, tuple[str, ...], Direction]] = []
    for weight in default_ranking(sector):
        w: RankingWeight = weight
        items.append((w.decision_field, tuple(w.pricing_items), w.direction))
    return tuple(items)


def market_report(catalog: ProductCatalog | Mapping[str, Any], *, registry: VerticalRegistry | None = None, include_product_cited: bool = True) -> MarketReport:
    """One table per decision field the sector ranks on."""

    c = _catalog(catalog)
    registry = registry or load_vertical_registry()
    vertical = registry.vertical(c.vertical_id)
    tables = [market_table(c, label=label, patterns=patterns, direction=direction, include_product_cited=include_product_cited) for label, patterns, direction in standard_items(vertical.sector)]
    disclosures = ["Every table is built from the same sealed catalog; rebuild the report when the catalog changes.", "No table is a recommendation; the plan's ranking weights decide how the fields combine for one client."]
    return seal(MarketReport, {"vertical_id": c.vertical_id, "jurisdiction": c.jurisdiction, "catalog_digest": c.catalog_digest, "run_date": c.run_date, "completeness": c.completeness, "tables": [table.to_dict() for table in tables], "disclosures": disclosures}, "report_digest")


def market_table_markdown(table: MarketTable | Mapping[str, Any], *, limit: int = 40) -> str:
    t = table if isinstance(table, MarketTable) else MarketTable.model_validate(dict(detached(table)))
    lines = [f"### {t.label} ({t.vertical_id})", "", f"{t.count} cited figures across {t.lenders} lenders, unit {t.unit or 'n/a'}; min {t.minimum}, median {t.median}, max {t.maximum}.", ""]
    if t.dropped:
        lines.append("Dropped: " + ", ".join(f"{key} {value}" for key, value in t.dropped.items()) + ".")
        lines.append("")
    lines += ["| # | Provider | Product | Figure | Support | Confidence | Retrieved |", "|---|---|---|---|---|---|---|"]
    for index, row in enumerate(t.rows[:limit], start=1):
        lines.append(f"| {index} | {row.provider_name} | {row.product_name} | {row.value} {row.unit or ''} | {row.support} | {row.confidence} | {row.retrieved_at or ''} |")
    if t.count > limit:
        lines.append(f"| … | {t.count - limit} more rows | | | | | |")
    lines.append("")
    for item in t.disclosures:
        lines.append(f"- {item}")
    return "\n".join(lines)


ADVICE_MARKET_MANIFEST: dict[str, Any] = {
    "kind": ADVICE_MARKET_KIND,
    "schemas": [MARKET_TABLE_SCHEMA, PROVIDER_POSITION_SCHEMA, MARKET_REPORT_SCHEMA],
    "hard_rules": [
        "a market table describes cited prices and never recommends a product",
        "quote-dependent and unstated pricing never enters a table because there is no published figure to place",
        "product-level citations are labelled on every row and never promoted to fact-level support",
        "a range, a phrase or a blank never becomes a figure",
        "tables use the sector's ranking decision fields so a table and a shortlist never disagree on what a figure means",
        "a provider's position is measured against every lender's best figure, never against every product",
    ],
    "non_goals": ["no personal advice", "no live prices: the table is as fresh as the catalog it was built from", "no hosted execution or certification claim"],
}

__all__ = [
    "ADVICE_MARKET_KIND",
    "ADVICE_MARKET_MANIFEST",
    "AdviceMarketError",
    "MARKET_REPORT_SCHEMA",
    "MARKET_TABLE_SCHEMA",
    "MarketReport",
    "MarketRow",
    "MarketTable",
    "PROVIDER_POSITION_SCHEMA",
    "ProviderPosition",
    "cited_number",
    "market_report",
    "market_table",
    "market_table_markdown",
    "provider_position",
    "standard_items",
]
