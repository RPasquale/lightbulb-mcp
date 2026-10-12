"""Advice catalog: the sourced product facts an advice business reasons over.

An advice business has a client with a *state*, an adviser, and a universe of regulated
providers whose products, policies or plans the adviser matches to that state. This module is
the universe: registers (who is authorised), providers (the legal entities on them), products
(what each provider declares, decision field by decision field) and a coverage statement that
says exactly how much of the register the run reached.

Everything here is a FACT with a source. A pricing figure without a URL, a retrieval date and a
supporting quotation is carried as *unsupported* and can never be ranked on. A product whose
class is not in the vertical's fixed taxonomy is *unclassified*, never silently reclassified. A
run that reached fifteen of sixty-seven providers is a *partial sample*, never a census. Person
specific ranking, suitability and recommendation live downstream in ``finance_advice_engine``; this
catalog contains no recommendation, and the SDK reads nothing and writes nothing.

The pack format ingested here is the owner's register-first research output (Australia and
Canada, 2026-09): ``{registers, providers, products, coverage}`` with per-product ``pricing``,
``key_terms``, ``eligibility``, ``sources``, ``confidence`` and ``gaps``.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from decimal import Decimal, InvalidOperation
from importlib import resources
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from pydantic import BaseModel

from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    OpaqueRef,
    Sha256Digest,
    StrictModel,
    detached,
    seal,
    sealed_digest,
    skip_digests,
)

ADVICE_CATALOG_KIND = "lightbulb.finance_advice_catalog"

# Research packs carry public URLs and quotations with long numeric runs (document ids, cache
# timestamps). The engine-core guard reads any 13-19 digit run as card-like, which is right at a
# tenant boundary and wrong for a provider's public rate-sheet URL. ResearchModel keeps every
# credential guard (key names, live keys, tokens, private keys) and drops only that digit rule.
_CREDENTIAL_KEYS = (
    "secret", "password", "passwd", "token", "api_key", "apikey", "authorization", "credential", "private_key",
    "client_secret", "tenant_id", "company_id", "user_id", "card_number", "cvc", "iban", "routing_number",
    "date_of_birth", "national_id", "passport", "access_key", "refresh_key",
)
_CREDENTIAL_VALUES = (
    re.compile(r"sk_(?:live|test)_[A-Za-z0-9]{8,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]{16,}", re.IGNORECASE),
)


def reject_credential_payload(value: Any, *, path: str = "input") -> None:
    if isinstance(value, str):
        if any(pattern.search(value) for pattern in _CREDENTIAL_VALUES):
            raise ValueError(f"{path} carries a credential-like value and is never accepted")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            lowered = str(key).lower()
            if any(marker in lowered for marker in _CREDENTIAL_KEYS):
                raise ValueError(f"{path}.{key} is a credential-, bank-, or personal-identity field and is never accepted")
            reject_credential_payload(item, path=f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            reject_credential_payload(item, path=f"{path}[{index}]")


class ResearchModel(StrictModel):
    """A strict, frozen, portable model for research facts: credential guards on, the card-like digit rule off."""

    @model_validator(mode="before")
    @classmethod
    def _portable_payload(cls, value: Any) -> Any:
        if isinstance(value, BaseModel):
            value = value.model_dump(mode="json", by_alias=True, exclude_none=True)
        if not isinstance(value, Mapping):
            return value
        reject_credential_payload(value)
        return {str(key): (tuple(item) if isinstance(item, list) else item) for key, item in value.items()}

CATALOG_SCHEMA = "lightbulb.finance_advice_product_catalog.v1"
VERTICAL_REGISTRY_SCHEMA = "lightbulb.finance_advice_vertical_registry.v1"
CATALOG_SUMMARY_SCHEMA = "lightbulb.finance_advice_catalog_summary.v1"
DATA_PACKAGE = "lightbulb.data"
VERTICALS_FILE = "finance_advice_verticals.v1.json"
FIXTURE_PACKAGE = "lightbulb.data.finance_advice_fixtures"
FIXTURE_FILES: Mapping[str, str] = {
    "au_home_loans_pilot": "au_home_loans_pilot.json",
    "au_credit_cards_pilot": "au_credit_cards_pilot.json",
    "ca_mortgages_batch": "ca_mortgages_batch.json",
    "ca_mortgages_census": "ca_mortgages_census.json",
}

Jurisdiction = Literal["AU", "CA"]
Confidence = Literal["verified", "single_source", "unverified"]
PricingKind = Literal["list", "quoted", "quote_required", "unstated"]
UnitKind = Literal["rate_percent_per_year", "percent", "percent_of_transaction", "money", "money_per_month", "money_per_year", "money_per_transaction", "other", "unstated"]
Support = Literal["fact_cited", "product_cited", "unsupported"]
Freshness = Literal["fresh", "stale", "scheduled", "expired", "held", "unstated"]
Completeness = Literal["census_complete", "partial_sample", "identity_only"]

MAX_PROVIDERS = 5000
MAX_PRODUCTS = 20000
_JURISDICTIONS = {"australia": "AU", "au": "AU", "canada": "CA", "ca": "CA"}
_CURRENCY_BY_JURISDICTION = {"AU": "AUD", "CA": "CAD"}
_DATE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}(T[0-9:.]+Z?)?$")


class AdviceCatalogError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise AdviceCatalogError(code, message)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _strings(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value.strip(),) if value.strip() else ()
    return tuple(str(item).strip() for item in value if str(item).strip())


def _jsonable(value: Any) -> Any:
    return json.loads(json.dumps(value, default=str, ensure_ascii=False))


def _jurisdiction(value: Any) -> str | None:
    text = _text(value)
    return None if text is None else _JURISDICTIONS.get(text.lower())


# --------------------------------------------------------------------------- #
# The vertical registry: 97 verticals, each with a frozen taxonomy and decision fields
# --------------------------------------------------------------------------- #


class Vertical(ResearchModel):
    vertical_id: str
    jurisdiction: Jurisdiction
    name: str
    sector: str
    scope: str | None = None
    taxonomy: tuple[str, ...]
    decision_fields: tuple[str, ...] = Field(default_factory=tuple)
    disclosures: tuple[str, ...] = Field(default_factory=tuple)
    provider_register_source_ids: tuple[str, ...] = Field(default_factory=tuple)
    product_data_source_ids: tuple[str, ...] = Field(default_factory=tuple)
    required_url_slots: tuple[str, ...] = Field(default_factory=tuple)
    priority_tier: str | None = None
    batch_rule: str | None = None
    coverage_risks: tuple[str, ...] = Field(default_factory=tuple)
    authority_for_recommendation: str

    @field_validator("taxonomy", "decision_fields", "disclosures", "provider_register_source_ids", "product_data_source_ids", "required_url_slots", "coverage_risks", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self) -> Vertical:
        if "unclassified" not in self.taxonomy:
            raise ValueError(f"vertical {self.vertical_id} taxonomy must end in unclassified")
        return self


class VerticalRegistry(ResearchModel):
    schema_id: str = Field(default=VERTICAL_REGISTRY_SCHEMA, alias="schema")
    derived_from: dict[str, Any] = Field(default_factory=dict)
    catalog_principles: tuple[str, ...] = Field(default_factory=tuple)
    scope_exclusions: tuple[str, ...] = Field(default_factory=tuple)
    confidence_rules: tuple[dict[str, Any], ...] = Field(default_factory=tuple)
    url_requirements: tuple[dict[str, Any], ...] = Field(default_factory=tuple)
    verticals: tuple[Vertical, ...]

    @field_validator("catalog_principles", "scope_exclusions", "confidence_rules", "url_requirements", "verticals", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _unique(self) -> VerticalRegistry:
        ids = [item.vertical_id for item in self.verticals]
        if len(ids) != len(set(ids)):
            raise ValueError("vertical ids must be unique")
        return self

    def vertical(self, vertical_id: str) -> Vertical:
        for item in self.verticals:
            if item.vertical_id == vertical_id:
                return item
        raise AdviceCatalogError("VERTICAL_UNKNOWN", f"{vertical_id} is not a registered vertical")

    def by_jurisdiction(self, jurisdiction: str) -> tuple[Vertical, ...]:
        return tuple(item for item in self.verticals if item.jurisdiction == jurisdiction)


_REGISTRY: VerticalRegistry | None = None


def load_vertical_registry() -> VerticalRegistry:
    """The packaged registry derived from the owner's master roadmap; parsed once."""

    global _REGISTRY
    if _REGISTRY is None:
        text = resources.files(DATA_PACKAGE).joinpath(VERTICALS_FILE).read_text(encoding="utf-8")
        _REGISTRY = VerticalRegistry.model_validate(json.loads(text))
    return _REGISTRY


# --------------------------------------------------------------------------- #
# Facts with sources
# --------------------------------------------------------------------------- #


class SourceCitation(ResearchModel):
    """Where a fact came from: the URL, when it was read, and what it said."""

    url: str
    retrieved_at: str
    document_title: str | None = None
    quote: str | None = None
    locator: str | None = None
    source_type: str | None = None
    source_id: str | None = None
    access_method: str | None = None
    publication_date: str | None = None
    effective_date_as_read: str | None = None

    @field_validator("url")
    @classmethod
    def _url(cls, value: str) -> str:
        if not value.startswith(("http://", "https://")):
            raise ValueError("a source citation names a resolvable URL")
        return value

    @field_validator("retrieved_at")
    @classmethod
    def _retrieved(cls, value: str) -> str:
        if not _DATE.match(value):
            raise ValueError("retrieved_at is a date or timestamp")
        return value

    @property
    def cited(self) -> bool:
        return bool(self.quote and self.quote.strip())


class PricingFact(ResearchModel):
    """One price the provider states, as stated: numeric when it was numeric, otherwise the text."""

    item: str
    value: Decimal | None = None
    value_as_stated: str | None = None
    unit: str | None = None
    unit_kind: UnitKind = "unstated"
    currency: str | None = None
    conditions: dict[str, Any] = Field(default_factory=dict)
    source_ids: tuple[str, ...] = Field(default_factory=tuple)
    quote: str | None = None
    support: Support = "unsupported"
    observed_at: str | None = None
    effective_from: str | None = None
    effective_to: str | None = None
    revalidated_at: str | None = None
    freshness: Freshness = "unstated"
    hold: str | None = None

    @field_validator("value", mode="before")
    @classmethod
    def _value(cls, value: Any) -> Decimal | None:
        return None if value is None else Decimal(str(value))

    @field_validator("source_ids", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @property
    def rankable(self) -> bool:
        """A fact can carry a ranking only when it is numeric, supported by a source, and fresh at the point of use."""

        return self.value is not None and self.support != "unsupported" and self.freshness in ("fresh", "unstated") and self.hold is None


class KeyTerm(ResearchModel):
    term: str
    value: Any = None
    source_ids: tuple[str, ...] = Field(default_factory=tuple)

    @field_validator("source_ids", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value


class Register(ResearchModel):
    register_name: str
    authority: str | None = None
    register_type: str | None = None
    jurisdiction: Jurisdiction | None = None
    url: str | None = None
    retrieved_at: str | None = None
    register_date: str | None = None
    entry_count: int | None = None
    entries_processed: int | None = None
    entries_unprocessed: int | None = None
    limitations: tuple[str, ...] = Field(default_factory=tuple)

    @field_validator("limitations", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value


class Provider(ResearchModel):
    """A legal entity on a register. Brands, issuers and distributors stay in their own fields."""

    provider_ref: OpaqueRef
    legal_name: str
    trading_names: tuple[str, ...] = Field(default_factory=tuple)
    register_identifier: str | None = None
    register_identifier_type: str | None = None
    licence_category: str | None = None
    registration_status: str | None = None
    register_name: str | None = None
    register_url: str | None = None
    retrieved_at: str | None = None
    sources: tuple[SourceCitation, ...] = Field(default_factory=tuple)
    gaps: tuple[str, ...] = Field(default_factory=tuple)
    product_discovery_status: str | None = None
    identity_only: bool = False
    as_stated_id: str | None = None
    legal_name_established: bool = True
    legal_name_status: str | None = None
    engine_eligible: bool | None = None

    @field_validator("trading_names", "sources", "gaps", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value


class Product(ResearchModel):
    """One product exactly as the provider declares it, decision field by decision field."""

    product_ref: OpaqueRef
    provider_ref: OpaqueRef
    provider_name: str
    issuer_legal_name: str | None = None
    product_name: str
    taxonomy_class: str
    classified: bool
    eligibility: tuple[str, ...] = Field(default_factory=tuple)
    pricing: tuple[PricingFact, ...] = Field(default_factory=tuple)
    key_terms: tuple[KeyTerm, ...] = Field(default_factory=tuple)
    effective_date: str | None = None
    pricing_kind: PricingKind = "unstated"
    pricing_kind_as_stated: str | None = None
    sources: tuple[SourceCitation, ...] = Field(default_factory=tuple)
    confidence: Confidence
    verification_basis: str | None = None
    availability_status: str | None = None
    gaps: tuple[str, ...] = Field(default_factory=tuple)
    as_stated_id: str | None = None
    engine_eligible: bool | None = None

    @field_validator("eligibility", "pricing", "key_terms", "sources", "gaps", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @property
    def rankable_pricing(self) -> tuple[PricingFact, ...]:
        return tuple(fact for fact in self.pricing if fact.rankable)

    def key_term(self, term: str) -> Any:
        for item in self.key_terms:
            if item.term == term:
                return item.value
        return None


class Coverage(ResearchModel):
    """How much of the register the run reached; a sample is never labelled complete."""

    vertical_id: str | None = None
    phase: str | None = None
    run_date: str | None = None
    providers_on_register: int | None = None
    providers_captured: int | None = None
    providers_with_products: int | None = None
    products_extracted: int | None = None
    products_verified: int | None = None
    products_single_source: int | None = None
    products_unverified: int | None = None
    census_complete: bool = False
    extraction_exhaustive: bool = False
    advice_engine_ready: bool | None = None
    published_as_of: str | None = None
    knowledge_at: str | None = None
    excluded: tuple[dict[str, Any], ...] = Field(default_factory=tuple)
    known_limitations: tuple[str, ...] = Field(default_factory=tuple)
    notes: tuple[str, ...] = Field(default_factory=tuple)

    @field_validator("excluded", "known_limitations", "notes", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value


class ProductCatalog(ResearchModel):
    schema_id: str = Field(default=CATALOG_SCHEMA, alias="schema")
    vertical_id: str
    jurisdiction: Jurisdiction
    run_date: str
    registers: tuple[Register, ...] = Field(default_factory=tuple)
    providers: tuple[Provider, ...] = Field(default_factory=tuple, max_length=MAX_PROVIDERS)
    products: tuple[Product, ...] = Field(default_factory=tuple, max_length=MAX_PRODUCTS)
    coverage: Coverage
    completeness: Completeness
    source_pack_digest: Sha256Digest
    catalog_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("registers", "providers", "products", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> ProductCatalog:
        refs = [item.provider_ref for item in self.providers]
        if len(refs) != len(set(refs)):
            raise ValueError("provider refs must be unique")
        product_refs = [item.product_ref for item in self.products]
        if len(product_refs) != len(set(product_refs)):
            raise ValueError("product refs must be unique")
        known = set(refs)
        for product in self.products:
            if product.provider_ref not in known:
                raise ValueError(f"product {product.product_name} names a provider outside the catalog")
        if self.completeness == "census_complete" and not self.coverage.census_complete:
            raise ValueError("a catalog is census_complete only when its coverage says so")
        if not skip_digests(info) and self.catalog_digest != sealed_digest(ProductCatalog, self, "catalog_digest"):
            raise ValueError("catalog_digest must commit the exact catalog")
        return self

    def provider(self, provider_ref: str) -> Provider:
        for item in self.providers:
            if item.provider_ref == provider_ref:
                return item
        raise AdviceCatalogError("PROVIDER_UNKNOWN", f"{provider_ref} is not in the catalog")

    def product(self, product_ref: str) -> Product:
        for item in self.products:
            if item.product_ref == product_ref:
                return item
        raise AdviceCatalogError("PRODUCT_UNKNOWN", f"{product_ref} is not in the catalog")

    def products_of(self, provider_ref: str) -> tuple[Product, ...]:
        return tuple(item for item in self.products if item.provider_ref == provider_ref)

    def in_class(self, taxonomy_class: str) -> tuple[Product, ...]:
        return tuple(item for item in self.products if item.taxonomy_class == taxonomy_class)


# --------------------------------------------------------------------------- #
# Ingest: the owner's pack format to a sealed catalog
# --------------------------------------------------------------------------- #


def provider_ref(jurisdiction: str, legal_name: str) -> str:
    return "provider:" + _sha256(f"{jurisdiction}|{legal_name.strip().lower()}")[:32]


def product_ref(jurisdiction: str, provider: str, product_name: str, taxonomy_class: str) -> str:
    return "product:" + _sha256(f"{jurisdiction}|{provider}|{product_name.strip().lower()}|{taxonomy_class}")[:32]


def _decimal(value: Any) -> Decimal | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float, Decimal)):
        try:
            parsed = Decimal(str(value))
        except InvalidOperation:
            return None
        return parsed if parsed.is_finite() else None
    if isinstance(value, str):
        cleaned = value.strip().replace(",", "").replace("$", "").rstrip("%")
        try:
            parsed = Decimal(cleaned)
        except InvalidOperation:
            return None
        return parsed if parsed.is_finite() else None
    return None


def unit_kind(unit: str | None) -> UnitKind:
    if unit is None:
        return "unstated"
    lower = unit.lower()
    if "p.a" in lower or "per_year" in lower or "per year" in lower or "percentage_points" in lower:
        return "rate_percent_per_year" if ("%" in lower or "percent" in lower) else "money_per_year"
    if "transaction" in lower or "withdrawal" in lower or "drawdown" in lower or "/service" in lower:
        return "percent_of_transaction" if ("%" in lower or "percent" in lower) else "money_per_transaction"
    if "/month" in lower or "per month" in lower:
        return "money_per_month"
    if "/year" in lower or "per year" in lower or "annual" in lower:
        return "money_per_year"
    if lower.startswith("%") or lower in ("percent", "pct") or "% of" in lower:
        return "percent"
    if re.fullmatch(r"[a-z]{3}( once-off)?", lower):
        return "money"
    return "other"


def _currency(unit: str | None, jurisdiction: str) -> str | None:
    if unit:
        match = re.match(r"^([A-Z]{3})\b", unit.strip())
        if match:
            return match.group(1)
        if unit.strip().startswith(("%", "percent")) or "p.a" in unit.lower():
            return None
    return _CURRENCY_BY_JURISDICTION.get(jurisdiction)


def _source(raw: Mapping[str, Any]) -> SourceCitation | None:
    url = _text(raw.get("url"))
    retrieved = _text(raw.get("retrieved_at"))
    if url is None or retrieved is None or not _DATE.match(retrieved) or not url.startswith(("http://", "https://")):
        return None
    return SourceCitation(url=url, retrieved_at=retrieved, document_title=_text(raw.get("document_title")), quote=_text(raw.get("quote") or raw.get("supporting_quote")), locator=_text(raw.get("locator")), source_type=_text(raw.get("source_type")), source_id=_text(raw.get("source_id")), access_method=_text(raw.get("access_method") or raw.get("retrieval_method")), publication_date=_text(raw.get("publication_date")), effective_date_as_read=_text(raw.get("effective_date_as_read")))


def _sources(raw: Any) -> tuple[SourceCitation, ...]:
    out: list[SourceCitation] = []
    for item in raw or ():
        if isinstance(item, Mapping):
            parsed = _source(item)
            if parsed is not None:
                out.append(parsed)
    return tuple(out)


def _flag(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in ("true", "false"):
        return value.strip().lower() == "true"
    return None


_UNRETRIEVED = ("failed", "empty_shell", "not_recovered", "not_retrieved", "pending")


def _ledger(pack: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    """The pack's evidence ledger: sources cited by id from products, facts and provider rows."""

    coverage = pack.get("coverage") if isinstance(pack.get("coverage"), Mapping) else {}
    out: dict[str, Mapping[str, Any]] = {}
    for candidate in (coverage.get("evidence_sources"), pack.get("evidence_sources"), pack.get("sources")):
        entries = candidate.values() if isinstance(candidate, Mapping) else (candidate or ())
        for entry in entries:
            if isinstance(entry, Mapping) and _text(entry.get("source_id")):
                out.setdefault(str(entry["source_id"]).strip(), entry)
    return out


def _ledger_citation(entry: Mapping[str, Any], quote_reference: str | None) -> SourceCitation | None:
    """A ledger entry as a citation; a placeholder or a failed retrieval supports nothing."""

    status = (_text(entry.get("retrieval_status")) or "").lower()
    if any(marker in status for marker in _UNRETRIEVED):
        return None
    quote = None
    if quote_reference:
        for item in entry.get("quotes") or ():
            if isinstance(item, Mapping) and _text(item.get("quote_id")) == quote_reference:
                quote = _text(item.get("exact_quote") or item.get("quote"))
                break
    return _source({"url": entry.get("url"), "retrieved_at": entry.get("retrieved_at"), "document_title": entry.get("title") or entry.get("document_title"), "quote": quote, "locator": entry.get("locator"), "source_type": entry.get("source_type"), "source_id": entry.get("source_id"), "access_method": entry.get("retrieval_status"), "publication_date": entry.get("source_date") or entry.get("publication_date")})


def _resolve_sources(raw: Mapping[str, Any], ledger: Mapping[str, Mapping[str, Any]]) -> tuple[SourceCitation, ...]:
    """Inline sources plus the ledger entries the row cites by id, the row's quote reference attached."""

    out: list[SourceCitation] = list(_sources(raw.get("sources")))
    reference = _text(raw.get("quote_reference"))
    for source_id in _strings(raw.get("source_ids") or raw.get("source_id")):
        entry = ledger.get(source_id)
        if entry is not None:
            citation = _ledger_citation(entry, reference)
            if citation is not None:
                out.append(citation)
    return _dedupe_sources(out)


def _dedupe_sources(sources: Sequence[SourceCitation]) -> tuple[SourceCitation, ...]:
    seen: set[tuple[str, str | None, str | None]] = set()
    out: list[SourceCitation] = []
    for source in sources:
        key = (source.url, source.quote, source.source_id)
        if key not in seen:
            seen.add(key)
            out.append(source)
    return tuple(out)


def _eligibility(raw: Any) -> tuple[str, ...]:
    """Eligibility as prose; a structured rule becomes ``field: value`` so nothing is lost or invented."""

    out: list[str] = []
    for item in raw or ():
        if isinstance(item, Mapping):
            field = _text(item.get("field") or item.get("term") or item.get("rule"))
            if field is None:
                continue
            value = _jsonable(item.get("value"))
            rendered = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, sort_keys=True)
            out.append(f"{field}: {rendered}")
        elif str(item).strip():
            out.append(str(item).strip())
    return tuple(out)


_RATE_STATUS_KIND: tuple[tuple[str, PricingKind], ...] = (("displayed", "list"), ("posted", "list"), ("conflicting", "list"), ("formula", "quoted"))


def _pricing_kind_from_items(raw: Any) -> tuple[PricingKind, str | None]:
    """When the product states no pricing kind, its priced items say how the price was shown."""

    statuses = [str(item.get("rate_status") or item.get("price_status")) for item in (raw or ()) if isinstance(item, Mapping) and (item.get("rate_status") or item.get("price_status"))]
    if not statuses:
        return "unstated", None
    stated = ", ".join(dict.fromkeys(statuses))
    for marker, kind in _RATE_STATUS_KIND:
        if any(marker in status.lower() for status in statuses):
            return kind, stated
    return "unstated", stated


_ITEM_CONDITION_KEYS = ("term_months", "term_years", "rate_type", "rate_tier", "variant", "effective_date", "expiry_date", "rate_status", "quoted_to_borrower", "offer_conditions", "conflict_group_id", "rate_formula", "is_selected_as_current_executable_price", "current_price_verified")


def _pricing_kind(raw: Any) -> tuple[PricingKind, str | None]:
    stated = None if raw is None else (", ".join(str(x) for x in raw) if isinstance(raw, list) else str(raw))
    if stated is None:
        return "unstated", None
    lower = stated.lower()
    if lower in ("list", "listed", "displayed_rate", "posted_rate", "posted_reference"):
        return "list", stated
    if "quote_required" in lower or "not_established" in lower:
        return "quote_required", stated
    if "quoted" in lower or "formula" in lower or "rate" in lower:
        return "quoted" if "quoted" in lower else "list", stated
    return "unstated", stated


def _confidence(raw: Any) -> Confidence:
    text = (_text(raw) or "unverified").lower()
    return text if text in ("verified", "single_source", "unverified") else "unverified"  # type: ignore[return-value]


def _fee_items(raw: Any, *, jurisdiction: str) -> list[dict[str, Any]]:
    """A fees mapping (``application_fee_cad: 300``) as priced items; a null fee states nothing."""

    if not isinstance(raw, Mapping):
        return []
    out: list[dict[str, Any]] = []
    for key, value in raw.items():
        amount = _decimal(value)
        if amount is None:
            continue
        name = str(key).strip().lower()
        currency = None
        for code in ("_cad", "_aud", "_usd"):
            if name.endswith(code):
                currency = code[1:].upper()
                name = name[: -len(code)]
        out.append({"item": name.replace("_", " "), "value": amount, "unit": currency or _CURRENCY_BY_JURISDICTION.get(jurisdiction)})
    return out


def _pricing(raw: Any, *, jurisdiction: str, product_sources: tuple[SourceCitation, ...], confidence: Confidence, ledger: Mapping[str, Mapping[str, Any]] | None = None) -> tuple[PricingFact, ...]:
    cited_product = any(source.cited for source in product_sources)
    source_ids = {source.source_id for source in product_sources if source.source_id}
    facts: list[PricingFact] = []
    expanded: list[Mapping[str, Any]] = []
    for item in raw or ():
        if not isinstance(item, Mapping):
            continue
        expanded.append(item)
        if item.get("apr_percent") is not None and item.get("interest_rate_percent") is not None:
            expanded.append({**{k: v for k, v in item.items() if k not in ("interest_rate_percent", "apr_percent")}, "item": "APR", "value": item.get("apr_percent"), "unit": "% p.a."})
    for item in expanded:
        name = _text(item.get("item"))
        if name is None:
            continue
        unit = _text(item.get("unit"))
        value = _decimal(item.get("value"))
        if value is None and item.get("interest_rate_percent") is not None:
            value = _decimal(item.get("interest_rate_percent"))
            unit = unit or "% p.a."
        elif value is None and item.get("value") is None and item.get("apr_percent") is not None:
            value = _decimal(item.get("apr_percent"))
            unit = unit or "% p.a."
            name = name if "apr" in name.lower() else "APR"
        conditions = item.get("conditions")
        if isinstance(conditions, Mapping):
            conditions_map = {str(k): _jsonable(v) for k, v in conditions.items()}
        elif conditions is None:
            conditions_map = {}
        else:
            conditions_map = {"note": str(conditions)}
        for key in _ITEM_CONDITION_KEYS:
            if item.get(key) is not None and key not in conditions_map:
                conditions_map[key] = _jsonable(item.get(key))
        ids = _strings(item.get("source_id") or item.get("source_ids"))
        quote = _text(item.get("supporting_quote") or item.get("quote"))
        reference = _text(item.get("quote_reference"))
        if quote is None and reference and ledger:
            for source_id in ids:
                entry = ledger.get(source_id)
                citation = _ledger_citation(entry, reference) if entry is not None else None
                if citation is not None and citation.quote:
                    quote = citation.quote
                    break
        if value is None and item.get("rate_formula"):
            stated_value = _text(item.get("rate_formula"))
        else:
            stated_value = None if value is not None else _text(item.get("value"))
        if ids and (set(ids) & source_ids) and (quote or cited_product):
            support: Support = "fact_cited"
        elif product_sources and (cited_product or confidence != "unverified"):
            support = "product_cited"
        else:
            support = "unsupported"
        facts.append(PricingFact(item=name, value=value, value_as_stated=stated_value, unit=unit, unit_kind=unit_kind(unit), currency=_currency(unit, jurisdiction), conditions=conditions_map, source_ids=ids, quote=quote, support=support))
    return tuple(facts)


def _key_terms(raw: Any) -> tuple[KeyTerm, ...]:
    out: list[KeyTerm] = []
    for item in raw or ():
        if isinstance(item, Mapping) and _text(item.get("term") or item.get("field")):
            out.append(KeyTerm(term=str(item.get("term") or item.get("field")).strip(), value=_jsonable(item.get("value")), source_ids=_strings(item.get("source_ids") or item.get("source_id"))))
    return tuple(out)


def engine_eligible(product: Product, catalog: ProductCatalog) -> bool:
    """A record ranks only when nothing that carries it says otherwise: the product, then its provider row, then the pack's own readiness verdict."""

    if product.engine_eligible is not None:
        return product.engine_eligible
    owner = next((item for item in catalog.providers if item.provider_ref == product.provider_ref), None)
    if owner is not None and owner.engine_eligible is not None:
        return owner.engine_eligible
    return catalog.coverage.advice_engine_ready is not False


def provider_identity_name(raw: Mapping[str, Any]) -> tuple[str | None, bool, str | None]:
    """The name a provider row is keyed on: its legal name, else the register's displayed entry, flagged as not established."""

    status = _text(raw.get("legal_name_status"))
    legal = _text(raw.get("legal_name"))
    if legal is not None:
        established = not (status and ("not_established" in status or "provisional" in status))
        return legal, established, status
    row_ref = raw.get("register_row_ref") if isinstance(raw.get("register_row_ref"), Mapping) else {}
    displayed = _text(raw.get("register_name_as_displayed") or row_ref.get("entry_name_as_displayed") or raw.get("provider_name"))
    if displayed is None:
        return None, False, status
    return displayed, False, status or "legal_name_not_stated; register-displayed entry used"


def _register(raw: Mapping[str, Any]) -> Register | None:
    name = _text(raw.get("register_name"))
    if name is None:
        return None
    count = raw.get("entry_count_reported")
    if count is None:
        calculated = raw.get("entry_count_calculated") or raw.get("entry_count_observed") or raw.get("entries_counted")
        count = calculated if isinstance(calculated, int) else (calculated.get("total") if isinstance(calculated, Mapping) and isinstance(calculated.get("total"), int) else None)
    limitations = _strings(raw.get("limitations")) + _strings(raw.get("unprocessed_reasons"))
    return Register(register_name=name, authority=_text(raw.get("authority")), register_type=_text(raw.get("register_type")), jurisdiction=_jurisdiction(raw.get("jurisdiction")), url=_text(raw.get("url")), retrieved_at=_text(raw.get("retrieved_at")), register_date=_text(raw.get("register_date") or raw.get("publication_date") or raw.get("page_date")), entry_count=count if isinstance(count, int) else None, entries_processed=raw.get("entries_processed") if isinstance(raw.get("entries_processed"), int) else None, entries_unprocessed=raw.get("entries_unprocessed") if isinstance(raw.get("entries_unprocessed"), int) else None, limitations=limitations)


def _coverage(raw: Mapping[str, Any], *, run_date: str) -> Coverage:
    def count(*keys: str) -> int | None:
        for key in keys:
            value = raw.get(key)
            if isinstance(value, int) and not isinstance(value, bool):
                return value
        return None

    excluded = tuple({str(k): _jsonable(v) for k, v in item.items()} for item in (raw.get("excluded") or ()) if isinstance(item, Mapping))
    return Coverage(vertical_id=_text(raw.get("vertical_id")), phase=_text(raw.get("phase") or raw.get("catalog_status")), run_date=_text(raw.get("run_date")) or run_date, providers_on_register=count("providers_on_register"), providers_captured=count("providers_captured"), providers_with_products=count("providers_with_products_extracted", "providers_with_products"), products_extracted=count("products_extracted"), products_verified=count("products_verified"), products_single_source=count("products_single_source"), products_unverified=count("products_unverified"), census_complete=raw.get("complete_national_provider_census") is True, extraction_exhaustive=raw.get("product_extraction_exhaustive") is True, advice_engine_ready=_flag(raw.get("advice_engine_ready")), excluded=excluded, known_limitations=_strings(raw.get("known_limitations")) + _strings(raw.get("global_limitations")), notes=_strings(raw.get("fixture_note")) + _strings(raw.get("providers_captured_definition")) + _strings(raw.get("run_date_scope")) + _strings(raw.get("product_count_definition")))


def ingest_catalog_pack(payload: Mapping[str, Any] | Any, *, vertical_id: str | None = None, jurisdiction: str | None = None, registry: VerticalRegistry | None = None) -> ProductCatalog:
    """The owner's ``{registers, providers, products, coverage}`` pack as a sealed catalog.

    Nothing is inferred beyond what the pack states: an unregistered vertical is refused, an
    unknown taxonomy class becomes ``unclassified`` with ``classified = False``, a fact without a
    citation is ``unsupported``, and a capped run is ``partial_sample``.
    """

    pack = dict(detached(payload))
    _require(isinstance(pack.get("providers"), list) and isinstance(pack.get("products"), list), "PACK_SHAPE_INVALID", "a catalog pack carries providers and products lists")
    registry = registry or load_vertical_registry()
    coverage_raw = pack.get("coverage") if isinstance(pack.get("coverage"), Mapping) else {}
    registers_raw = [item for item in (pack.get("registers") or ()) if isinstance(item, Mapping)]
    resolved_jurisdiction = _jurisdiction(jurisdiction) or _jurisdiction(coverage_raw.get("jurisdiction")) or next((_jurisdiction(item.get("jurisdiction")) for item in registers_raw if _jurisdiction(item.get("jurisdiction"))), None)
    _require(resolved_jurisdiction is not None, "JURISDICTION_UNKNOWN", "the pack names no jurisdiction; pass jurisdiction explicitly")
    assert resolved_jurisdiction is not None
    resolved_vertical = _text(vertical_id) or _text(coverage_raw.get("vertical_id"))
    _require(resolved_vertical is not None, "CATALOG_VERTICAL_UNKNOWN", "the pack names no vertical_id; pass vertical_id explicitly")
    assert resolved_vertical is not None
    vertical = registry.vertical(resolved_vertical)
    _require(vertical.jurisdiction == resolved_jurisdiction, "VERTICAL_JURISDICTION_MISMATCH", f"{resolved_vertical} is a {vertical.jurisdiction} vertical, the pack is {resolved_jurisdiction}")
    run_date = _text(coverage_raw.get("run_date")) or next((_text(item.get("retrieved_at")) for item in registers_raw if _text(item.get("retrieved_at"))), None) or "1970-01-01"

    ledger = _ledger(pack)
    providers: dict[str, Provider] = {}
    aliases: dict[str, str] = {}
    by_stated_id: dict[str, str] = {}
    for raw in pack["providers"]:
        if not isinstance(raw, Mapping):
            continue
        stated_legal = _text(raw.get("legal_name"))
        legal_name, established, status = provider_identity_name(raw)
        if legal_name is None:
            continue
        ref = provider_ref(resolved_jurisdiction, legal_name)
        if ref in providers:
            continue
        trading = _strings(raw.get("trading_names"))
        brand = _text(raw.get("provider_name"))
        if brand and brand.lower() != legal_name.lower() and brand not in trading:
            trading = trading + (brand,)
        review = raw.get("review_status")
        identity_only = raw.get("record_type") == "census_identity_dossier" or (isinstance(review, str) and review.startswith("census_identity"))
        row_ref = raw.get("register_row_ref") if isinstance(raw.get("register_row_ref"), Mapping) else {}
        providers[ref] = Provider(provider_ref=ref, legal_name=legal_name, trading_names=trading, register_identifier=_text(raw.get("register_identifier") or raw.get("provider_register_id") or raw.get("register_id") or raw.get("cdic_member_id")), register_identifier_type=_text(raw.get("register_identifier_type") or raw.get("register_id_type") or raw.get("cdic_member_id_namespace")), licence_category=_text(raw.get("licence_category") or raw.get("approval_category")), registration_status=_text(raw.get("registration_status")), register_name=_text(raw.get("register_name") or row_ref.get("register_key")), register_url=_text(raw.get("register_url")), retrieved_at=_text(raw.get("retrieved_at")), sources=_resolve_sources(raw, ledger), gaps=_strings(raw.get("gaps")), product_discovery_status=_text(raw.get("product_discovery_status") or raw.get("disposition")), identity_only=bool(identity_only), as_stated_id=_text(raw.get("catalog_provider_id") or raw.get("provider_key")), legal_name_established=established and stated_legal is not None, legal_name_status=status, engine_eligible=_flag(raw.get("advice_engine_eligible")))
        aliases[legal_name.lower()] = ref
        for name in trading:
            aliases.setdefault(name.lower(), ref)
        for key in ("provider_key", "catalog_provider_id", "canonical_provider_key"):
            if _text(raw.get(key)):
                by_stated_id.setdefault(str(raw[key]).strip(), ref)

    products: dict[str, Product] = {}
    for raw in pack["products"]:
        if not isinstance(raw, Mapping):
            continue
        name = _text(raw.get("product_name"))
        stated_provider = _text(raw.get("provider_legal_name") or raw.get("provider_name"))
        if name is None or stated_provider is None:
            continue
        owner = next((by_stated_id[str(raw[key]).strip()] for key in ("provider_key", "catalog_provider_id", "provider_ref") if _text(raw.get(key)) and str(raw[key]).strip() in by_stated_id), None)
        owner = owner or aliases.get(stated_provider.lower()) or aliases.get((_text(raw.get("provider_name")) or "").lower()) or aliases.get((_text(raw.get("issuer_legal_name")) or "").lower())
        if owner is None:
            # a product whose provider is not on the register section is kept under a provider row of its own, flagged
            owner = provider_ref(resolved_jurisdiction, stated_provider)
            providers.setdefault(owner, Provider(provider_ref=owner, legal_name=stated_provider, registration_status="not_on_captured_register_section", gaps=("provider row absent from the pack's register section; attributed from the product's own provider name",)))
            aliases[stated_provider.lower()] = owner
        taxonomy_class = _text(raw.get("taxonomy_class")) or "unclassified"
        classified = taxonomy_class in vertical.taxonomy and taxonomy_class != "unclassified"
        if taxonomy_class not in vertical.taxonomy:
            taxonomy_class = "unclassified"
        ref = product_ref(resolved_jurisdiction, owner, name, taxonomy_class)
        if ref in products:
            continue
        confidence = _confidence(raw.get("confidence"))
        priced_items = [item for item in (raw.get("pricing") or ()) if isinstance(item, Mapping)] + _fee_items(raw.get("fees"), jurisdiction=resolved_jurisdiction)
        cited_rows = [raw] + priced_items + [item for key in ("key_terms", "eligibility") for item in (raw.get(key) or ()) if isinstance(item, Mapping)]
        sources = _dedupe_sources([source for row in cited_rows for source in _resolve_sources(row, ledger)])
        kind, kind_stated = _pricing_kind(raw.get("pricing_kind"))
        if kind == "unstated" and kind_stated is None:
            kind, kind_stated = _pricing_kind_from_items(raw.get("pricing"))
        products[ref] = Product(product_ref=ref, provider_ref=owner, provider_name=stated_provider, issuer_legal_name=_text(raw.get("issuer_legal_name")), product_name=name, taxonomy_class=taxonomy_class, classified=classified, eligibility=_eligibility(raw.get("eligibility")), pricing=_pricing(priced_items, jurisdiction=resolved_jurisdiction, product_sources=sources, confidence=confidence, ledger=ledger), key_terms=_key_terms(raw.get("key_terms")), effective_date=_text(raw.get("effective_date")), pricing_kind=kind, pricing_kind_as_stated=kind_stated, sources=sources, confidence=confidence, verification_basis=_text(raw.get("verification_basis") or raw.get("confidence_basis") or raw.get("verification_scope")), availability_status=_text(raw.get("availability_status")), gaps=_strings(raw.get("gaps")), as_stated_id=_text(raw.get("catalog_product_id") or raw.get("product_id")), engine_eligible=_flag(raw.get("advice_engine_eligible")))

    coverage = _coverage(coverage_raw, run_date=run_date)
    if not products and all(item.identity_only for item in providers.values()) and providers:
        completeness: Completeness = "identity_only"
    elif coverage.census_complete and coverage.extraction_exhaustive:
        completeness = "census_complete"
    else:
        completeness = "partial_sample"
    registers = tuple(item for item in (_register(raw) for raw in registers_raw) if item is not None)
    return seal(ProductCatalog, {"vertical_id": resolved_vertical, "jurisdiction": resolved_jurisdiction, "run_date": run_date, "registers": [item.to_dict() for item in registers], "providers": [item.to_dict() for item in providers.values()], "products": [item.to_dict() for item in products.values()], "coverage": coverage.to_dict(), "completeness": completeness, "source_pack_digest": _sha256(json.dumps(_jsonable(pack), sort_keys=True, separators=(",", ":"), ensure_ascii=False))}, "catalog_digest")


def _merge_provider(existing: Provider | None, incoming: Provider) -> Provider:
    """The later row wins its fields; what only one batch established is kept, and a verdict the batches disagree on is unstated."""

    if existing is None:
        return incoming
    established = existing if existing.legal_name_established else (incoming if incoming.legal_name_established else None)
    verdicts = {existing.engine_eligible, incoming.engine_eligible}  # silence is a different answer, not an abstention
    return incoming.model_copy(update={
        "trading_names": tuple(dict.fromkeys(existing.trading_names + incoming.trading_names)),
        "sources": _dedupe_sources(existing.sources + incoming.sources),
        "gaps": tuple(dict.fromkeys(existing.gaps + incoming.gaps)),
        "identity_only": existing.identity_only and incoming.identity_only,
        "legal_name_established": established is not None,
        "legal_name_status": established.legal_name_status if established is not None else incoming.legal_name_status,
        "engine_eligible": next(iter(verdicts)) if len(verdicts) == 1 else None,
        "register_identifier": incoming.register_identifier or existing.register_identifier,
        "register_identifier_type": incoming.register_identifier_type or existing.register_identifier_type,
        "licence_category": incoming.licence_category or existing.licence_category,
        "registration_status": incoming.registration_status or existing.registration_status,
    })


def merge_catalogs(*catalogs: ProductCatalog | Mapping[str, Any]) -> ProductCatalog:
    """Batches of one vertical as one catalog: refs union, the later run wins a duplicate, coverage counts add."""

    parsed = [item if isinstance(item, ProductCatalog) else ProductCatalog.model_validate(dict(detached(item))) for item in catalogs]
    _require(bool(parsed), "MERGE_EMPTY", "merge at least one catalog")
    first = parsed[0]
    for item in parsed[1:]:
        _require(item.vertical_id == first.vertical_id and item.jurisdiction == first.jurisdiction, "MERGE_VERTICAL_MISMATCH", "only batches of one vertical and jurisdiction merge")
    ordered = sorted(parsed, key=lambda item: item.run_date)
    providers: dict[str, Provider] = {}
    products: dict[str, Product] = {}
    registers: dict[str, Register] = {}
    limitations: list[str] = []
    notes: list[str] = []
    excluded: list[dict[str, Any]] = []
    counts: dict[str, int] = {}
    census = True
    exhaustive = True
    for item in ordered:
        for provider in item.providers:
            providers[provider.provider_ref] = _merge_provider(providers.get(provider.provider_ref), provider)
        for product in item.products:
            products[product.product_ref] = product
        for register in item.registers:
            registers[register.register_name] = register
        limitations.extend(item.coverage.known_limitations)
        notes.extend(item.coverage.notes)
        excluded.extend(item.coverage.excluded)
        for key in ("providers_captured", "providers_with_products", "products_extracted", "products_verified", "products_single_source", "products_unverified"):
            value = getattr(item.coverage, key)
            if value is not None:
                counts[key] = counts.get(key, 0) + value
        census = census and item.coverage.census_complete
        exhaustive = exhaustive and item.coverage.extraction_exhaustive
    on_register = max((item.coverage.providers_on_register or 0 for item in ordered), default=0) or None
    verdicts = {item.coverage.advice_engine_ready for item in ordered}
    ready = next(iter(verdicts)) if len(verdicts) == 1 else None
    coverage = Coverage(vertical_id=first.vertical_id, phase="merged_batches", run_date=ordered[-1].run_date, providers_on_register=on_register, census_complete=census, extraction_exhaustive=exhaustive, advice_engine_ready=ready, excluded=tuple(excluded), known_limitations=tuple(dict.fromkeys(limitations)), notes=tuple(dict.fromkeys(notes + [f"merged {len(ordered)} batch(es)"])), **counts)
    completeness: Completeness = "census_complete" if census and exhaustive else ("identity_only" if not products and providers else "partial_sample")
    return seal(ProductCatalog, {"vertical_id": first.vertical_id, "jurisdiction": first.jurisdiction, "run_date": ordered[-1].run_date, "registers": [item.to_dict() for item in registers.values()], "providers": [item.to_dict() for item in providers.values()], "products": [item.to_dict() for item in products.values()], "coverage": coverage.to_dict(), "completeness": completeness, "source_pack_digest": _sha256("|".join(item.source_pack_digest for item in ordered))}, "catalog_digest")


def catalog_summary(catalog: ProductCatalog | Mapping[str, Any]) -> dict[str, Any]:
    parsed = catalog if isinstance(catalog, ProductCatalog) else ProductCatalog.model_validate(dict(detached(catalog)))
    by_class: dict[str, int] = {}
    by_confidence: dict[str, int] = {}
    rankable = 0
    facts = 0
    for product in parsed.products:
        by_class[product.taxonomy_class] = by_class.get(product.taxonomy_class, 0) + 1
        by_confidence[product.confidence] = by_confidence.get(product.confidence, 0) + 1
        facts += len(product.pricing)
        rankable += len(product.rankable_pricing)
    without_products = [item.legal_name for item in parsed.providers if not parsed.products_of(item.provider_ref)]
    return {"schema": CATALOG_SUMMARY_SCHEMA, "vertical_id": parsed.vertical_id, "jurisdiction": parsed.jurisdiction, "run_date": parsed.run_date, "completeness": parsed.completeness, "providers": len(parsed.providers), "providers_without_products": len(without_products), "products": len(parsed.products), "by_class": dict(sorted(by_class.items())), "by_confidence": dict(sorted(by_confidence.items())), "pricing_facts": facts, "rankable_pricing_facts": rankable, "coverage": {"providers_on_register": parsed.coverage.providers_on_register, "providers_captured": parsed.coverage.providers_captured, "census_complete": parsed.coverage.census_complete, "extraction_exhaustive": parsed.coverage.extraction_exhaustive}, "catalog_digest": parsed.catalog_digest}


def load_fixture_catalog(name: str, **overrides: Any) -> ProductCatalog:
    """A trimmed research pack shipped for tests, ingested exactly as a live pack would be."""

    file = FIXTURE_FILES.get(name)
    if file is None:
        raise KeyError(f"unknown advice fixture {name!r}; known: {sorted(FIXTURE_FILES)}")
    text = resources.files(FIXTURE_PACKAGE).joinpath(file).read_text(encoding="utf-8")
    return ingest_catalog_pack(json.loads(text), **overrides)


ADVICE_CATALOG_MANIFEST: dict[str, Any] = {
    "kind": ADVICE_CATALOG_KIND,
    "schemas": [CATALOG_SCHEMA, VERTICAL_REGISTRY_SCHEMA, CATALOG_SUMMARY_SCHEMA],
    "fixtures": sorted(FIXTURE_FILES),
    "hard_rules": [
        "register first; provider declarations second; third parties only as pointers",
        "legal entity, brand, product issuer, underwriter, distributor and custodian stay in separate fields",
        "every product fact carries a URL, a retrieval date and a supporting quotation, or it is unsupported and never ranked on",
        "list pricing and quote-dependent pricing are distinct",
        "a missing or conflicting field stays null and is recorded as a gap",
        "a class outside the vertical's fixed taxonomy is unclassified, never silently reclassified",
        "a capped run is a partial sample; a catalog is census_complete only when its coverage says so",
        "the catalog contains facts; person-specific ranking and recommendation happen downstream",
    ],
}

__all__ = [
    "ADVICE_CATALOG_KIND",
    "ADVICE_CATALOG_MANIFEST",
    "CATALOG_SCHEMA",
    "CATALOG_SUMMARY_SCHEMA",
    "FIXTURE_FILES",
    "VERTICAL_REGISTRY_SCHEMA",
    "AdviceCatalogError",
    "Coverage",
    "KeyTerm",
    "PricingFact",
    "Product",
    "ProductCatalog",
    "ResearchModel",
    "reject_credential_payload",
    "Provider",
    "Register",
    "SourceCitation",
    "Vertical",
    "VerticalRegistry",
    "catalog_summary",
    "ingest_catalog_pack",
    "provider_identity_name",
    "load_fixture_catalog",
    "load_vertical_registry",
    "merge_catalogs",
    "product_ref",
    "provider_ref",
    "unit_kind",
]
