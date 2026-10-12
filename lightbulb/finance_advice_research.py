"""Advice research: the register-first search and extraction of provider policies, planned and kept honest.

The catalog an advice business reasons over is built the way the owner's roadmap builds it:
freeze the vertical and its taxonomy, enumerate the authoritative registers, walk the register in
capped batches, discover structured product data before documents, collect primary disclosures
in trust order, extract decision fields, assign confidence by rule, and report coverage that
never calls a sample a census.

The SDK composes that work; it performs none of it. A :class:`CensusPlan` names the batches; an
:class:`ExtractionRequest` is a machine-runnable request for the platform's research tool aimed
at one provider; :func:`normalize_policy_findings` captures what came back as leads that are
always ``verification_required``; :func:`promote_findings_to_product` is the human step that
turns a lead into a catalog product, and it refuses a fact without a URL, a retrieval date and a
supporting quotation, a third-party source, and a confidence the evidence does not earn.
"""

from __future__ import annotations

import hashlib
import re
import json
import math
from collections.abc import Mapping, Sequence
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.finance_advice_catalog import engine_eligible
from lightbulb.finance_advice_catalog import (
    Confidence,
    load_vertical_registry,
    ProductCatalog,
    provider_ref,
    ResearchModel,
    Vertical,
    VerticalRegistry,
)
from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    BoundedText,
    OpaqueRef,
    Sha256Digest,
    ShortText,
    StrictModel,
    detached,
    parsed,
    seal,
    sealed_digest,
    skip_digests,
    timestamp,
)

ADVICE_RESEARCH_KIND = "lightbulb.finance_advice_research"
RESEARCH_TOOL = "deep_research.research_query"
CENSUS_PLAN_SCHEMA = "lightbulb.finance_advice_census_plan.v1"
EXTRACTION_REQUEST_SCHEMA = "lightbulb.finance_advice_extraction_request.v1"
POLICY_FINDINGS_SCHEMA = "lightbulb.finance_advice_policy_findings.v1"
FACT_PROMOTION_SCHEMA = "lightbulb.finance_advice_fact_promotion.v1"
PACK_BRIEF_SCHEMA = "lightbulb.finance_advice_pack_brief.v1"
DRAFT_REVIEW_SCHEMA = "lightbulb.finance_advice_draft_review.v1"
DRAFT_BASIS = "draft_from_research_findings; analyst promotion required"
DRAFT_PHASE = "draft_pack_pending_promotion"
RESEARCH_QUEUE_SCHEMA = "lightbulb.finance_advice_research_queue.v1"
PACK_FILE_PATTERN = "<country>_<vertical_slug>_batch_<NN>_catalog_<YYYY-MM-DD>.json"
REFRESH_PLAN_SCHEMA = "lightbulb.finance_advice_refresh_plan.v1"
DEFAULT_BATCH_CAP = 15
MAX_FINDINGS_CHARS = 8000

# Sources that may point at a fact but never support one (roadmap step 6).
THIRD_PARTY_SOURCE_TYPES = frozenset({"comparison_site", "aggregator", "news", "blog", "forum", "third_party", "review_site", "social"})
FIRST_PARTY_SOURCE_TYPES = frozenset({"structured_product_feed", "provider_web_page", "government_product_database", "regulator_register", "government_approval_register", "provider_product_page", "provider_rate_schedule", "provider_fee_schedule", "mandated_disclosure", "target_market_document", "provider_terms", "provider_faq", "web_page_text"})

FindingsStatus = Literal["completed", "empty"]
_DISCLAIMER = "Findings are leads captured verbatim from research; nothing here is a catalog fact until a person promotes it with a source URL, a retrieval date and a supporting quotation, and it is never a recommendation."


class AdviceResearchError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise AdviceResearchError(code, message)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _clean(text: str) -> str:
    return "".join(character if ord(character) >= 32 or character in "\n\t\r" else " " for character in text).strip()


# --------------------------------------------------------------------------- #
# The census plan: walk the register in capped, ordered batches
# --------------------------------------------------------------------------- #


class CensusBatch(ResearchModel):
    batch_id: ShortText
    register_name: ShortText
    start_ordinal: int = Field(ge=1)
    end_ordinal: int = Field(ge=1)
    status: Literal["planned"] = "planned"

    @model_validator(mode="after")
    def _guard(self) -> CensusBatch:
        if self.end_ordinal < self.start_ordinal:
            raise ValueError("a batch ends at or after it starts")
        return self


class CensusPlan(ResearchModel):
    schema_id: str = Field(default=CENSUS_PLAN_SCHEMA, alias="schema")
    vertical_id: str
    jurisdiction: Literal["AU", "CA"]
    taxonomy: tuple[str, ...]
    register_source_ids: tuple[str, ...] = Field(default_factory=tuple)
    product_data_source_ids: tuple[str, ...] = Field(default_factory=tuple)
    register_name: ShortText
    entry_count: int | None = Field(default=None, ge=0)
    batch_cap: int = Field(ge=1, le=100)
    batches: tuple[CensusBatch, ...] = Field(default_factory=tuple)
    required_url_slots: tuple[str, ...] = Field(default_factory=tuple)
    deliverable: BoundedText
    notes: tuple[str, ...] = Field(default_factory=tuple)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("taxonomy", "register_source_ids", "product_data_source_ids", "batches", "required_url_slots", "notes", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> CensusPlan:
        if not skip_digests(info) and self.plan_digest != sealed_digest(CensusPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact census plan")
        return self


def plan_census(vertical_id: str, *, register_name: str, register_entry_count: int | None = None, batch_cap: int = DEFAULT_BATCH_CAP, registry: VerticalRegistry | None = None) -> CensusPlan:
    """Batches of ``batch_cap`` register-ordered providers; an unknown entry count plans one batch and says so."""

    registry = registry or load_vertical_registry()
    vertical = registry.vertical(vertical_id)
    notes: list[str] = []
    if register_entry_count is None:
        batches = [CensusBatch(batch_id=f"{vertical_id}-CENSUS-01", register_name=register_name, start_ordinal=1, end_ordinal=batch_cap)]
        notes.append("the register's entry count is not yet established; plan the remaining batches after the first batch reports it")
    else:
        count = max(1, math.ceil(register_entry_count / batch_cap)) if register_entry_count else 0
        batches = [CensusBatch(batch_id=f"{vertical_id}-CENSUS-{index:02d}", register_name=register_name, start_ordinal=(index - 1) * batch_cap + 1, end_ordinal=min(index * batch_cap, register_entry_count)) for index in range(1, count + 1)]
        if register_entry_count == 0:
            notes.append("the register section reports no entries; nothing to census")
    notes.append("no provider discovery through ordinary web search before register coverage is documented")
    return seal(CensusPlan, {"vertical_id": vertical_id, "jurisdiction": vertical.jurisdiction, "taxonomy": list(vertical.taxonomy), "register_source_ids": list(vertical.provider_register_source_ids), "product_data_source_ids": list(vertical.product_data_source_ids), "register_name": register_name, "entry_count": register_entry_count, "batch_cap": batch_cap, "batches": [batch.to_dict() for batch in batches], "required_url_slots": list(vertical.required_url_slots), "deliverable": "Complete provider census; one JSON product object per product; provider/source URL manifest; coverage statement; exclusions and gaps.", "notes": notes}, "plan_digest")


# --------------------------------------------------------------------------- #
# Extraction requests: one provider, the platform's research tool, the roadmap's trust order
# --------------------------------------------------------------------------- #


class UrlSlot(ResearchModel):
    slot_id: ShortText
    url_type: ShortText
    trust_order: int = Field(ge=1, le=9)
    requirement: ShortText
    capture_field: ShortText


class ExtractionRequest(ResearchModel):
    schema_id: str = Field(default=EXTRACTION_REQUEST_SCHEMA, alias="schema")
    vertical_id: str
    jurisdiction: Literal["AU", "CA"]
    provider_ref: OpaqueRef
    provider_legal_name: ShortText
    target_tool: ShortText = RESEARCH_TOOL
    query: str = Field(min_length=1, max_length=1200)
    taxonomy: tuple[str, ...]
    decision_fields: tuple[str, ...] = Field(default_factory=tuple)
    url_slots: tuple[UrlSlot, ...] = Field(default_factory=tuple)
    disclaimer: str = _DISCLAIMER
    request_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("taxonomy", "decision_fields", "url_slots", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> ExtractionRequest:
        if not skip_digests(info) and self.request_digest != sealed_digest(ExtractionRequest, self, "request_digest"):
            raise ValueError("request_digest must commit the exact request")
        return self


def _url_slots(registry: VerticalRegistry, vertical: Vertical) -> list[UrlSlot]:
    wanted = set(vertical.required_url_slots)
    slots: list[UrlSlot] = []
    for raw in registry.url_requirements:
        slot_id = str(raw.get("slot_id", ""))
        if wanted and slot_id not in wanted:
            continue
        try:
            slots.append(UrlSlot(slot_id=slot_id, url_type=str(raw.get("url_type", "")), trust_order=int(raw.get("trust_order", 3)), requirement=str(raw.get("requirement", "")), capture_field=str(raw.get("capture_field", ""))))
        except Exception:  # noqa: BLE001 - a malformed registry row is skipped, never guessed
            continue
    return sorted(slots, key=lambda slot: (slot.trust_order, slot.slot_id))


def _query(vertical: Vertical, provider_legal_name: str, slots: Sequence[UrlSlot]) -> str:
    country = "Australia" if vertical.jurisdiction == "AU" else "Canada"
    fields = "; ".join(vertical.decision_fields[:12])
    classes = ", ".join(cls for cls in vertical.taxonomy if cls != "unclassified")
    slot_text = "; ".join(f"{slot.slot_id} {slot.url_type} ({slot.requirement})" for slot in slots[:8])
    text = (
        f"For the {country} provider '{provider_legal_name}', enumerate every current retail {vertical.name.lower()} product it declares as issuer. "
        f"Use only the provider's own pages, mandated disclosures, rate and fee schedules or a structured product feed; comparison sites and news are pointers only. "
        f"For each product return: legal issuer, product name, one class from [{classes}] or unclassified with a reason, and these decision fields exactly as stated: {fields}. "
        f"For every fact give the source URL, the retrieval date, the document title and a verbatim supporting quotation; leave a field null when it is not stated. "
        f"Distinguish list pricing from quote-dependent pricing and record effective dates. Capture these URL slots: {slot_text}."
    )
    return text[:1200].rstrip()


def compose_extraction_requests(vertical_id: str, provider_legal_names: Sequence[str], *, registry: VerticalRegistry | None = None, batch_cap: int = DEFAULT_BATCH_CAP) -> tuple[ExtractionRequest, ...]:
    """One request per provider, at most ``batch_cap`` per call, each aimed at the platform's research tool."""

    registry = registry or load_vertical_registry()
    vertical = registry.vertical(vertical_id)
    names = [name.strip() for name in provider_legal_names if name and name.strip()]
    _require(bool(names), "PROVIDERS_MISSING", "name at least one provider from the register")
    _require(len(names) <= batch_cap, "BATCH_CAP_EXCEEDED", f"at most {batch_cap} providers per batch; stop and report cumulative coverage between batches")
    slots = _url_slots(registry, vertical)
    requests: list[ExtractionRequest] = []
    for name in names:
        requests.append(seal(ExtractionRequest, {"vertical_id": vertical_id, "jurisdiction": vertical.jurisdiction, "provider_ref": provider_ref(vertical.jurisdiction, name), "provider_legal_name": name, "target_tool": RESEARCH_TOOL, "query": _query(vertical, name, slots), "taxonomy": list(vertical.taxonomy), "decision_fields": list(vertical.decision_fields), "url_slots": [slot.to_dict() for slot in slots]}, "request_digest"))
    return tuple(requests)


def requests_for_catalog(catalog: ProductCatalog | Mapping[str, Any], *, registry: VerticalRegistry | None = None, only_without_products: bool = True, batch_cap: int = DEFAULT_BATCH_CAP) -> tuple[ExtractionRequest, ...]:
    """Extraction requests for the catalog's providers that still have no products (or all of them)."""

    c = catalog if isinstance(catalog, ProductCatalog) else ProductCatalog.model_validate(dict(detached(catalog)))
    names = [item.legal_name for item in c.providers if not only_without_products or not c.products_of(item.provider_ref)]
    if not names:
        return ()
    return compose_extraction_requests(c.vertical_id, names[:batch_cap], registry=registry, batch_cap=batch_cap)


# --------------------------------------------------------------------------- #
# Findings: verbatim leads, always verification_required
# --------------------------------------------------------------------------- #


class PolicyFindings(ResearchModel):
    schema_id: str = Field(default=POLICY_FINDINGS_SCHEMA, alias="schema")
    request_digest: Sha256Digest
    provider_ref: OpaqueRef
    vertical_id: str
    source_tool: ShortText
    status: FindingsStatus
    findings: str | None = Field(default=None, max_length=MAX_FINDINGS_CHARS)
    verification_required: Literal[True] = True
    disclaimer: str = _DISCLAIMER
    notes: tuple[str, ...] = Field(default_factory=tuple, max_length=10)
    findings_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("notes", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> PolicyFindings:
        if not skip_digests(info) and self.findings_digest != sealed_digest(PolicyFindings, self, "findings_digest"):
            raise ValueError("findings_digest must commit the exact findings")
        return self


def _stringify(output: Any) -> str | None:
    if output is None:
        return None
    if isinstance(output, str):
        text = output
    elif isinstance(output, Mapping):
        for key in ("text", "result", "output", "answer", "summary", "content", "findings"):
            value = output.get(key)
            if isinstance(value, str) and value.strip():
                text = value
                break
        else:
            text = json.dumps(output, ensure_ascii=True, default=str)
    else:
        text = json.dumps(output, ensure_ascii=True, default=str)
    cleaned = _clean(text)
    return cleaned[:MAX_FINDINGS_CHARS] if cleaned else None


def normalize_policy_findings(request: ExtractionRequest | Mapping[str, Any], raw_response: Any, *, source_tool: str = RESEARCH_TOOL) -> PolicyFindings:
    """What the research tool returned, bounded and verbatim; leads, never facts."""

    req = request if isinstance(request, ExtractionRequest) else ExtractionRequest.model_validate(dict(detached(request)))
    text = _stringify(raw_response)
    notes = ["leads are unverified; promote each fact with its URL, retrieval date and quotation before it enters the catalog"]
    status: FindingsStatus = "completed" if text else "empty"
    if text is None:
        notes.insert(0, "the research tool returned no readable findings")
    return seal(PolicyFindings, {"request_digest": req.request_digest, "provider_ref": req.provider_ref, "vertical_id": req.vertical_id, "source_tool": source_tool, "status": status, "findings": text, "notes": notes}, "findings_digest")


# --------------------------------------------------------------------------- #
# Promotion: the human step from lead to catalog fact
# --------------------------------------------------------------------------- #


class PromotedSource(ResearchModel):
    url: str
    retrieved_at: str
    document_title: ShortText
    quote: str = Field(min_length=1, max_length=2000)
    source_type: ShortText
    source_id: ShortText | None = None
    locator: ShortText | None = None
    structured_feed: bool = False

    @field_validator("url")
    @classmethod
    def _url(cls, value: str) -> str:
        if not value.startswith(("http://", "https://")):
            raise ValueError("a promoted source names a resolvable URL")
        return value


class FactPromotion(ResearchModel):
    schema_id: str = Field(default=FACT_PROMOTION_SCHEMA, alias="schema")
    findings_digest: Sha256Digest
    provider_ref: OpaqueRef
    provider_legal_name: ShortText
    vertical_id: str
    product_name: ShortText
    taxonomy_class: ShortText
    classification_reason: ShortText | None = None
    eligibility: tuple[str, ...] = Field(default_factory=tuple)
    pricing: tuple[dict[str, Any], ...] = Field(default_factory=tuple)
    key_terms: tuple[dict[str, Any], ...] = Field(default_factory=tuple)
    pricing_kind: Literal["list", "quoted", "quote_required", "unstated"] = "unstated"
    effective_date: str | None = None
    sources: tuple[PromotedSource, ...] = Field(min_length=1)
    conflicts: tuple[str, ...] = Field(default_factory=tuple)
    confidence: Confidence
    gaps: tuple[str, ...] = Field(default_factory=tuple)
    promoted_by_ref: OpaqueRef
    promoted_at: str
    promotion_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("eligibility", "pricing", "key_terms", "sources", "conflicts", "gaps", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> FactPromotion:
        if not skip_digests(info) and self.promotion_digest != sealed_digest(FactPromotion, self, "promotion_digest"):
            raise ValueError("promotion_digest must commit the exact promotion")
        return self


def earned_confidence(sources: Sequence[PromotedSource], conflicts: Sequence[str]) -> Confidence:
    """The roadmap's rule: verified needs a structured feed or two independent first-party sources; a conflict is unverified."""

    if conflicts:
        return "unverified"
    first_party = [source for source in sources if source.source_type in FIRST_PARTY_SOURCE_TYPES]
    if any(source.structured_feed for source in first_party):
        return "verified"
    distinct = {source.url for source in first_party}
    if len(distinct) >= 2:
        return "verified"
    if len(distinct) == 1:
        return "single_source"
    return "unverified"


def promote_findings_to_product(findings: PolicyFindings | Mapping[str, Any], *, product_name: str, taxonomy_class: str, sources: Sequence[Mapping[str, Any] | PromotedSource], promoted_by_ref: str, promoted_at: str, provider_legal_name: str, pricing: Sequence[Mapping[str, Any]] = (), key_terms: Sequence[Mapping[str, Any]] = (), eligibility: Sequence[str] = (), pricing_kind: str = "unstated", effective_date: str | None = None, conflicts: Sequence[str] = (), gaps: Sequence[str] = (), classification_reason: str | None = None, registry: VerticalRegistry | None = None) -> FactPromotion:
    """A person turns a lead into a catalog product; every source is first party with a URL, a date and a quotation."""

    f = findings if isinstance(findings, PolicyFindings) else PolicyFindings.model_validate(dict(detached(findings)))
    _require(f.status == "completed", "FINDINGS_EMPTY", "nothing was found to promote")
    registry = registry or load_vertical_registry()
    vertical = registry.vertical(f.vertical_id)
    parsed_sources = tuple(item if isinstance(item, PromotedSource) else PromotedSource.model_validate(dict(detached(item))) for item in sources)
    _require(bool(parsed_sources), "SOURCE_MISSING", "a catalog fact carries at least one source")
    for source in parsed_sources:
        _require(source.source_type not in THIRD_PARTY_SOURCE_TYPES, "THIRD_PARTY_SOURCE_NOT_A_FACT", f"{source.source_type} sources are pointers only and never support a product fact")
        _require(bool(source.quote.strip()), "QUOTE_MISSING", "every source carries a verbatim supporting quotation")
    if taxonomy_class not in vertical.taxonomy:
        _require(bool(classification_reason), "CLASSIFICATION_REASON_MISSING", f"{taxonomy_class} is not in the {f.vertical_id} taxonomy; promote as unclassified with a reason")
        taxonomy_class = "unclassified"
    if taxonomy_class == "unclassified":
        _require(bool(classification_reason), "CLASSIFICATION_REASON_MISSING", "an unclassified product states why")
    confidence = earned_confidence(parsed_sources, conflicts)
    for fact in pricing:
        _require(isinstance(fact, Mapping) and str(fact.get("item", "")).strip() != "", "PRICING_ITEM_MISSING", "every pricing fact names its item")
    return seal(FactPromotion, {"findings_digest": f.findings_digest, "provider_ref": f.provider_ref, "provider_legal_name": provider_legal_name, "vertical_id": f.vertical_id, "product_name": product_name, "taxonomy_class": taxonomy_class, "classification_reason": classification_reason, "eligibility": list(eligibility), "pricing": [dict(item) for item in pricing], "key_terms": [dict(item) for item in key_terms], "pricing_kind": pricing_kind, "effective_date": effective_date, "sources": [item.to_dict() for item in parsed_sources], "conflicts": list(conflicts), "confidence": confidence, "gaps": list(gaps), "promoted_by_ref": promoted_by_ref, "promoted_at": timestamp(promoted_at, field_name="promoted_at")}, "promotion_digest")


def promotion_to_pack_product(promotion: FactPromotion | Mapping[str, Any]) -> dict[str, Any]:
    """The promotion in the owner's pack ``products[]`` shape, so ``finance_advice_catalog.ingest_catalog_pack`` accepts it unchanged."""

    p = promotion if isinstance(promotion, FactPromotion) else FactPromotion.model_validate(dict(detached(promotion)))
    return {"provider_name": p.provider_legal_name, "provider_legal_name": p.provider_legal_name, "provider_register_id": None, "product_name": p.product_name, "taxonomy_class": p.taxonomy_class, "eligibility": list(p.eligibility), "pricing": [dict(item) for item in p.pricing], "key_terms": [dict(item) for item in p.key_terms], "effective_date": p.effective_date, "pricing_kind": p.pricing_kind, "sources": [{"url": s.url, "retrieved_at": s.retrieved_at, "document_title": s.document_title, "quote": s.quote, "source_type": s.source_type, "source_id": s.source_id, "locator": s.locator} for s in p.sources], "confidence": p.confidence, "verification_basis": f"promoted from findings {p.findings_digest[:16]} by {p.promoted_by_ref}", "gaps": list(p.gaps) + ([f"unclassified: {p.classification_reason}"] if p.taxonomy_class == "unclassified" and p.classification_reason else []), "conflict_ids": list(p.conflicts)}


# --------------------------------------------------------------------------- #
# Refresh: stale records are not used for current decisions
# --------------------------------------------------------------------------- #


class RefreshPlan(ResearchModel):
    schema_id: str = Field(default=REFRESH_PLAN_SCHEMA, alias="schema")
    catalog_digest: Sha256Digest
    vertical_id: str
    as_of: str
    max_age_days: int = Field(ge=1, le=365)
    stale_products: tuple[str, ...] = Field(default_factory=tuple)
    unsupported_products: tuple[str, ...] = Field(default_factory=tuple)
    providers_without_products: tuple[str, ...] = Field(default_factory=tuple)
    requests: tuple[ExtractionRequest, ...] = Field(default_factory=tuple)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("stale_products", "unsupported_products", "providers_without_products", "requests", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> RefreshPlan:
        if not skip_digests(info) and self.plan_digest != sealed_digest(RefreshPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact refresh plan")
        return self


def plan_refresh(catalog: ProductCatalog | Mapping[str, Any], *, as_of: str, max_age_days: int = 45, registry: VerticalRegistry | None = None, batch_cap: int = DEFAULT_BATCH_CAP) -> RefreshPlan:
    """Which products are stale or unsupported and which providers still have no products, with the requests to re-run."""

    c = catalog if isinstance(catalog, ProductCatalog) else ProductCatalog.model_validate(dict(detached(catalog)))
    stamp = timestamp(as_of, field_name="as_of")
    now = parsed(stamp)
    stale: list[str] = []
    unsupported: list[str] = []
    providers: set[str] = set()
    for product in c.products:
        newest = max((source.retrieved_at for source in product.sources), default=None)
        if newest is None or (now - parsed(f"{newest[:10]}T00:00:00Z")).days > max_age_days:
            stale.append(product.product_ref)
            providers.add(product.provider_ref)
        if product.pricing and not product.rankable_pricing:
            unsupported.append(product.product_ref)
            providers.add(product.provider_ref)
    without = [item.provider_ref for item in c.providers if not c.products_of(item.provider_ref) and not item.identity_only]
    providers.update(without)
    names = [c.provider(ref).legal_name for ref in sorted(providers)][:batch_cap]
    requests = compose_extraction_requests(c.vertical_id, names, registry=registry, batch_cap=batch_cap) if names else ()
    return seal(RefreshPlan, {"catalog_digest": c.catalog_digest, "vertical_id": c.vertical_id, "as_of": stamp, "max_age_days": max_age_days, "stale_products": stale, "unsupported_products": unsupported, "providers_without_products": without, "requests": [item.to_dict() for item in requests]}, "plan_digest")


# --------------------------------------------------------------------------- #
# Pack briefs and the research queue: what the next run is handed, in the shape the map ingests
# --------------------------------------------------------------------------- #

_PACK_KEYS = ("registers", "providers", "products", "coverage")
_REGISTER_FIELDS = ("register_name", "authority", "jurisdiction", "url", "retrieved_at", "entry_count_calculated", "section")
_PROVIDER_FIELDS = ("legal_name", "trading_names", "register_name", "provider_register_id", "register_id_type", "registration_status", "licence_category", "product_discovery_status", "disposition", "gaps")
_PRODUCT_FIELDS = ("provider_name", "provider_legal_name", "product_name", "taxonomy_class", "classification_reason", "eligibility", "pricing", "key_terms", "pricing_kind", "effective_date", "sources", "confidence", "availability_status", "gaps")
_PRICING_FIELDS = ("item", "value", "unit", "conditions", "source_ids", "quote")
_SOURCE_FIELDS = ("source_id", "url", "retrieved_at", "document_title", "source_type", "quote", "locator", "access_method")
_COVERAGE_FIELDS = ("vertical_id", "jurisdiction", "run_date", "batch_id", "providers_on_register", "providers_captured", "providers_with_products", "products_extracted", "census_complete", "extraction_exhaustive", "excluded", "known_limitations")
_CONFIDENCE_RULES = (
    "verified: a structured provider feed, or two independent first-party documents that agree",
    "single_source: one first-party document; say so, never round up",
    "unverified: first-party documents conflict, or only a third-party pointer exists; record the conflict",
)
_BRIEF_RULES = (
    "register first: providers come from the named register in register order, never from web search",
    "one legal entity per provider row; a trading name is a trading_names entry, never a second provider",
    "every product names the legal issuer; a brand issued by another legal entity is excluded with a reason and a citation",
    "every fact carries url, retrieved_at, document_title and a verbatim quote; a fact without a quote is unsupported",
    "list pricing and quote-dependent pricing are labelled apart; ranges are recorded as ranges, never averaged",
    "a field the provider does not state is null; nothing is inferred from market knowledge or older products",
    "at most 15 providers per pack; stop and report cumulative coverage in coverage.known_limitations",
    "eligibility statements are quoted as the provider words them, including restrictions such as investment only or a named region",
)


class PackBrief(ResearchModel):
    """What a research run is told before it produces a pack for one vertical."""

    schema_id: str = Field(default=PACK_BRIEF_SCHEMA, alias="schema")
    vertical_id: str
    jurisdiction: Literal["AU", "CA"]
    name: ShortText
    sector: ShortText
    file_name_pattern: str = PACK_FILE_PATTERN
    top_level_keys: tuple[str, ...] = _PACK_KEYS
    register_fields: tuple[str, ...] = _REGISTER_FIELDS
    provider_fields: tuple[str, ...] = _PROVIDER_FIELDS
    product_fields: tuple[str, ...] = _PRODUCT_FIELDS
    pricing_fact_fields: tuple[str, ...] = _PRICING_FIELDS
    source_fields: tuple[str, ...] = _SOURCE_FIELDS
    coverage_fields: tuple[str, ...] = _COVERAGE_FIELDS
    taxonomy: tuple[str, ...]
    decision_fields: tuple[str, ...] = Field(default_factory=tuple)
    disclosures: tuple[str, ...] = Field(default_factory=tuple)
    url_slots: tuple[UrlSlot, ...] = Field(default_factory=tuple)
    confidence_rules: tuple[str, ...] = _CONFIDENCE_RULES
    hard_rules: tuple[str, ...] = _BRIEF_RULES
    authority_for_recommendation: ShortText
    brief_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("top_level_keys", "register_fields", "provider_fields", "product_fields", "pricing_fact_fields", "source_fields", "coverage_fields", "taxonomy", "decision_fields", "disclosures", "url_slots", "confidence_rules", "hard_rules", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> PackBrief:
        if not skip_digests(info) and self.brief_digest != sealed_digest(PackBrief, self, "brief_digest"):
            raise ValueError("brief_digest must commit the exact brief")
        return self


def pack_brief(vertical_id: str, *, registry: VerticalRegistry | None = None) -> PackBrief:
    registry = registry or load_vertical_registry()
    vertical = registry.vertical(vertical_id)
    return seal(PackBrief, {"vertical_id": vertical.vertical_id, "jurisdiction": vertical.jurisdiction, "name": vertical.name, "sector": vertical.sector, "taxonomy": vertical.taxonomy, "decision_fields": vertical.decision_fields, "disclosures": vertical.disclosures, "url_slots": [slot.to_dict() for slot in _url_slots(registry, vertical)], "authority_for_recommendation": vertical.authority_for_recommendation}, "brief_digest")


def vertical_slug(vertical: Vertical) -> str:
    return re.sub(r"[^a-z0-9]+", "_", vertical.name.lower()).strip("_")


def suggested_pack_file_name(vertical: Vertical, batch_number: int, run_date: str) -> str:
    country = "australia" if vertical.jurisdiction == "AU" else "canada"
    return f"{country}_{vertical_slug(vertical)}_batch_{batch_number:02d}_catalog_{run_date[:10]}.json"


QueueKind = Literal["census_continuation", "identity_product_review", "revalidation", "refresh"]


class QueueBatch(ResearchModel):
    batch_id: ShortText
    vertical_id: str
    jurisdiction: Literal["AU", "CA"]
    kind: QueueKind
    reason: str = Field(max_length=400)
    providers: tuple[str, ...]
    requests: tuple[ExtractionRequest, ...]
    suggested_file_name: ShortText

    @field_validator("providers", "requests", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value


class ResearchQueue(ResearchModel):
    """Every batch the map still needs, in register order, with the brief each run is handed."""

    schema_id: str = Field(default=RESEARCH_QUEUE_SCHEMA, alias="schema")
    as_of: str
    map_digest: Sha256Digest
    batch_cap: int = Field(ge=1, le=50)
    max_age_days: int = Field(ge=1, le=365)
    batches: tuple[QueueBatch, ...] = Field(default_factory=tuple)
    briefs: tuple[PackBrief, ...] = Field(default_factory=tuple)
    providers_queued: int = 0
    queue_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("batches", "briefs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> ResearchQueue:
        if not skip_digests(info) and self.queue_digest != sealed_digest(ResearchQueue, self, "queue_digest"):
            raise ValueError("queue_digest must commit the exact queue")
        return self

    def batches_for(self, vertical_id: str) -> tuple[QueueBatch, ...]:
        return tuple(batch for batch in self.batches if batch.vertical_id == vertical_id)


def _chunks(names: Sequence[str], size: int) -> list[list[str]]:
    return [list(names[index:index + size]) for index in range(0, len(names), size)]


def queue_group(vertical: Vertical) -> str:
    """The verticals an entity is owed a run across: the banking registers serve every credit and deposit vertical; an insurer's register serves its sector only."""

    from lightbulb.finance_advice_engine import sector_family

    family = sector_family(vertical.sector)
    return "banking" if family in ("credit", "deposits") else str(vertical.sector)


def _register_order(provider: Mapping[str, Any]) -> tuple[int, str]:
    ordinals = [int(item["row_ordinal"]) for item in provider.get("registers") or () if isinstance(item, Mapping) and isinstance(item.get("row_ordinal"), int)]
    return (min(ordinals) if ordinals else 10_000, str(provider.get("legal_name", "")).lower())


def queue_from_map(provider_map: Mapping[str, Any], catalogs: Mapping[str, ProductCatalog | Mapping[str, Any]] | None = None, *, as_of: str, registry: VerticalRegistry | None = None, batch_cap: int = DEFAULT_BATCH_CAP, max_age_days: int = 45) -> ResearchQueue:
    """What the packs still owe each vertical: register entities never run for it, census identities with no product review, and stale catalogs."""

    registry = registry or load_vertical_registry()
    stamp = timestamp(as_of, field_name="as_of")
    now = parsed(stamp)
    m = dict(detached(provider_map))
    providers = [dict(item) for item in m.get("providers") or ()]
    verticals = [dict(item) for item in m.get("verticals") or ()]
    _require(bool(verticals), "MAP_EMPTY", "the provider map names no vertical")
    batches: list[QueueBatch] = []
    briefs: list[PackBrief] = []
    groups = {str(item.get("vertical_id")): queue_group(registry.vertical(str(item.get("vertical_id")))) for item in verticals}
    for vertical_row in sorted(verticals, key=lambda item: str(item.get("vertical_id"))):
        vertical_id = str(vertical_row["vertical_id"])
        vertical = registry.vertical(vertical_id)
        briefs.append(pack_brief(vertical_id, registry=registry))
        existing = len(vertical_row.get("batches") or ())
        number = existing
        group = groups[vertical_id]
        frame = sorted((item for item in providers if item.get("jurisdiction") == vertical.jurisdiction), key=_register_order)
        present = {str(item["legal_name"]) for item in frame if any(str(v.get("vertical_id")) == vertical_id for v in item.get("verticals") or ())}
        unrun = [str(item["legal_name"]) for item in frame if str(item["legal_name"]) not in present and not item.get("identity_only") and any(groups.get(str(v.get("vertical_id"))) == group for v in item.get("verticals") or ())]
        identity_only = [str(item["legal_name"]) for item in frame if any(str(v.get("vertical_id")) == vertical_id and v.get("identity_only") for v in item.get("verticals") or ())]
        for names in _chunks(unrun, batch_cap):
            number += 1
            batches.append(QueueBatch(batch_id=f"{vertical_id}-B{number:02d}", vertical_id=vertical_id, jurisdiction=vertical.jurisdiction, kind="census_continuation", reason=f"{len(unrun)} register entities known to the map from other {group.lower()} verticals have not been run for {vertical.name.lower()}", providers=names, requests=compose_extraction_requests(vertical_id, names, registry=registry, batch_cap=batch_cap), suggested_file_name=suggested_pack_file_name(vertical, number, stamp)))
        for names in _chunks(identity_only, batch_cap):
            number += 1
            batches.append(QueueBatch(batch_id=f"{vertical_id}-B{number:02d}", vertical_id=vertical_id, jurisdiction=vertical.jurisdiction, kind="identity_product_review", reason=f"{len(identity_only)} census identities carry no product review; membership of a register is not a product", providers=names, requests=compose_extraction_requests(vertical_id, names, registry=registry, batch_cap=batch_cap), suggested_file_name=suggested_pack_file_name(vertical, number, stamp)))
        catalog = (catalogs or {}).get(vertical_id)
        if catalog is not None:
            c = catalog if isinstance(catalog, ProductCatalog) else ProductCatalog.model_validate(dict(detached(catalog)))
            eligible_by_provider: dict[str, bool] = {}
            for product in c.products:
                eligible_by_provider[product.provider_ref] = eligible_by_provider.get(product.provider_ref, False) or engine_eligible(product, c)
            revalidate = sorted((c.provider(ref).legal_name for ref, eligible in eligible_by_provider.items() if not eligible), key=str.lower)
            for names in _chunks(revalidate, batch_cap):
                number += 1
                batches.append(QueueBatch(batch_id=f"{vertical_id}-B{number:02d}", vertical_id=vertical_id, jurisdiction=vertical.jurisdiction, kind="revalidation", reason=f"{len(revalidate)} providers carry only product records their pack marks not advice-engine eligible; recapture the primary text and current availability before anything ranks", providers=names, requests=compose_extraction_requests(vertical_id, names, registry=registry, batch_cap=batch_cap), suggested_file_name=suggested_pack_file_name(vertical, number, stamp)))
            stale: dict[str, str] = {}
            for product in c.products:
                if not eligible_by_provider.get(product.provider_ref, True):
                    continue
                newest = max((source.retrieved_at for source in product.sources), default=None)
                if newest is None or (now - parsed(f"{newest[:10]}T00:00:00Z")).days > max_age_days:
                    stale.setdefault(product.provider_ref, c.provider(product.provider_ref).legal_name)
            names_all = sorted(stale.values(), key=str.lower)
            for names in _chunks(names_all, batch_cap):
                number += 1
                batches.append(QueueBatch(batch_id=f"{vertical_id}-B{number:02d}", vertical_id=vertical_id, jurisdiction=vertical.jurisdiction, kind="refresh", reason=f"{len(names_all)} providers have products older than {max_age_days} days at {stamp[:10]}", providers=names, requests=compose_extraction_requests(vertical_id, names, registry=registry, batch_cap=batch_cap), suggested_file_name=suggested_pack_file_name(vertical, number, stamp)))
    return seal(ResearchQueue, {"as_of": stamp, "map_digest": str(m.get("map_digest") or GENESIS_DIGEST), "batch_cap": batch_cap, "max_age_days": max_age_days, "batches": [batch.to_dict() for batch in batches], "briefs": [brief.to_dict() for brief in briefs], "providers_queued": sum(len(batch.providers) for batch in batches)}, "queue_digest")


def queue_report(queue: ResearchQueue | Mapping[str, Any]) -> str:
    q = queue if isinstance(queue, ResearchQueue) else ResearchQueue.model_validate(dict(detached(queue)))
    lines = ["# Research queue", "", f"As of {q.as_of}; {len(q.batches)} batch(es), {q.providers_queued} provider run(s) queued; batch cap {q.batch_cap}; refresh after {q.max_age_days} days.", ""]
    for brief in q.briefs:
        mine = q.batches_for(brief.vertical_id)
        lines.append(f"## {brief.vertical_id} {brief.name}")
        lines.append("")
        if not mine:
            lines.append("Nothing queued.")
            lines.append("")
            continue
        for batch in mine:
            lines.append(f"### {batch.batch_id} · {batch.kind.replace('_', ' ')} · {len(batch.providers)} providers")
            lines.append("")
            lines.append(batch.reason + ".")
            lines.append(f"Deliver as `{batch.suggested_file_name}`.")
            lines.append("")
            for name in batch.providers:
                lines.append(f"- {name}")
            lines.append("")
    lines.append("## Every pack follows the brief")
    lines.append("")
    for rule in _BRIEF_RULES:
        lines.append(f"- {rule}")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Draft packs: what the platform drafts from research findings, what the analyst confirms, what is promoted
# --------------------------------------------------------------------------- #


class DraftReviewItem(ResearchModel):
    provider_name: str
    product_name: str
    taxonomy_class: str
    checks: tuple[str, ...] = Field(default_factory=tuple)
    promotable: bool

    @field_validator("checks", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value


class DraftReview(ResearchModel):
    """What an analyst must confirm before any product of a draft pack becomes a catalog fact."""

    schema_id: str = Field(default=DRAFT_REVIEW_SCHEMA, alias="schema")
    vertical_id: str | None = None
    batch_id: str | None = None
    products: int
    promotable: int
    items: tuple[DraftReviewItem, ...] = Field(default_factory=tuple)
    review_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("items", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> DraftReview:
        if not skip_digests(info) and self.review_digest != sealed_digest(DraftReview, self, "review_digest"):
            raise ValueError("review_digest must commit the exact review")
        return self


def _draft_checks(product: Mapping[str, Any]) -> list[str]:
    checks: list[str] = []
    sources = [item for item in (product.get("sources") or ()) if isinstance(item, Mapping)]
    if not sources:
        checks.append("no source cited: attach the provider's page, its retrieval date and a verbatim quote")
    for source in sources:
        url = str(source.get("url") or "")
        if not url.startswith(("http://", "https://")):
            checks.append(f"source {url or '(blank)'} is not a resolvable URL")
        if str(source.get("quote") or "").startswith("(quote pending"):
            checks.append(f"quote pending for {url}: paste the verbatim supporting text")
        if source.get("source_type") == "research_finding":
            checks.append(f"source {url} was not among the research sources: confirm it is the provider's own page and set its source type")
    for fact in product.get("pricing") or ():
        if isinstance(fact, Mapping) and not fact.get("source_ids"):
            checks.append(f"pricing fact {fact.get('item')!r} lacks a citation: cite it or drop it")
    if str(product.get("taxonomy_class") or "unclassified") == "unclassified":
        checks.append("unclassified: choose a class from the vertical taxonomy or exclude the product with a reason")
    if str(product.get("pricing_kind") or "unstated") == "unstated":
        checks.append("pricing kind unstated: mark list or quote-dependent pricing as the provider publishes it")
    for gap in product.get("gaps") or ():
        text = str(gap)
        if "analyst" in text or "confirm" in text:
            checks.append(text[:300])
    return list(dict.fromkeys(checks))


def draft_promotion_checklist(pack: Mapping[str, Any]) -> DraftReview:
    """Every drafted product with the checks that stand between it and promotion; a product with none is promotable."""

    coverage = pack.get("coverage") if isinstance(pack.get("coverage"), Mapping) else {}
    items: list[DraftReviewItem] = []
    for product in pack.get("products") or ():
        if not isinstance(product, Mapping):
            continue
        checks = _draft_checks(product)
        items.append(DraftReviewItem(provider_name=str(product.get("provider_legal_name") or product.get("provider_name") or ""), product_name=str(product.get("product_name") or ""), taxonomy_class=str(product.get("taxonomy_class") or "unclassified"), checks=checks, promotable=not checks))
    return seal(DraftReview, {"vertical_id": coverage.get("vertical_id"), "batch_id": coverage.get("batch_id"), "products": len(items), "promotable": sum(1 for item in items if item.promotable), "items": [item.to_dict() for item in items]}, "review_digest")


def promote_draft_pack(pack: Mapping[str, Any], *, promoted_by_ref: str, promoted_at: str, product_names: Sequence[str] | None = None, retrieved_at: str | None = None) -> dict[str, Any]:
    """The analyst's promotion: the named (or every promotable) draft products become a receivable pack with earned confidence.

    Every promoted product must pass the checklist; a product that does not is refused by name, never silently dropped.
    """

    stamp = timestamp(promoted_at, field_name="promoted_at")
    _require(bool(promoted_by_ref and promoted_by_ref.strip()), "PROMOTER_REQUIRED", "promotion names the analyst")
    review = draft_promotion_checklist(pack)
    wanted = set(product_names) if product_names is not None else {item.product_name for item in review.items if item.promotable}
    _require(bool(wanted), "NOTHING_TO_PROMOTE", "no draft product is promotable; work the checklist first")
    blocked = [item for item in review.items if item.product_name in wanted and not item.promotable]
    _require(not blocked, "DRAFT_NOT_PROMOTABLE", "; ".join(f"{item.product_name}: {item.checks[0]}" for item in blocked))
    coverage = dict(pack.get("coverage") if isinstance(pack.get("coverage"), Mapping) else {})
    products: list[dict[str, Any]] = []
    promoted_providers: set[str] = set()
    for raw in pack.get("products") or ():
        if not isinstance(raw, Mapping) or str(raw.get("product_name") or "") not in wanted:
            continue
        product = dict(raw)
        sources = []
        promoted_sources: list[PromotedSource] = []
        for source in raw.get("sources") or ():
            item = dict(source)
            if retrieved_at:
                item["retrieved_at"] = retrieved_at
            sources.append(item)
            promoted_sources.append(PromotedSource(url=str(item.get("url")), retrieved_at=str(item.get("retrieved_at")), document_title=str(item.get("document_title") or item.get("url")), quote=str(item.get("quote")), source_type=str(item.get("source_type") or "provider_web_page"), source_id=item.get("source_id"), locator=item.get("locator"), structured_feed=bool(item.get("structured_feed", False))))
        product["sources"] = sources
        product["confidence"] = earned_confidence(promoted_sources, ())
        product["verification_basis"] = f"promoted by {promoted_by_ref} at {stamp} from {DRAFT_BASIS}"
        products.append(product)
        promoted_providers.add(str(raw.get("provider_legal_name") or raw.get("provider_name") or ""))
    providers = []
    for raw in pack.get("providers") or ():
        if not isinstance(raw, Mapping):
            continue
        provider = dict(raw)
        if str(provider.get("legal_name") or "") in promoted_providers:
            provider["product_discovery_status"] = "current_in_scope_products_extracted"
            provider["disposition"] = f"promoted by {promoted_by_ref}"
        providers.append(provider)
    by_confidence = {"verified": 0, "single_source": 0, "unverified": 0}
    for product in products:
        by_confidence[str(product["confidence"])] += 1
    coverage.update({
        "phase": "promoted_from_draft",
        "run_date": stamp[:10],
        "providers_captured": len(providers),
        "providers_with_products": len(promoted_providers),
        "products_extracted": len(products),
        "products_verified": by_confidence["verified"],
        "products_single_source": by_confidence["single_source"],
        "products_unverified": by_confidence["unverified"],
        "known_limitations": [f"Promoted from a platform draft by {promoted_by_ref} at {stamp}; only the products the analyst confirmed are present, the rest stay in the draft."],
        "notes": [note for note in (coverage.get("notes") or ()) if isinstance(note, str)],
    })
    return {"registers": list(pack.get("registers") or ()), "providers": providers, "products": products, "coverage": coverage}


ADVICE_RESEARCH_MANIFEST: dict[str, Any] = {
    "kind": ADVICE_RESEARCH_KIND,
    "schemas": [CENSUS_PLAN_SCHEMA, EXTRACTION_REQUEST_SCHEMA, POLICY_FINDINGS_SCHEMA, FACT_PROMOTION_SCHEMA, REFRESH_PLAN_SCHEMA, PACK_BRIEF_SCHEMA, RESEARCH_QUEUE_SCHEMA, DRAFT_REVIEW_SCHEMA],
    "research_tool": RESEARCH_TOOL,
    "stages": ["freeze_scope_and_taxonomy", "enumerate_registers", "census_in_capped_batches", "discover_structured_product_data", "collect_primary_disclosures_in_trust_order", "extract_decision_fields", "assign_confidence_by_rule", "report_coverage", "refresh_and_change_detection"],
    "hard_rules": [
        "no provider discovery through ordinary web search before register coverage is documented",
        "at most one batch cap of register-ordered providers per run; stop and report cumulative coverage",
        "comparison sites and news are pointers only and never support a product fact",
        "a lead becomes a fact only when a person promotes it with a URL, a retrieval date and a verbatim quotation",
        "verified needs a structured feed or two independent first-party sources; one source is single_source; a conflict is unverified",
        "a class outside the frozen taxonomy is promoted as unclassified with a reason",
        "stale records are not used for current decisions; the refresh plan names them and the requests that re-read them",
        "the SDK composes the research and performs none of it",
    ],
}

__all__ = [
    "ADVICE_RESEARCH_KIND",
    "ADVICE_RESEARCH_MANIFEST",
    "AdviceResearchError",
    "CENSUS_PLAN_SCHEMA",
    "CensusBatch",
    "CensusPlan",
    "DEFAULT_BATCH_CAP",
    "DRAFT_BASIS",
    "DRAFT_PHASE",
    "DRAFT_REVIEW_SCHEMA",
    "DraftReview",
    "DraftReviewItem",
    "EXTRACTION_REQUEST_SCHEMA",
    "ExtractionRequest",
    "FACT_PROMOTION_SCHEMA",
    "FIRST_PARTY_SOURCE_TYPES",
    "FactPromotion",
    "PACK_BRIEF_SCHEMA",
    "PACK_FILE_PATTERN",
    "POLICY_FINDINGS_SCHEMA",
    "PackBrief",
    "PolicyFindings",
    "PromotedSource",
    "QueueBatch",
    "REFRESH_PLAN_SCHEMA",
    "RESEARCH_QUEUE_SCHEMA",
    "RESEARCH_TOOL",
    "RefreshPlan",
    "ResearchQueue",
    "THIRD_PARTY_SOURCE_TYPES",
    "UrlSlot",
    "compose_extraction_requests",
    "draft_promotion_checklist",
    "earned_confidence",
    "normalize_policy_findings",
    "pack_brief",
    "plan_census",
    "plan_refresh",
    "promote_draft_pack",
    "promote_findings_to_product",
    "promotion_to_pack_product",
    "queue_from_map",
    "queue_group",
    "queue_report",
    "requests_for_catalog",
    "suggested_pack_file_name",
    "vertical_slug",
]
