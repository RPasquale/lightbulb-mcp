"""The source registry: what every catalog fact rests on, what to check, how, how often, and which facts depend on it.

A catalog's citations say where a fact came from. The registry turns them into an operational
ledger the platform can act on: one monitored source per URL *and request context* (the same
address answers differently after choosing a province, a segment or a channel), its document
role, the fetch method it needs, the cadence and freshness policy for that role, the fields that
depend on it, and the last attempt, success and successful revalidation. Sources are monitored,
product records are not: one rate page supports several families and is fetched once.

Nothing here performs a read. ``plan_checks`` names the checks that are due; the platform's worker
performs them and hands back a ``CheckReceipt``; ``record_check`` folds the receipt into a new
registry version. A 304 on a rendered page's shell revalidates nothing, because the widget that
carries the rate is not the shell. A failed fetch never advances the revalidation clock.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, Sha256Digest, detached, parsed, seal, sealed_digest, skip_digests, timestamp
from lightbulb.finance_advice_catalog import Product, ProductCatalog, ResearchModel, SourceCitation

SOURCE_REGISTRY_SCHEMA = "lightbulb.finance_advice_source_registry.v1"
CHECK_PLAN_SCHEMA = "lightbulb.finance_advice_check_plan.v1"
MAX_SOURCES = 20_000
MAX_CHECKS = 5_000

DocumentRole = Literal["rates", "fees", "eligibility", "terms", "disclosure", "product_index", "register", "structured_feed", "other"]
FetchMethod = Literal["http", "rendered", "pdf", "structured_api"]
CheckOutcome = Literal["retrieved", "not_modified", "failed", "blocked", "empty_shell", "missing_section"]

# Engineering starting points, not measured optima: rates daily, disclosures weekly, registers weekly.
# The freshness policy says how long a fact may be used without a successful revalidation.
DEFAULT_CADENCE_HOURS: dict[str, int] = {"rates": 24, "fees": 24, "eligibility": 24, "terms": 24 * 7, "disclosure": 24 * 7, "product_index": 24, "register": 24 * 7, "structured_feed": 24, "quote": 24 * 30, "other": 24 * 7}
DEFAULT_FRESHNESS_HOURS: dict[str, int] = {"rates": 72, "fees": 24 * 30, "eligibility": 24 * 30, "terms": 24 * 90, "disclosure": 24 * 90, "product_index": 24 * 30, "register": 24 * 90, "structured_feed": 72, "quote": 24 * 30, "other": 24 * 90}
MINIMUM_CADENCE_HOURS = 24 * 30  # a source is never neglected for longer than this, whatever its role
FAILURE_BACKOFF_HOURS = (1, 4, 12, 24, 72)  # after consecutive failures; capped, never silent

_ROLE_MARKERS: tuple[tuple[DocumentRole, tuple[str, ...]], ...] = (
    ("structured_feed", ("structured_product_feed", "product_api", "cds-au", "/banking/products", "open-data")),
    ("register", ("regulator_register", "approval_register", "register", "nha-approved-lenders", "cdr-register", "data-holders")),
    ("fees", ("fee", "charges", "pricing schedule")),
    ("rates", ("rate", "interest", "pricing", "apr", "comparison")),
    ("eligibility", ("eligib", "who can apply", "criteria")),
    ("disclosure", ("pds", "product disclosure", "target market", "tmd", "key facts", "mandated_disclosure", "disclosure")),
    ("terms", ("terms", "conditions", "agreement", "contract", "policy wording", "provider_terms")),
    ("product_index", ("products", "index", "compare", "our loans", "our mortgages", "product list")),
)


class AdviceSourceError(ValueError):
    pass


def _require(condition: bool, code: str, detail: str) -> None:
    if not condition:
        raise AdviceSourceError(f"{code}: {detail}")


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _jsonable(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    return value


def source_family(url: str) -> str:
    """The same widget shown on several pages is one family: host and path, no query or fragment."""

    parts = urlsplit(url.strip())
    path = re.sub(r"/+$", "", parts.path) or "/"
    return f"{parts.netloc.lower()}{path.lower()}"


def source_key(url: str, request_context: Mapping[str, Any] | None = None) -> str:
    """One key per URL and request context; the context is part of the identity, never folded away."""

    context = json.dumps(_jsonable(dict(request_context or {})), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "source:" + _sha256(url.strip() + "|" + context)[:24]


def classify_role(*, url: str, source_type: str | None = None, document_title: str | None = None, locator: str | None = None) -> DocumentRole:
    """The document's role from what the citation states; when nothing says, ``other``."""

    haystack = " ".join(item.lower() for item in (source_type or "", document_title or "", locator or "", url or "") if item)
    for role, markers in _ROLE_MARKERS:
        if any(marker in haystack for marker in markers):
            return role
    return "other"


def fetch_method_for(*, url: str, source_type: str | None = None, access_method: str | None = None) -> FetchMethod:
    lower_url = url.lower()
    lower_type = (source_type or "").lower()
    lower_access = (access_method or "").lower()
    if "structured_product_feed" in lower_type or "cds-au" in lower_url or "/banking/products" in lower_url or "api" in lower_type:
        return "structured_api"
    if lower_url.split("?")[0].endswith(".pdf") or "pdf" in lower_type:
        return "pdf"
    if any(marker in lower_access or marker in lower_type for marker in ("render", "browser", "javascript", "dynamic", "widget", "image")):
        return "rendered"
    return "http"


class DependentField(ResearchModel):
    """A catalog field that rests on the source: ``pricing:<item>[conditions]``, ``key_term:<term>``, ``eligibility``, ``identity``."""

    product_ref: str
    field: str
    rankable: bool = False


class MonitoredSource(ResearchModel):
    source_key: str
    url: str
    jurisdiction: Literal["AU", "CA"]
    vertical_ids: tuple[str, ...] = Field(default_factory=tuple)
    provider_ref: str | None = None
    provider_name: str | None = None
    document_role: DocumentRole = "other"
    fetch_method: FetchMethod = "http"
    request_context: dict[str, Any] = Field(default_factory=dict)
    extraction: dict[str, Any] = Field(default_factory=dict)
    source_family: str
    cadence_hours: int = Field(ge=1, le=24 * 365)
    freshness_hours: int = Field(ge=1, le=24 * 365)
    dependents: tuple[DependentField, ...] = Field(default_factory=tuple)
    source_ids_as_stated: tuple[str, ...] = Field(default_factory=tuple)
    document_title: str | None = None
    source_type_as_stated: str | None = None
    last_attempt_at: str | None = None
    last_success_at: str | None = None
    last_revalidated_at: str | None = None
    last_outcome: CheckOutcome | None = None
    content_fingerprint: str | None = None
    etag: str | None = None
    last_modified: str | None = None
    consecutive_failures: int = Field(default=0, ge=0)
    notes: tuple[str, ...] = Field(default_factory=tuple)

    @field_validator("url")
    @classmethod
    def _url(cls, value: str) -> str:
        if not value.startswith(("http://", "https://")):
            raise ValueError("a monitored source is a resolvable URL")
        return value

    @field_validator("vertical_ids", "dependents", "source_ids_as_stated", "notes", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @property
    def priority(self) -> int:
        """Impact of a missed change: rankable fields first, then any dependent field."""

        return sum(3 if item.rankable else 1 for item in self.dependents)

    def next_due_at(self) -> str | None:
        """When the next check is due; ``None`` means now (never checked)."""

        anchor = self.last_success_at or self.last_attempt_at
        if anchor is None:
            return None
        hours = self.cadence_hours
        if self.consecutive_failures:
            hours = min(FAILURE_BACKOFF_HOURS[min(self.consecutive_failures, len(FAILURE_BACKOFF_HOURS)) - 1], MINIMUM_CADENCE_HOURS)
            anchor = self.last_attempt_at or anchor
        due = parsed(anchor).timestamp() + hours * 3600
        floor = parsed(self.last_success_at).timestamp() + MINIMUM_CADENCE_HOURS * 3600 if self.last_success_at else due
        return _iso(min(due, floor))

    def is_due(self, as_of: str) -> bool:
        due = self.next_due_at()
        return due is None or parsed(due) <= parsed(as_of)


def _iso(epoch: float) -> str:
    from datetime import datetime, timezone

    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class SourceRegistry(ResearchModel):
    schema_id: str = Field(default=SOURCE_REGISTRY_SCHEMA, alias="schema")
    built_at: str
    sources: tuple[MonitoredSource, ...] = Field(default_factory=tuple, max_length=MAX_SOURCES)
    registry_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("sources", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> SourceRegistry:
        keys = [item.source_key for item in self.sources]
        if len(keys) != len(set(keys)):
            raise ValueError("source keys must be unique")
        if not skip_digests(info) and self.registry_digest != sealed_digest(SourceRegistry, self, "registry_digest"):
            raise ValueError("registry_digest must commit the exact registry")
        return self

    def source(self, key: str) -> MonitoredSource:
        for item in self.sources:
            if item.source_key == key:
                return item
        raise AdviceSourceError(f"SOURCE_UNKNOWN: {key}")

    def for_provider(self, provider_ref: str) -> tuple[MonitoredSource, ...]:
        return tuple(item for item in self.sources if item.provider_ref == provider_ref)

    def families(self) -> dict[str, tuple[str, ...]]:
        out: dict[str, list[str]] = {}
        for item in self.sources:
            out.setdefault(item.source_family, []).append(item.source_key)
        return {family: tuple(keys) for family, keys in out.items() if len(keys) > 1}


# --------------------------------------------------------------------------- #
# Building the registry from what the catalogs cite
# --------------------------------------------------------------------------- #


def fact_field(item: str, conditions: Mapping[str, Any] | None = None) -> str:
    """The field key a pricing fact occupies: the item plus the conditions that make it a distinct price."""

    keys = ("term_months", "term_years", "rate_tier", "rate_type", "loan_purpose", "repayment_type", "tier", "variant")
    signature = ",".join(f"{key}={_jsonable((conditions or {}).get(key))}" for key in keys if (conditions or {}).get(key) is not None)
    return f"pricing:{item}" + (f"[{signature}]" if signature else "")


class _Accumulator:
    def __init__(self, citation: SourceCitation, *, jurisdiction: str, provider_ref: str | None, provider_name: str | None) -> None:
        self.url = citation.url
        self.jurisdiction = jurisdiction
        self.provider_ref = provider_ref
        self.provider_name = provider_name
        self.verticals: dict[str, None] = {}
        self.dependents: dict[tuple[str, str], bool] = {}
        self.source_ids: dict[str, None] = {}
        self.titles: dict[str, None] = {}
        self.types: dict[str, None] = {}
        self.locators: dict[str, None] = {}
        self.access: dict[str, None] = {}
        self.newest: str | None = None

    def cite(self, citation: SourceCitation, vertical_id: str) -> None:
        self.verticals[vertical_id] = None
        if citation.source_id:
            self.source_ids[citation.source_id] = None
        if citation.document_title:
            self.titles[citation.document_title] = None
        if citation.source_type:
            self.types[citation.source_type] = None
        if citation.locator:
            self.locators[citation.locator] = None
        if citation.access_method:
            self.access[citation.access_method] = None
        stamp = citation.retrieved_at if len(citation.retrieved_at) > 10 else citation.retrieved_at + "T00:00:00Z"
        if self.newest is None or parsed(stamp) > parsed(self.newest):
            self.newest = stamp

    def depend(self, product_ref: str, field: str, rankable: bool) -> None:
        self.dependents[(product_ref, field)] = self.dependents.get((product_ref, field), False) or rankable

    def build(self, *, request_context: Mapping[str, Any] | None = None) -> MonitoredSource:
        role = classify_role(url=self.url, source_type=" ".join(self.types), document_title=" ".join(self.titles), locator=" ".join(self.locators))
        method = fetch_method_for(url=self.url, source_type=" ".join(self.types), access_method=" ".join(self.access))
        extraction = {"parser": "section_fingerprints", "sections": sorted(self.locators)} if method != "structured_api" else {"parser": "structured_feed"}
        return MonitoredSource(
            source_key=source_key(self.url, request_context),
            url=self.url,
            jurisdiction=self.jurisdiction,  # type: ignore[arg-type]
            vertical_ids=tuple(sorted(self.verticals)),
            provider_ref=self.provider_ref,
            provider_name=self.provider_name,
            document_role=role,
            fetch_method=method,
            request_context=dict(request_context or {}),
            extraction=extraction,
            source_family=source_family(self.url),
            cadence_hours=DEFAULT_CADENCE_HOURS[role],
            freshness_hours=DEFAULT_FRESHNESS_HOURS[role],
            dependents=tuple(DependentField(product_ref=ref, field=field, rankable=rankable) for (ref, field), rankable in sorted(self.dependents.items())),
            source_ids_as_stated=tuple(sorted(self.source_ids)),
            document_title=next(iter(self.titles), None),
            source_type_as_stated=next(iter(self.types), None),
            last_success_at=self.newest,
            last_revalidated_at=self.newest,
            last_outcome="retrieved" if self.newest else None,
        )


def registry_from_catalogs(catalogs: Mapping[str, ProductCatalog | Mapping[str, Any]], *, built_at: str, request_contexts: Mapping[str, Mapping[str, Any]] | None = None) -> SourceRegistry:
    """Every URL the catalogs cite becomes a monitored source; the facts that cite it are its dependents.

    ``request_contexts`` maps a URL to the context it was read under (province, segment, channel);
    a URL read under several contexts is several sources.
    """

    stamp = timestamp(built_at, field_name="built_at")
    accumulators: dict[str, _Accumulator] = {}
    for vertical_id, raw in sorted(catalogs.items()):
        catalog = raw if isinstance(raw, ProductCatalog) else ProductCatalog.model_validate(dict(detached(raw)))
        providers = {item.provider_ref: item for item in catalog.providers}
        for provider in catalog.providers:
            for citation in provider.sources:
                acc = _accumulator(accumulators, citation, catalog.jurisdiction, provider.provider_ref, provider.legal_name, request_contexts)
                acc.cite(citation, vertical_id)
                acc.depend(provider.provider_ref, "identity", False)
        for register in catalog.registers:
            if register.url and register.url.startswith(("http://", "https://")) and register.retrieved_at:
                citation = SourceCitation(url=register.url, retrieved_at=register.retrieved_at, document_title=register.register_name, source_type="regulator_register")
                acc = _accumulator(accumulators, citation, catalog.jurisdiction, None, register.authority, request_contexts)
                acc.cite(citation, vertical_id)
                acc.depend("register:" + register.register_name, "register", False)
        for product in catalog.products:
            owner = providers.get(product.provider_ref)
            by_id = {citation.source_id: citation for citation in product.sources if citation.source_id}
            for citation in product.sources:
                acc = _accumulator(accumulators, citation, catalog.jurisdiction, product.provider_ref, owner.legal_name if owner else product.provider_name, request_contexts)
                acc.cite(citation, vertical_id)
            _depend_facts(accumulators, product, by_id, catalog.jurisdiction, request_contexts)
    sources = sorted((acc.build(request_context=(request_contexts or {}).get(acc.url)) for acc in accumulators.values()), key=lambda item: (item.jurisdiction, item.provider_name or "", item.url))
    return seal(SourceRegistry, {"built_at": stamp, "sources": [item.to_dict() for item in sources]}, "registry_digest")


def _accumulator(accumulators: dict[str, _Accumulator], citation: SourceCitation, jurisdiction: str, provider_ref: str | None, provider_name: str | None, request_contexts: Mapping[str, Mapping[str, Any]] | None) -> _Accumulator:
    key = source_key(citation.url, (request_contexts or {}).get(citation.url))
    acc = accumulators.get(key)
    if acc is None:
        acc = _Accumulator(citation, jurisdiction=jurisdiction, provider_ref=provider_ref, provider_name=provider_name)
        accumulators[key] = acc
    elif acc.provider_ref is None and provider_ref is not None:
        acc.provider_ref = provider_ref
        acc.provider_name = provider_name
    return acc


def _depend_facts(accumulators: dict[str, _Accumulator], product: Product, by_id: Mapping[str, SourceCitation], jurisdiction: str, request_contexts: Mapping[str, Mapping[str, Any]] | None) -> None:
    def targets(source_ids: Sequence[str]) -> list[_Accumulator]:
        cited = [by_id[source_id] for source_id in source_ids if source_id in by_id]
        chosen = cited or list(product.sources)
        return [_accumulator(accumulators, citation, jurisdiction, product.provider_ref, product.provider_name, request_contexts) for citation in chosen]

    for fact in product.pricing:
        for acc in targets(fact.source_ids):
            acc.depend(product.product_ref, fact_field(fact.item, fact.conditions), fact.rankable)
    for term in product.key_terms:
        for acc in targets(term.source_ids):
            acc.depend(product.product_ref, f"key_term:{term.term}", False)
    if product.eligibility:
        for acc in targets(()):
            acc.depend(product.product_ref, "eligibility", False)
    for acc in targets(()):
        acc.depend(product.product_ref, "availability", False)


def extend_registry(registry: SourceRegistry | Mapping[str, Any], sources: Sequence[MonitoredSource | Mapping[str, Any]], *, built_at: str) -> SourceRegistry:
    """Fold sources into a registry: a key already present keeps its attempt history and validators, and gains any new dependents and verticals."""

    r = registry if isinstance(registry, SourceRegistry) else SourceRegistry.model_validate(dict(detached(registry)))
    stamp = timestamp(built_at, field_name="built_at")
    merged: dict[str, MonitoredSource] = {item.source_key: item for item in r.sources}
    for raw in sources:
        incoming = raw if isinstance(raw, MonitoredSource) else MonitoredSource.model_validate(dict(detached(raw)))
        existing = merged.get(incoming.source_key)
        if existing is None:
            merged[incoming.source_key] = incoming
            continue
        dependents = {(item.product_ref, item.field): item for item in existing.dependents}
        for item in incoming.dependents:
            current = dependents.get((item.product_ref, item.field))
            dependents[(item.product_ref, item.field)] = item if current is None or (item.rankable and not current.rankable) else current
        merged[incoming.source_key] = existing.model_copy(update={"vertical_ids": tuple(sorted(set(existing.vertical_ids) | set(incoming.vertical_ids))), "dependents": tuple(dependents[key] for key in sorted(dependents)), "extraction": {**incoming.extraction, **existing.extraction} if existing.extraction else dict(incoming.extraction), "provider_ref": existing.provider_ref or incoming.provider_ref, "provider_name": existing.provider_name or incoming.provider_name})
    ordered = sorted(merged.values(), key=lambda item: (item.jurisdiction, item.provider_name or "", item.url, item.source_key))
    return seal(SourceRegistry, {"built_at": stamp, "sources": [item.to_dict() for item in ordered]}, "registry_digest")


# --------------------------------------------------------------------------- #
# Checks: what is due, and folding the receipts back
# --------------------------------------------------------------------------- #


class CheckRequest(ResearchModel):
    source_key: str
    url: str
    fetch_method: FetchMethod
    document_role: DocumentRole
    request_context: dict[str, Any] = Field(default_factory=dict)
    extraction: dict[str, Any] = Field(default_factory=dict)
    conditional: dict[str, str] = Field(default_factory=dict)
    reason: str
    priority: int = Field(ge=0)


class CheckPlan(ResearchModel):
    schema_id: str = Field(default=CHECK_PLAN_SCHEMA, alias="schema")
    registry_digest: Sha256Digest
    as_of: str
    requests: tuple[CheckRequest, ...] = Field(default_factory=tuple, max_length=MAX_CHECKS)
    due_total: int = Field(ge=0)
    deferred: int = Field(ge=0)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("requests", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> CheckPlan:
        if not skip_digests(info) and self.plan_digest != sealed_digest(CheckPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self


def plan_checks(registry: SourceRegistry | Mapping[str, Any], *, as_of: str, budget: int | None = None) -> CheckPlan:
    """The checks due now, most overdue and most consequential first; a budget defers, it never hides."""

    r = registry if isinstance(registry, SourceRegistry) else SourceRegistry.model_validate(dict(detached(registry)))
    stamp = timestamp(as_of, field_name="as_of")
    now = parsed(stamp)
    due: list[tuple[float, int, MonitoredSource, str]] = []
    for source in r.sources:
        next_due = source.next_due_at()
        if next_due is None:
            due.append((float("inf"), source.priority, source, "never checked"))
            continue
        overdue_hours = (now - parsed(next_due)).total_seconds() / 3600
        if overdue_hours < 0:
            continue
        if source.consecutive_failures:
            reason = f"retry after {source.consecutive_failures} consecutive failure(s); last outcome {source.last_outcome}"
        elif source.last_success_at and (now - parsed(source.last_success_at)).total_seconds() >= MINIMUM_CADENCE_HOURS * 3600:
            reason = f"minimum cadence: no successful check since {source.last_success_at}"
        else:
            reason = f"due: {source.document_role} every {source.cadence_hours}h, last success {source.last_success_at or 'never'}"
        due.append((overdue_hours / max(source.cadence_hours, 1), source.priority, source, reason))
    due.sort(key=lambda item: (-item[0], -item[1], item[2].source_key))
    chosen = due if budget is None else due[:budget]
    requests = [
        CheckRequest(source_key=source.source_key, url=source.url, fetch_method=source.fetch_method, document_role=source.document_role, request_context=dict(source.request_context), extraction=dict(source.extraction), conditional={key: value for key, value in (("if_none_match", source.etag), ("if_modified_since", source.last_modified)) if value}, reason=reason, priority=source.priority)
        for _, _, source, reason in chosen
    ]
    return seal(CheckPlan, {"registry_digest": r.registry_digest, "as_of": stamp, "requests": [item.to_dict() for item in requests], "due_total": len(due), "deferred": len(due) - len(chosen)}, "plan_digest")


class CheckReceipt(ResearchModel):
    """What the worker hands back for one check. Bodies never come here: only hashes, headers and section fingerprints."""

    source_key: str
    attempted_at: str
    outcome: CheckOutcome
    status_code: int | None = None
    final_url: str | None = None
    content_sha256: str | None = None
    etag: str | None = None
    last_modified: str | None = None
    sections: dict[str, str] = Field(default_factory=dict)
    missing_sections: tuple[str, ...] = Field(default_factory=tuple)
    snapshot_digest: str | None = None
    note: str | None = None

    @field_validator("missing_sections", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value


def record_check(registry: SourceRegistry | Mapping[str, Any], receipt: CheckReceipt | Mapping[str, Any]) -> SourceRegistry:
    """Fold one receipt into the registry: the attempt always counts, success and revalidation only when earned."""

    r = registry if isinstance(registry, SourceRegistry) else SourceRegistry.model_validate(dict(detached(registry)))
    rc = receipt if isinstance(receipt, CheckReceipt) else CheckReceipt.model_validate(dict(detached(receipt)))
    stamp = timestamp(rc.attempted_at, field_name="attempted_at")
    source = r.source(rc.source_key)
    update: dict[str, Any] = {"last_attempt_at": stamp, "last_outcome": rc.outcome}
    if rc.outcome == "retrieved":
        expected = [str(item) for item in source.extraction.get("expected_sections", ())]
        missing = [label for label in expected if label not in rc.sections] + list(rc.missing_sections)
        if missing:
            update.update({"last_outcome": "missing_section", "consecutive_failures": source.consecutive_failures + 1, "notes": (*source.notes, f"{stamp}: expected section(s) missing: {', '.join(sorted(set(missing)))}; the old facts stay until a person looks")})
        else:
            update.update({"last_success_at": stamp, "last_revalidated_at": stamp, "consecutive_failures": 0, "content_fingerprint": rc.content_sha256 or source.content_fingerprint, "etag": rc.etag or source.etag, "last_modified": rc.last_modified or source.last_modified})
    elif rc.outcome == "not_modified":
        update.update({"last_success_at": stamp, "consecutive_failures": 0})
        if source.fetch_method != "rendered":
            update["last_revalidated_at"] = stamp  # the representation is the content; for a rendered page the shell is not the widget
        else:
            update["notes"] = (*source.notes, f"{stamp}: shell not modified; the rendered sections were not re-read, so nothing was revalidated")
    else:
        update["consecutive_failures"] = source.consecutive_failures + 1
        if rc.note:
            update["notes"] = (*source.notes, f"{stamp}: {rc.outcome}: {rc.note}")
    sources = [item.model_copy(update=update) if item.source_key == source.source_key else item for item in r.sources]
    return seal(SourceRegistry, {"built_at": r.built_at, "sources": [item.to_dict() for item in sources]}, "registry_digest")


def registry_report(registry: SourceRegistry | Mapping[str, Any], *, as_of: str) -> str:
    r = registry if isinstance(registry, SourceRegistry) else SourceRegistry.model_validate(dict(detached(registry)))
    stamp = timestamp(as_of, field_name="as_of")
    due = [item for item in r.sources if item.is_due(stamp)]
    failing = [item for item in r.sources if item.consecutive_failures]
    by_role: dict[str, int] = {}
    by_method: dict[str, int] = {}
    for item in r.sources:
        by_role[item.document_role] = by_role.get(item.document_role, 0) + 1
        by_method[item.fetch_method] = by_method.get(item.fetch_method, 0) + 1
    lines = ["# Source registry", "", f"Built {r.built_at}; {len(r.sources)} monitored source(s); {len(due)} due at {stamp}; {len(failing)} failing.", ""]
    lines.append("- By role: " + ", ".join(f"{k} {v}" for k, v in sorted(by_role.items())))
    lines.append("- By fetch method: " + ", ".join(f"{k} {v}" for k, v in sorted(by_method.items())))
    families = r.families()
    if families:
        lines.append(f"- {len(families)} source famil(ies) share a host and path under different contexts: " + "; ".join(f"{family} ({len(keys)})" for family, keys in sorted(families.items())[:20]))
    if failing:
        lines.append("")
        lines.append("## Failing")
        for item in failing[:50]:
            lines.append(f"- {item.provider_name or '?'} · {item.url} · {item.consecutive_failures} failure(s), last {item.last_outcome} at {item.last_attempt_at}")
    lines.append("")
    lines.append("## Due now (most overdue first)")
    plan = plan_checks(r, as_of=stamp)
    for request in plan.requests[:100]:
        lines.append(f"- [{request.document_role}/{request.fetch_method}] {request.url} · {request.reason}")
    return "\n".join(lines) + "\n"


__all__ = [
    "CHECK_PLAN_SCHEMA",
    "DEFAULT_CADENCE_HOURS",
    "DEFAULT_FRESHNESS_HOURS",
    "MINIMUM_CADENCE_HOURS",
    "SOURCE_REGISTRY_SCHEMA",
    "AdviceSourceError",
    "CheckPlan",
    "CheckReceipt",
    "CheckRequest",
    "DependentField",
    "MonitoredSource",
    "SourceRegistry",
    "classify_role",
    "extend_registry",
    "fact_field",
    "fetch_method_for",
    "plan_checks",
    "record_check",
    "registry_from_catalogs",
    "registry_report",
    "source_family",
    "source_key",
]
