"""Advice provider map: every provider on a register and every product it declares, per vertical, across packs.

The research arrives in packs: register-ordered catalog batches (fifteen providers at a time) and
census reconciliations (identity dossiers with no products). This module folds them into one map
per jurisdiction: a provider identity that survives across batches and census files, the
verticals each provider appears in with its product counts, the merged product catalog per
vertical, and coverage against every register the packs name. New packs in the same shape drop
straight in; the map is rebuilt, never edited.

Identity is conservative, as the roadmap demands. Two rows are one provider only when their
legal names normalise to the same key, or when a census file confirms a legacy-name match. A
trading name is an alias, never a merge key, and an unconfirmed name-variant match is recorded as
a candidate for a person to confirm. Nothing is attributed from a brand to a group company.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.finance_advice_catalog import engine_eligible, provider_identity_name
from lightbulb.finance_advice_catalog import (
    ProductCatalog,
    ResearchModel,
    VerticalRegistry,
    ingest_catalog_pack,
    load_vertical_registry,
    merge_catalogs,
)
from lightbulb.company_engine_core import GENESIS_DIGEST, Sha256Digest, StrictModel, detached, seal, sealed_digest, skip_digests, timestamp

PROVIDER_MAP_SCHEMA = "lightbulb.finance_advice_provider_map.v1"
VERTICAL_MAP_SCHEMA = "lightbulb.finance_advice_vertical_provider_map.v1"
PROVIDER_IDENTITY_SCHEMA = "lightbulb.finance_advice_provider_identity.v1"
PACK_RECORD_SCHEMA = "lightbulb.finance_advice_pack_record.v1"

PackKind = Literal["catalog_batch", "census_reconciliation"]
MatchType = Literal["legal_name", "census_confirmed", "name_variant_candidate", "trading_name_candidate"]

_JURISDICTION_PREFIX = {"australia": "AU", "canada": "CA", "au": "AU", "ca": "CA"}
_SUFFIXES = ("proprietary limited", "pty ltd", "pty. ltd.", "pty limited", "limited", "ltd.", "ltd", "incorporated", "inc.", "inc", "corporation", "corp.", "corp", "plc", "llc", "the")
_IDENTIFIER_NAMESPACES = (
    ("cdic_member_id", "CDIC_MEMBER_ID"),
    ("osfi_identifier", "OSFI"),
    ("legal_entity_identifier", "LEI"),
    ("mortgage_licence_identifier", "MORTGAGE_LICENCE"),
)


class AdviceProviderMapError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise AdviceProviderMapError(code, message)


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


def normalize_name(name: str) -> str:
    """A merge key for legal names: lower case, punctuation stripped, corporate suffixes removed."""

    lower = re.sub(r"[^a-z0-9& ]+", " ", name.lower().replace("&", " and "))
    lower = re.sub(r"\s+", " ", lower).strip()
    if lower.startswith("the "):
        lower = lower[4:]
    changed = True
    while changed:
        changed = False
        for suffix in _SUFFIXES:
            if lower.endswith(" " + suffix) or lower == suffix:
                lower = lower[: -len(suffix)].strip()
                changed = True
    return lower or name.lower().strip()


def provider_key(jurisdiction: str, legal_name: str) -> str:
    return f"provider:{jurisdiction.lower()}:{_sha256(jurisdiction + '|' + normalize_name(legal_name))[:16]}"


def slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")


def infer_vertical(file_name: str, payload: Mapping[str, Any], *, registry: VerticalRegistry | None = None) -> tuple[str, str]:
    """(jurisdiction, vertical_id) from the pack's coverage, else from the file name against the registry's vertical names."""

    registry = registry or load_vertical_registry()
    coverage = payload.get("coverage") if isinstance(payload.get("coverage"), Mapping) else {}
    registers = payload.get("registers") if isinstance(payload.get("registers"), list) else []
    lower = file_name.lower()
    jurisdiction = None
    for prefix, code in _JURISDICTION_PREFIX.items():
        if lower.startswith(prefix):
            jurisdiction = code
            break
    if jurisdiction is None:
        stated = _text(coverage.get("jurisdiction"))
        jurisdiction = _JURISDICTION_PREFIX.get(stated.lower()) if stated else None
    if jurisdiction is None:
        for register in registers:
            stated = _text(register.get("jurisdiction")) if isinstance(register, Mapping) else None
            if stated and stated.lower() in _JURISDICTION_PREFIX:
                jurisdiction = _JURISDICTION_PREFIX[stated.lower()]
                break
    _require(jurisdiction is not None, "JURISDICTION_UNKNOWN", f"{file_name} names no jurisdiction")
    assert jurisdiction is not None
    vertical_id = _text(coverage.get("vertical_id"))
    if vertical_id is None:
        stated_name = _text(coverage.get("vertical"))
        candidates = registry.by_jurisdiction(jurisdiction)
        for vertical in sorted(candidates, key=lambda item: -len(item.name)):
            name_slug = slug(vertical.name)
            if (stated_name and slug(stated_name) == name_slug) or name_slug in lower:
                vertical_id = vertical.vertical_id
                break
    _require(vertical_id is not None, "VERTICAL_UNKNOWN", f"{file_name} names no vertical the registry knows")
    assert vertical_id is not None
    registry.vertical(vertical_id)
    return jurisdiction, vertical_id


def pack_kind(file_name: str, payload: Mapping[str, Any]) -> PackKind:
    coverage = payload.get("coverage") if isinstance(payload.get("coverage"), Mapping) else {}
    phase = str(coverage.get("phase") or "")
    if "census" in file_name.lower() and not payload.get("products"):
        return "census_reconciliation"
    if "census" in phase and not payload.get("products"):
        return "census_reconciliation"
    return "catalog_batch"


# --------------------------------------------------------------------------- #
# Models
# --------------------------------------------------------------------------- #


class PackRecord(ResearchModel):
    schema_id: str = Field(default=PACK_RECORD_SCHEMA, alias="schema")
    file_name: str
    jurisdiction: Literal["AU", "CA"]
    vertical_id: str
    kind: PackKind
    batch_id: str
    run_date: str
    providers: int = Field(ge=0)
    products: int = Field(ge=0)
    pack_digest: Sha256Digest


class Identifier(ResearchModel):
    namespace: str
    value: str
    namespace_as_stated: str | None = None
    file_name: str


class RegisterPresence(ResearchModel):
    register_name: str
    registration_status: str | None = None
    row_ordinal: int | None = None
    licence_category: str | None = None
    file_name: str


class VerticalPresence(ResearchModel):
    vertical_id: str
    products: int = Field(ge=0)
    discovery_status: str | None = None
    disposition: str | None = None
    identity_only: bool = False
    files: tuple[str, ...] = Field(default_factory=tuple)

    @field_validator("files", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value


class CandidateMatch(ResearchModel):
    other_name: str
    match_type: MatchType
    file_name: str
    confirmed: bool = False
    note: str | None = None


class ProviderIdentity(ResearchModel):
    schema_id: str = Field(default=PROVIDER_IDENTITY_SCHEMA, alias="schema")
    provider_key: str
    jurisdiction: Literal["AU", "CA"]
    legal_name: str
    normalized_name: str
    aliases: tuple[str, ...] = Field(default_factory=tuple)
    identifiers: tuple[Identifier, ...] = Field(default_factory=tuple)
    licence_categories: tuple[str, ...] = Field(default_factory=tuple)
    registers: tuple[RegisterPresence, ...] = Field(default_factory=tuple)
    verticals: tuple[VerticalPresence, ...] = Field(default_factory=tuple)
    candidate_matches: tuple[CandidateMatch, ...] = Field(default_factory=tuple)
    gaps: tuple[str, ...] = Field(default_factory=tuple)
    identity_only: bool = False
    files: tuple[str, ...] = Field(default_factory=tuple)
    legal_name_established: bool = True
    legal_name_status: str | None = None

    @field_validator("aliases", "identifiers", "licence_categories", "registers", "verticals", "candidate_matches", "gaps", "files", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @property
    def product_count(self) -> int:
        return sum(item.products for item in self.verticals)


class RegisterCoverage(ResearchModel):
    register_name: str
    authority: str | None = None
    url: str | None = None
    entry_count: int | None = None
    files: tuple[str, ...] = Field(default_factory=tuple)

    @field_validator("files", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value


class BatchLineage(ResearchModel):
    file_name: str
    batch_id: str
    kind: PackKind
    run_date: str
    providers: int = Field(ge=0)
    products: int = Field(ge=0)


class VerticalProviderMap(ResearchModel):
    schema_id: str = Field(default=VERTICAL_MAP_SCHEMA, alias="schema")
    vertical_id: str
    jurisdiction: Literal["AU", "CA"]
    name: str
    registers: tuple[RegisterCoverage, ...] = Field(default_factory=tuple)
    provider_keys: tuple[str, ...] = Field(default_factory=tuple)
    providers_on_register: int | None = None
    providers_captured: int = Field(ge=0)
    providers_with_products: int = Field(ge=0)
    providers_identity_only: int = Field(ge=0)
    unprocessed_estimate: int | None = None
    products: int = Field(ge=0)
    by_class: dict[str, int] = Field(default_factory=dict)
    by_confidence: dict[str, int] = Field(default_factory=dict)
    rankable_pricing_facts: int = Field(ge=0)
    pricing_facts: int = Field(ge=0)
    census_complete: bool = False
    completeness: str
    catalog_digest: Sha256Digest
    advice_engine_ready: bool | None = None
    products_not_engine_eligible: int = Field(default=0, ge=0)
    providers_legal_name_unestablished: int = Field(default=0, ge=0)
    batches: tuple[BatchLineage, ...] = Field(default_factory=tuple)
    known_limitations: tuple[str, ...] = Field(default_factory=tuple)
    excluded: tuple[dict[str, Any], ...] = Field(default_factory=tuple)

    @field_validator("registers", "provider_keys", "batches", "known_limitations", "excluded", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value


class ProviderMap(ResearchModel):
    schema_id: str = Field(default=PROVIDER_MAP_SCHEMA, alias="schema")
    built_at: str
    packs: tuple[PackRecord, ...] = Field(default_factory=tuple)
    verticals: tuple[VerticalProviderMap, ...] = Field(default_factory=tuple)
    providers: tuple[ProviderIdentity, ...] = Field(default_factory=tuple)
    map_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("packs", "verticals", "providers", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> ProviderMap:
        keys = [item.provider_key for item in self.providers]
        if len(keys) != len(set(keys)):
            raise ValueError("provider keys must be unique")
        if not skip_digests(info) and self.map_digest != sealed_digest(ProviderMap, self, "map_digest"):
            raise ValueError("map_digest must commit the exact map")
        return self

    def provider(self, key: str) -> ProviderIdentity:
        for item in self.providers:
            if item.provider_key == key:
                return item
        raise AdviceProviderMapError("PROVIDER_UNKNOWN", f"{key} is not in the map")

    def vertical(self, vertical_id: str) -> VerticalProviderMap:
        for item in self.verticals:
            if item.vertical_id == vertical_id:
                return item
        raise AdviceProviderMapError("VERTICAL_UNKNOWN", f"{vertical_id} is not in the map")

    def providers_in(self, jurisdiction: str) -> tuple[ProviderIdentity, ...]:
        return tuple(item for item in self.providers if item.jurisdiction == jurisdiction)

    def cross_vertical(self) -> tuple[ProviderIdentity, ...]:
        return tuple(item for item in self.providers if len(item.verticals) > 1)


# --------------------------------------------------------------------------- #
# Building the map
# --------------------------------------------------------------------------- #


class _Identity:
    def __init__(self, jurisdiction: str, legal_name: str) -> None:
        self.jurisdiction = jurisdiction
        self.legal_name = legal_name
        self.normalized = normalize_name(legal_name)
        self.key = provider_key(jurisdiction, legal_name)
        self.aliases: dict[str, None] = {}
        self.identifiers: dict[tuple[str, str], Identifier] = {}
        self.licence_categories: dict[str, None] = {}
        self.registers: list[RegisterPresence] = []
        self.verticals: dict[str, dict[str, Any]] = {}
        self.candidates: list[CandidateMatch] = []
        self.gaps: dict[str, None] = {}
        self.files: dict[str, None] = {}
        self.product_reviewed = False
        self.legal_name_established = True
        self.legal_name_status: str | None = None

    def touch(self, vertical_id: str, file_name: str, *, products: int, discovery_status: str | None, disposition: str | None, identity_only: bool) -> None:
        presence = self.verticals.setdefault(vertical_id, {"products": 0, "discovery_status": None, "disposition": None, "identity_only": True, "files": {}})
        presence["products"] += products
        if discovery_status:
            presence["discovery_status"] = discovery_status
        if disposition:
            presence["disposition"] = disposition
        if not identity_only:
            presence["identity_only"] = False
            self.product_reviewed = True
        presence["files"][file_name] = None
        self.files[file_name] = None

    def build(self) -> ProviderIdentity:
        return ProviderIdentity(provider_key=self.key, jurisdiction=self.jurisdiction, legal_name=self.legal_name, normalized_name=self.normalized, aliases=tuple(name for name in self.aliases if normalize_name(name) != self.normalized), identifiers=tuple(self.identifiers.values()), licence_categories=tuple(self.licence_categories), registers=tuple(self.registers), verticals=tuple(VerticalPresence(vertical_id=vertical_id, products=item["products"], discovery_status=item["discovery_status"], disposition=item["disposition"], identity_only=item["identity_only"], files=tuple(item["files"])) for vertical_id, item in sorted(self.verticals.items())), candidate_matches=tuple(self.candidates), gaps=tuple(self.gaps), identity_only=not self.product_reviewed, files=tuple(self.files), legal_name_established=self.legal_name_established, legal_name_status=self.legal_name_status)


def _disposition_text(raw: Any) -> str | None:
    if isinstance(raw, Mapping):
        status = _text(raw.get("status"))
        reason = _text(raw.get("reason"))
        return status if reason is None else f"{status}: {reason}" if status else reason
    return _text(raw)


def _row_ordinal(raw: Mapping[str, Any]) -> int | None:
    for key in ("register_row_ordinal", "register_position", "sample_position"):
        value = raw.get(key)
        try:
            return int(str(value)) if value is not None and str(value).strip() != "" else None
        except ValueError:
            continue
    return None


def _fold_provider(identities: dict[str, _Identity], raw: Mapping[str, Any], *, jurisdiction: str, vertical_id: str, file_name: str, kind: PackKind, product_counts: Mapping[str, int]) -> None:
    legal_name, established, status = provider_identity_name(raw)
    if legal_name is None:
        return
    key = provider_key(jurisdiction, legal_name)
    identity = identities.get(key)
    if identity is None:
        identity = _Identity(jurisdiction, legal_name)
        identity.legal_name_established = established
        identity.legal_name_status = status
        identities[key] = identity
    elif not established and identity.legal_name_established and _text(raw.get("legal_name")) is None:
        identity.legal_name_established = False
        identity.legal_name_status = status
    for alias in _strings(raw.get("trading_names")):
        identity.aliases[alias] = None
    brand = _text(raw.get("provider_name"))
    if brand and normalize_name(brand) != identity.normalized:
        identity.aliases[brand] = None
    displayed = _text(raw.get("register_name_as_displayed"))
    if displayed and normalize_name(displayed) != identity.normalized:
        identity.aliases[displayed] = None
    for field, namespace in _IDENTIFIER_NAMESPACES:
        value = _text(raw.get(field))
        if value:
            identity.identifiers[(namespace, value)] = Identifier(namespace=namespace, value=value, namespace_as_stated=_text(raw.get(field + "_namespace")), file_name=file_name)
    register_identifier = _text(raw.get("register_identifier") or raw.get("provider_register_id") or raw.get("register_id"))
    if register_identifier:
        stated = _text(raw.get("register_identifier_type") or raw.get("register_id_type"))
        namespace = "ASIC_ACL" if stated and "credit licence" in stated.lower() else ("REGISTER_ID:" + slug(stated)[:40] if stated else "REGISTER_ID")
        identity.identifiers[(namespace, register_identifier)] = Identifier(namespace=namespace, value=register_identifier, namespace_as_stated=stated, file_name=file_name)
    for category in (_text(raw.get("licence_category")), _text(raw.get("approval_category"))):
        if category:
            identity.licence_categories[category] = None
    register_name = _text(raw.get("register_name") or raw.get("register_key"))
    if register_name:
        identity.registers.append(RegisterPresence(register_name=register_name, registration_status=_text(raw.get("registration_status")), row_ordinal=_row_ordinal(raw), licence_category=_text(raw.get("licence_category")), file_name=file_name))
    for gap in _strings(raw.get("gaps")):
        identity.gaps[gap] = None
    review = _text(raw.get("review_status")) or ""
    identity_only = kind == "census_reconciliation" or raw.get("record_type") == "census_identity_dossier" or review.startswith("census_identity")
    names = {legal_name.lower(), *(alias.lower() for alias in _strings(raw.get("trading_names"))), *((brand.lower(),) if brand else ())}
    products = sum(count for name, count in product_counts.items() if name in names)
    identity.touch(vertical_id, file_name, products=products, discovery_status=_text(raw.get("product_discovery_status")), disposition=_disposition_text(raw.get("disposition")), identity_only=identity_only)
    for match in raw.get("legacy_name_matches") or ():
        if not isinstance(match, Mapping):
            continue
        other = _text(match.get("inherited_name"))
        if other is None:
            continue
        confirmed = match.get("legal_identity_confirmed") is True
        match_type: MatchType = "census_confirmed" if confirmed else "name_variant_candidate"
        identity.candidates.append(CandidateMatch(other_name=other, match_type=match_type, file_name=file_name, confirmed=confirmed, note=_text(match.get("match_type"))))
        if confirmed and normalize_name(other) != identity.normalized:
            identity.aliases[other] = None
    for match in raw.get("legacy_trade_name_matches") or ():
        if isinstance(match, Mapping) and _text(match.get("inherited_name")):
            identity.candidates.append(CandidateMatch(other_name=str(match["inherited_name"]).strip(), match_type="trading_name_candidate", file_name=file_name, confirmed=False, note=_text(match.get("match_type"))))


def _merge_confirmed_aliases(identities: dict[str, _Identity]) -> None:
    """A census-confirmed legacy name that is itself a provider row folds into the census identity."""

    by_normalized = {identity.normalized: key for key, identity in identities.items()}
    for key, identity in list(identities.items()):
        for candidate in identity.candidates:
            if not candidate.confirmed:
                continue
            other_key = by_normalized.get(normalize_name(candidate.other_name))
            if other_key is None or other_key == key or other_key not in identities:
                continue
            other = identities.pop(other_key)
            identity.aliases[other.legal_name] = None
            identity.aliases.update(other.aliases)
            identity.identifiers.update(other.identifiers)
            identity.licence_categories.update(other.licence_categories)
            identity.registers.extend(other.registers)
            for vertical_id, presence in other.verticals.items():
                mine = identity.verticals.setdefault(vertical_id, {"products": 0, "discovery_status": None, "disposition": None, "identity_only": True, "files": {}})
                mine["products"] += presence["products"]
                mine["discovery_status"] = mine["discovery_status"] or presence["discovery_status"]
                mine["disposition"] = mine["disposition"] or presence["disposition"]
                mine["identity_only"] = mine["identity_only"] and presence["identity_only"]
                mine["files"].update(presence["files"])
            identity.gaps.update(other.gaps)
            identity.files.update(other.files)
            identity.product_reviewed = identity.product_reviewed or other.product_reviewed
            by_normalized[other.normalized] = key


def _trading_name_collisions(identities: dict[str, _Identity]) -> None:
    """A trading name that equals another provider's legal name is a candidate, never a merge."""

    by_normalized = {identity.normalized: identity for identity in identities.values()}
    for identity in identities.values():
        for alias in list(identity.aliases):
            other = by_normalized.get(normalize_name(alias))
            if other is not None and other is not identity:
                identity.candidates.append(CandidateMatch(other_name=other.legal_name, match_type="trading_name_candidate", file_name=next(iter(identity.files), ""), confirmed=False, note=f"trading name {alias!r} equals another provider's legal name"))


def _batch_id(file_name: str, payload: Mapping[str, Any]) -> str:
    coverage = payload.get("coverage") if isinstance(payload.get("coverage"), Mapping) else {}
    stated = _text(coverage.get("batch_id"))
    if stated:
        return stated
    match = re.search(r"(batch|census_reconciliation)_(\d+)", file_name.lower())
    if match:
        return f"{match.group(1)}_{int(match.group(2)):02d}"
    return "batch_01"


def build_provider_map(packs: Sequence[tuple[str, Mapping[str, Any]]], *, built_at: str, registry: VerticalRegistry | None = None) -> tuple[ProviderMap, dict[str, ProductCatalog]]:
    """Fold every pack into one map; returns the map and the merged product catalog per vertical."""

    registry = registry or load_vertical_registry()
    _require(bool(packs), "PACKS_MISSING", "build the map from at least one pack")
    stamp = timestamp(built_at, field_name="built_at")
    records: list[PackRecord] = []
    identities: dict[str, _Identity] = {}
    catalogs_by_vertical: dict[str, list[ProductCatalog]] = {}
    lineage: dict[str, list[BatchLineage]] = {}
    registers_by_vertical: dict[str, dict[str, dict[str, Any]]] = {}
    seen_digests: set[str] = set()
    for file_name, payload in packs:
        pack = dict(detached(payload))
        digest = _sha256(json.dumps(pack, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str))
        if digest in seen_digests:
            continue
        seen_digests.add(digest)
        jurisdiction, vertical_id = infer_vertical(file_name, pack, registry=registry)
        kind = pack_kind(file_name, pack)
        catalog = ingest_catalog_pack(pack, vertical_id=vertical_id, jurisdiction=jurisdiction, registry=registry)
        catalogs_by_vertical.setdefault(vertical_id, []).append(catalog)
        product_counts: dict[str, int] = {}
        for product in catalog.products:
            for name in {product.provider_name.lower(), (product.issuer_legal_name or "").lower()}:
                if name:
                    product_counts[name] = product_counts.get(name, 0) + 1
        for raw in pack.get("providers") or ():
            if isinstance(raw, Mapping):
                _fold_provider(identities, raw, jurisdiction=jurisdiction, vertical_id=vertical_id, file_name=file_name, kind=kind, product_counts=product_counts)
        # products whose provider row is absent still belong to a provider
        known_names = {identity.normalized for identity in identities.values()} | {normalize_name(alias) for identity in identities.values() for alias in identity.aliases}
        for product in catalog.products:
            key = provider_key(jurisdiction, product.provider_name)
            if key not in identities and normalize_name(product.provider_name) not in known_names:
                identity = _Identity(jurisdiction, product.provider_name)
                identity.gaps["provider row absent from the pack's register section; attributed from the product's own provider name"] = None
                identities[key] = identity
                identity.touch(vertical_id, file_name, products=0, discovery_status=None, disposition=None, identity_only=False)
        for register in catalog.registers:
            entry = registers_by_vertical.setdefault(vertical_id, {}).setdefault(register.register_name, {"authority": register.authority, "url": register.url, "entry_count": None, "files": {}})
            if register.entry_count is not None:
                entry["entry_count"] = max(entry["entry_count"] or 0, register.entry_count)
            entry["files"][file_name] = None
        batch = BatchLineage(file_name=file_name, batch_id=_batch_id(file_name, pack), kind=kind, run_date=catalog.run_date, providers=len(catalog.providers), products=len(catalog.products))
        lineage.setdefault(vertical_id, []).append(batch)
        records.append(PackRecord(file_name=file_name, jurisdiction=jurisdiction, vertical_id=vertical_id, kind=kind, batch_id=batch.batch_id, run_date=catalog.run_date, providers=len(catalog.providers), products=len(catalog.products), pack_digest=digest))
    _merge_confirmed_aliases(identities)
    _trading_name_collisions(identities)
    providers = tuple(sorted((identity.build() for identity in identities.values()), key=lambda item: (item.jurisdiction, item.normalized_name)))

    merged: dict[str, ProductCatalog] = {}
    verticals: list[VerticalProviderMap] = []
    for vertical_id, batches in sorted(catalogs_by_vertical.items()):
        catalog = merge_catalogs(*batches)
        merged[vertical_id] = catalog
        vertical = registry.vertical(vertical_id)
        keys = tuple(item.provider_key for item in providers if any(presence.vertical_id == vertical_id for presence in item.verticals))
        with_products = sum(1 for item in providers for presence in item.verticals if presence.vertical_id == vertical_id and presence.products > 0)
        identity_only = sum(1 for item in providers for presence in item.verticals if presence.vertical_id == vertical_id and presence.identity_only)
        by_class: dict[str, int] = {}
        by_confidence: dict[str, int] = {}
        facts = rankable = ineligible = 0
        for product in catalog.products:
            by_class[product.taxonomy_class] = by_class.get(product.taxonomy_class, 0) + 1
            by_confidence[product.confidence] = by_confidence.get(product.confidence, 0) + 1
            facts += len(product.pricing)
            rankable += len(product.rankable_pricing)
            if not engine_eligible(product, catalog):
                ineligible += 1
        unestablished = sum(1 for item in providers if not item.legal_name_established and any(presence.vertical_id == vertical_id for presence in item.verticals))
        on_register = max((batch.coverage.providers_on_register or 0 for batch in batches), default=0) or None
        registers = tuple(RegisterCoverage(register_name=name, authority=item["authority"], url=item["url"], entry_count=item["entry_count"], files=tuple(item["files"])) for name, item in sorted(registers_by_vertical.get(vertical_id, {}).items()))
        verticals.append(VerticalProviderMap(vertical_id=vertical_id, jurisdiction=vertical.jurisdiction, name=vertical.name, registers=registers, provider_keys=keys, providers_on_register=on_register, providers_captured=len(keys), providers_with_products=with_products, providers_identity_only=identity_only, unprocessed_estimate=None if on_register is None or len(keys) > on_register else on_register - len(keys), products=len(catalog.products), by_class=dict(sorted(by_class.items())), by_confidence=dict(sorted(by_confidence.items())), rankable_pricing_facts=rankable, pricing_facts=facts, census_complete=catalog.coverage.census_complete, completeness=catalog.completeness, catalog_digest=catalog.catalog_digest, advice_engine_ready=catalog.coverage.advice_engine_ready, products_not_engine_eligible=ineligible, providers_legal_name_unestablished=unestablished, batches=tuple(sorted(lineage.get(vertical_id, ()), key=lambda item: (item.run_date, 0 if item.kind == "catalog_batch" else 1, item.batch_id))), known_limitations=catalog.coverage.known_limitations[:20], excluded=catalog.coverage.excluded[:40]))
    provider_map = seal(ProviderMap, {"built_at": stamp, "packs": [item.to_dict() for item in sorted(records, key=lambda item: item.file_name)], "verticals": [item.to_dict() for item in verticals], "providers": [item.to_dict() for item in providers]}, "map_digest")
    return provider_map, merged


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #


def provider_map_report(provider_map: ProviderMap | Mapping[str, Any]) -> str:
    """A human-readable ledger of the map: per vertical coverage, the providers, and what a person still has to confirm."""

    m = provider_map if isinstance(provider_map, ProviderMap) else ProviderMap.model_validate(dict(detached(provider_map)))
    lines = [f"# Financial product provider map", "", f"Built {m.built_at} from {len(m.packs)} pack(s); {len(m.providers)} providers across {len(m.verticals)} vertical(s).", ""]
    for jurisdiction in ("AU", "CA"):
        verticals = [item for item in m.verticals if item.jurisdiction == jurisdiction]
        if not verticals:
            continue
        lines.append(f"## {'Australia' if jurisdiction == 'AU' else 'Canada'}")
        lines.append("")
        for vertical in verticals:
            lines.append(f"### {vertical.vertical_id} {vertical.name}")
            denominator = vertical.providers_on_register if vertical.providers_on_register is not None else "unstated"
            lines.append(f"- Register section: {denominator} providers; captured {vertical.providers_captured}; with products {vertical.providers_with_products}; identity only {vertical.providers_identity_only}; unprocessed estimate {vertical.unprocessed_estimate if vertical.unprocessed_estimate is not None else 'unknown'}.")
            lines.append(f"- Products {vertical.products} ({', '.join(f'{k} {v}' for k, v in vertical.by_class.items()) or 'none'}); confidence {', '.join(f'{k} {v}' for k, v in vertical.by_confidence.items()) or 'n/a'}; pricing facts {vertical.rankable_pricing_facts} rankable of {vertical.pricing_facts}.")
            lines.append(f"- Completeness: {vertical.completeness}; census complete: {'yes' if vertical.census_complete else 'no'}.")
            if vertical.products_not_engine_eligible or vertical.providers_legal_name_unestablished or vertical.advice_engine_ready is False:
                lines.append(f"- Not yet advisable: {vertical.products_not_engine_eligible} product record(s) marked not advice-engine eligible by their pack; {vertical.providers_legal_name_unestablished} provider(s) keyed on the register-displayed entry because no legal name is established; pack readiness {'not ready' if vertical.advice_engine_ready is False else ('ready' if vertical.advice_engine_ready else 'unstated')}.")
            lines.append(f"- Registers: " + "; ".join(f"{item.register_name} ({item.entry_count if item.entry_count is not None else 'count unstated'})" for item in vertical.registers))
            lines.append(f"- Batches: " + ", ".join(f"{item.batch_id} [{item.kind}] {item.run_date} ({item.providers} providers, {item.products} products)" for item in vertical.batches))
            top = sorted((m.provider(key) for key in vertical.provider_keys), key=lambda item: -next((presence.products for presence in item.verticals if presence.vertical_id == vertical.vertical_id), 0))
            lines.append("- Providers (products): " + "; ".join(f"{item.legal_name} ({next(presence.products for presence in item.verticals if presence.vertical_id == vertical.vertical_id)})" for item in top[:60]))
            if vertical.known_limitations:
                lines.append("- Known limitations: " + " | ".join(vertical.known_limitations[:4]))
            lines.append("")
    cross = m.cross_vertical()
    if cross:
        lines.append("## Providers present in more than one vertical")
        lines.append("")
        for item in cross:
            lines.append(f"- {item.legal_name} ({item.jurisdiction}): " + ", ".join(f"{presence.vertical_id} {presence.products}" for presence in item.verticals))
        lines.append("")
    pending = [(item, candidate) for item in m.providers for candidate in item.candidate_matches if not candidate.confirmed]
    if pending:
        lines.append("## Identity matches a person still confirms")
        lines.append("")
        for item, candidate in pending[:200]:
            lines.append(f"- {item.legal_name} ({item.jurisdiction}) ~ {candidate.other_name} [{candidate.match_type}] from {candidate.file_name}")
        lines.append("")
    return "\n".join(lines)


ADVICE_PROVIDER_MAP_MANIFEST: dict[str, Any] = {
    "kind": "lightbulb.finance_advice_provider_map",
    "schemas": [PROVIDER_MAP_SCHEMA, VERTICAL_MAP_SCHEMA, PROVIDER_IDENTITY_SCHEMA, PACK_RECORD_SCHEMA],
    "hard_rules": [
        "two rows are one provider only on a normalised legal-name match or a census-confirmed legacy match",
        "a trading name is an alias, never a merge key; a collision with another legal name is a candidate for a person",
        "a product is never attributed from a brand to a group company",
        "coverage denominators name the register section; a capped batch is a partial sample",
        "the map is rebuilt from the packs, never edited by hand",
    ],
}

__all__ = [
    "ADVICE_PROVIDER_MAP_MANIFEST",
    "PACK_RECORD_SCHEMA",
    "PROVIDER_IDENTITY_SCHEMA",
    "PROVIDER_MAP_SCHEMA",
    "VERTICAL_MAP_SCHEMA",
    "AdviceProviderMapError",
    "BatchLineage",
    "CandidateMatch",
    "Identifier",
    "PackRecord",
    "ProviderIdentity",
    "ProviderMap",
    "RegisterCoverage",
    "RegisterPresence",
    "VerticalPresence",
    "VerticalProviderMap",
    "build_provider_map",
    "infer_vertical",
    "normalize_name",
    "pack_kind",
    "provider_key",
    "provider_map_report",
    "slug",
]
