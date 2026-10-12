"""Evidence capture and change detection: what a source said when it was read, and what changed since.

A snapshot commits to the bytes a check retrieved (hash, length, media type, validators, the
fingerprint of each monitored section) and to the parser that read them, so a provider's change
can be told from a change in our own extraction. The bytes themselves live in the platform's
object store under ``storage_ref``; the SDK never holds them.

``compare_snapshots`` answers three separate questions, cheapest first: did the response change
(raw), did a monitored section change (relevant), did a decision input change (meaning). An
expected section that disappears is an operational problem, never an empty list that withdraws
every product. A PDF that changes under the same URL is a raw change like any other.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, Sha256Digest, detached, seal, sealed_digest, skip_digests, timestamp
from lightbulb.finance_advice_catalog import ProductCatalog, ResearchModel
from lightbulb.finance_advice_sources import fact_field

SNAPSHOT_SCHEMA = "lightbulb.finance_advice_snapshot.v1"
CHANGE_REPORT_SCHEMA = "lightbulb.finance_advice_change_report.v1"
MAX_FACTS = 50_000

ChangeTier = Literal["none", "cosmetic", "relevant", "meaning", "operational_problem"]


class AdviceSnapshotError(ValueError):
    pass


def _jsonable(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    return value


def _canonical(value: Any) -> str:
    return json.dumps(_jsonable(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


class Snapshot(ResearchModel):
    schema_id: str = Field(default=SNAPSHOT_SCHEMA, alias="schema")
    source_key: str
    retrieved_at: str
    final_url: str
    status_code: int | None = None
    media_type: str | None = None
    content_sha256: str
    content_length: int = Field(ge=0)
    etag: str | None = None
    last_modified: str | None = None
    request_context: dict[str, Any] = Field(default_factory=dict)
    rendered: bool = False
    sections: dict[str, str] = Field(default_factory=dict)
    missing_sections: tuple[str, ...] = Field(default_factory=tuple)
    parser: str | None = None
    parser_version: str | None = None
    storage_ref: str | None = None
    previous_snapshot_digest: str | None = None
    snapshot_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("missing_sections", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("content_sha256")
    @classmethod
    def _sha(cls, value: str) -> str:
        if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value.lower()):
            raise ValueError("content_sha256 is a hex sha256")
        return value.lower()

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> Snapshot:
        if not skip_digests(info) and self.snapshot_digest != sealed_digest(Snapshot, self, "snapshot_digest"):
            raise ValueError("snapshot_digest must commit the exact snapshot")
        return self


def snapshot(payload: Mapping[str, Any]) -> Snapshot:
    body = dict(detached(payload))
    body["retrieved_at"] = timestamp(str(body.get("retrieved_at")), field_name="retrieved_at")
    return seal(Snapshot, body, "snapshot_digest")


class ExtractedFact(ResearchModel):
    """One decision input as an extractor read it from a snapshot; the field key is the catalog's."""

    product_ref: str
    field: str
    value: Any = None
    unit: str | None = None
    applicability: dict[str, Any] = Field(default_factory=dict)
    locator: str | None = None
    quote: str | None = None
    source_effective_from: str | None = None
    source_effective_to: str | None = None

    @property
    def key(self) -> tuple[str, str]:
        return (self.product_ref, self.field)


def facts_from_catalog(catalog: ProductCatalog | Mapping[str, Any]) -> tuple[ExtractedFact, ...]:
    """A catalog's decision inputs as extracted facts, so two reads of one source compare the same way whatever produced them."""

    c = catalog if isinstance(catalog, ProductCatalog) else ProductCatalog.model_validate(dict(detached(catalog)))
    out: list[ExtractedFact] = []
    for product in c.products:
        for fact in product.pricing:
            value = str(fact.value) if fact.value is not None else fact.value_as_stated
            out.append(ExtractedFact(product_ref=product.product_ref, field=fact_field(fact.item, fact.conditions), value=value, unit=fact.unit, applicability={k: v for k, v in fact.conditions.items() if k not in ("rate_status", "current_price_verified", "is_selected_as_current_executable_price")}, quote=fact.quote, source_effective_from=str(fact.conditions.get("effective_date")) if fact.conditions.get("effective_date") else product.effective_date, source_effective_to=str(fact.conditions.get("expiry_date")) if fact.conditions.get("expiry_date") else None))
        for term in product.key_terms:
            out.append(ExtractedFact(product_ref=product.product_ref, field=f"key_term:{term.term}", value=_jsonable(term.value)))
        if product.eligibility:
            out.append(ExtractedFact(product_ref=product.product_ref, field="eligibility", value=list(product.eligibility)))
        out.append(ExtractedFact(product_ref=product.product_ref, field="availability", value=product.availability_status or "stated_available"))
    return tuple(out)


class FieldChange(ResearchModel):
    product_ref: str
    field: str
    previous: Any = None
    current: Any = None
    applicability: dict[str, Any] = Field(default_factory=dict)
    locator: str | None = None
    quote: str | None = None
    disposition: Literal["changed", "appeared", "disappeared"]


class ChangeReport(ResearchModel):
    schema_id: str = Field(default=CHANGE_REPORT_SCHEMA, alias="schema")
    source_key: str
    previous_snapshot_digest: str | None = None
    snapshot_digest: str
    raw_changed: bool
    relevant_changed: tuple[str, ...] = Field(default_factory=tuple)
    sections_missing: tuple[str, ...] = Field(default_factory=tuple)
    meaning_changed: tuple[FieldChange, ...] = Field(default_factory=tuple, max_length=MAX_FACTS)
    tier: ChangeTier
    notes: tuple[str, ...] = Field(default_factory=tuple)
    report_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("relevant_changed", "sections_missing", "meaning_changed", "notes", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> ChangeReport:
        if not skip_digests(info) and self.report_digest != sealed_digest(ChangeReport, self, "report_digest"):
            raise ValueError("report_digest must commit the exact report")
        return self


def compare_snapshots(previous: Snapshot | Mapping[str, Any] | None, current: Snapshot | Mapping[str, Any], *, previous_facts: Sequence[ExtractedFact | Mapping[str, Any]] = (), current_facts: Sequence[ExtractedFact | Mapping[str, Any]] = ()) -> ChangeReport:
    """Raw, relevant and meaning changes between two reads of one source; a missing expected section outranks everything."""

    cur = current if isinstance(current, Snapshot) else Snapshot.model_validate(dict(detached(current)))
    prev = None if previous is None else (previous if isinstance(previous, Snapshot) else Snapshot.model_validate(dict(detached(previous))))
    if prev is not None and prev.source_key != cur.source_key:
        raise AdviceSnapshotError("SNAPSHOT_SOURCE_MISMATCH: snapshots of different sources do not compare")
    notes: list[str] = []
    raw_changed = prev is None or prev.content_sha256 != cur.content_sha256
    if prev is None:
        notes.append("first snapshot of this source; every fact is an appearance, not a change")
    missing = sorted(set(cur.missing_sections) | ({label for label in prev.sections if label not in cur.sections} if prev is not None else set()))
    relevant = sorted(label for label, fingerprint in cur.sections.items() if prev is not None and label in prev.sections and prev.sections[label] != fingerprint)
    if prev is not None and prev.content_sha256 == cur.content_sha256 and cur.rendered and not cur.sections:
        notes.append("the shell is unchanged and no rendered section was fingerprinted; the widget's content is unknown, not unchanged")
    before = {fact.key: fact for fact in (item if isinstance(item, ExtractedFact) else ExtractedFact.model_validate(dict(detached(item))) for item in previous_facts)}
    after = {fact.key: fact for fact in (item if isinstance(item, ExtractedFact) else ExtractedFact.model_validate(dict(detached(item))) for item in current_facts)}
    changes: list[FieldChange] = []
    for key in sorted(set(before) | set(after)):
        old, new = before.get(key), after.get(key)
        if old is not None and new is not None:
            if _canonical(old.value) != _canonical(new.value) or (old.unit or "") != (new.unit or ""):
                changes.append(FieldChange(product_ref=key[0], field=key[1], previous=old.value, current=new.value, applicability=dict(new.applicability), locator=new.locator, quote=new.quote, disposition="changed"))
        elif new is not None:
            if prev is not None:
                changes.append(FieldChange(product_ref=key[0], field=key[1], previous=None, current=new.value, applicability=dict(new.applicability), locator=new.locator, quote=new.quote, disposition="appeared"))
        elif old is not None:
            if missing:
                notes.append(f"{key[1]} of {key[0]} was not read because a section is missing; that is an extraction failure, not a withdrawal")
            else:
                changes.append(FieldChange(product_ref=key[0], field=key[1], previous=old.value, current=None, applicability=dict(old.applicability), locator=old.locator, quote=None, disposition="disappeared"))
    if missing:
        tier: ChangeTier = "operational_problem"
    elif changes:
        tier = "meaning"
    elif relevant:
        tier = "relevant"
    elif raw_changed and prev is not None:
        tier = "cosmetic"
    else:
        tier = "none"
    return seal(ChangeReport, {"source_key": cur.source_key, "previous_snapshot_digest": prev.snapshot_digest if prev is not None else None, "snapshot_digest": cur.snapshot_digest, "raw_changed": raw_changed, "relevant_changed": relevant, "sections_missing": missing, "meaning_changed": [item.to_dict() for item in changes], "tier": tier, "notes": notes}, "report_digest")


__all__ = [
    "CHANGE_REPORT_SCHEMA",
    "SNAPSHOT_SCHEMA",
    "AdviceSnapshotError",
    "ChangeReport",
    "ChangeTier",
    "ExtractedFact",
    "FieldChange",
    "Snapshot",
    "compare_snapshots",
    "facts_from_catalog",
    "snapshot",
]
