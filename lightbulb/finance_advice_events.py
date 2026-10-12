"""Fact-change events and what they touch: the versioned message the platform's outbox carries, and the impact on advice already given.

Updating the published view is half the job. A published change must reach the comparisons,
cached answers and open cases that relied on the changed facts. The SDK names the event
(what changed, for which products and fields, from which observations) and judges impact
against a shortlist; the platform delivers it through its transactional outbox onto Kafka and
recomputes. Consumers tolerate duplicates and reordering: every event carries the observation
refs and the published catalog digest, so a late or repeated event is recognisable.

Advice already given is never rewritten. A recommendation stays what it was, sealed against the
catalog it used; a new comparison is produced when the facts move.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, Sha256Digest, detached, seal, sealed_digest, skip_digests, timestamp
from lightbulb.finance_advice_catalog import ResearchModel
from lightbulb.finance_advice_engine import Shortlist
from lightbulb.finance_advice_observations import Observation, ProposedChange

FACT_CHANGE_EVENT_SCHEMA = "lightbulb.finance_advice_fact_change_event.v1"
IMPACT_SCHEMA = "lightbulb.finance_advice_impact.v1"
EVENT_VERSION = 1

EventKind = Literal["fact_accepted", "fact_held", "fact_released", "fact_expired", "fact_scheduled_active", "fact_stale", "operational_problem"]


def _digest(*parts: Any) -> str:
    return hashlib.sha256(json.dumps(list(parts), sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")).hexdigest()


class FactChangeEvent(ResearchModel):
    schema_id: str = Field(default=FACT_CHANGE_EVENT_SCHEMA, alias="schema")
    event_ref: str
    event_version: int = EVENT_VERSION
    kind: EventKind
    jurisdiction: Literal["AU", "CA"]
    vertical_id: str
    product_refs: tuple[str, ...] = Field(default_factory=tuple)
    fields: tuple[str, ...] = Field(default_factory=tuple)
    observation_refs: tuple[str, ...] = Field(default_factory=tuple)
    change_refs: tuple[str, ...] = Field(default_factory=tuple)
    source_key: str | None = None
    published_catalog_digest: str | None = None
    occurred_at: str
    summary: str
    event_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("product_refs", "fields", "observation_refs", "change_refs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> FactChangeEvent:
        if not skip_digests(info) and self.event_digest != sealed_digest(FactChangeEvent, self, "event_digest"):
            raise ValueError("event_digest must commit the exact event")
        return self


def _event(kind: EventKind, *, jurisdiction: str, vertical_id: str, product_refs: Sequence[str], fields: Sequence[str], observation_refs: Sequence[str] = (), change_refs: Sequence[str] = (), source_key: str | None, published_catalog_digest: str | None, occurred_at: str, summary: str) -> FactChangeEvent:
    stamp = timestamp(occurred_at, field_name="occurred_at")
    refs = sorted(set(product_refs))
    names = sorted(set(fields))
    return seal(FactChangeEvent, {"event_ref": "event:" + _digest(kind, vertical_id, refs, names, list(observation_refs), list(change_refs), source_key, stamp)[:24], "kind": kind, "jurisdiction": jurisdiction, "vertical_id": vertical_id, "product_refs": refs, "fields": names, "observation_refs": sorted(set(observation_refs)), "change_refs": sorted(set(change_refs)), "source_key": source_key, "published_catalog_digest": published_catalog_digest, "occurred_at": stamp, "summary": summary}, "event_digest")


def events_for_accepted(accepted: Sequence[Observation | Mapping[str, Any]], *, jurisdiction: str, vertical_id: str, published_catalog_digest: str | None, occurred_at: str) -> tuple[FactChangeEvent, ...]:
    """One event per source for the observations a person or an earned adapter accepted."""

    items = [obs if isinstance(obs, Observation) else Observation.model_validate(dict(detached(obs))) for obs in accepted]
    by_source: dict[str, list[Observation]] = {}
    for item in items:
        if item.status == "accepted":
            by_source.setdefault(item.source_key, []).append(item)
    return tuple(_event("fact_accepted", jurisdiction=jurisdiction, vertical_id=vertical_id, product_refs=[o.product_ref for o in group], fields=[o.field for o in group], observation_refs=[o.observation_ref for o in group], source_key=source_key, published_catalog_digest=published_catalog_digest, occurred_at=occurred_at, summary=f"{len(group)} fact(s) accepted from {source_key}") for source_key, group in sorted(by_source.items()))


def events_for_holds(held: Sequence[Observation | Mapping[str, Any]], changes: Sequence[ProposedChange | Mapping[str, Any]], *, jurisdiction: str, vertical_id: str, occurred_at: str) -> tuple[FactChangeEvent, ...]:
    """A hold is news too: the facts a pending change or an operational problem restricted."""

    items = [obs if isinstance(obs, Observation) else Observation.model_validate(dict(detached(obs))) for obs in held]
    pending = [ch if isinstance(ch, ProposedChange) else ProposedChange.model_validate(dict(detached(ch))) for ch in changes]
    held_items = [item for item in items if item.hold and item.status == "accepted"]
    out: list[FactChangeEvent] = []
    if held_items:
        by_source: dict[str, list[Observation]] = {}
        for item in held_items:
            by_source.setdefault(item.source_key, []).append(item)
        for source_key, group in sorted(by_source.items()):
            refs = [ch.change_ref for ch in pending if ch.source_key == source_key]
            out.append(_event("fact_held", jurisdiction=jurisdiction, vertical_id=vertical_id, product_refs=[o.product_ref for o in group], fields=[o.field for o in group], observation_refs=[o.observation_ref for o in group], change_refs=refs, source_key=source_key, published_catalog_digest=None, occurred_at=occurred_at, summary=f"{len(group)} fact(s) held pending review of {len(refs)} change(s) from {source_key}"))
    for change in pending:
        if change.handling == "operational":
            out.append(_event("operational_problem", jurisdiction=jurisdiction, vertical_id=vertical_id, product_refs=(), fields=(), change_refs=[change.change_ref], source_key=change.source_key, published_catalog_digest=None, occurred_at=occurred_at, summary=change.policy_reason))
    return tuple(out)


def events_for_clock(observations: Sequence[Observation | Mapping[str, Any]], *, jurisdiction: str, vertical_id: str, previous_as_of: str, as_of: str, freshness_hours: Mapping[str, int] | None = None) -> tuple[FactChangeEvent, ...]:
    """What the clock alone changed between two moments: activations, expiries and facts that went stale with no website change at all."""

    from lightbulb.finance_advice_observations import field_role, freshness_of

    items = [obs if isinstance(obs, Observation) else Observation.model_validate(dict(detached(obs))) for obs in observations]
    groups: dict[str, list[Observation]] = {"fact_scheduled_active": [], "fact_expired": [], "fact_stale": []}
    for item in items:
        if item.status != "accepted":
            continue
        before = freshness_of(as_of=previous_as_of, last_revalidated_at=item.last_revalidated_at, effective_from=item.source_effective_from, effective_to=item.source_effective_to, hold=item.hold, role=field_role(item.field), freshness_hours=freshness_hours)
        after = freshness_of(as_of=as_of, last_revalidated_at=item.last_revalidated_at, effective_from=item.source_effective_from, effective_to=item.source_effective_to, hold=item.hold, role=field_role(item.field), freshness_hours=freshness_hours)
        if before == after:
            continue
        if before == "scheduled" and after == "fresh":
            groups["fact_scheduled_active"].append(item)
        elif after == "expired":
            groups["fact_expired"].append(item)
        elif after == "stale":
            groups["fact_stale"].append(item)
    return tuple(_event(kind, jurisdiction=jurisdiction, vertical_id=vertical_id, product_refs=[o.product_ref for o in group], fields=[o.field for o in group], observation_refs=[o.observation_ref for o in group], source_key=None, published_catalog_digest=None, occurred_at=as_of, summary=f"{len(group)} fact(s) {kind.replace('fact_', '').replace('_', ' ')} by the clock between {previous_as_of} and {as_of}") for kind, group in groups.items() if group)  # type: ignore[arg-type]


class Impact(ResearchModel):
    schema_id: str = Field(default=IMPACT_SCHEMA, alias="schema")
    event_ref: str
    shortlist_digest: str
    affected_product_refs: tuple[str, ...] = Field(default_factory=tuple)
    recompute: bool
    reason: str

    @field_validator("affected_product_refs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value


def impact_on_shortlist(event: FactChangeEvent | Mapping[str, Any], shortlist: Shortlist | Mapping[str, Any]) -> Impact:
    """Whether a shortlist must be produced again: a changed fact of a listed product, or a newly accepted fact in the same vertical that could reorder it."""

    ev = event if isinstance(event, FactChangeEvent) else FactChangeEvent.model_validate(dict(detached(event)))
    sl = shortlist if isinstance(shortlist, Shortlist) else Shortlist.model_validate(dict(detached(shortlist)))
    listed = {entry.product_ref for entry in sl.entries}
    affected = sorted(listed & set(ev.product_refs))
    if ev.vertical_id != sl.vertical_id:
        return Impact(event_ref=ev.event_ref, shortlist_digest=sl.shortlist_digest, affected_product_refs=(), recompute=False, reason="another vertical")
    if ev.kind == "operational_problem":
        return Impact(event_ref=ev.event_ref, shortlist_digest=sl.shortlist_digest, affected_product_refs=(), recompute=False, reason="an operational problem holds facts; the hold event decides")
    if affected:
        return Impact(event_ref=ev.event_ref, shortlist_digest=sl.shortlist_digest, affected_product_refs=tuple(affected), recompute=True, reason=f"{len(affected)} shortlisted product(s) carry a fact this event changed ({ev.kind})")
    if ev.kind == "fact_accepted" and any(field.startswith("pricing:") for field in ev.fields):
        return Impact(event_ref=ev.event_ref, shortlist_digest=sl.shortlist_digest, affected_product_refs=(), recompute=True, reason="a pricing fact was accepted in this vertical for a product outside the shortlist; the ranking may change")
    return Impact(event_ref=ev.event_ref, shortlist_digest=sl.shortlist_digest, affected_product_refs=(), recompute=False, reason="no shortlisted product and no new pricing in this vertical")


__all__ = [
    "EVENT_VERSION",
    "FACT_CHANGE_EVENT_SCHEMA",
    "IMPACT_SCHEMA",
    "EventKind",
    "FactChangeEvent",
    "Impact",
    "events_for_accepted",
    "events_for_clock",
    "events_for_holds",
    "impact_on_shortlist",
]
