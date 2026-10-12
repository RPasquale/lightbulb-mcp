"""Observations: versioned, bitemporal product facts, the publication policy, and the view the engine reads.

Three layers, never overwritten in place:

* **Evidence** is the snapshot (``finance_advice_snapshots``): what a source said when it was read.
* **Observations** are the facts extracted from evidence, each carrying the source's own effective
  dates, when it was observed, when a person accepted it, and when it was last successfully
  revalidated. A proposed observation is not a fact; an accepted one supersedes its predecessor
  and keeps it in history; a hold restricts a fact whose evidence changed while review is pending.
* **The published view** is the subset the advice engine may use as of one moment, reconstructed
  for any knowledge time so advice given on Tuesday is explained by what was known on Tuesday.

Freshness is a separate state from confidence: a verified fact can be stale and a fresh fact can
be unverified. Both are judged at the point of use, per field, and a stale rate never ranks.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import timedelta
from decimal import Decimal, InvalidOperation
from typing import Any, Literal

from pydantic import Field, field_validator, model_validator

from lightbulb.company_engine_core import detached, parsed, seal, timestamp
from lightbulb.finance_advice_catalog import KeyTerm, PricingFact, ProductCatalog, ResearchModel, unit_kind
from lightbulb.finance_advice_snapshots import ChangeReport, FieldChange
from lightbulb.finance_advice_sources import DEFAULT_FRESHNESS_HOURS

OBSERVATION_SCHEMA = "lightbulb.finance_advice_observation.v1"
PROPOSED_CHANGE_SCHEMA = "lightbulb.finance_advice_proposed_change.v1"
PUBLISHED_VIEW_NOTE = "published view"

ObservationStatus = Literal["proposed", "accepted", "rejected", "superseded", "withdrawn"]
ChangeKind = Literal["cosmetic", "rate_change", "fee_change", "eligibility_change", "terms_change", "availability_change", "new_product_candidate", "identity_change", "operational_problem", "expiry", "scheduled_activation"]
Handling = Literal["no_fact_change", "auto_publish", "review", "candidate", "operational"]
Freshness = Literal["fresh", "stale", "scheduled", "expired", "held", "unstated"]

# The starting publication policy. Automatic publication is a per-adapter, per-field decision
# that an adapter earns after testing; nothing here is a global "trust the AI" switch.
PUBLICATION_POLICY: dict[str, Handling] = {
    "cosmetic": "no_fact_change",
    "rate_change": "review",
    "fee_change": "review",
    "eligibility_change": "review",
    "terms_change": "review",
    "availability_change": "review",
    "new_product_candidate": "candidate",
    "identity_change": "review",
    "operational_problem": "operational",
    "expiry": "auto_publish",
    "scheduled_activation": "auto_publish",
}
AUTO_PUBLISHABLE_KINDS = frozenset({"rate_change", "fee_change"})


class AdviceObservationError(ValueError):
    pass


def _require(condition: bool, code: str, detail: str) -> None:
    if not condition:
        raise AdviceObservationError(f"{code}: {detail}")


def _jsonable(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, Decimal):
        return str(value)
    return value


def _canonical(value: Any) -> str:
    return json.dumps(_jsonable(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _digest(*parts: Any) -> str:
    return hashlib.sha256(_canonical(list(parts)).encode("utf-8")).hexdigest()


def _stamp(value: str | None) -> str | None:
    if value is None:
        return None
    return value if len(value) > 10 else value + "T00:00:00Z"


def field_role(field: str) -> str:
    """Which freshness policy a field falls under."""

    lower = field.lower()
    if "[profile=" in lower:
        return "quote"  # a captured quote is fresh for its validity window and expires with it
    if lower.startswith("pricing:"):
        return "fees" if "fee" in lower or "charge" in lower else "rates"
    if lower.startswith("key_term:"):
        return "terms"
    if lower == "eligibility":
        return "eligibility"
    if lower in ("availability", "identity"):
        return "product_index"
    return "other"


def change_kind(change: FieldChange) -> ChangeKind:
    if change.disposition == "appeared" and change.field == "availability":
        return "new_product_candidate"
    if change.field == "availability":
        return "availability_change"
    if change.field == "identity":
        return "identity_change"
    if change.field == "eligibility":
        return "eligibility_change"
    if change.field.startswith("key_term:"):
        return "terms_change"
    if change.field.startswith("pricing:"):
        return "fee_change" if field_role(change.field) == "fees" else "rate_change"
    return "terms_change"


class Observation(ResearchModel):
    schema_id: str = Field(default=OBSERVATION_SCHEMA, alias="schema")
    observation_ref: str
    product_ref: str
    field: str
    value: Any = None
    unit: str | None = None
    applicability: dict[str, Any] = Field(default_factory=dict)
    source_key: str
    snapshot_digest: str | None = None
    locator: str | None = None
    quote: str | None = None
    adapter: str | None = None
    source_effective_from: str | None = None
    source_effective_to: str | None = None
    observed_at: str
    accepted_at: str | None = None
    accepted_by_ref: str | None = None
    last_revalidated_at: str | None = None
    status: ObservationStatus = "proposed"
    supersedes: str | None = None
    hold: str | None = None
    notes: tuple[str, ...] = Field(default_factory=tuple)

    @field_validator("notes", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self) -> Observation:
        if self.status == "accepted" and (self.accepted_at is None or self.accepted_by_ref is None):
            raise ValueError("an accepted observation names who accepted it and when")
        if self.source_effective_from and self.source_effective_to and parsed(_stamp(self.source_effective_from) or "") > parsed(_stamp(self.source_effective_to) or ""):
            raise ValueError("source_effective_from is not after source_effective_to")
        return self

    @property
    def key(self) -> tuple[str, str]:
        return (self.product_ref, self.field)


def observation_ref(product_ref: str, field: str, source_key: str, observed_at: str, value: Any) -> str:
    return "observation:" + _digest(product_ref, field, source_key, observed_at, value)[:24]


def observe(*, product_ref: str, field: str, value: Any, source_key: str, observed_at: str, unit: str | None = None, applicability: Mapping[str, Any] | None = None, snapshot_digest: str | None = None, locator: str | None = None, quote: str | None = None, adapter: str | None = None, source_effective_from: str | None = None, source_effective_to: str | None = None) -> Observation:
    """A proposed observation: what an extractor read, before anyone accepted it."""

    stamp = timestamp(observed_at, field_name="observed_at")
    return Observation(observation_ref=observation_ref(product_ref, field, source_key, stamp, value), product_ref=product_ref, field=field, value=_jsonable(value), unit=unit, applicability=dict(applicability or {}), source_key=source_key, snapshot_digest=snapshot_digest, locator=locator, quote=quote, adapter=adapter, source_effective_from=source_effective_from, source_effective_to=source_effective_to, observed_at=stamp, last_revalidated_at=stamp, status="proposed")


class ProposedChange(ResearchModel):
    schema_id: str = Field(default=PROPOSED_CHANGE_SCHEMA, alias="schema")
    change_ref: str
    kind: ChangeKind
    handling: Handling
    policy_reason: str
    product_ref: str
    field: str
    previous_observation_ref: str | None = None
    previous_value: Any = None
    proposed: Observation | None = None
    source_key: str
    snapshot_digest: str | None = None
    adapter: str | None = None
    unresolved_questions: tuple[str, ...] = Field(default_factory=tuple)
    proposed_at: str

    @field_validator("unresolved_questions", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @property
    def requires_review(self) -> bool:
        return self.handling in ("review", "candidate")


def propose_changes(report: ChangeReport | Mapping[str, Any], accepted: Sequence[Observation | Mapping[str, Any]], *, adapter: str, proposed_at: str, auto_publish_adapters: Sequence[str] = (), unit_by_field: Mapping[str, str] | None = None) -> tuple[ProposedChange, ...]:
    """Turn a change report into proposed changes under the publication policy; the model never publishes.

    Automatic publication needs all of: a kind that may be automated, an adapter that has earned
    it (``auto_publish_adapters``), field-level evidence (a quote), and complete applicability
    (a rate without its term, tier or purpose is not a fact yet).
    """

    rep = report if isinstance(report, ChangeReport) else ChangeReport.model_validate(dict(detached(report)))
    stamp = timestamp(proposed_at, field_name="proposed_at")
    current = {item.key: item for item in (obs if isinstance(obs, Observation) else Observation.model_validate(dict(detached(obs))) for obs in accepted) if item.status == "accepted"}
    out: list[ProposedChange] = []
    if rep.tier == "operational_problem":
        for label in rep.sections_missing:
            out.append(ProposedChange(change_ref="change:" + _digest(rep.snapshot_digest, "operational", label)[:24], kind="operational_problem", handling="operational", policy_reason=f"expected section {label!r} missing: an extraction failure, never a withdrawal; dependents are held for revalidation", product_ref="*", field="*", source_key=rep.source_key, snapshot_digest=rep.snapshot_digest, adapter=adapter, unresolved_questions=(f"is the section {label!r} gone from the page, renamed, or did retrieval fail?",), proposed_at=stamp))
    if rep.tier == "cosmetic":
        out.append(ProposedChange(change_ref="change:" + _digest(rep.snapshot_digest, "cosmetic")[:24], kind="cosmetic", handling="no_fact_change", policy_reason="the response changed but no monitored section or decision input did; the snapshot is kept, no fact moves", product_ref="*", field="*", source_key=rep.source_key, snapshot_digest=rep.snapshot_digest, adapter=adapter, proposed_at=stamp))
    if rep.tier == "relevant" and not rep.meaning_changed:
        for label in rep.relevant_changed:
            out.append(ProposedChange(change_ref="change:" + _digest(rep.snapshot_digest, "section", label)[:24], kind="terms_change", handling="review", policy_reason=f"monitored section {label!r} changed and no extractor read the facts on it; a person re-extracts, and every fact resting on this source is held meanwhile", product_ref="*", field=f"section:{label}", source_key=rep.source_key, snapshot_digest=rep.snapshot_digest, adapter=adapter, unresolved_questions=(f"what changed in {label!r}: a price, a condition, a footnote, or only its presentation?",), proposed_at=stamp))
    for change in rep.meaning_changed:
        kind = change_kind(change)
        previous = current.get((change.product_ref, change.field))
        proposed = None
        if change.disposition != "disappeared":
            proposed = observe(product_ref=change.product_ref, field=change.field, value=change.current, unit=(unit_by_field or {}).get(change.field, previous.unit if previous else None), applicability=change.applicability, source_key=rep.source_key, observed_at=stamp, snapshot_digest=rep.snapshot_digest, locator=change.locator, quote=change.quote, adapter=adapter)
        handling: Handling = PUBLICATION_POLICY[kind]
        reason = f"policy for {kind}: {handling}"
        questions: list[str] = []
        if change.disposition == "disappeared":
            kind, handling = "availability_change", "review"
            reason = "a decision input disappeared while its section was read; a person confirms withdrawal before the old value stops being shown"
            questions.append(f"is {change.field} of {change.product_ref} withdrawn, moved, or renamed?")
        elif kind in AUTO_PUBLISHABLE_KINDS and adapter in auto_publish_adapters:
            missing = [key for key in _APPLICABILITY_REQUIRED.get(field_role(change.field), ()) if key not in change.applicability]
            if not change.quote:
                reason = f"{adapter} may publish {kind} automatically but this change carries no field-level quote; review"
            elif missing:
                reason = f"{adapter} may publish {kind} automatically but applicability lacks {', '.join(missing)}; review"
            else:
                handling, reason = "auto_publish", f"{adapter} has earned automatic publication for {kind}; evidence and applicability are complete"
        if change.disposition == "appeared" and kind != "new_product_candidate":
            questions.append(f"{change.field} appeared on a source that did not carry it before; is it new to market or newly captured?")
        out.append(ProposedChange(change_ref="change:" + _digest(rep.snapshot_digest, change.product_ref, change.field, change.current)[:24], kind=kind, handling=handling, policy_reason=reason, product_ref=change.product_ref, field=change.field, previous_observation_ref=previous.observation_ref if previous else None, previous_value=change.previous, proposed=proposed, source_key=rep.source_key, snapshot_digest=rep.snapshot_digest, adapter=adapter, unresolved_questions=tuple(questions), proposed_at=stamp))
    return tuple(out)


_APPLICABILITY_REQUIRED: dict[str, tuple[str, ...]] = {"rates": ("term_months",), "fees": ()}


def accept_change(change: ProposedChange | Mapping[str, Any], *, accepted_by_ref: str, accepted_at: str, previous: Observation | Mapping[str, Any] | None = None) -> tuple[Observation, Observation | None]:
    """A person (or an adapter that has earned it) accepts a change: the new observation, and the superseded one kept in history."""

    ch = change if isinstance(change, ProposedChange) else ProposedChange.model_validate(dict(detached(change)))
    _require(ch.proposed is not None, "CHANGE_HAS_NO_FACT", f"{ch.kind} carries no observation to accept")
    _require(ch.handling in ("review", "candidate", "auto_publish"), "CHANGE_NOT_ACCEPTABLE", f"{ch.handling} changes are not accepted; they are noted or resolved")
    stamp = timestamp(accepted_at, field_name="accepted_at")
    assert ch.proposed is not None
    prev = None if previous is None else (previous if isinstance(previous, Observation) else Observation.model_validate(dict(detached(previous))))
    if prev is not None:
        _require(prev.key == ch.proposed.key, "PREVIOUS_MISMATCH", "the superseded observation is the same field of the same product")
        _require(prev.observation_ref == ch.previous_observation_ref or ch.previous_observation_ref is None, "PREVIOUS_STALE", "the change was proposed against a different predecessor; re-propose against the current fact")
    accepted = ch.proposed.model_copy(update={"status": "accepted", "accepted_at": stamp, "accepted_by_ref": accepted_by_ref, "last_revalidated_at": stamp, "supersedes": prev.observation_ref if prev else None, "hold": None})
    superseded = prev.model_copy(update={"status": "superseded", "notes": (*prev.notes, f"superseded by {accepted.observation_ref} at {stamp}")}) if prev is not None else None
    return accepted, superseded


def reject_change(change: ProposedChange | Mapping[str, Any], *, rejected_by_ref: str, rejected_at: str, reason: str) -> Observation | None:
    ch = change if isinstance(change, ProposedChange) else ProposedChange.model_validate(dict(detached(change)))
    stamp = timestamp(rejected_at, field_name="rejected_at")
    if ch.proposed is None:
        return None
    return ch.proposed.model_copy(update={"status": "rejected", "notes": (*ch.proposed.notes, f"rejected by {rejected_by_ref} at {stamp}: {reason}")})


def hold_dependents(accepted: Sequence[Observation | Mapping[str, Any]], changes: Sequence[ProposedChange | Mapping[str, Any]], *, at: str) -> tuple[Observation, ...]:
    """While a material change or an operational problem is pending, the affected old facts are held: kept in history, not presented as current."""

    stamp = timestamp(at, field_name="at")
    items = [obs if isinstance(obs, Observation) else Observation.model_validate(dict(detached(obs))) for obs in accepted]
    pending = [ch if isinstance(ch, ProposedChange) else ProposedChange.model_validate(dict(detached(ch))) for ch in changes]
    held_keys: dict[tuple[str, str], str] = {}
    held_sources: dict[str, str] = {}
    for change in pending:
        if change.handling in ("review", "candidate") and change.product_ref == "*":
            held_sources[change.source_key] = f"held at {stamp}: {change.kind} pending review ({change.change_ref}); the source changed and its facts were not re-read"
        elif change.handling in ("review", "candidate"):
            held_keys[(change.product_ref, change.field)] = f"held at {stamp}: {change.kind} pending review ({change.change_ref})"
        elif change.handling == "operational":
            held_sources[change.source_key] = f"held at {stamp}: {change.policy_reason}"
    out: list[Observation] = []
    for item in items:
        reason = held_keys.get(item.key) or held_sources.get(item.source_key)
        out.append(item.model_copy(update={"hold": reason}) if reason and item.status == "accepted" else item)
    return tuple(out)


def revalidate(observations: Sequence[Observation | Mapping[str, Any]], *, source_key: str, at: str) -> tuple[Observation, ...]:
    """A successful re-read of a source with no meaning change revalidates every accepted fact it carries and lifts operational holds."""

    stamp = timestamp(at, field_name="at")
    out: list[Observation] = []
    for raw in observations:
        item = raw if isinstance(raw, Observation) else Observation.model_validate(dict(detached(raw)))
        if item.source_key == source_key and item.status == "accepted":
            lift = item.hold is not None and "pending review" not in item.hold
            out.append(item.model_copy(update={"last_revalidated_at": stamp, "hold": None if lift else item.hold}))
        else:
            out.append(item)
    return tuple(out)


# --------------------------------------------------------------------------- #
# Freshness and the published view
# --------------------------------------------------------------------------- #


def freshness_of(*, as_of: str, last_revalidated_at: str | None, effective_from: str | None = None, effective_to: str | None = None, hold: str | None = None, role: str = "rates", freshness_hours: Mapping[str, int] | None = None) -> Freshness:
    """One fact's state at the point of use: held, scheduled, expired, stale, fresh, or unstated when nothing dates it."""

    now = parsed(timestamp(as_of, field_name="as_of"))
    if hold:
        return "held"
    if effective_from and parsed(_stamp(effective_from) or "") > now:
        return "scheduled"
    if effective_to and parsed(_stamp(effective_to) or "") < now:
        return "expired"
    if last_revalidated_at is None:
        return "unstated"
    limit = (freshness_hours or DEFAULT_FRESHNESS_HOURS).get(role, DEFAULT_FRESHNESS_HOURS["other"])
    return "stale" if now - parsed(_stamp(last_revalidated_at) or "") > timedelta(hours=limit) else "fresh"


def _decimal(value: Any) -> Decimal | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return Decimal(str(value).replace(",", "").replace("%", "").strip())
    except (InvalidOperation, ValueError):
        return None


def _fact_from_observation(fact: PricingFact | None, item: str, observation: Observation, *, as_of: str, freshness_hours: Mapping[str, int] | None) -> PricingFact:
    value = _decimal(observation.value)
    unit = observation.unit or (fact.unit if fact else None)
    conditions = dict(fact.conditions) if fact else {}
    conditions.update(observation.applicability)
    return PricingFact(item=item, value=value, value_as_stated=None if value is not None else (str(observation.value) if observation.value is not None else None), unit=unit, unit_kind=unit_kind(unit), currency=fact.currency if fact else None, conditions=conditions, source_ids=(observation.source_key,), quote=observation.quote, support="fact_cited" if observation.quote else "product_cited", observed_at=observation.observed_at, effective_from=observation.source_effective_from, effective_to=observation.source_effective_to, revalidated_at=observation.last_revalidated_at, freshness=freshness_of(as_of=as_of, last_revalidated_at=observation.last_revalidated_at, effective_from=observation.source_effective_from, effective_to=observation.source_effective_to, hold=observation.hold, role=field_role(observation.field), freshness_hours=freshness_hours), hold=observation.hold)


def published_catalog(catalog: ProductCatalog | Mapping[str, Any], observations: Sequence[Observation | Mapping[str, Any]] = (), *, as_of: str, knowledge_at: str | None = None, freshness_hours: Mapping[str, int] | None = None) -> ProductCatalog:
    """The catalog as the engine may read it at ``as_of``, knowing only what was accepted by ``knowledge_at``.

    Accepted, effective observations replace the pack's facts field by field; every other fact is
    dated by the newest citation that supports it. Each fact carries its freshness; a stale,
    held, scheduled or expired fact stays visible and never ranks.
    """

    c = catalog if isinstance(catalog, ProductCatalog) else ProductCatalog.model_validate(dict(detached(catalog)))
    stamp = timestamp(as_of, field_name="as_of")
    known = parsed(timestamp(knowledge_at, field_name="knowledge_at")) if knowledge_at else parsed(stamp)
    latest: dict[tuple[str, str], Observation] = {}
    for raw in observations:
        item = raw if isinstance(raw, Observation) else Observation.model_validate(dict(detached(raw)))
        if item.status != "accepted" or item.accepted_at is None or parsed(item.accepted_at) > known:
            continue
        if item.source_effective_from and parsed(_stamp(item.source_effective_from) or "") > parsed(stamp):
            continue  # scheduled: not yet the fact
        current = latest.get(item.key)
        if current is None or parsed(item.accepted_at) > parsed(current.accepted_at or ""):
            latest[item.key] = item
    from lightbulb.finance_advice_sources import fact_field

    products: list[dict[str, Any]] = []
    for product in c.products:
        by_id = {citation.source_id: citation for citation in product.sources if citation.source_id}
        newest_any = max((_stamp(citation.retrieved_at) or "" for citation in product.sources), default=None)
        facts: list[PricingFact] = []
        seen_fields: set[str] = set()
        for fact in product.pricing:
            field = fact_field(fact.item, fact.conditions)
            seen_fields.add(field)
            observation = latest.get((product.product_ref, field))
            if observation is not None:
                facts.append(_fact_from_observation(fact, fact.item, observation, as_of=stamp, freshness_hours=freshness_hours))
                continue
            cited = [_stamp(by_id[source_id].retrieved_at) for source_id in fact.source_ids if source_id in by_id]
            revalidated = fact.revalidated_at or max((item for item in cited if item), default=newest_any)
            facts.append(fact.model_copy(update={"revalidated_at": revalidated, "effective_from": fact.effective_from or (str(fact.conditions.get("effective_date")) if fact.conditions.get("effective_date") else None), "effective_to": fact.effective_to or (str(fact.conditions.get("expiry_date")) if fact.conditions.get("expiry_date") else None), "freshness": freshness_of(as_of=stamp, last_revalidated_at=revalidated, effective_from=fact.effective_from or (str(fact.conditions.get("effective_date")) if fact.conditions.get("effective_date") else None), effective_to=fact.effective_to or (str(fact.conditions.get("expiry_date")) if fact.conditions.get("expiry_date") else None), hold=fact.hold, role=field_role(field), freshness_hours=freshness_hours)}))
        for (ref, field), observation in sorted(latest.items()):
            if ref == product.product_ref and field.startswith("pricing:") and field not in seen_fields:
                item = field[len("pricing:"):].split("[", 1)[0]
                facts.append(_fact_from_observation(None, item, observation, as_of=stamp, freshness_hours=freshness_hours))
        terms = []
        for term in product.key_terms:
            observation = latest.get((product.product_ref, f"key_term:{term.term}"))
            terms.append(KeyTerm(term=term.term, value=observation.value if observation else term.value, source_ids=(observation.source_key,) if observation else term.source_ids))
        eligibility = product.eligibility
        observation = latest.get((product.product_ref, "eligibility"))
        if observation is not None and isinstance(observation.value, (list, tuple)):
            eligibility = tuple(str(item) for item in observation.value)
        availability = product.availability_status
        observation = latest.get((product.product_ref, "availability"))
        if observation is not None and observation.value is not None:
            availability = str(observation.value)
        products.append({**product.to_dict(), "pricing": [fact.to_dict() for fact in facts], "key_terms": [term.to_dict() for term in terms], "eligibility": list(eligibility), "availability_status": availability})
    coverage = c.coverage.model_copy(update={"published_as_of": stamp, "knowledge_at": timestamp(knowledge_at, field_name="knowledge_at") if knowledge_at else stamp, "notes": (*c.coverage.notes, f"{PUBLISHED_VIEW_NOTE} as of {stamp}; {len(latest)} accepted observation(s) applied")})
    body = {**c.to_dict(), "products": products, "coverage": coverage.to_dict()}
    body.pop("catalog_digest", None)
    return seal(ProductCatalog, body, "catalog_digest")


def freshness_summary(catalog: ProductCatalog | Mapping[str, Any]) -> dict[str, int]:
    c = catalog if isinstance(catalog, ProductCatalog) else ProductCatalog.model_validate(dict(detached(catalog)))
    out: dict[str, int] = {}
    for product in c.products:
        for fact in product.pricing:
            out[fact.freshness] = out.get(fact.freshness, 0) + 1
    return dict(sorted(out.items()))


def observations_from_catalog(catalog: ProductCatalog | Mapping[str, Any], *, source_keys: Mapping[str, str], accepted_by_ref: str, accepted_at: str) -> tuple[Observation, ...]:
    """Seed the observation layer from a promoted catalog: every cited fact becomes an accepted observation dated by its citation.

    ``source_keys`` maps citation URLs to registry source keys. Facts whose citations are not in
    the registry are skipped; they stay pack facts and are dated by their citations in the view.
    """

    c = catalog if isinstance(catalog, ProductCatalog) else ProductCatalog.model_validate(dict(detached(catalog)))
    stamp = timestamp(accepted_at, field_name="accepted_at")
    from lightbulb.finance_advice_sources import fact_field

    out: list[Observation] = []
    for product in c.products:
        by_id = {citation.source_id: citation for citation in product.sources if citation.source_id}
        for fact in product.pricing:
            if fact.value is None and fact.value_as_stated is None:
                continue
            cited = [by_id[source_id] for source_id in fact.source_ids if source_id in by_id] or list(product.sources[:1])
            if not cited or cited[0].url not in source_keys:
                continue
            citation = cited[0]
            observed = _stamp(citation.retrieved_at) or stamp
            proposed = observe(product_ref=product.product_ref, field=fact_field(fact.item, fact.conditions), value=str(fact.value) if fact.value is not None else fact.value_as_stated, unit=fact.unit, applicability={k: v for k, v in fact.conditions.items()}, source_key=source_keys[citation.url], observed_at=observed, locator=citation.locator, quote=fact.quote, adapter="pack_promotion", source_effective_from=str(fact.conditions.get("effective_date")) if fact.conditions.get("effective_date") else product.effective_date)
            out.append(proposed.model_copy(update={"status": "accepted", "accepted_at": stamp, "accepted_by_ref": accepted_by_ref, "last_revalidated_at": observed}))
    return tuple(out)


__all__ = [
    "AUTO_PUBLISHABLE_KINDS",
    "OBSERVATION_SCHEMA",
    "PROPOSED_CHANGE_SCHEMA",
    "PUBLICATION_POLICY",
    "AdviceObservationError",
    "ChangeKind",
    "Freshness",
    "Handling",
    "Observation",
    "ProposedChange",
    "accept_change",
    "change_kind",
    "field_role",
    "freshness_of",
    "freshness_summary",
    "hold_dependents",
    "observations_from_catalog",
    "observe",
    "propose_changes",
    "published_catalog",
    "reject_change",
    "revalidate",
]
