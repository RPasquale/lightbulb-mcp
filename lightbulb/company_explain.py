"""Explain a number: walk any engine state's history back to the transitions, receipts, and sources behind a ledger field.

Every engine state is self-proving, but until now nothing answered "why is
total_revenue 14,550?".  ``explain_field`` replays the state's history through
the engine's own ``step`` function and records, for every transition that
changed the field, the event, the receipt fields that carried the change, the
evidence and provenance references on the receipt, and the source tools those
references name.  The result is a sealed ``Explanation``: the final value,
the ordered contributions, the distinct sources, and the digests that tie it
to the exact state.  ``explain_assessment`` does the same for a company health
figure by explaining the underlying period fields, and ``explain_reason``
turns a portfolio attention reason into the states and figures it cites.

Nothing here reads the platform; it reads the digests the SDK already carries.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import Decimal
from typing import Any

from pydantic import Field, ValidationInfo, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, BoundedText, LifecycleSpec, OpaqueRef, Rejected, Sha256Digest, ShortText, StrictModel, detached, seal, sealed_digest, skip_digests
from lightbulb.company_plan_migration import ENGINE_LIFECYCLES, lifecycle_for

EXPLANATION_SCHEMA = "lightbulb.company_explanation.v1"
_SOURCE_PREFIXES: Mapping[str, str] = {"observation": "observation_read", "provenance": "sealed_provenance", "execution": "governed_execution", "receipt": "execution_receipt", "trial_balance": "ledger_report", "source": "independent_source", "account_map": "operator_account_map", "period_status": "provider_period_status", "classification": "reply_classifier", "enrichment": "enrichment_result", "calendar": "calendar_booking", "thread": "mail_thread", "confirmation": "customer_confirmation", "ticket_status": "ticket_status", "content_variant": "content_agent", "trace": "agent_dispatch", "dispatch": "agent_dispatch", "books": "books_verification", "stripe-balance": "stripe_settlements", "stripe-settled": "stripe_settlements", "open-invoices": "provider_invoices", "sim": "synthetic_simulation"}


class Contribution(StrictModel):
    version: int = Field(ge=1)
    event: ShortText
    occurred_at: str
    actor_ref: OpaqueRef
    before: str | None = None
    after: str | None = None
    delta: str | None = None
    receipt_fields: dict[str, Any] = Field(default_factory=dict)
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=60)
    sources: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=20)
    transition_digest: Sha256Digest
    request_digest: Sha256Digest


class Explanation(StrictModel):
    schema_id: str = Field(default=EXPLANATION_SCHEMA, alias="schema")
    engine: ShortText
    entity_ref: OpaqueRef
    field: ShortText
    value: str | None = None
    state_digest: Sha256Digest
    plan_digest: Sha256Digest
    contributions: tuple[Contribution, ...] = Field(default_factory=tuple, max_length=4096)
    sources: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=40)
    synthetic: bool = False
    unexplained: BoundedText | None = None
    explanation_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> Explanation:
        if not skip_digests(info) and self.explanation_digest != sealed_digest(Explanation, self, "explanation_digest"):
            raise ValueError("explanation_digest must commit the exact explanation")
        return self

    def narrative(self) -> str:
        """One paragraph a person can read: the value, how many transitions moved it, and where the evidence came from."""

        if not self.contributions:
            return f"{self.field} on {self.entity_ref} is {self.value!r}; no transition changed it ({self.unexplained or 'default value'})."
        steps = "; ".join(f"v{item.version} {item.event}" + (f" ({item.delta})" if item.delta else "") for item in self.contributions)
        sources = ", ".join(self.sources) if self.sources else "no external sources"
        flag = " Synthetic (simulation) evidence." if self.synthetic else ""
        return f"{self.field} on {self.entity_ref} is {self.value} after {len(self.contributions)} transition(s): {steps}. Evidence from {sources}.{flag}"


def _render(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, (list, tuple, set, frozenset)):
        return str(sorted(str(item) for item in value)) if not isinstance(value, (list, tuple)) else str([_render(item) for item in value])
    if isinstance(value, Mapping):
        return str({str(key): _render(item) for key, item in sorted(value.items())})
    return str(value)


def _delta(before: Any, after: Any) -> str | None:
    try:
        if isinstance(before, Decimal) or isinstance(after, Decimal):
            return str(Decimal(str(after if after is not None else 0)) - Decimal(str(before if before is not None else 0)))
        if isinstance(before, str) and isinstance(after, str) and before.replace(".", "", 1).lstrip("-").isdigit() and after.replace(".", "", 1).lstrip("-").isdigit():
            return str(Decimal(after) - Decimal(before))
        if isinstance(before, int) and isinstance(after, int) and not isinstance(before, bool):
            return str(after - before)
    except (ArithmeticError, ValueError):
        return None
    return None


def _sources_from(refs: Sequence[str]) -> list[str]:
    out: list[str] = []
    for ref in refs:
        head = str(ref).split(":", 1)[0]
        kind = _SOURCE_PREFIXES.get(head)
        if kind is None:
            kind = "reference"
        if kind not in out:
            out.append(kind)
    return out


def _field_value(ledger: Any, field: str) -> Any:
    fields = type(ledger).model_fields if hasattr(type(ledger), "model_fields") else {}
    if field in fields:
        return getattr(ledger, field)
    head, _, key = field.partition(".")
    if head in fields and isinstance(getattr(ledger, head), Mapping):
        return getattr(ledger, head).get(key)
    raise KeyError(field)


def _relevant_receipt(receipt: Any, field: str) -> dict[str, Any]:
    raw = receipt.to_dict() if hasattr(receipt, "to_dict") else dict(receipt or {})
    keep = {key: value for key, value in raw.items() if value not in (None, (), [], {}, "") and key != "evidence_refs"}
    return keep


def explain_field(spec: LifecycleSpec, plan: Mapping[str, Any] | Any, state: Mapping[str, Any] | Any, field: str, *, engine: str | None = None) -> Explanation:
    """Replay the state and record every transition that changed ``field`` (a ledger field, or ``map.key`` inside a mapping field)."""

    parsed_plan, bound = spec.bind(plan, state)
    status, ledger = "new", spec.ledger_model()
    try:
        previous = _field_value(ledger, field)
    except KeyError as exc:
        raise ValueError(f"{field!r} is not a {spec.entity} ledger field") from exc
    contributions: list[dict[str, Any]] = []
    all_sources: list[str] = []
    synthetic = False
    for transition in bound.transition_history:
        try:
            status, ledger = spec.step(parsed_plan, status, ledger, transition.command)
        except Rejected as exc:  # pragma: no cover - a persisted state never replays into a rejection
            raise ValueError(f"historical transition {transition.to_version} does not replay: {exc.code}") from exc
        current = _field_value(ledger, field)
        if current == previous:
            continue
        refs = [str(item) for item in (getattr(transition.command.receipt, "evidence_refs", ()) or ())]
        sources = _sources_from(refs)
        if "synthetic_simulation" in sources or str(bound.scope.entity_ref).startswith("sim-"):
            synthetic = True
        for source in sources:
            if source not in all_sources:
                all_sources.append(source)
        contributions.append({"version": transition.to_version, "event": transition.command.event, "occurred_at": transition.command.occurred_at, "actor_ref": transition.command.actor_ref, "before": _render(previous), "after": _render(current), "delta": _delta(previous, current), "receipt_fields": _relevant_receipt(transition.command.receipt, field), "evidence_refs": refs[:60], "sources": sources, "transition_digest": transition.transition_digest, "request_digest": transition.command.request_digest})
        previous = current
    final = _field_value(bound.ledger, field)
    return seal(Explanation, {"engine": engine or spec.entity, "entity_ref": bound.scope.entity_ref, "field": field, "value": _render(final), "state_digest": bound.state_digest, "plan_digest": bound.plan_digest, "contributions": contributions, "sources": all_sources, "synthetic": synthetic, "unexplained": None if contributions else "the field never changed from its opening value"}, "explanation_digest")


def explain_engine_field(engine: str, plan: Mapping[str, Any] | Any, state: Mapping[str, Any] | Any, field: str) -> Explanation:
    lifecycle = lifecycle_for(engine)
    return explain_field(lifecycle.spec, plan, state, field, engine=engine)


ASSESSMENT_FIELDS: Mapping[str, str] = {"total_revenue": "total_revenue", "total_spend": "total_spend", "revenue_attainment_percent": "total_revenue", "spend_utilisation_percent": "total_spend", "halted": "halt_reason", "closed": "outcome"}


def explain_assessment(plan: Mapping[str, Any] | Any, periods: Sequence[Mapping[str, Any] | Any], metric: str, *, prior_plans: Sequence[Mapping[str, Any] | Any] = ()) -> list[Explanation]:
    """Explain a company health metric by explaining the period ledger field it aggregates, one explanation per period."""

    field = ASSESSMENT_FIELDS.get(metric)
    if field is None and metric.startswith("engines."):
        _, engine, measure = metric.split(".", 2)
        field = f"{'revenue' if measure == 'revenue' else 'spend'}_by_engine.{engine}"
    if field is None:
        raise ValueError(f"{metric!r} is not an explainable assessment metric; known: {sorted(ASSESSMENT_FIELDS)} or engines.<engine>.revenue|spend")
    lifecycle = ENGINE_LIFECYCLES["company_operating_system"]
    lineage = [plan, *prior_plans]
    out: list[Explanation] = []
    for period in periods:
        document = dict(period["state"]) if isinstance(period, Mapping) and "state" in period else (period.to_dict() if hasattr(period, "to_dict") else dict(period))
        owner = next((candidate for candidate in lineage if (candidate.plan_digest if hasattr(candidate, "plan_digest") else dict(detached(candidate)).get("plan_digest")) == document.get("plan_digest")), None)
        if owner is None:
            raise ValueError("a period belongs to a plan outside the supplied lineage")
        out.append(explain_field(lifecycle.spec, owner, document, field, engine="company_operating_system"))
    return out


def explain_reason(reason: Mapping[str, Any] | Any, *, plan: Mapping[str, Any] | Any, periods: Sequence[Mapping[str, Any] | Any] = (), prior_plans: Sequence[Mapping[str, Any] | Any] = ()) -> list[Explanation]:
    """Explain a portfolio attention reason from the period states it cites; reasons from other sources return an empty list."""

    raw = reason.to_dict() if hasattr(reason, "to_dict") else dict(reason)
    code = str(raw.get("code", ""))
    if code == "PERIOD_HALTED":
        return [item for item in explain_assessment(plan, periods, "halted", prior_plans=prior_plans) if item.contributions]
    if code in ("REVENUE_BEHIND",):
        return explain_assessment(plan, periods, "total_revenue", prior_plans=prior_plans)
    if code in ("RUNWAY_SHORT", "RUNWAY_TIGHT"):
        return explain_assessment(plan, periods, "total_spend", prior_plans=prior_plans)
    return []


EXPLAIN_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "company_explain",
    "golden_loop": "company.blueprint_to_governed_operating_cadence@0.1.0",
    "stages": ["bind", "replay", "attribute", "seal"],
    "explainable_engines": sorted(ENGINE_LIFECYCLES),
    "source_kinds": sorted(set(_SOURCE_PREFIXES.values())),
    "required_connectors": [],
    "hard_rules": [
        "an explanation replays the state through the engine's own step function; it never reads the platform",
        "every contribution names the transition digest and request digest it came from",
        "synthetic (simulation) evidence is flagged, never presented as observed",
    ],
}

__all__ = ["ASSESSMENT_FIELDS", "EXPLAIN_MANIFEST", "EXPLANATION_SCHEMA", "Contribution", "Explanation", "explain_assessment", "explain_engine_field", "explain_field", "explain_reason"]
