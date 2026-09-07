"""The front door's first seam: platform planning runs sealed into receipts a blueprint can compile from.

Before a company exists there is nothing to observe, so the only evidence the
SDK can stand on is what the platform's planning agents already produced: a
go-to-market plan, a market-entry analysis, an ICP definition, a pricing
landscape, a prioritised roadmap, the incorporation document package and the
service / employment paper, a revenue forecast, a content plan.  Each of those
is a dispatched domain-agent run with a trace, and each trace has a workflow
instance the platform persisted.

``planning_run_receipt`` takes exactly two mappings that a wrapper fetched from
the platform - ``DispatchResult.raw`` and the JSON of
``GET /api/workflows/instances/{traceId}`` - and either refuses the run or
seals a ``PlanningRunReceipt``:

* refused when the source is unknown, when the dispatch's domain+action is not
  the source, when there is no trace, when the instance was not fetched (so the
  inputs digest would commit nothing), when the instance carries a different
  trace, when the run did not complete, when the outputs say they need input or
  have no data, when the run was synthetic, when a different agent answered,
  when nothing timestamps it, and when it is older than ``MAX_RUN_AGE_DAYS``;
* sealed with the run's provenance (trace ref, agent, both digests, COMPLETED
  state) and only the typed facts a blueprint can compile from.

What it proves is narrow on purpose.  Extraction reads a per-source whitelist of
JSON paths and copies nothing else: no identifiers, no ``domain_payload``, no
``specialist_inputs``, no ``inputs_summary``, no document or content bodies.
Legal paper is retained as a content digest with ``requires_review`` true, never
as text.  Pricing intelligence yields observed prices as evidence and
``price_recommended`` is the constant ``False`` - the SDK never mints a price.
Identifier-bearing inputs are hashed into ``inputs_digest`` and never copied.

Every fact carries a ``Provenance`` row naming the run it came from and the
dotted path it was read at, so a downstream ``LaunchBlueprint`` field can always
name its run.  ``build_intake`` collects one receipt per source into a sealed
``PlanningIntake``, which is what the blueprint compiler consumes.  Nothing here
dispatches, reads a provider, or writes anything.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from decimal import Decimal
from importlib import resources
from typing import Annotated, Any, Literal

from pydantic import Field, StringConstraints, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    OpaqueRef,
    Sha256Digest,
    ShortText,
    StrictModel,
    add_days,
    decimal_value,
    parsed,
    seal,
    sealed_digest,
    skip_digests,
    stable_digest,
    timestamp,
    unique,
)

RECEIPT_SCHEMA = "lightbulb.planning_run_receipt.v1"
INTAKE_SCHEMA = "lightbulb.planning_intake.v1"
PLANNING_GOLDEN_LOOP = "company.idea_to_first_dollar@0.1.0"
MAX_RUN_AGE_DAYS = 30
FIXTURE_PACKAGE = "lightbulb.data.planning_fixtures"
FIXTURE_CORPUS_SCHEMA = "lightbulb.planning_fixture_corpus.v1"

PlanningSource = Literal[
    "gtm.go_to_market_plan",
    "gtm.market_entry_analysis",
    "gtm.launch_readiness",
    "crm.icp_intelligence",
    "product.pricing_intelligence",
    "product.roadmap_plan",
    "legal.incorporation_readiness",
    "legal.incorporation_document_package",
    "legal.service_agreement_packet",
    "legal.employment_agreement_packet",
    "finance.finance_forecasting",
    "content.generate_plan",
]

# The registry agents that may answer for a source; any other named agent is refused.
SOURCE_AGENTS: dict[str, tuple[str, ...]] = {
    "gtm.go_to_market_plan": ("gtm_campaign_orchestrator",),
    "gtm.market_entry_analysis": ("gtm_campaign_orchestrator",),
    "gtm.launch_readiness": ("gtm_campaign_orchestrator",),
    "crm.icp_intelligence": ("crm_domain_agent", "icp_intelligence_agent"),
    "product.pricing_intelligence": ("product_domain_agent", "product_intelligence_agent", "product_catalog_agent"),
    "product.roadmap_plan": ("product_domain_agent", "product_roadmap_agent"),
    "legal.incorporation_readiness": ("legal_doc_generator",),
    "legal.incorporation_document_package": ("legal_doc_generator",),
    "legal.service_agreement_packet": ("legal_doc_generator",),
    "legal.employment_agreement_packet": ("legal_doc_generator",),
    "finance.finance_forecasting": ("financial_forecaster",),
    "content.generate_plan": ("content_strategy_agent",),
}

REFUSED_OUTPUT_STATUSES = frozenset({"needs_input", "pending_approval", "no_data", "failed", "error", "not_persisted"})

_LEGAL_SOURCES = frozenset({
    "legal.incorporation_readiness",
    "legal.incorporation_document_package",
    "legal.service_agreement_packet",
    "legal.employment_agreement_packet",
})
_GTM_PLAN_SOURCES = frozenset({"gtm.go_to_market_plan", "gtm.market_entry_analysis"})

FACTS_REQUIRED_BY_SOURCE: dict[str, tuple[str, ...]] = {
    "gtm.go_to_market_plan": ("campaign_name", "plan_source", "track_domains"),
    "gtm.market_entry_analysis": ("campaign_name", "plan_source"),
    "gtm.launch_readiness": ("launch_ready",),
    "crm.icp_intelligence": ("icp_complete",),
    "product.pricing_intelligence": ("observed_prices", "discrepancy_count", "price_recommended"),
    "product.roadmap_plan": ("framework", "prioritized_count"),
    "legal.incorporation_readiness": ("document_ref", "document_type", "requires_review", "content_origin", "content_sha256"),
    "legal.service_agreement_packet": ("document_ref", "document_type", "requires_review", "content_origin", "content_sha256"),
    "legal.employment_agreement_packet": ("document_ref", "document_type", "requires_review", "content_origin", "content_sha256"),
    "legal.incorporation_document_package": (
        "document_ref", "document_type", "requires_review", "content_origin", "content_sha256",
        "country", "registrar", "filing_steps", "guide_only",
    ),
    "finance.finance_forecasting": ("forecast_type", "periods", "forecast_points", "methodology"),
    "content.generate_plan": ("pillars", "platforms"),
}

MAX_PROVENANCE_ROWS = 60
MAX_OBSERVED_PRICES = 50
_PERIOD_PATTERN = r"^\d{4}-\d{2}$"
_PERIOD_RE = re.compile(_PERIOD_PATTERN)
# The same grammar OpaqueRef enforces, so a malformed id is refused with a code.
_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}$")
Period = Annotated[str, StringConstraints(pattern=_PERIOD_PATTERN)]


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #


class PlanningIntakeError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise PlanningIntakeError(code, message)


# --------------------------------------------------------------------------- #
# Models
# --------------------------------------------------------------------------- #


class Provenance(StrictModel):
    """Where one extracted fact came from: the run, and the dotted path inside its outputs."""

    source: PlanningSource
    trace_ref: OpaqueRef
    outputs_digest: Sha256Digest
    path: ShortText
    confidence: Literal["extracted", "fallback"] = "extracted"


class ObservedPrice(StrictModel):
    """One price spread the platform observed; evidence, never a recommendation."""

    subject: ShortText
    connector: ShortText
    min_price: Decimal
    max_price: Decimal
    currency: ShortText

    @field_validator("min_price", "max_price", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Any:
        return decimal_value(value, field_name="price")


class ForecastPoint(StrictModel):
    """One period of a forecast series, exactly as the forecaster emitted it."""

    period: Period
    predicted_value: Decimal
    lower_bound: Decimal
    upper_bound: Decimal

    @field_validator("predicted_value", "lower_bound", "upper_bound", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Any:
        return decimal_value(value, field_name="forecast_value", allow_negative=True)


class PlanningFacts(StrictModel):
    """The whitelisted facts a blueprint may compile from; everything else stays on the platform."""

    # gtm
    campaign_name: ShortText | None = None
    target_industry: ShortText | None = None
    target_segment: ShortText | None = None
    target_persona: ShortText | None = None
    target_geography: ShortText | None = None
    track_domains: tuple[Literal["crm", "content", "commerce", "finance"], ...] | None = Field(default=None, max_length=4)
    success_metrics: tuple[ShortText, ...] | None = Field(default=None, max_length=12)
    plan_source: Literal["llm", "fallback"] | None = None
    launch_ready: bool | None = None
    # crm
    icp_industries: tuple[ShortText, ...] | None = Field(default=None, max_length=40)
    icp_regions: tuple[ShortText, ...] | None = Field(default=None, max_length=40)
    icp_buyer_titles: tuple[ShortText, ...] | None = Field(default=None, max_length=40)
    icp_required_signals: tuple[ShortText, ...] | None = Field(default=None, max_length=40)
    icp_disqualifiers: tuple[ShortText, ...] | None = Field(default=None, max_length=40)
    channels_to_test: tuple[ShortText, ...] | None = Field(default=None, max_length=8)
    icp_complete: bool | None = None
    # pricing
    observed_prices: tuple[ObservedPrice, ...] | None = Field(default=None, max_length=50)
    discrepancy_count: int | None = Field(default=None, ge=0)
    price_recommended: Literal[False] = False
    # roadmap
    framework: Literal["rice", "wsjf"] | None = None
    prioritized_count: int | None = Field(default=None, ge=0)
    top_items: tuple[ShortText, ...] | None = Field(default=None, max_length=10)
    # legal paper
    document_ref: OpaqueRef | None = None
    document_type: ShortText | None = None
    template: ShortText | None = None
    requires_review: Literal[True] | None = None
    content_origin: Literal["template", "generated", "deterministic"] | None = None
    content_sha256: Sha256Digest | None = None
    provenance_manifest_digest: Sha256Digest | None = None
    # incorporation package
    country: Literal["AU", "CA"] | None = None
    registrar: ShortText | None = None
    filing_steps: tuple[ShortText, ...] | None = Field(default=None, max_length=12)
    guide_only: bool | None = None
    proposed_name: ShortText | None = None
    # finance
    forecast_type: Literal["revenue", "expense", "cash_flow", "profit", "budget"] | None = None
    periods: int | None = Field(default=None, ge=0)
    forecast_points: tuple[ForecastPoint, ...] | None = Field(default=None, max_length=60)
    methodology: ShortText | None = None
    trend_direction: Literal["up", "down", "stable"] | None = None
    # content
    pillars: tuple[ShortText, ...] | None = Field(default=None, max_length=12)
    platforms: tuple[ShortText, ...] | None = Field(default=None, max_length=8)
    campaigns_count: int | None = Field(default=None, ge=0)

    @field_validator(
        "track_domains", "success_metrics", "icp_industries", "icp_regions", "icp_buyer_titles",
        "icp_required_signals", "icp_disqualifiers", "channels_to_test", "observed_prices",
        "top_items", "filing_steps", "forecast_points", "pillars", "platforms",
        mode="before",
    )
    @classmethod
    def _sequences(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value


class PlanningRunReceipt(StrictModel):
    """One COMPLETED planning run, sealed: its provenance and the facts a blueprint may cite."""

    schema_id: Literal["lightbulb.planning_run_receipt.v1"] = Field(default=RECEIPT_SCHEMA, alias="schema")
    source: PlanningSource
    trace_ref: OpaqueRef
    agent_ref: ShortText
    workflow_type: ShortText | None = None
    generated_at: str
    state: Literal["COMPLETED"] = "COMPLETED"
    mode: Literal["completed"] = "completed"
    inputs_digest: Sha256Digest
    outputs_digest: Sha256Digest
    synthetic_only: Literal[False] = False
    evidence_refs: tuple[OpaqueRef, ...] = Field(default=(), max_length=24)
    facts: PlanningFacts
    provenance: tuple[Provenance, ...] = Field(default=(), max_length=MAX_PROVENANCE_ROWS)
    receipt_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("generated_at")
    @classmethod
    def _when(cls, value: str) -> str:
        return timestamp(value, field_name="generated_at")

    @field_validator("evidence_refs", "provenance", mode="before")
    @classmethod
    def _sequences(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> PlanningRunReceipt:
        for field in FACTS_REQUIRED_BY_SOURCE.get(self.source, ()):
            if getattr(self.facts, field, None) is None:
                raise ValueError(f"FACTS_INCOMPLETE_FOR_SOURCE: {field}")
        for row in self.provenance:
            if row.source != self.source or row.trace_ref != self.trace_ref:
                raise ValueError("every provenance row must cite this run")
            if row.outputs_digest != self.outputs_digest:
                raise ValueError("every provenance row must cite this run's outputs digest")
        if not skip_digests(info) and self.receipt_digest != sealed_digest(PlanningRunReceipt, self, "receipt_digest"):
            raise ValueError("receipt_digest must commit the exact receipt")
        return self


class PlanningIntake(StrictModel):
    """One receipt per planning source, sealed together: the compiler's only planning evidence."""

    schema_id: Literal["lightbulb.planning_intake.v1"] = Field(default=INTAKE_SCHEMA, alias="schema")
    receipts: tuple[PlanningRunReceipt, ...] = Field(min_length=1, max_length=20)
    sealed_at: str
    intake_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("sealed_at")
    @classmethod
    def _when(cls, value: str) -> str:
        return timestamp(value, field_name="sealed_at")

    @field_validator("receipts", mode="before")
    @classmethod
    def _sequences(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> PlanningIntake:
        sources = [receipt.source for receipt in self.receipts]
        if len(set(sources)) != len(sources):
            raise ValueError(f"PLANNING_SOURCE_DUPLICATE: one receipt per source; got {sorted(sources)}")
        unique([receipt.trace_ref for receipt in self.receipts], label="planning trace refs")
        if not skip_digests(info) and self.intake_digest != sealed_digest(PlanningIntake, self, "intake_digest"):
            raise ValueError("intake_digest must commit the exact intake")
        return self

    def receipt(self, source: str) -> PlanningRunReceipt | None:
        return next((item for item in self.receipts if item.source == source), None)

    @property
    def sources(self) -> tuple[str, ...]:
        return tuple(item.source for item in self.receipts)


def build_intake(receipts: Any, *, sealed_at: str) -> PlanningIntake:
    """Seal one receipt per source; refuses a source or a trace that appears twice."""

    rows = [item if isinstance(item, Mapping) else item.to_dict() for item in tuple(receipts)]
    present = len(rows) > 0
    _require(present, "PLANNING_INTAKE_EMPTY", "an intake carries at least one planning receipt")
    sources = [str(row.get("source")) for row in rows]
    one_per_source = len(set(sources)) == len(sources)
    _require(one_per_source, "PLANNING_SOURCE_DUPLICATE", f"one receipt per source; got {sorted(sources)}")
    traces = [str(row.get("trace_ref")) for row in rows]
    one_per_trace = len(set(traces)) == len(traces)
    _require(one_per_trace, "PLANNING_SOURCE_DUPLICATE", f"one receipt per trace; got {sorted(traces)}")
    return seal(PlanningIntake, {"receipts": rows, "sealed_at": sealed_at}, "intake_digest")


# --------------------------------------------------------------------------- #
# Reading the platform's JSON: whitelisted paths only
# --------------------------------------------------------------------------- #


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _rows(value: Any) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(item for item in value if isinstance(item, Mapping))


def _indexed_rows(value: Any) -> tuple[tuple[int, Mapping[str, Any]], ...]:
    """Mapping rows paired with the index they actually occupy in the platform's array.

    Skipping a non-mapping row must not renumber the rows after it: a provenance
    path that cites discrepancies[0] has to mean the platform's row 0.
    """

    if not isinstance(value, (list, tuple)):
        return ()
    return tuple((index, item) for index, item in enumerate(value) if isinstance(item, Mapping))


def _ref(prefix: str, value: Any) -> str | None:
    """prefix:value when the platform's id can form an OpaqueRef, else nothing.

    An id the ref grammar cannot carry is not a usable reference.  Dropping it here
    keeps the outcome a coded refusal (or a missing required fact) instead of a raw
    model-validation dump naming every field the bad ref happened to reach.
    """

    text = _text(value, limit=200)
    candidate = f"{prefix}:{text}" if text else None
    return candidate if candidate is not None and _REF_RE.match(candidate) else None


def _text(value: Any, *, limit: int = 300) -> str | None:
    if value is None or isinstance(value, (Mapping, list, tuple, bool)):
        return None
    text = str(value).strip()
    return text[:limit] if text else None


def _texts(value: Any, *, cap: int, limit: int = 300) -> tuple[str, ...]:
    items = [value] if isinstance(value, str) else (list(value) if isinstance(value, (list, tuple)) else [])
    out: list[str] = []
    for item in items:
        text = _text(item.get("name") if isinstance(item, Mapping) else item, limit=limit)
        if text and text not in out:
            out.append(text)
        if len(out) >= cap:
            break
    return tuple(out)


def _whole(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return None
    try:
        result = int(float(value))
    except (TypeError, ValueError):
        return None
    return result if result >= 0 else None


def _normalised_timestamp(value: Any) -> str | None:
    text = _text(value, limit=64)
    if text is None:
        return None
    if text.endswith("+00:00"):
        text = f"{text[:-6]}Z"
    elif not text.endswith("Z"):
        text = f"{text}Z"
    try:
        return timestamp(text, field_name="generated_at")
    except ValueError:
        return None


def _gtm_facts(outputs: Mapping[str, Any], note: Any) -> dict[str, Any]:
    plan = _mapping(outputs.get("plan"))
    declared = _text(plan.get("source"))
    fallback = (declared or "").strip().lower() == "fallback"
    confidence = "fallback" if fallback else "extracted"
    facts: dict[str, Any] = {"plan_source": "fallback" if fallback else "llm"}
    # Nothing declared the planner: ``llm`` is only the closed literal's other member,
    # so the row says the value was inferred rather than read off the run.
    note("outputs.plan.source", confidence=confidence if declared is not None else "fallback")
    name = _text(plan.get("campaign_name"))
    if name is not None:
        facts["campaign_name"] = name
        note("outputs.plan.campaign_name", confidence=confidence)
    market = _mapping(plan.get("target_market"))
    for field, key in (("target_industry", "industry"), ("target_segment", "segment"), ("target_persona", "persona"), ("target_geography", "geography")):
        value = _text(market.get(key))
        if value is not None:
            facts[field] = value
            note(f"outputs.plan.target_market.{key}", confidence=confidence)
    domains = tuple(dict.fromkeys(
        domain for domain in (_text(row.get("domain")) for row in _rows(plan.get("tracks")))
        if domain in ("crm", "content", "commerce", "finance")
    ))
    if domains:
        facts["track_domains"] = domains
        note("outputs.plan.tracks[].domain", confidence=confidence)
    metrics = _texts(plan.get("success_metrics"), cap=12)
    if metrics:
        facts["success_metrics"] = metrics
        note("outputs.plan.success_metrics", confidence=confidence)
    return facts


def _launch_readiness_facts(outputs: Mapping[str, Any], note: Any) -> dict[str, Any]:
    note("outputs.status")
    return {"launch_ready": str(outputs.get("status") or "").strip().lower() == "completed"}


def _icp_facts(outputs: Mapping[str, Any], note: Any) -> dict[str, Any]:
    analysis = _mapping(outputs.get("analysis"))
    icp = _mapping(analysis.get("icp_definition"))
    facts: dict[str, Any] = {}
    for field, keys in (
        ("icp_industries", ("industries", "industry")),
        ("icp_regions", ("regions", "geographies")),
        ("icp_buyer_titles", ("buyer_titles", "titles", "personas")),
        ("icp_required_signals", ("required_signals", "signals")),
        ("icp_disqualifiers", ("disqualifiers",)),
    ):
        for key in keys:
            values = _texts(icp.get(key), cap=40)
            if values:
                facts[field] = values
                note(f"outputs.analysis.icp_definition.{key}")
                break
    channels = _texts(analysis.get("channels_to_test"), cap=8)
    if channels:
        facts["channels_to_test"] = channels
        note("outputs.analysis.channels_to_test")
    facts["icp_complete"] = all(facts.get(field) for field in ("icp_industries", "icp_regions", "icp_buyer_titles"))
    return facts


def _pricing_facts(outputs: Mapping[str, Any], note: Any) -> dict[str, Any]:
    observed: list[dict[str, Any]] = []
    for key in ("discrepancies", "market_discrepancies"):
        if len(observed) >= MAX_OBSERVED_PRICES:
            break
        for index, row in _indexed_rows(outputs.get(key)):
            subject = _text(row.get("sku") or row.get("subject_key") or row.get("name"))
            low, high = row.get("min_price"), row.get("max_price")
            prices = _rows(row.get("prices"))
            connectors = tuple(dict.fromkeys(item for item in (_text(price.get("connector")) for price in prices) if item))
            # The currency is read, never defaulted: an observation that does not say
            # what it is denominated in is not evidence of a price.
            currency = next((item for item in (_text(price.get("currency")) for price in prices) if item), None)
            if subject is None or low is None or high is None or not connectors or currency is None:
                continue
            observed.append({
                "subject": subject,
                "connector": ",".join(connectors)[:300],
                "min_price": str(low),
                "max_price": str(high),
                "currency": currency,
            })
            note(f"outputs.{key}[{index}]")
            if len(observed) >= MAX_OBSERVED_PRICES:
                break
    counted, cited = 0, False
    for key in ("discrepancy_count", "market_discrepancy_count"):
        value = _whole(outputs.get(key))
        if value is not None:
            counted, cited = counted + value, True
            note(f"outputs.{key}")
    if not cited:
        # Nothing published a count; the only honest number is the rows actually read.
        counted = len(observed)
        note("outputs.discrepancies[]", confidence="fallback")
    return {"observed_prices": tuple(observed), "discrepancy_count": counted, "price_recommended": False}


def _roadmap_facts(outputs: Mapping[str, Any], note: Any) -> dict[str, Any]:
    facts: dict[str, Any] = {}
    framework = str(outputs.get("framework") or "").strip().lower()
    if framework in ("rice", "wsjf"):
        facts["framework"] = framework
        note("outputs.framework")
    total = _whole(outputs.get("total_items"))
    if total is not None:
        facts["prioritized_count"] = total
        note("outputs.total_items")
    titles = tuple(dict.fromkeys(item for item in (_text(row.get("title")) for row in _rows(outputs.get("prioritized"))[:10]) if item))
    if titles:
        facts["top_items"] = titles
        note("outputs.prioritized[].title")
    return facts


def _legal_facts(source: str, outputs: Mapping[str, Any], note: Any) -> dict[str, Any]:
    facts: dict[str, Any] = {}
    document_ref = _ref("document", outputs.get("document_id"))
    if document_ref is not None:
        facts["document_ref"] = document_ref
        note("outputs.document_id")
    document_type = _text(outputs.get("document_type"))
    if document_type is not None:
        facts["document_type"] = document_type
        note("outputs.document_type")
    template = _text(outputs.get("template"))
    if template is not None:
        facts["template"] = template
        note("outputs.template")
    reviewed = outputs.get("requires_review") is True
    _require(reviewed, "PLANNING_LEGAL_PACKET_UNREVIEWED", f"{source} must carry requires_review true; legal paper is never self-cleared")
    facts["requires_review"] = True
    note("outputs.requires_review")
    manifest = _mapping(outputs.get("legal_provenance_manifest"))
    origin = _text(manifest.get("content_origin"))
    if origin in ("template", "generated", "deterministic"):
        facts["content_origin"] = origin
        note("outputs.legal_provenance_manifest.content_origin")
    if manifest:
        facts["provenance_manifest_digest"] = stable_digest({key: value for key, value in manifest.items() if key not in ("tenant_id", "company_id", "matter_id")})
        note("outputs.legal_provenance_manifest")
    content = outputs.get("content")
    if isinstance(content, str) and content:
        facts["content_sha256"] = hashlib.sha256(content.encode("utf-8")).hexdigest()
        note("outputs.content")
    if source != "legal.incorporation_document_package":
        return facts
    country = _text(outputs.get("country"))
    if country in ("AU", "CA"):
        facts["country"] = country
        note("outputs.country")
    registrar = _text(outputs.get("registrar"))
    if registrar is not None:
        facts["registrar"] = registrar
        note("outputs.registrar")
    steps = tuple(item for item in (_text(row.get("action")) for row in _rows(outputs.get("filing_guide"))[:12]) if item)
    if steps:
        facts["filing_steps"] = steps
        note("outputs.filing_guide[].action")
    if isinstance(outputs.get("guide_only"), bool):
        facts["guide_only"] = outputs["guide_only"]
        note("outputs.guide_only")
    proposed = _text(_mapping(outputs.get("company_provisioning_hint")).get("name"))
    if proposed is not None:
        facts["proposed_name"] = proposed
        note("outputs.company_provisioning_hint.name")
    return facts


def _forecast_facts(outputs: Mapping[str, Any], note: Any) -> dict[str, Any]:
    series, path = outputs.get("forecasts"), "outputs.forecasts"
    if not _rows(series):
        series, path = _mapping(outputs.get("forecast_payload")).get("forecasts"), "outputs.forecast_payload.forecasts"
    entries = _indexed_rows(series)[:60]
    has_series = len(entries) > 0
    _require(has_series, "FORECAST_SERIES_MISSING", "neither outputs.forecasts nor outputs.forecast_payload.forecasts carries a series")
    points: list[dict[str, Any]] = []
    for index, row in entries:
        period = _text(row.get("period"))
        well_formed = _PERIOD_RE.match(period or "") is not None
        _require(well_formed, "FORECAST_PERIOD_INVALID", f"{path}[{index}].period is {period!r}; expected YYYY-MM")
        predicted = row.get("predicted_value")
        _require(predicted is not None, "FORECAST_SERIES_MISSING", f"{path}[{index}] carries no predicted_value")
        low, high = row.get("lower_bound"), row.get("upper_bound")
        points.append({
            "period": period,
            "predicted_value": str(predicted),
            "lower_bound": str(low if low is not None else predicted),
            "upper_bound": str(high if high is not None else predicted),
        })
    note(f"{path}[].period")
    note(f"{path}[].predicted_value")
    if any(row.get("lower_bound") is None or row.get("upper_bound") is None for _, row in entries):
        note(f"{path}[].lower_bound", confidence="fallback")
    facts: dict[str, Any] = {"forecast_points": tuple(points)}
    forecast_type = str(outputs.get("forecast_type") or "").strip().lower()
    if forecast_type in ("revenue", "expense", "cash_flow", "profit", "budget"):
        facts["forecast_type"] = forecast_type
        note("outputs.forecast_type")
    periods = _whole(outputs.get("periods"))
    if periods is not None:
        facts["periods"] = periods
        note("outputs.periods")
    methodology = _text(outputs.get("methodology"))
    if methodology is not None:
        facts["methodology"] = methodology
        note("outputs.methodology")
    direction = str(outputs.get("trend_direction") or "").strip().lower()
    if direction in ("up", "down", "stable"):
        facts["trend_direction"] = direction
        note("outputs.trend_direction")
    return facts


def _content_facts(outputs: Mapping[str, Any], note: Any) -> dict[str, Any]:
    plan = _mapping(outputs.get("plan"))
    facts: dict[str, Any] = {}
    pillars = _texts(plan.get("content_pillars"), cap=12)
    if pillars:
        facts["pillars"] = pillars
        note("outputs.plan.content_pillars[].name")
    schedule = _mapping(plan.get("posting_schedule"))
    platforms = tuple(item for item in (_text(key) for key in list(schedule)[:8]) if item)
    if platforms:
        facts["platforms"] = platforms
        note("outputs.plan.posting_schedule")
    facts["campaigns_count"] = len(_rows(plan.get("campaigns")))
    note("outputs.plan.campaigns")
    return facts


def _extract(source: str, outputs: Mapping[str, Any], note: Any) -> dict[str, Any]:
    if source in _GTM_PLAN_SOURCES:
        return _gtm_facts(outputs, note)
    if source == "gtm.launch_readiness":
        return _launch_readiness_facts(outputs, note)
    if source == "crm.icp_intelligence":
        return _icp_facts(outputs, note)
    if source == "product.pricing_intelligence":
        return _pricing_facts(outputs, note)
    if source == "product.roadmap_plan":
        return _roadmap_facts(outputs, note)
    if source in _LEGAL_SOURCES:
        return _legal_facts(source, outputs, note)
    if source == "finance.finance_forecasting":
        return _forecast_facts(outputs, note)
    return _content_facts(outputs, note)


# --------------------------------------------------------------------------- #
# The builder
# --------------------------------------------------------------------------- #


def planning_run_receipt(source: str, dispatch: Mapping[str, Any], instance: Mapping[str, Any] | None, *, now: str) -> PlanningRunReceipt:
    """Seal one COMPLETED planning run; the caller asserts nothing but the source it asked for."""

    _require(source in SOURCE_AGENTS, "PLANNING_SOURCE_UNKNOWN", f"{source!r} is not a planning source; known: {sorted(SOURCE_AGENTS)}")
    now = timestamp(now, field_name="now")
    dispatch = _mapping(dispatch)
    domain, action = _text(dispatch.get("domain")) or "", _text(dispatch.get("action")) or ""
    _require(f"{domain}.{action}" == source, "PLANNING_DOMAIN_MISMATCH", f"dispatch answered {domain}.{action}, not {source}")
    trace = _text(dispatch.get("traceId") or dispatch.get("trace_id"), limit=200)
    trace_ref = _ref("trace", trace)
    _require(trace_ref is not None, "PLANNING_TRACE_MISSING", f"the dispatch carries no traceId a reference can be built from; got {trace!r}")
    fetched = isinstance(instance, Mapping)
    _require(fetched, "PLANNING_INSTANCE_MISSING", f"fetch GET /api/workflows/instances/{trace} first; without it inputs_digest commits nothing")
    instance = _mapping(instance)
    instance_trace = _text(instance.get("traceId") or instance.get("trace_id"))
    _require(instance_trace == trace, "PLANNING_TRACE_MISMATCH", f"the workflow instance carries {instance_trace!r}, not the dispatched trace")
    mode, state = _text(dispatch.get("mode")) or "", _text(instance.get("state")) or ""
    dispatch_state = _text(dispatch.get("state")) or ""
    agreed = dispatch_state in ("", state)
    completed = mode == "completed" and state == "COMPLETED" and agreed
    _require(completed, "PLANNING_RUN_NOT_COMPLETED", f"dispatch mode {mode!r} / dispatch state {dispatch_state!r} / instance state {state!r} is not one completed run")

    inputs = _mapping(instance.get("inputs"))
    # An instance fetched but carrying no inputs leaves the same hole PLANNING_INSTANCE_MISSING
    # exists to close: inputs_digest would commit the empty object, identically for every run.
    _require(bool(inputs), "PLANNING_INSTANCE_MISSING", f"the instance for {trace} carries no inputs; inputs_digest would commit nothing")
    outputs = _mapping(instance.get("outputs")) or _mapping(dispatch.get("outputs"))
    status = str(outputs.get("status") or "").strip().lower()
    _require(status not in REFUSED_OUTPUT_STATUSES, "PLANNING_RUN_NEEDS_INPUT", f"the run reported status {status!r}; it is not evidence")
    access = {str(inputs.get("data_access_mode") or "").strip().lower(), str(outputs.get("data_access_mode") or "").strip().lower()}
    supplied = bool(inputs.get("synthetic_only")) or bool(outputs.get("synthetic_only")) or "synthetic" in access
    _require(not supplied, "PLANNING_RUN_SYNTHETIC", "the run was answered from supplied or synthetic input and proves nothing")
    named_agent = _text(outputs.get("agent"))
    _require(named_agent is None or named_agent in SOURCE_AGENTS[source], "PLANNING_AGENT_MISMATCH", f"{named_agent!r} may not answer for {source}; expected one of {list(SOURCE_AGENTS[source])}")

    generated_at = next((value for value in (
        _normalised_timestamp(outputs.get("timestamp")),
        _normalised_timestamp(outputs.get("generated_at")),
        _normalised_timestamp(outputs.get("analyzed_at")),
        _normalised_timestamp(instance.get("completedAt")),
    ) if value is not None), None)
    _require(generated_at is not None, "PLANNING_TIMESTAMP_MISSING", "nothing in the outputs or the instance timestamps this run")
    already_run = parsed(generated_at) <= parsed(now)
    _require(already_run, "PLANNING_TIMESTAMP_IN_FUTURE", f"the run claims it completed {generated_at}, after {now}; a future stamp never goes stale")
    expires_at = add_days(generated_at, MAX_RUN_AGE_DAYS)
    fresh = parsed(now) <= parsed(expires_at)
    _require(fresh, "PLANNING_RUN_STALE", f"the run completed {generated_at} and is older than {MAX_RUN_AGE_DAYS} days at {now}")

    outputs_digest = stable_digest(outputs)
    rows: list[dict[str, Any]] = []

    def note(path: str, *, confidence: str = "extracted", reserved: int = 1) -> None:
        # ``reserved`` holds a slot for the agent row appended after extraction, so the
        # row naming who answered is never the one silently dropped at the cap.
        if len(rows) + reserved <= MAX_PROVENANCE_ROWS:
            rows.append({"source": source, "trace_ref": trace_ref, "outputs_digest": outputs_digest, "path": path, "confidence": confidence})

    facts = _extract(source, outputs, note)
    agent_ref = named_agent or SOURCE_AGENTS[source][0]
    note("outputs.agent" if named_agent else "SOURCE_AGENTS", confidence="extracted" if named_agent else "fallback", reserved=0)

    evidence = [trace_ref]
    run_ref = _ref("run", instance.get("executionRunId"))
    if run_ref is not None:
        evidence.append(run_ref)
    if facts.get("document_ref") is not None:
        evidence.append(str(facts["document_ref"]))

    payload: dict[str, Any] = {
        "source": source,
        "trace_ref": trace_ref,
        "agent_ref": agent_ref,
        "generated_at": generated_at,
        "state": "COMPLETED",
        "mode": "completed",
        "inputs_digest": stable_digest(dict(inputs)),
        "outputs_digest": outputs_digest,
        "evidence_refs": tuple(evidence[:24]),
        "facts": facts,
        "provenance": tuple(rows),
    }
    workflow_type = _text(instance.get("workflowType"))
    if workflow_type is not None:
        payload["workflow_type"] = workflow_type
    return seal(PlanningRunReceipt, payload, "receipt_digest")


# --------------------------------------------------------------------------- #
# The recorded planning corpus
# --------------------------------------------------------------------------- #

# name -> (file, the planning source whose contract the fixture follows)
PLANNING_FIXTURE_INDEX: dict[str, dict[str, str]] = {
    "gtm.go_to_market_plan": {"file": "gtm_go_to_market_plan.json", "source": "gtm.go_to_market_plan"},
    "gtm.market_entry_analysis": {"file": "gtm_market_entry_analysis.json", "source": "gtm.market_entry_analysis"},
    "crm.icp_intelligence": {"file": "crm_icp_intelligence.json", "source": "crm.icp_intelligence"},
    "product.pricing_intelligence": {"file": "product_pricing_intelligence.json", "source": "product.pricing_intelligence"},
    "product.roadmap_plan": {"file": "product_roadmap_plan.json", "source": "product.roadmap_plan"},
    "legal.incorporation_document_package_au": {"file": "legal_incorporation_document_package_au.json", "source": "legal.incorporation_document_package"},
    "legal.service_agreement_packet": {"file": "legal_service_agreement_packet.json", "source": "legal.service_agreement_packet"},
    "legal.employment_agreement_packet": {"file": "legal_employment_agreement_packet.json", "source": "legal.employment_agreement_packet"},
    "finance.finance_forecasting": {"file": "finance_finance_forecasting.json", "source": "finance.finance_forecasting"},
    "content.generate_plan": {"file": "content_generate_plan.json", "source": "content.generate_plan"},
}

# Pinned canonical digests; regenerate with ``python -m lightbulb.planning_intake`` after an intentional change.
PLANNING_FIXTURE_DIGESTS: dict[str, str] = {
    "gtm.go_to_market_plan": "147c76a0f7f425b11ab8117c4fcda6ba029240fdcbc546ed1db5a14aee3728f0",
    "gtm.market_entry_analysis": "5fd3f0f6fcb281022b25653df209e35543e78bc1b52028789efaef75e59d487f",
    "crm.icp_intelligence": "1795aad7987f5ae5c1375f690e0dc7824225849a4f11a4abb4493af978dfec8e",
    "product.pricing_intelligence": "66541233e8f10deb736e3bd00ab001595118536743acb088d7ad67c333964f0b",
    "product.roadmap_plan": "855e5871c20a0b8ea62cf4f5c64a2679527987f5ecd96159c7fb6285dae1a7f2",
    "legal.incorporation_document_package_au": "e37e6d8722e791822be40251c7a6a1dce680a098ac7c4a2b838a1bcb52be01ca",
    "legal.service_agreement_packet": "4f116e73aafd51bf373b75f1532e228dc0919b26a86cda6d970ca30ebef3baf0",
    "legal.employment_agreement_packet": "db8fc24426e276e027f15707f3c14e03bfc9ec94031076a5ece8f0376a185cdc",
    "finance.finance_forecasting": "6595ebf85cd928c6393d5785c7811705775e078aab4fec579f204f521a85776a",
    "content.generate_plan": "c17a051905ffd57d7ae38698eff6abc8e5573a155c4d1d5c621edf2cf1cd53aa",
}


class PlanningFixtureDrift(ValueError):
    pass


def _read_planning_fixture(name: str) -> dict[str, Any]:
    entry = PLANNING_FIXTURE_INDEX.get(name)
    if entry is None:
        raise KeyError(f"unknown planning fixture {name!r}; known: {sorted(PLANNING_FIXTURE_INDEX)}")
    text = resources.files(FIXTURE_PACKAGE).joinpath(entry["file"]).read_text(encoding="utf-8")
    return json.loads(text)


def planning_fixture_digest(name: str) -> str:
    return stable_digest(_read_planning_fixture(name))


def load_planning_fixture(name: str, *, verify: bool = True) -> dict[str, Any]:
    """The recorded dispatch + workflow instance for one planning source; refused when its digest drifted."""

    document = _read_planning_fixture(name)
    if verify and PLANNING_FIXTURE_DIGESTS:
        expected = PLANNING_FIXTURE_DIGESTS.get(name)
        actual = stable_digest(document)
        if expected is None or expected != actual:
            raise PlanningFixtureDrift(f"planning fixture {name} digest {actual[:16]} is not the pinned {str(expected)[:16]}; update PLANNING_FIXTURE_DIGESTS deliberately")
    return document


def planning_fixture_manifest() -> dict[str, Any]:
    entries = {name: {**entry, "digest": planning_fixture_digest(name)} for name, entry in PLANNING_FIXTURE_INDEX.items()}
    return {"schema": FIXTURE_CORPUS_SCHEMA, "fixtures": entries, "corpus_digest": stable_digest({name: item["digest"] for name, item in entries.items()})}


def _main() -> int:
    manifest = planning_fixture_manifest()
    lines = ["PLANNING_FIXTURE_DIGESTS: dict[str, str] = {"]
    for name, item in manifest["fixtures"].items():
        lines.append(f'    "{name}": "{item["digest"]}",')
    lines.append("}")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_main())


PLANNING_INTAKE_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "planning_intake",
    "golden_loop": PLANNING_GOLDEN_LOOP,
    "stages": ["dispatch_on_platform", "fetch_instance_by_trace", "admit", "extract", "seal"],
    "sources": list(SOURCE_AGENTS),
    "refused_statuses": sorted(REFUSED_OUTPUT_STATUSES),
    "required_connectors": ["lightbulb.domain_agents", "lightbulb.workflow_instances"],
    "hard_rules": [
        "a receipt is sealed only from a COMPLETED run whose workflow instance was fetched by trace; nothing is asserted by the caller",
        "pricing intelligence never yields a price: observed prices are evidence and price_recommended is constant False",
        "legal packets are retained as digests with requires_review true; content bodies never enter the SDK",
        "no identifier, credential or domain payload leaves the extraction whitelist",
    ],
}


__all__ = [
    "FACTS_REQUIRED_BY_SOURCE",
    "FIXTURE_CORPUS_SCHEMA",
    "FIXTURE_PACKAGE",
    "INTAKE_SCHEMA",
    "MAX_OBSERVED_PRICES",
    "MAX_PROVENANCE_ROWS",
    "MAX_RUN_AGE_DAYS",
    "PLANNING_FIXTURE_DIGESTS",
    "PLANNING_FIXTURE_INDEX",
    "PLANNING_GOLDEN_LOOP",
    "PLANNING_INTAKE_MANIFEST",
    "RECEIPT_SCHEMA",
    "REFUSED_OUTPUT_STATUSES",
    "SOURCE_AGENTS",
    "ForecastPoint",
    "ObservedPrice",
    "PlanningFacts",
    "PlanningFixtureDrift",
    "PlanningIntake",
    "PlanningIntakeError",
    "PlanningRunReceipt",
    "PlanningSource",
    "Provenance",
    "build_intake",
    "load_planning_fixture",
    "planning_fixture_digest",
    "planning_fixture_manifest",
    "planning_run_receipt",
]
