"""Agent cockpit for the Growth Engine: diagnose, then act.

Slice 5 of the Lightbulb Growth Engine. :func:`diagnose_growth` turns a funnel
snapshot plus applicable learnings into one deterministic, ranked answer to
the agent's question "what should I do next, and why": the verified
bottleneck, concrete opportunities with the exact primitive to call and
argument hints, evidence gaps with the connector capabilities that would fill
them, and the learnings that apply. Every impact estimate is labeled for what
it is; a diagnosis never invents data and never claims causality.

The module also exposes the Growth Engine's four read-only executable
primitives (``growth.build_funnel_snapshot``, ``growth.diagnose``,
``demand_gen.plan_content_calendar``, ``demand_gen.plan_audience_growth``).
They run the honest *unverified* path — primitives execute without the
host keyring, so their outputs are labeled ``caller_supplied_unverified``;
hosts seal artifacts through the module-level functions. Sealed experiment
design and readout stay host-side by design and are deliberately not
exposed as primitives.

Catalog note: these primitives are intentionally not added to the Backbone
``BUSINESS_PRIMITIVES`` catalog — no domain agent implements them; they are
SDK-only capabilities projected automatically.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import datetime, timezone
from decimal import ROUND_HALF_UP, Decimal
from typing import Annotated, Any, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from .demand_gen_primitives import (
    AudienceGrowthBrief,
    AudienceGrowthPlan,
    ContentCalendarBrief,
    ContentCalendarPlan,
    plan_audience_growth,
    plan_content_calendar,
)
from .growth_funnel import (
    BuildGrowthFunnelSnapshotInput,
    GrowthFunnelSnapshot,
    build_growth_funnel_snapshot,
)
from .growth_learnings import GrowthLearningEntry
from .primitive_runtime import (
    BusinessProcessPrimitive,
    PrimitiveBlocker,
    PrimitiveEvent,
    PrimitiveEvidence,
    PrimitiveExecutionContext,
    PrimitiveExecutionResult,
    PrimitiveExecutionStatus,
)

GROWTH_DIAGNOSIS_SCHEMA = "lightbulb.growth_diagnosis.v1"

_RATE_QUANTUM = Decimal("0.000001")
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_MAX_DIAGNOSIS_LEARNINGS = 20

OpportunityKind = Literal[
    "run_experiment",
    "plan_content_calendar",
    "plan_audience_growth",
    "collect_evidence",
]

# Stage -> connector capabilities that can produce admissible evidence for it.
_STAGE_EVIDENCE_SOURCES: dict[str, tuple[str, ...]] = {
    "audience": (
        "facebook.fetch_metrics",
        "instagram.fetch_metrics",
        "linkedin.fetch_metrics",
    ),
    "traffic": ("google_analytics.fetch_metrics",),
    "engagement": (
        "google_analytics.fetch_metrics",
        "facebook.fetch_metrics",
        "instagram.fetch_metrics",
        "linkedin.fetch_metrics",
    ),
    "conversion": ("shopify.analytics_query", "crm.search_deals"),
    "revenue": ("shopify.analytics_query",),
    "retention": ("shopify.analytics_query",),
}

_BOTTLENECK_DEMAND_GEN: dict[str, OpportunityKind] = {
    "reach_to_visit": "plan_content_calendar",
    "visit_to_engage": "plan_content_calendar",
    "visit_to_purchase": "plan_content_calendar",
    "lead_capture": "plan_audience_growth",
    "purchase_to_repeat": "plan_content_calendar",
}


class GrowthCockpitValidationError(ValueError):
    """Cockpit inputs cannot produce an honest diagnosis."""


def _stable_digest(value: Any) -> str:
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _bounded_text(value: str) -> str:
    if value != value.strip():
        raise ValueError("content must not contain surrounding whitespace")
    if any(ord(character) < 32 for character in value):
        raise ValueError("content contains an unsupported control character")
    return value


ShortText = Annotated[
    str,
    StringConstraints(min_length=1, max_length=300),
    AfterValidator(_bounded_text),
]
Sha256Digest = Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)]


def _parse_timestamp(value: str) -> datetime:
    clean = value.strip()
    try:
        parsed = datetime.fromisoformat(clean.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamp must be valid ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def _normalized_timestamp(value: str) -> str:
    return _parse_timestamp(value).isoformat().replace("+00:00", "Z")


def _immutable_sequence(value: Any) -> Any:
    if isinstance(value, list):
        return tuple(value)
    return value


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=False,
        serialize_by_alias=True,
        strict=True,
    )


class DiagnoseGrowthInput(_StrictModel):
    as_of: str
    funnel_snapshot: GrowthFunnelSnapshot
    learnings: tuple[GrowthLearningEntry, ...] = Field(
        default_factory=tuple, max_length=_MAX_DIAGNOSIS_LEARNINGS
    )

    @field_validator("as_of")
    @classmethod
    def _valid_as_of(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator("learnings", mode="before")
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)


class GrowthOpportunity(_StrictModel):
    rank: int = Field(ge=1, le=50)
    kind: OpportunityKind
    stage: ShortText
    title: ShortText
    mechanism: ShortText
    expected_impact_note: ShortText
    next_primitive_ref: ShortText
    argument_hints: dict[str, str] = Field(default_factory=dict)

    @field_validator("argument_hints", mode="before")
    @classmethod
    def _string_hints(cls, value: Any) -> Any:
        if isinstance(value, Mapping):
            return {str(key): str(item) for key, item in value.items()}
        return value


class ApplicableLearning(_StrictModel):
    entry_digest: Sha256Digest
    grade: Literal["experimental", "observational", "heuristic"]
    lever: ShortText
    claim: ShortText


class DiagnosisRate(_StrictModel):
    rate_name: ShortText
    value: Decimal = Field(ge=0, multiple_of=_RATE_QUANTUM)
    cross_basis: bool
    anomalous: bool

    @field_validator("value", mode="before")
    @classmethod
    def _rate_decimal(cls, value: Any) -> Decimal:
        if isinstance(value, Decimal):
            return value.quantize(_RATE_QUANTUM)
        return Decimal(str(value)).quantize(_RATE_QUANTUM)


class DiagnosisStage(_StrictModel):
    stage: ShortText
    completeness: Literal["present", "partial", "unknown"]
    metric_count: int = Field(ge=0)


class GrowthDiagnosis(_StrictModel):
    """One deterministic answer to "what should I do next, and why"."""

    schema_id: Literal["lightbulb.growth_diagnosis.v1"] = Field(
        default=GROWTH_DIAGNOSIS_SCHEMA,
        alias="schema",
    )
    as_of: str
    funnel_digest: Sha256Digest
    evidence_scope_status: Literal["caller_supplied_unverified", "host_hmac_verified"]
    stages: tuple[DiagnosisStage, ...]
    rates: tuple[DiagnosisRate, ...] = Field(default_factory=tuple)
    bottleneck_rate: ShortText | None = None
    bottleneck_note: ShortText
    opportunities: tuple[GrowthOpportunity, ...] = Field(default_factory=tuple)
    applicable_learnings: tuple[ApplicableLearning, ...] = Field(default_factory=tuple)
    data_quality_notes: tuple[ShortText, ...] = Field(default_factory=tuple)
    diagnosis_digest: Sha256Digest = "0" * 64

    @field_validator("as_of")
    @classmethod
    def _valid_as_of(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator(
        "stages",
        "rates",
        "opportunities",
        "applicable_learnings",
        "data_quality_notes",
        mode="before",
    )
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _pinned_digest(self) -> "GrowthDiagnosis":
        ranks = [item.rank for item in self.opportunities]
        if ranks != sorted(ranks) or len(ranks) != len(set(ranks)):
            raise ValueError("opportunities must carry unique ascending ranks")
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"diagnosis_digest"},
            exclude_none=True,
        )
        expected = _stable_digest(payload)
        if self.diagnosis_digest != "0" * 64 and self.diagnosis_digest != expected:
            raise ValueError("diagnosis_digest does not match the canonical payload")
        object.__setattr__(self, "diagnosis_digest", expected)
        return self

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def _relative_shortfall_note(observed: Decimal, reference: Decimal) -> str:
    if observed <= 0:
        return (
            "observed rate is zero; closing to the reference would be "
            "unbounded relative improvement (treat as exploratory)"
        )
    lift = ((reference - observed) / observed * Decimal(100)).quantize(
        Decimal("0.1"), rounding=ROUND_HALF_UP
    )
    return (
        f"closing to the reference is roughly a {lift}% relative lift at "
        "this stage; heuristic projection, not a forecast"
    )


def diagnose_growth(
    inputs: DiagnoseGrowthInput | Mapping[str, Any],
) -> GrowthDiagnosis:
    """Deterministically rank what to do next from funnel state + learnings.

    The diagnosis echoes the snapshot's own evidence trust label; it never
    upgrades trust, never invents metrics for unknown stages, and labels
    every impact estimate as heuristic. Verification of the snapshot and
    learnings is the caller's job (via the verify_* functions) — advice is
    re-derivable and therefore carries a content digest, not a seal.
    """

    parsed = (
        inputs
        if isinstance(inputs, DiagnoseGrowthInput)
        else DiagnoseGrowthInput.model_validate(inputs)
    )
    snapshot = parsed.funnel_snapshot
    as_of_at = _parse_timestamp(parsed.as_of)
    if _parse_timestamp(snapshot.analysis_as_of) > as_of_at:
        raise GrowthCockpitValidationError(
            "the funnel snapshot is from the future of the diagnosis as_of"
        )

    stages = tuple(
        DiagnosisStage(
            stage=aggregate.stage,
            completeness=aggregate.completeness,
            metric_count=len(aggregate.totals),
        )
        for aggregate in snapshot.stages
    )
    rates = tuple(
        DiagnosisRate(
            rate_name=rate.rate_name,
            value=rate.value,
            cross_basis=rate.cross_basis,
            anomalous=rate.anomalous,
        )
        for rate in snapshot.rates
    )

    opportunities: list[GrowthOpportunity] = []
    notes: list[str] = []
    rank = 1

    bottleneck = snapshot.bottleneck
    if bottleneck is not None:
        reference = bottleneck.reference
        mechanism = (
            f"{bottleneck.rate_name} is {bottleneck.observed} against a "
            f"{reference.quality} reference of {reference.value}"
        )
        opportunities.append(
            GrowthOpportunity(
                rank=rank,
                kind="run_experiment",
                stage=_stage_for_rate(snapshot, bottleneck.rate_name),
                title=f"Experiment on {bottleneck.rate_name}",
                mechanism=mechanism,
                expected_impact_note=_relative_shortfall_note(
                    bottleneck.observed, reference.value
                ),
                next_primitive_ref="design_growth_experiment",
                argument_hints={
                    "metric_name": bottleneck.rate_name,
                    "baseline_source": "funnel_snapshot",
                    "baseline_value": str(bottleneck.observed),
                    "baseline_evidence_digest": snapshot.funnel_digest,
                    "direction": "increase",
                },
            )
        )
        rank += 1
        demand_kind = _BOTTLENECK_DEMAND_GEN[bottleneck.rate_name]
        demand_ref = (
            "demand_gen.plan_content_calendar"
            if demand_kind == "plan_content_calendar"
            else "demand_gen.plan_audience_growth"
        )
        opportunities.append(
            GrowthOpportunity(
                rank=rank,
                kind=demand_kind,
                stage=_stage_for_rate(snapshot, bottleneck.rate_name),
                title=f"Demand-gen plan aimed at {bottleneck.rate_name}",
                mechanism=(
                    "the planner weights its intent mix toward the verified "
                    "bottleneck automatically"
                ),
                expected_impact_note=(
                    "supporting action; measure through the experiment above, "
                    "not by itself"
                ),
                next_primitive_ref=demand_ref,
                argument_hints={"funnel_snapshot": "pass this snapshot"},
            )
        )
        rank += 1
        bottleneck_note = (
            f"verified bottleneck: {bottleneck.rate_name} "
            f"(shortfall {bottleneck.shortfall} of its reference)"
        )
    else:
        bottleneck_note = snapshot.bottleneck_reason or "no bottleneck was determined"

    for aggregate in snapshot.stages:
        if aggregate.completeness != "unknown":
            continue
        sources = _STAGE_EVIDENCE_SOURCES[aggregate.stage]
        opportunities.append(
            GrowthOpportunity(
                rank=rank,
                kind="collect_evidence",
                stage=aggregate.stage,
                title=f"Collect {aggregate.stage} evidence",
                mechanism=(
                    f"the {aggregate.stage} stage has no admissible evidence; "
                    "decisions touching it are blind until it is measured"
                ),
                expected_impact_note=(
                    "unblocks diagnosis; no revenue impact is claimed for "
                    "measurement itself"
                ),
                next_primitive_ref="growth.build_funnel_snapshot",
                argument_hints={
                    "suggested_sources": ", ".join(sources),
                },
            )
        )
        rank += 1

    for rate in snapshot.rates:
        if rate.anomalous:
            notes.append(
                f"rate {rate.rate_name} exceeds 1 and was excluded from "
                "bottleneck ranking; check window alignment across sources"
            )
        if rate.cross_basis:
            notes.append(
                f"rate {rate.rate_name} mixes measurement bases "
                f"({rate.numerator.basis}/{rate.denominator.basis}); treat "
                "small differences with caution"
            )

    if snapshot.evidence_scope_status == "host_hmac_verified":
        notes.append(
            "trust label echoed from the snapshot without verification here; "
            "verify the snapshot seal (verify_growth_funnel_snapshot) before "
            "acting on it"
        )

    applicable: list[ApplicableLearning] = []
    for entry in parsed.learnings:
        if entry.valid_until is not None and (
            _parse_timestamp(entry.valid_until) <= as_of_at
        ):
            continue
        claim = entry.claim if len(entry.claim) <= 300 else entry.claim[:297] + "..."
        applicable.append(
            ApplicableLearning(
                entry_digest=entry.entry_digest,
                grade=entry.grade,
                lever=entry.lever,
                claim=claim,
            )
        )
    grade_rank = {"experimental": 0, "observational": 1, "heuristic": 2}
    applicable.sort(key=lambda item: (grade_rank[item.grade], item.entry_digest))

    return GrowthDiagnosis(
        as_of=parsed.as_of,
        funnel_digest=snapshot.funnel_digest,
        evidence_scope_status=snapshot.evidence_scope_status,
        stages=stages,
        rates=rates,
        bottleneck_rate=(bottleneck.rate_name if bottleneck is not None else None),
        bottleneck_note=bottleneck_note,
        opportunities=tuple(opportunities),
        applicable_learnings=tuple(applicable),
        data_quality_notes=tuple(notes),
    )


def _stage_for_rate(snapshot: GrowthFunnelSnapshot, rate_name: str) -> str:
    for rate in snapshot.rates:
        if rate.rate_name == rate_name:
            return rate.numerator.stage
    return "conversion"


# ---------------------------------------------------------------------------
# Executable primitives (read-only planners; unverified path by design)
# ---------------------------------------------------------------------------

_EXAMPLE_EVIDENCE: dict[str, Any] = {
    "observation_ref": "ga-example",
    "connector_account_ref": "acct.ga.example",
    "provider": "google_analytics",
    "source_capability": "google_analytics.fetch_metrics",
    "observed_at": "2026-08-18T00:00:00Z",
    "window_start": "2026-08-01T00:00:00Z",
    "window_end": "2026-08-15T00:00:00Z",
    "sample_size": 1000,
    "metrics": {"sessions": 1500, "engagements": 520},
    "evidence_digest": "5" * 64,
}

_EXAMPLE_SNAPSHOT: dict[str, Any] = build_growth_funnel_snapshot(
    {
        "analysis_as_of": "2026-08-19T00:00:00Z",
        "snapshot_ref": "snap-example",
        "evidence": (_EXAMPLE_EVIDENCE,),
    }
).to_dict()


def _planner_failure(
    primitive_ref: str,
    version: str,
    exc: ValueError,
) -> PrimitiveExecutionResult[Any]:
    return PrimitiveExecutionResult(
        status=PrimitiveExecutionStatus.FAILED,
        primitive_ref=primitive_ref,
        primitive_version=version,
        summary="The growth planner rejected the brief.",
        blockers=[
            PrimitiveBlocker(
                code="growth_plan_invalid",
                message=str(exc)[:500],
            )
        ],
        retryable=False,
    )


class BuildGrowthFunnelSnapshotPrimitive(
    BusinessProcessPrimitive[BuildGrowthFunnelSnapshotInput, GrowthFunnelSnapshot]
):
    """Compile a canonical funnel snapshot from supplied evidence envelopes."""

    primitive_ref = "growth.build_funnel_snapshot"
    version = "2.0.0"
    title = "Build growth funnel snapshot"
    description = (
        "Aggregate sealed or caller-supplied connector analytics envelopes "
        "into the canonical six-stage growth funnel with honest completeness, "
        "basis separation, and reference-labeled bottleneck detection. "
        "Runs without connector calls; host sealing happens server-side."
    )
    input_model = BuildGrowthFunnelSnapshotInput
    output_model = GrowthFunnelSnapshot
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs = {
        "analysis_as_of": "2026-08-19T00:00:00Z",
        "snapshot_ref": "snap-example",
        "evidence": [_EXAMPLE_EVIDENCE],
    }

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: BuildGrowthFunnelSnapshotInput,
    ) -> PrimitiveExecutionResult[GrowthFunnelSnapshot]:
        try:
            snapshot = build_growth_funnel_snapshot(inputs)
        except ValueError as exc:
            return _planner_failure(self.primitive_ref, self.version, exc)
        return PrimitiveExecutionResult[GrowthFunnelSnapshot](
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                f"Funnel snapshot built: {len(snapshot.admitted_evidence)} "
                f"envelopes admitted, {len(snapshot.excluded_evidence)} "
                f"excluded; bottleneck "
                f"{snapshot.bottleneck.rate_name if snapshot.bottleneck else 'none'}."
            ),
            output=snapshot,
            events=[
                PrimitiveEvent(
                    type="growth.funnel_snapshot_built",
                    payload={
                        "snapshot_ref": snapshot.snapshot_ref,
                        "admitted": len(snapshot.admitted_evidence),
                        "excluded": len(snapshot.excluded_evidence),
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="deterministic_plan",
                    summary="Snapshot digest "
                    + snapshot.funnel_digest[:16]
                    + "… derived from admitted evidence only.",
                )
            ],
        )


class DiagnoseGrowthPrimitive(
    BusinessProcessPrimitive[DiagnoseGrowthInput, GrowthDiagnosis]
):
    """Rank the next best growth actions from a funnel snapshot."""

    primitive_ref = "growth.diagnose"
    version = "2.0.0"
    title = "Diagnose growth"
    description = (
        "Turn a funnel snapshot plus applicable learnings into ranked, "
        "actionable opportunities: the verified bottleneck, the exact next "
        "primitive to call with argument hints, evidence gaps, and data "
        "quality notes. Impact estimates are labeled heuristics."
    )
    input_model = DiagnoseGrowthInput
    output_model = GrowthDiagnosis
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs = {
        "as_of": "2026-08-19T00:00:00Z",
        "funnel_snapshot": _EXAMPLE_SNAPSHOT,
    }

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: DiagnoseGrowthInput,
    ) -> PrimitiveExecutionResult[GrowthDiagnosis]:
        try:
            diagnosis = diagnose_growth(inputs)
        except ValueError as exc:
            return _planner_failure(self.primitive_ref, self.version, exc)
        return PrimitiveExecutionResult[GrowthDiagnosis](
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                f"Diagnosis ready: {len(diagnosis.opportunities)} "
                f"opportunities; {diagnosis.bottleneck_note}"
            ),
            output=diagnosis,
            events=[
                PrimitiveEvent(
                    type="growth.diagnosis_ready",
                    payload={
                        "opportunities": len(diagnosis.opportunities),
                        "bottleneck": diagnosis.bottleneck_rate or "none",
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="deterministic_plan",
                    summary="Diagnosis derived from funnel digest "
                    + diagnosis.funnel_digest[:16]
                    + "…",
                )
            ],
        )


class PlanContentCalendarPrimitive(
    BusinessProcessPrimitive[ContentCalendarBrief, ContentCalendarPlan]
):
    """Compile a bottleneck-aimed, approval-ready posting calendar."""

    primitive_ref = "demand_gen.plan_content_calendar"
    version = "2.0.0"
    title = "Plan content calendar"
    description = (
        "Deterministically compile a bounded social posting calendar across "
        "LinkedIn, Facebook, and Instagram accounts. The intent mix targets "
        "the funnel bottleneck; every item is a content brief bound to a "
        "content-digest approval unit. Planning only — execution requires "
        "governed approvals."
    )
    input_model = ContentCalendarBrief
    output_model = ContentCalendarPlan
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs = {
        "calendar_ref": "cal-example",
        "planning_as_of": "2026-08-19T00:00:00Z",
        "campaign_goal": "Launch the ceramic mug collection to repeat buyers.",
        "window_start": "2026-08-24T00:00:00Z",
        "window_weeks": 2,
        "posts_per_week_per_channel": 3,
        "channel_accounts": [
            {
                "channel": "facebook",
                "connector_account_ref": "acct.fb.example",
                "provider_target_id": "12345",
            }
        ],
        "content_themes": ["craftsmanship"],
        "funnel_snapshot": _EXAMPLE_SNAPSHOT,
    }

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: ContentCalendarBrief,
    ) -> PrimitiveExecutionResult[ContentCalendarPlan]:
        try:
            plan = plan_content_calendar(inputs)
        except ValueError as exc:
            return _planner_failure(self.primitive_ref, self.version, exc)
        return PrimitiveExecutionResult[ContentCalendarPlan](
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                f"Calendar planned: {len(plan.items)} briefs, primary intent "
                f"{plan.primary_intent}, status {plan.evidence_scope_status}."
            ),
            output=plan,
            events=[
                PrimitiveEvent(
                    type="growth.content_calendar_planned",
                    payload={
                        "calendar_ref": plan.calendar_ref,
                        "items": len(plan.items),
                        "primary_intent": plan.primary_intent,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="deterministic_plan",
                    summary="Plan digest "
                    + plan.plan_digest[:16]
                    + "…; every item carries a content-bound approval unit.",
                )
            ],
        )


class PlanAudienceGrowthPrimitive(
    BusinessProcessPrimitive[AudienceGrowthBrief, AudienceGrowthPlan]
):
    """Compile follower-growth or lead-magnet loops from funnel state."""

    primitive_ref = "demand_gen.plan_audience_growth"
    version = "2.0.0"
    title = "Plan audience growth"
    description = (
        "Deterministically compile audience-building actions (follower "
        "growth or lead-magnet funnel) chosen from the funnel's audience and "
        "lead state, with structural frequency caps and content-digest "
        "approval units. Planning only."
    )
    input_model = AudienceGrowthBrief
    output_model = AudienceGrowthPlan
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs = {
        "plan_ref": "aud-example",
        "planning_as_of": "2026-08-19T00:00:00Z",
        "growth_goal": "Grow the newsletter with the mug-care guide magnet.",
        "window_start": "2026-08-24T00:00:00Z",
        "window_weeks": 2,
        "actions_per_week_per_channel": 2,
        "channel_accounts": [
            {
                "channel": "instagram",
                "connector_account_ref": "acct.ig.example",
                "provider_target_id": "6789",
            }
        ],
        "lead_magnet_title": "Mug care guide",
        "funnel_snapshot": _EXAMPLE_SNAPSHOT,
    }

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: AudienceGrowthBrief,
    ) -> PrimitiveExecutionResult[AudienceGrowthPlan]:
        try:
            plan = plan_audience_growth(inputs)
        except ValueError as exc:
            return _planner_failure(self.primitive_ref, self.version, exc)
        return PrimitiveExecutionResult[AudienceGrowthPlan](
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                f"Audience plan ready: strategy {plan.strategy} "
                f"({plan.strategy_rationale}); {len(plan.items)} actions."
            ),
            output=plan,
            events=[
                PrimitiveEvent(
                    type="growth.audience_growth_planned",
                    payload={
                        "plan_ref": plan.plan_ref,
                        "strategy": plan.strategy,
                        "items": len(plan.items),
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="deterministic_plan",
                    summary="Plan digest "
                    + plan.plan_digest[:16]
                    + "…; actions carry content-bound approval units.",
                )
            ],
        )


__all__ = [
    "GROWTH_DIAGNOSIS_SCHEMA",
    "ApplicableLearning",
    "BuildGrowthFunnelSnapshotPrimitive",
    "DiagnoseGrowthInput",
    "DiagnoseGrowthPrimitive",
    "DiagnosisRate",
    "DiagnosisStage",
    "GrowthCockpitValidationError",
    "GrowthDiagnosis",
    "GrowthOpportunity",
    "PlanAudienceGrowthPrimitive",
    "PlanContentCalendarPrimitive",
    "diagnose_growth",
]
