"""Growth briefing: session rehydration for a mind that reboots.

The Growth Engine's primary user is an AI agent, and an agent's defining
operational constraint is amnesia — every session starts with an empty
context window while the workspace quietly holds everything that matters.
This module is the cold-start answer: one deterministic call that renders
the compiled agenda and the scope's sealed artifacts into a single
plain-text briefing that FITS A STATED BUDGET, so rehydration costs a
known number of characters instead of a workspace crawl.

Design rules, all in service of honest compression:

- **The briefing renders; it never re-decides.** Ranking, staleness,
  escalations, verdicts — all come from :func:`compile_growth_agenda` and
  the artifacts verbatim. The one computation added here is the mandate
  spend summary, and that is pinned by test to the gate's own receipts.
- **Lossy is fine; silent loss is not.** Sections are dropped whole, in a
  documented priority order, and every dropped section is named in
  ``sections_omitted`` with the workspace kind to fetch — the reader
  always knows what the briefing did NOT tell them.
- **A budget too small for honesty is refused.** Below the floor (header,
  the objective line, and at least one agenda item) the compile raises
  instead of emitting a briefing that hides the operating picture.
- **Trust is echoed, never upgraded.** The briefing carries the agenda's
  own trust label; a rendering cannot be more verified than its inputs.
- **Deterministic.** Same inputs, same text, same digest. No wall clock,
  no randomness; ``as_of`` is the caller's.

The section priority (highest first): header, objective, agenda,
authority, money, funnel, experiments, learnings. Drops start from the
bottom.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import datetime, timezone
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

from .growth_mandate import summarize_mandate_spend
from .growth_operating import (
    GrowthAgenda,
    GrowthAgendaInput,
    compile_growth_agenda,
)
from .primitive_runtime import (
    BusinessProcessPrimitive,
    PrimitiveBlocker,
    PrimitiveEvent,
    PrimitiveEvidence,
    PrimitiveExecutionContext,
    PrimitiveExecutionResult,
    PrimitiveExecutionStatus,
)

GROWTH_BRIEFING_SCHEMA = "lightbulb.growth_briefing.v1"

_SHA256_PATTERN = r"^[0-9a-f]{64}$"

_MIN_BUDGET_CHARS = 600
_MAX_BUDGET_CHARS = 32_000
_DEFAULT_BUDGET_CHARS = 4_000
_MAX_SOURCE_DIGESTS = 64
_MAX_RENDERED_ITEMS = 20
_DIGEST_ABBREV = 12

# Highest priority first; budget drops start from the tail. The header is
# structural and never dropped; objective and at least one agenda item are
# the honesty floor.
_SECTION_PRIORITY: tuple[str, ...] = (
    "objective",
    "agenda",
    "authority",
    "money",
    "funnel",
    "experiments",
    "learnings",
)


class GrowthBriefingValidationError(ValueError):
    """Briefing inputs cannot produce an honest rendering."""


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


def _multiline_text(value: str) -> str:
    if value != value.strip():
        raise ValueError("content must not contain surrounding whitespace")
    if any(ord(character) < 32 and character != "\n" for character in value):
        raise ValueError("content contains an unsupported control character")
    return value


ShortText = Annotated[
    str,
    StringConstraints(min_length=1, max_length=300),
    AfterValidator(_bounded_text),
]
BriefingText = Annotated[
    str,
    StringConstraints(min_length=1, max_length=_MAX_BUDGET_CHARS),
    AfterValidator(_multiline_text),
]
Sha256Digest = Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)]


def _abbrev(digest: str) -> str:
    return digest[:_DIGEST_ABBREV] + "…"


def _parse_timestamp(value: str) -> datetime:
    clean = value.strip()
    try:
        parsed = datetime.fromisoformat(clean.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamp must be valid ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must include a UTC offset")
    return parsed.astimezone(timezone.utc)


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=False,
        serialize_by_alias=True,
        strict=True,
    )


class GrowthBriefing(_StrictModel):
    """One budgeted, digest-pinned rendering of the scope's state."""

    schema_id: Literal["lightbulb.growth_briefing.v1"] = Field(
        default=GROWTH_BRIEFING_SCHEMA,
        alias="schema",
    )
    as_of: str
    budget_chars: int = Field(ge=_MIN_BUDGET_CHARS, le=_MAX_BUDGET_CHARS)
    used_chars: int = Field(ge=1, le=_MAX_BUDGET_CHARS)
    evidence_scope_status: Literal[
        "caller_supplied_unverified", "host_hmac_verified"
    ]
    text: BriefingText
    sections_included: tuple[ShortText, ...] = Field(min_length=1, max_length=10)
    sections_omitted: tuple[ShortText, ...] = Field(
        default_factory=tuple, max_length=10
    )
    agenda_digest: Sha256Digest
    source_digests: tuple[Sha256Digest, ...] = Field(
        default_factory=tuple, max_length=_MAX_SOURCE_DIGESTS
    )
    data_quality_notes: tuple[ShortText, ...] = Field(
        default_factory=tuple, max_length=10
    )
    briefing_digest: Sha256Digest = "0" * 64

    @field_validator(
        "sections_included",
        "sections_omitted",
        "source_digests",
        "data_quality_notes",
        mode="before",
    )
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        if isinstance(value, list):
            return tuple(value)
        return value

    @model_validator(mode="after")
    def _honest_rendering(self) -> "GrowthBriefing":
        if self.used_chars != len(self.text):
            raise ValueError("used_chars must equal the rendered text length")
        if self.used_chars > self.budget_chars:
            raise ValueError("the rendering exceeds its stated budget")
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"briefing_digest"},
            exclude_none=True,
        )
        expected = _stable_digest(payload)
        if self.briefing_digest != "0" * 64 and self.briefing_digest != expected:
            raise ValueError("briefing_digest does not match the canonical payload")
        object.__setattr__(self, "briefing_digest", expected)
        return self

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


class CompileBriefingInput(_StrictModel):
    budget_chars: int = Field(
        default=_DEFAULT_BUDGET_CHARS, ge=_MIN_BUDGET_CHARS, le=_MAX_BUDGET_CHARS
    )
    max_agenda_items: int = Field(default=10, ge=1, le=_MAX_RENDERED_ITEMS)
    # Cosmetic display label for the header (e.g. the workspace project
    # ref); never authority — scope binding lives in the artifacts' seals.
    scope_label: ShortText | None = None
    agenda: GrowthAgendaInput


# ---------------------------------------------------------------------------
# Section renderers — each returns (lines, digests); pure string assembly
# ---------------------------------------------------------------------------


def _objective_section(
    parsed: CompileBriefingInput,
) -> tuple[list[str], list[str], str | None]:
    objective = parsed.agenda.objective
    assessment = parsed.agenda.objective_assessment
    if objective is None:
        return (
            [
                "no growth objective is committed; the loop has no "
                "destination (commit_growth_objective)",
            ],
            [],
            None,
        )
    digests = [objective.objective_digest]
    if assessment is None:
        return (
            [
                f"{objective.objective_ref}: committed, unassessed · target "
                f"{objective.target_per_period} {objective.currency}"
                f"/{objective.period_days}d by {objective.target_by} · run "
                "growth.assess_objective"
                f" ({_abbrev(objective.objective_digest)})",
            ],
            digests,
            "growth_objective/" + objective.objective_ref,
        )
    digests.append(assessment.assessment_digest)
    return (
        [
            f"{objective.objective_ref}: {assessment.verdict} · observed "
            f"{assessment.observed_per_period} vs target "
            f"{assessment.target_per_period} {assessment.currency}"
            f"/{assessment.period_days}d · gap "
            f"{assessment.remaining_gap_per_period} · deadline "
            f"{objective.target_by} ({_abbrev(assessment.assessment_digest)})",
        ],
        digests,
        "growth_objective/" + objective.objective_ref,
    )


def _agenda_section(
    agenda: GrowthAgenda,
    item_limit: int,
) -> tuple[list[str], list[str]]:
    wake = f", wake {agenda.wake_at}" if agenda.wake_at is not None else ""
    lines = [f"idle={agenda.idle}{wake}"]
    for item in agenda.items[:item_limit]:
        if item.kind == "opportunity_blocked":
            # A compiled "blocked" verdict must survive the rendering: an
            # actionable-looking arrow on a blocked item re-decides it.
            reason = item.blocked_by[0] if item.blocked_by else "blocked"
            lines.append(
                f"{item.rank}. [{item.urgency}·blocked] {item.title} · "
                f"{reason}"
            )
            continue
        pointer = (
            f" -> {item.next_primitive_ref}"
            if item.next_primitive_ref is not None
            else ""
        )
        lines.append(f"{item.rank}. [{item.urgency}] {item.title}{pointer}")
    hidden = len(agenda.items) - item_limit
    if hidden > 0:
        lines.append(f"(+{hidden} more items in the full agenda)")
    return lines, [agenda.agenda_digest]


def _authority_section(
    parsed: CompileBriefingInput,
) -> tuple[list[str], list[str], str | None]:
    mandate = parsed.agenda.mandate
    if mandate is None:
        return (
            [
                "no mandate is granted; every action needs the human "
                "(grant_growth_mandate starts bounded autonomy)",
            ],
            [],
            None,
        )
    # Effectiveness is a pure comparison of two already-quoted timestamps,
    # not a re-decision — and remaining-authority lines on a lapsed mandate
    # would read as live budget.
    as_of_at = _parse_timestamp(parsed.agenda.as_of)
    if as_of_at >= _parse_timestamp(mandate.expires_at):
        return (
            [
                f"mandate {mandate.mandate_ref} EXPIRED at "
                f"{mandate.expires_at}; nothing can be authorized — renewal "
                f"is the human's call ({_abbrev(mandate.mandate_digest)})"
            ],
            [mandate.mandate_digest],
            "growth_mandate/" + mandate.mandate_ref,
        )
    if as_of_at < _parse_timestamp(mandate.granted_at):
        return (
            [
                f"mandate {mandate.mandate_ref} not yet effective until "
                f"{mandate.granted_at} ({_abbrev(mandate.mandate_digest)})"
            ],
            [mandate.mandate_digest],
            "growth_mandate/" + mandate.mandate_ref,
        )
    lines = [
        f"mandate {mandate.mandate_ref} (to {mandate.granted_to}, expires "
        f"{mandate.expires_at}) ({_abbrev(mandate.mandate_digest)})"
    ]
    summaries = summarize_mandate_spend(
        mandate, parsed.agenda.authorizations, as_of=parsed.agenda.as_of
    )
    for summary in summaries:
        lines.append(
            f"- {summary.action_kind}: {summary.window_spent} of "
            f"{summary.window_limit} {mandate.currency} spent this "
            f"{summary.window_days}d window · remaining "
            f"{summary.window_remaining} · per-action cap "
            f"{summary.per_action_limit}"
        )
    return lines, [mandate.mandate_digest], "growth_mandate/" + mandate.mandate_ref


def _money_section(
    parsed: CompileBriefingInput,
) -> tuple[list[str], list[str], str | None]:
    economics = parsed.agenda.unit_economics
    value = parsed.agenda.customer_value
    lines: list[str] = []
    digests: list[str] = []
    ref: str | None = None
    if economics is not None:
        parts: list[str] = []
        for name, label in (
            ("contribution_profit", "contribution"),
            ("contribution_margin", "margin"),
            ("customer_acquisition_cost", "CAC"),
        ):
            component = economics.component(name)
            if component is None:
                continue
            flag = "" if component.complete else " (incomplete)"
            parts.append(f"{label} {component.value}{flag}")
        rendered = " · ".join(parts) if parts else "no derivable components"
        lines.append(
            f"economics {economics.economics_ref} (as of "
            f"{economics.analysis_as_of}, {economics.currency}): {rendered} "
            f"({_abbrev(economics.economics_digest)})"
        )
        digests.append(economics.economics_digest)
        ref = "unit_economics/" + economics.economics_ref
    if value is not None:
        # A sealed customer-value snapshot renders whether or not economics
        # travelled with it: an artifact the reader cannot see is a silent
        # loss. With no ceiling horizon, observed revenue still shows.
        summary = next(
            (
                f"h{component.horizon_days} LTV {component.contribution_ltv}"
                f" · CAC ceiling {component.cac_ceiling}"
                for component in reversed(value.horizons)
                if component.cac_ceiling is not None
            ),
            None,
        )
        if summary is None and value.horizons:
            longest = value.horizons[-1]
            summary = (
                f"h{longest.horizon_days} net revenue/customer "
                f"{longest.net_revenue_per_customer}"
            )
        if summary is None:
            summary = "no fully-aged horizons yet"
        lines.append(
            f"customer value {value.value_ref}: {summary} "
            f"({_abbrev(value.value_digest)})"
        )
        digests.append(value.value_digest)
        if ref is None:
            ref = "customer_value/" + value.value_ref
    return lines, digests, ref


def _funnel_section(
    parsed: CompileBriefingInput,
) -> tuple[list[str], list[str], str | None]:
    snapshot = parsed.agenda.funnel_snapshot
    if snapshot is None:
        return [], [], None
    stage_bits = []
    for aggregate in snapshot.stages:
        if aggregate.completeness == "unknown" or not aggregate.totals:
            stage_bits.append(f"{aggregate.stage} unknown")
            continue
        total = aggregate.totals[0]
        suffix = "" if aggregate.completeness == "present" else " (partial)"
        more = (
            f" (+{len(aggregate.totals) - 1} more metrics)"
            if len(aggregate.totals) > 1
            else ""
        )
        stage_bits.append(
            f"{aggregate.stage} {total.metric}={total.value}{suffix}{more}"
        )
    bottleneck = (
        f"{snapshot.bottleneck.rate_name} (observed "
        f"{snapshot.bottleneck.observed})"
        if snapshot.bottleneck is not None
        else "none identified"
    )
    return (
        [
            f"funnel {snapshot.snapshot_ref} (as of {snapshot.analysis_as_of}): "
            + " · ".join(stage_bits)
            + f" · bottleneck: {bottleneck} ({_abbrev(snapshot.funnel_digest)})"
        ],
        [snapshot.funnel_digest],
        "funnel_snapshot/" + snapshot.snapshot_ref,
    )


def _experiments_section(
    parsed: CompileBriefingInput,
) -> tuple[list[str], list[str], str | None]:
    read_out = {readout.design_digest for readout in parsed.agenda.readouts}
    in_flight = [
        design
        for design in parsed.agenda.designs
        if design.design_digest not in read_out
    ]
    if not in_flight:
        return [], [], None
    lines = ["in flight:"]
    digests: list[str] = []
    for design in in_flight[:5]:
        lines.append(
            f"- {design.design_ref} (readout due {design.readout_horizon})"
        )
        digests.append(design.design_digest)
    if len(in_flight) > 5:
        lines.append(f"(+{len(in_flight) - 5} more designs)")
    return lines, digests, "experiment_design"


def _learnings_section(
    parsed: CompileBriefingInput,
) -> tuple[list[str], list[str], str | None]:
    learnings = parsed.agenda.learnings
    if not learnings:
        return [], [], None
    levers: list[str] = []
    for entry in learnings:
        if entry.lever not in levers:
            levers.append(entry.lever)
    shown = ", ".join(levers[:3])
    more = f" (+{len(levers) - 3} more levers)" if len(levers) > 3 else ""
    return (
        [f"{len(learnings)} banked learnings · levers: {shown}{more}"],
        [],
        "growth_learnings ledger",
    )


def _render(header: list[str], sections: list[tuple[str, list[str]]]) -> str:
    lines = list(header)
    for name, body in sections:
        lines.append(f"== {name} ==")
        lines.extend(body)
    return "\n".join(lines)


def compile_growth_briefing(
    inputs: CompileBriefingInput | Mapping[str, Any],
    *,
    inputs_verified_by_host: bool = False,
) -> GrowthBriefing:
    """Render one budgeted cold-start briefing; the agenda does the deciding.

    Compiles the agenda from the supplied inputs (the same pure join the
    conductor uses, trust label included), then renders sections in
    priority order — objective, agenda, authority, money, funnel,
    experiments, learnings — dropping whole sections from the bottom until
    the text fits ``budget_chars``. Dropped sections are NAMED in
    ``sections_omitted`` with where to fetch them. If even the honesty
    floor (header + objective + one agenda line) cannot fit, the compile
    refuses rather than hide the operating picture.
    """

    parsed = (
        inputs
        if isinstance(inputs, CompileBriefingInput)
        else CompileBriefingInput.model_validate(inputs)
    )
    agenda = compile_growth_agenda(
        parsed.agenda, inputs_verified_by_host=inputs_verified_by_host
    )

    source_digests: list[str] = []

    def _pin(digests: list[str]) -> None:
        for digest in digests:
            if digest not in source_digests:
                source_digests.append(digest)

    objective_lines, objective_digests, _ = _objective_section(parsed)
    agenda_lines, agenda_digests = _agenda_section(
        agenda, parsed.max_agenda_items
    )
    optional: dict[str, tuple[list[str], list[str], str | None]] = {
        "authority": _authority_section(parsed),
        "money": _money_section(parsed),
        "funnel": _funnel_section(parsed),
        "experiments": _experiments_section(parsed),
        "learnings": _learnings_section(parsed),
    }

    scope_bit = f" · {parsed.scope_label}" if parsed.scope_label else ""
    header = [
        f"GROWTH BRIEFING{scope_bit} · as of {parsed.agenda.as_of}",
        f"trust: {agenda.evidence_scope_status} · budget "
        f"{parsed.budget_chars} chars",
    ]

    included: list[tuple[str, list[str]]] = [("objective", objective_lines)]
    omitted: list[str] = []
    _pin(objective_digests)

    # The agenda section shrinks before anything else is judged: fewer
    # items, never zero — the do-this-now list is the point of a briefing.
    item_limit = parsed.max_agenda_items
    while True:
        agenda_lines, agenda_digests = _agenda_section(agenda, item_limit)
        candidate = _render(header, included + [("agenda", agenda_lines)])
        if len(candidate) <= parsed.budget_chars or item_limit == 1:
            break
        item_limit -= 1
    included.append(("agenda", agenda_lines))
    _pin(agenda_digests)
    text = _render(header, included)
    if len(text) > parsed.budget_chars:
        raise GrowthBriefingValidationError(
            f"budget_chars={parsed.budget_chars} cannot hold an honest "
            "briefing (header, the objective line, and one agenda item); "
            "raise the budget"
        )

    for name in _SECTION_PRIORITY:
        if name in {"objective", "agenda"}:
            continue
        lines, digests, pointer = optional[name]
        if not lines:
            continue
        candidate = _render(header, included + [(name, lines)])
        if len(candidate) <= parsed.budget_chars:
            included.append((name, lines))
            _pin(digests)
            text = candidate
        else:
            omitted.append(
                f"{name}" + (f" (see {pointer})" if pointer else "")
            )

    notes = [
        "the briefing is a lossy rendering; every number is quoted from a "
        "digest-pinned artifact — verify seals before acting on money",
        "mandate spend lines are advisory window arithmetic over stored "
        "receipts; the sealed gate remains the authority",
    ]
    # The agenda's own caveats (truncation, reconciliation failures,
    # staleness heuristics) are material context, not decoration — they
    # travel with the briefing or their elision is counted out loud.
    agenda_note_room = 10 - len(notes) - 1
    notes.extend(agenda.data_quality_notes[:agenda_note_room])
    elided = len(agenda.data_quality_notes) - agenda_note_room
    if elided > 0:
        notes.append(
            f"{elided} agenda data-quality note(s) elided; read the full "
            "agenda for all caveats"
        )
    if len(source_digests) > _MAX_SOURCE_DIGESTS:
        notes.append(
            f"{len(source_digests) - _MAX_SOURCE_DIGESTS} source digest(s) "
            "beyond the pin cap are cited only inside their sections"
        )
    return GrowthBriefing(
        as_of=parsed.agenda.as_of,
        budget_chars=parsed.budget_chars,
        used_chars=len(text),
        evidence_scope_status=agenda.evidence_scope_status,
        text=text,
        sections_included=tuple(name for name, _ in included),
        sections_omitted=tuple(omitted),
        agenda_digest=agenda.agenda_digest,
        source_digests=tuple(source_digests[:_MAX_SOURCE_DIGESTS]),
        data_quality_notes=tuple(notes[:10]),
    )


# ---------------------------------------------------------------------------
# Executable primitive (read-only; unverified path by design)
# ---------------------------------------------------------------------------


def _planner_failure(
    primitive_ref: str,
    version: str,
    exc: ValueError,
) -> PrimitiveExecutionResult[Any]:
    return PrimitiveExecutionResult(
        status=PrimitiveExecutionStatus.FAILED,
        primitive_ref=primitive_ref,
        primitive_version=version,
        summary="The briefing engine rejected the inputs.",
        blockers=[
            PrimitiveBlocker(
                code="growth_briefing_invalid",
                message=str(exc)[:500],
            )
        ],
        retryable=False,
    )


class CompileBriefingPrimitive(
    BusinessProcessPrimitive[CompileBriefingInput, GrowthBriefing]
):
    """Render the scope's cold-start briefing under a character budget."""

    primitive_ref = "growth.compile_briefing"
    version = "1.0.0"
    title = "Compile growth briefing"
    description = (
        "One deterministic, budgeted rehydration for an agent starting a "
        "session cold: the compiled agenda plus the scope's sealed "
        "artifacts rendered as plain text that fits a stated character "
        "budget — objective status, the ranked do-this-now list, remaining "
        "mandate authority, unit economics, funnel state, in-flight "
        "experiments, banked learnings. Sections drop whole and are NAMED "
        "when the budget is tight; a budget too small for the honesty "
        "floor is refused. This path is honestly labeled "
        "caller_supplied_unverified; the workspace host path compiles the "
        "same briefing from verified artifacts."
    )
    input_model = CompileBriefingInput
    output_model = GrowthBriefing
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs = {
        "budget_chars": 1200,
        "agenda": {"as_of": "2026-08-22T00:00:00Z"},
    }

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: CompileBriefingInput,
    ) -> PrimitiveExecutionResult[GrowthBriefing]:
        try:
            briefing = compile_growth_briefing(inputs)
        except ValueError as exc:
            return _planner_failure(self.primitive_ref, self.version, exc)
        return PrimitiveExecutionResult[GrowthBriefing](
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                f"Briefing rendered in {briefing.used_chars} of "
                f"{briefing.budget_chars} chars; "
                f"{len(briefing.sections_included)} section(s), "
                f"{len(briefing.sections_omitted)} omitted."
            ),
            output=briefing,
            events=[
                PrimitiveEvent(
                    type="growth.briefing_compiled",
                    payload={
                        "used_chars": briefing.used_chars,
                        "sections_omitted": len(briefing.sections_omitted),
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="deterministic_plan",
                    summary="Briefing bound to agenda "
                    + briefing.agenda_digest[:16]
                    + "…; lossy rendering with named omissions",
                )
            ],
        )


__all__ = [
    "GROWTH_BRIEFING_SCHEMA",
    "CompileBriefingInput",
    "CompileBriefingPrimitive",
    "GrowthBriefing",
    "GrowthBriefingValidationError",
    "compile_growth_briefing",
]
