"""Win/loss: what the replayed prospects say about where deals are won and lost, and what to change in the ICP, the outreach, or the qualification.

Every lost prospect carries the reason it was lost and the stage it was
lost at; every won one carries its fit score, source, sequence, and last
channel.  Nothing aggregated them.  ``build_win_loss`` does, from replayed
prospect states only: win rate overall and by fit band, source, sequence,
last channel, stage at loss, and loss reason (and by industry, region, and
size band when the caller supplies the prospects' facts, which the state
deliberately does not persist), with deterministic recommendations that
name the segment and the number behind them.  Nothing here reads a
provider, persists anything, or scores a prospect: the report is the
consequence of the states it read.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from decimal import ROUND_HALF_UP, Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    MONEY_QUANTUM,
    CurrencyCode,
    Sha256Digest,
    ShortText,
    StrictModel,
    decimal_value,
    detached,
    parsed,
    seal,
    sealed_digest,
    skip_digests,
    timestamp,
)

WIN_LOSS_SCHEMA = "lightbulb.pipeline_win_loss.v1"
SEGMENT_DIMENSIONS: tuple[str, ...] = ("fit_band", "source", "sequence", "last_channel", "stage_at_loss", "loss_reason", "industry", "region", "size_band")
SegmentDimension = Literal["fit_band", "source", "sequence", "last_channel", "stage_at_loss", "loss_reason", "industry", "region", "size_band"]
_SIZE_BANDS: tuple[tuple[int, str], ...] = ((10, "1-9"), (50, "10-49"), (200, "50-199"), (1000, "200-999"), (10_000_000, "1000+"))
_RATE_QUANTUM = Decimal("0.01")
_HUNDRED = Decimal("100")


class WinLossError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise WinLossError(code, message)


def _rate(numerator: int, denominator: int) -> Decimal | None:
    return None if denominator == 0 else (Decimal(numerator) / Decimal(denominator) * _HUNDRED).quantize(_RATE_QUANTUM, rounding=ROUND_HALF_UP)


def _money(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


class WinLossSegment(StrictModel):
    dimension: SegmentDimension
    value: ShortText
    prospects: int = Field(ge=0)
    won: int = Field(ge=0)
    lost: int = Field(ge=0)
    open: int = Field(ge=0)
    win_rate_percent: Decimal | None = None
    loss_share_percent: Decimal | None = None
    won_value: Decimal

    @field_validator("win_rate_percent", "loss_share_percent", "won_value", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))


class WinLossReport(StrictModel):
    schema_id: str = Field(default=WIN_LOSS_SCHEMA, alias="schema")
    currency: CurrencyCode
    as_of: str
    pipeline_plan_digest: Sha256Digest
    since: str | None = None
    prospects: int = Field(ge=0)
    won: int = Field(ge=0)
    lost: int = Field(ge=0)
    open: int = Field(ge=0)
    suppressed: int = Field(ge=0)
    disqualified: int = Field(ge=0)
    win_rate_percent: Decimal | None = None
    won_value: Decimal
    average_won_value: Decimal | None = None
    average_touches_to_win: Decimal | None = None
    average_touches_to_loss: Decimal | None = None
    facts_supplied_for: int = Field(ge=0)
    segments: tuple[WinLossSegment, ...] = Field(default_factory=tuple, max_length=400)
    top_loss_reasons: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=5)
    recommendations: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=8)
    source_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=6000)
    report_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("segments", "top_loss_reasons", "recommendations", "source_digests", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("win_rate_percent", "won_value", "average_won_value", "average_touches_to_win", "average_touches_to_loss", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "WinLossReport":
        if self.won + self.lost + self.open + self.suppressed + self.disqualified != self.prospects:
            raise ValueError("every prospect is won, lost, open, suppressed, or disqualified")
        if not skip_digests(info) and self.report_digest != sealed_digest(WinLossReport, self, "report_digest"):
            raise ValueError("report_digest must commit the exact report")
        return self

    def segment(self, dimension: str, value: str) -> WinLossSegment | None:
        return next((item for item in self.segments if item.dimension == dimension and item.value == value), None)

    def by_dimension(self, dimension: str) -> list[WinLossSegment]:
        return [item for item in self.segments if item.dimension == dimension]

    def render(self) -> str:
        rate = "n/a" if self.win_rate_percent is None else f"{self.win_rate_percent}%"
        lines = [f"**Win/loss** as of {self.as_of[:10]}: {self.prospects} prospect(s), {self.won} won ({self.won_value} {self.currency}), {self.lost} lost, {self.open} open; win rate {rate}."]
        if self.top_loss_reasons:
            lines.append(f"- top loss reasons: {', '.join(self.top_loss_reasons)}")
        lines.extend(f"- {item}" for item in self.recommendations)
        return "\n".join(lines)


def _fit_band(score: int, threshold: int) -> str:
    if score < threshold:
        return f"below-{threshold}"
    low = (score // 10) * 10
    return "90-100" if low >= 90 else f"{low}-{low + 9}"


def _size_band(employees: int) -> str:
    return next(label for limit, label in _SIZE_BANDS if employees < limit)


def _stage_at_loss(state: Any) -> str:
    history = state.transition_history
    return history[-2].to_status if len(history) >= 2 else "sourced"


def build_win_loss(pipeline_plan: Mapping[str, Any] | Any, prospect_states: Sequence[Any], *, as_of: str, facts: Mapping[str, Mapping[str, Any]] | None = None, since: str | None = None) -> WinLossReport:
    """The sealed report from replayed prospects; ``facts`` (by prospect_ref) adds industry, region, and size segments the state does not carry."""

    from lightbulb.pipeline_engine_loop import PROSPECT_LIFECYCLE, PipelineEngineLoopPlan

    plan = PipelineEngineLoopPlan.model_validate(detached(pipeline_plan))
    at = timestamp(as_of, field_name="as_of")
    floor = timestamp(since, field_name="since") if since is not None else None
    bound = [PROSPECT_LIFECYCLE.bind(plan, item)[1] for item in prospect_states]
    if floor is not None:
        bound = [state for state in bound if parsed(state.transition_history[0].command.occurred_at) >= parsed(floor)]
    for state in bound:
        _require(parsed(state.transition_history[-1].command.occurred_at) <= parsed(at), "STATE_FROM_FUTURE", f"{state.scope.entity_ref} moved after {at}")
    known_facts = {str(key): dict(detached(value)) for key, value in (facts or {}).items()}
    rows: list[dict[str, Any]] = []
    for state in bound:
        ledger = state.ledger
        ref = state.scope.entity_ref
        outcome = "won" if state.status == "handed_off" else ("lost" if state.status == "lost" else ("suppressed" if state.status == "suppressed" else ("disqualified" if state.status == "disqualified" else "open")))
        row: dict[str, Any] = {"ref": ref, "outcome": outcome, "value": _money(ledger.deal_value) if outcome == "won" else Decimal("0"), "touches": int(ledger.touches), "fit_band": _fit_band(int(ledger.fit_score), plan.blueprint.icp.fit_threshold), "source": str(ledger.source_ref or "unknown"), "sequence": str(ledger.sequence_ref or "none"), "last_channel": str(ledger.last_channel or "none")}
        if outcome == "lost":
            row["stage_at_loss"] = _stage_at_loss(state)
            row["loss_reason"] = str(ledger.lost_reason or "unstated")[:80]
        fact = known_facts.get(ref) or known_facts.get(str(ledger.account_ref or ""))
        if fact:
            row["industry"] = str(fact.get("industry") or "unknown")
            row["region"] = str(fact.get("region") or "unknown")
            if fact.get("employees") is not None:
                row["size_band"] = _size_band(int(fact["employees"]))
        rows.append(row)
    decided = [row for row in rows if row["outcome"] in {"won", "lost"}]
    won = [row for row in rows if row["outcome"] == "won"]
    lost = [row for row in rows if row["outcome"] == "lost"]
    segments: list[dict[str, Any]] = []
    for dimension in SEGMENT_DIMENSIONS:
        values = sorted({str(row[dimension]) for row in rows if dimension in row})
        for value in values:
            members = [row for row in rows if row.get(dimension) == value]
            segment_won = sum(1 for row in members if row["outcome"] == "won")
            segment_lost = sum(1 for row in members if row["outcome"] == "lost")
            segments.append({"dimension": dimension, "value": value, "prospects": len(members), "won": segment_won, "lost": segment_lost, "open": sum(1 for row in members if row["outcome"] == "open"), "win_rate_percent": None if dimension in {"stage_at_loss", "loss_reason"} else _rate(segment_won, segment_won + segment_lost), "loss_share_percent": _rate(segment_lost, len(lost)) if lost else None, "won_value": str(sum((row["value"] for row in members), Decimal("0")))})
    overall = _rate(len(won), len(decided))
    reasons = Counter(row["loss_reason"] for row in lost)
    top_reasons = [reason for reason, _ in reasons.most_common(5)]
    recommendations: list[str] = []
    if overall is not None:
        weak = [item for item in segments if item["dimension"] == "fit_band" and item["win_rate_percent"] is not None and item["won"] + item["lost"] >= 3 and item["win_rate_percent"] < overall]
        if weak and all(item["value"].startswith(("below", "6", "7")) for item in weak):
            lowest = min(weak, key=lambda item: item["win_rate_percent"])
            recommendations.append(f"fit band {lowest['value']} wins {lowest['win_rate_percent']}% against {overall}% overall across {lowest['won'] + lowest['lost']} decided prospect(s); raise the fit threshold above it")
    if lost:
        reason, count = reasons.most_common(1)[0]
        if count * 100 >= len(lost) * 40:
            recommendations.append(f"'{reason}' explains {count} of {len(lost)} losses; address it before sourcing more")
        stages = Counter(row["stage_at_loss"] for row in lost)
        stage, stage_count = stages.most_common(1)[0]
        if stage_count * 100 >= len(lost) * 50:
            if stage in {"sourced", "enriched", "sequenced", "engaged"}:
                recommendations.append(f"{stage_count} of {len(lost)} losses happen at {stage}, before a reply; rework the introduce and value touches")
            elif stage in {"replied", "qualified"}:
                recommendations.append(f"{stage_count} of {len(lost)} losses happen at {stage}; tighten the qualification rubric before booking")
            else:
                recommendations.append(f"{stage_count} of {len(lost)} losses happen at {stage}; review the meeting-to-hand-off step")
    for dimension in ("source", "last_channel", "industry", "region"):
        candidates = [item for item in segments if item["dimension"] == dimension and item["win_rate_percent"] is not None and item["won"] + item["lost"] >= 3]
        if len(candidates) >= 2:
            best = max(candidates, key=lambda item: item["win_rate_percent"])
            worst = min(candidates, key=lambda item: item["win_rate_percent"])
            if best["win_rate_percent"] - worst["win_rate_percent"] >= Decimal("25"):
                recommendations.append(f"{dimension} {best['value']} wins {best['win_rate_percent']}% and {worst['value']} {worst['win_rate_percent']}%; shift sourcing toward {best['value']}")
    if not recommendations:
        recommendations.append("no segment stands out yet; keep sourcing inside the ICP and revisit with more decided prospects")
    payload = {
        "currency": plan.blueprint.currency, "as_of": at, "pipeline_plan_digest": plan.plan_digest, "since": floor,
        "prospects": len(rows), "won": len(won), "lost": len(lost), "open": sum(1 for row in rows if row["outcome"] == "open"), "suppressed": sum(1 for row in rows if row["outcome"] == "suppressed"), "disqualified": sum(1 for row in rows if row["outcome"] == "disqualified"),
        "win_rate_percent": None if overall is None else str(overall), "won_value": str(sum((row["value"] for row in won), Decimal("0"))),
        "average_won_value": None if not won else str(_money(sum((row["value"] for row in won), Decimal("0")) / len(won))),
        "average_touches_to_win": None if not won else str((Decimal(sum(row["touches"] for row in won)) / len(won)).quantize(_RATE_QUANTUM, rounding=ROUND_HALF_UP)),
        "average_touches_to_loss": None if not lost else str((Decimal(sum(row["touches"] for row in lost)) / len(lost)).quantize(_RATE_QUANTUM, rounding=ROUND_HALF_UP)),
        "facts_supplied_for": sum(1 for row in rows if "industry" in row), "segments": segments, "top_loss_reasons": top_reasons, "recommendations": recommendations[:8],
        "source_digests": [state.state_digest for state in bound],
    }
    return seal(WinLossReport, payload, "report_digest")


def verify_win_loss(value: Any) -> WinLossReport:
    return value if isinstance(value, WinLossReport) else WinLossReport.model_validate(dict(detached(value)))


WIN_LOSS_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "pipeline_win_loss",
    "golden_loop": "revenue.icp_to_qualified_pipeline@0.1.0",
    "stages": ["replay_prospects", "classify_outcomes", "segment", "recommend", "seal_report"],
    "dimensions": list(SEGMENT_DIMENSIONS),
    "required_connectors": ["lightbulb.sdk_engine_state"],
    "hard_rules": [
        "outcomes come from replayed prospect statuses; the stage at loss is the transition before the loss",
        "industry, region, and size segments exist only when the caller supplies the facts; the state never persists them",
        "every recommendation names the segment and the count behind it; nothing scores a prospect",
    ],
}

__all__ = ["SEGMENT_DIMENSIONS", "WIN_LOSS_MANIFEST", "WIN_LOSS_SCHEMA", "WinLossError", "WinLossReport", "WinLossSegment", "build_win_loss", "verify_win_loss"]
