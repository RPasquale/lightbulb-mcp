"""Growth bets: the experiments an agent runs to grow the company, each with a spend cap, one metric, a kill rule, and a verdict read from the record.

A goal says what must be true; a bet is one try at making it so.  Each
bet is preregistered before money moves: the hypothesis, the driver it
serves, the spend cap (the mandate's ``spend_marketing`` decides whether
the agent may commit it alone), the one metric that will judge it (a
metric the intelligence history tracks, so the reading comes from the
recorded documents and never from the agent's own report), the baseline
when it started, the target, the horizon in months, and the kill rule:
how far the metric may fall for how many windows before the bet stops.

``judge_bets`` is deterministic and reads only the history: a bet whose
metric has reached its target is ``scale``; one that breached its kill
rule is ``kill``; one past its horizon without either is ``extend`` if
the metric is moving the right way and ``kill`` if not; anything else is
``running``.  A verdict is a proposal: the owner or the mandate decides
what follows.  Nothing here spends or records.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import ROUND_HALF_UP, Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, CurrencyCode, OpaqueRef, Sha256Digest, ShortText, StrictModel, decimal_value, detached, parsed, seal, sealed_digest, skip_digests, timestamp
from lightbulb.intelligence_history import METRICS

GROWTH_BET_SCHEMA = "lightbulb.growth_bet.v1"
BET_VERDICTS_SCHEMA = "lightbulb.growth_bet_verdicts.v1"
GROWTH_BETS_MANIFEST: dict[str, Any] = {"engine": "growth_bets", "kind": "intelligence_document", "reads": ("intelligence_history", "growth_goal"), "writes": ()}
Verdict = Literal["running", "scale", "kill", "extend"]
_CENT = Decimal("0.01")


class GrowthBetError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise GrowthBetError(code, message)


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


class GrowthBet(StrictModel):
    schema_id: str = Field(default=GROWTH_BET_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    bet_ref: OpaqueRef
    goal_ref: OpaqueRef | None = None
    driver: ShortText
    hypothesis: ShortText
    metric: ShortText
    baseline: Decimal
    target: Decimal
    spend_cap: Decimal
    starts_at: str
    horizon_months: int = Field(ge=1, le=12)
    kill_drop_percent: Decimal
    kill_after_windows: int = Field(ge=1, le=12)
    bet_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("baseline", "target", "spend_cap", "kill_drop_percent", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name), allow_negative=str(info.field_name) in ("baseline", "target"))

    @field_validator("starts_at")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="starts_at")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "GrowthBet":
        if self.metric not in METRICS:
            raise ValueError(f"{self.metric} is not a metric the history tracks; the metrics are {', '.join(METRICS)}")
        good = METRICS[self.metric][3]
        if good == "flat":
            raise ValueError(f"{self.metric} has no good direction, so no bet can be judged on it")
        if (self.target > self.baseline) != (good == "up"):
            raise ValueError(f"the target must move {self.metric} {good}, its good direction")
        if not (Decimal("0") < self.kill_drop_percent <= Decimal("100")):
            raise ValueError("the kill rule is a drop above 0% and at most 100%")
        if not skip_digests(info) and self.bet_digest != sealed_digest(GrowthBet, self, "bet_digest"):
            raise ValueError("bet_digest must commit the exact bet")
        return self

    @property
    def good_direction(self) -> str:
        return METRICS[self.metric][3]


def place_bet(*, company_ref: str, currency: str, bet_ref: str, driver: str, hypothesis: str, metric: str, baseline: Any, target: Any, spend_cap: Any, starts_at: str, horizon_months: int = 3, kill_drop_percent: Any = "10", kill_after_windows: int = 2, goal_ref: str | None = None) -> GrowthBet:
    """The sealed preregistration of one bet; nothing is spent by placing it."""

    return seal(GrowthBet, {"company_ref": company_ref, "currency": str(currency).upper(), "bet_ref": bet_ref, "goal_ref": goal_ref, "driver": driver[:300], "hypothesis": hypothesis[:300], "metric": metric, "baseline": str(decimal_value(baseline, field_name="baseline", allow_negative=True)), "target": str(decimal_value(target, field_name="target", allow_negative=True)), "spend_cap": str(decimal_value(spend_cap, field_name="spend_cap")), "starts_at": starts_at, "horizon_months": int(horizon_months), "kill_drop_percent": str(decimal_value(kill_drop_percent, field_name="kill_drop_percent")), "kill_after_windows": int(kill_after_windows)}, "bet_digest")


class BetVerdict(StrictModel):
    bet_ref: OpaqueRef
    bet_digest: Sha256Digest
    metric: ShortText
    baseline: Decimal
    target: Decimal
    latest: Decimal | None = None
    windows_observed: int = Field(ge=0)
    months_elapsed: int = Field(ge=0)
    verdict: Verdict
    reason: ShortText

    @field_validator("baseline", "target", "latest", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class BetVerdicts(StrictModel):
    schema_id: str = Field(default=BET_VERDICTS_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    as_of: str
    history_digest: Sha256Digest | None = None
    verdicts: tuple[BetVerdict, ...] = Field(default_factory=tuple, max_length=100)
    by_verdict: dict[str, int] = Field(default_factory=dict)
    verdict: ShortText
    verdicts_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("verdicts", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "BetVerdicts":
        if sum(self.by_verdict.values()) != len(self.verdicts):
            raise ValueError("by_verdict counts the verdicts")
        if not skip_digests(info) and self.verdicts_digest != sealed_digest(BetVerdicts, self, "verdicts_digest"):
            raise ValueError("verdicts_digest must commit the exact verdicts")
        return self

    def render(self) -> str:
        lines = [f"**Growth bets** ({self.company_ref}, {self.as_of[:10]}): {self.verdict}"]
        lines.extend(f"- {row.bet_ref}: {row.verdict}; {row.reason}" for row in self.verdicts)
        return "\n".join(lines)


def judge_bets(bets: Sequence[GrowthBet | Mapping[str, Any]], *, history: Mapping[str, Any] | None, as_of: str) -> BetVerdicts:
    """Every bet judged from the history's series alone: scale, kill, extend or running, with the reason."""

    at = timestamp(as_of, field_name="as_of")
    parsed_bets = [bet if isinstance(bet, GrowthBet) else GrowthBet.model_validate({key: value for key, value in dict(detached(bet)).items() if key not in {"summary", "provider_effect_executed", "version"}}) for bet in bets]
    _require(len({bet.bet_ref for bet in parsed_bets}) == len(parsed_bets), "BET_REF_DUPLICATE", "each bet has its own ref")
    series: dict[str, dict[str, Any]] = {}
    history_digest = None
    if history is not None:
        from lightbulb.intelligence_history import verify_intelligence_history

        parsed_history = verify_intelligence_history({key: value for key, value in dict(detached(history)).items() if key not in {"summary", "provider_effect_executed", "gaps", "documents_built"}})
        history_digest = parsed_history.history_digest
        refs = list(parsed_history.window_refs)
        for row in parsed_history.series:
            series[row.metric] = {"values": [Decimal(str(value)) for value in row.values], "refs": refs[-len(row.values):] if row.values else []}
    rows: list[dict[str, Any]] = []
    for bet in parsed_bets:
        _require(bet.company_ref == (parsed_bets[0].company_ref), "SOURCE_SCOPE_MISMATCH", "the bets name different companies")
        start, now = parsed(bet.starts_at), parsed(at)
        elapsed = max(0, (now.year - start.year) * 12 + now.month - start.month)
        found = series.get(bet.metric, {"values": [], "refs": []})
        # only windows that closed after the bet started count for it
        observed = [value for value, ref in zip(found["values"], found["refs"]) if ref.split(":")[-1] > bet.starts_at[:10]] if found["refs"] else []
        latest = observed[-1] if observed else None
        up = bet.good_direction == "up"
        row = {"bet_ref": bet.bet_ref, "bet_digest": bet.bet_digest, "metric": bet.metric, "baseline": str(bet.baseline), "target": str(bet.target), "latest": None if latest is None else str(latest), "windows_observed": len(observed), "months_elapsed": elapsed}
        if latest is None:
            rows.append({**row, "verdict": "running", "reason": "no window has closed since the bet started"})
            continue
        reached = latest >= bet.target if up else latest <= bet.target
        breached = 0
        for value in reversed(observed):
            drop = ((bet.baseline - value) if up else (value - bet.baseline)) * Decimal(100) / bet.baseline.copy_abs() if bet.baseline else Decimal("0")
            if drop >= bet.kill_drop_percent:
                breached += 1
            else:
                break
        improving = len(observed) >= 2 and ((observed[-1] > observed[-2]) if up else (observed[-1] < observed[-2]))
        if reached:
            verdict, reason = "scale", f"{bet.metric} reached {latest} against the {bet.target} target after {len(observed)} window(s)"
        elif breached >= bet.kill_after_windows:
            verdict, reason = "kill", f"{bet.metric} has been {bet.kill_drop_percent}% or more the wrong way from the {bet.baseline} baseline for {breached} window(s); the kill rule fires"
        elif elapsed >= bet.horizon_months:
            verdict, reason = ("extend", f"the horizon has passed without reaching {bet.target}, but {bet.metric} is moving the right way ({latest})") if improving else ("kill", f"the horizon has passed, {bet.metric} is at {latest} and not moving the right way")
        else:
            verdict, reason = "running", f"{len(observed)} window(s) in, {bet.metric} at {latest} against {bet.target}; {bet.horizon_months - elapsed} month(s) left"
        rows.append({**row, "verdict": verdict, "reason": reason[:300]})
    by_verdict: dict[str, int] = {}
    for row in rows:
        by_verdict[row["verdict"]] = by_verdict.get(row["verdict"], 0) + 1
    summary = ", ".join(f"{count} {name}" for name, count in sorted(by_verdict.items())) or "no bets placed"
    return seal(BetVerdicts, {"company_ref": parsed_bets[0].company_ref if parsed_bets else "none", "as_of": at, "history_digest": history_digest, "verdicts": [{key: value for key, value in row.items() if value is not None} for row in rows], "by_verdict": by_verdict, "verdict": (f"{len(rows)} bet(s): {summary}; verdicts are proposals, the owner or the mandate decides what follows")[:300]}, "verdicts_digest")


def verify_growth_bet(value: Any) -> GrowthBet:
    return value if isinstance(value, GrowthBet) else GrowthBet.model_validate({key: item for key, item in dict(detached(value)).items() if key not in {"summary", "provider_effect_executed", "version"}})


__all__ = ["BET_VERDICTS_SCHEMA", "GROWTH_BETS_MANIFEST", "GROWTH_BET_SCHEMA", "BetVerdict", "BetVerdicts", "GrowthBet", "GrowthBetError", "judge_bets", "place_bet", "verify_growth_bet"]
