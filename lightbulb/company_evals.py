"""Company evals: score the SDK's own recommendations against what the periods then recorded, and feed the lesson to memory.

Every decision brief forecast an outcome for approve, reject, and the
alternative and recommended one.  Once the next period closed, the company
knows what actually happened.  ``evaluate_recommendations`` lines the two
up per recommendation record: the forecast gross profit for the option that
was taken against the realised gross profit of the periods that followed,
whether the recommended direction was right, whether the operator followed
the recommendation, and the regret when they did not (realised outcome
against the forecast of the option the SDK recommended).  The scorecard is
sealed per archetype and engine and becomes memory samples, so the next
brief can say how well the last ones did.

``scenario_scorecard`` runs the standard scenarios against the golden
expectations for an archetype and reports the checks, so the simulator that
underlies every counterfactual is itself scored.  Nothing here decides or
executes anything.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, MONEY_QUANTUM, BoundedText, OpaqueRef, Sha256Digest, ShortText, StrictModel, decimal_value, detached, parsed, seal, sealed_digest, skip_digests, stable_digest, timestamp
from lightbulb.company_operating_system import PERIOD_LIFECYCLE, CompanyOperatingPlan, compile_company_operating_blueprint
from lightbulb.company_simulator import evaluate_scenario, simulate_company, standard_scenario

EVALS_SCHEMA = "lightbulb.company_recommendation_scorecard.v1"
SCENARIO_SCORECARD_SCHEMA = "lightbulb.company_scenario_scorecard.v1"
_HUNDRED = Decimal("100")
_FINE = Decimal("0.0001")
Option = Literal["approve", "reject", "alternative"]


class RecommendationRecord(StrictModel):
    """One decision the SDK briefed: the brief's digest and forecasts, what was decided, and when."""

    brief_digest: Sha256Digest
    engine: ShortText
    event: ShortText
    entity_ref: OpaqueRef
    decided_at: str
    recommendation: Option
    decided_option: Option
    horizon_periods: int = Field(ge=1, le=52)
    forecasts: dict[str, Decimal] = Field(default_factory=dict)
    forecast_revenue: dict[str, Decimal] = Field(default_factory=dict)

    @field_validator("decided_at")
    @classmethod
    def _decided(cls, value: str) -> str:
        return timestamp(value, field_name="decided_at")

    @field_validator("forecasts", "forecast_revenue", mode="before")
    @classmethod
    def _maps(cls, value: Any, info: ValidationInfo) -> dict[str, Decimal]:
        return {str(key): decimal_value(item, field_name=f"{info.field_name}.{key}", allow_negative=True) for key, item in dict(value or {}).items()}

    @model_validator(mode="after")
    def _complete(self) -> RecommendationRecord:
        if self.recommendation not in self.forecasts or self.decided_option not in self.forecasts:
            raise ValueError("the record carries a forecast for the recommended and the decided option")
        return self


def record_from_brief(brief: Mapping[str, Any] | Any, *, decided_option: str, decided_at: str) -> RecommendationRecord:
    """A record from a sealed ``DecisionBrief`` and the option the person took."""

    raw = dict(detached(brief))
    forecasts = {str(dict(detached(item))["option"]): str(dict(detached(item))["total_gross_profit"]) for item in raw.get("forecasts") or []}
    revenue = {str(dict(detached(item))["option"]): str(dict(detached(item))["total_revenue"]) for item in raw.get("forecasts") or []}
    if not forecasts:
        raise ValueError("the brief carries no forecasts; a hold brief cannot be scored")
    return RecommendationRecord(brief_digest=str(raw["brief_digest"]), engine=str(raw["engine"]), event=str(raw["event"]), entity_ref=str(raw["entity_ref"]), decided_at=decided_at, recommendation=str(raw["recommendation"]), decided_option=decided_option, horizon_periods=int(raw.get("horizon_periods", 1)), forecasts=forecasts, forecast_revenue=revenue)


LAUNCH_DECISION_OPTIONS: Mapping[str, str] = {"scale": "approve", "kill": "reject", "extend": "alternative"}


def record_from_launch_brief(brief: Mapping[str, Any] | Any, *, decided_option: str, decided_at: str) -> RecommendationRecord:
    """A sealed ``launch_board.LaunchDecisionBrief`` on the same scale as every other brief: scale->approve, kill->reject, extend->alternative."""

    raw = dict(detached(brief))
    options = [dict(detached(item)) for item in raw.get("forecasts") or []]
    mapped = {**raw, "engine": "company_launch", "event": "decide", "entity_ref": str(raw.get("launch_ref", "")), "recommendation": LAUNCH_DECISION_OPTIONS.get(str(raw.get("recommendation")), str(raw.get("recommendation"))), "forecasts": [{**item, "option": LAUNCH_DECISION_OPTIONS.get(str(item.get("option")), str(item.get("option")))} for item in options]}
    return record_from_brief(mapped, decided_option=LAUNCH_DECISION_OPTIONS.get(str(decided_option), str(decided_option)), decided_at=decided_at)


class RecommendationScore(StrictModel):
    brief_digest: Sha256Digest
    engine: ShortText
    event: ShortText
    entity_ref: OpaqueRef
    recommendation: Option
    decided_option: Option
    followed: bool
    periods_scored: int = Field(ge=0)
    forecast_gross_profit: Decimal
    realized_gross_profit: Decimal
    abs_error_percent: Decimal | None = None
    direction_right: bool | None = None
    regret: Decimal | None = None
    note: BoundedText

    @field_validator("forecast_gross_profit", "realized_gross_profit", "regret", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)

    @field_validator("abs_error_percent", mode="before")
    @classmethod
    def _pct(cls, value: Any) -> Decimal | None:
        return None if value is None else Decimal(str(value)).quantize(Decimal("0.01"))


class RecommendationScorecard(StrictModel):
    schema_id: str = Field(default=EVALS_SCHEMA, alias="schema")
    archetype: ShortText
    company_ref: OpaqueRef
    scored_at: str
    records: int = Field(ge=0)
    scored: int = Field(ge=0)
    mean_abs_error_percent: Decimal | None = None
    direction_hit_rate_percent: Decimal | None = None
    followed_rate_percent: Decimal | None = None
    override_regret_total: Decimal
    by_engine: dict[str, dict[str, str]] = Field(default_factory=dict)
    scores: tuple[RecommendationScore, ...] = Field(default_factory=tuple, max_length=500)
    plan_digest: Sha256Digest
    scorecard_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("override_regret_total", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="override_regret_total", allow_negative=True)

    @field_validator("mean_abs_error_percent", "direction_hit_rate_percent", "followed_rate_percent", mode="before")
    @classmethod
    def _pct(cls, value: Any) -> Decimal | None:
        return None if value is None else Decimal(str(value)).quantize(Decimal("0.01"))

    @field_validator("scores", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> RecommendationScorecard:
        if not skip_digests(info) and self.scorecard_digest != sealed_digest(RecommendationScorecard, self, "scorecard_digest"):
            raise ValueError("scorecard_digest must commit the exact scorecard")
        return self

    def render(self) -> str:
        lines = [f"**Recommendation scorecard** for {self.company_ref} ({self.archetype}): {self.scored} of {self.records} scored"]
        if self.scored:
            lines.append(f"- mean absolute error {self.mean_abs_error_percent}%; direction right {self.direction_hit_rate_percent}%; followed {self.followed_rate_percent}%; regret when overridden {self.override_regret_total}")
        for engine, stats in self.by_engine.items():
            lines.append(f"- {engine}: " + ", ".join(f"{key} {value}" for key, value in stats.items()))
        for score in self.scores[:10]:
            lines.append(f"- {score.event} on {score.entity_ref}: {score.note}")
        return "\n".join(lines)


def _bind_periods(plan: CompanyOperatingPlan, periods: Sequence[Mapping[str, Any] | Any]) -> list[Any]:
    out = []
    for item in periods:
        raw = dict(detached(item))
        doc = dict(raw.get("state") or raw)
        if doc.get("plan_digest") != plan.plan_digest:
            continue
        try:
            out.append(PERIOD_LIFECYCLE.State.model_validate(doc, context={PERIOD_LIFECYCLE.plan_context_key: plan}))
        except ValueError:
            continue
    return out


def evaluate_recommendations(plan: CompanyOperatingPlan | Mapping[str, Any], periods: Sequence[Mapping[str, Any] | Any], records: Sequence[RecommendationRecord | Mapping[str, Any]], *, company_ref: str, scored_at: str) -> RecommendationScorecard:
    """Score each record against the closed periods that started after the decision, over its horizon."""

    parsed_plan = CompanyOperatingPlan.model_validate(detached(plan))
    states = sorted(_bind_periods(parsed_plan, periods), key=lambda state: str(state.ledger.period_start or ""))
    stamp = timestamp(scored_at, field_name="scored_at")
    scores: list[dict[str, Any]] = []
    for item in records:
        record = item if isinstance(item, RecommendationRecord) else RecommendationRecord.model_validate(dict(detached(item)))
        following = [state for state in states if state.ledger.period_start and parsed(str(state.ledger.period_start)) >= parsed(record.decided_at) and state.ledger.outcome in ("closed", "halted")][: record.horizon_periods]
        forecast = record.forecasts[record.decided_option]
        if len(following) < record.horizon_periods:
            scores.append({"brief_digest": record.brief_digest, "engine": record.engine, "event": record.event, "entity_ref": record.entity_ref, "recommendation": record.recommendation, "decided_option": record.decided_option, "followed": record.decided_option == record.recommendation, "periods_scored": len(following), "forecast_gross_profit": str(forecast), "realized_gross_profit": "0", "note": f"{len(following)} of {record.horizon_periods} period(s) closed since the decision; not yet scorable"})
            continue
        realized = sum(((state.ledger.total_revenue - state.ledger.total_spend) for state in following), Decimal("0")).quantize(MONEY_QUANTUM)
        error = None if forecast == 0 else ((realized - forecast).copy_abs() / forecast.copy_abs() * _HUNDRED).quantize(Decimal("0.01"))
        baseline = record.forecasts.get("reject", forecast)
        direction = None
        if record.recommendation != "reject" and baseline != forecast:
            direction = (realized >= baseline) == (record.forecasts[record.recommendation] >= baseline)
        regret = None
        if record.decided_option != record.recommendation:
            regret = (record.forecasts[record.recommendation] - realized).quantize(MONEY_QUANTUM)
        note = f"forecast {forecast} for {record.decided_option}, realised {realized}" + (f" ({error}% off)" if error is not None else "") + ("; followed the recommendation" if record.decided_option == record.recommendation else f"; overrode {record.recommendation}, regret {regret}")
        scores.append({"brief_digest": record.brief_digest, "engine": record.engine, "event": record.event, "entity_ref": record.entity_ref, "recommendation": record.recommendation, "decided_option": record.decided_option, "followed": record.decided_option == record.recommendation, "periods_scored": len(following), "forecast_gross_profit": str(forecast), "realized_gross_profit": str(realized), "abs_error_percent": None if error is None else str(error), "direction_right": direction, "regret": None if regret is None else str(regret), "note": note})
    scorable = [score for score in scores if score["periods_scored"] > 0 and score["abs_error_percent"] is not None]
    errors = [Decimal(score["abs_error_percent"]) for score in scorable]
    directions = [score["direction_right"] for score in scorable if score["direction_right"] is not None]
    followed = [score["followed"] for score in scores if score["periods_scored"] > 0]
    regrets = [Decimal(score["regret"]) for score in scorable if score["regret"] is not None and Decimal(score["regret"]) > 0]
    by_engine: dict[str, dict[str, str]] = {}
    for engine in sorted({score["engine"] for score in scorable}):
        rows = [score for score in scorable if score["engine"] == engine]
        by_engine[engine] = {"scored": str(len(rows)), "mean_abs_error_percent": str((sum(Decimal(row["abs_error_percent"]) for row in rows) / len(rows)).quantize(Decimal("0.01")))}
    card = {"archetype": parsed_plan.blueprint.archetype, "company_ref": company_ref, "scored_at": stamp, "records": len(scores), "scored": len(scorable), "mean_abs_error_percent": None if not errors else str(sum(errors) / len(errors)), "direction_hit_rate_percent": None if not directions else str(Decimal(sum(1 for item in directions if item)) / len(directions) * _HUNDRED), "followed_rate_percent": None if not followed else str(Decimal(sum(1 for item in followed if item)) / len(followed) * _HUNDRED), "override_regret_total": str(sum(regrets, Decimal("0"))), "by_engine": by_engine, "scores": scores, "plan_digest": parsed_plan.plan_digest}
    return seal(RecommendationScorecard, card, "scorecard_digest")


def samples_for_memory(scorecard: RecommendationScorecard | Mapping[str, Any]) -> list[dict[str, Any]]:
    """Memory samples: one ``recommendation_abs_error_percent`` per scored decision, so briefs can cite their own track record."""

    card = scorecard if isinstance(scorecard, RecommendationScorecard) else RecommendationScorecard.model_validate(dict(detached(scorecard)))
    out = []
    for score in card.scores:
        if score.abs_error_percent is None:
            continue
        out.append({"key": f"{card.archetype}:{score.engine}:recommendation_abs_error_percent", "archetype": card.archetype, "engine": score.engine, "metric": "recommendation_abs_error_percent", "value": str(score.abs_error_percent.quantize(_FINE)), "source_engine": "company_evals", "source_ref": f"brief:{score.brief_digest[:16]}", "source_state_digest": score.brief_digest, "observed_at": card.scored_at})
    return out


# --------------------------------------------------------------------------- #
# Scoring the simulator itself
# --------------------------------------------------------------------------- #

_SCENARIO_EXPECTATIONS: dict[str, dict[str, Any]] = {
    "steady_state": {"must_not_halt": True, "min_revenue_attainment_percent": "60"},
    "aggressive_reallocation": {"max_replans": 6},
    "cash_squeeze": {"expected_halt_reason": None},
    "close_failure": {"forbidden_signals": ()},
}


class ScenarioScorecard(StrictModel):
    schema_id: str = Field(default=SCENARIO_SCORECARD_SCHEMA, alias="schema")
    archetype: ShortText
    plan_digest: Sha256Digest
    scenarios: dict[str, dict[str, Any]] = Field(default_factory=dict)
    passed: int = Field(ge=0)
    failed: int = Field(ge=0)
    scorecard_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> ScenarioScorecard:
        if not skip_digests(info) and self.scorecard_digest != sealed_digest(ScenarioScorecard, self, "scorecard_digest"):
            raise ValueError("scorecard_digest must commit the exact scorecard")
        return self


def scenario_scorecard(archetype: str, *, expectations: Mapping[str, Mapping[str, Any]] | None = None) -> ScenarioScorecard:
    """Run every standard scenario against the archetype and score it against the expectations (the defaults, or the caller's)."""

    plan = compile_company_operating_blueprint(archetype)
    table = {**_SCENARIO_EXPECTATIONS, **{str(key): dict(value) for key, value in (expectations or {}).items()}}
    results: dict[str, dict[str, Any]] = {}
    passed = failed = 0
    for name, expectation in table.items():
        result = simulate_company(plan, standard_scenario(name))
        evaluation = evaluate_scenario(result, {key: value for key, value in expectation.items() if value is not None and value != ()})
        ok = all(finding.passed for finding in evaluation.findings)
        passed += 1 if ok else 0
        failed += 0 if ok else 1
        results[name] = {"passed": ok, "checks": [{"check": finding.check, "passed": finding.passed, "detail": finding.detail} for finding in evaluation.findings], "result_digest": result.result_digest, "periods_run": result.periods_run, "halted_at_period": result.halted_at_period}
    return seal(ScenarioScorecard, {"archetype": archetype, "plan_digest": plan.plan_digest, "scenarios": results, "passed": passed, "failed": failed}, "scorecard_digest")


EVALS_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "company_evals",
    "golden_loop": "company.blueprint_to_governed_operating_cadence@0.1.0",
    "stages": ["record_decision", "wait_for_periods", "score", "feed_memory", "score_scenarios"],
    "required_connectors": ["lightbulb.sdk_engine_state"],
    "hard_rules": [
        "a recommendation is scored only against periods that closed after the decision, over the brief's own horizon",
        "regret is measured against the forecast of the option the SDK recommended, only when the person overrode it",
        "the scorecard becomes memory samples so the next brief can cite its track record; nothing here decides",
    ],
}

__all__ = ["EVALS_MANIFEST", "EVALS_SCHEMA", "LAUNCH_DECISION_OPTIONS", "SCENARIO_SCORECARD_SCHEMA", "RecommendationRecord", "RecommendationScore", "RecommendationScorecard", "ScenarioScorecard", "evaluate_recommendations", "record_from_brief", "record_from_launch_brief", "samples_for_memory", "scenario_scorecard"]
