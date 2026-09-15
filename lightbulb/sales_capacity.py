"""Sales capacity: quota, ramp, attainment, and owned pipeline per rep from the replayed prospects.

Coverage sizes the sales team from touches; nothing said who owns which
prospect, what each rep is on quota for, how far through ramp they are, or
whether the pipeline they hold covers what is left of their number.
``build_sales_capacity`` does, from the sealed plan (quota, ramp, and
start per rep, typed by the operator because a quota is a target) and the
replayed prospects only: a prospect's owner is the actor of its latest
transition, a win is a hand-off by that actor inside the window at the
deal value the chain recorded, and a rep's ramped quota is the quota
scaled by the months served against the ramp.  Verdicts are arithmetic
(ahead, on pace, behind, ramping, no activity) and every recommendation
names the rep and the number.  Nothing here reads a provider, persists
anything, or predicts a close rate.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import timedelta
from decimal import ROUND_HALF_UP, Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    MONEY_QUANTUM,
    CurrencyCode,
    OpaqueRef,
    Sha256Digest,
    ShortText,
    StrictModel,
    decimal_value,
    detached,
    iso,
    parsed,
    seal,
    sealed_digest,
    skip_digests,
    timestamp,
)

SALES_CAPACITY_PLAN_SCHEMA = "lightbulb.sales_capacity_plan.v1"
SALES_CAPACITY_SCHEMA = "lightbulb.sales_capacity.v1"
REP_VERDICTS: tuple[str, ...] = ("ahead", "on_pace", "behind", "ramping", "no_activity")
RepVerdict = Literal["ahead", "on_pace", "behind", "ramping", "no_activity"]
TeamVerdict = Literal["on_pace", "behind", "no_activity"]
OPEN_STATUSES: frozenset[str] = frozenset({"sourced", "enriched", "sequenced", "engaged", "replied", "qualified", "meeting_booked"})
_HUNDRED = Decimal("100")
_RATE_QUANTUM = Decimal("0.01")


class SalesCapacityError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise SalesCapacityError(code, message)


def _money(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


def _rate(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(_RATE_QUANTUM, rounding=ROUND_HALF_UP)


class RepQuota(StrictModel):
    rep_ref: OpaqueRef
    quota_per_period: Decimal
    ramp_months: int = Field(default=0, ge=0, le=24)
    started_at: str | None = None

    @field_validator("quota_per_period", mode="before")
    @classmethod
    def _quota(cls, value: Any) -> Decimal:
        result = decimal_value(value, field_name="quota_per_period")
        if result <= 0:
            raise ValueError("a quota is positive")
        return result

    @field_validator("started_at")
    @classmethod
    def _started(cls, value: str | None) -> str | None:
        return None if value is None else timestamp(value, field_name="started_at")


class SalesCapacityPlan(StrictModel):
    """Who is on quota for what, sealed; a quota is a target the operator sets, never a number the SDK invents."""

    schema_id: str = Field(default=SALES_CAPACITY_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    period_days: int = Field(default=30, ge=7, le=366)
    reps: tuple[RepQuota, ...] = Field(min_length=1, max_length=200)
    on_pace_percent: Decimal = Field(default=Decimal("80"), validate_default=True)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("reps", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("on_pace_percent", mode="before")
    @classmethod
    def _pace(cls, value: Any) -> Decimal:
        result = decimal_value(value, field_name="on_pace_percent")
        if result <= 0 or result > _HUNDRED:
            raise ValueError("the on-pace threshold is a percentage above 0 and up to 100")
        return result

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "SalesCapacityPlan":
        if len({rep.rep_ref for rep in self.reps}) != len(self.reps):
            raise ValueError("each rep is on quota once")
        if not skip_digests(info) and self.plan_digest != sealed_digest(SalesCapacityPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self

    def rep(self, rep_ref: str) -> RepQuota | None:
        return next((rep for rep in self.reps if rep.rep_ref == rep_ref), None)


def compile_sales_capacity_plan(company_ref: str, *, currency: str, reps: Sequence[Mapping[str, Any]], overrides: Mapping[str, Any] | None = None) -> SalesCapacityPlan:
    raw: dict[str, Any] = {"company_ref": company_ref, "currency": str(currency).upper(), "reps": [dict(detached(item)) for item in reps], **dict(overrides or {})}
    return seal(SalesCapacityPlan, raw, "plan_digest")


class RepCapacity(StrictModel):
    rep_ref: OpaqueRef
    quota_per_period: Decimal
    ramp_percent: Decimal
    ramped_quota: Decimal
    deals_won: int = Field(ge=0)
    deals_lost: int = Field(ge=0)
    won_value: Decimal
    attainment_percent: Decimal | None = None
    open_prospects: int = Field(ge=0)
    weighted_pipeline_owned: Decimal
    remaining_quota: Decimal
    pipeline_to_remaining_percent: Decimal | None = None
    verdict: RepVerdict

    @field_validator("quota_per_period", "ramp_percent", "ramped_quota", "won_value", "attainment_percent", "weighted_pipeline_owned", "remaining_quota", "pipeline_to_remaining_percent", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))


class SalesCapacity(StrictModel):
    schema_id: str = Field(default=SALES_CAPACITY_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    as_of: str
    window_start: str
    plan_digest: Sha256Digest
    pipeline_plan_digest: Sha256Digest
    reps: tuple[RepCapacity, ...] = Field(min_length=1, max_length=200)
    total_quota: Decimal
    total_ramped_quota: Decimal
    total_won: Decimal
    attainment_percent: Decimal | None = None
    weighted_pipeline_owned: Decimal
    unowned_prospects: int = Field(ge=0)
    unowned_weighted_pipeline: Decimal
    verdict: TeamVerdict
    recommendations: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=12)
    source_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=6000)
    capacity_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("reps", "recommendations", "source_digests", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("total_quota", "total_ramped_quota", "total_won", "attainment_percent", "weighted_pipeline_owned", "unowned_weighted_pipeline", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "SalesCapacity":
        if sum((rep.won_value for rep in self.reps), Decimal("0")).quantize(MONEY_QUANTUM) != self.total_won:
            raise ValueError("total_won must equal the reps")
        if not skip_digests(info) and self.capacity_digest != sealed_digest(SalesCapacity, self, "capacity_digest"):
            raise ValueError("capacity_digest must commit the exact assessment")
        return self

    def rep(self, rep_ref: str) -> RepCapacity | None:
        return next((rep for rep in self.reps if rep.rep_ref == rep_ref), None)

    def render(self) -> str:
        rate = "n/a" if self.attainment_percent is None else f"{self.attainment_percent}%"
        lines = [f"**Sales capacity {self.company_ref}** as of {self.as_of[:10]}: {self.verdict}; {self.total_won} won against {self.total_ramped_quota} ramped quota ({rate}), {self.weighted_pipeline_owned} weighted pipeline owned, {self.unowned_prospects} prospect(s) without an owner."]
        for rep in self.reps:
            lines.append(f"- {rep.rep_ref}: {rep.verdict}; won {rep.won_value} of {rep.ramped_quota} (ramp {rep.ramp_percent}%), {rep.open_prospects} open prospect(s) worth {rep.weighted_pipeline_owned} weighted")
        lines.extend(f"- {item}" for item in self.recommendations)
        return "\n".join(lines)


def _months_between(start: str, end: str) -> Decimal:
    return Decimal((parsed(end) - parsed(start)).days) / Decimal(30)


def build_sales_capacity(plan: SalesCapacityPlan | Mapping[str, Any], *, pipeline_plan: Any, prospect_states: Sequence[Any] = (), as_of: str, window_start: str | None = None) -> SalesCapacity:
    """The sealed assessment from the plan and the replayed prospects; the window defaults to the plan's period ending at ``as_of``."""

    from lightbulb.pipeline_engine_loop import PROSPECT_LIFECYCLE, PipelineEngineLoopPlan, _STAGE_PROBABILITY

    parsed_plan = plan if isinstance(plan, SalesCapacityPlan) else SalesCapacityPlan.model_validate(detached(plan))
    at = timestamp(as_of, field_name="as_of")
    start = timestamp(window_start, field_name="window_start") if window_start else iso(parsed(at) - timedelta(days=parsed_plan.period_days))
    _require(parsed(start) < parsed(at), "WINDOW_EMPTY", "the window starts before it ends")
    engine_plan = PipelineEngineLoopPlan.model_validate(detached(pipeline_plan))
    _require(engine_plan.blueprint.currency == parsed_plan.currency, "SOURCE_SCOPE_MISMATCH", f"the pipeline blueprint forecasts in {engine_plan.blueprint.currency}, not {parsed_plan.currency}")
    bound = [PROSPECT_LIFECYCLE.bind(engine_plan, item)[1] for item in prospect_states]
    for state in bound:
        _require(parsed(state.transition_history[-1].command.occurred_at) <= parsed(at), "STATE_FROM_FUTURE", f"{state.scope.entity_ref} moved after {at}")
    rows: dict[str, dict[str, Any]] = {rep.rep_ref: {"won": Decimal("0"), "deals_won": 0, "deals_lost": 0, "open": 0, "weighted": Decimal("0")} for rep in parsed_plan.reps}
    unowned = 0
    unowned_weighted = Decimal("0")
    for state in bound:
        owner = state.transition_history[-1].command.actor_ref
        row = rows.get(owner)
        if state.status == "handed_off":
            handed = next((item for item in reversed(state.transition_history) if item.command.event == "hand_off"), None)
            if handed is not None and parsed(start) <= parsed(handed.command.occurred_at) <= parsed(at):
                winner = rows.get(handed.command.actor_ref)
                if winner is not None:
                    winner["won"] += Decimal(str(state.ledger.deal_value))
                    winner["deals_won"] += 1
        elif state.status == "lost":
            if row is not None and parsed(start) <= parsed(state.transition_history[-1].command.occurred_at) <= parsed(at):
                row["deals_lost"] += 1
        elif state.status in OPEN_STATUSES:
            weight = engine_plan.blueprint.average_deal_value * _STAGE_PROBABILITY.get(state.status, Decimal("0"))
            if row is None:
                unowned += 1
                unowned_weighted += weight
            else:
                row["open"] += 1
                row["weighted"] += weight
    reps: list[dict[str, Any]] = []
    recommendations: list[str] = []
    for rep in parsed_plan.reps:
        row = rows[rep.rep_ref]
        if rep.ramp_months and rep.started_at:
            ramp = min(_HUNDRED, max(Decimal("0"), _months_between(rep.started_at, at) / Decimal(rep.ramp_months) * _HUNDRED))
        else:
            ramp = _HUNDRED
        ramped = _money(rep.quota_per_period * ramp / _HUNDRED)
        won = _money(row["won"])
        weighted = _money(row["weighted"])
        attainment = None if ramped <= 0 else _rate(won / ramped * _HUNDRED)
        remaining = _money(max(Decimal("0"), ramped - won))
        pipeline_to_remaining = None if remaining <= 0 else _rate(weighted / remaining * _HUNDRED)
        if won <= 0 and row["open"] == 0 and row["deals_lost"] == 0:
            verdict = "no_activity"
        elif attainment is not None and attainment >= _HUNDRED:
            verdict = "ahead"
        elif ramp < _HUNDRED:
            verdict = "ramping"
        elif attainment is not None and attainment >= parsed_plan.on_pace_percent:
            verdict = "on_pace"
        elif pipeline_to_remaining is not None and pipeline_to_remaining >= _HUNDRED:
            verdict = "on_pace"
        else:
            verdict = "behind"
        reps.append({"rep_ref": rep.rep_ref, "quota_per_period": str(_money(rep.quota_per_period)), "ramp_percent": str(_rate(ramp)), "ramped_quota": str(ramped), "deals_won": row["deals_won"], "deals_lost": row["deals_lost"], "won_value": str(won), "attainment_percent": None if attainment is None else str(attainment), "open_prospects": row["open"], "weighted_pipeline_owned": str(weighted), "remaining_quota": str(remaining), "pipeline_to_remaining_percent": None if pipeline_to_remaining is None else str(pipeline_to_remaining), "verdict": verdict})
        if verdict == "behind":
            recommendations.append(f"{rep.rep_ref} has {weighted} weighted pipeline against {remaining} still to win; source before the window closes")
        elif verdict == "no_activity":
            recommendations.append(f"{rep.rep_ref} owns no prospect and won nothing in the window; assign the unowned prospects or review the quota")
    total_quota = _money(sum((rep.quota_per_period for rep in parsed_plan.reps), Decimal("0")))
    total_ramped = _money(sum((Decimal(item["ramped_quota"]) for item in reps), Decimal("0")))
    total_won = _money(sum((Decimal(item["won_value"]) for item in reps), Decimal("0")))
    attainment_total = None if total_ramped <= 0 else _rate(total_won / total_ramped * _HUNDRED)
    if all(item["verdict"] == "no_activity" for item in reps):
        verdict = "no_activity"
    elif attainment_total is not None and attainment_total >= parsed_plan.on_pace_percent:
        verdict = "on_pace"
    elif sum(1 for item in reps if item["verdict"] in {"ahead", "on_pace", "ramping"}) * 2 >= len(reps):
        verdict = "on_pace"
    else:
        verdict = "behind"
    if unowned:
        recommendations.append(f"{unowned} open prospect(s) worth {_money(unowned_weighted)} weighted have no rep on quota as owner; assign them")
    if not recommendations:
        recommendations.append("every rep is ahead, on pace, or ramping; hold the plan")
    payload = {
        "company_ref": parsed_plan.company_ref, "currency": parsed_plan.currency, "as_of": at, "window_start": start, "plan_digest": parsed_plan.plan_digest, "pipeline_plan_digest": engine_plan.plan_digest,
        "reps": reps, "total_quota": str(total_quota), "total_ramped_quota": str(total_ramped), "total_won": str(total_won), "attainment_percent": None if attainment_total is None else str(attainment_total),
        "weighted_pipeline_owned": str(_money(sum((Decimal(item["weighted_pipeline_owned"]) for item in reps), Decimal("0")))), "unowned_prospects": unowned, "unowned_weighted_pipeline": str(_money(unowned_weighted)),
        "verdict": verdict, "recommendations": recommendations[:12], "source_digests": [state.state_digest for state in bound],
    }
    return seal(SalesCapacity, payload, "capacity_digest")


def verify_sales_capacity(value: Any) -> SalesCapacity:
    return value if isinstance(value, SalesCapacity) else SalesCapacity.model_validate(dict(detached(value)))


SALES_CAPACITY_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "sales_capacity",
    "golden_loop": "revenue.icp_to_qualified_pipeline@0.1.0",
    "stages": ["replay_prospects", "attribute_owners", "ramp_quotas", "measure_attainment", "seal_assessment"],
    "verdicts": list(REP_VERDICTS),
    "required_connectors": ["lightbulb.sdk_engine_state"],
    "hard_rules": [
        "a quota is a target the operator seals in the plan; the SDK never invents one",
        "a prospect's owner is the actor of its latest replayed transition; a win is a hand-off by that actor at the deal value the chain recorded",
        "ramp scales the quota by months served; nothing predicts a close rate",
        "every recommendation names the rep and the number behind it",
    ],
}

__all__ = ["OPEN_STATUSES", "REP_VERDICTS", "SALES_CAPACITY_MANIFEST", "SALES_CAPACITY_PLAN_SCHEMA", "SALES_CAPACITY_SCHEMA", "RepCapacity", "RepQuota", "SalesCapacity", "SalesCapacityError", "SalesCapacityPlan", "build_sales_capacity", "compile_sales_capacity_plan", "verify_sales_capacity"]
