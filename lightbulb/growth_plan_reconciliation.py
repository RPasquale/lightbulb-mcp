"""Objective versus plan: does the operating plan's revenue, at the margin, deliver the contribution the growth objective committed to, and does the revenue model deliver the plan?

The growth objective is a sealed contribution commitment per period, the
operating plan is a typed revenue and spend line per period, and the
revenue model is what sales and marketing are actually holding by month.
Nothing reconciled the three.  ``build_objective_plan_reconciliation``
does, from the sealed objective, the replayed plan, and the sealed model:

* each plan period's revenue line is turned into implied contribution at
  the plan's sealed margin and compared with the objective's target scaled
  to the period's length;
* the revenue model's months are pro-rated by day onto each period and
  compared with the plan's revenue line inside the plan's tolerance;
* the verdict names which side is short, and ``reforecast_lines`` produces
  the operating plan's reforecast lines for the periods still ahead with
  the revenue lines lifted to what the objective needs, spend untouched.

The reforecast itself stays a lifecycle transition the operating plan
guards (a reviewed breach first, replan authority when spend rises).
Nothing here reads a provider, persists anything, or predicts a growth
rate: the reconciliation computes the consequence of the assumptions the
plan names.
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
    parsed,
    seal,
    sealed_digest,
    skip_digests,
    timestamp,
)

RECONCILIATION_PLAN_SCHEMA = "lightbulb.objective_plan_reconciliation_plan.v1"
RECONCILIATION_SCHEMA = "lightbulb.objective_plan_reconciliation.v1"
RECONCILIATION_VERDICTS: tuple[str, ...] = ("aligned", "plan_below_objective", "model_below_plan", "plan_below_objective_and_model_below_plan", "no_periods_ahead")
ReconciliationVerdict = Literal["aligned", "plan_below_objective", "model_below_plan", "plan_below_objective_and_model_below_plan", "no_periods_ahead"]
PeriodStatus = Literal["covers", "short"]
ModelStatus = Literal["within_tolerance", "model_below_plan", "model_above_plan", "no_model"]
_HUNDRED = Decimal("100")
_RATE_QUANTUM = Decimal("0.01")


class ReconciliationError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise ReconciliationError(code, message)


def _money(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


def _rate(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(_RATE_QUANTUM, rounding=ROUND_HALF_UP)


# --------------------------------------------------------------------------- #
# Plan
# --------------------------------------------------------------------------- #


class ReconciliationPlan(StrictModel):
    """The margin that turns plan revenue into contribution and the tolerance the model is held to, sealed."""

    schema_id: str = Field(default=RECONCILIATION_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    contribution_margin_percent: Decimal = Field(default=Decimal("60"), validate_default=True)
    tolerance_percent: Decimal = Field(default=Decimal("5"), validate_default=True)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("contribution_margin_percent", mode="before")
    @classmethod
    def _margin(cls, value: Any) -> Decimal:
        result = decimal_value(value, field_name="contribution_margin_percent")
        if result <= 0 or result > _HUNDRED:
            raise ValueError("the contribution margin is a percentage above 0 and up to 100")
        return result

    @field_validator("tolerance_percent", mode="before")
    @classmethod
    def _tolerance(cls, value: Any) -> Decimal:
        result = decimal_value(value, field_name="tolerance_percent")
        if result > _HUNDRED:
            raise ValueError("the tolerance is a percentage up to 100")
        return result

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "ReconciliationPlan":
        if not skip_digests(info) and self.plan_digest != sealed_digest(ReconciliationPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self


def compile_reconciliation_plan(company_ref: str, *, currency: str, overrides: Mapping[str, Any] | None = None) -> ReconciliationPlan:
    raw: dict[str, Any] = {"company_ref": company_ref, "currency": str(currency).upper(), **dict(overrides or {})}
    return seal(ReconciliationPlan, raw, "plan_digest")


# --------------------------------------------------------------------------- #
# Reconciliation
# --------------------------------------------------------------------------- #


class PeriodReconciliation(StrictModel):
    period_ref: OpaqueRef
    period_start: str
    period_end: str
    period_days: int = Field(ge=1, le=366)
    ahead: bool
    plan_revenue: Decimal
    plan_spend: Decimal
    implied_contribution: Decimal
    objective_contribution: Decimal
    contribution_gap: Decimal
    required_revenue: Decimal
    revenue_shortfall: Decimal
    status: PeriodStatus
    model_revenue: Decimal | None = None
    model_variance: Decimal | None = None
    model_variance_percent: Decimal | None = None
    model_status: ModelStatus

    @field_validator("plan_revenue", "plan_spend", "implied_contribution", "objective_contribution", "contribution_gap", "required_revenue", "revenue_shortfall", "model_revenue", "model_variance", "model_variance_percent", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class ObjectivePlanReconciliation(StrictModel):
    schema_id: str = Field(default=RECONCILIATION_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    as_of: str
    plan_digest: Sha256Digest
    objective_ref: ShortText
    objective_digest: Sha256Digest
    objective_target_per_period: Decimal
    objective_period_days: int = Field(ge=1, le=366)
    operating_plan_ref: OpaqueRef
    operating_plan_digest: Sha256Digest
    forecast_version: int = Field(ge=1)
    revenue_model_digest: Sha256Digest | None = None
    assessment_digest: Sha256Digest | None = None
    assessment_verdict: ShortText | None = None
    assessment_remaining_gap_per_period: Decimal | None = None
    periods: tuple[PeriodReconciliation, ...] = Field(min_length=1, max_length=24)
    periods_ahead: int = Field(ge=0)
    periods_short: int = Field(ge=0)
    periods_model_below_plan: int = Field(ge=0)
    total_revenue_shortfall_ahead: Decimal
    verdict: ReconciliationVerdict
    assumptions: dict[str, str] = Field(default_factory=dict)
    source_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=64)
    reconciliation_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("periods", "source_digests", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("objective_target_per_period", "total_revenue_shortfall_ahead", "assessment_remaining_gap_per_period", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "ObjectivePlanReconciliation":
        if self.periods_short > self.periods_ahead or self.periods_model_below_plan > self.periods_ahead:
            raise ValueError("short periods are counted among the periods ahead")
        if sum((item.revenue_shortfall for item in self.periods if item.ahead), Decimal("0")).quantize(MONEY_QUANTUM) != self.total_revenue_shortfall_ahead:
            raise ValueError("total_revenue_shortfall_ahead must equal the periods ahead")
        if not skip_digests(info) and self.reconciliation_digest != sealed_digest(ObjectivePlanReconciliation, self, "reconciliation_digest"):
            raise ValueError("reconciliation_digest must commit the exact reconciliation")
        return self

    def period(self, ref: str) -> PeriodReconciliation | None:
        return next((item for item in self.periods if item.period_ref == ref), None)

    def render(self) -> str:
        lines = [f"**Objective vs plan {self.company_ref}** as of {self.as_of[:10]}: {self.verdict}; objective {self.objective_ref} needs {self.objective_target_per_period} contribution per {self.objective_period_days} days; {self.periods_short} of {self.periods_ahead} period(s) ahead fall short by {self.total_revenue_shortfall_ahead} {self.currency} of revenue in total."]
        for item in self.periods:
            model = "no model" if item.model_revenue is None else f"model {item.model_revenue} ({item.model_status})"
            lines.append(f"- {item.period_ref}{' (ahead)' if item.ahead else ''}: plan revenue {item.plan_revenue} -> contribution {item.implied_contribution} against {item.objective_contribution} needed ({item.status}); {model}")
        return "\n".join(lines)


def _overlap_days(start: str, end: str, other_start: str, other_end: str) -> int:
    latest_start = max(parsed(start), parsed(other_start))
    earliest_end = min(parsed(end), parsed(other_end))
    return max(0, (earliest_end - latest_start).days)


def _model_revenue_for(model: Any, start: str, end: str) -> Decimal:
    total = Decimal("0")
    for month in model.months:
        month_start = parsed(month.starts_at)
        next_month = (month_start.replace(day=1) + timedelta(days=32)).replace(day=1)
        month_days = (next_month - month_start).days
        overlap = _overlap_days(start, end, month.starts_at, next_month.strftime("%Y-%m-%dT%H:%M:%SZ"))
        if overlap:
            total += month.total * Decimal(overlap) / Decimal(month_days)
    return _money(total)


def build_objective_plan_reconciliation(plan: ReconciliationPlan | Mapping[str, Any], *, objective: Mapping[str, Any] | Any, operating_plan_state: tuple[Any, Any], revenue_model: Mapping[str, Any] | Any | None = None, assessment: Mapping[str, Any] | Any | None = None, as_of: str) -> ObjectivePlanReconciliation:
    """The sealed reconciliation of one growth objective, one replayed operating plan, and optionally the sealed revenue model and objective assessment."""

    from lightbulb.growth_objectives import GrowthObjective, ObjectiveAssessment
    from lightbulb.operating_plan import OPERATING_PLAN_LIFECYCLE

    parsed_plan = plan if isinstance(plan, ReconciliationPlan) else ReconciliationPlan.model_validate(detached(plan))
    at = timestamp(as_of, field_name="as_of")
    parsed_objective = objective if isinstance(objective, GrowthObjective) else GrowthObjective.model_validate(dict(detached(objective)))
    _require(parsed_objective.currency == parsed_plan.currency, "OBJECTIVE_SCOPE_MISMATCH", f"the objective is in {parsed_objective.currency}, not {parsed_plan.currency}")
    _require(parsed_objective.metric == "contribution_profit", "OBJECTIVE_METRIC_UNSUPPORTED", "only contribution profit objectives reconcile with a revenue plan")
    policy, state = OPERATING_PLAN_LIFECYCLE.bind(*operating_plan_state)
    _require(policy.company_ref == parsed_plan.company_ref and policy.currency == parsed_plan.currency, "SOURCE_SCOPE_MISMATCH", "the operating plan names another company or currency")
    model = None
    if revenue_model is not None:
        from lightbulb.growth_revenue_model import verify_revenue_model

        model = verify_revenue_model(revenue_model)
        _require(model.company_ref == parsed_plan.company_ref and model.currency == parsed_plan.currency, "SOURCE_SCOPE_MISMATCH", "the revenue model names another company or currency")
    parsed_assessment = None
    if assessment is not None:
        parsed_assessment = assessment if isinstance(assessment, ObjectiveAssessment) else ObjectiveAssessment.model_validate(dict(detached(assessment)))
        _require(parsed_assessment.objective_digest == parsed_objective.objective_digest, "ASSESSMENT_MISMATCH", "the assessment judges another objective")
    margin = parsed_plan.contribution_margin_percent / _HUNDRED
    lines = state.ledger.forecast or state.ledger.plan_of_record
    periods: list[dict[str, Any]] = []
    for period in policy.periods:
        days = max(1, (parsed(period.period_end) - parsed(period.period_start)).days)
        ahead = parsed(period.period_end) > parsed(at)
        revenue = _money(sum((line.amount for line in lines if line.period_ref == period.period_ref and line.kind == "revenue"), Decimal("0")))
        spend = _money(sum((line.amount for line in lines if line.period_ref == period.period_ref and line.kind == "spend"), Decimal("0")))
        implied = _money(revenue * margin)
        needed = _money(parsed_objective.target_per_period * Decimal(days) / Decimal(parsed_objective.period_days))
        gap = _money(max(Decimal("0"), needed - implied))
        required = _money(needed / margin)
        shortfall = _money(max(Decimal("0"), required - revenue))
        row: dict[str, Any] = {
            "period_ref": period.period_ref, "period_start": period.period_start, "period_end": period.period_end, "period_days": days, "ahead": ahead,
            "plan_revenue": str(revenue), "plan_spend": str(spend), "implied_contribution": str(implied), "objective_contribution": str(needed), "contribution_gap": str(gap),
            "required_revenue": str(required), "revenue_shortfall": str(shortfall), "status": "short" if gap > 0 else "covers", "model_status": "no_model",
        }
        if model is not None:
            model_revenue = _model_revenue_for(model, period.period_start, period.period_end)
            variance = _money(model_revenue - revenue)
            percent = None if revenue == 0 else _rate(variance / revenue * _HUNDRED)
            if percent is None:
                status = "within_tolerance" if variance == 0 else ("model_above_plan" if variance > 0 else "model_below_plan")
            elif abs(percent) <= parsed_plan.tolerance_percent:
                status = "within_tolerance"
            else:
                status = "model_above_plan" if variance > 0 else "model_below_plan"
            row.update({"model_revenue": str(model_revenue), "model_variance": str(variance), "model_variance_percent": None if percent is None else str(percent), "model_status": status})
        periods.append(row)
    ahead_rows = [row for row in periods if row["ahead"]]
    short = [row for row in ahead_rows if row["status"] == "short"]
    below = [row for row in ahead_rows if row["model_status"] == "model_below_plan"]
    if not ahead_rows:
        verdict = "no_periods_ahead"
    elif short and below:
        verdict = "plan_below_objective_and_model_below_plan"
    elif short:
        verdict = "plan_below_objective"
    elif below:
        verdict = "model_below_plan"
    else:
        verdict = "aligned"
    sources = [parsed_objective.objective_digest, state.state_digest, policy.plan_digest]
    if model is not None:
        sources.append(model.model_digest)
    if parsed_assessment is not None:
        sources.append(parsed_assessment.assessment_digest)
    payload = {
        "company_ref": parsed_plan.company_ref, "currency": parsed_plan.currency, "as_of": at, "plan_digest": parsed_plan.plan_digest,
        "objective_ref": parsed_objective.objective_ref, "objective_digest": parsed_objective.objective_digest, "objective_target_per_period": str(_money(parsed_objective.target_per_period)), "objective_period_days": parsed_objective.period_days,
        "operating_plan_ref": state.scope.entity_ref, "operating_plan_digest": state.state_digest, "forecast_version": state.ledger.forecast_version,
        "revenue_model_digest": None if model is None else model.model_digest,
        "assessment_digest": None if parsed_assessment is None else parsed_assessment.assessment_digest, "assessment_verdict": None if parsed_assessment is None else parsed_assessment.verdict,
        "assessment_remaining_gap_per_period": None if parsed_assessment is None else str(_money(parsed_assessment.remaining_gap_per_period)),
        "periods": periods, "periods_ahead": len(ahead_rows), "periods_short": len(short), "periods_model_below_plan": len(below),
        "total_revenue_shortfall_ahead": str(_money(sum((Decimal(row["revenue_shortfall"]) for row in ahead_rows), Decimal("0")))), "verdict": verdict,
        "assumptions": {"contribution_margin_percent": str(parsed_plan.contribution_margin_percent), "tolerance_percent": str(parsed_plan.tolerance_percent)},
        "source_digests": sources,
    }
    return seal(ObjectivePlanReconciliation, payload, "reconciliation_digest")


def verify_reconciliation(value: Any) -> ObjectivePlanReconciliation:
    return value if isinstance(value, ObjectivePlanReconciliation) else ObjectivePlanReconciliation.model_validate(dict(detached(value)))


def reforecast_lines(reconciliation: ObjectivePlanReconciliation | Mapping[str, Any], operating_plan_state: tuple[Any, Any]) -> list[dict[str, Any]]:
    """The operating plan's lines for the periods ahead with revenue lifted to what the objective needs and spend untouched."""

    from lightbulb.operating_plan import OPERATING_PLAN_LIFECYCLE

    verified = verify_reconciliation(reconciliation)
    policy, state = OPERATING_PLAN_LIFECYCLE.bind(*operating_plan_state)
    _require(state.state_digest == verified.operating_plan_digest, "PLAN_MOVED", "the operating plan has changed since the reconciliation; rebuild it")
    _require(verified.periods_ahead > 0, "NO_PERIODS_AHEAD", "every period has ended; nothing to reforecast")
    lines = state.ledger.forecast or state.ledger.plan_of_record
    result: list[dict[str, Any]] = []
    for period in verified.periods:
        if not period.ahead:
            continue
        current = [line for line in lines if line.period_ref == period.period_ref]
        revenue_lines = [line for line in current if line.kind == "revenue"]
        result.extend(line.to_dict() for line in current if line.kind == "spend")
        if period.status != "short":
            result.extend(line.to_dict() for line in revenue_lines)
            continue
        required = period.required_revenue
        if not revenue_lines:
            result.append({"period_ref": period.period_ref, "kind": "revenue", "ref": policy.revenue_engines[0], "amount": str(required)})
            continue
        factor = required / period.plan_revenue if period.plan_revenue > 0 else None
        lifted = []
        for line in revenue_lines:
            amount = _money(line.amount * factor) if factor is not None else _money(required / len(revenue_lines))
            lifted.append({"period_ref": line.period_ref, "kind": "revenue", "ref": line.ref, "amount": amount})
        remainder = _money(required - sum((item["amount"] for item in lifted), Decimal("0")))
        lifted[-1]["amount"] = _money(lifted[-1]["amount"] + remainder)
        result.extend({**item, "amount": str(item["amount"])} for item in lifted)
    return result


def reconciliation_reforecast_receipt(reconciliation: ObjectivePlanReconciliation | Mapping[str, Any], operating_plan_state: tuple[Any, Any], *, authorization: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """The operating plan's reforecast receipt for the lifted lines, bound to the sealed reconciliation."""

    from lightbulb.operating_plan import reforecast_receipt

    verified = verify_reconciliation(reconciliation)
    receipt = reforecast_receipt(reforecast_lines(verified, operating_plan_state), authorization=authorization)
    receipt["evidence_refs"] = [*receipt["evidence_refs"], f"reconciliation:{verified.reconciliation_digest[:16]}"]
    return receipt


RECONCILIATION_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "growth_plan_reconciliation",
    "golden_loop": "planning.operating_plan_to_reforecast@0.1.0",
    "stages": ["verify_objective", "replay_operating_plan", "verify_revenue_model", "reconcile_periods", "seal_reconciliation"],
    "verdicts": list(RECONCILIATION_VERDICTS),
    "required_connectors": ["lightbulb.sdk_engine_state"],
    "hard_rules": [
        "the objective's target is scaled to each period's length; nothing retypes the commitment",
        "plan revenue becomes contribution only at the plan's sealed margin, echoed in the reconciliation",
        "the revenue model is pro-rated by day onto the plan's periods and held to the sealed tolerance",
        "the reforecast stays a guarded operating plan transition: a reviewed breach first, replan authority when spend rises",
    ],
}

__all__ = ["RECONCILIATION_MANIFEST", "RECONCILIATION_PLAN_SCHEMA", "RECONCILIATION_SCHEMA", "RECONCILIATION_VERDICTS", "ObjectivePlanReconciliation", "PeriodReconciliation", "ReconciliationError", "ReconciliationPlan", "build_objective_plan_reconciliation", "compile_reconciliation_plan", "reconciliation_reforecast_receipt", "reforecast_lines", "verify_reconciliation"]
