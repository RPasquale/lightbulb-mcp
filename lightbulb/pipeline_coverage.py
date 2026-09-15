"""Pipeline coverage: does the pipeline sales is holding cover the revenue the plan needs next period, and if not, how many heads close the gap?

The operating plan types a revenue line per period and the pipeline engine
forecasts what its prospects are worth, but nothing put the two side by
side.  ``build_pipeline_coverage`` does, from replayed states and sealed
documents only:

* the target is the operating plan's forecast revenue for the period, the
  revenue model's month, or a typed amount, and the assessment says which;
* the pipeline is the sealed forecast of the persisted prospects: the
  weighted value, the open (unweighted) value, and the hand-offs;
* coverage is weighted pipeline over the sales-sourced share of the target;
  the plan's coverage multiple is checked against the open pipeline;
* the gap is turned into prospects at the observed meeting rate (else the
  blueprint's target) and the plan's meeting-to-hand-off assumption, into
  touches at the blueprint's sequence length, and into heads at the plan's
  touches per head per month.

``coverage_headcount_request`` hands the hiring chain a requisition for
exactly the additional heads, bound to the sealed assessment.  Nothing here
reads a provider, persists anything, or predicts a win rate: every
conversion assumption is sealed in the plan and echoed in the assessment.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
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
    stable_digest,
    timestamp,
)

PIPELINE_COVERAGE_PLAN_SCHEMA = "lightbulb.pipeline_coverage_plan.v1"
PIPELINE_COVERAGE_SCHEMA = "lightbulb.pipeline_coverage.v1"
COVERAGE_VERDICTS: tuple[str, ...] = ("covered", "thin", "uncovered")
TARGET_BASES: tuple[str, ...] = ("operating_plan", "revenue_model", "typed")
OPEN_PROSPECT_STATUSES: frozenset[str] = frozenset({"sourced", "enriched", "sequenced", "engaged", "replied", "qualified", "meeting_booked"})
CoverageVerdict = Literal["covered", "thin", "uncovered"]
TargetBasis = Literal["operating_plan", "revenue_model", "typed"]
_HUNDRED = Decimal("100")
_RATE_QUANTUM = Decimal("0.01")


class PipelineCoverageError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise PipelineCoverageError(code, message)


def _money(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


def _rate(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(_RATE_QUANTUM, rounding=ROUND_HALF_UP)


# --------------------------------------------------------------------------- #
# Plan
# --------------------------------------------------------------------------- #


class PipelineCoveragePlan(StrictModel):
    """The conversion assumptions coverage computes with, sealed so every reader sees the same ones."""

    schema_id: str = Field(default=PIPELINE_COVERAGE_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    coverage_multiple: Decimal = Field(default=Decimal("3"), validate_default=True)
    sales_sourced_percent: Decimal = Field(default=Decimal("100"), validate_default=True)
    meeting_to_handoff_percent: Decimal = Field(default=Decimal("50"), validate_default=True)
    touches_per_head_per_month: int = Field(default=400, ge=1, le=100000)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("coverage_multiple", "sales_sourced_percent", "meeting_to_handoff_percent", mode="before")
    @classmethod
    def _positive(cls, value: Any, info: ValidationInfo) -> Decimal:
        result = decimal_value(value, field_name=str(info.field_name))
        if result <= 0:
            raise ValueError(f"{info.field_name} is positive")
        if info.field_name != "coverage_multiple" and result > _HUNDRED:
            raise ValueError(f"{info.field_name} is a percentage up to 100")
        return result

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "PipelineCoveragePlan":
        if not skip_digests(info) and self.plan_digest != sealed_digest(PipelineCoveragePlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self


def compile_pipeline_coverage_plan(company_ref: str, *, currency: str, overrides: Mapping[str, Any] | None = None) -> PipelineCoveragePlan:
    raw: dict[str, Any] = {"company_ref": company_ref, "currency": str(currency).upper(), **dict(overrides or {})}
    return seal(PipelineCoveragePlan, raw, "plan_digest")


# --------------------------------------------------------------------------- #
# Assessment
# --------------------------------------------------------------------------- #


class PipelineCoverage(StrictModel):
    schema_id: str = Field(default=PIPELINE_COVERAGE_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    as_of: str
    plan_digest: Sha256Digest
    period_ref: ShortText
    period_days: int = Field(ge=1, le=366)
    target_basis: TargetBasis
    target_digest: Sha256Digest | None = None
    target_revenue: Decimal
    sales_sourced_target: Decimal
    prospects: int = Field(ge=0)
    open_prospects: int = Field(ge=0)
    weighted_pipeline: Decimal
    open_pipeline: Decimal
    handed_off_value: Decimal
    coverage_ratio: Decimal | None = None
    open_coverage_ratio: Decimal | None = None
    required_open_pipeline: Decimal
    pipeline_gap: Decimal
    verdict: CoverageVerdict
    meeting_rate_percent: Decimal
    meeting_rate_basis: Literal["observed", "blueprint_target"]
    expected_value_per_prospect: Decimal
    prospects_needed: int = Field(ge=0)
    touches_per_prospect: int = Field(ge=1)
    touches_needed: int = Field(ge=0)
    heads_needed: int = Field(ge=0)
    current_sales_heads: int = Field(ge=0)
    additional_heads: int = Field(ge=0)
    assumptions: dict[str, str] = Field(default_factory=dict)
    pipeline_forecast_digest: Sha256Digest
    recommendations: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=8)
    coverage_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("recommendations", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("target_revenue", "sales_sourced_target", "weighted_pipeline", "open_pipeline", "handed_off_value", "required_open_pipeline", "pipeline_gap", "expected_value_per_prospect", "meeting_rate_percent", "coverage_ratio", "open_coverage_ratio", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "PipelineCoverage":
        if self.additional_heads > self.heads_needed:
            raise ValueError("additional heads never exceed the heads needed")
        if not skip_digests(info) and self.coverage_digest != sealed_digest(PipelineCoverage, self, "coverage_digest"):
            raise ValueError("coverage_digest must commit the exact assessment")
        return self

    def render(self) -> str:
        ratio = "n/a" if self.coverage_ratio is None else f"{self.coverage_ratio}x"
        lines = [f"**Pipeline coverage {self.company_ref}** for {self.period_ref} as of {self.as_of[:10]}: {self.verdict}; weighted pipeline {self.weighted_pipeline} against a sales-sourced target of {self.sales_sourced_target} ({ratio}), open pipeline {self.open_pipeline} against {self.required_open_pipeline} required."]
        if self.pipeline_gap > 0:
            lines.append(f"- gap {self.pipeline_gap} {self.currency}: {self.prospects_needed} prospect(s) at {self.expected_value_per_prospect} expected each, {self.touches_needed} touch(es), {self.heads_needed} head(s) needed, {self.additional_heads} additional")
        lines.extend(f"- {item}" for item in self.recommendations)
        return "\n".join(lines)


def _period_days(start: str, end: str) -> int:
    return max(1, (parsed(end) - parsed(start)).days)


def _resolve_target(plan: PipelineCoveragePlan, *, period_ref: str, operating_plan_state: tuple[Any, Any] | None, revenue_model: Mapping[str, Any] | Any | None, target_amount: Any | None) -> tuple[Decimal, str, str | None, int]:
    sources = [name for name, value in (("operating_plan", operating_plan_state), ("revenue_model", revenue_model), ("typed", target_amount)) if value is not None]
    _require(len(sources) == 1, "TARGET_AMBIGUOUS" if sources else "TARGET_MISSING", "exactly one of operating_plan_state, revenue_model, or target_amount names the target")
    if operating_plan_state is not None:
        from lightbulb.operating_plan import OPERATING_PLAN_LIFECYCLE

        policy_raw, state_raw = operating_plan_state
        policy, state = OPERATING_PLAN_LIFECYCLE.bind(policy_raw, state_raw)
        _require(policy.company_ref == plan.company_ref and policy.currency == plan.currency, "SOURCE_SCOPE_MISMATCH", "the operating plan names another company or currency")
        period = next((item for item in policy.periods if item.period_ref == period_ref), None)
        _require(period is not None, "PERIOD_UNKNOWN", f"{period_ref} is not a period of the operating plan")
        lines = state.ledger.forecast or state.ledger.plan_of_record
        amount = sum((line.amount for line in lines if line.period_ref == period_ref and line.kind == "revenue"), Decimal("0"))
        return _money(amount), "operating_plan", state.state_digest, _period_days(period.period_start, period.period_end)
    if revenue_model is not None:
        from lightbulb.growth_revenue_model import verify_revenue_model

        model = verify_revenue_model(revenue_model)
        _require(model.company_ref == plan.company_ref and model.currency == plan.currency, "SOURCE_SCOPE_MISMATCH", "the revenue model names another company or currency")
        month = model.month(period_ref)
        _require(month is not None, "PERIOD_UNKNOWN", f"{period_ref} is not a month of the revenue model")
        return _money(month.total), "revenue_model", model.model_digest, 30
    amount = decimal_value(target_amount, field_name="target_amount")
    return _money(amount), "typed", None, 30


def build_pipeline_coverage(plan: PipelineCoveragePlan | Mapping[str, Any], *, pipeline_plan: Any, prospect_states: Sequence[Any] = (), period_ref: str, as_of: str, operating_plan_state: tuple[Any, Any] | None = None, revenue_model: Mapping[str, Any] | Any | None = None, target_amount: Any | None = None, current_sales_heads: int = 0) -> PipelineCoverage:
    """The sealed coverage assessment from the pipeline's forecast of the replayed prospects and one named target."""

    from lightbulb.pipeline_engine_loop import PROSPECT_LIFECYCLE, PipelineEngineLoopPlan, forecast_pipeline

    parsed_plan = plan if isinstance(plan, PipelineCoveragePlan) else PipelineCoveragePlan.model_validate(detached(plan))
    at = timestamp(as_of, field_name="as_of")
    _require(int(current_sales_heads) >= 0, "HEADS_NEGATIVE", "current sales heads is a count")
    engine_plan = PipelineEngineLoopPlan.model_validate(detached(pipeline_plan))
    bp = engine_plan.blueprint
    _require(bp.currency == parsed_plan.currency, "SOURCE_SCOPE_MISMATCH", f"the pipeline blueprint forecasts in {bp.currency}, not {parsed_plan.currency}")
    target, basis, target_digest, days = _resolve_target(parsed_plan, period_ref=period_ref, operating_plan_state=operating_plan_state, revenue_model=revenue_model, target_amount=target_amount)
    forecast = forecast_pipeline(engine_plan, list(prospect_states), forecast_at=at)
    bound = [PROSPECT_LIFECYCLE.bind(engine_plan, item)[1] for item in prospect_states]
    open_states = [item for item in bound if item.status in OPEN_PROSPECT_STATUSES]
    open_pipeline = _money(bp.average_deal_value * len(open_states) + forecast.handed_off_value)
    sourced_target = _money(target * parsed_plan.sales_sourced_percent / _HUNDRED)
    weighted = _money(forecast.weighted_pipeline_value)
    coverage = None if sourced_target <= 0 else _rate(weighted / sourced_target)
    required_open = _money(sourced_target * parsed_plan.coverage_multiple)
    open_coverage = None if sourced_target <= 0 else _rate(open_pipeline / sourced_target)
    gap = _money(max(Decimal("0"), sourced_target - weighted))
    if gap > 0:
        verdict = "uncovered"
    elif open_pipeline < required_open:
        verdict = "thin"
    else:
        verdict = "covered"
    if forecast.meeting_rate_percent is not None and forecast.touched > 0:
        meeting_rate, rate_basis = _rate(forecast.meeting_rate_percent), "observed"
    else:
        meeting_rate, rate_basis = _rate(bp.target_meeting_rate_percent), "blueprint_target"
    per_prospect = _money(bp.average_deal_value * meeting_rate / _HUNDRED * parsed_plan.meeting_to_handoff_percent / _HUNDRED)
    prospects_needed = 0 if gap <= 0 else (int(math.ceil(gap / per_prospect)) if per_prospect > 0 else 0)
    touches_per_prospect = max(len(item.steps) for item in bp.sequences)
    touches_needed = prospects_needed * touches_per_prospect
    months = Decimal(days) / Decimal(30)
    heads_needed = 0 if touches_needed == 0 else int(math.ceil(Decimal(touches_needed) / (Decimal(parsed_plan.touches_per_head_per_month) * months)))
    additional = max(0, heads_needed - int(current_sales_heads))
    recommendations: list[str] = []
    if verdict == "uncovered" and per_prospect <= 0:
        recommendations.append("the meeting rate is zero; fix conversion before sourcing more prospects")
    elif verdict == "uncovered" and additional > 0:
        recommendations.append(f"source {prospects_needed} prospect(s) inside the ICP; that is {additional} additional sales head(s) at {parsed_plan.touches_per_head_per_month} touches a month")
    elif verdict == "uncovered":
        recommendations.append(f"source {prospects_needed} prospect(s) inside the ICP with the current team")
    elif verdict == "thin":
        recommendations.append(f"weighted pipeline covers the target but open pipeline is under {parsed_plan.coverage_multiple}x; keep sourcing before the period starts")
    else:
        recommendations.append("pipeline covers the period; hold sourcing at the current pace")
    if rate_basis == "blueprint_target":
        recommendations.append("no prospect has been touched yet; the meeting rate is the blueprint's target, not an observation")
    payload = {
        "company_ref": parsed_plan.company_ref, "currency": parsed_plan.currency, "as_of": at, "plan_digest": parsed_plan.plan_digest, "period_ref": period_ref, "period_days": days,
        "target_basis": basis, "target_digest": target_digest, "target_revenue": str(target), "sales_sourced_target": str(sourced_target),
        "prospects": len(bound), "open_prospects": len(open_states), "weighted_pipeline": str(weighted), "open_pipeline": str(open_pipeline), "handed_off_value": str(_money(forecast.handed_off_value)),
        "coverage_ratio": None if coverage is None else str(coverage), "open_coverage_ratio": None if open_coverage is None else str(open_coverage), "required_open_pipeline": str(required_open), "pipeline_gap": str(gap), "verdict": verdict,
        "meeting_rate_percent": str(meeting_rate), "meeting_rate_basis": rate_basis, "expected_value_per_prospect": str(per_prospect), "prospects_needed": prospects_needed,
        "touches_per_prospect": touches_per_prospect, "touches_needed": touches_needed, "heads_needed": heads_needed, "current_sales_heads": int(current_sales_heads), "additional_heads": additional,
        "assumptions": {"coverage_multiple": str(parsed_plan.coverage_multiple), "sales_sourced_percent": str(parsed_plan.sales_sourced_percent), "meeting_to_handoff_percent": str(parsed_plan.meeting_to_handoff_percent), "touches_per_head_per_month": str(parsed_plan.touches_per_head_per_month), "average_deal_value": str(bp.average_deal_value)},
        "pipeline_forecast_digest": forecast.forecast_digest, "recommendations": recommendations[:8],
    }
    return seal(PipelineCoverage, payload, "coverage_digest")


def verify_pipeline_coverage(value: Any) -> PipelineCoverage:
    return value if isinstance(value, PipelineCoverage) else PipelineCoverage.model_validate(dict(detached(value)))


def coverage_headcount_request(coverage: PipelineCoverage | Mapping[str, Any], hiring_plan: Any, *, role_ref: str, pay_rate: Any, pay_rate_uom: str, requester_ref: str, envelope: Mapping[str, Any] | Any | None = None) -> dict[str, Any]:
    """The hiring chain's opening receipt for exactly the additional heads the sealed assessment needs, bound to it by digest."""

    from lightbulb.hiring_chain import headcount_receipt

    verified = verify_pipeline_coverage(coverage)
    _require(verified.additional_heads > 0, "COVERAGE_NO_GAP", "the assessment needs no additional heads; nothing to requisition")
    receipt = headcount_receipt(hiring_plan, role_ref=role_ref, headcount=verified.additional_heads, pay_rate=pay_rate, pay_rate_uom=pay_rate_uom, requester_ref=requester_ref, envelope=envelope, period_ref=verified.period_ref)
    receipt["evidence_refs"] = [*receipt["evidence_refs"], f"coverage:{verified.coverage_digest[:16]}"]
    return receipt


PIPELINE_COVERAGE_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "pipeline_coverage",
    "golden_loop": "revenue.icp_to_qualified_pipeline@0.1.0",
    "stages": ["resolve_target", "forecast_pipeline", "measure_coverage", "size_gap", "seal_assessment"],
    "verdicts": list(COVERAGE_VERDICTS),
    "target_bases": list(TARGET_BASES),
    "required_connectors": ["lightbulb.sdk_engine_state"],
    "hard_rules": [
        "the target is the operating plan's forecast line, the revenue model's month, or a typed amount, and the assessment names which",
        "the pipeline is the sealed forecast of the replayed prospects; nothing types a pipeline value",
        "the gap is sized at the observed meeting rate, else the blueprint's target, and the assessment says which",
        "the hiring chain accepts the gap only as a requisition bound to the sealed assessment",
    ],
}

__all__ = ["COVERAGE_VERDICTS", "OPEN_PROSPECT_STATUSES", "PIPELINE_COVERAGE_MANIFEST", "PIPELINE_COVERAGE_PLAN_SCHEMA", "PIPELINE_COVERAGE_SCHEMA", "TARGET_BASES", "PipelineCoverage", "PipelineCoverageError", "PipelineCoveragePlan", "build_pipeline_coverage", "compile_pipeline_coverage_plan", "coverage_headcount_request", "verify_pipeline_coverage"]
