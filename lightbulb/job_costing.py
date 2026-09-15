"""Job costing: what every job actually cost against its estimate, where the money went, which assets keep costing, and how the contractors billed.

The work order chain records the estimate, the parts and stock drawn,
the timesheet labour at the plan's rate, the contractor units at their
rate, the variance, and whether the job overran and finished on time; the
contractor chain records the work approved against each contractor, what
they invoiced, and what was paid.  ``build_job_costing`` reads both and
seals:

* per job: kind, asset, estimate, actual (the cost to date while the job
  is open), variance and its percent, the
  cost mix (parts, stock, labour, contractor), labour hours and the cost
  per labour hour, on time or the days late;
* per kind: jobs, the mean variance (the estimating bias), the overrun
  rate, and the on-time rate;
* per asset: jobs, total cost, and whether the last job cost more than
  the first (the repair-or-replace question);
* per contractor: units, the value of approved work, what they invoiced
  and were paid, and the billing accuracy;
* recommendations that name the number: re-base estimates for a kind
  that runs over, review an asset past the plan's threshold, and query a
  contractor whose invoices exceed the approved work.

Everything is arithmetic on replayed states; nothing here reads a
provider or persists anything.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import ROUND_HALF_UP, Decimal
from typing import Any

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

JOB_COSTING_PLAN_SCHEMA = "lightbulb.job_costing_plan.v1"
JOB_COSTING_SCHEMA = "lightbulb.job_costing.v1"
_HUNDRED = Decimal("100")
_PCT = Decimal("0.01")


class JobCostingError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise JobCostingError(code, message)


def _money(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


def _pct(numerator: Decimal, denominator: Decimal) -> Decimal | None:
    return None if denominator <= 0 else (numerator / denominator * _HUNDRED).quantize(_PCT, rounding=ROUND_HALF_UP)


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


class JobCostingPlan(StrictModel):
    schema_id: str = Field(default=JOB_COSTING_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    estimate_bias_threshold_percent: Decimal = Field(default=Decimal("10"), validate_default=True)
    overrun_rate_threshold_percent: Decimal = Field(default=Decimal("25"), validate_default=True)
    asset_review_threshold: Decimal = Field(default=Decimal("5000"), validate_default=True)
    billing_tolerance_percent: Decimal = Field(default=Decimal("2"), validate_default=True)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("estimate_bias_threshold_percent", "overrun_rate_threshold_percent", "asset_review_threshold", "billing_tolerance_percent", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "JobCostingPlan":
        if not skip_digests(info) and self.plan_digest != sealed_digest(JobCostingPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self


def compile_job_costing_plan(company_ref: str, *, currency: str, overrides: Mapping[str, Any] | None = None) -> JobCostingPlan:
    return seal(JobCostingPlan, {"company_ref": company_ref, "currency": str(currency).upper(), **dict(overrides or {})}, "plan_digest")


class JobRow(StrictModel):
    work_order_ref: OpaqueRef
    kind: ShortText
    asset_ref: OpaqueRef | None = None
    status: ShortText
    raised_at: str
    completed_at: str | None = None
    target_at: str | None = None
    on_time: bool | None = None
    days_late: int | None = None
    estimated_cost: Decimal
    actual_cost: Decimal
    variance: Decimal
    variance_percent: Decimal | None = None
    overrun: bool
    parts_cost: Decimal
    stock_cost: Decimal
    labour_cost: Decimal
    contractor_cost: Decimal
    labour_hours: Decimal
    cost_per_labour_hour: Decimal | None = None

    @field_validator("estimated_cost", "actual_cost", "variance", "variance_percent", "parts_cost", "stock_cost", "labour_cost", "contractor_cost", "labour_hours", "cost_per_labour_hour", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class KindSummary(StrictModel):
    kind: ShortText
    jobs: int = Field(ge=1)
    estimated_cost: Decimal
    actual_cost: Decimal
    mean_variance_percent: Decimal | None = None
    overrun_rate_percent: Decimal
    on_time_rate_percent: Decimal | None = None
    labour_hours: Decimal
    cost_per_labour_hour: Decimal | None = None
    verdict: ShortText

    @field_validator("estimated_cost", "actual_cost", "mean_variance_percent", "overrun_rate_percent", "on_time_rate_percent", "labour_hours", "cost_per_labour_hour", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class AssetSummary(StrictModel):
    asset_ref: OpaqueRef
    jobs: int = Field(ge=1)
    actual_cost: Decimal
    first_job_cost: Decimal
    last_job_cost: Decimal
    rising: bool
    review: bool
    note: ShortText

    @field_validator("actual_cost", "first_job_cost", "last_job_cost", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))


class ContractorSummary(StrictModel):
    contractor_ref: OpaqueRef
    status: ShortText
    rate: Decimal
    rate_uom: ShortText | None = None
    units: Decimal
    work_value: Decimal
    invoiced: Decimal
    paid: Decimal
    uninvoiced: Decimal
    bills: int = Field(ge=0)
    billing_accuracy_percent: Decimal | None = None
    work_order_cost: Decimal
    verdict: ShortText

    @field_validator("rate", "units", "work_value", "invoiced", "paid", "uninvoiced", "billing_accuracy_percent", "work_order_cost", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class JobCosting(StrictModel):
    schema_id: str = Field(default=JOB_COSTING_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    window_start: str
    window_end: str
    as_of: str
    plan_digest: Sha256Digest
    jobs: tuple[JobRow, ...] = Field(default_factory=tuple, max_length=5000)
    kinds: tuple[KindSummary, ...] = Field(default_factory=tuple, max_length=50)
    assets: tuple[AssetSummary, ...] = Field(default_factory=tuple, max_length=2000)
    contractors: tuple[ContractorSummary, ...] = Field(default_factory=tuple, max_length=500)
    estimated_cost: Decimal
    actual_cost: Decimal
    variance: Decimal
    overrun_jobs: int = Field(ge=0)
    late_jobs: int = Field(ge=0)
    recommendations: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=24)
    source_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=6000)
    costing_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("jobs", "kinds", "assets", "contractors", "recommendations", "source_digests", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("estimated_cost", "actual_cost", "variance", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name), allow_negative=True)

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "JobCosting":
        if not skip_digests(info) and self.costing_digest != sealed_digest(JobCosting, self, "costing_digest"):
            raise ValueError("costing_digest must commit the exact document")
        return self

    def job(self, work_order_ref: str) -> JobRow | None:
        return next((row for row in self.jobs if row.work_order_ref == work_order_ref), None)

    def kind(self, kind: str) -> KindSummary | None:
        return next((row for row in self.kinds if row.kind == kind), None)

    def contractor(self, contractor_ref: str) -> ContractorSummary | None:
        return next((row for row in self.contractors if row.contractor_ref == contractor_ref), None)

    def render(self) -> str:
        lines = [f"**Job costing {self.company_ref}** {self.window_start[:10]} to {self.window_end[:10]}: {len(self.jobs)} job(s), estimated {self.estimated_cost} against actual {self.actual_cost} {self.currency} (variance {self.variance}); {self.overrun_jobs} overran, {self.late_jobs} late."]
        for row in self.kinds:
            lines.append(f"- {row.kind}: {row.jobs} job(s), {row.verdict}")
        for row in self.assets:
            if row.review:
                lines.append(f"- asset {row.asset_ref}: {row.note}")
        for row in self.contractors:
            lines.append(f"- contractor {row.contractor_ref}: {row.verdict}")
        return "\n".join(lines)


def build_job_costing(plan: JobCostingPlan | Mapping[str, Any], *, work_order_states: Sequence[tuple[Any, Any]], contractor_states: Sequence[tuple[Any, Any]] = (), window_start: str, window_end: str, as_of: str) -> JobCosting:
    """The sealed costing over the window: every work order raised inside it, the kinds and assets it rolls up to, and the contractors it drew on."""

    from lightbulb.work_order_chain import WORK_ORDER_LIFECYCLE

    parsed_plan = plan if isinstance(plan, JobCostingPlan) else JobCostingPlan.model_validate(detached(plan))
    start, end = timestamp(window_start, field_name="window_start"), timestamp(window_end, field_name="window_end")
    _require(parsed(end) > parsed(start), "WINDOW_EMPTY", "window_end must follow window_start")
    at = timestamp(as_of, field_name="as_of")
    digests: list[str] = []
    jobs: list[dict[str, Any]] = []
    contractor_costs: dict[str, Decimal] = {}
    for plan_doc, state_doc in work_order_states:
        wplan, state = WORK_ORDER_LIFECYCLE.bind(plan_doc, state_doc)
        _require(wplan.company_ref == parsed_plan.company_ref and wplan.currency == parsed_plan.currency, "SOURCE_SCOPE_MISMATCH", f"work order {state.scope.entity_ref} belongs to another company or currency")
        digests.append(state.state_digest)
        ledger = state.ledger
        if ledger.raised_at is None or not (parsed(start) <= parsed(str(ledger.raised_at)) < parsed(end)) or state.status == "cancelled":
            continue
        estimated = Decimal(str(ledger.estimated_cost))
        to_date = Decimal(str(ledger.parts_cost)) + Decimal(str(ledger.stock_cost)) + Decimal(str(ledger.labour_cost)) + Decimal(str(ledger.contractor_cost))
        actual = max(Decimal(str(ledger.actual_cost)), to_date)  # an open job carries its cost to date; a completed one the chain's own actual
        variance = _money(actual - estimated)
        on_time = None
        days_late = None
        if ledger.completed_at and ledger.target_at:
            days_late = (parsed(str(ledger.completed_at)) - parsed(str(ledger.target_at))).days
            on_time = days_late <= 0
        hours = Decimal(str(ledger.labour_hours))
        for record in ledger.contractor_labour:
            contractor_costs[str(record.contractor_ref)] = contractor_costs.get(str(record.contractor_ref), Decimal("0")) + Decimal(str(record.value))
        jobs.append({"work_order_ref": str(ledger.work_order_ref or state.scope.entity_ref), "kind": str(ledger.kind), "asset_ref": ledger.asset_ref, "status": state.status, "raised_at": ledger.raised_at, "completed_at": ledger.completed_at, "target_at": ledger.target_at, "on_time": on_time, "days_late": days_late, "estimated_cost": str(_money(estimated)), "actual_cost": str(_money(actual)), "variance": str(variance), "variance_percent": None if _pct(variance, estimated) is None else str(_pct(variance, estimated)), "overrun": bool(ledger.overrun), "parts_cost": str(_money(ledger.parts_cost)), "stock_cost": str(_money(ledger.stock_cost)), "labour_cost": str(_money(ledger.labour_cost)), "contractor_cost": str(_money(ledger.contractor_cost)), "labour_hours": str(hours.quantize(_PCT)), "cost_per_labour_hour": None if hours <= 0 else str(_money(Decimal(str(ledger.labour_cost)) / hours))})
    kinds: list[dict[str, Any]] = []
    for kind in sorted({job["kind"] for job in jobs}):
        rows = [job for job in jobs if job["kind"] == kind]
        estimated = sum((Decimal(job["estimated_cost"]) for job in rows), Decimal("0"))
        actual = sum((Decimal(job["actual_cost"]) for job in rows), Decimal("0"))
        variances = [Decimal(job["variance_percent"]) for job in rows if job["variance_percent"] is not None and job["status"] in ("completed", "costed")]  # only finished jobs measure the estimate
        mean_variance = None if not variances else (sum(variances, Decimal("0")) / len(variances)).quantize(_PCT, rounding=ROUND_HALF_UP)
        overrun_rate = _pct(Decimal(sum(1 for job in rows if job["overrun"])), Decimal(len(rows))) or Decimal("0")
        timed = [job for job in rows if job["on_time"] is not None]
        on_time_rate = _pct(Decimal(sum(1 for job in timed if job["on_time"])), Decimal(len(timed)))
        hours = sum((Decimal(job["labour_hours"]) for job in rows), Decimal("0"))
        labour = sum((Decimal(job["labour_cost"]) for job in rows), Decimal("0"))
        if mean_variance is not None and mean_variance > parsed_plan.estimate_bias_threshold_percent:
            verdict = f"estimates run {mean_variance}% under actual: re-base {kind} estimates"
        elif overrun_rate > parsed_plan.overrun_rate_threshold_percent:
            verdict = f"{overrun_rate}% of jobs overran the {kind} tolerance"
        elif mean_variance is not None and mean_variance < -parsed_plan.estimate_bias_threshold_percent:
            verdict = f"estimates run {abs(mean_variance)}% over actual: {kind} is being over-quoted"
        else:
            verdict = f"estimates within {parsed_plan.estimate_bias_threshold_percent}% (mean variance {mean_variance if mean_variance is not None else 'n/a'}%)" + (f", {on_time_rate}% on time" if on_time_rate is not None else "")
        kinds.append({"kind": kind, "jobs": len(rows), "estimated_cost": str(_money(estimated)), "actual_cost": str(_money(actual)), "mean_variance_percent": None if mean_variance is None else str(mean_variance), "overrun_rate_percent": str(overrun_rate), "on_time_rate_percent": None if on_time_rate is None else str(on_time_rate), "labour_hours": str(hours.quantize(_PCT)), "cost_per_labour_hour": None if hours <= 0 else str(_money(labour / hours)), "verdict": verdict[:300]})
    assets: list[dict[str, Any]] = []
    for asset_ref in sorted({job["asset_ref"] for job in jobs if job["asset_ref"]}):
        rows = sorted((job for job in jobs if job["asset_ref"] == asset_ref), key=lambda job: job["raised_at"])
        total = sum((Decimal(job["actual_cost"]) for job in rows), Decimal("0"))
        first, last = Decimal(rows[0]["actual_cost"]), Decimal(rows[-1]["actual_cost"])
        rising = len(rows) >= 2 and last > first
        review = total >= parsed_plan.asset_review_threshold or (rising and len(rows) >= 3)
        note = f"{len(rows)} job(s) costing {_money(total)} in the window" + (f", the last ({last}) above the first ({first})" if rising else "") + ("; past the review threshold, weigh repair against replacement" if review else "")
        assets.append({"asset_ref": asset_ref, "jobs": len(rows), "actual_cost": str(_money(total)), "first_job_cost": str(first), "last_job_cost": str(last), "rising": rising, "review": review, "note": note[:300]})
    contractors: list[dict[str, Any]] = []
    if contractor_states:
        from lightbulb.contractor_chain import CONTRACTOR_LIFECYCLE

        for plan_doc, state_doc in contractor_states:
            cplan, state = CONTRACTOR_LIFECYCLE.bind(plan_doc, state_doc)
            _require(cplan.company_ref == parsed_plan.company_ref and cplan.currency == parsed_plan.currency, "SOURCE_SCOPE_MISMATCH", f"contractor {state.scope.entity_ref} belongs to another company or currency")
            digests.append(state.state_digest)
            ledger = state.ledger
            if not ledger.contractor_ref:
                continue
            work_value, invoiced, paid = Decimal(str(ledger.work_value_total)), Decimal(str(ledger.invoiced_total)), Decimal(str(ledger.paid_total))
            accuracy = _pct(invoiced, work_value)
            if accuracy is not None and accuracy > _HUNDRED + parsed_plan.billing_tolerance_percent:
                verdict = f"invoiced {invoiced} against {work_value} of approved work ({accuracy}%): query the bills"
            elif Decimal(str(ledger.uninvoiced_value)) > 0:
                verdict = f"{ledger.uninvoiced_value} of approved work not yet invoiced"
            elif invoiced > paid:
                verdict = f"{_money(invoiced - paid)} invoiced and unpaid"
            else:
                verdict = f"{ledger.units_total} unit(s) at {ledger.rate}, invoiced {invoiced} and paid {paid}" + (f"; {accuracy}% of approved work" if accuracy is not None else "")
            contractors.append({"contractor_ref": str(ledger.contractor_ref), "status": state.status, "rate": str(ledger.rate), "rate_uom": ledger.rate_uom, "units": str(ledger.units_total), "work_value": str(_money(work_value)), "invoiced": str(_money(invoiced)), "paid": str(_money(paid)), "uninvoiced": str(_money(ledger.uninvoiced_value)), "bills": len(ledger.bills), "billing_accuracy_percent": None if accuracy is None else str(accuracy), "work_order_cost": str(_money(contractor_costs.get(str(ledger.contractor_ref), Decimal("0")))), "verdict": verdict[:300]})
    jobs.sort(key=lambda job: (-abs(Decimal(job["variance"])), job["work_order_ref"]))
    estimated = _money(sum((Decimal(job["estimated_cost"]) for job in jobs), Decimal("0")))
    actual = _money(sum((Decimal(job["actual_cost"]) for job in jobs), Decimal("0")))
    recommendations = [f"{row['kind']}: {row['verdict']}" for row in kinds if not row["verdict"].startswith("estimates within")]
    recommendations += [f"asset {row['asset_ref']}: {row['note']}" for row in assets if row["review"]]
    recommendations += [f"contractor {row['contractor_ref']}: {row['verdict']}" for row in contractors if "query" in row["verdict"] or "not yet invoiced" in row["verdict"]]
    recommendations += [f"{job['work_order_ref']}: {job['days_late']} day(s) late against {job['target_at'][:10]}" for job in jobs if job["on_time"] is False][:6]
    if not recommendations:
        recommendations.append("every job is inside its estimate and on time" if jobs else "no work orders raised in the window")
    payload = {"company_ref": parsed_plan.company_ref, "currency": parsed_plan.currency, "window_start": start, "window_end": end, "as_of": at, "plan_digest": parsed_plan.plan_digest, "jobs": jobs, "kinds": kinds, "assets": assets, "contractors": contractors, "estimated_cost": str(estimated), "actual_cost": str(actual), "variance": str(_money(actual - estimated)), "overrun_jobs": sum(1 for job in jobs if job["overrun"]), "late_jobs": sum(1 for job in jobs if job["on_time"] is False), "recommendations": [item[:300] for item in recommendations[:24]], "source_digests": digests}
    return seal(JobCosting, payload, "costing_digest")


def verify_job_costing(value: Any) -> JobCosting:
    return value if isinstance(value, JobCosting) else JobCosting.model_validate(dict(detached(value)))


JOB_COSTING_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "job_costing",
    "golden_loop": "services.quote_to_cash@0.1.0",
    "stages": ["replay_work_orders", "cost_mix_and_variance", "roll_up_kinds_and_assets", "replay_contractors", "billing_accuracy", "seal_costing"],
    "required_connectors": ["lightbulb.sdk_engine_state"],
    "hard_rules": [
        "estimate, actual, cost mix, variance, overrun, and dates are the work order chain's own ledger; approved work, invoices, and payments are the contractor chain's",
        "the estimating bias is the mean variance percent per kind; the overrun and on-time rates are counts",
        "an asset is for review past the plan's threshold or when three or more jobs cost more each time",
        "nothing here reads a provider or persists anything",
    ],
}

__all__ = ["JOB_COSTING_MANIFEST", "JOB_COSTING_PLAN_SCHEMA", "JOB_COSTING_SCHEMA", "AssetSummary", "ContractorSummary", "JobCosting", "JobCostingError", "JobCostingPlan", "JobRow", "KindSummary", "build_job_costing", "compile_job_costing_plan", "verify_job_costing"]
