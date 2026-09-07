"""Multi-company operator view: one sealed portfolio assessment across every company an operator runs.

An operator who runs several companies through the SDK needs one place that
answers "which company needs me now, and why".  ``assess_portfolio`` takes,
per company, the persisted engine states, the operating plan (and its
lineage), the cadence state, the approval inbox, and the latest simulation,
and produces a ranked ``PortfolioAssessment``:

* per company: the health assessment the operating system already computes,
  the cadence status, open and halted periods, pending and stale approvals,
  workforce cost this period, the latest simulation's halt reason, and an
  ordered list of *attention reasons* with a score;
* across companies: totals, the ranking by attention, and the companies with
  nothing outstanding.

Every reason is derived from a sealed input (a state, an inbox, a
simulation); nothing is inferred from prose, and nothing here reads the
platform or executes anything.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_approval_inbox import ApprovalInbox
from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    MONEY_QUANTUM,
    BoundedText,
    OpaqueRef,
    Sha256Digest,
    ShortText,
    StrictModel,
    decimal_value,
    detached,
    seal,
    sealed_digest,
    skip_digests,
    timestamp,
    unique,
)
from lightbulb.company_operating_system import PERIOD_LIFECYCLE, CompanyHealthAssessment, CompanyOperatingPlan, assess_company_health
from lightbulb.company_simulator import SimulationResult
from lightbulb.company_workforce import WORKER_LIFECYCLE, WorkforcePlan

PORTFOLIO_SCHEMA = "lightbulb.company_portfolio_assessment.v1"
MAX_COMPANIES = 60
Severity = Literal["critical", "high", "medium", "low"]
_SEVERITY_SCORE: Mapping[str, int] = {"critical": 40, "high": 20, "medium": 8, "low": 3}


class AttentionReason(StrictModel):
    code: ShortText
    severity: Severity
    detail: BoundedText
    source: ShortText


class CompanyPortfolioInput(StrictModel):
    """Everything the portfolio view knows about one company; all of it sealed elsewhere."""

    company_ref: OpaqueRef
    name: ShortText | None = None
    operating_plan: CompanyOperatingPlan
    prior_plans: tuple[CompanyOperatingPlan, ...] = Field(default_factory=tuple, max_length=24)
    period_states: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=120)
    worker_states: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=120)
    workforce_plan: WorkforcePlan | None = None
    cadence_status: Literal["running", "paused", "stopped", "not_started"] = "not_started"
    inbox: ApprovalInbox | None = None
    simulation: SimulationResult | None = None
    cash_on_hand: Decimal | None = None
    monthly_burn: Decimal | None = None

    @field_validator("period_states", "worker_states", "prior_plans", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("cash_on_hand", "monthly_burn", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))


class CompanyPortfolioEntry(StrictModel):
    company_ref: OpaqueRef
    name: ShortText | None = None
    archetype: ShortText
    currency: ShortText
    plan_digest: Sha256Digest
    cadence_status: ShortText
    periods: int = Field(ge=0)
    open_periods: int = Field(ge=0)
    halted_periods: int = Field(ge=0)
    revenue_attainment_percent: Decimal | None = None
    runway_months: Decimal | None = None
    pending_approvals: int = Field(ge=0)
    stale_approvals: int = Field(ge=0)
    expiring_approvals: int = Field(ge=0)
    active_workers: int = Field(ge=0)
    workforce_cost_this_period: Decimal
    simulation_halt_reason: ShortText | None = None
    simulation_final_cash: Decimal | None = None
    health_digest: Sha256Digest
    attention_score: int = Field(ge=0)
    reasons: tuple[AttentionReason, ...] = Field(default_factory=tuple, max_length=16)
    recommendations: tuple[BoundedText, ...] = Field(default_factory=tuple, max_length=12)

    @field_validator("workforce_cost_this_period", "simulation_final_cash", mode="before")
    @classmethod
    def _signed(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)

    @field_validator("revenue_attainment_percent", "runway_months", mode="before")
    @classmethod
    def _optional(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))


class PortfolioAssessment(StrictModel):
    schema_id: str = Field(default=PORTFOLIO_SCHEMA, alias="schema")
    assessed_at: str
    companies: int = Field(ge=1, le=MAX_COMPANIES)
    entries: tuple[CompanyPortfolioEntry, ...] = Field(min_length=1, max_length=MAX_COMPANIES)
    ranked: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=MAX_COMPANIES)
    quiet: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=MAX_COMPANIES)
    pending_approvals: int = Field(ge=0)
    stale_approvals: int = Field(ge=0)
    halted_periods: int = Field(ge=0)
    cadences_not_running: int = Field(ge=0)
    reasons_by_code: dict[str, int] = Field(default_factory=dict)
    assessment_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("assessed_at")
    @classmethod
    def _assessed(cls, value: str) -> str:
        return timestamp(value, field_name="assessed_at")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> PortfolioAssessment:
        refs = [entry.company_ref for entry in self.entries]
        unique(refs, label="company refs")
        if self.companies != len(self.entries) or sorted(self.ranked) != sorted(refs):
            raise ValueError("ranked must permute the entries")
        if not skip_digests(info) and self.assessment_digest != sealed_digest(PortfolioAssessment, self, "assessment_digest"):
            raise ValueError("assessment_digest must commit the exact assessment")
        return self

    def entry(self, company_ref: str) -> CompanyPortfolioEntry | None:
        return next((entry for entry in self.entries if entry.company_ref == company_ref), None)


def _reason(code: str, severity: Severity, detail: str, source: str) -> dict[str, Any]:
    return {"code": code, "severity": severity, "detail": detail, "source": source}


def _assess_one(item: CompanyPortfolioInput, *, assessed_at: str) -> CompanyPortfolioEntry:
    plan = item.operating_plan
    lineage = {plan.plan_digest: plan, **{prior.plan_digest: prior for prior in item.prior_plans}}
    periods = []
    for record in item.period_states:
        document = dict(record["state"]) if "state" in record else dict(record)
        owner = lineage.get(str(document.get("plan_digest")))
        if owner is None:
            raise ValueError(f"{item.company_ref}: a period belongs to a plan outside the supplied lineage")
        periods.append(PERIOD_LIFECYCLE.State.model_validate(document, context={PERIOD_LIFECYCLE.plan_context_key: owner}))
    health: CompanyHealthAssessment = assess_company_health(plan, periods, assessed_at=assessed_at, cash_on_hand=item.cash_on_hand, monthly_burn=item.monthly_burn, prior_plans=item.prior_plans)
    open_periods = sum(1 for period in periods if period.status not in PERIOD_LIFECYCLE.terminal)
    halted = sum(1 for period in periods if period.status == "halted")
    workers = []
    if item.workforce_plan is not None:
        for record in item.worker_states:
            document = dict(record["state"]) if "state" in record else dict(record)
            workers.append(WORKER_LIFECYCLE.State.model_validate(document, context={WORKER_LIFECYCLE.plan_context_key: item.workforce_plan}))
    active_workers = sum(1 for worker in workers if worker.status == "active")
    workforce_cost = sum((Decimal(str(worker.ledger.cost_this_period)) for worker in workers), Decimal("0")).quantize(MONEY_QUANTUM)
    reasons: list[dict[str, Any]] = []
    if halted:
        reasons.append(_reason("PERIOD_HALTED", "critical", f"{halted} operating period(s) halted; the company is not spending until an operator reopens it", "operating_period"))
    if health.runway_months is not None and health.runway_months < Decimal("3"):
        reasons.append(_reason("RUNWAY_SHORT", "critical", f"runway is {health.runway_months} month(s) at the stated burn", "company_health"))
    elif health.runway_months is not None and health.runway_months < Decimal("6"):
        reasons.append(_reason("RUNWAY_TIGHT", "high", f"runway is {health.runway_months} month(s) at the stated burn", "company_health"))
    if item.cadence_status != "running":
        severity: Severity = "high" if item.cadence_status in ("paused", "stopped") else "medium"
        reasons.append(_reason("CADENCE_NOT_RUNNING", severity, f"the cadence is {item.cadence_status.replace('_', ' ')}; nothing advances automatically", "company_cadence"))
    pending = stale = expiring = 0
    if item.inbox is not None:
        pending = item.inbox.engine_items
        stale = item.inbox.stale_items
        expiring = len(item.inbox.expiring_soon)
        if stale:
            reasons.append(_reason("APPROVALS_STALE", "high", f"{stale} approval(s) no longer match the persisted state; decide against the current state", "approval_inbox"))
        if expiring:
            reasons.append(_reason("APPROVALS_EXPIRING", "high", f"{expiring} approval(s) expire within the inbox window", "approval_inbox"))
        elif pending:
            reasons.append(_reason("APPROVALS_PENDING", "medium", f"{pending} engine transition(s) wait on a decision", "approval_inbox"))
    if health.revenue_attainment_percent is not None and health.closed and health.revenue_attainment_percent < Decimal("50"):
        reasons.append(_reason("REVENUE_BEHIND", "medium", f"revenue attainment is {health.revenue_attainment_percent}% across {health.closed} closed period(s)", "company_health"))
    sim_halt = item.simulation.halt_reason if item.simulation is not None else None
    sim_cash = item.simulation.final_cash if item.simulation is not None else None
    if item.simulation is not None and item.simulation.plan_lineage[0] != plan.plan_digest and item.simulation.initial_plan_digest not in lineage:
        reasons.append(_reason("SIMULATION_STALE", "low", "the latest simulation ran under a plan outside this company's lineage", "company_simulator"))
    elif sim_halt:
        reasons.append(_reason("SIMULATION_HALTS", "medium", f"the latest simulation halted: {sim_halt}", "company_simulator"))
    elif sim_cash is not None and sim_cash < Decimal("0"):
        reasons.append(_reason("SIMULATION_NEGATIVE_CASH", "medium", f"the latest simulation ends with {sim_cash} {plan.blueprint.currency}", "company_simulator"))
    if not periods:
        reasons.append(_reason("NO_PERIODS", "low", "no operating period has been opened", "operating_period"))
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    reasons.sort(key=lambda reason: (order[reason["severity"]], reason["code"]))
    score = sum(_SEVERITY_SCORE[reason["severity"]] for reason in reasons)
    return CompanyPortfolioEntry.model_validate(
        {
            "company_ref": item.company_ref,
            "name": item.name,
            "archetype": plan.blueprint.archetype,
            "currency": plan.blueprint.currency,
            "plan_digest": plan.plan_digest,
            "cadence_status": item.cadence_status,
            "periods": len(periods),
            "open_periods": open_periods,
            "halted_periods": halted,
            "revenue_attainment_percent": None if health.revenue_attainment_percent is None else str(health.revenue_attainment_percent),
            "runway_months": None if health.runway_months is None else str(health.runway_months),
            "pending_approvals": pending,
            "stale_approvals": stale,
            "expiring_approvals": expiring,
            "active_workers": active_workers,
            "workforce_cost_this_period": str(workforce_cost),
            "simulation_halt_reason": sim_halt,
            "simulation_final_cash": None if sim_cash is None else str(sim_cash),
            "health_digest": health.assessment_digest,
            "attention_score": score,
            "reasons": reasons[:16],
            "recommendations": list(health.recommendations)[:12],
        }
    )


def assess_portfolio(inputs: Sequence[CompanyPortfolioInput | Mapping[str, Any]], *, assessed_at: str) -> PortfolioAssessment:
    """Assess every company and rank them by attention; deterministic for the same sealed inputs."""

    stamp = timestamp(assessed_at, field_name="assessed_at")
    items = [entry if isinstance(entry, CompanyPortfolioInput) else CompanyPortfolioInput.model_validate(dict(detached(entry))) for entry in inputs]
    if not items:
        raise ValueError("a portfolio assesses at least one company")
    if len(items) > MAX_COMPANIES:
        raise ValueError(f"a portfolio assesses at most {MAX_COMPANIES} companies")
    unique([item.company_ref for item in items], label="company refs")
    entries = [_assess_one(item, assessed_at=stamp) for item in items]
    ranked = sorted(entries, key=lambda entry: (-entry.attention_score, entry.company_ref))
    by_code: dict[str, int] = {}
    for entry in entries:
        for reason in entry.reasons:
            by_code[reason.code] = by_code.get(reason.code, 0) + 1
    return seal(
        PortfolioAssessment,
        {
            "assessed_at": stamp,
            "companies": len(entries),
            "entries": [entry.to_dict() for entry in entries],
            "ranked": [entry.company_ref for entry in ranked],
            "quiet": [entry.company_ref for entry in ranked if entry.attention_score == 0],
            "pending_approvals": sum(entry.pending_approvals for entry in entries),
            "stale_approvals": sum(entry.stale_approvals for entry in entries),
            "halted_periods": sum(entry.halted_periods for entry in entries),
            "cadences_not_running": sum(1 for entry in entries if entry.cadence_status != "running"),
            "reasons_by_code": dict(sorted(by_code.items())),
        },
        "assessment_digest",
    )


def render_portfolio(assessment: PortfolioAssessment | Mapping[str, Any], *, limit: int = 20) -> str:
    """Operator-readable summary, ranked by attention; the sealed assessment is the source of truth."""

    parsed = assessment if isinstance(assessment, PortfolioAssessment) else PortfolioAssessment.model_validate(dict(detached(assessment)))
    lines = [f"**{parsed.companies} compan{'y' if parsed.companies == 1 else 'ies'}** at {parsed.assessed_at}: {parsed.pending_approvals} approval(s) pending ({parsed.stale_approvals} stale), {parsed.halted_periods} halted period(s), {parsed.cadences_not_running} cadence(s) not running"]
    for ref in parsed.ranked[: max(1, limit)]:
        entry = parsed.entry(ref)
        assert entry is not None
        label = f"{entry.name} (`{ref}`)" if entry.name else f"`{ref}`"
        lines.append(f"- {label} {entry.archetype}, cadence {entry.cadence_status}, attention {entry.attention_score}")
        for reason in entry.reasons[:4]:
            lines.append(f"  - {reason.severity}: {reason.detail}")
    if parsed.quiet:
        lines.append(f"Nothing outstanding: {', '.join(parsed.quiet)}")
    return "\n".join(lines)


PORTFOLIO_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "company_portfolio",
    "golden_loop": "company_operating_system",
    "stages": ["gather_sealed_inputs", "assess_each_company", "rank_by_attention", "render"],
    "reason_codes": ["PERIOD_HALTED", "RUNWAY_SHORT", "RUNWAY_TIGHT", "CADENCE_NOT_RUNNING", "APPROVALS_STALE", "APPROVALS_EXPIRING", "APPROVALS_PENDING", "REVENUE_BEHIND", "SIMULATION_STALE", "SIMULATION_HALTS", "SIMULATION_NEGATIVE_CASH", "NO_PERIODS"],
    "required_connectors": ["lightbulb.sdk_engine_state", "lightbulb.approvals"],
    "hard_rules": [
        "every attention reason cites the sealed input it came from",
        "companies are ranked by the sum of reason severities, ties broken by company ref",
        "the view reads persisted states, inboxes, and simulations; it never executes, decides, or spends",
    ],
}

__all__ = [
    "PORTFOLIO_MANIFEST",
    "PORTFOLIO_SCHEMA",
    "AttentionReason",
    "CompanyPortfolioEntry",
    "CompanyPortfolioInput",
    "PortfolioAssessment",
    "assess_portfolio",
    "render_portfolio",
]
