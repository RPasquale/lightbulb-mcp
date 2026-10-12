"""Product and labour intelligence as executable primitives.

Twenty-eight typed, read-only primitives over the sealed documents the product
and skills modules build: the product margin report, the price / volume /
mix bridge between two of them, the product portfolio, the skills match
report, and the labour sourcing plan.  Each one is a pure function of its
inputs (sealed plans, replayed states as dicts, sealed documents); none
reads a provider, persists anything, opens a requisition, or moves money.
Their examples are built from library code alone so the registry can run
them.
"""

from __future__ import annotations

from typing import Any, ClassVar, Mapping

from pydantic import BaseModel, ConfigDict

from lightbulb.contribution_bridge import ContributionBridge, build_contribution_bridge
from lightbulb.customer_cohorts import CustomerCohorts, build_customer_cohorts, compile_customer_cohort_plan
from lightbulb.company_engine_core import stable_digest
from lightbulb.books_backfill import BooksBackfillPlan, plan_books_backfill
from lightbulb.owner_digest import OwnerDigest, build_owner_digest
from lightbulb.payroll_team import PayrollTeam, build_payroll_team
from lightbulb.books_hygiene import BooksHygiene, assess_books_hygiene
from lightbulb.intelligence_history import IntelligenceHistory, ThresholdCalibration, build_history, calibrate_thresholds
from lightbulb.job_assignment import JobAssignment, assign_jobs, compile_job_assignment_plan
from lightbulb.customer_ledger import CustomerLedger, build_customer_ledger, compile_customer_ledger_plan
from lightbulb.company_scenario import Scenario, run_scenario
from lightbulb.ledger_tie_out import LedgerTieOut, compile_tie_out_plan, tie_out_documents
from lightbulb.books_cash_forecast import BooksCashForecast, build_books_cash_forecast
from lightbulb.books_snapshot import BooksSnapshot, build_books_snapshot, compile_books_plan
from lightbulb.decision_work_items import DecisionWorkItems, plan_decision_work_items
from lightbulb.customer_profitability import CustomerProfitability, build_customer_profitability
from lightbulb.intelligence_review import IntelligenceReview, build_intelligence_review
from lightbulb.job_costing import JobCosting, build_job_costing, compile_job_costing_plan
from lightbulb.job_quote import JobQuote, build_job_quote, compile_job_quote_plan
from lightbulb.break_even import BreakEven, build_break_even, compile_break_even_plan
from lightbulb.intelligence_outcomes import ReviewOutcomes, score_review_outcomes
from lightbulb.probe_outcomes import ProbeOutcomes, compile_probe_outcomes_plan, score_probe_outcomes
from lightbulb.quote_outcomes import QuoteOutcomes, compile_quote_outcomes_plan, score_quote_outcomes
from lightbulb.returns_ledger import ReturnsLedger, build_returns_ledger, compile_returns_plan
from lightbulb.review_decisions import ReviewDecisions, decide_review_actions
from lightbulb.stockouts import Stockouts, build_stockouts, compile_stockout_plan
from lightbulb.skills_development import SkillsDevelopment, build_skills_development, compile_skills_development_plan
from lightbulb.open_to_buy import OpenToBuy, build_open_to_buy, compile_open_to_buy_plan
from lightbulb.working_capital import WorkingCapital, build_working_capital, compile_working_capital_plan
from lightbulb.labour_sourcing import LabourSourcing, build_labour_sourcing, compile_labour_sourcing_plan
from lightbulb.price_probes import PriceProbes, compile_price_probe_plan, plan_price_probes
from lightbulb.primitive_runtime import (
    BusinessProcessPrimitive,
    PrimitiveEvent,
    PrimitiveExecutionContext,
    PrimitiveExecutionResult,
    PrimitiveExecutionStatus,
)
from lightbulb.product_margin import PriceVolumeMix, ProductMarginReport, build_product_margin, compile_product_margin_plan, price_volume_mix
from lightbulb.product_portfolio import ProductPortfolio, build_product_portfolio, compile_product_portfolio_plan
from lightbulb.rate_card import RateCard, build_rate_card, compile_rate_card_plan
from lightbulb.services_margin import ServicesMargin, build_services_margin, compile_services_margin_plan
from lightbulb.skills_inventory import SkillsInventory, build_skills_inventory
from lightbulb.supplier_scorecard import SupplierScorecard, build_supplier_scorecard, compile_supplier_scorecard_plan
from lightbulb.skills_matching import SkillsMatchReport, build_skills_match_report, compile_job_requirements, compile_skills_matching_plan, compile_skills_taxonomy, compile_worker_profile
from lightbulb.workforce_capacity import WorkforceCapacity, build_workforce_capacity

_EXAMPLE_COMPANY = "company-example"
_EXAMPLE_AS_OF = "2026-11-01T00:00:00Z"


class _Input(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class SourceState(_Input):
    """One replayed lifecycle state with the sealed plan it was produced under."""

    plan: dict[str, Any]
    state: dict[str, Any]


def _pairs(rows: tuple[SourceState, ...]) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    return [(row.plan, row.state) for row in rows]


def _failed(primitive: BusinessProcessPrimitive[Any, Any], exc: Exception) -> PrimitiveExecutionResult[Any]:
    return PrimitiveExecutionResult(status=PrimitiveExecutionStatus.FAILED, primitive_ref=primitive.primitive_ref, primitive_version=primitive.version, summary=f"{primitive.primitive_ref} rejected: {exc}", output=None)


def _completed(primitive: BusinessProcessPrimitive[Any, Any], output: Any, summary: str, event: str, payload: Mapping[str, Any]) -> PrimitiveExecutionResult[Any]:
    return PrimitiveExecutionResult(status=PrimitiveExecutionStatus.COMPLETED, primitive_ref=primitive.primitive_ref, primitive_version=primitive.version, summary=summary, output=output, events=[PrimitiveEvent(type=event, payload=dict(payload))])


class _LazyExample(Mapping[str, Any]):
    """Built on first read so importing the module stays cheap."""

    def __init__(self, factory: Any) -> None:
        self._factory, self._value = factory, None

    def _load(self) -> dict[str, Any]:
        if self._value is None:
            self._value = dict(self._factory())
        return self._value

    def __getitem__(self, key: str) -> Any:
        return self._load()[key]

    def __iter__(self) -> Any:
        return iter(self._load())

    def __len__(self) -> int:
        return len(self._load())


# --------------------------------------------------------------------------- #
# Product margin and price / volume / mix
# --------------------------------------------------------------------------- #


class BuildProductMarginInput(_Input):
    plan: dict[str, Any]
    window_start: str
    window_end: str
    as_of: str
    fulfilment_states: tuple[SourceState, ...] = ()
    inventory_states: tuple[SourceState, ...] = ()
    settlement_states: tuple[SourceState, ...] = ()
    catalog_states: tuple[SourceState, ...] = ()


def _example_margin_plan() -> dict[str, Any]:
    return compile_product_margin_plan(_EXAMPLE_COMPANY, currency="USD", overrides={"fulfilment_cost_per_order": "4", "payment_fee_percent": "2.9"}).to_dict()


class BuildProductMarginPrimitive(BusinessProcessPrimitive[BuildProductMarginInput, ProductMarginReport]):
    """What each SKU earned after every cost the chains proved."""

    primitive_ref = "commerce.build_product_margin"
    version = "1.0.0"
    title = "Build the product margin report"
    description = "Seal per-SKU units, gross revenue, discounts, returns, net revenue, landed cost of goods from the replayed stock positions, fees at the settlement batches' observed rate, fulfilment and return handling from the plan, contribution, margin, break-even units, and the revenue-to-contribution waterfall from replayed orders, stock positions, settlement batches, and the published catalog."
    input_model = BuildProductMarginInput
    output_model = ProductMarginReport
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs: ClassVar[Mapping[str, Any]] = _LazyExample(lambda: {"plan": _example_margin_plan(), "window_start": "2026-10-01T00:00:00Z", "window_end": "2026-11-01T00:00:00Z", "as_of": _EXAMPLE_AS_OF})

    def _execute(self, context: PrimitiveExecutionContext, inputs: BuildProductMarginInput) -> PrimitiveExecutionResult[ProductMarginReport]:
        try:
            report = build_product_margin(inputs.plan, fulfilment_states=_pairs(inputs.fulfilment_states), inventory_states=_pairs(inputs.inventory_states), settlement_states=_pairs(inputs.settlement_states), catalog_states=_pairs(inputs.catalog_states), window_start=inputs.window_start, window_end=inputs.window_end, as_of=inputs.as_of)
        except ValueError as exc:
            return _failed(self, exc)
        return _completed(self, report, f"Product margin: {len(report.rows)} SKU(s), net revenue {report.net_revenue} {report.currency}, contribution {report.contribution}.", "commerce.product_margin_built", {"report_digest": report.report_digest, "skus": len(report.rows), "contribution": str(report.contribution)})


class PriceVolumeMixInput(_Input):
    previous_report: dict[str, Any]
    current_report: dict[str, Any]


def _example_margin_report(window_start: str, window_end: str, as_of: str) -> dict[str, Any]:
    return build_product_margin(_example_margin_plan(), fulfilment_states=[], window_start=window_start, window_end=window_end, as_of=as_of).to_dict()


class PriceVolumeMixPrimitive(BusinessProcessPrimitive[PriceVolumeMixInput, PriceVolumeMix]):
    """Why revenue moved between two windows: price, volume, or mix."""

    primitive_ref = "commerce.price_volume_mix"
    version = "1.0.0"
    title = "Bridge two margin reports by price, volume, and mix"
    description = "Seal the exact decomposition of the revenue change between two sealed product margin reports into price, volume, and mix effects per SKU (continuing, new, dropped), summing to the change, with the largest driver named."
    input_model = PriceVolumeMixInput
    output_model = PriceVolumeMix
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs: ClassVar[Mapping[str, Any]] = _LazyExample(lambda: {"previous_report": _example_margin_report("2026-09-01T00:00:00Z", "2026-10-01T00:00:00Z", "2026-10-02T00:00:00Z"), "current_report": _example_margin_report("2026-10-01T00:00:00Z", "2026-11-01T00:00:00Z", _EXAMPLE_AS_OF)})

    def _execute(self, context: PrimitiveExecutionContext, inputs: PriceVolumeMixInput) -> PrimitiveExecutionResult[PriceVolumeMix]:
        try:
            bridge = price_volume_mix(inputs.previous_report, inputs.current_report)
        except ValueError as exc:
            return _failed(self, exc)
        return _completed(self, bridge, f"Revenue {bridge.previous_revenue} to {bridge.current_revenue}: price {bridge.price_effect}, volume {bridge.volume_effect}, mix {bridge.mix_effect}.", "commerce.price_volume_mix_built", {"variance_digest": bridge.variance_digest, "revenue_change": str(bridge.revenue_change)})


# --------------------------------------------------------------------------- #
# Product portfolio
# --------------------------------------------------------------------------- #


class BuildProductPortfolioInput(_Input):
    plan: dict[str, Any]
    margin_report: dict[str, Any]
    as_of: str
    previous_report: dict[str, Any] | None = None
    inventory_states: tuple[SourceState, ...] = ()


class BuildProductPortfolioPrimitive(BusinessProcessPrimitive[BuildProductPortfolioInput, ProductPortfolio]):
    """Every SKU placed by growth, margin, velocity, and cover, with one action each."""

    primitive_ref = "commerce.build_product_portfolio"
    version = "1.0.0"
    title = "Build the product portfolio"
    description = "Seal per-SKU velocity, growth against the previous window, contribution margin, revenue share, return rate, days of cover and sell-through from the replayed stock positions, a grow / harvest / fix / cut quadrant against the plan's thresholds, flags (overstocked, stockout risk, return problem, unpriced, uncosted), and one recommendation per SKU that names the number behind it."
    input_model = BuildProductPortfolioInput
    output_model = ProductPortfolio
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs: ClassVar[Mapping[str, Any]] = _LazyExample(lambda: {"plan": compile_product_portfolio_plan(_EXAMPLE_COMPANY, currency="USD").to_dict(), "margin_report": _example_margin_report("2026-10-01T00:00:00Z", "2026-11-01T00:00:00Z", _EXAMPLE_AS_OF), "as_of": _EXAMPLE_AS_OF})

    def _execute(self, context: PrimitiveExecutionContext, inputs: BuildProductPortfolioInput) -> PrimitiveExecutionResult[ProductPortfolio]:
        try:
            portfolio = build_product_portfolio(inputs.plan, margin_report=inputs.margin_report, previous_report=inputs.previous_report, inventory_states=_pairs(inputs.inventory_states), as_of=inputs.as_of)
        except ValueError as exc:
            return _failed(self, exc)
        return _completed(self, portfolio, f"Product portfolio: {len(portfolio.rows)} SKU(s), stock at cost {portfolio.stock_value} {portfolio.currency}; {portfolio.recommendations[0]}", "commerce.product_portfolio_built", {"portfolio_digest": portfolio.portfolio_digest, "skus": len(portfolio.rows), "by_quadrant": dict(portfolio.by_quadrant)})


# --------------------------------------------------------------------------- #
# Skills matching and labour sourcing
# --------------------------------------------------------------------------- #


class MatchSkillsInput(_Input):
    plan: dict[str, Any]
    taxonomy: dict[str, Any]
    jobs: tuple[dict[str, Any], ...]
    profiles: tuple[dict[str, Any], ...]
    as_of: str
    work_order_states: tuple[SourceState, ...] = ()


def _example_skills() -> dict[str, Any]:
    taxonomy = compile_skills_taxonomy(_EXAMPLE_COMPANY, skills=[{"skill_ref": "hydraulics", "name": "Hydraulic systems", "family": "mechanical"}, {"skill_ref": "electrical", "name": "Electrical work", "family": "electrical", "licence": True}])
    plan = compile_skills_matching_plan(_EXAMPLE_COMPANY, currency="USD")
    jobs = [compile_job_requirements("job:press-overhaul", title="Overhaul the press", kind="work_order", requirements=[{"skill_ref": "hydraulics", "minimum_level": 3}, {"skill_ref": "electrical", "minimum_level": 2}], hours_required="40", starts_at="2026-11-10T00:00:00Z", due_at="2026-11-20T00:00:00Z", budget="3000", currency="USD")]
    profiles = [
        compile_worker_profile("worker:jo", kind="employee", cost_rate="45", currency="USD", claims=[{"skill_ref": "hydraulics", "level": 4, "declared_by": "manager", "declared_at": "2026-06-01T00:00:00Z"}, {"skill_ref": "electrical", "level": 3, "declared_by": "licence", "declared_at": "2026-01-10T00:00:00Z", "expires_at": "2027-01-10T00:00:00Z"}], evidence=[{"skill_ref": "hydraulics", "kind": "timesheet", "hours": "120", "at": "2026-09-01T00:00:00Z", "source_ref": "wo:press-7:2026-W36", "source_digest": "ab" * 32}]),
        compile_worker_profile("worker:sam", kind="employee", cost_rate="40", currency="USD", claims=[{"skill_ref": "hydraulics", "level": 2, "declared_at": "2026-06-01T00:00:00Z"}]),
    ]
    return {"plan": plan.to_dict(), "taxonomy": taxonomy.to_dict(), "jobs": [job.to_dict() for job in jobs], "profiles": [profile.to_dict() for profile in profiles], "as_of": _EXAMPLE_AS_OF}


class MatchSkillsPrimitive(BusinessProcessPrimitive[MatchSkillsInput, SkillsMatchReport]):
    """Which worker fits which job, and why."""

    primitive_ref = "services.match_skills"
    version = "1.0.0"
    title = "Match workers to jobs by skill"
    description = "Seal every worker's fit for every job: effective skill levels from claims corroborated or discounted by the work order chain's decayed recorded hours and by transfers from adjacent skills, scored on proficiency, evidence, availability, and cost with sealed weights; mandatory shortfalls, expired licences, low availability, and over-budget cost disqualify with the reason; a team is assembled for the headcount and every gap names the best worker seen."
    input_model = MatchSkillsInput
    output_model = SkillsMatchReport
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs: ClassVar[Mapping[str, Any]] = _LazyExample(_example_skills)

    def _execute(self, context: PrimitiveExecutionContext, inputs: MatchSkillsInput) -> PrimitiveExecutionResult[SkillsMatchReport]:
        try:
            report = build_skills_match_report(inputs.plan, taxonomy=inputs.taxonomy, jobs=list(inputs.jobs), profiles=list(inputs.profiles), work_order_states=_pairs(inputs.work_order_states), as_of=inputs.as_of)
        except ValueError as exc:
            return _failed(self, exc)
        return _completed(self, report, f"Skills match: {report.staffed_jobs} of {len(report.jobs)} job(s) staffed from {report.workers} worker(s), {report.open_gaps} gap(s).", "services.skills_matched", {"report_digest": report.report_digest, "staffed_jobs": report.staffed_jobs, "open_gaps": report.open_gaps})


class SourceLabourInput(_Input):
    plan: dict[str, Any]
    match_report: dict[str, Any]
    taxonomy: dict[str, Any]
    matching_plan: dict[str, Any]
    jobs: tuple[dict[str, Any], ...]
    profiles: tuple[dict[str, Any], ...]
    as_of: str
    hiring_plan: dict[str, Any] | None = None


def _example_sourcing() -> dict[str, Any]:
    skills = _example_skills()
    report = build_skills_match_report(skills["plan"], taxonomy=skills["taxonomy"], jobs=skills["jobs"], profiles=skills["profiles"], as_of=skills["as_of"])
    plan = compile_labour_sourcing_plan(_EXAMPLE_COMPANY, currency="USD", roles=[{"role_ref": "role:electrician", "title": "Licensed electrician", "skills": {"electrical": 4}, "pay_rate": "62", "pay_rate_uom": "hour"}], market_rates={"hydraulics": "110", "electrical": "125"})
    return {"plan": plan.to_dict(), "match_report": report.to_dict(), "taxonomy": skills["taxonomy"], "matching_plan": skills["plan"], "jobs": skills["jobs"], "profiles": skills["profiles"], "as_of": skills["as_of"]}


class SourceLabourPrimitive(BusinessProcessPrimitive[SourceLabourInput, LabourSourcing]):
    """Close every skill gap by the cheapest feasible route, with the alternatives priced."""

    primitive_ref = "services.source_labour"
    version = "1.0.0"
    title = "Source the labour for every skill gap"
    description = "Seal, for every gap in a skills match report, the priced options to assign a worker on the books, upskill an employee in reach, contract at the typed market rate, or hire into a role at the hiring chain's pay band (only when demand is recurring and the lead time fits), choosing the cheapest feasible route make-before-buy; plus the skill capacity ledger and the requisitions recurring shortfalls justify, shaped for the hiring chain."
    input_model = SourceLabourInput
    output_model = LabourSourcing
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs: ClassVar[Mapping[str, Any]] = _LazyExample(_example_sourcing)

    def _execute(self, context: PrimitiveExecutionContext, inputs: SourceLabourInput) -> PrimitiveExecutionResult[LabourSourcing]:
        try:
            hiring_plan = None
            if inputs.hiring_plan is not None:
                from lightbulb.hiring_chain import HiringChainPlan

                hiring_plan = HiringChainPlan.model_validate(dict(inputs.hiring_plan))
            sourcing = build_labour_sourcing(inputs.plan, match_report=inputs.match_report, taxonomy=inputs.taxonomy, matching_plan=inputs.matching_plan, jobs=list(inputs.jobs), profiles=list(inputs.profiles), hiring_plan=hiring_plan, as_of=inputs.as_of)
        except ValueError as exc:
            return _failed(self, exc)
        return _completed(self, sourcing, f"Labour sourcing: {len(sourcing.actions)} gap(s) for {sourcing.total_cost} {sourcing.currency}, {len(sourcing.requisitions)} requisition(s).", "services.labour_sourced", {"sourcing_digest": sourcing.sourcing_digest, "actions": len(sourcing.actions), "by_kind": dict(sourcing.by_kind), "total_cost": str(sourcing.total_cost)})


# --------------------------------------------------------------------------- #
# Services margin, skills inventory, and price probes
# --------------------------------------------------------------------------- #


class BuildServicesMarginInput(_Input):
    plan: dict[str, Any]
    window_start: str
    window_end: str
    as_of: str
    engagement_states: tuple[SourceState, ...] = ()
    work_order_states: tuple[SourceState, ...] = ()
    profiles: tuple[dict[str, Any], ...] = ()


class BuildServicesMarginPrimitive(BusinessProcessPrimitive[BuildServicesMarginInput, ServicesMargin]):
    """What each engagement, role, and worker earned against what they cost."""

    primitive_ref = "services.build_services_margin"
    version = "1.0.0"
    title = "Build the services margin"
    description = "Seal per engagement the hours at the adopted bill and cost rates, revenue capped at the contract value, margin, burn, value at risk, and a verdict; per role the blended rates, margin, and the bill rate the target margin needs; per worker billable hours from approved time entries, internal hours from the work order chain, availability from the profiles, and utilisation."
    input_model = BuildServicesMarginInput
    output_model = ServicesMargin
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs: ClassVar[Mapping[str, Any]] = _LazyExample(lambda: {"plan": compile_services_margin_plan(_EXAMPLE_COMPANY, currency="USD").to_dict(), "window_start": "2026-10-01T00:00:00Z", "window_end": "2026-11-01T00:00:00Z", "as_of": _EXAMPLE_AS_OF, "profiles": ({"worker_ref": "worker:jo", "hours_per_week": "38"},)})

    def _execute(self, context: PrimitiveExecutionContext, inputs: BuildServicesMarginInput) -> PrimitiveExecutionResult[ServicesMargin]:
        try:
            document = build_services_margin(inputs.plan, engagement_states=_pairs(inputs.engagement_states), work_order_states=_pairs(inputs.work_order_states), profiles=list(inputs.profiles), window_start=inputs.window_start, window_end=inputs.window_end, as_of=inputs.as_of)
        except ValueError as exc:
            return _failed(self, exc)
        return _completed(self, document, f"Services margin: {len(document.engagements)} engagement(s), margin {document.margin} {document.currency} on {document.recognisable_value} recognisable; value at risk {document.value_at_risk}.", "services.margin_built", {"margin_digest": document.margin_digest, "margin": str(document.margin), "by_verdict": dict(document.by_verdict)})


class BuildSkillsInventoryInput(_Input):
    plan: dict[str, Any]
    taxonomy: dict[str, Any]
    profiles: tuple[dict[str, Any], ...]
    as_of: str
    jobs: tuple[dict[str, Any], ...] = ()
    work_order_states: tuple[SourceState, ...] = ()
    minimum_depth: int = 2
    licence_horizon_days: int = 90


class BuildSkillsInventoryPrimitive(BusinessProcessPrimitive[BuildSkillsInventoryInput, SkillsInventory]):
    """How deep the company is in every skill, and where one person is the only one."""

    primitive_ref = "services.build_skills_inventory"
    version = "1.0.0"
    title = "Build the skills inventory"
    description = "Seal per skill the holders, the workers qualified at the level the jobs demand, verified and expert counts, the best worker, a depth status (absent, single point of failure, thin, deep against the minimum depth), every licence lapsing inside the horizon with the days left, and the nearest upskilling candidates, from the same corroborated standing the match report uses."
    input_model = BuildSkillsInventoryInput
    output_model = SkillsInventory
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs: ClassVar[Mapping[str, Any]] = _LazyExample(lambda: {key: value for key, value in _example_skills().items() if key in {"plan", "taxonomy", "profiles", "jobs", "as_of"}})

    def _execute(self, context: PrimitiveExecutionContext, inputs: BuildSkillsInventoryInput) -> PrimitiveExecutionResult[SkillsInventory]:
        try:
            inventory = build_skills_inventory(inputs.plan, taxonomy=inputs.taxonomy, profiles=list(inputs.profiles), jobs=list(inputs.jobs), work_order_states=_pairs(inputs.work_order_states), as_of=inputs.as_of, minimum_depth=inputs.minimum_depth, licence_horizon_days=inputs.licence_horizon_days)
        except ValueError as exc:
            return _failed(self, exc)
        return _completed(self, inventory, f"Skills inventory: {len(inventory.skills)} skill(s) across {inventory.workers} worker(s); {inventory.licence_alerts} licence alert(s); {inventory.recommendations[0]}", "services.skills_inventoried", {"inventory_digest": inventory.inventory_digest, "by_status": dict(inventory.by_status), "licence_alerts": inventory.licence_alerts})


class PlanPriceProbesInput(_Input):
    plan: dict[str, Any]
    margin_report: dict[str, Any]
    as_of: str
    portfolio: dict[str, Any] | None = None


class PlanPriceProbesPrimitive(BusinessProcessPrimitive[PlanPriceProbesInput, PriceProbes]):
    """What each price move does to unit contribution, and how much volume it can afford to lose."""

    primitive_ref = "commerce.plan_price_probes"
    version = "1.0.0"
    title = "Plan the price probes"
    description = "Seal per priced and costed SKU the realised price, unit costs, unit contribution, floor price, and for every candidate move the new price, unit contribution, margin, and break-even volume change; recommend the largest increase inside the break-even tolerance, reprice a SKU under the minimum margin to its floor, and let the portfolio's actions decide which SKUs are probed. Every number is a break-even; nothing estimates elasticity."
    input_model = PlanPriceProbesInput
    output_model = PriceProbes
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs: ClassVar[Mapping[str, Any]] = _LazyExample(lambda: {"plan": compile_price_probe_plan(_EXAMPLE_COMPANY, currency="USD").to_dict(), "margin_report": _example_margin_report("2026-10-01T00:00:00Z", "2026-11-01T00:00:00Z", _EXAMPLE_AS_OF), "as_of": _EXAMPLE_AS_OF})

    def _execute(self, context: PrimitiveExecutionContext, inputs: PlanPriceProbesInput) -> PrimitiveExecutionResult[PriceProbes]:
        try:
            probes = plan_price_probes(inputs.plan, margin_report=inputs.margin_report, portfolio=inputs.portfolio, as_of=inputs.as_of)
        except ValueError as exc:
            return _failed(self, exc)
        return _completed(self, probes, f"Price probes: {len(probes.skus)} SKU(s); {probes.recommendations[0]}", "commerce.price_probes_planned", {"probes_digest": probes.probes_digest, "by_action": dict(probes.by_action), "recommended_moves": len(probes.recommended_moves)})


# --------------------------------------------------------------------------- #
# Contribution bridge, rate card, and workforce capacity
# --------------------------------------------------------------------------- #


class BuildContributionBridgeInput(_Input):
    previous_report: dict[str, Any]
    current_report: dict[str, Any]


class BuildContributionBridgePrimitive(BusinessProcessPrimitive[BuildContributionBridgeInput, ContributionBridge]):
    """Exactly why contribution moved between two windows, SKU by SKU."""

    primitive_ref = "commerce.build_contribution_bridge"
    version = "1.0.0"
    title = "Build the contribution bridge"
    description = "Seal the exact decomposition of the change in contribution between two sealed product margin reports into volume, mix, price, fee, cost of goods, fulfilment, and return handling effects per SKU (continuing, new, dropped) that sum to the change, with the largest driver named."
    input_model = BuildContributionBridgeInput
    output_model = ContributionBridge
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs: ClassVar[Mapping[str, Any]] = _LazyExample(lambda: {"previous_report": _example_margin_report("2026-09-01T00:00:00Z", "2026-10-01T00:00:00Z", "2026-10-02T00:00:00Z"), "current_report": _example_margin_report("2026-10-01T00:00:00Z", "2026-11-01T00:00:00Z", _EXAMPLE_AS_OF)})

    def _execute(self, context: PrimitiveExecutionContext, inputs: BuildContributionBridgeInput) -> PrimitiveExecutionResult[ContributionBridge]:
        try:
            bridge = build_contribution_bridge(inputs.previous_report, inputs.current_report)
        except ValueError as exc:
            return _failed(self, exc)
        return _completed(self, bridge, f"Contribution {bridge.previous_contribution} to {bridge.current_contribution}: {bridge.explanation[0]}", "commerce.contribution_bridge_built", {"bridge_digest": bridge.bridge_digest, "change": str(bridge.change), "effects": {name: str(amount) for name, amount in bridge.effects.items()}})


class BuildRateCardInput(_Input):
    plan: dict[str, Any]
    services_margin: dict[str, Any]
    as_of: str


class BuildRateCardPrimitive(BusinessProcessPrimitive[BuildRateCardInput, RateCard]):
    """The bill rate each role needs once the unbilled hours are counted."""

    primitive_ref = "services.build_rate_card"
    version = "1.0.0"
    title = "Build the rate card"
    description = "Seal per role, from a sealed services margin, the loaded cost of a billable hour (cost rate plus overhead over the target utilisation), the bill rate the target margin needs, the gap, the margin the current rate really earns, the market position and the utilisation a typed market rate would need, and the recommendation: hold, raise, raise in steps past the cap, or fix cost or utilisation when the requirement sits above the market."
    input_model = BuildRateCardInput
    output_model = RateCard
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs: ClassVar[Mapping[str, Any]] = _LazyExample(lambda: {"plan": compile_rate_card_plan(_EXAMPLE_COMPANY, currency="USD", market_rates={"role:consultant": "150"}).to_dict(), "services_margin": build_services_margin(compile_services_margin_plan(_EXAMPLE_COMPANY, currency="USD"), engagement_states=[], window_start="2026-10-01T00:00:00Z", window_end="2026-11-01T00:00:00Z", as_of=_EXAMPLE_AS_OF).to_dict(), "as_of": _EXAMPLE_AS_OF})

    def _execute(self, context: PrimitiveExecutionContext, inputs: BuildRateCardInput) -> PrimitiveExecutionResult[RateCard]:
        try:
            card = build_rate_card(inputs.plan, services_margin=inputs.services_margin, as_of=inputs.as_of)
        except ValueError as exc:
            return _failed(self, exc)
        return _completed(self, card, f"Rate card: {len(card.rows)} role(s); {card.recommendations[0]}", "services.rate_card_built", {"card_digest": card.card_digest, "by_action": dict(card.by_action)})


class BuildWorkforceCapacityInput(_Input):
    plan: dict[str, Any]
    taxonomy: dict[str, Any]
    profiles: tuple[dict[str, Any], ...]
    jobs: tuple[dict[str, Any], ...]
    as_of: str
    work_order_states: tuple[SourceState, ...] = ()
    weeks: int = 8


class BuildWorkforceCapacityPrimitive(BusinessProcessPrimitive[BuildWorkforceCapacityInput, WorkforceCapacity]):
    """Week by week, the hours each skill is asked for against the qualified hours on offer."""

    primitive_ref = "services.build_workforce_capacity"
    version = "1.0.0"
    title = "Build the workforce capacity plan"
    description = "Seal per week and skill the demand (each job's hours spread over its window and across its requirements by weight), the supply (every qualified worker's weekly hours inside their availability), utilisation, shortfall, and bench; per skill the peak week, the weeks short in a row (four or more is the case for a hire), and the bench cost; per worker the hours asked against the hours offered. Nothing assigns anyone or predicts demand."
    input_model = BuildWorkforceCapacityInput
    output_model = WorkforceCapacity
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs: ClassVar[Mapping[str, Any]] = _LazyExample(lambda: {key: value for key, value in _example_skills().items() if key in {"plan", "taxonomy", "profiles", "jobs", "as_of"}})

    def _execute(self, context: PrimitiveExecutionContext, inputs: BuildWorkforceCapacityInput) -> PrimitiveExecutionResult[WorkforceCapacity]:
        try:
            capacity = build_workforce_capacity(inputs.plan, taxonomy=inputs.taxonomy, profiles=list(inputs.profiles), jobs=list(inputs.jobs), work_order_states=_pairs(inputs.work_order_states), as_of=inputs.as_of, weeks=inputs.weeks)
        except ValueError as exc:
            return _failed(self, exc)
        return _completed(self, capacity, f"Workforce capacity over {capacity.weeks} week(s): demand {capacity.demand_hours}h against {capacity.supply_hours}h; shortfall {capacity.shortfall_hours}h, bench {capacity.bench_hours}h costing {capacity.bench_cost}.", "services.workforce_capacity_built", {"capacity_digest": capacity.capacity_digest, "shortfall_hours": str(capacity.shortfall_hours), "bench_hours": str(capacity.bench_hours)})


# --------------------------------------------------------------------------- #
# Job quote and customer profitability
# --------------------------------------------------------------------------- #


class BuildJobQuoteInput(_Input):
    plan: dict[str, Any]
    job: dict[str, Any]
    taxonomy: dict[str, Any]
    matching_plan: dict[str, Any]
    profiles: tuple[dict[str, Any], ...]
    as_of: str
    work_order_states: tuple[SourceState, ...] = ()
    offered_price: str | None = None


class BuildJobQuotePrimitive(BusinessProcessPrimitive[BuildJobQuoteInput, JobQuote]):
    """Should we take this job at this price?"""

    primitive_ref = "services.build_job_quote"
    version = "1.0.0"
    title = "Quote a job"
    description = "Seal the matched team for a job (from the same corroborated standing the match report uses), its direct cost plus a contingency on every stretch fit, the loaded cost carrying overhead and the target utilisation, the floor and target prices, and the verdict against the offered price or the job's budget (bid, negotiate, no bid, cannot staff, unpriced) with the risks and gaps named."
    input_model = BuildJobQuoteInput
    output_model = JobQuote
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs: ClassVar[Mapping[str, Any]] = _LazyExample(lambda: {"plan": compile_job_quote_plan(_EXAMPLE_COMPANY, currency="USD").to_dict(), **{key: value for key, value in _example_skills().items() if key in {"taxonomy", "profiles", "as_of"}}, "matching_plan": _example_skills()["plan"], "job": _example_skills()["jobs"][0], "offered_price": "4500"})

    def _execute(self, context: PrimitiveExecutionContext, inputs: BuildJobQuoteInput) -> PrimitiveExecutionResult[JobQuote]:
        try:
            quote = build_job_quote(inputs.plan, job=inputs.job, taxonomy=inputs.taxonomy, matching_plan=inputs.matching_plan, profiles=list(inputs.profiles), work_order_states=_pairs(inputs.work_order_states), offered_price=inputs.offered_price, as_of=inputs.as_of)
        except ValueError as exc:
            return _failed(self, exc)
        return _completed(self, quote, f"Job quote {quote.job_ref} [{quote.verdict}]: {quote.rationale}", "services.job_quoted", {"quote_digest": quote.quote_digest, "verdict": quote.verdict, "loaded_cost": str(quote.loaded_cost), "target_price": str(quote.target_price)})


class BuildCustomerProfitabilityInput(_Input):
    plan: dict[str, Any]
    margin_report: dict[str, Any]
    as_of: str
    fulfilment_states: tuple[SourceState, ...] = ()
    target_margin_percent: str = "30"
    return_rate_threshold_percent: str = "10"
    core_share_percent: str = "80"


class BuildCustomerProfitabilityPrimitive(BusinessProcessPrimitive[BuildCustomerProfitabilityInput, CustomerProfitability]):
    """What each customer earned after the cost to serve them."""

    primitive_ref = "commerce.build_customer_profitability"
    version = "1.0.0"
    title = "Build the customer profitability table"
    description = "Seal per customer (the opaque ref each replayed order was captured with) orders, units, returns, net revenue, landed cost, fees, fulfilment, return handling, contribution, margin, average order value, return rate, rank, share, and a class (core, promising, drain, long tail), with the concentration and whether the totals tie to the sealed margin report."
    input_model = BuildCustomerProfitabilityInput
    output_model = CustomerProfitability
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs: ClassVar[Mapping[str, Any]] = _LazyExample(lambda: {"plan": _example_margin_plan(), "margin_report": _example_margin_report("2026-10-01T00:00:00Z", "2026-11-01T00:00:00Z", _EXAMPLE_AS_OF), "as_of": _EXAMPLE_AS_OF})

    def _execute(self, context: PrimitiveExecutionContext, inputs: BuildCustomerProfitabilityInput) -> PrimitiveExecutionResult[CustomerProfitability]:
        try:
            document = build_customer_profitability(inputs.plan, margin_report=inputs.margin_report, fulfilment_states=_pairs(inputs.fulfilment_states), as_of=inputs.as_of, target_margin_percent=inputs.target_margin_percent, return_rate_threshold_percent=inputs.return_rate_threshold_percent, core_share_percent=inputs.core_share_percent)
        except ValueError as exc:
            return _failed(self, exc)
        return _completed(self, document, f"Customer profitability: {document.customers} customer(s), contribution {document.contribution} {document.currency}; {document.recommendations[0]}", "commerce.customer_profitability_built", {"profitability_digest": document.profitability_digest, "customers": document.customers, "by_class": dict(document.by_class)})


# --------------------------------------------------------------------------- #
# The intelligence review
# --------------------------------------------------------------------------- #


class BuildIntelligenceReviewInput(_Input):
    review_ref: str
    company_ref: str
    currency: str
    as_of: str
    documents: dict[str, Any]
    max_age_days: int = 7


class BuildIntelligenceReviewPrimitive(BusinessProcessPrimitive[BuildIntelligenceReviewInput, IntelligenceReview]):
    """Every product and labour document read together, its actions ranked by the money at stake."""

    primitive_ref = "company.build_intelligence_review"
    version = "1.0.0"
    title = "Build the intelligence review"
    description = "Seal the weekly review over whichever sealed product and labour documents are supplied (margin, portfolio, price probes, contribution bridge, customer profitability, skills match, labour sourcing, skills inventory, services margin, rate card, workforce capacity, job quotes): each verified by its seal, refused for another company or currency, marked stale past the horizon, and every recommendation lifted into one list ranked by severity then the document's own money at stake, with blind spots named."
    input_model = BuildIntelligenceReviewInput
    output_model = IntelligenceReview
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs: ClassVar[Mapping[str, Any]] = _LazyExample(lambda: {"review_ref": "review-2026-W44", "company_ref": _EXAMPLE_COMPANY, "currency": "USD", "as_of": _EXAMPLE_AS_OF, "documents": {"product_margin": _example_margin_report("2026-10-01T00:00:00Z", "2026-11-01T00:00:00Z", _EXAMPLE_AS_OF)}})

    def _execute(self, context: PrimitiveExecutionContext, inputs: BuildIntelligenceReviewInput) -> PrimitiveExecutionResult[IntelligenceReview]:
        try:
            review = build_intelligence_review(review_ref=inputs.review_ref, company_ref=inputs.company_ref, currency=inputs.currency, as_of=inputs.as_of, max_age_days=inputs.max_age_days, documents=inputs.documents)
        except ValueError as exc:
            return _failed(self, exc)
        return _completed(self, review, f"Intelligence review {review.review_ref}: {review.headline}", "company.intelligence_reviewed", {"review_digest": review.review_digest, "actions": len(review.actions), "money_at_stake": str(review.money_at_stake), "by_severity": dict(review.by_severity)})


# --------------------------------------------------------------------------- #
# Supplier scorecard and job costing
# --------------------------------------------------------------------------- #


class BuildSupplierScorecardInput(_Input):
    plan: dict[str, Any]
    window_start: str
    window_end: str
    as_of: str
    inventory_states: tuple[SourceState, ...] = ()


class BuildSupplierScorecardPrimitive(BusinessProcessPrimitive[BuildSupplierScorecardInput, SupplierScorecard]):
    """How every goods supplier actually performed."""

    primitive_ref = "commerce.build_supplier_scorecard"
    version = "1.0.0"
    title = "Build the supplier scorecard"
    description = "Seal per supplier, from the replayed stock positions' purchases, receipts, and landed costs, the fill rate, on-time receipts against the expected date, the actual lead time against the policy, the price against standard cost, the landed premium, shrinkage and write-downs, single-source exposure, and a grade (reliable, watch, replace, unproven) with the number behind it."
    input_model = BuildSupplierScorecardInput
    output_model = SupplierScorecard
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs: ClassVar[Mapping[str, Any]] = _LazyExample(lambda: {"plan": compile_supplier_scorecard_plan(_EXAMPLE_COMPANY, currency="USD").to_dict(), "window_start": "2026-10-01T00:00:00Z", "window_end": "2026-11-01T00:00:00Z", "as_of": _EXAMPLE_AS_OF})

    def _execute(self, context: PrimitiveExecutionContext, inputs: BuildSupplierScorecardInput) -> PrimitiveExecutionResult[SupplierScorecard]:
        try:
            card = build_supplier_scorecard(inputs.plan, inventory_states=_pairs(inputs.inventory_states), window_start=inputs.window_start, window_end=inputs.window_end, as_of=inputs.as_of)
        except ValueError as exc:
            return _failed(self, exc)
        return _completed(self, card, f"Supplier scorecard: {len(card.suppliers)} supplier(s), {card.purchases} purchase(s) for {card.committed_amount} {card.currency}; {card.recommendations[0]}", "commerce.supplier_scorecard_built", {"scorecard_digest": card.scorecard_digest, "by_grade": dict(card.by_grade)})


class BuildJobCostingInput(_Input):
    plan: dict[str, Any]
    window_start: str
    window_end: str
    as_of: str
    work_order_states: tuple[SourceState, ...] = ()
    contractor_states: tuple[SourceState, ...] = ()


class BuildJobCostingPrimitive(BusinessProcessPrimitive[BuildJobCostingInput, JobCosting]):
    """What every job actually cost against its estimate."""

    primitive_ref = "services.build_job_costing"
    version = "1.0.0"
    title = "Build the job costing"
    description = "Seal from the replayed work orders and contractor engagements: per job the estimate, actual, variance, cost mix, labour hours, and on-time; per kind the estimating bias and the overrun and on-time rates; per asset the total cost and whether it is for review; per contractor the approved work against invoices and payments, with the recommendations that name the number."
    input_model = BuildJobCostingInput
    output_model = JobCosting
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs: ClassVar[Mapping[str, Any]] = _LazyExample(lambda: {"plan": compile_job_costing_plan(_EXAMPLE_COMPANY, currency="USD").to_dict(), "window_start": "2026-10-01T00:00:00Z", "window_end": "2026-11-01T00:00:00Z", "as_of": _EXAMPLE_AS_OF})

    def _execute(self, context: PrimitiveExecutionContext, inputs: BuildJobCostingInput) -> PrimitiveExecutionResult[JobCosting]:
        try:
            costing = build_job_costing(inputs.plan, work_order_states=_pairs(inputs.work_order_states), contractor_states=_pairs(inputs.contractor_states), window_start=inputs.window_start, window_end=inputs.window_end, as_of=inputs.as_of)
        except ValueError as exc:
            return _failed(self, exc)
        return _completed(self, costing, f"Job costing: {len(costing.jobs)} job(s), estimated {costing.estimated_cost} against actual {costing.actual_cost} {costing.currency}; {costing.recommendations[0]}", "services.job_costing_built", {"costing_digest": costing.costing_digest, "variance": str(costing.variance), "overrun_jobs": costing.overrun_jobs})


# --------------------------------------------------------------------------- #
# Open to buy
# --------------------------------------------------------------------------- #


class BuildOpenToBuyInput(_Input):
    plan: dict[str, Any]
    portfolio: dict[str, Any]
    margin_report: dict[str, Any]
    as_of: str
    budget_envelope: dict[str, Any] | None = None


def _example_open_to_buy() -> dict[str, Any]:
    report = _example_margin_report("2026-10-01T00:00:00Z", "2026-11-01T00:00:00Z", _EXAMPLE_AS_OF)
    portfolio = build_product_portfolio(compile_product_portfolio_plan(_EXAMPLE_COMPANY, currency="USD"), margin_report=report, as_of=_EXAMPLE_AS_OF).to_dict()
    return {"plan": compile_open_to_buy_plan(_EXAMPLE_COMPANY, currency="USD").to_dict(), "portfolio": portfolio, "margin_report": report, "as_of": _EXAMPLE_AS_OF}


class BuildOpenToBuyPrimitive(BusinessProcessPrimitive[BuildOpenToBuyInput, OpenToBuy]):
    """How much of each SKU to order now, inside the cash allowed."""

    primitive_ref = "commerce.build_open_to_buy"
    version = "1.0.0"
    title = "Build the open-to-buy list"
    description = "Seal per SKU the demand over the lead time plus the target cover from the portfolio's velocity, the units to order at the landed cost, the priority by contribution per unit, and what is funded inside the cash envelope's one-time capacity capped by the plan's maximum spend, with run-down, discontinue, and unmeasured SKUs never bought; the funded lines are shaped for the inventory chain's reorder proposal."
    input_model = BuildOpenToBuyInput
    output_model = OpenToBuy
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs: ClassVar[Mapping[str, Any]] = _LazyExample(_example_open_to_buy)

    def _execute(self, context: PrimitiveExecutionContext, inputs: BuildOpenToBuyInput) -> PrimitiveExecutionResult[OpenToBuy]:
        try:
            buy = build_open_to_buy(inputs.plan, portfolio=inputs.portfolio, margin_report=inputs.margin_report, budget_envelope=inputs.budget_envelope, as_of=inputs.as_of)
        except ValueError as exc:
            return _failed(self, exc)
        return _completed(self, buy, f"Open to buy: {buy.requested_cost} {buy.currency} requested, {buy.funded_cost} funded, {buy.deferred_cost} deferred; {buy.recommendations[0]}", "commerce.open_to_buy_built", {"buy_digest": buy.buy_digest, "funded_cost": str(buy.funded_cost), "by_decision": dict(buy.by_decision)})


# --------------------------------------------------------------------------- #
# Working capital and review outcomes
# --------------------------------------------------------------------------- #


class BuildWorkingCapitalInput(_Input):
    plan: dict[str, Any]
    window_start: str
    window_end: str
    as_of: str
    collections_states: tuple[SourceState, ...] = ()
    payables_states: tuple[SourceState, ...] = ()
    inventory_states: tuple[SourceState, ...] = ()
    margin_report: dict[str, Any] | None = None
    books: dict[str, Any] | None = None


class BuildWorkingCapitalPrimitive(BusinessProcessPrimitive[BuildWorkingCapitalInput, WorkingCapital]):
    """How many days cash sits in receivables and stock less the days suppliers wait, and which lever frees the most."""

    primitive_ref = "finance.build_working_capital"
    version = "1.0.0"
    title = "Build the working capital document"
    description = "Seal the cash conversion cycle over the window from the replayed chains: days sales outstanding and the realised days to collect from the receivables, days payable outstanding and the realised days to pay from the bills, days of stock from the positions over the margin report's cost of goods, each against the plan's target with the cash a day of improvement frees, the cash tied up, and a recommendation that names the lever freeing the most; a metric whose flow is missing from the window is left unknown, never estimated."
    input_model = BuildWorkingCapitalInput
    output_model = WorkingCapital
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs: ClassVar[Mapping[str, Any]] = _LazyExample(lambda: {"plan": compile_working_capital_plan(_EXAMPLE_COMPANY, currency="USD").to_dict(), "window_start": "2026-10-01T00:00:00Z", "window_end": "2026-11-01T00:00:00Z", "as_of": _EXAMPLE_AS_OF, "margin_report": _example_margin_report("2026-10-01T00:00:00Z", "2026-11-01T00:00:00Z", _EXAMPLE_AS_OF)})

    def _execute(self, context: PrimitiveExecutionContext, inputs: BuildWorkingCapitalInput) -> PrimitiveExecutionResult[WorkingCapital]:
        try:
            capital = build_working_capital(inputs.plan, collections_states=_pairs(inputs.collections_states), payables_states=_pairs(inputs.payables_states), inventory_states=_pairs(inputs.inventory_states), margin_report=inputs.margin_report, books=inputs.books, window_start=inputs.window_start, window_end=inputs.window_end, as_of=inputs.as_of)
        except ValueError as exc:
            return _failed(self, exc)
        cycle = "unknown" if capital.cash_conversion_days is None else f"{capital.cash_conversion_days} day(s)"
        return _completed(self, capital, f"Working capital: cash conversion cycle {cycle}, {capital.cash_tied} {capital.currency} tied up, {capital.cash_to_free} to free" + (f"; {capital.recommendations[0]}" if capital.recommendations else ""), "finance.working_capital_built", {"capital_digest": capital.capital_digest, "cash_tied": str(capital.cash_tied), "cash_to_free": str(capital.cash_to_free)})


class ScoreReviewOutcomesInput(_Input):
    previous: dict[str, Any]
    current: dict[str, Any]


def _example_review_outcomes() -> dict[str, Any]:
    report = _example_margin_report("2026-10-01T00:00:00Z", "2026-11-01T00:00:00Z", _EXAMPLE_AS_OF)
    first = build_intelligence_review(review_ref="review-2026-W44", company_ref=_EXAMPLE_COMPANY, currency="USD", as_of=_EXAMPLE_AS_OF, documents={"product_margin": report}).to_dict()
    second = build_intelligence_review(review_ref="review-2026-W45", company_ref=_EXAMPLE_COMPANY, currency="USD", as_of="2026-11-08T00:00:00Z", max_age_days=14, documents={"product_margin": report}, previous=first).to_dict()
    return {"previous": first, "current": second}


class ScoreReviewOutcomesPrimitive(BusinessProcessPrimitive[ScoreReviewOutcomesInput, ReviewOutcomes]):
    """What happened to last review's actions by this one."""

    primitive_ref = "company.score_review_outcomes"
    version = "1.0.0"
    title = "Score the review outcomes"
    description = "Line two sealed intelligence reviews up action by action (same source, kind, and subject) and seal, per action, carried or cleared with the money at stake then and now, the roll-up per source document, the clearance rate, the money released, and the actions the current review raised anew; nothing here judges why an action cleared."
    input_model = ScoreReviewOutcomesInput
    output_model = ReviewOutcomes
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs: ClassVar[Mapping[str, Any]] = _LazyExample(_example_review_outcomes)

    def _execute(self, context: PrimitiveExecutionContext, inputs: ScoreReviewOutcomesInput) -> PrimitiveExecutionResult[ReviewOutcomes]:
        try:
            outcomes = score_review_outcomes(inputs.previous, inputs.current)
        except ValueError as exc:
            return _failed(self, exc)
        return _completed(self, outcomes, f"Review outcomes {outcomes.previous_review_ref} to {outcomes.current_review_ref}: {outcomes.verdict}", "company.review_outcomes_scored", {"outcomes_digest": outcomes.outcomes_digest, "cleared": outcomes.cleared, "carried": outcomes.carried, "money_released": str(outcomes.money_released)})


# --------------------------------------------------------------------------- #
# Break-even and probe outcomes
# --------------------------------------------------------------------------- #


class BuildBreakEvenInput(_Input):
    plan: dict[str, Any]
    window_start: str
    window_end: str
    as_of: str
    margin_report: dict[str, Any] | None = None
    services_margin: dict[str, Any] | None = None
    register_states: tuple[SourceState, ...] = ()
    books: dict[str, Any] | None = None


class BuildBreakEvenPrimitive(BusinessProcessPrimitive[BuildBreakEvenInput, BreakEven]):
    """The revenue that covers the fixed cost the registers prove, and how far above or below it the window ran."""

    primitive_ref = "finance.build_break_even"
    version = "1.0.0"
    title = "Build the break-even document"
    description = "Seal the break-even over the window from the sealed contribution documents (the margin report for goods, the services margin for engagements) and the replayed cost registers overlapping the window, prorated by day and stripped of the source kinds a contribution document already carries: the operating result, the break-even revenue at the blended contribution margin, the margin of safety, the operating leverage, and the revenue, margin, or fixed-cost change that closes a gap; no register means the fixed cost is unknown, never zero."
    input_model = BuildBreakEvenInput
    output_model = BreakEven
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs: ClassVar[Mapping[str, Any]] = _LazyExample(lambda: {"plan": compile_break_even_plan(_EXAMPLE_COMPANY, currency="USD").to_dict(), "window_start": "2026-10-01T00:00:00Z", "window_end": "2026-11-01T00:00:00Z", "as_of": _EXAMPLE_AS_OF, "margin_report": _example_margin_report("2026-10-01T00:00:00Z", "2026-11-01T00:00:00Z", _EXAMPLE_AS_OF)})

    def _execute(self, context: PrimitiveExecutionContext, inputs: BuildBreakEvenInput) -> PrimitiveExecutionResult[BreakEven]:
        try:
            document = build_break_even(inputs.plan, margin_report=inputs.margin_report, services_margin=inputs.services_margin, register_states=_pairs(inputs.register_states), books=inputs.books, window_start=inputs.window_start, window_end=inputs.window_end, as_of=inputs.as_of)
        except ValueError as exc:
            return _failed(self, exc)
        return _completed(self, document, f"Break-even: {document.verdict}", "finance.break_even_built", {"break_even_digest": document.break_even_digest, "fixed_cost_known": document.fixed_cost_known, "operating_result": None if document.operating_result is None else str(document.operating_result)})


class ScoreProbeOutcomesInput(_Input):
    plan: dict[str, Any]
    probes: dict[str, Any]
    before: dict[str, Any]
    after: dict[str, Any]
    as_of: str


def _example_probe_outcomes() -> dict[str, Any]:
    before = _example_margin_report("2026-09-01T00:00:00Z", "2026-10-01T00:00:00Z", "2026-10-02T00:00:00Z")
    probes = plan_price_probes(compile_price_probe_plan(_EXAMPLE_COMPANY, currency="USD"), margin_report=before, as_of="2026-10-02T00:00:00Z").to_dict()
    return {"plan": compile_probe_outcomes_plan(_EXAMPLE_COMPANY, currency="USD").to_dict(), "probes": probes, "before": before, "after": _example_margin_report("2026-10-01T00:00:00Z", "2026-11-01T00:00:00Z", _EXAMPLE_AS_OF), "as_of": _EXAMPLE_AS_OF}


class ScoreProbeOutcomesPrimitive(BusinessProcessPrimitive[ScoreProbeOutcomesInput, ProbeOutcomes]):
    """Whether each recommended price move was taken, and whether it paid."""

    primitive_ref = "commerce.score_probe_outcomes"
    version = "1.0.0"
    title = "Score the price probe outcomes"
    description = "Score a sealed price probe table against the margin report of the window after, bound to the report it was planned from: per probed SKU whether the move was applied within the plan's tolerance, the volume change a day against the break-even volume change the probe allowed, the contribution a day before and after with the money that made, and a verdict (held, backfired, not applied, unmeasured) with the next step: keep, revert, apply, or measure."
    input_model = ScoreProbeOutcomesInput
    output_model = ProbeOutcomes
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs: ClassVar[Mapping[str, Any]] = _LazyExample(_example_probe_outcomes)

    def _execute(self, context: PrimitiveExecutionContext, inputs: ScoreProbeOutcomesInput) -> PrimitiveExecutionResult[ProbeOutcomes]:
        try:
            outcomes = score_probe_outcomes(inputs.plan, probes=inputs.probes, before=inputs.before, after=inputs.after, as_of=inputs.as_of)
        except ValueError as exc:
            return _failed(self, exc)
        return _completed(self, outcomes, f"Probe outcomes: {outcomes.verdict}", "commerce.probe_outcomes_scored", {"outcomes_digest": outcomes.outcomes_digest, "by_verdict": dict(outcomes.by_verdict), "contribution_change_applied": str(outcomes.contribution_change_applied)})


# --------------------------------------------------------------------------- #
# Skills development
# --------------------------------------------------------------------------- #


class BuildSkillsDevelopmentInput(_Input):
    plan: dict[str, Any]
    inventory: dict[str, Any]
    sourcing_plan: dict[str, Any]
    profiles: tuple[dict[str, Any], ...] = ()
    as_of: str
    capacity: dict[str, Any] | None = None


def _example_skills_development() -> dict[str, Any]:
    example = _example_skills()
    inventory = build_skills_inventory(example["plan"], taxonomy=example["taxonomy"], profiles=example["profiles"], jobs=example["jobs"], as_of=example["as_of"]).to_dict()
    market = compile_labour_sourcing_plan(_EXAMPLE_COMPANY, currency="USD", roles=[{"role_ref": "role:electrician", "title": "Licensed electrician", "skills": {"electrical": 4}, "pay_rate": "62", "pay_rate_uom": "hour"}], market_rates={"hydraulics": "110", "electrical": "125"}).to_dict()
    return {"plan": compile_skills_development_plan(_EXAMPLE_COMPANY, currency="USD").to_dict(), "inventory": inventory, "sourcing_plan": market, "profiles": tuple(example["profiles"]), "as_of": example["as_of"]}


class BuildSkillsDevelopmentPrimitive(BusinessProcessPrimitive[BuildSkillsDevelopmentInput, SkillsDevelopment]):
    """Train, hire, or contract for every skill short or exposed, with the cost, the lead, and the payback."""

    primitive_ref = "services.build_skills_development"
    version = "1.0.0"
    title = "Build the skills development plan"
    description = "Seal, for every skill the sealed inventory shows short, thin, single-point, or lapsing (and the sealed capacity plan shows short by the week), the priced routes: train a named worker for the levels short at the worker's own cost rate over the sourcing plan's hours and weeks per level, hire into a role that carries the skill for the recruiting cost plus the pay over the payback horizon, or contract the hours short at the market rate; choose the cheapest route ready before the peak week (a depth risk trains when a worker is within reach and otherwise hires, and escalates when nothing builds depth), schedule who trains in what by when, and name the contracting each training spend avoids."
    input_model = BuildSkillsDevelopmentInput
    output_model = SkillsDevelopment
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs: ClassVar[Mapping[str, Any]] = _LazyExample(_example_skills_development)

    def _execute(self, context: PrimitiveExecutionContext, inputs: BuildSkillsDevelopmentInput) -> PrimitiveExecutionResult[SkillsDevelopment]:
        try:
            document = build_skills_development(inputs.plan, inventory=inputs.inventory, capacity=inputs.capacity, sourcing_plan=inputs.sourcing_plan, profiles=list(inputs.profiles), as_of=inputs.as_of)
        except ValueError as exc:
            return _failed(self, exc)
        return _completed(self, document, f"Skills development: {len(document.actions)} skill(s); train {document.training_cost} {document.currency}, hire {document.hiring_cost}, contract {document.contracting_cost}; {document.workers_in_training} in training", "services.skills_development_built", {"development_digest": document.development_digest, "by_choice": dict(document.by_choice), "training_cost": str(document.training_cost)})


# --------------------------------------------------------------------------- #
# Customer cohorts
# --------------------------------------------------------------------------- #


class BuildCustomerCohortsInput(_Input):
    plan: dict[str, Any]
    window_start: str
    window_end: str
    as_of: str
    fulfilment_states: tuple[SourceState, ...] = ()
    register_states: tuple[SourceState, ...] = ()
    margin_report: dict[str, Any] | None = None
    subscription_states: tuple[SourceState, ...] = ()
    invoice_reads: tuple[dict[str, Any], ...] = ()


class BuildCustomerCohortsPrimitive(BusinessProcessPrimitive[BuildCustomerCohortsInput, CustomerCohorts]):
    """What a customer acquired in a given month goes on to buy, what it cost to acquire them, and when it pays back."""

    primitive_ref = "commerce.build_customer_cohorts"
    version = "1.0.0"
    title = "Build the customer cohort table"
    description = "Seal every customer first seen in the window by the month of their first replayed order, with the orders, repeat customers and repeat rate, revenue per customer and its curve by month since acquisition, contribution per customer at the sealed margin report's contribution margin, the acquisition spend per month from the replayed cost registers' channel spend and media bills, the cost per acquired customer, the months to pay it back, and the value-to-cost ratio; returning customers from before the window are counted separately and orders without a customer are counted, not guessed."
    input_model = BuildCustomerCohortsInput
    output_model = CustomerCohorts
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs: ClassVar[Mapping[str, Any]] = _LazyExample(lambda: {"plan": compile_customer_cohort_plan(_EXAMPLE_COMPANY, currency="USD").to_dict(), "window_start": "2026-10-01T00:00:00Z", "window_end": "2026-11-01T00:00:00Z", "as_of": _EXAMPLE_AS_OF, "margin_report": _example_margin_report("2026-10-01T00:00:00Z", "2026-11-01T00:00:00Z", _EXAMPLE_AS_OF)})

    def _execute(self, context: PrimitiveExecutionContext, inputs: BuildCustomerCohortsInput) -> PrimitiveExecutionResult[CustomerCohorts]:
        try:
            cohorts = build_customer_cohorts(inputs.plan, fulfilment_states=_pairs(inputs.fulfilment_states), register_states=_pairs(inputs.register_states), margin_report=inputs.margin_report, subscription_states=_pairs(inputs.subscription_states), invoice_reads=inputs.invoice_reads, window_start=inputs.window_start, window_end=inputs.window_end, as_of=inputs.as_of)
        except ValueError as exc:
            return _failed(self, exc)
        repeat = "n/a" if cohorts.repeat_rate_percent is None else f"{cohorts.repeat_rate_percent}%"
        return _completed(self, cohorts, f"Customer cohorts: {cohorts.customers} new customer(s) in {len(cohorts.cohorts)} cohort(s), repeat rate {repeat}; {cohorts.recommendations[0]}", "commerce.customer_cohorts_built", {"cohorts_digest": cohorts.cohorts_digest, "customers": cohorts.customers, "repeat_rate_percent": None if cohorts.repeat_rate_percent is None else str(cohorts.repeat_rate_percent)})


# --------------------------------------------------------------------------- #
# Quote outcomes
# --------------------------------------------------------------------------- #


class ScoreQuoteOutcomesInput(_Input):
    plan: dict[str, Any]
    quotes: tuple[dict[str, Any], ...] = ()
    costing: dict[str, Any]
    as_of: str
    contingency_percent: str = "15"


def _example_quote_outcomes() -> dict[str, Any]:
    skills = _example_skills()
    quote = build_job_quote(compile_job_quote_plan(_EXAMPLE_COMPANY, currency="USD"), job=skills["jobs"][0], taxonomy=skills["taxonomy"], matching_plan=skills["plan"], profiles=skills["profiles"], offered_price="4500", as_of=skills["as_of"]).to_dict()
    costing = build_job_costing(compile_job_costing_plan(_EXAMPLE_COMPANY, currency="USD"), work_order_states=[], window_start="2026-10-01T00:00:00Z", window_end="2026-11-01T00:00:00Z", as_of=_EXAMPLE_AS_OF).to_dict()
    return {"plan": compile_quote_outcomes_plan(_EXAMPLE_COMPANY, currency="USD").to_dict(), "quotes": (quote,), "costing": costing, "as_of": _EXAMPLE_AS_OF}


class ScoreQuoteOutcomesPrimitive(BusinessProcessPrimitive[ScoreQuoteOutcomesInput, QuoteOutcomes]):
    """Whether each job quote held once the job was costed."""

    primitive_ref = "services.score_quote_outcomes"
    version = "1.0.0"
    title = "Score the job quote outcomes"
    description = "Score sealed job quotes against a sealed job costing: each quote bound to the completed, costed job it was written for, with the quoted hours and loaded labour cost against the recorded labour and contractor cost, the parts and stock the quote never priced, the margin realised at the offered or target price on the whole cost, and a verdict (held, overran, underquoted, open, unmatched); across quotes the realised margin and the contingency the stretch overruns say to carry, never below the contingency carried now."
    input_model = ScoreQuoteOutcomesInput
    output_model = QuoteOutcomes
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs: ClassVar[Mapping[str, Any]] = _LazyExample(_example_quote_outcomes)

    def _execute(self, context: PrimitiveExecutionContext, inputs: ScoreQuoteOutcomesInput) -> PrimitiveExecutionResult[QuoteOutcomes]:
        try:
            outcomes = score_quote_outcomes(inputs.plan, quotes=list(inputs.quotes), costing=inputs.costing, contingency_percent=inputs.contingency_percent, as_of=inputs.as_of)
        except ValueError as exc:
            return _failed(self, exc)
        return _completed(self, outcomes, f"Quote outcomes: {outcomes.verdict}", "services.quote_outcomes_scored", {"outcomes_digest": outcomes.outcomes_digest, "by_verdict": dict(outcomes.by_verdict), "realised_margin_percent": None if outcomes.realised_margin_percent is None else str(outcomes.realised_margin_percent)})


# --------------------------------------------------------------------------- #
# Review decisions
# --------------------------------------------------------------------------- #


class DecideReviewActionsInput(_Input):
    review: dict[str, Any]
    decisions: tuple[dict[str, Any], ...] = ()
    as_of: str


def _example_review_decisions() -> dict[str, Any]:
    report = _example_margin_report("2026-10-01T00:00:00Z", "2026-11-01T00:00:00Z", _EXAMPLE_AS_OF)
    review = build_intelligence_review(review_ref="review-2026-W44", company_ref=_EXAMPLE_COMPANY, currency="USD", as_of=_EXAMPLE_AS_OF, documents={"product_margin": report}).to_dict()
    return {"review": review, "decisions": (), "as_of": _EXAMPLE_AS_OF}


class DecideReviewActionsPrimitive(BusinessProcessPrimitive[DecideReviewActionsInput, ReviewDecisions]):
    """What the operator decided about each action a review raised."""

    primitive_ref = "company.decide_review_actions"
    version = "1.0.0"
    title = "Seal the review decisions"
    description = "Seal the operator's decisions on the actions a sealed intelligence review raised: each decision (accept with an owner and a due date, defer with a due date, decline) bound to a raised action by source, kind, and subject and decided once; undecided actions named rather than assumed accepted; the money at stake by decision, the accepted and deferred actions past due at as_of, and the next step; the ledger the next review carries and the review outcomes read."
    input_model = DecideReviewActionsInput
    output_model = ReviewDecisions
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs: ClassVar[Mapping[str, Any]] = _LazyExample(_example_review_decisions)

    def _execute(self, context: PrimitiveExecutionContext, inputs: DecideReviewActionsInput) -> PrimitiveExecutionResult[ReviewDecisions]:
        try:
            ledger = decide_review_actions(inputs.review, list(inputs.decisions), as_of=inputs.as_of)
        except ValueError as exc:
            return _failed(self, exc)
        return _completed(self, ledger, f"Review decisions {ledger.review_ref}: {ledger.verdict}", "company.review_actions_decided", {"decisions_digest": ledger.decisions_digest, "decided": ledger.decided, "undecided": ledger.undecided, "overdue": ledger.overdue})


# --------------------------------------------------------------------------- #
# Stockouts
# --------------------------------------------------------------------------- #


class BuildStockoutsInput(_Input):
    plan: dict[str, Any]
    window_start: str
    window_end: str
    as_of: str
    inventory_states: tuple[SourceState, ...] = ()
    margin_report: dict[str, Any] | None = None


class BuildStockoutsPrimitive(BusinessProcessPrimitive[BuildStockoutsInput, Stockouts]):
    """What an empty shelf cost, and whether the order was small or late."""

    primitive_ref = "commerce.build_stockouts"
    version = "1.0.0"
    title = "Build the stockout ledger"
    description = "Seal, per replayed stock position, the days inside the window with nothing on hand and the spells, the velocity while stocked, the units lost at that velocity plus the units the chain recorded as oversold, the revenue and contribution lost at the sealed margin report's realised price and contribution per unit, and the reorder point the policy would have needed (velocity over the lead time plus safety stock) against the one it carries, so each recommendation says whether the order was small or late; velocity is measured only while stock was held."
    input_model = BuildStockoutsInput
    output_model = Stockouts
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs: ClassVar[Mapping[str, Any]] = _LazyExample(lambda: {"plan": compile_stockout_plan(_EXAMPLE_COMPANY, currency="USD").to_dict(), "window_start": "2026-10-01T00:00:00Z", "window_end": "2026-11-01T00:00:00Z", "as_of": _EXAMPLE_AS_OF, "margin_report": _example_margin_report("2026-10-01T00:00:00Z", "2026-11-01T00:00:00Z", _EXAMPLE_AS_OF)})

    def _execute(self, context: PrimitiveExecutionContext, inputs: BuildStockoutsInput) -> PrimitiveExecutionResult[Stockouts]:
        try:
            ledger = build_stockouts(inputs.plan, inventory_states=_pairs(inputs.inventory_states), margin_report=inputs.margin_report, window_start=inputs.window_start, window_end=inputs.window_end, as_of=inputs.as_of)
        except ValueError as exc:
            return _failed(self, exc)
        return _completed(self, ledger, f"Stockouts: {ledger.positions_with_stockouts} of {ledger.positions} position(s) ran empty for {ledger.empty_days} day(s); {ledger.lost_units} unit(s) lost; {ledger.recommendations[0]}", "commerce.stockouts_built", {"stockouts_digest": ledger.stockouts_digest, "positions_with_stockouts": ledger.positions_with_stockouts, "lost_units": str(ledger.lost_units)})


# --------------------------------------------------------------------------- #
# Returns ledger
# --------------------------------------------------------------------------- #


class BuildReturnsLedgerInput(_Input):
    plan: dict[str, Any]
    window_start: str
    window_end: str
    as_of: str
    fulfilment_states: tuple[SourceState, ...] = ()
    inventory_states: tuple[SourceState, ...] = ()
    margin_report: dict[str, Any] | None = None


class BuildReturnsLedgerPrimitive(BusinessProcessPrimitive[BuildReturnsLedgerInput, ReturnsLedger]):
    """What came back, in what condition, and what it cost once the goods were back."""

    primitive_ref = "commerce.build_returns_ledger"
    version = "1.0.0"
    title = "Build the returns ledger"
    description = "Seal, per SKU, the units sold and returned inside the window from the replayed orders, the return rate, the returned orders and their conditions, the refund value at the sealed margin report's realised price (the order's average price without one), the handling cost at the plan's rate, the units the replayed stock positions actually restocked from those returns (bound by the fulfilment state's digest) and the value put back, the write-downs in the window, and the net cost of returns as a share of net revenue; a return the inventory chain has not restocked is counted as not back on the shelf, never assumed."
    input_model = BuildReturnsLedgerInput
    output_model = ReturnsLedger
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs: ClassVar[Mapping[str, Any]] = _LazyExample(lambda: {"plan": compile_returns_plan(_EXAMPLE_COMPANY, currency="USD").to_dict(), "window_start": "2026-10-01T00:00:00Z", "window_end": "2026-11-01T00:00:00Z", "as_of": _EXAMPLE_AS_OF, "margin_report": _example_margin_report("2026-10-01T00:00:00Z", "2026-11-01T00:00:00Z", _EXAMPLE_AS_OF)})

    def _execute(self, context: PrimitiveExecutionContext, inputs: BuildReturnsLedgerInput) -> PrimitiveExecutionResult[ReturnsLedger]:
        try:
            ledger = build_returns_ledger(inputs.plan, fulfilment_states=_pairs(inputs.fulfilment_states), inventory_states=_pairs(inputs.inventory_states), margin_report=inputs.margin_report, window_start=inputs.window_start, window_end=inputs.window_end, as_of=inputs.as_of)
        except ValueError as exc:
            return _failed(self, exc)
        return _completed(self, ledger, f"Returns: {ledger.orders_returned} of {ledger.orders_in_window} order(s) returned, net cost {ledger.net_cost} {ledger.currency}; {ledger.recommendations[0]}", "commerce.returns_ledger_built", {"returns_digest": ledger.returns_digest, "orders_returned": ledger.orders_returned, "net_cost": str(ledger.net_cost)})


# --------------------------------------------------------------------------- #
# Decision work items
# --------------------------------------------------------------------------- #


class PlanDecisionWorkItemsInput(_Input):
    decisions: dict[str, Any]
    as_of: str


class PlanDecisionWorkItemsPrimitive(BusinessProcessPrimitive[PlanDecisionWorkItemsInput, DecisionWorkItems]):
    """Every accepted or deferred review decision still open, as a work item."""

    primitive_ref = "company.plan_decision_work_items"
    version = "1.0.0"
    title = "Plan the decision work items"
    description = "Seal, from a sealed review decisions ledger, one work item per accepted or deferred action without an outcome: a stable item ref, the decision, the owner, the due date and the days to it (or overdue), the money at stake, and the summary the cadence raises; closed actions counted by outcome; declined and undecided actions raise nothing."
    input_model = PlanDecisionWorkItemsInput
    output_model = DecisionWorkItems
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs: ClassVar[Mapping[str, Any]] = _LazyExample(lambda: {"decisions": decide_review_actions(_example_review_decisions()["review"], [], as_of=_EXAMPLE_AS_OF).to_dict(), "as_of": _EXAMPLE_AS_OF})

    def _execute(self, context: PrimitiveExecutionContext, inputs: PlanDecisionWorkItemsInput) -> PrimitiveExecutionResult[DecisionWorkItems]:
        try:
            planned = plan_decision_work_items(inputs.decisions, as_of=inputs.as_of)
        except ValueError as exc:
            return _failed(self, exc)
        return _completed(self, planned, f"Decision work items {planned.review_ref}: {planned.verdict}", "company.decision_work_items_planned", {"work_items_digest": planned.work_items_digest, "open": planned.open, "overdue": planned.overdue, "closed": planned.closed})


# --------------------------------------------------------------------------- #
# Books snapshot
# --------------------------------------------------------------------------- #


def _example_books_snapshot() -> dict[str, Any]:
    import json
    from importlib import resources

    from lightbulb.company_engine_core import stable_digest

    def read(tool: str, name: str) -> dict[str, Any]:
        payload = json.loads(resources.files("lightbulb.data.provider_fixtures").joinpath(name).read_text(encoding="utf-8"))
        return {"payload": payload, "provenance": {"lane": "host_read", "source_tool": tool, "observation_ref": f"example:{tool}", "provenance_digest": stable_digest({"example": name}), "output_digest": stable_digest(payload), "completed_at": "2026-10-01T06:00:00Z"}}

    plan = compile_books_plan(_EXAMPLE_COMPANY, currency="AUD", overrides={"account_roles": {"receivable": ["Accounts Receivable"], "payable": ["Accounts Payable"], "tax": ["GST"]}})
    return {"plan": plan.to_dict(), "sources": [{"kind": "profit_and_loss", **read("xero.profit_loss_report", "xero_profit_loss_report.json")}, {"kind": "balance_sheet", **read("xero.balance_sheet_report", "xero_balance_sheet_report.json")}], "window_start": "2026-07-01T00:00:00Z", "window_end": "2026-10-01T00:00:00Z", "as_of": "2026-10-02T00:00:00Z"}


class BuildBooksSnapshotInput(_Input):
    plan: dict[str, Any]
    sources: list[dict[str, Any]]
    window_start: str
    window_end: str
    as_of: str


class BuildBooksSnapshotPrimitive(BusinessProcessPrimitive[BuildBooksSnapshotInput, BooksSnapshot]):
    """What the ledger alone says about the company, sealed."""

    primitive_ref = "company.build_books_snapshot"
    version = "1.0.0"
    title = "Build the books snapshot"
    description = "Seal, from the ledger's income statement read for a window and optionally its balance sheet read, the margin ladder, the split of cost into variable and fixed, cash, receivables, payables, tax owed and cash net of it, and the books-health findings; the period is the one each report states for itself, the ladder must foot to the report's own totals, and a role the plan does not map stays unknown."
    input_model = BuildBooksSnapshotInput
    output_model = BooksSnapshot
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs: ClassVar[Mapping[str, Any]] = _LazyExample(_example_books_snapshot)

    def _execute(self, context: PrimitiveExecutionContext, inputs: BuildBooksSnapshotInput) -> PrimitiveExecutionResult[BooksSnapshot]:
        try:
            snapshot = build_books_snapshot(inputs.plan, sources=inputs.sources, window_start=inputs.window_start, window_end=inputs.window_end, as_of=inputs.as_of)
        except ValueError as exc:
            return _failed(self, exc)
        return _completed(self, snapshot, f"Books {snapshot.period_label}: {snapshot.verdict}", "company.books_snapshot_built", {"snapshot_digest": snapshot.snapshot_digest, "findings": len(snapshot.findings), "net_margin_percent": None if snapshot.net_margin_percent is None else str(snapshot.net_margin_percent)})


# --------------------------------------------------------------------------- #
# Cash calendar from the books
# --------------------------------------------------------------------------- #


class BuildBooksCashForecastInput(_Input):
    books: dict[str, Any]
    as_of: str
    horizon_weeks: int = 13
    receivables_collected_in_days: int | None = None
    payables_paid_in_days: int | None = None
    tax_paid_in_days: int | None = None
    weekly_receipts_at_run_rate: bool = False


class BuildBooksCashForecastPrimitive(BusinessProcessPrimitive[BuildBooksCashForecastInput, BooksCashForecast]):
    """What the balances in the books do to cash over the coming weeks."""

    primitive_ref = "company.build_books_cash_forecast"
    version = "1.0.0"
    title = "Build the cash calendar from the books"
    description = "Seal, from one books snapshot, the week-by-week cash calendar: opening cash, the receivable, payable and tax balances dated only by the stated timings, and the recorded cost run-rate when the books record enough cost for it to mean anything; a balance with no timing is left out and named, thin books make the calendar an optimistic ceiling, and the document re-runs its engine when verified."
    input_model = BuildBooksCashForecastInput
    output_model = BooksCashForecast
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs: ClassVar[Mapping[str, Any]] = _LazyExample(lambda: {"books": build_books_snapshot(**_example_books_snapshot()).to_dict(), "as_of": "2026-10-02T00:00:00Z", "receivables_collected_in_days": 30, "payables_paid_in_days": 30, "tax_paid_in_days": 28})

    def _execute(self, context: PrimitiveExecutionContext, inputs: BuildBooksCashForecastInput) -> PrimitiveExecutionResult[BooksCashForecast]:
        try:
            calendar = build_books_cash_forecast(inputs.books, as_of=inputs.as_of, horizon_weeks=inputs.horizon_weeks, receivables_collected_in_days=inputs.receivables_collected_in_days, payables_paid_in_days=inputs.payables_paid_in_days, tax_paid_in_days=inputs.tax_paid_in_days, weekly_receipts_at_run_rate=inputs.weekly_receipts_at_run_rate)
        except ValueError as exc:
            return _failed(self, exc)
        return _completed(self, calendar, f"Cash calendar: {calendar.verdict}", "company.books_cash_forecast_built", {"cash_digest": calendar.cash_digest, "first_negative_week": calendar.first_negative_week, "reliability": calendar.reliability})


# --------------------------------------------------------------------------- #
# Tie-out to the books
# --------------------------------------------------------------------------- #


class TieOutDocumentsInput(_Input):
    plan: dict[str, Any]
    books: dict[str, Any]
    documents: dict[str, dict[str, Any]]
    as_of: str


class TieOutDocumentsPrimitive(BusinessProcessPrimitive[TieOutDocumentsInput, LedgerTieOut]):
    """Every document's headline total against the books."""

    primitive_ref = "company.tie_out_documents"
    version = "1.0.0"
    title = "Tie the documents out to the books"
    description = "Seal, for each supplied document, its comparable total beside the books' figure for the same window: the difference, whether it sits inside the plan's tolerance, and the reasons such a difference usually has, named but never chosen; a figure drawn from the books is not compared with them."
    input_model = TieOutDocumentsInput
    output_model = LedgerTieOut
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs: ClassVar[Mapping[str, Any]] = _LazyExample(lambda: (lambda books: {"plan": compile_tie_out_plan(_EXAMPLE_COMPANY, currency="AUD").to_dict(), "books": books.to_dict(), "documents": {"working_capital": build_working_capital(compile_working_capital_plan(_EXAMPLE_COMPANY, currency="AUD"), books=books, window_start=books.window_start, window_end=books.window_end, as_of="2026-10-02T00:00:00Z").to_dict()}, "as_of": "2026-10-02T00:00:00Z"})(build_books_snapshot(**_example_books_snapshot())))

    def _execute(self, context: PrimitiveExecutionContext, inputs: TieOutDocumentsInput) -> PrimitiveExecutionResult[LedgerTieOut]:
        try:
            tie = tie_out_documents(inputs.plan, books=inputs.books, documents=inputs.documents, as_of=inputs.as_of)
        except ValueError as exc:
            return _failed(self, exc)
        return _completed(self, tie, f"Tie-out: {tie.verdict}", "company.documents_tied_out", {"tie_out_digest": tie.tie_out_digest, "tied": tie.tied, "outside_tolerance": tie.outside_tolerance})


# --------------------------------------------------------------------------- #
# What-if
# --------------------------------------------------------------------------- #


class RunScenarioInput(_Input):
    books: dict[str, Any]
    scenario_ref: str
    levers: list[dict[str, Any]]
    as_of: str


class RunScenarioPrimitive(BusinessProcessPrimitive[RunScenarioInput, Scenario]):
    """The exact consequence of a decision on the books' ladder."""

    primitive_ref = "company.run_scenario"
    version = "1.0.0"
    title = "Run a what-if over the books"
    description = "Seal the consequence of the stated levers (price with elasticity, volume, hire, contractor, customer won or lost, cost line, payment terms) applied in order to a books snapshot: the ladder before and after, the change in operating result, break-even and cash, payback when a one-off cost is recovered, a price lever at three elasticities, and every assumption; arithmetic, not a forecast."
    input_model = RunScenarioInput
    output_model = Scenario
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs: ClassVar[Mapping[str, Any]] = _LazyExample(lambda: {"books": build_books_snapshot(**_example_books_snapshot()).to_dict(), "scenario_ref": "raise-prices-5", "levers": [{"kind": "price", "label": "raise prices 5%", "percent": "5"}], "as_of": "2026-10-02T00:00:00Z"})

    def _execute(self, context: PrimitiveExecutionContext, inputs: RunScenarioInput) -> PrimitiveExecutionResult[Scenario]:
        try:
            scenario = run_scenario(inputs.books, scenario_ref=inputs.scenario_ref, levers=inputs.levers, as_of=inputs.as_of)
        except ValueError as exc:
            return _failed(self, exc)
        return _completed(self, scenario, f"What if {scenario.scenario_ref}: {scenario.verdict}", "company.scenario_run", {"scenario_digest": scenario.scenario_digest, "operating_result_change": str(scenario.operating_result_change)})


# --------------------------------------------------------------------------- #
# Customer ledger
# --------------------------------------------------------------------------- #


class BuildCustomerLedgerInput(_Input):
    plan: dict[str, Any]
    source: dict[str, Any]
    window_start: str
    window_end: str
    as_of: str


class BuildCustomerLedgerPrimitive(BusinessProcessPrimitive[BuildCustomerLedgerInput, CustomerLedger]):
    """Who brought the revenue and how they pay, from the sales invoices alone."""

    primitive_ref = "company.build_customer_ledger"
    version = "1.0.0"
    title = "Build the customer ledger from the sales records"
    description = "Seal, from one sales-record read over a window, per customer the billed count, revenue and share, the balance outstanding, how much is past due and by how long, and the realised days to pay where the page carries paid dates; flags concentration over the plan's ceiling, balances past due beyond tolerance, and slow payers; reads the governed month page or a provider page and says what each lacks."
    input_model = BuildCustomerLedgerInput
    output_model = CustomerLedger
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs: ClassVar[Mapping[str, Any]] = _LazyExample(lambda: (lambda page: {"plan": compile_customer_ledger_plan(_EXAMPLE_COMPANY, currency="AUD").to_dict(), "source": {"provenance": {"lane": "host_read", "source_tool": "xero.list_invoices", "observation_ref": "example:xero.list_invoices", "provenance_digest": stable_digest({"example": "xero_invoice_page_raw.json"}), "output_digest": stable_digest(page), "completed_at": "2026-10-15T06:00:00Z"}, "payload": page}, "window_start": "2026-07-01T00:00:00Z", "window_end": "2026-10-01T00:00:00Z", "as_of": "2026-10-16T00:00:00Z"})(__import__("json").loads(__import__("importlib.resources", fromlist=["files"]).files("lightbulb.data.provider_fixtures").joinpath("xero_invoice_page_raw.json").read_text(encoding="utf-8"))))

    def _execute(self, context: PrimitiveExecutionContext, inputs: BuildCustomerLedgerInput) -> PrimitiveExecutionResult[CustomerLedger]:
        try:
            ledger = build_customer_ledger(inputs.plan, source=inputs.source, window_start=inputs.window_start, window_end=inputs.window_end, as_of=inputs.as_of)
        except ValueError as exc:
            return _failed(self, exc)
        return _completed(self, ledger, f"Customers: {ledger.verdict}", "company.customer_ledger_built", {"ledger_digest": ledger.ledger_digest, "customers": ledger.customers, "overdue": str(ledger.overdue)})


# --------------------------------------------------------------------------- #
# Job assignment
# --------------------------------------------------------------------------- #


class AssignJobsInput(_Input):
    plan: dict[str, Any]
    match_report: dict[str, Any]
    profiles: list[dict[str, Any]]
    as_of: str


class AssignJobsPrimitive(BusinessProcessPrimitive[AssignJobsInput, JobAssignment]):
    """Every job staffed at once, no hour given twice."""

    primitive_ref = "company.assign_jobs"
    version = "1.0.0"
    title = "Assign every job at once"
    description = "Seal the allocation of every worker's hours across every job in a skills match report: jobs in the plan's priority, then due date, then money at stake; each job's fit workers in rank order from what remains of their weekly hours across overlapping jobs; a job that cannot be filled is short by a stated number of hours and names who would have covered it; each worker's load and peak week; deterministic."
    input_model = AssignJobsInput
    output_model = JobAssignment
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs: ClassVar[Mapping[str, Any]] = _LazyExample(lambda: (lambda skills: {"plan": compile_job_assignment_plan(_EXAMPLE_COMPANY, currency="USD").to_dict(), "match_report": build_skills_match_report(skills["plan"], taxonomy=skills["taxonomy"], jobs=skills["jobs"], profiles=skills["profiles"], as_of=skills["as_of"]).to_dict(), "profiles": skills["profiles"], "as_of": skills["as_of"]})(_example_skills()))

    def _execute(self, context: PrimitiveExecutionContext, inputs: AssignJobsInput) -> PrimitiveExecutionResult[JobAssignment]:
        try:
            assignment = assign_jobs(inputs.plan, match_report=inputs.match_report, profiles=inputs.profiles, as_of=inputs.as_of)
        except ValueError as exc:
            return _failed(self, exc)
        return _completed(self, assignment, f"Assignment: {assignment.verdict}", "company.jobs_assigned", {"assignment_digest": assignment.assignment_digest, "staffed": assignment.staffed, "hours_short": str(assignment.hours_short)})


# --------------------------------------------------------------------------- #
# Intelligence history and threshold calibration
# --------------------------------------------------------------------------- #


def _example_history_windows() -> list[dict[str, Any]]:
    """Three months of the example company's books, its sales moving each month with every stated total moved to match."""

    import copy
    from decimal import Decimal

    example = _example_books_snapshot()
    windows = []
    for month, (title, start, end, sales, net) in enumerate((("1 July 2026 to 31 July 2026", "2026-07-01T00:00:00Z", "2026-08-01T00:00:00Z", "84000.00", "21150.00"), ("1 August 2026 to 31 August 2026", "2026-08-01T00:00:00Z", "2026-09-01T00:00:00Z", "80000.00", "17150.00"), ("1 September 2026 to 30 September 2026", "2026-09-01T00:00:00Z", "2026-10-01T00:00:00Z", "76000.00", "13150.00"))):
        source = copy.deepcopy(example["sources"][0])
        report = source["payload"]["Reports"][0]
        report["ReportTitles"][2] = title
        total = str(Decimal(sales) + Decimal("12500.00"))
        for section in report["Rows"]:
            for row in section.get("Rows", []):
                cells = row.get("Cells") or []
                label = cells[0].get("Value") if cells else None
                if label in {"Sales", "Total Income", "Gross Profit", "Net Profit"}:
                    cells[1]["Value"] = {"Sales": sales, "Total Income": total, "Gross Profit": str(Decimal(total) - Decimal("21000.00")), "Net Profit": net}[label]
        source["provenance"] = {**source["provenance"], "observation_ref": f"example:xero.profit_loss_report:{month}", "output_digest": stable_digest(source["payload"])}
        books = build_books_snapshot(example["plan"], sources=[source], window_start=start, window_end=end, as_of=example["as_of"])
        windows.append({"window_ref": f"books:{start[:10]}:{end[:10]}", "as_of": end, "documents": {"books_snapshot": books.to_dict()}, "open_actions": 3 - month})
    return windows


class BuildIntelligenceHistoryInput(_Input):
    company_ref: str
    currency: str
    windows: list[dict[str, Any]]
    as_of: str


class BuildIntelligenceHistoryPrimitive(BusinessProcessPrimitive[BuildIntelligenceHistoryInput, IntelligenceHistory]):
    """Every headline figure lined up across the recorded windows."""

    primitive_ref = "company.build_intelligence_history"
    version = "1.0.0"
    title = "Build the intelligence history"
    description = "Seal the series of headline figures across recorded windows (revenue, net margin, cash, cost share, overdue receivables, top-customer share, cash conversion days, margin of safety, hours short, tie-out differences, open actions): per figure the latest value, the change on the previous window, its direction over the last three, and a warning when it has moved the wrong way three windows running; a figure a window could not build is a gap, never a zero; deterministic."
    input_model = BuildIntelligenceHistoryInput
    output_model = IntelligenceHistory
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs: ClassVar[Mapping[str, Any]] = _LazyExample(lambda: {"company_ref": _EXAMPLE_COMPANY, "currency": "AUD", "windows": _example_history_windows(), "as_of": "2026-10-02T00:00:00Z"})

    def _execute(self, context: PrimitiveExecutionContext, inputs: BuildIntelligenceHistoryInput) -> PrimitiveExecutionResult[IntelligenceHistory]:
        try:
            history = build_history(inputs.windows, company_ref=inputs.company_ref, currency=inputs.currency, as_of=inputs.as_of)
        except ValueError as exc:
            return _failed(self, exc)
        return _completed(self, history, f"History: {history.verdict}", "company.intelligence_history_built", {"history_digest": history.history_digest, "windows": history.windows, "warnings": len(history.warnings)})


class CalibrateThresholdsInput(_Input):
    history: dict[str, Any]
    as_of: str
    minimum_observations: int = 6


class CalibrateThresholdsPrimitive(BusinessProcessPrimitive[CalibrateThresholdsInput, ThresholdCalibration]):
    """Plan settings proposed from the company's own past."""

    primitive_ref = "company.calibrate_thresholds"
    version = "1.0.0"
    title = "Calibrate the plan thresholds from the history"
    description = "Propose plan settings from a sealed intelligence history by plain percentiles: the customer concentration ceiling at the 75th percentile of the observed top-customer share, the minimum cost share at half the observed median, the receivable-days target at the 25th percentile of the observed cash conversion cycle; each proposal states the observations it rests on and is declined below the minimum; proposals only, applied by nothing; deterministic."
    input_model = CalibrateThresholdsInput
    output_model = ThresholdCalibration
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs: ClassVar[Mapping[str, Any]] = _LazyExample(lambda: {"history": build_history(_example_history_windows(), company_ref=_EXAMPLE_COMPANY, currency="AUD", as_of="2026-10-02T00:00:00Z").to_dict(), "as_of": "2026-10-02T00:00:00Z", "minimum_observations": 3})

    def _execute(self, context: PrimitiveExecutionContext, inputs: CalibrateThresholdsInput) -> PrimitiveExecutionResult[ThresholdCalibration]:
        try:
            calibration = calibrate_thresholds(inputs.history, as_of=inputs.as_of, minimum_observations=inputs.minimum_observations)
        except ValueError as exc:
            return _failed(self, exc)
        return _completed(self, calibration, f"Calibration: {calibration.verdict}", "company.thresholds_calibrated", {"calibration_digest": calibration.calibration_digest, "proposals": len(calibration.proposals)})


# --------------------------------------------------------------------------- #
# Books backfill
# --------------------------------------------------------------------------- #


class PlanBooksBackfillInput(_Input):
    company_ref: str
    as_of: str
    months: int = 12
    balance_sheets: bool = True
    provider: str = "xero"


class PlanBooksBackfillPrimitive(BusinessProcessPrimitive[PlanBooksBackfillInput, BooksBackfillPlan]):
    """The ledger reads that recover a company's past months."""

    primitive_ref = "company.plan_books_backfill"
    version = "1.0.0"
    title = "Plan the books backfill"
    description = "Seal the ledger reads that recover a company's last complete calendar months so its history works on day one: one income-statement read per month and one balance sheet at each month end, oldest first, each with the exact arguments the platform read takes; up to 36 months; deterministic; reads nothing itself."
    input_model = PlanBooksBackfillInput
    output_model = BooksBackfillPlan
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs: ClassVar[Mapping[str, Any]] = _LazyExample(lambda: {"company_ref": _EXAMPLE_COMPANY, "as_of": "2026-10-02T00:00:00Z", "months": 12})

    def _execute(self, context: PrimitiveExecutionContext, inputs: PlanBooksBackfillInput) -> PrimitiveExecutionResult[BooksBackfillPlan]:
        try:
            plan = plan_books_backfill(inputs.company_ref, as_of=inputs.as_of, months=inputs.months, provider=inputs.provider, balance_sheets=inputs.balance_sheets)
        except ValueError as exc:
            return _failed(self, exc)
        return _completed(self, plan, f"Backfill: {plan.verdict}", "company.books_backfill_planned", {"plan_digest": plan.plan_digest, "reads": len(plan.reads)})


# --------------------------------------------------------------------------- #
# Owner digest
# --------------------------------------------------------------------------- #


class BuildOwnerDigestInput(_Input):
    company_ref: str
    company_name: str
    currency: str
    as_of: str
    books: dict[str, Any] | None = None
    history: dict[str, Any] | None = None
    cash_calendar: dict[str, Any] | None = None
    review: dict[str, Any] | None = None
    work_items: dict[str, Any] | None = None


class BuildOwnerDigestPrimitive(BusinessProcessPrimitive[BuildOwnerDigestInput, OwnerDigest]):
    """The week's documents said plainly for the owner."""

    primitive_ref = "company.build_owner_digest"
    version = "1.0.0"
    title = "Build the owner's weekly digest"
    description = "Seal the owner's weekly digest from sealed documents: the last month against the one before, the figures that matter with their change, three actions ranked by the money at stake keyed to the review's actions, what has moved the wrong way three months running, what the books leave out, and what cannot be said yet; every sentence is a fixed template over a sealed figure; sends nothing; deterministic."
    input_model = BuildOwnerDigestInput
    output_model = OwnerDigest
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs: ClassVar[Mapping[str, Any]] = _LazyExample(lambda: (lambda books: {"company_ref": _EXAMPLE_COMPANY, "company_name": "Example Services", "currency": "AUD", "as_of": books["as_of"], "books": build_books_snapshot(books["plan"], sources=books["sources"], window_start=books["window_start"], window_end=books["window_end"], as_of=books["as_of"]).to_dict()})(_example_books_snapshot()))

    def _execute(self, context: PrimitiveExecutionContext, inputs: BuildOwnerDigestInput) -> PrimitiveExecutionResult[OwnerDigest]:
        try:
            digest = build_owner_digest(company_ref=inputs.company_ref, company_name=inputs.company_name, currency=inputs.currency, as_of=inputs.as_of, books=inputs.books, history=inputs.history, cash_calendar=inputs.cash_calendar, review=inputs.review, work_items=inputs.work_items)
        except ValueError as exc:
            return _failed(self, exc)
        return _completed(self, digest, f"Digest: {digest.subject}", "company.owner_digest_built", {"digest_digest": digest.digest_digest, "actions": len(digest.actions)})


# --------------------------------------------------------------------------- #
# Books hygiene
# --------------------------------------------------------------------------- #


class AssessBooksHygieneInput(_Input):
    company_ref: str
    currency: str
    as_of: str
    snapshots: list[dict[str, Any]]
    bank_transactions: dict[str, Any] | None = None


class AssessBooksHygienePrimitive(BusinessProcessPrimitive[AssessBooksHygieneInput, BooksHygiene]):
    """What in the books makes the numbers weaker than they look."""

    primitive_ref = "company.assess_books_hygiene"
    version = "1.0.0"
    title = "Assess the books hygiene"
    description = "Seal where recorded books make the owner's numbers weaker than they look, each with its effect and the fix: months with sales and no costs, no wages or contractor costs, money in catch-all accounts, tax owed beyond the cash, and old unreconciled bank lines when a bank transactions read is supplied; what could not be checked is listed; trust graded good, fair or weak; deterministic."
    input_model = AssessBooksHygieneInput
    output_model = BooksHygiene
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs: ClassVar[Mapping[str, Any]] = _LazyExample(lambda: (lambda books: {"company_ref": _EXAMPLE_COMPANY, "currency": "AUD", "as_of": books["as_of"], "snapshots": [build_books_snapshot(books["plan"], sources=books["sources"], window_start=books["window_start"], window_end=books["window_end"], as_of=books["as_of"]).to_dict()]})(_example_books_snapshot()))

    def _execute(self, context: PrimitiveExecutionContext, inputs: AssessBooksHygieneInput) -> PrimitiveExecutionResult[BooksHygiene]:
        try:
            doc = assess_books_hygiene(company_ref=inputs.company_ref, currency=inputs.currency, as_of=inputs.as_of, snapshots=inputs.snapshots, bank_transactions=inputs.bank_transactions)
        except ValueError as exc:
            return _failed(self, exc)
        return _completed(self, doc, f"Books hygiene: {doc.verdict}", "company.books_hygiene_assessed", {"hygiene_digest": doc.hygiene_digest, "trust": doc.trust, "findings": len(doc.findings)})



# --------------------------------------------------------------------------- #
# The team from payroll
# --------------------------------------------------------------------------- #


def _payroll_example() -> dict[str, Any]:
    from lightbulb.provider_fixtures import load_fixture, provenance_for

    def read(name: str) -> dict[str, Any]:
        return {"provenance": dict(provenance_for(name, completed_at="2026-10-21T02:00:00Z")), "payload": load_fixture(name)}

    return {"company_ref": _EXAMPLE_COMPANY, "currency": "AUD", "as_of": "2026-10-22T00:00:00Z", "headcount": read("xero.headcount_page"), "payruns": [read("xero.payrun_observation")], "timesheets": [read("xero.timesheet_page")]}


class BuildPayrollTeamInput(_Input):
    company_ref: str
    currency: str
    as_of: str
    headcount: dict[str, Any]
    payruns: list[dict[str, Any]] = []
    timesheets: list[dict[str, Any]] = []
    basis_by_worker: dict[str, str] = {}
    hours_by_worker: dict[str, Any] = {}
    on_cost_percent: str = "0"
    profiles: list[dict[str, Any]] = []


class BuildPayrollTeamPrimitive(BusinessProcessPrimitive[BuildPayrollTeamInput, PayrollTeam]):
    """Who works here, the hours they work and what an hour of their time costs, from the payroll's governed pages."""

    primitive_ref = "company.build_payroll_team"
    version = "1.0.0"
    title = "Build the team from payroll"
    description = "Seal, from the governed Xero Payroll AU headcount, posted pay runs and timesheet pages (identities already sha256 commitments), every worker as worker:<sha[:24]>, active or left, the hours the approved timesheets show and their weekly average, and the cost of an hour (wages and super paid over the timesheet hours in the same pay periods, plus the stated on-costs; a salaried worker only on stated weekly hours), with a ready worker profile for each active worker whose hours and hour's cost are known and skills carried from earlier profiles; employment basis and skills are the owner's to confirm; deterministic; reads and changes nothing."
    input_model = BuildPayrollTeamInput
    output_model = PayrollTeam
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs: ClassVar[Mapping[str, Any]] = _LazyExample(_payroll_example)

    def _execute(self, context: PrimitiveExecutionContext, inputs: BuildPayrollTeamInput) -> PrimitiveExecutionResult[PayrollTeam]:
        try:
            team = build_payroll_team(company_ref=inputs.company_ref, currency=inputs.currency, as_of=inputs.as_of, headcount=inputs.headcount, payruns=inputs.payruns, timesheets=inputs.timesheets, basis_by_worker=inputs.basis_by_worker, hours_by_worker=inputs.hours_by_worker, on_cost_percent=inputs.on_cost_percent, profiles=inputs.profiles)
        except ValueError as exc:
            return _failed(self, exc)
        return _completed(self, team, f"Team: {team.verdict}", "company.payroll_team_built", {"team_digest": team.team_digest, "ready": team.ready, "members": len(team.members)})


BUSINESS_INTELLIGENCE_EXECUTABLE_PRIMITIVES: tuple[BusinessProcessPrimitive[Any, Any], ...] = (
    BuildProductMarginPrimitive(),
    PriceVolumeMixPrimitive(),
    BuildProductPortfolioPrimitive(),
    MatchSkillsPrimitive(),
    SourceLabourPrimitive(),
    BuildServicesMarginPrimitive(),
    BuildSkillsInventoryPrimitive(),
    PlanPriceProbesPrimitive(),
    BuildContributionBridgePrimitive(),
    BuildRateCardPrimitive(),
    BuildWorkforceCapacityPrimitive(),
    BuildJobQuotePrimitive(),
    BuildCustomerProfitabilityPrimitive(),
    BuildIntelligenceReviewPrimitive(),
    BuildSupplierScorecardPrimitive(),
    BuildJobCostingPrimitive(),
    BuildOpenToBuyPrimitive(),
    BuildWorkingCapitalPrimitive(),
    ScoreReviewOutcomesPrimitive(),
    BuildBreakEvenPrimitive(),
    ScoreProbeOutcomesPrimitive(),
    BuildSkillsDevelopmentPrimitive(),
    BuildCustomerCohortsPrimitive(),
    ScoreQuoteOutcomesPrimitive(),
    DecideReviewActionsPrimitive(),
    BuildStockoutsPrimitive(),
    BuildReturnsLedgerPrimitive(),
    PlanDecisionWorkItemsPrimitive(),
    BuildBooksSnapshotPrimitive(),
    BuildBooksCashForecastPrimitive(),
    TieOutDocumentsPrimitive(),
    RunScenarioPrimitive(),
    BuildCustomerLedgerPrimitive(),
    AssignJobsPrimitive(),
    BuildIntelligenceHistoryPrimitive(),
    CalibrateThresholdsPrimitive(),
    PlanBooksBackfillPrimitive(),
    BuildOwnerDigestPrimitive(),
    AssessBooksHygienePrimitive(),
    BuildPayrollTeamPrimitive(),
)

__all__ = [
    "BUSINESS_INTELLIGENCE_EXECUTABLE_PRIMITIVES",
    "BuildProductMarginInput",
    "BuildProductMarginPrimitive",
    "BuildProductPortfolioInput",
    "BuildProductPortfolioPrimitive",
    "BuildOpenToBuyInput",
    "BuildOpenToBuyPrimitive",
    "BuildWorkingCapitalInput",
    "BuildWorkingCapitalPrimitive",
    "ScoreReviewOutcomesInput",
    "ScoreReviewOutcomesPrimitive",
    "BuildBreakEvenInput",
    "BuildBreakEvenPrimitive",
    "ScoreProbeOutcomesInput",
    "ScoreProbeOutcomesPrimitive",
    "BuildSkillsDevelopmentInput",
    "BuildSkillsDevelopmentPrimitive",
    "BuildCustomerCohortsInput",
    "BuildCustomerCohortsPrimitive",
    "ScoreQuoteOutcomesInput",
    "ScoreQuoteOutcomesPrimitive",
    "DecideReviewActionsInput",
    "DecideReviewActionsPrimitive",
    "BuildStockoutsInput",
    "BuildStockoutsPrimitive",
    "BuildReturnsLedgerInput",
    "BuildReturnsLedgerPrimitive",
    "AssignJobsInput",
    "AssignJobsPrimitive",
    "BuildIntelligenceHistoryInput",
    "BuildIntelligenceHistoryPrimitive",
    "CalibrateThresholdsInput",
    "CalibrateThresholdsPrimitive",
    "PlanBooksBackfillInput",
    "PlanBooksBackfillPrimitive",
    "BuildOwnerDigestInput",
    "BuildOwnerDigestPrimitive",
    "AssessBooksHygieneInput",
    "AssessBooksHygienePrimitive",
    "BuildPayrollTeamInput",
    "BuildPayrollTeamPrimitive",
    "BuildCustomerLedgerInput",
    "BuildCustomerLedgerPrimitive",
    "RunScenarioInput",
    "RunScenarioPrimitive",
    "TieOutDocumentsInput",
    "TieOutDocumentsPrimitive",
    "BuildBooksCashForecastInput",
    "BuildBooksCashForecastPrimitive",
    "BuildBooksSnapshotInput",
    "BuildBooksSnapshotPrimitive",
    "PlanDecisionWorkItemsInput",
    "PlanDecisionWorkItemsPrimitive",
    "BuildSupplierScorecardInput",
    "BuildSupplierScorecardPrimitive",
    "BuildJobCostingInput",
    "BuildJobCostingPrimitive",
    "BuildIntelligenceReviewInput",
    "BuildIntelligenceReviewPrimitive",
    "BuildJobQuoteInput",
    "BuildJobQuotePrimitive",
    "BuildCustomerProfitabilityInput",
    "BuildCustomerProfitabilityPrimitive",
    "BuildContributionBridgeInput",
    "BuildContributionBridgePrimitive",
    "BuildRateCardInput",
    "BuildRateCardPrimitive",
    "BuildWorkforceCapacityInput",
    "BuildWorkforceCapacityPrimitive",
    "BuildServicesMarginInput",
    "BuildServicesMarginPrimitive",
    "BuildSkillsInventoryInput",
    "BuildSkillsInventoryPrimitive",
    "PlanPriceProbesInput",
    "PlanPriceProbesPrimitive",
    "MatchSkillsInput",
    "MatchSkillsPrimitive",
    "PriceVolumeMixInput",
    "PriceVolumeMixPrimitive",
    "SourceLabourInput",
    "SourceLabourPrimitive",
    "SourceState",
]
