"""The growth × sales × finance seams as executable primitives.

Nine typed, read-only primitives over the sealed documents the seam modules
build: the revenue model, the channel cohort table, pipeline coverage, the
objective-versus-plan reconciliation, the catalog draft that implements a
price plan, and the allocation by payback.  Each one is a pure function of
its inputs (sealed plans, replayed states as dicts, sealed documents); none
reads a provider, persists anything, or moves money.  Their examples are
built from library code alone so the registry can run them.
"""

from __future__ import annotations

from typing import Any, ClassVar, Mapping

from pydantic import BaseModel, ConfigDict, Field

from lightbulb.growth_channel_allocation import ChannelAllocation, build_channel_allocation, compile_channel_allocation_plan
from lightbulb.growth_allocation_outcomes import AllocationOutcome, score_allocation
from lightbulb.growth_channel_cohorts import ChannelCohortReport, build_channel_cohorts, compile_channel_cohort_plan
from lightbulb.growth_operating_review import GrowthReview, build_growth_review
from lightbulb.growth_plan_reconciliation import ObjectivePlanReconciliation, build_objective_plan_reconciliation, compile_reconciliation_plan
from lightbulb.growth_revenue_model import RevenueModel, build_revenue_model, compile_revenue_model_plan
from lightbulb.pipeline_coverage import PipelineCoverage, build_pipeline_coverage, compile_pipeline_coverage_plan
from lightbulb.pipeline_win_loss import WinLossReport, build_win_loss
from lightbulb.primitive_runtime import (
    BusinessProcessPrimitive,
    PrimitiveEvent,
    PrimitiveExecutionContext,
    PrimitiveExecutionResult,
    PrimitiveExecutionStatus,
)

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


# --------------------------------------------------------------------------- #
# Revenue model
# --------------------------------------------------------------------------- #


class BuildRevenueModelInput(_Input):
    plan: dict[str, Any]
    as_of: str
    subscription_states: tuple[SourceState, ...] = ()
    revenue_states: tuple[SourceState, ...] = ()
    deposit_states: tuple[SourceState, ...] = ()
    pipeline_forecast: dict[str, Any] | None = None


class BuildRevenueModelPrimitive(BusinessProcessPrimitive[BuildRevenueModelInput, RevenueModel]):
    """Expected revenue and cash by month from what sales and marketing hold."""

    primitive_ref = "growth.build_revenue_model"
    version = "1.0.0"
    title = "Build the revenue model"
    description = "Seal expected revenue and cash by month from live subscription MRR decayed at the plan's churn, the sealed pipeline forecast over the sales cycle, unpaid invoices at their terms, and deposits held over the draw months. Every assumption is sealed in the plan and echoed; nothing predicts a growth rate. The cash position chain accepts the model's inflows bound by digest."
    input_model = BuildRevenueModelInput
    output_model = RevenueModel
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs: ClassVar[Mapping[str, Any]] = {"plan": compile_revenue_model_plan(_EXAMPLE_COMPANY, currency="USD", overrides={"horizon_months": 3}).to_dict(), "as_of": _EXAMPLE_AS_OF}

    def _execute(self, context: PrimitiveExecutionContext, inputs: BuildRevenueModelInput) -> PrimitiveExecutionResult[RevenueModel]:
        try:
            model = build_revenue_model(inputs.plan, subscription_states=_pairs(inputs.subscription_states), revenue_states=_pairs(inputs.revenue_states), deposit_states=_pairs(inputs.deposit_states), pipeline_forecast=inputs.pipeline_forecast, as_of=inputs.as_of)
        except ValueError as exc:
            return _failed(self, exc)
        return _completed(self, model, f"Revenue model {model.company_ref}: {model.total_expected} {model.currency} expected over {len(model.months)} month(s).", "growth.revenue_model_built", {"model_digest": model.model_digest, "total_expected": str(model.total_expected)})


# --------------------------------------------------------------------------- #
# Channel cohorts
# --------------------------------------------------------------------------- #


class BuildChannelCohortsInput(_Input):
    plan: dict[str, Any]
    as_of: str
    revenue_states: tuple[SourceState, ...] = ()
    subscription_states: tuple[SourceState, ...] = ()
    register_states: tuple[SourceState, ...] = ()
    commission_states: tuple[SourceState, ...] = ()
    attribution: dict[str, Any] | None = None


class BuildChannelCohortsPrimitive(BusinessProcessPrimitive[BuildChannelCohortsInput, ChannelCohortReport]):
    """CAC, payback, and lifetime value per acquisition channel per cohort."""

    primitive_ref = "growth.build_channel_cohorts"
    version = "1.0.0"
    title = "Build the channel cohorts"
    description = "Seal CAC, payback, and lifetime value per acquisition channel per cohort from replayed revenue cases, subscriptions, commissions, and cost registers. Sales is a channel costed from the centres the plan assigns; a customer's channel is the attribution ledger's credited touch or how the case was won, never typed in. Channels are ranked by LTV/CAC."
    input_model = BuildChannelCohortsInput
    output_model = ChannelCohortReport
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs: ClassVar[Mapping[str, Any]] = {"plan": compile_channel_cohort_plan(_EXAMPLE_COMPANY, currency="USD").to_dict(), "as_of": _EXAMPLE_AS_OF}

    def _execute(self, context: PrimitiveExecutionContext, inputs: BuildChannelCohortsInput) -> PrimitiveExecutionResult[ChannelCohortReport]:
        try:
            report = build_channel_cohorts(inputs.plan, revenue_states=_pairs(inputs.revenue_states), subscription_states=_pairs(inputs.subscription_states), register_states=_pairs(inputs.register_states), commission_states=_pairs(inputs.commission_states), attribution=inputs.attribution, as_of=inputs.as_of)
        except ValueError as exc:
            return _failed(self, exc)
        return _completed(self, report, f"Channel cohorts {report.company_ref}: {len(report.customers)} customer(s) across {len(report.cohorts)} cohort row(s); ranking {', '.join(report.channel_ranking) or 'n/a'}.", "growth.channel_cohorts_built", {"report_digest": report.report_digest, "channel_ranking": list(report.channel_ranking)})


# --------------------------------------------------------------------------- #
# Pipeline coverage
# --------------------------------------------------------------------------- #


class AssessPipelineCoverageInput(_Input):
    plan: dict[str, Any]
    pipeline_plan: dict[str, Any]
    period_ref: str
    as_of: str
    prospect_states: tuple[dict[str, Any], ...] = ()
    operating_plan_state: SourceState | None = None
    revenue_model: dict[str, Any] | None = None
    target_amount: str | None = None
    current_sales_heads: int = Field(default=0, ge=0)


def _example_pipeline_plan(currency: str = "USD") -> dict[str, Any]:
    from lightbulb.pipeline_engine_loop import compile_pipeline_engine_blueprint

    return compile_pipeline_engine_blueprint("b2b_saas_outbound", {"require_permission_register": False, "currency": currency}).to_dict()


class AssessPipelineCoveragePrimitive(BusinessProcessPrimitive[AssessPipelineCoverageInput, PipelineCoverage]):
    """Does the pipeline cover next period's revenue, and how many heads close the gap?"""

    primitive_ref = "pipeline.assess_coverage"
    version = "1.0.0"
    title = "Assess pipeline coverage"
    description = "Seal weighted and open pipeline against the period's revenue target (the operating plan's line, the revenue model's month, or a typed amount, and the assessment names which), the coverage ratio against the plan's multiple, and the gap in prospects, touches, and heads at the observed meeting rate or the blueprint's target. The hiring chain accepts the gap only as a requisition bound to the sealed assessment."
    input_model = AssessPipelineCoverageInput
    output_model = PipelineCoverage
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs: ClassVar[Mapping[str, Any]] = {"plan": compile_pipeline_coverage_plan(_EXAMPLE_COMPANY, currency="USD").to_dict(), "pipeline_plan": _example_pipeline_plan(), "period_ref": "2026-11", "as_of": _EXAMPLE_AS_OF, "target_amount": "50000.00"}

    def _execute(self, context: PrimitiveExecutionContext, inputs: AssessPipelineCoverageInput) -> PrimitiveExecutionResult[PipelineCoverage]:
        try:
            coverage = build_pipeline_coverage(inputs.plan, pipeline_plan=inputs.pipeline_plan, prospect_states=list(inputs.prospect_states), period_ref=inputs.period_ref, as_of=inputs.as_of, operating_plan_state=None if inputs.operating_plan_state is None else (inputs.operating_plan_state.plan, inputs.operating_plan_state.state), revenue_model=inputs.revenue_model, target_amount=inputs.target_amount, current_sales_heads=inputs.current_sales_heads)
        except ValueError as exc:
            return _failed(self, exc)
        return _completed(self, coverage, f"Pipeline coverage {coverage.company_ref} for {coverage.period_ref}: {coverage.verdict}; gap {coverage.pipeline_gap} {coverage.currency}, {coverage.additional_heads} additional head(s).", "pipeline.coverage_assessed", {"coverage_digest": coverage.coverage_digest, "verdict": coverage.verdict, "additional_heads": coverage.additional_heads})


# --------------------------------------------------------------------------- #
# Objective versus plan
# --------------------------------------------------------------------------- #


class ReconcileObjectiveWithPlanInput(_Input):
    plan: dict[str, Any]
    objective: dict[str, Any]
    operating_plan_state: SourceState
    as_of: str
    revenue_model: dict[str, Any] | None = None
    assessment: dict[str, Any] | None = None


def _example_reconciliation_input() -> dict[str, Any]:
    from lightbulb.company_cost_centres import compile_cost_centres
    from lightbulb.company_operating_system import compile_company_operating_blueprint
    from lightbulb.growth_objectives import GrowthObjective
    from lightbulb.growth_profit import build_unit_economics
    from lightbulb.operating_plan import compile_operating_plan_policy, open_operating_plan, plan_receipt

    operating = compile_company_operating_blueprint("b2b_saas")
    currency = operating.blueprint.currency
    centres = compile_cost_centres(_EXAMPLE_COMPANY, currency=currency, period_ref="2026-11", centres=[{"centre_ref": "cc-sales", "label": "Sales", "kind": "labour"}])
    policy = compile_operating_plan_policy(_EXAMPLE_COMPANY, operating_plan=operating, periods=[{"period_ref": "2026-11", "period_start": "2026-11-01T00:00:00Z", "period_end": "2026-12-01T00:00:00Z"}], centre_refs=["cc-sales"], cost_centre_map=centres)
    lines = [{"period_ref": "2026-11", "kind": "spend", "ref": "cc-sales", "amount": "100.00"}, {"period_ref": "2026-11", "kind": "revenue", "ref": "pipeline_engine", "amount": "9000.00"}]
    scope = {"tenant_ref": "tenant-example", "company_ref": _EXAMPLE_COMPANY, "project_ref": "project-example", "project_id": "40100000-0000-4000-8000-000000000001", "entity_ref": "plan-2026-11", "currency": currency}
    state = open_operating_plan(policy, scope, receipt=plan_receipt(policy, lines, requester_ref="principal:finance"), opened_at="2026-10-15T00:00:00Z", actor_ref="actor-example")
    economics = build_unit_economics({"analysis_as_of": "2026-08-19T00:00:00Z", "economics_ref": "econ-reconcile-example", "currency": currency, "evidence": ({"observation_ref": "shopify-reconcile-example", "connector_account_ref": "acct.shopify.example", "provider": "shopify", "source_capability": "shopify.analytics_query", "currency": currency, "observed_at": "2026-08-18T00:00:00Z", "window_start": "2026-08-01T00:00:00Z", "window_end": "2026-08-15T00:00:00Z", "metrics": {"gross_sales": "12000.00", "discounts": "600.00", "cogs": "4800.00", "orders": 300}, "evidence_digest": "6" * 64},)})
    objective = GrowthObjective.model_validate({"objective_ref": "q4-contribution-example", "metric": "contribution_profit", "currency": currency, "period_days": 30, "baseline_per_period": "10178.57", "target_per_period": "14000.00", "baseline_economics_digest": economics.economics_digest, "baseline_economics_as_of": "2026-08-19T00:00:00Z", "baseline_window_days": "14.000000", "baseline_complete": True, "committed_at": "2026-08-19T00:00:00Z", "target_by": "2026-12-17T00:00:00Z", "rationale": "Reach 14k monthly contribution before the holiday buy."})
    return {"plan": compile_reconciliation_plan(_EXAMPLE_COMPANY, currency=currency).to_dict(), "objective": objective.model_dump(mode="json", by_alias=True, exclude_none=True), "operating_plan_state": {"plan": policy.to_dict(), "state": state.to_dict()}, "as_of": "2026-10-20T00:00:00Z"}


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


class ReconcileObjectiveWithPlanPrimitive(BusinessProcessPrimitive[ReconcileObjectiveWithPlanInput, ObjectivePlanReconciliation]):
    """Does the plan's revenue, at the margin, deliver the objective, and does the model deliver the plan?"""

    primitive_ref = "growth.reconcile_objective_with_plan"
    version = "1.0.0"
    title = "Reconcile the objective with the plan"
    description = "Seal, per operating plan period, the plan's revenue line turned into contribution at the sealed margin against the growth objective's target scaled to the period, and the revenue model pro-rated onto the period against the plan inside the sealed tolerance. The verdict names which side is short; the lifted reforecast lines stay a guarded operating plan transition."
    input_model = ReconcileObjectiveWithPlanInput
    output_model = ObjectivePlanReconciliation
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs: ClassVar[Mapping[str, Any]] = _LazyExample(_example_reconciliation_input)

    def _execute(self, context: PrimitiveExecutionContext, inputs: ReconcileObjectiveWithPlanInput) -> PrimitiveExecutionResult[ObjectivePlanReconciliation]:
        try:
            reconciliation = build_objective_plan_reconciliation(inputs.plan, objective=inputs.objective, operating_plan_state=(inputs.operating_plan_state.plan, inputs.operating_plan_state.state), revenue_model=inputs.revenue_model, assessment=inputs.assessment, as_of=inputs.as_of)
        except ValueError as exc:
            return _failed(self, exc)
        return _completed(self, reconciliation, f"Objective vs plan {reconciliation.company_ref}: {reconciliation.verdict}; {reconciliation.periods_short} of {reconciliation.periods_ahead} period(s) ahead short by {reconciliation.total_revenue_shortfall_ahead} {reconciliation.currency}.", "growth.objective_reconciled_with_plan", {"reconciliation_digest": reconciliation.reconciliation_digest, "verdict": reconciliation.verdict})


# --------------------------------------------------------------------------- #
# Price plan into the catalog
# --------------------------------------------------------------------------- #


class DraftCatalogFromPricePlanInput(_Input):
    price_plan: dict[str, Any]
    version_ref: str
    drafter_ref: str
    current: dict[str, Any]
    current_plan: dict[str, Any]
    item_refs: tuple[str, ...] | None = None


class PriceCatalogDraft(BaseModel):
    """The catalog's opening receipt for the version that implements the price plan; the catalog still approves and publishes it."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_id: str = Field(default="lightbulb.price_catalog_draft.v1", alias="schema")
    version_ref: str
    price_plan_digest: str
    operation_ref: str
    items_moved: int
    receipt: dict[str, Any]


def _example_draft_input() -> dict[str, Any]:
    from lightbulb.growth_profit import PlanPriceMovePrimitive, plan_price_move
    from lightbulb.price_catalog import compile_price_catalog, draft_receipt, open_catalog_version

    price_plan = plan_price_move(dict(PlanPriceMovePrimitive.example_inputs))
    catalog = compile_price_catalog(_EXAMPLE_COMPANY, currency=price_plan.currency, catalog_ref="catalog-example")
    scope = {"tenant_ref": "tenant-example", "company_ref": _EXAMPLE_COMPANY, "project_ref": "project-example", "project_id": "40100000-0000-4000-8000-000000000001", "entity_ref": "catalog-v1", "currency": price_plan.currency}
    current = open_catalog_version(catalog, scope, receipt=draft_receipt(version_ref="v1", drafter_ref="principal:pricing", items=[{"item_ref": "plan:starter", "kind": "plan", "unit": "seat", "list_price": "49", "billing_period": "month"}]), opened_at="2026-10-01T00:00:00Z", actor_ref="actor-example")
    return {"price_plan": price_plan.to_dict(), "version_ref": "v2", "drafter_ref": "principal:pricing", "current": current.to_dict(), "current_plan": catalog.to_dict()}


class DraftCatalogFromPricePlanPrimitive(BusinessProcessPrimitive[DraftCatalogFromPricePlanInput, PriceCatalogDraft]):
    """Turn a sealed price plan into the catalog version that implements it."""

    primitive_ref = "pricing.draft_from_price_plan"
    version = "1.0.0"
    title = "Draft the catalog version from a price plan"
    description = "Build the price catalog's opening receipt for the version that implements a sealed growth price plan: every named item moved by the plan's ratio, the current version replayed, and the plan bound by digest. The price plan stays non-dispatchable; pricing authority still approves the version by someone other than the drafter and the notice period still runs."
    input_model = DraftCatalogFromPricePlanInput
    output_model = PriceCatalogDraft
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs: ClassVar[Mapping[str, Any]] = _LazyExample(_example_draft_input)

    def _execute(self, context: PrimitiveExecutionContext, inputs: DraftCatalogFromPricePlanInput) -> PrimitiveExecutionResult[PriceCatalogDraft]:
        from lightbulb.growth_profit import PricePlan
        from lightbulb.price_catalog import draft_from_price_plan

        try:
            receipt = draft_from_price_plan(inputs.price_plan, version_ref=inputs.version_ref, drafter_ref=inputs.drafter_ref, current=inputs.current, current_plan=inputs.current_plan, item_refs=None if inputs.item_refs is None else list(inputs.item_refs))
            plan = PricePlan.model_validate(dict(inputs.price_plan))
        except ValueError as exc:
            return _failed(self, exc)
        moved = len(inputs.item_refs) if inputs.item_refs is not None else len(receipt["items"])
        draft = PriceCatalogDraft(version_ref=inputs.version_ref, price_plan_digest=plan.plan_digest, operation_ref=plan.operation.operation_ref, items_moved=moved, receipt=receipt)
        return _completed(self, draft, f"Catalog version {inputs.version_ref} drafted from price plan {plan.plan_ref}: {moved} item(s) moved {plan.operation.direction} by {plan.operation.price_change_ratio}; approval and notice stay the catalog's.", "pricing.catalog_drafted_from_price_plan", {"price_plan_digest": plan.plan_digest, "version_ref": inputs.version_ref, "items_moved": moved})


# --------------------------------------------------------------------------- #
# Allocate by payback
# --------------------------------------------------------------------------- #


class AllocateByPaybackInput(_Input):
    plan: dict[str, Any]
    cohorts: dict[str, Any]
    as_of: str
    allocation_ref: str
    funding_gate: dict[str, Any] | None = None
    budget_envelope: dict[str, Any] | None = None


def _example_envelope(currency: str = "USD") -> dict[str, Any]:
    from lightbulb.cash_runway import build_runway_snapshot, derive_budget_envelope

    snapshot = build_runway_snapshot({"analysis_as_of": "2026-09-18T00:00:00Z", "runway_ref": "runway-allocate-example", "currency": currency, "evidence": ({"observation_ref": "bank-allocate-example", "connector_account_ref": "acct.bank.operating", "provider": "bank", "source_capability": "bank.statement_import", "currency": currency, "observed_at": "2026-09-18T00:00:00Z", "window_start": "2026-08-18T00:00:00Z", "window_end": "2026-09-18T00:00:00Z", "metrics": {"cash_inflows": "30000.00", "cash_outflows": "60000.00", "ending_cash_balance": "600000.00"}, "evidence_digest": "c" * 64},)})
    envelope = derive_budget_envelope({"envelope_ref": "budget-allocate-example", "analysis_as_of": "2026-09-18T00:00:00Z", "runway_snapshot": snapshot, "runway_floor_months": "12"})
    return envelope.model_dump(mode="json", by_alias=True, exclude_none=True)


def _example_allocation_input() -> dict[str, Any]:
    cohorts = build_channel_cohorts(compile_channel_cohort_plan(_EXAMPLE_COMPANY, currency="USD"), as_of=_EXAMPLE_AS_OF)
    return {"plan": compile_channel_allocation_plan(_EXAMPLE_COMPANY, currency="USD").to_dict(), "cohorts": cohorts.to_dict(), "as_of": _EXAMPLE_AS_OF, "allocation_ref": "allocation-example", "budget_envelope": _example_envelope("USD")}


class AllocateByPaybackPrimitive(BusinessProcessPrimitive[AllocateByPaybackInput, ChannelAllocation]):
    """Share the deployable growth spend across paid-back channels by LTV/CAC."""

    primitive_ref = "growth.allocate_by_payback"
    version = "1.0.0"
    title = "Allocate growth spend by payback"
    description = "Seal a monthly budget per acquisition channel from the sealed cohort table and one deployable amount (the funding gate's deployable monthly when deployment is permitted, else the budget envelope's affordable incremental burn). A channel earns budget only after a cohort has paid back and its LTV/CAC clears the floor; shares are capped and the remainder stays unallocated. Every line is a proposed mandate action; nothing moves a budget."
    input_model = AllocateByPaybackInput
    output_model = ChannelAllocation
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs: ClassVar[Mapping[str, Any]] = _LazyExample(_example_allocation_input)

    def _execute(self, context: PrimitiveExecutionContext, inputs: AllocateByPaybackInput) -> PrimitiveExecutionResult[ChannelAllocation]:
        try:
            allocation = build_channel_allocation(inputs.plan, cohorts=inputs.cohorts, as_of=inputs.as_of, allocation_ref=inputs.allocation_ref, funding_gate=inputs.funding_gate, budget_envelope=inputs.budget_envelope)
        except ValueError as exc:
            return _failed(self, exc)
        return _completed(self, allocation, f"Channel allocation {allocation.allocation_ref}: {allocation.verdict}; {allocation.allocated_monthly} of {allocation.deployable_monthly} {allocation.currency} a month across {len(allocation.lines)} channel(s).", "growth.spend_allocated_by_payback", {"allocation_digest": allocation.allocation_digest, "verdict": allocation.verdict, "allocated_monthly": str(allocation.allocated_monthly)})


# --------------------------------------------------------------------------- #
# Win/loss, allocation outcomes, the growth review
# --------------------------------------------------------------------------- #


class BuildWinLossInput(_Input):
    pipeline_plan: dict[str, Any]
    as_of: str
    prospect_states: tuple[dict[str, Any], ...] = ()
    facts: dict[str, dict[str, Any]] | None = None
    since: str | None = None


class BuildWinLossPrimitive(BusinessProcessPrimitive[BuildWinLossInput, WinLossReport]):
    """Where deals are won and lost, and what to change."""

    primitive_ref = "pipeline.build_win_loss"
    version = "1.0.0"
    title = "Build the win/loss report"
    description = "Seal win rate overall and by fit band, source, sequence, last channel, stage at loss, and loss reason from replayed prospects (industry, region, and size when the caller supplies facts), with deterministic recommendations that name the segment and the count behind them."
    input_model = BuildWinLossInput
    output_model = WinLossReport
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs: ClassVar[Mapping[str, Any]] = _LazyExample(lambda: {"pipeline_plan": _example_pipeline_plan(), "as_of": _EXAMPLE_AS_OF})

    def _execute(self, context: PrimitiveExecutionContext, inputs: BuildWinLossInput) -> PrimitiveExecutionResult[WinLossReport]:
        try:
            report = build_win_loss(inputs.pipeline_plan, list(inputs.prospect_states), as_of=inputs.as_of, facts=inputs.facts, since=inputs.since)
        except ValueError as exc:
            return _failed(self, exc)
        return _completed(self, report, f"Win/loss: {report.won} won, {report.lost} lost of {report.prospects}; win rate {report.win_rate_percent if report.win_rate_percent is not None else 'n/a'}.", "pipeline.win_loss_built", {"report_digest": report.report_digest, "won": report.won, "lost": report.lost})


class ScoreAllocationInput(_Input):
    allocation: dict[str, Any]
    cohorts: dict[str, Any]
    as_of: str


def _example_cohort_table(as_of: str, *, paid_back: bool, currency: str = "USD") -> dict[str, Any]:
    """An example-only cohort table with one outbound cohort; real tables come from replayed states."""

    from lightbulb.company_engine_core import seal as _seal

    plan = compile_channel_cohort_plan(_EXAMPLE_COMPANY, currency=currency)
    row = {"cohort": "2026-09", "channel": "outbound", "customers": 2, "churned": 0, "months_observed": 2, "acquisition_cost": "4000.00", "revenue_to_date": "12000.00", "contribution_to_date": "9600.00" if paid_back else "1200.00", "mrr": "1500.00", "cac": "2000.00", "payback_months": 1 if paid_back else None, "payback_met": paid_back, "monthly_churn_percent": "0.00", "lifetime_value": "18000.00" if paid_back else "2250.00", "ltv_cac": "4.50" if paid_back else "0.56", "cost_source_refs": ["bill-example-1"]}
    customers = [{"customer_ref": "customer-example-1", "channel": "outbound", "channel_basis": "pipeline_prospect", "cohort": "2026-09", "first_revenue_at": "2026-09-10T00:00:00Z", "revenue_to_date": "6000.00", "mrr": "750.00", "churned": False, "source_digests": []}, {"customer_ref": "customer-example-2", "channel": "outbound", "channel_basis": "pipeline_prospect", "cohort": "2026-09", "first_revenue_at": "2026-09-12T00:00:00Z", "revenue_to_date": "6000.00", "mrr": "750.00", "churned": False, "source_digests": []}]
    payload = {"company_ref": _EXAMPLE_COMPANY, "currency": currency, "as_of": as_of, "plan_digest": plan.plan_digest, "customers": customers, "cohorts": [row], "channel_ranking": ["outbound"], "unassigned_cost": "0.00", "unassigned_cost_refs": [], "source_digests": []}
    return _seal(ChannelCohortReport, payload, "report_digest").to_dict()


def _example_score_input() -> dict[str, Any]:
    cohorts = _example_cohort_table("2026-11-01T00:00:00Z", paid_back=True)
    allocation = build_channel_allocation(compile_channel_allocation_plan(_EXAMPLE_COMPANY, currency="USD", overrides={"max_share_percent": "100"}), cohorts=cohorts, as_of="2026-09-01T00:00:00Z", allocation_ref="allocation-example", budget_envelope=_example_allocation_input()["budget_envelope"])
    return {"allocation": allocation.to_dict(), "cohorts": cohorts, "as_of": "2026-11-01T00:00:00Z"}


class ScoreAllocationPrimitive(BusinessProcessPrimitive[ScoreAllocationInput, AllocationOutcome]):
    """Did the tranche pay back the way the cohort table said it would?"""

    primitive_ref = "growth.score_allocation"
    version = "1.0.0"
    title = "Score an allocation against the later cohorts"
    description = "Seal, per allocation line, the cohorts acquired from the allocation month on: spend against budget, realised CAC, payback, and LTV/CAC against the predicted, with a verdict (paid_back, on_track, missed, no_customers, unspent) and evidence-weighted samples for the operating memory. An unexecuted allocation is unspent, never a failed channel."
    input_model = ScoreAllocationInput
    output_model = AllocationOutcome
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs: ClassVar[Mapping[str, Any]] = _LazyExample(_example_score_input)

    def _execute(self, context: PrimitiveExecutionContext, inputs: ScoreAllocationInput) -> PrimitiveExecutionResult[AllocationOutcome]:
        try:
            outcome = score_allocation(inputs.allocation, cohorts=inputs.cohorts, as_of=inputs.as_of)
        except ValueError as exc:
            return _failed(self, exc)
        return _completed(self, outcome, f"Allocation {outcome.allocation_ref} after {outcome.months_elapsed} month(s): {outcome.verdict}; {outcome.paid_back} paid back, {outcome.missed} missed.", "growth.allocation_scored", {"outcome_digest": outcome.outcome_digest, "verdict": outcome.verdict})


class BuildGrowthReviewInput(_Input):
    review_ref: str
    as_of: str
    revenue_model: dict[str, Any]
    cohorts: dict[str, Any]
    coverage: dict[str, Any]
    reconciliation: dict[str, Any]
    allocation: dict[str, Any]
    authorizations: tuple[dict[str, Any], ...] = ()
    max_age_days: int = Field(default=7, ge=0, le=90)


def _example_review_input() -> dict[str, Any]:
    from lightbulb.growth_objectives import GrowthObjective

    as_of = "2026-10-20T00:00:00Z"
    reconciliation_input = _example_reconciliation_input()
    currency = str(reconciliation_input["plan"]["currency"])
    model = build_revenue_model(compile_revenue_model_plan(_EXAMPLE_COMPANY, currency=currency, overrides={"horizon_months": 3}), as_of=as_of)
    cohorts = _example_cohort_table(as_of, paid_back=True, currency=currency)
    coverage = build_pipeline_coverage(compile_pipeline_coverage_plan(_EXAMPLE_COMPANY, currency=currency), pipeline_plan=_example_pipeline_plan(currency), period_ref=model.months[1].month, as_of=as_of, revenue_model=model)
    reconciliation = build_objective_plan_reconciliation(reconciliation_input["plan"], objective=GrowthObjective.model_validate(reconciliation_input["objective"]), operating_plan_state=(reconciliation_input["operating_plan_state"]["plan"], reconciliation_input["operating_plan_state"]["state"]), revenue_model=model, as_of=as_of)
    allocation = build_channel_allocation(compile_channel_allocation_plan(_EXAMPLE_COMPANY, currency=currency), cohorts=cohorts, as_of=as_of, allocation_ref="allocation-review-example", budget_envelope=_example_envelope(currency))
    return {"review_ref": "review-example", "as_of": as_of, "revenue_model": model.to_dict(), "cohorts": cohorts, "coverage": coverage.to_dict(), "reconciliation": reconciliation.to_dict(), "allocation": allocation.to_dict()}


class BuildGrowthReviewPrimitive(BusinessProcessPrimitive[BuildGrowthReviewInput, GrowthReview]):
    """The weekly growth review: five sealed documents read together into ordered decisions."""

    primitive_ref = "growth.build_review"
    version = "1.0.0"
    title = "Build the weekly growth review"
    description = "Seal one review from the revenue model, cohort table, coverage assessment, objective reconciliation, and allocation: coherence and freshness checked, headline numbers carried, and the decisions ordered runway, plan, pipeline, channels, each with the authority it needs and, when mandate receipts are supplied, whether it was authorized. The review decides nothing itself."
    input_model = BuildGrowthReviewInput
    output_model = GrowthReview
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs: ClassVar[Mapping[str, Any]] = _LazyExample(_example_review_input)

    def _execute(self, context: PrimitiveExecutionContext, inputs: BuildGrowthReviewInput) -> PrimitiveExecutionResult[GrowthReview]:
        try:
            review = build_growth_review(review_ref=inputs.review_ref, as_of=inputs.as_of, revenue_model=inputs.revenue_model, cohorts=inputs.cohorts, coverage=inputs.coverage, reconciliation=inputs.reconciliation, allocation=inputs.allocation, authorizations=list(inputs.authorizations), max_age_days=inputs.max_age_days)
        except ValueError as exc:
            return _failed(self, exc)
        return _completed(self, review, f"Growth review {review.review_ref}: {review.verdict}; {len(review.decisions)} decision(s).", "growth.review_built", {"review_digest": review.review_digest, "verdict": review.verdict, "decisions": len(review.decisions)})


GROWTH_SEAM_EXECUTABLE_PRIMITIVES: tuple[BusinessProcessPrimitive[Any, Any], ...] = (
    BuildRevenueModelPrimitive(),
    BuildChannelCohortsPrimitive(),
    AssessPipelineCoveragePrimitive(),
    ReconcileObjectiveWithPlanPrimitive(),
    DraftCatalogFromPricePlanPrimitive(),
    AllocateByPaybackPrimitive(),
    BuildWinLossPrimitive(),
    ScoreAllocationPrimitive(),
    BuildGrowthReviewPrimitive(),
)

__all__ = [
    "GROWTH_SEAM_EXECUTABLE_PRIMITIVES",
    "AllocateByPaybackInput",
    "AllocateByPaybackPrimitive",
    "AssessPipelineCoverageInput",
    "AssessPipelineCoveragePrimitive",
    "BuildChannelCohortsInput",
    "BuildChannelCohortsPrimitive",
    "BuildGrowthReviewInput",
    "BuildGrowthReviewPrimitive",
    "BuildWinLossInput",
    "BuildWinLossPrimitive",
    "ScoreAllocationInput",
    "ScoreAllocationPrimitive",
    "BuildRevenueModelInput",
    "BuildRevenueModelPrimitive",
    "DraftCatalogFromPricePlanInput",
    "DraftCatalogFromPricePlanPrimitive",
    "PriceCatalogDraft",
    "ReconcileObjectiveWithPlanInput",
    "ReconcileObjectiveWithPlanPrimitive",
    "SourceState",
]
