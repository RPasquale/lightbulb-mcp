"""Acquisition-period economics replayed from attribution and protected costs.

This fold does not post money. Cost is consumed once from the protected register;
media invoices, content work and reconciled inference cannot be added again as
parallel cost summaries. Conversion CPA and customer acquisition cost are distinct.
"""
from __future__ import annotations
from decimal import Decimal
from typing import Any, Literal
from pydantic import Field, ValidationInfo, field_validator, model_validator
from lightbulb.company_engine_core import (StrictModel, EngineScope, OpaqueRef, Sha256Digest,
    GENESIS_DIGEST, CurrencyCode, MONEY_QUANTUM, detached, seal, sealed_digest, skip_digests,
    same_scope, parsed, timestamp)
from lightbulb.conversion_attribution import AttributionChannel, verify_attribution
from lightbulb.company_cost_centres import COST_REGISTER_LIFECYCLE
from lightbulb.growth_engine_loop import GrowthEngineLoopPlan, CampaignPortfolio

FOLD_KIND = "growth_period_fold"
FOLD_SCHEMA = "lightbulb.growth_acquisition_period_fold.v1"

class GrowthFoldError(ValueError):
    def __init__(self, code, message):
        self.code = code
        super().__init__(f"{code}: {message}")

def _require(condition, code, message):
    if not condition:
        raise GrowthFoldError(code, message)

class ChannelPeriod(StrictModel):
    channel: AttributionChannel | Literal["direct_unattributed"]
    credited_revenue: Decimal
    conversions: int = Field(ge=0, strict=True)
    attributed_conversion_credit: Decimal = Field(default=Decimal(0), ge=0)
    observed_customers: int = Field(ge=0, strict=True)
    media_cost: Decimal
    observed_roas: Decimal | None = None
    cost_per_conversion: Decimal | None = None
    marginal_return_proven: Literal[False] = False

    @field_validator("credited_revenue", "media_cost", "observed_roas", "cost_per_conversion", "attributed_conversion_credit", mode="before")
    @classmethod
    def money(cls, value):
        if value is None: return None
        amount = Decimal(str(value))
        if not amount.is_finite() or amount < 0:
            raise ValueError("period economic values must be finite and nonnegative")
        return amount

class GrowthPeriodFold(StrictModel):
    schema_id: Literal["lightbulb.growth_acquisition_period_fold.v1"] = Field(default=FOLD_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    scope: EngineScope
    currency: CurrencyCode
    period_start: str
    period_end: str
    folded_at: str
    growth_plan: dict[str, Any]
    portfolio: dict[str, Any]
    attribution_ledger: dict[str, Any]
    cost_register: dict[str, Any]
    cost_plan: dict[str, Any]
    acquisition_engines: tuple[OpaqueRef, ...]
    channels: tuple[ChannelPeriod, ...]
    observed_revenue: Decimal
    attributed_revenue: Decimal
    unmatched_revenue: Decimal
    acquisition_cost: Decimal
    cost_basis: Literal["recorded_accruals"] = "recorded_accruals"
    cost_register_status: str
    cost_coverage_percent: Decimal | None = None
    shared_acquisition_cost: Decimal
    conversions: int = Field(ge=0, strict=True)
    observed_customers: int = Field(ge=0, strict=True)
    blended_cost_per_conversion: Decimal | None = None
    customer_cohort: dict[str,Any] | None = None
    new_customers: int | None = Field(default=None,ge=0,strict=True)
    blended_cac: Decimal | None = None
    customer_cohort_status: Literal["first_purchase_history_required","host_attested_acquisition_cohort"] = "first_purchase_history_required"
    cost_source_digests: tuple[Sha256Digest, ...]
    posts_money: Literal[False] = False
    fold_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("observed_revenue", "attributed_revenue", "unmatched_revenue", "acquisition_cost",
                     "shared_acquisition_cost", "blended_cost_per_conversion", "blended_cac", mode="before")
    @classmethod
    def money(cls, value):
        return ChannelPeriod.money(value)

    @model_validator(mode="after")
    def exact(self, info: ValidationInfo):
        if sum((c.credited_revenue for c in self.channels), Decimal(0)) != self.observed_revenue:
            raise ValueError("channel revenue must conserve all observed conversions, including unmatched")
        if self.attributed_revenue + self.unmatched_revenue != self.observed_revenue:
            raise ValueError("credited and unmatched money must conserve observed revenue")
        if sum((c.media_cost for c in self.channels), Decimal(0)) + self.shared_acquisition_cost != self.acquisition_cost:
            raise ValueError("channel and shared costs must conserve the protected acquisition numerator")
        if not skip_digests(info) and self.fold_digest != sealed_digest(type(self), self, "fold_digest"):
            raise ValueError("fold_digest must commit the complete retained evidence")
        return self


def fold_growth_period(plan, portfolio, attribution_ledger, cost_register, *, cost_plan, company_ref,
        scope, folded_at, acquisition_engines=("growth_engine", "pipeline_engine"), customer_cohort=None, cohort_scope=None, cohort_keyring=None):
    plan = GrowthEngineLoopPlan.model_validate(detached(plan))
    portfolio = CampaignPortfolio.model_validate(detached(portfolio))
    scoped = EngineScope.model_validate(detached(scope))
    attribution = verify_attribution(attribution_ledger)
    costs_plan, costs = COST_REGISTER_LIFECYCLE.bind(cost_plan, cost_register)
    at = timestamp(folded_at, field_name="folded_at")
    _require(portfolio.plan_digest == plan.plan_digest and attribution.portfolio_digest == portfolio.portfolio_digest,
        "PORTFOLIO_NOT_BOUND", "attribution must name this exact growth plan and portfolio")
    _require(attribution.company_ref == costs_plan.company_ref == company_ref
        and same_scope(scoped, attribution.scope) and same_scope(scoped, costs.scope),
        "SOURCE_SCOPE_MISMATCH", "all economic sources must belong to this company and execution scope")
    _require(scoped.currency == plan.blueprint.currency == costs.scope.currency,
        "CURRENCY_MISMATCH", "acquisition economics cannot infer foreign exchange")
    _require(attribution.window_start == costs.ledger.period_start == portfolio.period_start
        and attribution.window_end == costs.ledger.period_end == portfolio.period_end,
        "PERIOD_MISMATCH", "attribution and protected costs must cover the exact portfolio period")
    _require(parsed(portfolio.period_end) <= parsed(at)
        and all(parsed(t.command.occurred_at) <= parsed(at) for t in costs.transition_history),
        "PERIOD_NOT_OBSERVED", "fold after the complete period and its recorded source evidence")
    _require(attribution.attribution_window_days == plan.blueprint.attribution_window_days,
        "ATTRIBUTION_WINDOW_MISMATCH", "the fold uses the growth plan's lookback policy")
    _require({"last_touch":"last_eligible_touch", "first_touch":"first_eligible_touch", "linear":"linear_eligible_touches"}.get(plan.blueprint.attribution_model) == attribution.method, "ATTRIBUTION_MODEL_MISMATCH", "the canonical attribution ledger must use the declared growth model")
    engines = tuple(sorted(set(acquisition_engines)))
    _require(bool(engines) and len(engines) == len(acquisition_engines)
        and set(engines) <= set(costs.ledger.bound_engines),
        "ACQUISITION_ENGINE_UNKNOWN", "select unique acquisition engines bound to the protected cost register")
    _require(costs.status != "abandoned", "COST_REGISTER_ABANDONED", "abandoned cost evidence cannot close acquisition economics")
    rows = [row for row in costs.ledger.sources if row.engine in engines and row.spend_amount > 0]
    total_cost = sum((Decimal(costs.ledger.engine_spend.get(engine, 0)) for engine in engines), Decimal(0))
    by_source = {t.command.receipt.source_ref:t.command.receipt for t in costs.transition_history if t.command.event == "record_source"}
    media = {}
    for row in rows:
        receipt = by_source.get(row.source_ref)
        if receipt is not None and receipt.media_statement is not None:
            from lightbulb.channel_spend_statements import verify_statement
            statement = verify_statement(receipt.media_statement)
            media[statement.channel] = media.get(statement.channel,Decimal(0)) + row.spend_amount
    shared = total_cost - sum(media.values(), Decimal(0))
    _require(shared >= 0, "COST_SOURCE_MISMATCH", "per-channel costs cannot exceed the protected numerator")
    conversion_map = {c.identity_commitment:c for c in attribution.conversions}
    grouped = {}
    for credit in attribution.credits:
        grouped.setdefault(credit.channel, []).append(credit)
    grouped["direct_unattributed"] = [conversion_map[key] for key in attribution.unmatched]
    channels=[]
    for channel in sorted(set(grouped) | set(media)):
        conversions = grouped.get(channel, [])
        revenue = sum((c.value for c in conversions), Decimal(0)); cost = media.get(channel, Decimal(0))
        channels.append(ChannelPeriod(channel=channel, credited_revenue=revenue, conversions=len({c.identity_commitment for c in conversions}),
            observed_customers=len({conversion_map[c.identity_commitment].unit_commitment for c in conversions}), media_cost=cost,
            attributed_conversion_credit=sum((getattr(c,"conversion_weight",Decimal(1)) for c in conversions),Decimal(0)),
            observed_roas=None if cost==0 else (revenue/cost).quantize(Decimal("0.0001")),
            cost_per_conversion=None if not conversions else (cost/sum((getattr(c,"conversion_weight",Decimal(1)) for c in conversions),Decimal(0))).quantize(MONEY_QUANTUM)))
    cohort=None
    if customer_cohort is not None:
        from lightbulb.growth_customers import verify_customer_cohort_evidence
        from lightbulb.dynamic_workflows import DynamicWorkflowScope
        _require(cohort_scope is not None and cohort_keyring is not None,"COHORT_AUTHORITY_REQUIRED",
            "the host must supply its trusted exact-scope verifier; a JSON count cannot prove acquisition")
        authority=DynamicWorkflowScope.model_validate(cohort_scope)
        _require(authority.project_ref==scoped.project_ref,"SOURCE_SCOPE_MISMATCH","the cohort verifier must use the active project")
        cohort=verify_customer_cohort_evidence(customer_cohort,scope=authority,scope_keyring=cohort_keyring)
        _require(cohort.currency==scoped.currency and cohort.acquisition_window_start==portfolio.period_start
            and cohort.acquisition_window_end==portfolio.period_end,"COHORT_PERIOD_MISMATCH",
            "the host-attested first-acquisition cohort must cover this exact currency and period")
        _require(parsed(cohort.observed_at)<=parsed(at),"COHORT_NOT_OBSERVED","future cohort evidence cannot establish new customers")
        _require(cohort.cohort_size<=len({c.unit_commitment for c in attribution.conversions}),"COHORT_EXCEEDS_OBSERVED",
            "new customers cannot exceed the distinct customers in retained conversions")
    count = len(attribution.conversions)
    return seal(GrowthPeriodFold, dict(company_ref=company_ref, scope=scoped.to_dict(), currency=scoped.currency,
        period_start=portfolio.period_start, period_end=portfolio.period_end, folded_at=at,
        growth_plan=plan.to_dict(), portfolio=portfolio.to_dict(), attribution_ledger=attribution.to_dict(),
        cost_register=costs.to_dict(), cost_plan=costs_plan.to_dict(), acquisition_engines=engines,
        channels=[c.to_dict() for c in channels], observed_revenue=attribution.observed_total,
        attributed_revenue=attribution.attributed_total, unmatched_revenue=attribution.observed_total-attribution.attributed_total,
        acquisition_cost=total_cost, cost_register_status=costs.status, cost_coverage_percent=costs.ledger.coverage_percent,
        shared_acquisition_cost=shared, conversions=count,
        observed_customers=len({c.unit_commitment for c in attribution.conversions}),
        blended_cost_per_conversion=None if not count else (total_cost/count).quantize(MONEY_QUANTUM),
        customer_cohort=None if cohort is None else cohort.model_dump(mode="json"),
        new_customers=None if cohort is None else cohort.cohort_size,
        blended_cac=None if cohort is None or cohort.cohort_size == 0 else (total_cost/cohort.cohort_size).quantize(MONEY_QUANTUM),
        customer_cohort_status="first_purchase_history_required" if cohort is None else "host_attested_acquisition_cohort",
        cost_source_digests=sorted({r.source_digest for r in rows})), "fold_digest")


def verify_growth_period_fold(value, *, cohort_scope=None, cohort_keyring=None):
    result = GrowthPeriodFold.model_validate(detached(value))
    expected = fold_growth_period(result.growth_plan, result.portfolio, result.attribution_ledger, result.cost_register,
        cost_plan=result.cost_plan, company_ref=result.company_ref, scope=result.scope, folded_at=result.folded_at,
        acquisition_engines=result.acquisition_engines,customer_cohort=result.customer_cohort,cohort_scope=cohort_scope,cohort_keyring=cohort_keyring)
    _require(expected.fold_digest == result.fold_digest, "FOLD_SOURCE_MISMATCH", "period economics must replay all canonical sources")
    return result


def growth_period_signals(value, *, cohort_scope=None, cohort_keyring=None):
    from lightbulb.company_operating_system import CompanySignal
    fold = verify_growth_period_fold(value,cohort_scope=cohort_scope,cohort_keyring=cohort_keyring)
    return [CompanySignal(name="signals.attributed_revenue", producer="growth_engine", emitted_at=fold.folded_at,
        payload={"channel":"portfolio_blended", "attributed_revenue":str(fold.attributed_revenue),
            "spend":str(fold.acquisition_cost), "window_end":fold.period_end, "fold_digest":fold.fold_digest,
            "source_cost_register_digest":fold.cost_register["state_digest"], "posts_money":False})]

GROWTH_PERIOD_FOLD_MANIFEST = {"schema":"lightbulb.company_engine_manifest.v1", "engine":FOLD_KIND,
    "golden_loop":"growth.store_truth_to_attributed_revenue@0.1.0", "stages":["replay_attribution", "replay_protected_costs", "fold_acquisition", "emit_advisory_signal"],
    "hard_rules":["aggregate provider metrics cannot create revenue", "all acquisition costs enter once through the protected register",
        "observed customers are not proven new customers", "zero denominators produce no ratio", "a fold does not post money"]}
__all__=["GrowthFoldError", "ChannelPeriod", "GrowthPeriodFold", "fold_growth_period", "verify_growth_period_fold", "growth_period_signals", "GROWTH_PERIOD_FOLD_MANIFEST"]
