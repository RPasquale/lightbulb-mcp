"""Observed unit economics from closed periods, verified books and reconciled cash.

Cost classifications are an explicit sealed operator policy. Money and customer
counts come only from replayed engine states. Missing customer or cash evidence
leaves CAC, payback or runway unavailable; no caller-written balance fills it.
The report retains its sources and recomputes every metric when validated.
It plans and proves; it performs no reads, writes or statutory calculations.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, MONEY_QUANTUM, OpaqueRef, Sha256Digest, StrictModel, decimal_value, detached, parsed, seal, sealed_digest, skip_digests, timestamp
from lightbulb.company_operating_system import CompanyOperatingPlan, PERIOD_LIFECYCLE
from lightbulb.finance_close_engine import CLOSE_LIFECYCLE, FinanceCloseLoopPlan, verify_books

UNIT_ECONOMICS_KIND = "company_unit_economics"


class UnitEconomicsError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise UnitEconomicsError(code, message)


class UnitEconomicsPlan(StrictModel):
    schema_id: Literal["lightbulb.company_unit_economics_plan.v1"] = Field(default="lightbulb.company_unit_economics_plan.v1", alias="schema")
    company_ref: OpaqueRef
    operating_plan: CompanyOperatingPlan
    acquisition_engines: tuple[OpaqueRef, ...] = ("growth_engine", "pipeline_engine")
    direct_cost_engines: tuple[OpaqueRef, ...] = ("saas_operating_engine", "service_delivery", "people_engine")
    operator_supplied_classification: Literal[True] = True
    max_cash_age_days: int = Field(default=31, ge=0, le=366)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> UnitEconomicsPlan:
        if len(set(self.acquisition_engines)) != len(self.acquisition_engines) or len(set(self.direct_cost_engines)) != len(self.direct_cost_engines):
            raise ValueError("cost classification engines must be unique")
        known = set(self.operating_plan.blueprint.engine_kinds)
        if not set((*self.acquisition_engines, *self.direct_cost_engines)) <= known:
            raise ValueError("cost classifications must name engines bound by the operating plan")
        if not skip_digests(info) and self.plan_digest != sealed_digest(UnitEconomicsPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the classification policy and operating plan")
        return self


def compile_unit_economics(company_ref: str, *, operating_plan: CompanyOperatingPlan | Mapping[str, Any], overrides: Mapping[str, Any] | None = None) -> UnitEconomicsPlan:
    operating = CompanyOperatingPlan.model_validate(detached(operating_plan))
    known = set(operating.blueprint.engine_kinds)
    defaults = {"acquisition_engines": [value for value in ("growth_engine", "pipeline_engine") if value in known], "direct_cost_engines": [value for value in ("saas_operating_engine", "service_delivery", "people_engine") if value in known]}
    return seal(UnitEconomicsPlan, {"company_ref": company_ref, "operating_plan": operating, **defaults, **dict(overrides or {})}, "plan_digest")


class EngineEvidence(StrictModel):
    source_state: dict[str, Any]
    source_plan: dict[str, Any]


def _evidence(state: Any, plan: Any) -> EngineEvidence:
    return EngineEvidence(source_state=dict(detached(state)), source_plan=dict(detached(plan)))


def _scope(state: Any) -> tuple[str, ...]:
    return tuple(str(getattr(state.scope, key)) for key in ("tenant_ref", "company_ref", "project_ref", "project_id", "currency"))


def _ratio(numerator: Decimal, denominator: Decimal) -> Decimal | None:
    return None if denominator <= 0 else (numerator / denominator).quantize(MONEY_QUANTUM)


def _money_proof(period: Any, plan: UnitEconomicsPlan, at: str) -> None:
    """Legacy scalar evidence can replay, but cannot establish observed money."""
    from lightbulb.company_cost_centres import COST_REGISTER_KIND, COST_REGISTER_LIFECYCLE, period_evidence_receipt
    for transition in period.transition_history:
        command, receipt = transition.command, transition.command.receipt
        if command.event != "record_evidence" or not ((receipt.spend or 0) > 0 or (receipt.revenue or 0) > 0):
            continue
        _require(receipt.source_kind == COST_REGISTER_KIND and receipt.source_state is not None and receipt.source_plan is not None,
                 "SPEND_NOT_PROVEN", "positive period money must retain the actual cost register and its plan; a typed digest and amount are not evidence")
        source_plan, source = COST_REGISTER_LIFECYCLE.bind(receipt.source_plan, receipt.source_state)
        _require(source_plan.company_ref == plan.company_ref and _scope(source) == _scope(period), "SCOPE_MISMATCH", "cost money must belong to the measured logical company and authenticated execution scope")
        _require(source.ledger.period_start == period.ledger.period_start and source.ledger.period_end == period.ledger.period_end, "BOOKS_PERIOD_MISMATCH", "cost source must cover the measured accounting window")
        _require(parsed(source.transition_history[-1].command.occurred_at) <= parsed(command.occurred_at) <= parsed(at), "SOURCE_FROM_FUTURE", "cost evidence must exist before the period consumes it and before assessment")
        expected = period_evidence_receipt(source, source_plan=source_plan, engine=receipt.engine, period_ref=period.scope.entity_ref)
        _require(receipt.spend == Decimal(expected["spend"]) and receipt.revenue == Decimal(expected["revenue"]), "SPEND_NOT_PROVEN", "period money must reproduce the actual cost-register projection")


def _derive(plan: UnitEconomicsPlan, period_sources: Sequence[EngineEvidence], close_sources: Sequence[EngineEvidence], subscription_sources: Sequence[EngineEvidence], bank_source: EngineEvidence | None, at: str, custody_source: EngineEvidence | None = None) -> dict[str, Any]:
    _require(bool(period_sources), "PERIODS_MISSING", "economics needs at least one closed operating period")
    periods = []
    digests: list[str] = []
    seen_cash_sources: set[str] = set()
    for source in period_sources:
        source_plan = CompanyOperatingPlan.model_validate(source.source_plan)
        _require(source_plan.blueprint.archetype == plan.operating_plan.blueprint.archetype and source_plan.blueprint.currency == plan.operating_plan.blueprint.currency, "PLAN_MISMATCH", "period plans must share the operating archetype and currency")
        state = PERIOD_LIFECYCLE.State.model_validate(source.source_state, context={PERIOD_LIFECYCLE.plan_context_key: source_plan})
        _require(state.status == "closed", "PERIOD_NOT_CLOSED", "open or merely reconciled periods do not form an observed baseline")
        _require(parsed(at) >= parsed(state.ledger.period_end), "ASSESSMENT_BEFORE_PERIOD_END", "economics cannot be observed before the measurement window ends")
        _money_proof(state, plan, at)
        _require(bool(state.ledger.evidence_source_digests), "SPEND_NOT_PROVEN", "the period must retain artifact-backed cost evidence")
        _require(state.state_digest not in digests, "SOURCE_ALREADY_RECORDED", "a period contributes once")
        cash_sources = set(state.ledger.evidence_source_digests)
        _require(not seen_cash_sources.intersection(cash_sources), "SOURCE_ALREADY_RECORDED", "the same underlying cash evidence cannot fund two periods")
        seen_cash_sources.update(cash_sources)
        digests.append(state.state_digest)
        periods.append(state)
    scope = _scope(periods[0])
    _require(all(_scope(state) == scope for state in periods), "SCOPE_MISMATCH", "all period evidence must belong to the same company and project")
    periods.sort(key=lambda state: state.ledger.period_start)
    for prior, current in zip(periods, periods[1:]):
        _require(prior.ledger.period_end == current.ledger.period_start, "PERIOD_COVERAGE_GAP", "the observed baseline must be contiguous and non-overlapping")
    verified_closes: dict[str, Any] = {}
    for source in close_sources:
        close_plan = FinanceCloseLoopPlan.model_validate(source.source_plan)
        state = CLOSE_LIFECYCLE.State.model_validate(source.source_state, context={CLOSE_LIFECYCLE.plan_context_key: close_plan})
        _require(_scope(state) == scope, "SCOPE_MISMATCH", "the books must belong to the same company and project")
        proof = verify_books(close_plan, state)
        _require(proof.verified, "BOOKS_NOT_VERIFIED", "the finance close must verify its books")
        _require(state.state_digest not in verified_closes, "SOURCE_ALREADY_RECORDED", "a verified close contributes once")
        verified_closes[state.state_digest] = state
        digests.append(state.state_digest)
    for period in periods:
        close = verified_closes.get(period.ledger.close_state_digest)
        _require(close is not None, "BOOKS_NOT_VERIFIED", "every period cites a supplied, replayed and verified finance close")
        _require(close.ledger.period_start == period.ledger.period_start and close.ledger.period_end == period.ledger.period_end, "BOOKS_PERIOD_MISMATCH", "the close must cover exactly the observed period")
    start, end = periods[0].ledger.period_start, periods[-1].ledger.period_end
    _require(parsed(at) >= parsed(end), "ASSESSMENT_BEFORE_PERIOD_END", "economics cannot be observed before the measurement window ends")
    _require(all(parsed(state.transition_history[-1].command.occurred_at) <= parsed(at) for state in [*periods, *verified_closes.values()]), "SOURCE_FROM_FUTURE", "periods and verified books must already exist at assessment")
    days = Decimal(str((parsed(end) - parsed(start)).total_seconds())) / Decimal("86400")
    revenue = sum((state.ledger.total_revenue for state in periods), Decimal("0"))
    spend = sum((state.ledger.total_spend for state in periods), Decimal("0"))
    acquisition = sum((sum((state.ledger.spend_by_engine.get(engine, Decimal("0")) for engine in plan.acquisition_engines), Decimal("0")) for state in periods), Decimal("0"))
    direct = sum((sum((state.ledger.spend_by_engine.get(engine, Decimal("0")) for engine in plan.direct_cost_engines), Decimal("0")) for state in periods), Decimal("0"))
    contribution = revenue - direct
    customers: set[str] = set()
    acquired: set[str] = set()
    for source in subscription_sources:
        from lightbulb.subscription_chain import SUBSCRIPTION_CHAIN_LIFECYCLE, SubscriptionChainPlan

        source_plan = SubscriptionChainPlan.model_validate(source.source_plan)
        _require(source_plan.company_ref == plan.company_ref, "SCOPE_MISMATCH", "subscription plans must name this company")
        state = SUBSCRIPTION_CHAIN_LIFECYCLE.State.model_validate(source.source_state, context={SUBSCRIPTION_CHAIN_LIFECYCLE.plan_context_key: source_plan})
        _require(_scope(state) == scope, "SCOPE_MISMATCH", "customer evidence must belong to the measured company")
        _require(parsed(state.transition_history[-1].command.occurred_at) <= parsed(at), "SOURCE_FROM_FUTURE", "customer evidence must exist before assessment")
        _require(state.ledger.cash_settled_to_date > 0, "CUSTOMER_NOT_PROVEN", "a counted customer has proven settled cash")
        _require(any(item.command.event == "settle_cash" and item.command.receipt.payout_arrival_at is not None and parsed(start) <= parsed(item.command.receipt.payout_arrival_at) < parsed(end) for item in state.transition_history), "CUSTOMER_NOT_PROVEN", "the provider's proven payout arrival must fall inside the measured window")
        ref = str(state.ledger.account_ref)
        _require(ref not in customers, "SOURCE_ALREADY_RECORDED", "a customer is counted once across subscription states")
        customers.add(ref)
        first_subscription = next((transition.command.occurred_at for transition in state.transition_history if transition.command.event == "subscribe"), None)
        _require(first_subscription is not None, "CUSTOMER_NOT_PROVEN", "a counted customer has a subscription transition")
        if parsed(start) <= parsed(first_subscription) < parsed(end):
            acquired.add(ref)
        digests.append(state.state_digest)
    operating_cash = None
    if bank_source is not None:
        from lightbulb.bank_reconciliation import BANK_REC_LIFECYCLE, BankReconciliationPlan

        bank_plan = BankReconciliationPlan.model_validate(bank_source.source_plan)
        _require(bank_plan.company_ref == plan.company_ref, "SCOPE_MISMATCH", "the bank plan must name the measured company")
        bank = BANK_REC_LIFECYCLE.State.model_validate(bank_source.source_state, context={BANK_REC_LIFECYCLE.plan_context_key: bank_plan})
        _require(_scope(bank) == scope, "SCOPE_MISMATCH", "cash evidence must belong to the same company and project")
        _require(bank.status == "reconciled", "BANK_NOT_RECONCILED", "cash comes from a reconciled bank statement")
        _require(parsed(bank.transition_history[-1].command.occurred_at) <= parsed(at), "SOURCE_FROM_FUTURE", "bank reconciliation must exist before assessment")
        age = (parsed(at) - parsed(bank.ledger.period_end)).total_seconds() / 86400
        _require(0 <= age <= plan.max_cash_age_days, "CASH_STALE", "the reconciled balance is future-dated or outside the policy's freshness window")
        operating_cash = bank.ledger.statement_closing
        digests.append(bank.state_digest)
    if "marketplace_supply_engine" in plan.operating_plan.blueprint.engine_kinds and bank_source is not None:
        _require(custody_source is not None, "CUSTODY_SOURCE_MISSING", "marketplace runway must reserve the seller liabilities against bank cash")
    if custody_source is not None:
        from lightbulb.custodial_funds import CUSTODY_LIFECYCLE, operating_cash_position
        custody_plan, custody = CUSTODY_LIFECYCLE.bind(custody_source.source_plan, custody_source.source_state)
        _require(custody_plan.company_ref == plan.company_ref and _scope(custody) == scope, "SCOPE_MISMATCH", "custody belongs to the measured company and project")
        _require(parsed(custody.transition_history[-1].command.occurred_at) <= parsed(at), "SOURCE_FROM_FUTURE", "custody reconciliation must exist before assessment")
        age = (parsed(at) - parsed(custody.ledger.balance_as_of)).total_seconds() / 86400
        _require(0 <= age <= plan.max_cash_age_days, "CASH_STALE", "custody cash must also meet the unit-economics freshness policy")
        if bank_source is not None:
            _require(custody.ledger.bank_state_digest == bank_source.source_state["state_digest"], "CUSTODY_SOURCE_MISMATCH", "bank cash and custody must use the same reconciled statement")
        operating_cash = operating_cash_position(custody, source_plan=custody_plan, at=at).available
        digests.extend(custody.ledger.source_digests)
        digests.append(custody.state_digest)
    monthly_burn = (max(spend - revenue, Decimal("0")) * Decimal("30") / days).quantize(MONEY_QUANTUM)
    cac = _ratio(acquisition, Decimal(len(acquired)))
    monthly_contribution_per_customer = contribution * Decimal("30") / days / Decimal(len(customers)) if customers else Decimal("0")
    return {"currency": plan.operating_plan.blueprint.currency, "period_start": start, "period_end": end, "periods": len(periods), "days": str(days), "revenue": str(revenue), "spend": str(spend), "acquisition_spend": str(acquisition), "direct_cost": str(direct), "contribution": str(contribution), "contribution_margin_percent": _ratio(contribution * Decimal("100"), revenue), "customers": len(customers) if subscription_sources else None, "new_customers": len(acquired) if subscription_sources else None, "cac": cac, "payback_months": _ratio(cac, monthly_contribution_per_customer) if cac is not None else None, "monthly_burn": str(monthly_burn), "operating_cash": operating_cash, "runway_months": _ratio(operating_cash, monthly_burn) if operating_cash is not None else None, "source_digests": tuple(sorted(set(digests)))}


class UnitEconomics(StrictModel):
    schema_id: Literal["lightbulb.company_unit_economics.v1"] = Field(default="lightbulb.company_unit_economics.v1", alias="schema")
    plan: UnitEconomicsPlan
    assessed_at: str
    period_sources: tuple[EngineEvidence, ...] = Field(min_length=1, max_length=24)
    close_sources: tuple[EngineEvidence, ...] = Field(min_length=1, max_length=24)
    subscription_sources: tuple[EngineEvidence, ...] = Field(default_factory=tuple, max_length=500)
    bank_source: EngineEvidence | None = None
    custody_source: EngineEvidence | None = None
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    period_start: str
    period_end: str
    periods: int = Field(ge=1, le=24)
    days: Decimal
    revenue: Decimal
    spend: Decimal
    acquisition_spend: Decimal
    direct_cost: Decimal
    contribution: Decimal
    contribution_margin_percent: Decimal | None = None
    customers: int | None = Field(default=None, ge=0)
    new_customers: int | None = Field(default=None, ge=0)
    cac: Decimal | None = None
    payback_months: Decimal | None = None
    monthly_burn: Decimal
    operating_cash: Decimal | None = None
    runway_months: Decimal | None = None
    source_digests: tuple[Sha256Digest, ...]
    effects_executed: Literal[False] = False
    report_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("assessed_at", "period_start", "period_end")
    @classmethod
    def _stamp(cls, value: str, info: ValidationInfo) -> str:
        return timestamp(value, field_name=str(info.field_name))

    @field_validator("days", "revenue", "spend", "acquisition_spend", "direct_cost", "contribution", "contribution_margin_percent", "cac", "payback_months", "monthly_burn", "operating_cash", "runway_months", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> UnitEconomics:
        if not skip_digests(info):
            expected = _derive(self.plan, self.period_sources, self.close_sources, self.subscription_sources, self.bank_source, self.assessed_at, self.custody_source)
            for key, value in expected.items():
                actual = getattr(self, key)
                if isinstance(actual, Decimal) and value is not None:
                    value = Decimal(str(value)).quantize(MONEY_QUANTUM)
                _require(actual == value, "METRIC_NOT_DERIVED", f"{key} must be recomputed from the retained source states")
            if self.report_digest != sealed_digest(UnitEconomics, self, "report_digest"):
                raise ValueError("report_digest must commit the derived metrics and sources")
        return self


def assess_unit_economics(plan: UnitEconomicsPlan | Mapping[str, Any], periods: Sequence[Any], *, source_plans: Mapping[str, Any], closes: Sequence[Any], assessed_at: str, subscriptions: Sequence[Any] = (), bank_state: Any = None, custody_state: Any = None) -> UnitEconomics:
    parsed_plan = UnitEconomicsPlan.model_validate(detached(plan))
    at = timestamp(assessed_at, field_name="assessed_at")
    def evidence(state: Any) -> EngineEvidence:
        raw = dict(detached(state))
        source_plan = source_plans.get(str(raw.get("plan_digest")))
        _require(source_plan is not None, "SOURCE_PLAN_MISSING", "each engine state needs its exact sealed plan for ledger replay")
        return _evidence(raw, source_plan)
    period_sources, close_sources = tuple(map(evidence, periods)), tuple(map(evidence, closes))
    subscription_sources = tuple(map(evidence, subscriptions))
    bank_source = evidence(bank_state) if bank_state is not None else None
    custody_source = evidence(custody_state) if custody_state is not None else None
    metrics = _derive(parsed_plan, period_sources, close_sources, subscription_sources, bank_source, at, custody_source)
    return seal(UnitEconomics, {"plan": parsed_plan, "assessed_at": at, "period_sources": period_sources, "close_sources": close_sources, "subscription_sources": subscription_sources, "bank_source": bank_source, "custody_source": custody_source, **metrics}, "report_digest")


def economics_summary(report: UnitEconomics | Mapping[str, Any]) -> dict[str, Any]:
    verified = UnitEconomics.model_validate(detached(report))
    return {key: value for key, value in verified.to_dict().items() if key not in {"plan", "period_sources", "close_sources", "subscription_sources", "bank_source", "custody_source"}}


UNIT_ECONOMICS_MANIFEST = {"schema": "lightbulb.company_engine_manifest.v1", "engine": UNIT_ECONOMICS_KIND, "golden_loop": "company.observed_spend_to_unit_economics@0.1.0", "stages": ["bind_closed_periods", "verify_books", "derive_costs", "bind_customers", "bind_cash", "assess"], "statuses": [], "events": [], "hops": {"periods": "closed company_operating_system states retaining replayed cost-register proofs", "books": "finance_close states and verify_books", "customers": "settled subscription_chain states", "cash": "reconciled bank_reconciliation state"}, "required_connectors": [], "hard_rules": ["every metric is derived from retained replayed engine states", "missing customer or cash evidence leaves dependent metrics unavailable", "the classification policy names its operator-supplied basis", "a period and a customer contribute at most once", "cash is not a caller-written balance"]}

__all__ = ["UNIT_ECONOMICS_KIND", "UNIT_ECONOMICS_MANIFEST", "EngineEvidence", "UnitEconomics", "UnitEconomicsError", "UnitEconomicsPlan", "assess_unit_economics", "compile_unit_economics", "economics_summary"]
