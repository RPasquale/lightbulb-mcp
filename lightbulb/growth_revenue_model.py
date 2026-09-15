"""The revenue model: expected revenue and cash by month from what sales and marketing are actually holding.

The operating plan's revenue line is typed by the operator and the cash
forecast takes only dated hand-offs.  Nothing turned the subscriptions in
force, the weighted pipeline, the invoices issued and unpaid, and the
deposits held into expected cash by month.  ``build_revenue_model`` does,
from replayed states and sealed forecasts only, with every assumption it
needs (churn, sales cycle, deposit draw) sealed in the plan and echoed in
the model:

* recurring: each live subscription's MRR, decayed month by month at the
  plan's churn assumption;
* pipeline: the sealed pipeline forecast's weighted value, landing evenly
  over the plan's sales-cycle months;
* receivable: revenue-chain and subscription-chain invoices issued and not
  yet settled, landing at their terms;
* deposits: prepayments held, drawn evenly over the plan's draw months.

``expected_inflows`` hands the cash position chain one dated receivable per
month per component, bound to the sealed model by digest.  Nothing here
reads a provider, persists anything, or predicts a growth rate: the model
computes the consequence of the assumptions it names.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
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
    iso,
    parsed,
    seal,
    sealed_digest,
    skip_digests,
    timestamp,
)

REVENUE_MODEL_PLAN_SCHEMA = "lightbulb.revenue_model_plan.v1"
REVENUE_MODEL_SCHEMA = "lightbulb.revenue_model.v1"
EXPECTED_INFLOW_SCHEMA = "lightbulb.revenue_expected_inflow.v1"
COMPONENTS: tuple[str, ...] = ("recurring", "pipeline", "quotes", "receivable", "deposits")
QUOTE_STAGES: tuple[str, ...] = ("quoted", "accepted", "deposit_held", "executed")
DEFAULT_QUOTE_STAGE_WEIGHTS: dict[str, str] = {"quoted": "50", "accepted": "80", "deposit_held": "90", "executed": "100"}
INVOICED_REVENUE_STATUSES: frozenset[str] = frozenset({"invoice_issued", "payment_applied"})
INVOICED_SUBSCRIPTION_STATUSES: frozenset[str] = frozenset({"invoiced", "payment_failed", "retry_scheduled", "outreach_sent"})
LIVE_SUBSCRIPTION_STATUSES: frozenset[str] = frozenset({"activated", "subscribed", "invoiced", "paid", "cash_settled", "revenue_recognized", "payment_failed", "retry_scheduled", "outreach_sent", "recovered"})
_HUNDRED = Decimal("100")


class RevenueModelError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise RevenueModelError(code, message)


def _money(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


def _month_start(stamp: str, offset: int = 0) -> str:
    at = parsed(stamp)
    year, month = at.year, at.month + offset
    year += (month - 1) // 12
    month = (month - 1) % 12 + 1
    return iso(datetime(year, month, 1, tzinfo=timezone.utc))


def _month_ref(stamp: str) -> str:
    return str(stamp)[:7]


# --------------------------------------------------------------------------- #
# Plan
# --------------------------------------------------------------------------- #


class RevenueModelPlan(StrictModel):
    """The assumptions the model computes with, sealed so every reader sees the same ones: churn, sales cycle, terms, deposit draw, horizon."""

    schema_id: str = Field(default=REVENUE_MODEL_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    horizon_months: int = Field(default=6, ge=1, le=24)
    monthly_churn_percent: Decimal = Field(default=Decimal("2"), validate_default=True)
    sales_cycle_months: int = Field(default=2, ge=1, le=12)
    receivable_terms_days: int = Field(default=30, ge=0, le=180)
    deposit_draw_months: int = Field(default=2, ge=1, le=12)
    quote_stage_weights: dict[str, Decimal] = Field(default_factory=lambda: {key: Decimal(value) for key, value in DEFAULT_QUOTE_STAGE_WEIGHTS.items()}, validate_default=True)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("quote_stage_weights", mode="before")
    @classmethod
    def _weights(cls, value: Any) -> dict[str, Decimal]:
        raw = {str(key): decimal_value(item, field_name=f"quote_stage_weights.{key}") for key, item in dict(value or {}).items()}
        if set(raw) != set(QUOTE_STAGES):
            raise ValueError(f"quote stage weights name exactly {QUOTE_STAGES}")
        if any(weight > _HUNDRED for weight in raw.values()):
            raise ValueError("a quote stage weight is a percentage up to 100")
        return raw

    @field_validator("monthly_churn_percent", mode="before")
    @classmethod
    def _churn(cls, value: Any) -> Decimal:
        result = decimal_value(value, field_name="monthly_churn_percent")
        if result >= _HUNDRED:
            raise ValueError("monthly churn is a percentage below 100")
        return result

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "RevenueModelPlan":
        if not skip_digests(info) and self.plan_digest != sealed_digest(RevenueModelPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self


def compile_revenue_model_plan(company_ref: str, *, currency: str, overrides: Mapping[str, Any] | None = None) -> RevenueModelPlan:
    raw: dict[str, Any] = {"company_ref": company_ref, "currency": str(currency).upper(), **dict(overrides or {})}
    return seal(RevenueModelPlan, raw, "plan_digest")


# --------------------------------------------------------------------------- #
# Model
# --------------------------------------------------------------------------- #


class RevenueMonth(StrictModel):
    month: ShortText
    starts_at: str
    recurring: Decimal
    pipeline: Decimal
    quotes: Decimal = Field(default=Decimal("0"), validate_default=True)
    receivable: Decimal
    deposits: Decimal
    total: Decimal
    live_subscriptions: int = Field(ge=0)

    @field_validator("recurring", "pipeline", "quotes", "receivable", "deposits", "total", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))


class RevenueModel(StrictModel):
    schema_id: str = Field(default=REVENUE_MODEL_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    as_of: str
    plan_digest: Sha256Digest
    months: tuple[RevenueMonth, ...] = Field(min_length=1, max_length=24)
    mrr_now: Decimal
    live_subscriptions_now: int = Field(ge=0)
    weighted_pipeline: Decimal
    weighted_quotes: Decimal = Field(default=Decimal("0"), validate_default=True)
    open_quotes: int = Field(default=0, ge=0)
    receivable_outstanding: Decimal
    deposits_held: Decimal
    total_expected: Decimal
    assumptions: dict[str, str] = Field(default_factory=dict)
    pipeline_forecast_digest: Sha256Digest | None = None
    source_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=6000)
    model_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("months", "source_digests", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("mrr_now", "weighted_pipeline", "weighted_quotes", "receivable_outstanding", "deposits_held", "total_expected", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "RevenueModel":
        if sum((item.total for item in self.months), Decimal("0")).quantize(MONEY_QUANTUM) != self.total_expected:
            raise ValueError("total_expected must equal the months")
        if not skip_digests(info) and self.model_digest != sealed_digest(RevenueModel, self, "model_digest"):
            raise ValueError("model_digest must commit the exact model")
        return self

    def month(self, ref: str) -> RevenueMonth | None:
        return next((item for item in self.months if item.month == ref), None)

    def render(self) -> str:
        lines = [f"**Revenue model {self.company_ref}** as of {self.as_of[:10]}: MRR {self.mrr_now} across {self.live_subscriptions_now} live subscription(s), weighted pipeline {self.weighted_pipeline}, receivable {self.receivable_outstanding}, deposits {self.deposits_held}; {self.total_expected} {self.currency} expected over {len(self.months)} month(s)"]
        for item in self.months:
            lines.append(f"- {item.month}: {item.total} (recurring {item.recurring}, pipeline {item.pipeline}, quotes {item.quotes}, receivable {item.receivable}, deposits {item.deposits})")
        return "\n".join(lines)


def build_revenue_model(plan: RevenueModelPlan | Mapping[str, Any], *, subscription_states: Sequence[tuple[Any, Any]] = (), revenue_states: Sequence[tuple[Any, Any]] = (), deposit_states: Sequence[tuple[Any, Any]] = (), deal_states: Sequence[tuple[Any, Any]] = (), pipeline_forecast: Any = None, as_of: str) -> RevenueModel:
    """The sealed model from replayed subscriptions, revenue cases, and deposits, and the sealed pipeline forecast."""

    from lightbulb.revenue_chain import REVENUE_CHAIN_LIFECYCLE
    from lightbulb.subscription_chain import SUBSCRIPTION_CHAIN_LIFECYCLE

    parsed_plan = plan if isinstance(plan, RevenueModelPlan) else RevenueModelPlan.model_validate(detached(plan))
    stamp = timestamp(as_of, field_name="as_of")
    starts = [_month_start(stamp, offset) for offset in range(parsed_plan.horizon_months)]
    refs = [_month_ref(item) for item in starts]
    buckets = {ref: {"recurring": Decimal("0"), "pipeline": Decimal("0"), "quotes": Decimal("0"), "receivable": Decimal("0"), "deposits": Decimal("0")} for ref in refs}
    digests: list[str] = []

    def land(component: str, when: str, amount: Decimal) -> None:
        """A dated amount lands in its month; anything before the horizon lands in the first month, anything after is outside the model."""

        ref = _month_ref(when)
        if ref < refs[0]:
            ref = refs[0]
        if ref in buckets:
            buckets[ref][component] += amount

    mrr_now = Decimal("0")
    live = 0
    receivable = Decimal("0")
    retention = (_HUNDRED - parsed_plan.monthly_churn_percent) / _HUNDRED
    for plan_doc, state_doc in subscription_states:
        source_plan, state = SUBSCRIPTION_CHAIN_LIFECYCLE.bind(plan_doc, state_doc)
        _require(getattr(source_plan, "company_ref", parsed_plan.company_ref) == parsed_plan.company_ref and state.scope.currency == parsed_plan.currency, "SOURCE_SCOPE_MISMATCH", f"subscription {state.scope.entity_ref} belongs to another company or currency")
        digests.append(state.state_digest)
        ledger = state.ledger
        if state.status in LIVE_SUBSCRIPTION_STATUSES and Decimal(str(ledger.mrr)) > 0:
            mrr = Decimal(str(ledger.mrr))
            mrr_now += mrr
            live += 1
            for index, ref in enumerate(refs):
                buckets[ref]["recurring"] += mrr * (retention ** index)
        outstanding = Decimal(str(ledger.outstanding_amount))
        if state.status == "invoiced" and outstanding <= 0:
            outstanding = Decimal(str(ledger.invoice_total)) - Decimal(str(ledger.applied_amount))  # an issued, unpaid invoice is owed in full until a failure names the balance
        if state.status in INVOICED_SUBSCRIPTION_STATUSES and outstanding > 0:
            amount = outstanding
            receivable += amount
            land("receivable", iso(parsed(str(ledger.issued_at or stamp)) + timedelta(days=parsed_plan.receivable_terms_days)), amount)
    for plan_doc, state_doc in revenue_states:
        source_plan, state = REVENUE_CHAIN_LIFECYCLE.bind(plan_doc, state_doc)
        _require(source_plan.company_ref == parsed_plan.company_ref and state.scope.currency == parsed_plan.currency, "SOURCE_SCOPE_MISMATCH", f"revenue case {state.scope.entity_ref} belongs to another company or currency")
        digests.append(state.state_digest)
        ledger = state.ledger
        if state.status in INVOICED_REVENUE_STATUSES:
            amount = _money(Decimal(str(ledger.invoice_total)) - Decimal(str(ledger.applied_amount)))
            if amount > 0:
                receivable += amount
                land("receivable", iso(parsed(str(ledger.issued_at or stamp)) + timedelta(days=parsed_plan.receivable_terms_days)), amount)
    deposits_held = Decimal("0")
    if deposit_states:
        from lightbulb.prepayment_chain import PREPAYMENT_LIFECYCLE

        for plan_doc, state_doc in deposit_states:
            source_plan, state = PREPAYMENT_LIFECYCLE.bind(plan_doc, state_doc)
            _require(source_plan.company_ref == parsed_plan.company_ref and source_plan.currency == parsed_plan.currency, "SOURCE_SCOPE_MISMATCH", f"deposit {state.scope.entity_ref} belongs to another company or currency")
            digests.append(state.state_digest)
            if state.status == "held" and Decimal(str(state.ledger.remaining)) > 0:
                remaining = Decimal(str(state.ledger.remaining))
                deposits_held += remaining
                slice_amount = remaining / Decimal(parsed_plan.deposit_draw_months)
                for offset in range(parsed_plan.deposit_draw_months):
                    if offset < len(refs):
                        buckets[refs[offset]]["deposits"] += slice_amount
    won_deal_refs: set[str] = set()
    for plan_doc, state_doc in revenue_states:
        deal_ref = dict(detached(state_doc)).get("ledger", {}).get("deal_ref")
        if deal_ref:
            won_deal_refs.add(str(deal_ref))
    weighted_quotes = Decimal("0")
    open_quotes = 0
    if deal_states:
        from lightbulb.deal_desk_engine import DEAL_DESK_LIFECYCLE

        for plan_doc, state_doc in deal_states:
            source_plan, state = DEAL_DESK_LIFECYCLE.bind(plan_doc, state_doc)
            _require(source_plan.company_ref == parsed_plan.company_ref and source_plan.currency == parsed_plan.currency, "SOURCE_SCOPE_MISMATCH", f"deal {state.scope.entity_ref} belongs to another company or currency")
            digests.append(state.state_digest)
            if state.status not in QUOTE_STAGES or state.scope.entity_ref in won_deal_refs or (state.ledger.quote_ref and str(state.ledger.quote_ref) in won_deal_refs):
                continue
            face = Decimal(str(state.ledger.accepted_amount)) if state.status != "quoted" and Decimal(str(state.ledger.accepted_amount)) > 0 else Decimal(str(state.ledger.contract_value))
            if face <= 0:
                continue
            open_quotes += 1
            value = face * parsed_plan.quote_stage_weights[state.status] / _HUNDRED
            weighted_quotes += value
            if state.status == "quoted":
                slice_amount = value / Decimal(parsed_plan.sales_cycle_months)
                for offset in range(parsed_plan.sales_cycle_months):
                    if offset < len(refs):
                        buckets[refs[offset]]["quotes"] += slice_amount
            else:
                buckets[refs[min(1, len(refs) - 1)]]["quotes"] += value
    weighted = Decimal("0")
    forecast_digest = None
    if pipeline_forecast is not None:
        from lightbulb.pipeline_engine_loop import PipelineForecast

        forecast = pipeline_forecast if isinstance(pipeline_forecast, PipelineForecast) else PipelineForecast.model_validate(dict(detached(pipeline_forecast)))
        _require(forecast.currency == parsed_plan.currency, "FORECAST_CURRENCY_MISMATCH", f"the pipeline forecast is in {forecast.currency}, not {parsed_plan.currency}")
        _require(parsed(forecast.forecast_at) <= parsed(stamp), "FORECAST_FROM_FUTURE", "the pipeline forecast cannot come from the future")
        forecast_digest = forecast.forecast_digest
        weighted = Decimal(str(forecast.weighted_pipeline_value))
        if deal_states:
            weighted = max(Decimal("0"), weighted - Decimal(str(forecast.handed_off_value)))  # handed-off prospects are now their deals
        slice_amount = weighted / Decimal(parsed_plan.sales_cycle_months)
        for offset in range(parsed_plan.sales_cycle_months):
            if offset < len(refs):
                buckets[refs[offset]]["pipeline"] += slice_amount
    months = []
    for index, ref in enumerate(refs):
        row = {key: _money(value) for key, value in buckets[ref].items()}
        alive = sum(1 for _plan_doc, state_doc in subscription_states if dict(detached(state_doc)).get("status") in LIVE_SUBSCRIPTION_STATUSES) if index == 0 else None
        months.append({"month": ref, "starts_at": starts[index], **{key: str(value) for key, value in row.items()}, "total": str(_money(sum(row.values(), Decimal("0")))), "live_subscriptions": live if alive is None else alive})
    total = _money(sum((Decimal(item["total"]) for item in months), Decimal("0")))
    assumptions = {"quote_stage_weights": ",".join(f"{key}={parsed_plan.quote_stage_weights[key]}" for key in QUOTE_STAGES), "monthly_churn_percent": str(parsed_plan.monthly_churn_percent), "sales_cycle_months": str(parsed_plan.sales_cycle_months), "receivable_terms_days": str(parsed_plan.receivable_terms_days), "deposit_draw_months": str(parsed_plan.deposit_draw_months), "horizon_months": str(parsed_plan.horizon_months)}
    return seal(RevenueModel, {"company_ref": parsed_plan.company_ref, "currency": parsed_plan.currency, "as_of": stamp, "plan_digest": parsed_plan.plan_digest, "months": months, "mrr_now": str(_money(mrr_now)), "weighted_quotes": str(_money(weighted_quotes)), "open_quotes": open_quotes, "live_subscriptions_now": live, "weighted_pipeline": str(_money(weighted)), "receivable_outstanding": str(_money(receivable)), "deposits_held": str(_money(deposits_held)), "total_expected": str(total), "assumptions": assumptions, "pipeline_forecast_digest": forecast_digest, "source_digests": sorted(set(digests))}, "model_digest")


def verify_revenue_model(value: Any) -> RevenueModel:
    return value if isinstance(value, RevenueModel) else RevenueModel.model_validate(dict(detached(value)))


def expected_inflows(model: RevenueModel | Mapping[str, Any], *, components: Sequence[str] = ("recurring", "pipeline", "receivable")) -> list[dict[str, Any]]:
    """The cash position chain's hand-offs: one dated receivable per month per component, bound to the sealed model."""

    verified = verify_revenue_model(model)
    _require(all(item in COMPONENTS for item in components), "COMPONENT_UNKNOWN", f"components are {COMPONENTS}")
    rows = []
    for item in verified.months:
        for component in components:
            amount = getattr(item, component)
            if amount <= 0:
                continue
            expected_at = item.starts_at if parsed(item.starts_at) >= parsed(verified.as_of) else verified.as_of
            rows.append({"schema": EXPECTED_INFLOW_SCHEMA, "kind": "receivable", "flow_ref": f"revenue_model:{item.month}:{component}", "amount": str(amount), "currency": verified.currency, "expected_at": expected_at, "basis": f"{component} revenue modelled for {item.month} under churn {verified.assumptions.get('monthly_churn_percent')}%", "source_digest": verified.model_digest})
    return rows


REVENUE_MODEL_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "growth_revenue_model",
    "golden_loop": "finance.observed_balances_to_reviewed_cash_forecast@0.1.0",
    "stages": ["replay_subscriptions", "replay_receivables", "replay_deposits", "verify_pipeline_forecast", "seal_model"],
    "components": list(COMPONENTS),
    "required_connectors": ["lightbulb.sdk_engine_state"],
    "hard_rules": [
        "recurring revenue is live MRR decayed at the plan's sealed churn; nothing predicts a growth rate",
        "quotes are the deal desk's replayed deals at the plan's sealed stage weights; a deal that became a revenue case is never counted twice",
        "pipeline revenue is the sealed forecast's weighted value over the plan's sales cycle, never a typed number",
        "receivables and deposits come from replayed cases; the model carries every digest it read",
        "the cash position chain accepts the model's inflows only bound to the sealed model",
    ],
}

__all__ = ["DEFAULT_QUOTE_STAGE_WEIGHTS", "QUOTE_STAGES", "COMPONENTS", "EXPECTED_INFLOW_SCHEMA", "REVENUE_MODEL_MANIFEST", "REVENUE_MODEL_PLAN_SCHEMA", "REVENUE_MODEL_SCHEMA", "RevenueModel", "RevenueModelError", "RevenueModelPlan", "RevenueMonth", "build_revenue_model", "compile_revenue_model_plan", "expected_inflows", "verify_revenue_model"]
