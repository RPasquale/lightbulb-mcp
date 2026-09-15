"""Customer cohorts: what a customer acquired in a given month goes on to buy, what that is worth, what it cost to acquire, and when it pays back, from the replayed orders and registers.

The customer table says what each customer earned in one window; the
question a growing business asks is what a new customer is worth over
time.  ``build_customer_cohorts`` seals that from the chains:

* every replayed fulfilment state that names a customer, grouped by the
  month of the customer's first order (the cohort), with the orders,
  units, returns, and net order value each cohort placed in every month
  since;
* per cohort: customers, orders, repeat customers and the repeat rate,
  orders per customer, revenue per customer, the revenue curve by month
  since acquisition, and the months observed;
* contribution per customer at the sealed margin report's contribution
  margin when a report is supplied, else revenue only;
* acquisition spend per cohort month from the replayed cost registers
  (channel spend and media invoices), the cost per acquired customer,
  and the months to pay it back at the cohort's contribution a month.

Customers whose first order fell before the window are excluded from
cohorts but their later orders are counted as returning revenue.
Nothing here reads a provider or persists anything.
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

CUSTOMER_COHORT_PLAN_SCHEMA = "lightbulb.customer_cohort_plan.v1"
CUSTOMER_COHORTS_SCHEMA = "lightbulb.customer_cohorts.v1"
ACQUISITION_SOURCE_KINDS: tuple[str, ...] = ("channel_spend", "media_invoice")
_HUNDRED = Decimal("100")
_PCT = Decimal("0.01")


class CustomerCohortError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise CustomerCohortError(code, message)


def _money(value: Any) -> Decimal:
    result = Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)
    return Decimal("0.00") if result == 0 else result


def _pct(value: Any) -> Decimal:
    result = Decimal(str(value)).quantize(_PCT, rounding=ROUND_HALF_UP)
    return Decimal("0.00") if result == 0 else result


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


def _month(stamp: str) -> str:
    return stamp[:7]


def _months_between(first: str, later: str) -> int:
    return (int(later[:4]) - int(first[:4])) * 12 + (int(later[5:7]) - int(first[5:7]))


class CustomerCohortPlan(StrictModel):
    schema_id: str = Field(default=CUSTOMER_COHORT_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    acquisition_centre_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    repeat_rate_floor_percent: Decimal = Field(default=Decimal("20"), validate_default=True)
    payback_ceiling_months: int = Field(default=12, ge=1, le=120)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("acquisition_centre_refs", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("repeat_rate_floor_percent", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "CustomerCohortPlan":
        if not skip_digests(info) and self.plan_digest != sealed_digest(CustomerCohortPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self


def compile_customer_cohort_plan(company_ref: str, *, currency: str, overrides: Mapping[str, Any] | None = None) -> CustomerCohortPlan:
    return seal(CustomerCohortPlan, {"company_ref": company_ref, "currency": str(currency).upper(), **dict(overrides or {})}, "plan_digest")


class CohortMonth(StrictModel):
    months_since: int = Field(ge=0)
    customers_active: int = Field(ge=0)
    orders: int = Field(ge=0)
    revenue: Decimal
    revenue_per_customer: Decimal
    cumulative_revenue_per_customer: Decimal

    @field_validator("revenue", "revenue_per_customer", "cumulative_revenue_per_customer", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class Cohort(StrictModel):
    cohort: ShortText
    customers: int = Field(ge=1)
    orders: int = Field(ge=1)
    units: Decimal
    returned_units: Decimal
    repeat_customers: int = Field(ge=0)
    repeat_rate_percent: Decimal
    orders_per_customer: Decimal
    revenue: Decimal
    revenue_per_customer: Decimal
    contribution_per_customer: Decimal | None = None
    months_observed: int = Field(ge=1)
    curve: tuple[CohortMonth, ...] = Field(default_factory=tuple, max_length=240)
    acquisition_spend: Decimal | None = None
    cost_per_customer: Decimal | None = None
    payback_months: Decimal | None = None
    value_to_cost: Decimal | None = None
    verdict: ShortText

    @field_validator("curve", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("units", "returned_units", "repeat_rate_percent", "orders_per_customer", "revenue", "revenue_per_customer", "contribution_per_customer", "acquisition_spend", "cost_per_customer", "payback_months", "value_to_cost", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class CustomerCohorts(StrictModel):
    schema_id: str = Field(default=CUSTOMER_COHORTS_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    window_start: str
    window_end: str
    as_of: str
    plan_digest: Sha256Digest
    margin_report_digest: Sha256Digest | None = None
    contribution_margin_percent: Decimal | None = None
    cohorts: tuple[Cohort, ...] = Field(default_factory=tuple, max_length=240)
    customers: int = Field(ge=0)
    orders: int = Field(ge=0)
    orders_unattributed: int = Field(ge=0)
    returning_customers: int = Field(ge=0)
    returning_orders: int = Field(ge=0)
    returning_revenue: Decimal
    repeat_rate_percent: Decimal | None = None
    acquisition_spend: Decimal | None = None
    acquisition_unassigned: Decimal | None = None
    recommendations: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=24)
    source_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=12000)
    cohorts_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("cohorts", "recommendations", "source_digests", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("contribution_margin_percent", "returning_revenue", "repeat_rate_percent", "acquisition_spend", "acquisition_unassigned", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "CustomerCohorts":
        if sum(row.customers for row in self.cohorts) != self.customers:
            raise ValueError("customers is the sum of every cohort")
        if not skip_digests(info) and self.cohorts_digest != sealed_digest(CustomerCohorts, self, "cohorts_digest"):
            raise ValueError("cohorts_digest must commit the exact document")
        return self

    def cohort(self, month: str) -> Cohort | None:
        return next((row for row in self.cohorts if row.cohort == month), None)

    def render(self) -> str:
        repeat = "n/a" if self.repeat_rate_percent is None else f"{self.repeat_rate_percent}%"
        lines = [f"**Customer cohorts {self.company_ref}** {self.window_start[:10]} to {self.window_end[:10]}: {self.customers} new customer(s) in {len(self.cohorts)} cohort(s), repeat rate {repeat}; {self.returning_customers} returning customer(s) worth {self.returning_revenue} {self.currency}."]
        lines.extend(f"- {row.cohort}: {row.verdict}" for row in self.cohorts)
        return "\n".join(lines)


def build_customer_cohorts(plan: CustomerCohortPlan | Mapping[str, Any], *, fulfilment_states: Sequence[tuple[Any, Any]], register_states: Sequence[tuple[Any, Any]] = (), margin_report: Mapping[str, Any] | Any | None = None, window_start: str, window_end: str, as_of: str) -> CustomerCohorts:
    """The sealed cohort table: every customer first seen in the window, what they went on to order, what it cost to acquire them, and when it pays back."""

    parsed_plan = plan if isinstance(plan, CustomerCohortPlan) else CustomerCohortPlan.model_validate(detached(plan))
    start, end = timestamp(window_start, field_name="window_start"), timestamp(window_end, field_name="window_end")
    _require(parsed(end) > parsed(start), "WINDOW_EMPTY", "window_end must follow window_start")
    at = timestamp(as_of, field_name="as_of")
    digests: list[str] = []
    margin = None
    report_digest = None
    if margin_report is not None:
        from lightbulb.product_margin import verify_product_margin

        report = verify_product_margin(margin_report)
        _require(report.company_ref == parsed_plan.company_ref and report.currency == parsed_plan.currency, "SOURCE_SCOPE_MISMATCH", "the margin report names another company or currency")
        margin = None if report.contribution_margin_percent is None else Decimal(str(report.contribution_margin_percent))
        report_digest = report.report_digest
        digests.append(report_digest)

    # every attributed order, oldest first, so a customer's first order is known before the window is applied
    orders: list[dict[str, Any]] = []
    unattributed = 0
    for order_plan, state in fulfilment_states:
        _require(getattr(order_plan, "company_ref", None) == parsed_plan.company_ref and getattr(order_plan, "currency", None) == parsed_plan.currency, "SOURCE_SCOPE_MISMATCH", f"order {state.scope.entity_ref} belongs to another company or currency")
        ledger = state.ledger
        if ledger.order_created_at is None or state.status == "cancelled":
            continue
        digests.append(state.state_digest)
        customer_ref = getattr(ledger, "customer_ref", None)
        if not customer_ref:
            unattributed += 1
            continue
        orders.append({"customer_ref": str(customer_ref), "at": str(ledger.order_created_at), "value": Decimal(str(ledger.order_total)), "units": sum((Decimal(str(value)) for value in ledger.units.values()), Decimal("0")), "returned": sum((Decimal(str(value)) for value in ledger.returned_units.values()), Decimal("0"))})
    orders.sort(key=lambda row: (row["at"], row["customer_ref"]))
    first_order: dict[str, str] = {}
    for row in orders:
        first_order.setdefault(row["customer_ref"], row["at"])
    in_window = {customer for customer, stamp in first_order.items() if start <= stamp < end}

    # acquisition spend per month from the registers
    spend_by_month: dict[str, Decimal] = {}
    unassigned = Decimal("0")
    spend_known = False
    if register_states:
        from lightbulb.company_cost_centres import COST_REGISTER_LIFECYCLE

        spend_known = True
        for plan_doc, state_doc in register_states:
            register_map, register = COST_REGISTER_LIFECYCLE.bind(plan_doc, state_doc)
            _require(register_map.company_ref == parsed_plan.company_ref and register_map.currency == parsed_plan.currency, "SOURCE_SCOPE_MISMATCH", f"register {register.scope.entity_ref} belongs to another company or currency")
            digests.append(register.state_digest)
            for source in register.ledger.sources:
                if source.source_kind not in ACQUISITION_SOURCE_KINDS:
                    continue
                amount = Decimal(str(source.spend_amount)) if Decimal(str(source.spend_amount)) > 0 else Decimal(str(source.amount))
                if amount <= 0:
                    continue
                if parsed_plan.acquisition_centre_refs and str(source.centre_ref) not in parsed_plan.acquisition_centre_refs:
                    unassigned += amount
                    continue
                month = _month(str(source.recorded_at))
                spend_by_month[month] = spend_by_month.get(month, Decimal("0")) + amount

    # cohorts by first-order month
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in orders:
        customer = row["customer_ref"]
        if customer in in_window:
            grouped.setdefault(_month(first_order[customer]), []).append(row)
    returning_customers = {row["customer_ref"] for row in orders if row["customer_ref"] not in in_window and start <= row["at"] < end}
    returning_orders = [row for row in orders if row["customer_ref"] in returning_customers and start <= row["at"] < end]
    horizon_month = _month(at)
    cohorts: list[dict[str, Any]] = []
    for month in sorted(grouped):
        rows = grouped[month]
        customers = sorted({row["customer_ref"] for row in rows})
        per_customer_orders = {customer: sum(1 for row in rows if row["customer_ref"] == customer) for customer in customers}
        repeat = sum(1 for count in per_customer_orders.values() if count > 1)
        revenue = _money(sum((row["value"] for row in rows), Decimal("0")))
        count = len(customers)
        months_observed = max(_months_between(month, horizon_month) + 1, 1)
        curve: list[dict[str, Any]] = []
        cumulative = Decimal("0")
        for since in range(months_observed):
            slice_rows = [row for row in rows if _months_between(month, _month(row["at"])) == since]
            slice_revenue = _money(sum((row["value"] for row in slice_rows), Decimal("0")))
            cumulative += slice_revenue
            curve.append({"months_since": since, "customers_active": len({row["customer_ref"] for row in slice_rows}), "orders": len(slice_rows), "revenue": str(slice_revenue), "revenue_per_customer": str(_money(slice_revenue / count)), "cumulative_revenue_per_customer": str(_money(cumulative / count))})
        revenue_per_customer = _money(revenue / count)
        contribution_per_customer = None if margin is None else _money(revenue_per_customer * margin / _HUNDRED)
        spend = spend_by_month.get(month) if spend_known else None
        cost_per_customer = None if spend is None else _money(spend / count)
        monthly_contribution = None if contribution_per_customer is None else contribution_per_customer / Decimal(months_observed)
        payback = None if cost_per_customer is None or monthly_contribution is None or monthly_contribution <= 0 else _pct(cost_per_customer / monthly_contribution)
        value_to_cost = None if cost_per_customer is None or cost_per_customer <= 0 or contribution_per_customer is None else _pct(contribution_per_customer / cost_per_customer)
        repeat_rate = _pct(Decimal(repeat) / Decimal(count) * _HUNDRED)
        verdict = f"{count} customer(s), {len(rows)} order(s), {revenue_per_customer} {parsed_plan.currency} a customer over {months_observed} month(s), repeat rate {repeat_rate}%"
        if contribution_per_customer is not None:
            verdict += f", contribution {contribution_per_customer} a customer"
        if cost_per_customer is not None:
            verdict += f", acquired at {cost_per_customer} each" + (f", payback {payback} month(s)" if payback is not None else ", no payback at this contribution") + (f", {value_to_cost}x value to cost" if value_to_cost is not None else "")
        elif spend_known:
            verdict += ", no acquisition spend recorded for the month"
        cohorts.append({"cohort": month, "customers": count, "orders": len(rows), "units": str(_money(sum((row["units"] for row in rows), Decimal("0")))), "returned_units": str(_money(sum((row["returned"] for row in rows), Decimal("0")))), "repeat_customers": repeat, "repeat_rate_percent": str(repeat_rate), "orders_per_customer": str(_pct(Decimal(len(rows)) / Decimal(count))), "revenue": str(revenue), "revenue_per_customer": str(revenue_per_customer), "contribution_per_customer": None if contribution_per_customer is None else str(contribution_per_customer), "months_observed": months_observed, "curve": curve, "acquisition_spend": None if spend is None else str(_money(spend)), "cost_per_customer": None if cost_per_customer is None else str(cost_per_customer), "payback_months": None if payback is None else str(payback), "value_to_cost": None if value_to_cost is None else str(value_to_cost), "verdict": verdict[:300]})
    total_customers = sum(row["customers"] for row in cohorts)
    total_repeat = sum(row["repeat_customers"] for row in cohorts)
    overall_repeat = None if total_customers == 0 else _pct(Decimal(total_repeat) / Decimal(total_customers) * _HUNDRED)
    recommendations: list[str] = []
    for row in cohorts:
        if Decimal(row["repeat_rate_percent"]) < parsed_plan.repeat_rate_floor_percent and row["months_observed"] >= 2:
            recommendations.append(f"{row['cohort']}: repeat rate {row['repeat_rate_percent']}% under the {parsed_plan.repeat_rate_floor_percent}% floor after {row['months_observed']} month(s); win the second order before buying more first orders")
        if row["payback_months"] is not None and Decimal(row["payback_months"]) > parsed_plan.payback_ceiling_months:
            recommendations.append(f"{row['cohort']}: {row['payback_months']} month(s) to pay back {row['cost_per_customer']} a customer, past the {parsed_plan.payback_ceiling_months}-month ceiling; cut the acquisition cost or lift the contribution a customer")
        if row["cost_per_customer"] is not None and row["payback_months"] is None and row["contribution_per_customer"] is not None:
            recommendations.append(f"{row['cohort']}: {row['cost_per_customer']} a customer never pays back at {row['contribution_per_customer']} of contribution")
    if not cohorts:
        recommendations.append("no customer placed a first order in the window; nothing to cohort")
    elif not recommendations:
        recommendations.append(f"every cohort repeats above {parsed_plan.repeat_rate_floor_percent}% or is too young to judge" + (f" and pays back inside {parsed_plan.payback_ceiling_months} month(s)" if spend_known else ""))
    payload = {"company_ref": parsed_plan.company_ref, "currency": parsed_plan.currency, "window_start": start, "window_end": end, "as_of": at, "plan_digest": parsed_plan.plan_digest, "margin_report_digest": report_digest, "contribution_margin_percent": None if margin is None else str(margin), "cohorts": cohorts, "customers": total_customers, "orders": sum(row["orders"] for row in cohorts), "orders_unattributed": unattributed, "returning_customers": len(returning_customers), "returning_orders": len(returning_orders), "returning_revenue": str(_money(sum((row["value"] for row in returning_orders), Decimal("0")))), "repeat_rate_percent": None if overall_repeat is None else str(overall_repeat), "acquisition_spend": None if not spend_known else str(_money(sum(spend_by_month.values(), Decimal("0")))), "acquisition_unassigned": None if not spend_known else str(_money(unassigned)), "recommendations": [row[:300] for row in recommendations[:24]], "source_digests": digests}
    return seal(CustomerCohorts, payload, "cohorts_digest")


def verify_customer_cohorts(value: Any) -> CustomerCohorts:
    return value if isinstance(value, CustomerCohorts) else CustomerCohorts.model_validate(dict(detached(value)))


CUSTOMER_COHORTS_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "customer_cohorts",
    "golden_loop": "commerce.product_truth_to_measured_income@0.1.0",
    "stages": ["replay_orders_by_customer", "first_order_month_is_the_cohort", "revenue_curve_by_month_since", "contribution_at_the_report_margin", "acquisition_spend_from_registers", "payback_and_value_to_cost", "seal_document"],
    "required_connectors": ["lightbulb.sdk_engine_state"],
    "hard_rules": [
        "a customer joins the cohort of the month of their first replayed order; orders without a customer are counted, not guessed",
        "contribution a customer is revenue a customer at the sealed margin report's contribution margin; without a report the document is revenue only",
        "acquisition spend comes from replayed registers' channel spend and media invoices by the month recorded; nothing here reads a provider or persists anything",
    ],
}

__all__ = ["ACQUISITION_SOURCE_KINDS", "CUSTOMER_COHORTS_MANIFEST", "CUSTOMER_COHORTS_SCHEMA", "CUSTOMER_COHORT_PLAN_SCHEMA", "Cohort", "CohortMonth", "CustomerCohortError", "CustomerCohortPlan", "CustomerCohorts", "build_customer_cohorts", "compile_customer_cohort_plan", "verify_customer_cohorts"]
