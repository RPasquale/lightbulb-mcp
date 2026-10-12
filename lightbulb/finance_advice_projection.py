"""Cost over a horizon: what a product costs, or returns, over the years the client will hold it, from cited facts only.

A rate on its own misleads: a lower rate with a package fee can cost more over five years than a
higher rate with none, and a premium quoted monthly is not comparable with one quoted yearly. This
module turns the pricing facts a catalog carries into one figure per product over one horizon,
with every assumption written down. Every input is either a fact the provider stated, with its
support, or a decision fact from the fact find; a projection that needs a figure it does not have
is reported and never ranked. Amortisation is the standard monthly annuity; nothing here forecasts
rates, growth or claims.
"""

from __future__ import annotations

import re

from collections.abc import Mapping, Sequence
from decimal import ROUND_HALF_UP, Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.finance_advice_catalog import PricingFact, Product
from lightbulb.company_engine_core import GENESIS_DIGEST, BoundedText, OpaqueRef, Sha256Digest, ShortText, StrictModel, seal, sealed_digest, skip_digests

COST_PROJECTION_SCHEMA = "lightbulb.finance_advice_cost_projection.v1"
Family = Literal["credit", "deposits", "insurance", "investments"]
DEFAULT_HORIZON_YEARS: dict[str, int] = {"credit": 5, "deposits": 1, "insurance": 1, "investments": 5}
DEFAULT_LOAN_TERM_YEARS = 30
_CENTS = Decimal("0.01")

_RATE_ITEMS = ("interest rate", "variable interest rate", "fixed interest rate", "current interest rate", "interest_rate", "current_interest_rate", "mortgage interest rate", "standard variable rate", "variable rate", "fixed rate", "purchase interest rate", "purchase rate", "annual percentage rate", "apr")
_COMPARISON_ITEMS = ("comparison rate", "interest/comparison rate", "apr", "current_apr", "posted_apr", "annual percentage rate")
_DEPOSIT_RATE_ITEMS = ("interest rate", "base interest rate", "bonus interest rate", "total interest rate", "standard interest rate")
_UPFRONT_FEE_ITEMS = ("application fee", "establishment fee", "settlement fee", "valuation fee", "legal fee", "documentation fee", "upfront fee", "set-up fee", "setup fee", "loan approval fee")
_ONGOING_YEAR_ITEMS = ("annual fee", "annual package fee", "package fee", "ongoing fee", "account keeping fee", "annual card fee", "annual account fee", "account fee", "administration fee", "platform fee")
_ONGOING_MONTH_ITEMS = ("monthly fee", "monthly account fee", "monthly service fee", "monthly account keeping fee")
_PREMIUM_YEAR_ITEMS = ("annual premium", "premium per year", "yearly premium")
_PREMIUM_MONTH_ITEMS = ("monthly premium", "premium per month")
_PREMIUM_ITEMS = ("premium", "base premium", "indicative premium", "total premium")
_MER_ITEMS = ("management fee/mer", "management fee", "mer", "management expense ratio", "indirect cost ratio", "total fees and costs", "management cost", "investment fee")
_SPREAD_ITEMS = ("buy/sell spread", "buy-sell spread", "buy sell spread")
_BROKERAGE_ITEMS = ("brokerage", "brokerage per trade", "trading fee", "trading commission", "commission per trade")


class CostComponent(StrictModel):
    label: ShortText
    amount: Decimal
    basis: BoundedText
    item: str | None = None
    support: str | None = None
    cited: bool

    @field_validator("amount", mode="before")
    @classmethod
    def _decimal(cls, value: Any) -> Decimal:
        return value if isinstance(value, Decimal) else Decimal(str(value))


class CostProjection(StrictModel):
    """One product's cost over one horizon: total, the components it is made of, and what was assumed or missing."""

    schema_id: str = Field(default=COST_PROJECTION_SCHEMA, alias="schema")
    product_ref: OpaqueRef
    provider_ref: OpaqueRef
    product_name: str
    family: Family
    horizon_years: int = Field(ge=1, le=40)
    currency: str | None = None
    amount: Decimal | None = None
    total: Decimal
    components: tuple[CostComponent, ...] = Field(default_factory=tuple)
    assumptions: tuple[str, ...] = Field(default_factory=tuple)
    missing: tuple[str, ...] = Field(default_factory=tuple)
    rankable: bool
    projection_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("components", "assumptions", "missing", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("amount", "total", mode="before")
    @classmethod
    def _decimals(cls, value: Any) -> Decimal | None:
        return None if value is None else (value if isinstance(value, Decimal) else Decimal(str(value)))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> CostProjection:
        if self.rankable and self.missing:
            raise ValueError("a projection with missing inputs is never rankable")
        if not skip_digests(info) and self.projection_digest != sealed_digest(CostProjection, self, "projection_digest"):
            raise ValueError("projection_digest must commit the exact projection")
        return self


def _money(value: Decimal) -> Decimal:
    return value.quantize(_CENTS, rounding=ROUND_HALF_UP)


def monthly_payment(principal: Decimal, annual_rate_percent: Decimal, term_years: int) -> Decimal:
    """The level monthly payment of a fully amortising loan."""

    months = term_years * 12
    if annual_rate_percent == 0:
        return _money(principal / months)
    rate = annual_rate_percent / Decimal(1200)
    factor = (Decimal(1) + rate) ** months
    return _money(principal * rate * factor / (factor - Decimal(1)))


def interest_over(principal: Decimal, annual_rate_percent: Decimal, term_years: int, horizon_years: int) -> Decimal:
    """Interest paid in the first ``horizon_years`` of a fully amortising loan (or the whole term when shorter)."""

    months = min(horizon_years, term_years) * 12
    payment = monthly_payment(principal, annual_rate_percent, term_years)
    rate = annual_rate_percent / Decimal(1200)
    balance = principal
    interest = Decimal(0)
    for _ in range(months):
        month_interest = balance * rate
        interest += month_interest
        balance = balance - (payment - month_interest)
        if balance <= 0:
            break
    return _money(interest)


def _matches(item: str, patterns: Sequence[str]) -> bool:
    lower = item.strip().lower()
    return any(lower == pattern or lower.startswith(pattern + " ") or lower.startswith(pattern + "/") or lower == pattern.replace(" ", "_") for pattern in patterns)


def _fact(product: Product, patterns: Sequence[str], *, kinds: Sequence[str] | None = None) -> PricingFact | None:
    for fact in product.pricing:
        if _matches(fact.item, patterns) and fact.value is not None and (kinds is None or fact.unit_kind in kinds):
            return fact
    return None


def _all_facts(product: Product, patterns: Sequence[str], *, kinds: Sequence[str]) -> list[PricingFact]:
    seen: set[str] = set()
    out: list[PricingFact] = []
    for fact in product.pricing:
        if _matches(fact.item, patterns) and fact.value is not None and fact.unit_kind in kinds and fact.item not in seen:
            seen.add(fact.item)
            out.append(fact)
    return out


_INTRO_WORDS = ("introductory", "intro rate", "intro variable", "intro fixed", "honeymoon")
_REVERT_ITEMS = ("revert variable rate", "revert rate", "revert interest rate", "reverting rate", "revert variable interest rate", "revert fixed rate")
_PERIOD_TERMS = ("introductory period", "introductory/fixed period", "intro period", "honeymoon period", "discount period", "introductory discount period", "fixed period", "fixed term", "fixed rate period", "fixed-rate period")
_PERIOD_RE = re.compile(r"(?:first\s+)?(\d{1,3})\s*[- ]?\s*(months?|mths?|years?|yrs?)\b")
_PERCENT_RE = re.compile(r"(\d{1,2}(?:\.\d{1,3})?)\s*%")
_RATE_KINDS = ("rate_percent_per_year", "percent")


def _months(value: Any) -> int | None:
    """A stated period as months: '24 months', '2 years', 'for the first 3 years', '24-month'."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, Decimal)) and not isinstance(value, bool):
        return int(value) if int(value) > 0 else None
    match = _PERIOD_RE.search(str(value).lower())
    if not match:
        return None
    count = int(match.group(1))
    unit = match.group(2)
    months = count * 12 if unit.startswith("y") else count
    return months if months > 0 else None


class RatePhases(StrictModel):
    """The stated first rate, how long it lasts, and the stated rate it reverts to."""

    kind: str
    first: PricingFact
    revert: PricingFact | None = None
    period_months: int | None = None
    period_source: str | None = None


def rate_phases(product: Product) -> RatePhases | None:
    """An introductory rate (or a fixed rate on a fixed product), its stated period and its stated revert rate, all from the provider's own facts; nothing is inferred."""
    first: PricingFact | None = None
    kind = "introductory"
    for fact in product.pricing:
        lower = fact.item.lower()
        if fact.value is not None and fact.unit_kind in _RATE_KINDS and any(word in lower for word in _INTRO_WORDS) and "revert" not in lower and "comparison" not in lower:
            first = fact
            break
    if first is None and "fixed" in product.taxonomy_class.lower():
        kind = "fixed"
        for fact in product.pricing:
            lower = fact.item.lower()
            if fact.value is not None and fact.unit_kind in _RATE_KINDS and "fixed" in lower and "revert" not in lower and "comparison" not in lower:
                first = fact
                break
    if first is None:
        return None
    revert = None
    for fact in product.pricing:
        lower = fact.item.lower()
        if fact.value is not None and fact.unit_kind in _RATE_KINDS and (_matches(fact.item, _REVERT_ITEMS) or (lower.startswith("revert") and "comparison" not in lower)):
            revert = fact
            break
    period = _months(first.item.split(" ")[0]) if first.item[:1].isdigit() else None
    source = f"the item name {first.item!r}" if period else None
    if period is None:
        for term in product.key_terms:
            if _matches(term.term, _PERIOD_TERMS) or any(term.term.lower().startswith(name) for name in _PERIOD_TERMS):
                period = _months(term.value)
                if period:
                    source = f"the key term {term.term!r} ({term.value})"
                    break
    return RatePhases(kind=kind, first=first, revert=revert, period_months=period, period_source=source)


def _payment_for_months(principal: Decimal, annual_rate_percent: Decimal, months: int) -> Decimal:
    if months <= 0:
        return principal
    if annual_rate_percent == 0:
        return _money(principal / months)
    rate = annual_rate_percent / Decimal(1200)
    factor = (Decimal(1) + rate) ** months
    return _money(principal * rate * factor / (factor - Decimal(1)))


def interest_two_phase(principal: Decimal, first_rate_percent: Decimal, first_months: int, revert_rate_percent: Decimal, term_years: int, horizon_years: int) -> tuple[Decimal, Decimal]:
    """Interest in the first ``horizon_years``: the first rate for ``first_months`` on the full-term payment, then the revert rate on the balance re-amortised over the remaining term."""

    total_months = term_years * 12
    horizon_months = min(horizon_years, term_years) * 12
    first_months = max(0, min(first_months, horizon_months, total_months))
    payment = monthly_payment(principal, first_rate_percent, term_years)
    rate = first_rate_percent / Decimal(1200)
    balance = principal
    first_interest = Decimal(0)
    for _ in range(first_months):
        month_interest = balance * rate
        first_interest += month_interest
        balance = balance - (payment - month_interest)
        if balance <= 0:
            balance = Decimal(0)
            break
    revert_interest = Decimal(0)
    remaining = total_months - first_months
    if balance > 0 and remaining > 0 and horizon_months > first_months:
        payment = _payment_for_months(balance, revert_rate_percent, remaining)
        rate = revert_rate_percent / Decimal(1200)
        for _ in range(horizon_months - first_months):
            month_interest = balance * rate
            revert_interest += month_interest
            balance = balance - (payment - month_interest)
            if balance <= 0:
                break
    return _money(first_interest), _money(revert_interest)


def _component(label: str, amount: Decimal, basis: str, fact: PricingFact | None) -> CostComponent:
    return CostComponent(label=label, amount=_money(amount), basis=basis[:500], item=fact.item if fact else None, support=fact.support if fact else None, cited=bool(fact and fact.support != "unsupported"))


def _decimal(value: Any) -> Decimal | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return Decimal(str(value))
    except Exception:  # noqa: BLE001 - a non-numeric fact find value is simply absent
        return None


def _fee_components(product: Product, horizon_years: int, *, upfront: bool) -> tuple[list[CostComponent], list[str]]:
    components: list[CostComponent] = []
    notes: list[str] = []
    if upfront:
        for fact in _all_facts(product, _UPFRONT_FEE_ITEMS, kinds=("money",)):
            components.append(_component(f"{fact.item} (once)", fact.value, f"{fact.item} {fact.value} {fact.unit or ''} paid once", fact))
    for fact in _all_facts(product, _ONGOING_YEAR_ITEMS, kinds=("money_per_year", "money")):
        components.append(_component(f"{fact.item} × {horizon_years} years", fact.value * horizon_years, f"{fact.item} {fact.value} {fact.unit or ''} each year for {horizon_years} years", fact))
        if fact.unit_kind == "money":
            notes.append(f"{fact.item} has no stated period; treated as yearly")
    for fact in _all_facts(product, _ONGOING_MONTH_ITEMS, kinds=("money_per_month",)):
        components.append(_component(f"{fact.item} × {horizon_years * 12} months", fact.value * 12 * horizon_years, f"{fact.item} {fact.value} {fact.unit or ''} each month for {horizon_years} years", fact))
    return components, notes


def project_cost(product: Product, state: Any, *, family: str, horizon_years: int | None = None, currency: str | None = None) -> CostProjection:
    """One product's cost over the horizon for one client state; never a recommendation, never a forecast."""

    facts: Mapping[str, Any] = getattr(state, "facts", None) or {}
    horizon = int(horizon_years or _decimal(facts.get("horizon_years")) or DEFAULT_HORIZON_YEARS.get(family, 5))
    horizon = max(1, min(horizon, 40))
    amount = _decimal(getattr(state, "amount", None))
    components: list[CostComponent] = []
    assumptions: list[str] = []
    missing: list[str] = []
    is_card = "card" in product.taxonomy_class.lower() or "card" in product.product_name.lower()

    if family == "credit":
        rate = None
        phased = False
        phases = rate_phases(product) if not is_card else None
        if phases is not None and phases.revert is not None:
            phased = True
            if amount is None:
                missing.append("the client's amount")
            else:
                term = int(getattr(state, "term_years", None) or 0) or DEFAULT_LOAN_TERM_YEARS
                if not getattr(state, "term_years", None):
                    assumptions.append(f"a {DEFAULT_LOAN_TERM_YEARS}-year term because the fact find states none")
                comparison = _fact(product, _COMPARISON_ITEMS, kinds=("rate_percent_per_year", "percent"))
                if phases.period_months:
                    months = phases.period_months
                    first_interest, revert_interest = interest_two_phase(amount, phases.first.value, months, phases.revert.value, term, horizon)
                    components.append(_component(f"interest at {phases.first.value}% for the first {months} months", first_interest, f"monthly amortisation of {amount} over {term} years at the {phases.kind} rate of {phases.first.value}% p.a. for {months} months", phases.first))
                    if horizon * 12 > months:
                        components.append(_component(f"interest at {phases.revert.value}% from month {months + 1} to year {horizon}", revert_interest, f"the balance after {months} months re-amortised over the remaining term at the stated revert rate of {phases.revert.value}% p.a.", phases.revert))
                    assumptions.append(f"the {phases.kind} rate of {phases.first.value}% is held for the stated {months} months (from {phases.period_source}), then the stated revert rate of {phases.revert.value}% for the rest of the horizon; the revert rate is the rate the provider displays today" + (f"; the comparison rate of {comparison.value}% is stated and not used because the periods are projected on the client's own amount" if comparison is not None else ""))
                else:
                    interest = interest_over(amount, phases.revert.value, term, horizon)
                    components.append(_component(f"interest at {phases.revert.value}% over {horizon} years", interest, f"monthly amortisation of {amount} over {term} years at the stated revert rate of {phases.revert.value}% p.a.; interest in the first {horizon} years", phases.revert))
                    assumptions.append(f"the {phases.kind} period is not stated, so the revert rate of {phases.revert.value}% is applied for the whole horizon; the true cost is lower by the {phases.kind} discount over that unstated period")
        elif phases is not None:
            revert_terms = [term for term in product.key_terms if "revert" in term.term.lower() and isinstance(term.value, str) and _PERCENT_RE.search(term.value)]
            if revert_terms:
                assumptions.append(f"a revert rate is stated in the key terms ({revert_terms[0].term}: {revert_terms[0].value}) without a cited pricing fact; the {phases.kind} period is not projected from it")
        if not is_card and not phased:
            comparisons = _all_facts(product, _COMPARISON_ITEMS, kinds=("rate_percent_per_year", "percent"))
            if comparisons:
                rate = min(comparisons, key=lambda fact: fact.value)
                nominal = _fact(product, _RATE_ITEMS, kinds=("rate_percent_per_year", "percent"))
                assumptions.append("the comparison rate stands in for the nominal rate: it is the provider's all-in figure on the regulator's standard loan and covers fees and any introductory period, so no fee component is added" + (f"; the headline rate is {nominal.value}%" if nominal is not None and nominal.value != rate.value else ""))
        if rate is None and not phased:
            rate = _fact(product, _RATE_ITEMS, kinds=("rate_percent_per_year", "percent"))
        if rate is None and not phased:
            rate = _fact(product, _COMPARISON_ITEMS, kinds=("rate_percent_per_year", "percent"))
            if rate is not None:
                assumptions.append("the comparison rate stands in for the nominal rate; fees are inside it, so no fee component is added")
        if rate is None and not phased:
            missing.append("an interest rate fact")
        if amount is None and not phased:
            missing.append("the client's amount")
        if rate is not None and amount is not None and not phased:
            if is_card:
                interest = amount * rate.value / Decimal(100) * horizon
                assumptions.append(f"the balance of {amount} revolves for the whole {horizon} years; paying in full each month makes interest zero")
                components.append(_component(f"interest at {rate.value}% on the revolving balance", interest, f"{amount} × {rate.value}% × {horizon} years", rate))
            else:
                term = int(getattr(state, "term_years", None) or 0) or DEFAULT_LOAN_TERM_YEARS
                if not getattr(state, "term_years", None):
                    assumptions.append(f"a {DEFAULT_LOAN_TERM_YEARS}-year term because the fact find states none")
                if "fixed" in product.taxonomy_class.lower():
                    assumptions.append("the fixed rate is held for the whole horizon; the revert rate after the fixed period is not stated")
                interest = interest_over(amount, rate.value, term, horizon)
                components.append(_component(f"interest at {rate.value}% over {horizon} years", interest, f"monthly amortisation of {amount} over {term} years at {rate.value}% p.a.; interest in the first {horizon} years", rate))
        if phased or not any("comparison rate stands in" in item for item in assumptions):
            fees, notes = _fee_components(product, horizon, upfront=True)
            components.extend(fees)
            assumptions.extend(notes)
        assumptions.append("discharge, exit and break fees are left out; they apply only if the client leaves within the horizon")
    elif family == "deposits":
        rate = _fact(product, _DEPOSIT_RATE_ITEMS, kinds=("rate_percent_per_year", "percent"))
        if rate is None:
            missing.append("an interest rate fact")
        if amount is None:
            missing.append("the client's amount")
        if rate is not None and amount is not None:
            earned = amount * ((Decimal(1) + rate.value / Decimal(100)) ** horizon - Decimal(1))
            assumptions.append("interest compounds yearly at the stated rate for the whole horizon; bonus conditions are assumed met")
            components.append(_component(f"interest earned at {rate.value}% over {horizon} years", -earned, f"{amount} × ((1 + {rate.value}%)^{horizon} − 1), shown as a negative cost", rate))
        fees, notes = _fee_components(product, horizon, upfront=False)
        components.extend(fees)
        assumptions.extend(notes)
    elif family == "insurance":
        yearly = _fact(product, _PREMIUM_YEAR_ITEMS, kinds=("money_per_year", "money"))
        monthly = _fact(product, _PREMIUM_MONTH_ITEMS, kinds=("money_per_month", "money"))
        unstated = None if (yearly or monthly) else _fact(product, _PREMIUM_ITEMS, kinds=("money_per_year", "money", "money_per_month"))
        if yearly is not None:
            components.append(_component(f"premium × {horizon} years", yearly.value * horizon, f"{yearly.item} {yearly.value} {yearly.unit or ''} each year for {horizon} years", yearly))
        elif monthly is not None:
            components.append(_component(f"premium × {horizon * 12} months", monthly.value * 12 * horizon, f"{monthly.item} {monthly.value} {monthly.unit or ''} each month for {horizon} years", monthly))
        elif unstated is not None:
            if unstated.unit_kind == "money_per_month":
                components.append(_component(f"premium × {horizon * 12} months", unstated.value * 12 * horizon, f"{unstated.item} {unstated.value} {unstated.unit or ''} each month for {horizon} years", unstated))
            else:
                components.append(_component(f"premium × {horizon} years", unstated.value * horizon, f"{unstated.item} {unstated.value} {unstated.unit or ''}, treated as yearly, for {horizon} years", unstated))
                if unstated.unit_kind != "money_per_year":
                    assumptions.append(f"{unstated.item} has no stated period; treated as yearly")
        else:
            missing.append("a premium fact")
        assumptions.append("premiums are held at the stated figure; age steps, indexation and claims are not projected; the excess applies only on a claim")
    elif family == "investments":
        if amount is None:
            missing.append("the client's amount")
        mer = _fact(product, _MER_ITEMS, kinds=("rate_percent_per_year", "percent"))
        if mer is not None and amount is not None:
            components.append(_component(f"{mer.item} at {mer.value}% × {horizon} years", amount * mer.value / Decimal(100) * horizon, f"{amount} × {mer.value}% × {horizon} years on a flat balance", mer))
            assumptions.append("the balance is held flat; growth and its effect on percentage fees are not projected")
        elif mer is None and not any(_matches(fact.item, _ONGOING_YEAR_ITEMS + _ONGOING_MONTH_ITEMS) for fact in product.pricing):
            missing.append("a management fee, MER or account fee fact")
        spread = _fact(product, _SPREAD_ITEMS, kinds=("percent", "rate_percent_per_year"))
        if spread is not None and amount is not None:
            components.append(_component(f"{spread.item} on entry", amount * spread.value / Decimal(100), f"{amount} × {spread.value}% once on entry", spread))
        brokerage = _fact(product, _BROKERAGE_ITEMS, kinds=("money", "money_per_transaction"))
        trades = _decimal(facts.get("trades_per_year"))
        if brokerage is not None:
            if trades is not None:
                components.append(_component(f"{brokerage.item} × {trades} trades a year", brokerage.value * trades * horizon, f"{brokerage.value} per trade × {trades} trades a year × {horizon} years", brokerage))
            else:
                assumptions.append(f"{brokerage.item} is left out because the fact find states no trades per year")
        fees, notes = _fee_components(product, horizon, upfront=False)
        components.extend(fees)
        assumptions.extend(notes)
    else:
        missing.append(f"a projection rule for the {family} family")

    uncited = [item.label for item in components if not item.cited]
    if uncited:
        missing.append("a citation for " + ", ".join(uncited))
    total = _money(sum((item.amount for item in components), Decimal(0)))
    rankable = not missing and bool(components)
    if not components and not missing:
        missing.append("any pricing fact the projection could use")
        rankable = False
    return seal(CostProjection, {"product_ref": product.product_ref, "provider_ref": product.provider_ref, "product_name": product.product_name, "family": family, "horizon_years": horizon, "currency": currency, "amount": amount, "total": total, "components": [item.to_dict() for item in components], "assumptions": list(dict.fromkeys(assumptions)), "missing": list(dict.fromkeys(missing)), "rankable": rankable}, "projection_digest")


def projection_table(projections: Sequence[CostProjection | Mapping[str, Any]]) -> dict[str, Any]:
    """The projections side by side, cheapest first, rankable ones before the rest; a description, not advice."""

    rows = []
    for item in projections:
        p = item if isinstance(item, CostProjection) else CostProjection.model_validate(dict(item))
        rows.append({"product_ref": p.product_ref, "product": p.product_name, "family": p.family, "horizon_years": p.horizon_years, "currency": p.currency, "total": str(p.total), "rankable": p.rankable, "components": [{"label": c.label, "amount": str(c.amount), "cited": c.cited} for c in p.components], "assumptions": list(p.assumptions), "missing": list(p.missing)})
    rows.sort(key=lambda row: (not row["rankable"], Decimal(row["total"]), row["product"]))
    return {"schema": "lightbulb.finance_advice_projection_table.v1", "rows": rows, "disclosures": ["Projected figures use the providers' stated prices and the client's stated amount and term; nothing is forecast.", "A projection is not a recommendation; suitability and the adviser's approval decide."]}


FINANCE_ADVICE_PROJECTION_MANIFEST: dict[str, Any] = {
    "kind": "lightbulb.finance_advice_projection.v1",
    "schemas": [COST_PROJECTION_SCHEMA],
    "hard_rules": [
        "every figure comes from a cited pricing fact or a decision fact in the fact find; a projection missing either is never rankable",
        "every assumption is written down on the projection",
        "no rate, growth or claim forecast; amortisation is the standard monthly annuity",
        "a comparison rate standing in for a nominal rate carries no fee component, so nothing is counted twice",
    "an introductory or fixed rate is projected for its stated period and then the stated revert rate; without a stated period the revert rate is applied for the whole horizon; an introductory rate alone is never projected",
        "a projection describes cost; it never recommends",
    ],
}

__all__ = [
    "COST_PROJECTION_SCHEMA",
    "CostComponent",
    "CostProjection",
    "DEFAULT_HORIZON_YEARS",
    "FINANCE_ADVICE_PROJECTION_MANIFEST",
    "interest_over",
    "monthly_payment",
    "project_cost",
    "projection_table",
]
