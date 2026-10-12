"""Insurance needs analysis: how much cover the client's situation calls for, and how a product's benefit measures against it.

Suitability for cover is not a price question first; it is a needs question. The sum insured a
family needs follows from its debts, the income it must replace, the years it must replace it for,
the children's education and the final expenses, less the cover already held. Income protection
follows from income, the waiting period the client can bridge from sick leave and savings, and the
benefit period to retirement. This module computes those needs from decision facts, writes every
assumption down, and measures a candidate's benefit against them so a shortfall is named, never
hidden. It recommends nothing; the adviser reads the gap.
"""

from __future__ import annotations

from collections.abc import Mapping
from decimal import ROUND_HALF_UP, Decimal
from typing import Any, Literal

from pydantic import Field, field_validator

from lightbulb.company_engine_core import detached
from lightbulb.finance_advice_catalog import Product, ResearchModel
from lightbulb.finance_advice_engine import ClientState

NEEDS_SCHEMA = "lightbulb.finance_advice_needs_assessment.v1"
NeedsKind = Literal["life", "income_protection", "tpd", "trauma", "health", "general"]
_CENTS = Decimal("0.01")

DEFAULTS: dict[str, Any] = {
    "income_replacement_years": 10,
    "education_per_dependant": {"AU": 50000, "CA": 40000},
    "final_expenses": {"AU": 15000, "CA": 15000},
    "income_protection_replacement_percent": 70,
    "retirement_age": 65,
    "tpd_years_of_income": 5,
    "trauma_months_of_income": 24,
}
_VERTICAL_KIND: dict[str, NeedsKind] = {"AU-32": "life", "CA-35": "life", "AU-44": "life", "CA-46": "life", "AU-33": "income_protection", "CA-36": "income_protection", "AU-34": "tpd", "AU-35": "trauma", "CA-37": "trauma", "AU-31": "health", "CA-39": "health"}


def _money(value: Decimal) -> Decimal:
    return value.quantize(_CENTS, rounding=ROUND_HALF_UP)


def _decimal(value: Any) -> Decimal | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return Decimal(str(value).replace(",", "").replace("$", "").strip())
    except Exception:  # noqa: BLE001
        return None


def _fact(state: ClientState, *keys: str) -> Decimal | None:
    for key in keys:
        value = _decimal((state.facts or {}).get(key)) if isinstance(state.facts, Mapping) else None
        if value is not None:
            return value
    return None


def _age(state: ClientState) -> int | None:
    value = _fact(state, "age")
    if value is not None:
        return int(value)
    digits = "".join(ch if ch.isdigit() else " " for ch in (state.age_band or "")).split()
    return int(digits[0]) if digits else None


class NeedsAssessment(ResearchModel):
    schema_id: str = Field(default=NEEDS_SCHEMA, alias="schema")
    kind: NeedsKind
    vertical_id: str
    need: Decimal | None = None
    unit: str
    components: dict[str, Decimal] = Field(default_factory=dict)
    existing_cover: Decimal = Decimal("0")
    waiting_period_days: int | None = None
    benefit_period_years: int | None = None
    assumptions: tuple[str, ...] = Field(default_factory=tuple)
    missing: tuple[str, ...] = Field(default_factory=tuple)

    @field_validator("assumptions", "missing", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @property
    def complete(self) -> bool:
        return self.need is not None and not self.missing


class BenefitFit(ResearchModel):
    product_ref: str
    product_name: str
    benefit: Decimal | None = None
    need: Decimal | None = None
    shortfall: Decimal | None = None
    fit: Literal["meets", "short", "exceeds", "unassessed"]
    waiting_period_days: int | None = None
    benefit_period_years: int | None = None
    notes: tuple[str, ...] = Field(default_factory=tuple)

    @field_validator("notes", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value


def needs_kind(vertical_id: str) -> NeedsKind:
    return _VERTICAL_KIND.get(vertical_id, "general")


def assess_needs(state: ClientState | Mapping[str, Any], *, defaults: Mapping[str, Any] | None = None) -> NeedsAssessment:
    """The cover the client's facts call for, component by component, with every assumption and gap named."""

    s = state if isinstance(state, ClientState) else ClientState.model_validate(dict(detached(state)))
    d = {**DEFAULTS, **(defaults or {})}
    kind = needs_kind(s.vertical_id)
    currency = "AUD" if s.jurisdiction == "AU" else "CAD"
    income = _fact(s, "income", "annual_income")
    existing = _fact(s, "existing_cover", "existing_sum_insured") or Decimal("0")
    assumptions: list[str] = []
    missing: list[str] = []
    components: dict[str, Decimal] = {}
    if kind == "life":
        debts = _fact(s, "debts", "total_debts", "mortgage_balance")
        dependants = _fact(s, "dependants") or Decimal("0")
        years = _fact(s, "income_replacement_years") or Decimal(str(d["income_replacement_years"]))
        if debts is None:
            missing.append("debts (the mortgage and other debts the cover would clear)")
        else:
            components["clear debts"] = _money(debts)
        if income is None:
            missing.append("income (to replace for the dependants)")
        else:
            components["replace income"] = _money(income * years)
            assumptions.append(f"income replaced for {years} years{'' if _fact(s, 'income_replacement_years') else ' (default; the adviser sets the years)'}")
        if dependants > 0:
            per = Decimal(str(d["education_per_dependant"][s.jurisdiction]))
            components["education"] = _money(per * dependants)
            assumptions.append(f"education {per} per dependant for {int(dependants)} dependant(s) (default)")
        final = Decimal(str(d["final_expenses"][s.jurisdiction]))
        components["final expenses"] = _money(final)
        assumptions.append(f"final expenses {final} (default)")
        if existing > 0:
            components["less existing cover"] = _money(-existing)
            assumptions.append(f"existing cover {existing} deducted; its own terms are not assessed here")
        need = _money(max(Decimal("0"), sum(components.values(), Decimal("0")))) if not missing else None
        return NeedsAssessment(kind=kind, vertical_id=s.vertical_id, need=need, unit=currency, components=components, existing_cover=existing, assumptions=assumptions, missing=missing)
    if kind == "income_protection":
        if income is None:
            missing.append("income (the monthly benefit is a share of it)")
        percent = _fact(s, "replacement_percent") or Decimal(str(d["income_protection_replacement_percent"]))
        age = _age(s)
        retirement = int(_fact(s, "retirement_age") or d["retirement_age"])
        sick_days = _fact(s, "sick_leave_days") or Decimal("0")
        savings_months = _fact(s, "savings_months") or Decimal("0")
        waiting = int(sick_days + savings_months * Decimal("30"))
        waiting_choice = 30 if waiting < 30 else (60 if waiting < 60 else (90 if waiting < 90 else 180 if waiting < 180 else 365))
        benefit_period = max(1, retirement - age) if age is not None else None
        if age is None:
            missing.append("age (the benefit period runs to retirement)")
        if income is not None:
            components["monthly benefit"] = _money(income * percent / Decimal("100") / Decimal("12"))
            assumptions.append(f"{percent}% of income replaced monthly{'' if _fact(s, 'replacement_percent') else ' (default)'}")
        assumptions.append(f"the client can bridge about {waiting} day(s) from sick leave and savings, so a {waiting_choice}-day waiting period fits")
        if benefit_period is not None:
            assumptions.append(f"benefit period to age {retirement}: {benefit_period} year(s)")
        need = components.get("monthly benefit") if not missing else None
        return NeedsAssessment(kind=kind, vertical_id=s.vertical_id, need=need, unit=f"{currency}/month", components=components, existing_cover=existing, waiting_period_days=waiting_choice, benefit_period_years=benefit_period, assumptions=assumptions, missing=missing)
    if kind in ("tpd", "trauma"):
        if income is None:
            missing.append("income")
            return NeedsAssessment(kind=kind, vertical_id=s.vertical_id, need=None, unit=currency, components={}, existing_cover=existing, assumptions=assumptions, missing=missing)
        if kind == "tpd":
            years = Decimal(str(d["tpd_years_of_income"]))
            debts = _fact(s, "debts", "total_debts", "mortgage_balance") or Decimal("0")
            components["income for adjustment"] = _money(income * years)
            components["clear debts"] = _money(debts)
            assumptions.append(f"{years} years of income for adjustment and care (default) plus debts cleared")
        else:
            months = Decimal(str(d["trauma_months_of_income"]))
            components["income during recovery"] = _money(income * months / Decimal("12"))
            assumptions.append(f"{months} months of income during recovery (default)")
        if existing > 0:
            components["less existing cover"] = _money(-existing)
        return NeedsAssessment(kind=kind, vertical_id=s.vertical_id, need=_money(max(Decimal("0"), sum(components.values(), Decimal("0")))), unit=currency, components=components, existing_cover=existing, assumptions=assumptions, missing=missing)
    return NeedsAssessment(kind=kind, vertical_id=s.vertical_id, need=None, unit=currency, components={}, existing_cover=existing, assumptions=("no needs formula for this vertical; the adviser states the need",), missing=())


_BENEFIT_TERMS = ("sum insured", "maximum cover", "maximum sum insured", "cover limit", "death cover", "benefit amount", "monthly benefit", "maximum monthly benefit")


def benefit_fit(product: Product | Mapping[str, Any], assessment: NeedsAssessment | Mapping[str, Any], *, requested: Decimal | None = None) -> BenefitFit:
    """How the product's stated benefit measures against the need: the benefit is the requested sum insured when the product lets the client choose, else its stated maximum."""

    p = product if isinstance(product, Product) else Product.model_validate(dict(detached(product)))
    a = assessment if isinstance(assessment, NeedsAssessment) else NeedsAssessment.model_validate(dict(detached(assessment)))
    notes: list[str] = []
    stated: Decimal | None = None
    for fact in p.pricing:
        if fact.value is not None and any(term in fact.item.lower() for term in _BENEFIT_TERMS):
            stated = Decimal(str(fact.value))
            notes.append(f"benefit from the product's stated {fact.item} {fact.value} {fact.unit or ''}".strip())
            break
    if stated is None:
        for term in p.key_terms:
            if any(name in term.term.lower() for name in _BENEFIT_TERMS):
                value = _decimal(term.value if not isinstance(term.value, (list, tuple)) else (term.value[-1] if term.value else None))
                if value is not None:
                    stated = value
                    notes.append(f"benefit from the product's key term {term.term} {term.value}")
                    break
    benefit = requested if requested is not None else stated
    if requested is not None and stated is not None and requested > stated:
        benefit = stated
        notes.append(f"the requested {requested} exceeds the product's maximum {stated}")
    waiting = None
    period = None
    for term in p.key_terms:
        lower = term.term.lower()
        if "waiting" in lower and waiting is None:
            value = _decimal(term.value if not isinstance(term.value, (list, tuple)) else (term.value[0] if term.value else None))
            waiting = int(value) if value is not None else None
        if "benefit period" in lower and period is None:
            value = _decimal(term.value if not isinstance(term.value, (list, tuple)) else (term.value[-1] if term.value else None))
            period = int(value) if value is not None else None
    if a.need is None or benefit is None:
        return BenefitFit(product_ref=p.product_ref, product_name=p.product_name, benefit=benefit, need=a.need, shortfall=None, fit="unassessed", waiting_period_days=waiting, benefit_period_years=period, notes=tuple(notes) or ("the need or the benefit is not stated",))
    shortfall = _money(a.need - benefit)
    if shortfall > 0:
        fit = "short"
        notes.append(f"{shortfall} {a.unit} short of the assessed need")
    elif benefit > a.need * Decimal("1.5"):
        fit = "exceeds"
        notes.append("benefit is more than half again the assessed need; the client pays for cover beyond it")
    else:
        fit = "meets"
    if a.waiting_period_days is not None and waiting is not None and waiting > a.waiting_period_days:
        notes.append(f"waiting period {waiting} days is longer than the {a.waiting_period_days} days the client can bridge")
    if a.benefit_period_years is not None and period is not None and period < a.benefit_period_years:
        notes.append(f"benefit period {period} year(s) ends before retirement ({a.benefit_period_years} year(s) away)")
    return BenefitFit(product_ref=p.product_ref, product_name=p.product_name, benefit=benefit, need=a.need, shortfall=max(shortfall, Decimal("0")), fit=fit, waiting_period_days=waiting, benefit_period_years=period, notes=tuple(notes))


NEEDS_MANIFEST: dict[str, Any] = {
    "kind": "lightbulb.finance_advice_needs.v1",
    "defaults": DEFAULTS,
    "verticals": _VERTICAL_KIND,
    "hard_rules": [
        "a need is computed from decision facts with every default written down; the adviser sets the years, the percent and the retirement age",
        "a shortfall against the need is named, never hidden; a product that exceeds the need by half again is named too",
        "nothing here recommends; the adviser reads the fit",
    ],
}


__all__ = ["DEFAULTS", "NEEDS_MANIFEST", "NEEDS_SCHEMA", "BenefitFit", "NeedsAssessment", "assess_needs", "benefit_fit", "needs_kind"]
