"""The fact find each vertical needs before a shortlist means anything.

Suitability is only as good as the facts it is settled against. Every vertical family has a
small set of decision facts a shortlist cannot do without (a loan needs an amount, a purpose,
a loan-to-value ratio and a term; life cover needs an age band and smoker status; a fund needs
an amount, a horizon and a risk profile) and a second set that sharpens the verdict. This
module names them per vertical, measures a client state against them, and gives the case
lifecycle a reason to refuse a fact find that is not complete. It never asks for personal
identity; the state carries only decision facts and a commitment to the personal data.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.finance_advice_catalog import VerticalRegistry, load_vertical_registry
from lightbulb.finance_advice_engine import ClientState, sector_family
from lightbulb.company_engine_core import GENESIS_DIGEST, Sha256Digest, StrictModel, detached, seal, sealed_digest, skip_digests

FACT_FIND_REQUIREMENTS_SCHEMA = "lightbulb.finance_advice_fact_find_requirements.v1"
FACT_FIND_GAPS_SCHEMA = "lightbulb.finance_advice_fact_find_gaps.v1"

_STATE_FIELDS = ("amount", "lvr_percent", "term_years", "residency", "age_band", "income_band", "purpose", "region")

_WHY: dict[str, str] = {
    "amount": "every price scales with it: interest, cover, fees on balance",
    "purpose": "investment-only and owner-occupier-only products are settled by it",
    "lvr_percent": "maximum LVR terms and LMI tiers are settled by it",
    "term_years": "amortisation and maximum-term checks need it",
    "residency": "provider eligibility statements exclude non-residents",
    "region": "state- or province-only products are settled by it",
    "income_band": "serviceability and income-based limits need it",
    "age_band": "entry ages, youth products and registered-plan ceilings are settled by it",
    "first_home_buyer": "first-home-buyer products and schemes are settled by it",
    "existing_customer": "new-customer-only pricing is settled by it",
    "energy_efficient_property": "green loans are settled by it",
    "smoker": "smoker and non-smoker premiums differ; non-smoker-only products are settled by it",
    "occupation_class": "income protection and TPD pricing is settled by it",
    "horizon_years": "suggested minimum timeframes and projected costs need it",
    "risk_profile": "standard risk measures are settled by it",
    "investor_classification": "wholesale-only products are settled by it",
    "trades_per_year": "brokerage over the horizon needs it",
    "affinity_groups": "employer, defence or union products are settled by it",
    "income": "annual income drives the cover needed, the rebate tier and the monthly benefit",
    "income_basis": "identify whether stated income is before deductions (gross) or take-home (net); affordability never assumes the basis",
    "net_income": "annual take-home pay after tax and payroll deductions; needed for disposable cash flow when stated income is gross",
    "expenses": "annual expenses set the surplus the cash flow projects and the emergency fund target",
    "savings": "the balance held today is the emergency fund and bridges a waiting period",
    "contributions_per_year": "regular contributions carry the balance the fees and the horizon are projected on",
    "debts": "the debts cover would clear set the sum insured",
    "dependants": "dependants set the education and income-replacement components of the need",
    "existing_cover": "cover already held is deducted from the need and weighed against a switch",
    "sick_leave_days": "sick leave bridges the waiting period",
    "savings_months": "savings bridge the waiting period",
    "retirement_age": "the benefit period runs to retirement",
    "cover_type": "single, couple or family cover changes the price and the rebate thresholds",
    "tier": "the hospital tier decides what is covered and what it costs",
    "hospital_cover_since_age": "the age at which hospital cover began sets the Lifetime Health Cover loading",
    "driver_age": "insurers rate motor cover on the driver's age",
    "vehicle_class": "the vehicle rated on",
    "usage": "private, business or rideshare use changes eligibility and price",
    "claims_history_years": "years claim-free change the price",
    "excess": "the excess chosen changes the premium",
    "holdings": "the current policy or loan: its price, its exit costs and the features relied on, for stay-or-switch",
    "cover": "building, contents or both",
    "construction_type": "construction affects the premium and eligibility",
    "year_built": "age of the building affects the premium",
    "destination": "the destination decides the cover and the price",
    "trip_days": "trip length decides single-trip against annual cover",
    "trip_type": "single trip or annual multi-trip",
    "pre_existing_conditions": "declared conditions change what is covered",
    "animal": "dog or cat, rated differently",
    "age_years": "the animal's age changes eligibility and price",
    "breed": "breed changes the price",
    "transaction": "purchase, refinance, top-up or construction; a refinance is never a first-home purchase",
    "pension_or_concession": "pensioner, retiree and concession accounts are settled by it",
    "student": "youth and student accounts are settled by it",
}


class FactFindRequirements(StrictModel):
    schema_id: str = Field(default=FACT_FIND_REQUIREMENTS_SCHEMA, alias="schema")
    vertical_id: str
    family: str
    required: tuple[str, ...]
    recommended: tuple[str, ...] = Field(default_factory=tuple)
    why: dict[str, str] = Field(default_factory=dict)

    @field_validator("required", "recommended", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value


class FactFindGaps(StrictModel):
    schema_id: str = Field(default=FACT_FIND_GAPS_SCHEMA, alias="schema")
    vertical_id: str
    state_digest: Sha256Digest
    required_missing: tuple[str, ...] = Field(default_factory=tuple)
    recommended_missing: tuple[str, ...] = Field(default_factory=tuple)
    complete: bool
    gaps_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("required_missing", "recommended_missing", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> FactFindGaps:
        if self.complete and self.required_missing:
            raise ValueError("a fact find with required facts missing is not complete")
        if not skip_digests(info) and self.gaps_digest != sealed_digest(FactFindGaps, self, "gaps_digest"):
            raise ValueError("gaps_digest must commit the exact gaps")
        return self


def _rules(family: str, name: str, sector: str) -> tuple[list[str], list[str]]:
    lower = f"{name} {sector}".lower()
    if family == "credit":
        if any(word in lower for word in ("home loan", "mortgage", "housing", "construction", "reverse")):
            return ["amount", "purpose", "lvr_percent", "term_years", "residency", "region"], ["transaction", "income_band", "first_home_buyer", "existing_customer", "energy_efficient_property", "horizon_years", "income", "expenses", "debts", "savings", "dependants"]
        if any(word in lower for word in ("card", "overdraft", "buy now")):
            return ["amount", "residency"], ["income_band", "existing_customer", "purpose", "income", "expenses", "debts", "savings", "dependants"]
        return ["amount", "purpose", "term_years", "residency"], ["income_band", "region", "existing_customer", "income", "expenses", "debts", "savings", "dependants"]
    if family == "deposits":
        return ["amount", "residency", "age_band"], ["pension_or_concession", "student", "existing_customer", "horizon_years", "savings"]
    if family == "insurance":
        if any(word in lower for word in ("income protection", "disability income")):
            return ["age_band", "residency", "smoker", "occupation_class", "income"], ["sick_leave_days", "savings_months", "retirement_age", "existing_cover", "region", "affinity_groups"]
        if any(word in lower for word in ("life", "trauma", "critical", "funeral", "final-expense", "annuit", "permanent disability")):
            return ["age_band", "residency", "smoker", "amount"], ["income", "debts", "dependants", "existing_cover", "occupation_class", "region", "affinity_groups"]
        if "health" in lower or "dental" in lower:
            return ["age_band", "residency", "region", "cover_type"], ["income", "tier", "hospital_cover_since_age", "dependants", "affinity_groups"]
        if any(word in lower for word in ("motor", "auto", "third-party", "third party")):
            return ["region", "driver_age", "vehicle_class", "usage"], ["existing_customer", "claims_history_years", "excess", "holdings"]
        if any(word in lower for word in ("home", "contents", "landlord", "strata", "tenant", "condominium")):
            return ["region", "amount", "residency", "cover"], ["construction_type", "year_built", "claims_history_years", "existing_customer", "holdings"]
        if "travel" in lower:
            return ["age_band", "residency", "destination", "trip_days"], ["pre_existing_conditions", "trip_type", "existing_cover"]
        if "pet" in lower:
            return ["region", "animal", "age_years"], ["breed", "existing_cover"]
        if any(word in lower for word in ("mortgage", "creditor", "credit")):
            return ["amount", "lvr_percent", "residency"], ["age_band", "income", "region"]
        return ["region", "amount", "residency"], ["age_band", "existing_customer"]
    if family == "investments":
        required = ["amount", "horizon_years", "risk_profile", "residency"]
        if any(word in lower for word in ("registered", "superannuation", "retirement", "rrsp", "tfsa", "resp", "rdsp", "fhsa")):
            required.append("age_band")
        return required, ["investor_classification", "age_band", "trades_per_year", "income_band", "contributions_per_year", "savings"]
    return ["amount", "residency"], []


def fact_find_requirements(vertical_id: str, *, registry: VerticalRegistry | None = None) -> FactFindRequirements:
    registry = registry or load_vertical_registry()
    vertical = registry.vertical(vertical_id)
    family = sector_family(vertical.sector)
    required, recommended = _rules(family, vertical.name, vertical.sector)
    if "income" in required or "income" in recommended:
        recommended.extend(("income_basis", "net_income"))
    recommended = [item for item in recommended if item not in required]
    return FactFindRequirements(vertical_id=vertical_id, family=family, required=tuple(dict.fromkeys(required)), recommended=tuple(dict.fromkeys(recommended)), why={key: _WHY[key] for key in [*required, *recommended] if key in _WHY})


def _present(state: ClientState, key: str) -> bool:
    if key == "net_income" and state.facts.get("income_basis") == "net" and (_present(state, "income") or _present(state, "annual_income")):
        return True
    if key == "income_basis" and _present(state, "net_income"):
        return True
    if key in _STATE_FIELDS:
        value = getattr(state, key)
        if key == "residency":
            return value not in (None, "", "unstated")
        return value not in (None, "")
    value = state.facts.get(key)
    if isinstance(value, (list, tuple, set, dict)):
        return bool(value)
    return value is not None and value != ""


def fact_find_gaps(state: ClientState | Mapping[str, Any], *, registry: VerticalRegistry | None = None) -> FactFindGaps:
    """What the fact find still lacks for the state's vertical; complete only when every required fact is present."""

    s = state if isinstance(state, ClientState) else ClientState.model_validate(dict(detached(state)))
    requirements = fact_find_requirements(s.vertical_id, registry=registry)
    required_missing = [key for key in requirements.required if not _present(s, key)]
    recommended_missing = [key for key in requirements.recommended if not _present(s, key)]
    return seal(FactFindGaps, {"vertical_id": s.vertical_id, "state_digest": s.state_digest, "required_missing": required_missing, "recommended_missing": recommended_missing, "complete": not required_missing}, "gaps_digest")


def fact_find_questions(vertical_id: str, *, registry: VerticalRegistry | None = None) -> tuple[dict[str, Any], ...]:
    """The facts to collect, in order, each with why it matters; for an intake form or an agent's questions."""

    requirements = fact_find_requirements(vertical_id, registry=registry)
    rows = [{"fact": key, "required": True, "why": requirements.why.get(key, "")} for key in requirements.required]
    rows += [{"fact": key, "required": False, "why": requirements.why.get(key, "")} for key in requirements.recommended]
    return tuple(rows)


FINANCE_ADVICE_FACT_FIND_MANIFEST: dict[str, Any] = {
    "kind": "lightbulb.finance_advice_fact_find.v1",
    "schemas": [FACT_FIND_REQUIREMENTS_SCHEMA, FACT_FIND_GAPS_SCHEMA],
    "hard_rules": [
        "the fact find asks for decision facts only; identity and contact details never enter the state",
        "a fact find with a required fact missing is not complete and the case lifecycle refuses it",
        "required facts are the ones suitability and projections cannot do without; recommended facts sharpen the verdict",
    ],
}

__all__ = [
    "FACT_FIND_GAPS_SCHEMA",
    "FACT_FIND_REQUIREMENTS_SCHEMA",
    "FINANCE_ADVICE_FACT_FIND_MANIFEST",
    "FactFindGaps",
    "FactFindRequirements",
    "fact_find_gaps",
    "fact_find_questions",
    "fact_find_requirements",
]
