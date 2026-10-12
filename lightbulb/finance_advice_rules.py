"""Government rules per vertical: the levies, rebates, loadings and public schemes that change what a product costs a client.

A projection that ignores the Medicare Levy Surcharge, the private health rebate, Lifetime Health
Cover loading, lenders mortgage insurance or a province's public auto plan is wrong for the
client. These rules are not provider facts and never come from a pack; they are the jurisdiction's
own, held here as a small table with a citation, an effective date and a plain statement, applied
by the projection as extra cost or credit items, and disclosed line by line. Every figure carries
the URL it came from and the date it applies from; a figure the operator has not confirmed is
labelled so, and the disclosure says which figures were used.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import ROUND_HALF_UP, Decimal
from typing import Any, Literal

from pydantic import Field, field_validator

from lightbulb.company_engine_core import detached
from lightbulb.finance_advice_catalog import Product, ResearchModel
from lightbulb.finance_advice_engine import ClientState

RULES_SCHEMA = "lightbulb.finance_advice_jurisdiction_rule.v1"
RuleEffect = Literal["cost_per_year", "credit_per_year", "one_off_cost", "one_off_credit", "disclosure_only", "exclusion"]
_CENTS = Decimal("0.01")


def _money(value: Decimal) -> Decimal:
    return value.quantize(_CENTS, rounding=ROUND_HALF_UP)


def _decimal(value: Any) -> Decimal | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return Decimal(str(value).replace(",", "").replace("%", "").replace("$", "").strip())
    except Exception:  # noqa: BLE001
        return None


class JurisdictionRule(ResearchModel):
    schema_id: str = Field(default=RULES_SCHEMA, alias="schema")
    rule_ref: str
    jurisdiction: Literal["AU", "CA"]
    verticals: tuple[str, ...]
    title: str
    statement: str
    effect: RuleEffect
    source_url: str
    effective_from: str
    effective_to: str | None = None
    reviewed_at: str | None = None
    confirmed: bool = False
    parameters: dict[str, Any] = Field(default_factory=dict)

    @field_validator("verticals", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value


class RuleAdjustment(ResearchModel):
    rule_ref: str
    title: str
    effect: RuleEffect
    amount: Decimal | None = None
    per_year: bool = False
    basis: str
    disclosure: str


# --------------------------------------------------------------------------- #
# The table. Figures are as published by the jurisdiction on the cited page as at the effective
# date; the operator confirms them (confirmed=True) before a client sees a projection built on them.
# --------------------------------------------------------------------------- #

RETIREMENT_TAX_RULES: tuple[JurisdictionRule, ...] = (
    JurisdictionRule(
        rule_ref="au.income_tax.resident.2026_27", jurisdiction="AU", verticals=(),
        title="Australian resident income tax brackets 2026-27",
        statement="Ordinary resident income tax before offsets, Medicare, surcharge and other liabilities; tax residency must be stated separately from citizenship.",
        effect="disclosure_only", source_url="https://www.legislation.gov.au/C2004A03348/2026-07-01/2026-07-01/text/original/epub/OEBPS/document_1/document_1.html",
        effective_from="2026-07-01", effective_to="2027-06-30", reviewed_at="2026-09-07",
        parameters={"brackets": [(18200, "0"), (45000, "15"), (135000, "30"), (190000, "37"), (None, "45")]},
    ),
    JurisdictionRule(
        rule_ref="ca.income_tax.federal.2026", jurisdiction="CA", verticals=(),
        title="Canadian federal income tax brackets 2026",
        statement="Federal bracket tax before credits, Quebec abatement, provincial or territorial tax and other liabilities; this is not total Canadian tax.",
        effect="disclosure_only", source_url="https://www.canada.ca/en/revenue-agency/services/tax/businesses/topics/payroll/payroll-deductions-contributions/income-tax/reducing-remuneration-subject-income-tax.html",
        effective_from="2026-01-01", effective_to="2026-12-31", reviewed_at="2026-09-07",
        parameters={"brackets": [(58523, "14"), (117045, "20.5"), (181440, "26"), (258482, "29"), (None, "33")]},
    ),
    JurisdictionRule(
        rule_ref="au.super.concessional.2026_27", jurisdiction="AU", verticals=(),
        title="General concessional super contribution cap 2026-27",
        statement="The general cap includes employer and personal concessional contributions across all funds; carry-forward availability and deduction eligibility require individual evidence.",
        effect="disclosure_only", source_url="https://www.ato.gov.au/tax-rates-and-codes/key-superannuation-rates-and-thresholds/contributions-caps",
        effective_from="2026-07-01", effective_to="2027-06-30", reviewed_at="2026-09-07",
        parameters={"general_cap": "32500", "scheme": "super_concessional"},
    ),
    JurisdictionRule(
        rule_ref="ca.rrsp.limit.2026", jurisdiction="CA", verticals=(),
        title="RRSP dollar limit 2026",
        statement="The annual RRSP dollar limit is not the individual's available contribution room; use their assessed room and subsequent contributions.",
        effect="disclosure_only", source_url="https://www.canada.ca/en/revenue-agency/services/tax/registered-plans-administrators/pspa/mp-rrsp-dpsp-tfsa-limits-ympe.html",
        effective_from="2026-01-01", effective_to="2026-12-31", reviewed_at="2026-09-07",
        parameters={"general_cap": "33810", "scheme": "rrsp"},
    ),
    JurisdictionRule(
        rule_ref="ca.tfsa.limit.2026", jurisdiction="CA", verticals=(),
        title="TFSA annual dollar limit 2026",
        statement="The annual TFSA increment is not available room; residency, unused room, withdrawals and subsequent contributions must be reconciled separately.",
        effect="disclosure_only", source_url="https://www.canada.ca/en/revenue-agency/services/tax/registered-plans-administrators/pspa/mp-rrsp-dpsp-tfsa-limits-ympe.html",
        effective_from="2026-01-01", effective_to="2026-12-31", reviewed_at="2026-09-07",
        parameters={"general_cap": "7000", "scheme": "tfsa"},
    ),
    JurisdictionRule(
        rule_ref="au.super.access", jurisdiction="AU", verticals=(), title="Super access requires a condition of release",
        statement="Reaching preservation age and retiring, or reaching age 65, ordinarily permits access; this projection does not determine release eligibility.",
        effect="disclosure_only", source_url="https://www.ato.gov.au/individuals-and-families/super-for-individuals-and-families/super/withdrawing-and-using-your-super/early-access-to-super/illegal-early-access-to-super",
        effective_from="2025-04-14", reviewed_at="2026-09-07", parameters={},
    ),
    JurisdictionRule(
        rule_ref="ca.rrsp.maturity", jurisdiction="CA", verticals=(), title="RRSP maturity",
        statement="An RRSP generally matures by the end of the year the annuitant turns 71; withdrawal, RRIF transfer or annuity options require adviser review.",
        effect="disclosure_only", source_url="https://www.canada.ca/en/revenue-agency/services/forms-publications/publications/t4040/rrsps-other-registered-plans-retirement.html",
        effective_from="2026-01-01", reviewed_at="2026-09-07", parameters={"maturity_age": 71},
    ),
)


RULES: tuple[JurisdictionRule, ...] = (
    JurisdictionRule(rule_ref="au.phi.rebate", jurisdiction="AU", verticals=("AU-31",), title="Australian Government private health insurance rebate", statement="An income-tested rebate reduces the premium of a complying private health insurance policy; the percentage depends on the income tier and the age of the oldest person covered.", effect="credit_per_year", source_url="https://www.privatehealth.gov.au/health_insurance/surcharges_incentives/insurance_rebate.htm", effective_from="2025-07-01", parameters={"tiers": [{"tier": "base", "single_income_max": 101000, "family_income_max": 202000, "rebate_percent": {"under_65": "24.608", "65_to_69": "28.710", "70_plus": "32.812"}}, {"tier": "1", "single_income_max": 118000, "family_income_max": 236000, "rebate_percent": {"under_65": "16.405", "65_to_69": "20.507", "70_plus": "24.608"}}, {"tier": "2", "single_income_max": 158000, "family_income_max": 316000, "rebate_percent": {"under_65": "8.202", "65_to_69": "12.303", "70_plus": "16.405"}}, {"tier": "3", "single_income_max": None, "family_income_max": None, "rebate_percent": {"under_65": "0", "65_to_69": "0", "70_plus": "0"}}]}),
    JurisdictionRule(rule_ref="au.phi.lhc_loading", jurisdiction="AU", verticals=("AU-31",), title="Lifetime Health Cover loading", statement="A person who takes out hospital cover after 1 July following their 31st birthday pays a 2% loading on the hospital premium for every year past 30, to a maximum of 70%, removed after ten continuous years of cover.", effect="cost_per_year", source_url="https://www.privatehealth.gov.au/health_insurance/surcharges_incentives/lifetime_health_cover.htm", effective_from="2000-07-01", parameters={"percent_per_year_over_30": "2", "maximum_percent": "70", "removed_after_years": 10}),
    JurisdictionRule(rule_ref="au.phi.mls", jurisdiction="AU", verticals=("AU-31",), title="Medicare Levy Surcharge", statement="A person above the income threshold without complying hospital cover pays a surcharge of 1% to 1.5% of income; holding hospital cover avoids it, which is a credit against the cost of cover.", effect="credit_per_year", source_url="https://www.ato.gov.au/individuals-and-families/medicare-and-private-health-insurance/medicare-levy-surcharge", effective_from="2025-07-01", parameters={"tiers": [{"single_income_max": 101000, "family_income_max": 202000, "surcharge_percent": "0"}, {"single_income_max": 118000, "family_income_max": 236000, "surcharge_percent": "1"}, {"single_income_max": 158000, "family_income_max": 316000, "surcharge_percent": "1.25"}, {"single_income_max": None, "family_income_max": None, "surcharge_percent": "1.5"}]}),
    JurisdictionRule(rule_ref="au.home_loan.lmi", jurisdiction="AU", verticals=("AU-05",), title="Lenders mortgage insurance above 80% LVR", statement="A loan above 80% of the property value ordinarily requires lenders mortgage insurance paid by the borrower; the premium depends on the lender, the loan amount and the LVR and is quoted by the lender.", effect="disclosure_only", source_url="https://moneysmart.gov.au/home-loans/lenders-mortgage-insurance", effective_from="2020-01-01", parameters={"lvr_threshold_percent": "80"}),
    JurisdictionRule(rule_ref="ca.mortgage.default_insurance", jurisdiction="CA", verticals=("CA-05",), title="Mortgage default insurance above 80% loan-to-value", statement="A mortgage with a down payment under 20% must carry mortgage default insurance (CMHC, Sagen or Canada Guaranty); the premium is a percentage of the loan by loan-to-value band and is usually added to the loan.", effect="one_off_cost", source_url="https://www.cmhc-schl.gc.ca/consumers/home-buying/mortgage-loan-insurance-for-consumers", effective_from="2025-01-01", parameters={"lvr_threshold_percent": "80", "premium_percent_by_ltv": [{"ltv_max": "65", "percent": "0.60"}, {"ltv_max": "75", "percent": "1.70"}, {"ltv_max": "80", "percent": "2.40"}, {"ltv_max": "85", "percent": "2.80"}, {"ltv_max": "90", "percent": "3.10"}, {"ltv_max": "95", "percent": "4.00"}]}),
    JurisdictionRule(rule_ref="ca.auto.public_plans", jurisdiction="CA", verticals=("CA-44",), title="Public auto insurance provinces", statement="Basic auto insurance is provided by a public insurer in British Columbia (ICBC), Saskatchewan (SGI), Manitoba (MPI) and, for bodily injury, Quebec (SAAQ); private insurers compete only for optional cover there.", effect="exclusion", source_url="https://www.canada.ca/en/financial-consumer-agency/services/insurance/auto.html", effective_from="2020-01-01", parameters={"public_basic": ["BC", "SK", "MB"], "public_injury": ["QC"]}),
    JurisdictionRule(rule_ref="au.ctp.schemes", jurisdiction="AU", verticals=("AU-41",), title="Compulsory third party motor schemes by state", statement="CTP is bought from competing licensed insurers in NSW, Queensland, South Australia and the ACT, and from a single government scheme in Victoria (TAC), Western Australia (ICWA), Tasmania (MAIB) and the Northern Territory (MAC).", effect="exclusion", source_url="https://www.sira.nsw.gov.au/insurance-coverage/CTP-insurance", effective_from="2020-01-01", parameters={"competitive": ["NSW", "QLD", "SA", "ACT"], "single_scheme": ["VIC", "WA", "TAS", "NT"]}),
    JurisdictionRule(rule_ref="au.deposits.fcs", jurisdiction="AU", verticals=("AU-01", "AU-02", "AU-03"), title="Financial Claims Scheme deposit guarantee", statement="Deposits with an authorised deposit-taking institution are protected up to $250,000 per account holder per institution under the Financial Claims Scheme.", effect="disclosure_only", source_url="https://www.fcs.gov.au/", effective_from="2013-02-01", parameters={"limit": 250000}),
    JurisdictionRule(rule_ref="ca.deposits.cdic", jurisdiction="CA", verticals=("CA-01", "CA-02", "CA-03"), title="CDIC deposit insurance", statement="Eligible deposits at a CDIC member institution are insured up to $100,000 per depositor per insured category.", effect="disclosure_only", source_url="https://www.cdic.ca/your-coverage/", effective_from="2020-04-30", parameters={"limit": 100000}),
    JurisdictionRule(rule_ref="au.credit.serviceability_buffer", jurisdiction="AU", verticals=("AU-04", "AU-05"), title="Serviceability buffer over the contract rate", statement="A lender assesses the borrower's capacity to repay at the loan's contract rate plus a buffer of at least 3.00 percentage points.", effect="disclosure_only", source_url="https://www.apra.gov.au/news-and-publications/apra-increases-banks-loan-serviceability-expectations-to-counter-rising-risks", effective_from="2021-11-01", confirmed=False, parameters={"buffer_percentage_points": "3.00"}),
    JurisdictionRule(rule_ref="ca.mortgage.stress_test", jurisdiction="CA", verticals=("CA-05",), title="Minimum qualifying rate for a residential mortgage", statement="A borrower qualifies at the greater of the contract rate plus 2.00 percentage points and 5.25 percent.", effect="disclosure_only", source_url="https://www.osfi-bsif.gc.ca/en/guidance/guidance-library/residential-mortgage-underwriting-practices-procedures-guideline-2023", effective_from="2021-06-01", confirmed=False, parameters={"buffer_percentage_points": "2.00", "floor_percent": "5.25"}),
) + RETIREMENT_TAX_RULES


def rules_for(vertical_id: str, jurisdiction: str | None = None) -> tuple[JurisdictionRule, ...]:
    return tuple(rule for rule in RULES if vertical_id in rule.verticals and (jurisdiction is None or rule.jurisdiction == jurisdiction))


def _income(state: ClientState) -> Decimal | None:
    for key in ("income", "annual_income", "household_income"):
        value = _decimal(state.facts.get(key)) if isinstance(state.facts, Mapping) else None
        if value is not None:
            return value
    band = state.income_band or ""
    digits = [int("".join(ch for ch in part if ch.isdigit())) for part in band.replace("k", "000").split("-") if any(ch.isdigit() for ch in part)]
    return Decimal(str(max(digits))) if digits else None


def _age(state: ClientState) -> int | None:
    if isinstance(state.facts, Mapping) and state.facts.get("age") is not None:
        try:
            return int(state.facts["age"])
        except (TypeError, ValueError):
            return None
    band = state.age_band or ""
    digits = "".join(ch if ch.isdigit() else " " for ch in band).split()
    return int(digits[0]) if digits else None


def _family(state: ClientState) -> bool:
    cover = str((state.facts or {}).get("cover_type") or "").lower()
    return cover in ("family", "couple", "single_parent") or str((state.facts or {}).get("dependants") or "0") not in ("0", "", "None")


def _tier(income: Decimal, family: bool, tiers: Sequence[Mapping[str, Any]], key: str) -> Mapping[str, Any]:
    for tier in tiers:
        cap = tier.get("family_income_max" if family else "single_income_max")
        if cap is None or income <= Decimal(str(cap)):
            return tier
    return tiers[-1]


def apply_rules(state: ClientState | Mapping[str, Any], product: Product | Mapping[str, Any] | None, *, vertical_id: str | None = None, annual_premium: Decimal | None = None, horizon_years: int = 1) -> tuple[tuple[RuleAdjustment, ...], tuple[str, ...]]:
    """The rule adjustments that apply to this client and product, and the disclosures every projection built on them carries."""

    s = state if isinstance(state, ClientState) else ClientState.model_validate(dict(detached(state)))
    if product is not None and not isinstance(product, Product):
        Product.model_validate(dict(detached(product)))  # the product is validated for shape; the rules read the client, not the product
    vertical = vertical_id or s.vertical_id
    adjustments: list[RuleAdjustment] = []
    disclosures: list[str] = []
    for rule in rules_for(vertical, s.jurisdiction):
        stamp = f" (figures as published at {rule.source_url}, effective {rule.effective_from}{'' if rule.confirmed else '; not yet confirmed by the operator'})"
        if rule.rule_ref == "au.phi.rebate":
            income, age = _income(s), _age(s)
            if income is None or annual_premium is None:
                disclosures.append(f"{rule.title}: the client's income and the annual premium decide the rebate; income or premium not stated, so no rebate is applied{stamp}")
                continue
            tier = _tier(income, _family(s), rule.parameters["tiers"], "rebate_percent")
            band = "under_65" if age is None or age < 65 else ("65_to_69" if age < 70 else "70_plus")
            percent = Decimal(str(tier["rebate_percent"][band]))
            credit = _money(annual_premium * percent / Decimal("100"))
            adjustments.append(RuleAdjustment(rule_ref=rule.rule_ref, title=rule.title, effect="credit_per_year", amount=credit, per_year=True, basis=f"tier {tier['tier']} at income {income}, age band {band}: {percent}% of {annual_premium}", disclosure=f"{rule.title}: {percent}% rebate (tier {tier['tier']}) reduces the premium by {credit} per year{stamp}"))
            disclosures.append(adjustments[-1].disclosure)
        elif rule.rule_ref == "au.phi.lhc_loading":
            age = _age(s)
            held_since = (s.facts or {}).get("hospital_cover_since_age")
            if age is None or annual_premium is None:
                disclosures.append(f"{rule.title}: the client's age at entry decides the loading; age or premium not stated{stamp}")
                continue
            entry_age = int(held_since) if held_since not in (None, "") else age
            years_over = max(0, entry_age - 30)
            percent = min(Decimal(str(rule.parameters["percent_per_year_over_30"])) * years_over, Decimal(str(rule.parameters["maximum_percent"])))
            if percent > 0:
                cost = _money(annual_premium * percent / Decimal("100"))
                adjustments.append(RuleAdjustment(rule_ref=rule.rule_ref, title=rule.title, effect="cost_per_year", amount=cost, per_year=True, basis=f"entry at {entry_age}: {years_over} year(s) over 30 at 2% = {percent}%", disclosure=f"{rule.title}: {percent}% loading adds {cost} per year to hospital cover taken out at {entry_age}{stamp}"))
                disclosures.append(adjustments[-1].disclosure)
            else:
                disclosures.append(f"{rule.title}: no loading applies at entry age {entry_age}{stamp}")
        elif rule.rule_ref == "au.phi.mls":
            income = _income(s)
            if income is None:
                disclosures.append(f"{rule.title}: income not stated, so the surcharge avoided by holding hospital cover is not counted{stamp}")
                continue
            tier = _tier(income, _family(s), rule.parameters["tiers"], "surcharge_percent")
            percent = Decimal(str(tier["surcharge_percent"]))
            if percent > 0:
                credit = _money(income * percent / Decimal("100"))
                adjustments.append(RuleAdjustment(rule_ref=rule.rule_ref, title=rule.title, effect="credit_per_year", amount=credit, per_year=True, basis=f"{percent}% of income {income} avoided by holding complying hospital cover", disclosure=f"{rule.title}: holding hospital cover avoids a surcharge of {credit} per year ({percent}% of income){stamp}"))
                disclosures.append(adjustments[-1].disclosure)
            else:
                disclosures.append(f"{rule.title}: below the threshold, no surcharge applies{stamp}")
        elif rule.rule_ref in ("au.home_loan.lmi", "ca.mortgage.default_insurance"):
            lvr = s.lvr_percent
            threshold = Decimal(str(rule.parameters["lvr_threshold_percent"]))
            if lvr is None:
                disclosures.append(f"{rule.title}: LVR not stated{stamp}")
                continue
            if lvr <= threshold:
                disclosures.append(f"{rule.title}: does not apply at {lvr}% LVR{stamp}")
                continue
            if rule.effect == "one_off_cost" and s.amount is not None:
                percent = next((Decimal(str(band["percent"])) for band in rule.parameters["premium_percent_by_ltv"] if lvr <= Decimal(str(band["ltv_max"]))), None)
                if percent is not None:
                    cost = _money(s.amount * percent / Decimal("100"))
                    adjustments.append(RuleAdjustment(rule_ref=rule.rule_ref, title=rule.title, effect="one_off_cost", amount=cost, per_year=False, basis=f"{percent}% of {s.amount} at {lvr}% LTV", disclosure=f"{rule.title}: about {cost} ({percent}% of the loan) at {lvr}% loan-to-value, usually added to the loan{stamp}"))
                    disclosures.append(adjustments[-1].disclosure)
                    continue
            adjustments.append(RuleAdjustment(rule_ref=rule.rule_ref, title=rule.title, effect="disclosure_only", amount=None, per_year=False, basis=f"{lvr}% LVR is above {threshold}%", disclosure=f"{rule.title}: applies at {lvr}% LVR; the lender quotes the premium and it is not in this total{stamp}"))
            disclosures.append(adjustments[-1].disclosure)
        elif rule.effect == "exclusion":
            region = (s.region or "").upper()
            public = [str(item).upper() for item in (rule.parameters.get("public_basic") or rule.parameters.get("single_scheme") or ())]
            if region and region in public:
                adjustments.append(RuleAdjustment(rule_ref=rule.rule_ref, title=rule.title, effect="exclusion", amount=None, per_year=False, basis=f"{region} is a public-scheme jurisdiction", disclosure=f"{rule.title}: in {region} the basic cover is public; private products compare on optional cover only{stamp}"))
                disclosures.append(adjustments[-1].disclosure)
            elif region:
                disclosures.append(f"{rule.title}: {region} is a competitive market{stamp}")
            else:
                disclosures.append(f"{rule.title}: region not stated; whether a public scheme applies is unknown{stamp}")
        else:
            disclosures.append(f"{rule.title}: {rule.statement}{stamp}")
    return tuple(adjustments), tuple(disclosures)


def rules_total(adjustments: Sequence[RuleAdjustment | Mapping[str, Any]], *, horizon_years: int) -> Decimal:
    """The net cost (positive) or credit (negative) the rules add over the horizon."""

    total = Decimal("0")
    for raw in adjustments:
        item = raw if isinstance(raw, RuleAdjustment) else RuleAdjustment.model_validate(dict(detached(raw)))
        if item.amount is None:
            continue
        years = Decimal(horizon_years) if item.per_year else Decimal("1")
        sign = Decimal("-1") if "credit" in item.effect else Decimal("1")
        total += sign * item.amount * years
    return _money(total)


RULES_MANIFEST: dict[str, Any] = {
    "kind": "lightbulb.finance_advice_rules.v1",
    "rules": [{"rule_ref": rule.rule_ref, "jurisdiction": rule.jurisdiction, "verticals": list(rule.verticals), "title": rule.title, "effect": rule.effect, "source_url": rule.source_url, "effective_from": rule.effective_from, "effective_to": rule.effective_to, "reviewed_at": rule.reviewed_at, "confirmed": rule.confirmed} for rule in RULES],
    "hard_rules": [
        "a rule is the jurisdiction's own, cited by URL and effective date; it never comes from a provider pack",
        "every figure a projection uses is disclosed with its source and whether the operator has confirmed it",
        "an unconfirmed figure is still disclosed as unconfirmed; it is never silently used as fact",
    ],
}


__all__ = ["RULES", "RULES_MANIFEST", "RULES_SCHEMA", "RETIREMENT_TAX_RULES", "JurisdictionRule", "RuleAdjustment", "apply_rules", "rules_for", "rules_total"]
