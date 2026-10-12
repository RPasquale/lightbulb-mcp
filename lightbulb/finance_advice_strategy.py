"""Strategy: the client's cash flow, debts, emergency fund and serviceability as arithmetic the adviser reads.

Stage two of advice is not a product question; it is the client's own numbers over the years
ahead. From the facts the client disclosed (annual income, annual expenses, the debts with their
balances, rates and minimum payments, the savings held) this module projects a year-by-year cash
flow with every default written down as an assumption (zero wage growth, zero inflation, zero
savings growth, a three-month emergency fund), states whether the emergency fund and the
debt-free goal are met and in which year, orders the debts for paydown by rate or by balance,
assesses a credit product's repayment at the contract rate plus the jurisdiction's buffer (a
RULES row carried unconfirmed and named so in every verdict), and compares scenarios that change
only the facts they name. A fact the client did not give is listed as missing and never
estimated; nothing here forecasts returns, inflation or retirement, and nothing recommends: the
adviser reads the verdicts, and the compliance checklist reads them as evidence.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import ROUND_CEILING, ROUND_HALF_UP, Decimal, InvalidOperation
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, OpaqueRef, Sha256Digest, ShortText, detached, seal, sealed_digest, skip_digests, timestamp
from lightbulb.finance_advice_identity import AdviceIdentityModel as StrictModel
from lightbulb.finance_advice_catalog import PricingFact, Product
from lightbulb.finance_advice_engine import ClientState
from lightbulb.finance_advice_holistic import ORDER
from lightbulb.finance_advice_needs import NeedsAssessment, assess_needs, needs_kind
from lightbulb.finance_advice_projection import DEFAULT_LOAN_TERM_YEARS, monthly_payment, rate_phases
from lightbulb.finance_advice_rules import RULES, JurisdictionRule
from lightbulb.finance_advice_retirement import RetirementProjection, TaxEstimate, has_retirement_facts, income_tax_estimate, retirement_projection

STRATEGY_SCHEMA = "lightbulb.finance_advice_strategy_plan.v1"
CASHFLOW_SCHEMA = "lightbulb.finance_advice_cashflow_projection.v1"
DEBT_PLAN_SCHEMA = "lightbulb.finance_advice_debt_plan.v1"
EMERGENCY_FUND_SCHEMA = "lightbulb.finance_advice_emergency_fund_gap.v1"
SERVICEABILITY_SCHEMA = "lightbulb.finance_advice_serviceability.v1"
SCENARIO_SCHEMA = "lightbulb.finance_advice_scenario_comparison.v1"

STRATEGY_DEFAULTS: dict[str, Any] = {"emergency_fund_months": 3, "savings_growth_percent": Decimal("0"), "wage_growth_percent": Decimal("0"), "inflation_percent": Decimal("0")}
FORBIDDEN_DEBT_KEYS = frozenset({"account_number", "lender_account", "bsb", "iban", "card_number"})
# A debt entry is a nested object the ClientState guard does not walk, so the personal-data keys are refused here too.
_PERSONAL_DEBT_KEYS = frozenset({"name", "first_name", "last_name", "full_name", "email", "phone", "mobile", "address", "street", "date_of_birth", "dob", "policy_number", "member_number", "tax_file_number", "tfn", "sin", "social_insurance_number", "passport", "drivers_licence"})
AU_SERVICEABILITY_BUFFER_REF = "au.credit.serviceability_buffer"
CA_STRESS_TEST_REF = "ca.mortgage.stress_test"
MAX_HORIZON_YEARS = 40
MAX_EMERGENCY_FUND_MONTHS = 60
MAX_FIGURE = Decimal("1000000000000")
MAX_PAYDOWN_MONTHS = MAX_HORIZON_YEARS * 12
CARD_ASSESSMENT_TERM_YEARS = 3
NOT_CONFIRMED = "not yet confirmed by the operator"

GoalKind = Literal["emergency_fund", "debt_free", "insurance_sufficiency"]
GoalStatus = Literal["met", "met_by_year", "short", "unassessed"]
PaydownStrategy = Literal["avalanche", "snowball"]
FundStatus = Literal["met", "short", "unassessed"]
ServiceabilityVerdict = Literal["serviceable", "not_serviceable", "unassessed"]

_CENTS = Decimal("0.01")
_ROW_FIELDS: tuple[str, ...] = ("income", "expenses", "debt_payments", "surplus", "savings_balance", "debts_outstanding")
_SCENARIO_FACTS = frozenset({"income", "income_basis", "net_income", "expenses", "savings", "debts"})
_COMPARISON_ITEMS = ("comparison rate", "interest/comparison rate", "apr", "current_apr", "posted_apr", "annual percentage rate")
_RATE_ITEMS = ("interest rate", "variable interest rate", "fixed interest rate", "current interest rate", "interest_rate", "current_interest_rate", "mortgage interest rate", "standard variable rate", "variable rate", "fixed rate", "annual percentage rate", "apr")
_CARD_RATE_ITEMS = ("purchase interest rate", "purchase rate", "interest rate", "annual percentage rate", "apr")
_RATE_KINDS = ("rate_percent_per_year", "percent")
_INSURANCE_KINDS = ("life", "income_protection", "tpd", "trauma")
_INSURANCE_VERTICALS: dict[str, dict[str, str]] = {"AU": {"life": "AU-32", "income_protection": "AU-33", "tpd": "AU-34", "trauma": "AU-35"}, "CA": {"life": "CA-35", "income_protection": "CA-36", "trauma": "CA-37"}}

# The buffer rows the serviceability verdict cites. They live in finance_advice_rules.RULES once the
# integrator applies scratch_patches/strategy.py; until then this table carries the same rows in the same
# shape so the verdict is the same either way. Both are unconfirmed until the operator confirms them.
BUFFER_RULES: tuple[JurisdictionRule, ...] = (
    JurisdictionRule(rule_ref=AU_SERVICEABILITY_BUFFER_REF, jurisdiction="AU", verticals=("AU-04", "AU-05"), title="Serviceability buffer over the contract rate", statement="A lender assesses the borrower's capacity to repay at the loan's contract rate plus a buffer of at least 3.00 percentage points.", effect="disclosure_only", source_url="https://www.apra.gov.au/news-and-publications/apra-increases-banks-loan-serviceability-expectations-to-counter-rising-risks", effective_from="2021-11-01", confirmed=False, parameters={"buffer_percentage_points": "3.00"}),
    JurisdictionRule(rule_ref=CA_STRESS_TEST_REF, jurisdiction="CA", verticals=("CA-05",), title="Minimum qualifying rate for a residential mortgage", statement="A borrower qualifies at the greater of the contract rate plus 2.00 percentage points and 5.25 percent.", effect="disclosure_only", source_url="https://www.osfi-bsif.gc.ca/en/guidance/guidance-library/residential-mortgage-underwriting-practices-procedures-guideline-2023", effective_from="2021-06-01", confirmed=False, parameters={"buffer_percentage_points": "2.00", "floor_percent": "5.25"}),
)


class AdviceStrategyError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _money(value: Decimal) -> Decimal:
    return value.quantize(_CENTS, rounding=ROUND_HALF_UP)


def _decimal(value: Any) -> Decimal | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return Decimal(str(value).replace(",", "").replace("$", "").replace("%", "").strip())
    except (InvalidOperation, ValueError):
        return None


def _number(value: Any, name: str, *, allow_negative: bool = False) -> Decimal | None:
    """A disclosed figure as a Decimal; absent is None, unreadable and negative figures refuse."""

    if value is None or value == "":
        return None
    if isinstance(value, bool) or isinstance(value, (list, tuple, Mapping)):
        raise AdviceStrategyError("FACT_NOT_NUMERIC", f"{name} must be a number; got {type(value).__name__}")
    number = _decimal(value)
    if number is None or not number.is_finite():
        raise AdviceStrategyError("FACT_NOT_NUMERIC", f"{name} must be a number; got {value!r}")
    if number < 0 and not allow_negative:
        raise AdviceStrategyError("NEGATIVE_FIGURE", f"{name} cannot be negative; got {number}")
    if abs(number) > MAX_FIGURE:
        raise AdviceStrategyError("FACT_NOT_NUMERIC", f"{name} is out of range; got {number}")
    return number


def _percent(value: Any, name: str) -> Decimal:
    number = _number(value, name, allow_negative=True)
    if number is None:
        raise AdviceStrategyError("FACT_NOT_NUMERIC", f"{name} must be a number")
    return number


def _state(state: ClientState | Mapping[str, Any]) -> ClientState:
    return state if isinstance(state, ClientState) else ClientState.model_validate(dict(detached(state)))


def _fact(state: ClientState, *keys: str) -> Any:
    facts = state.facts if isinstance(state.facts, Mapping) else {}
    for key in keys:
        if key in facts and facts[key] not in (None, ""):
            return facts[key]
    return None


def _income(state: ClientState) -> Decimal | None:
    income = _number(_fact(state, "income"), "income")
    annual = _number(_fact(state, "annual_income"), "annual_income")
    if income is not None and annual is not None and income != annual:
        raise AdviceStrategyError("INCOME_CONFLICT", "income and annual_income must state the same annual figure")
    return income if income is not None else annual


def _spendable_income(state: ClientState) -> tuple[Decimal | None, str, str | None]:
    """Resolve stated annual take-home income without deriving tax or relabelling gross pay."""
    declared = _income(state)
    basis = _fact(state, "income_basis")
    if basis is not None and basis not in ("gross", "net"):
        raise AdviceStrategyError("INCOME_BASIS_INVALID", "income_basis must be gross or net")
    net = _number(_fact(state, "net_income"), "net_income")
    if net is not None:
        if basis == "net" and declared is not None and declared != net:
            raise AdviceStrategyError("INCOME_CONFLICT", "net_income conflicts with income explicitly stated as net")
        return net, "income_basis: net_income is the stated annual take-home amount after tax and payroll deductions; no further tax is deducted", None
    if declared is not None and basis == "net":
        return declared, "income_basis: income is explicitly net annual take-home pay; no further tax is deducted", None
    missing = "income (annual)" if declared is None else "net income (annual net_income, or income with income_basis=net)"
    note = "income_basis: " + ("gross income is not spendable income" if basis == "gross" else "take-home income is not established") + "; no tax estimate or gross-to-net conversion is inferred"
    return None, note, missing


def _expenses(state: ClientState) -> Decimal | None:
    return _number(_fact(state, "expenses", "annual_expenses"), "expenses")


def _savings(state: ClientState) -> Decimal | None:
    return _number(_fact(state, "savings", "savings_balance"), "savings")


def _decimals(value: Any) -> Any:
    return None if value is None else (value if isinstance(value, Decimal) else Decimal(str(value)))


def _tuples(value: Any) -> Any:
    return tuple(value) if isinstance(value, list) else value


# --------------------------------------------------------------------------- #
# Debts: decision facts, never identifiers
# --------------------------------------------------------------------------- #


class DebtEntry(StrictModel):
    kind: ShortText
    balance: Decimal
    rate_percent: Decimal | None = None
    minimum_payment_per_year: Decimal | None = None

    @field_validator("balance", "rate_percent", "minimum_payment_per_year", mode="before")
    @classmethod
    def _amounts(cls, value: Any) -> Any:
        return _decimals(value)

    @property
    def complete(self) -> bool:
        return self.rate_percent is not None and self.minimum_payment_per_year is not None


def _debts(state: ClientState) -> tuple[tuple[DebtEntry, ...] | None, list[str]]:
    """The debts as stated: a list of entries, a single total, or nothing; (None, missing) when the fact is absent."""

    raw = _fact(state, "debts")
    if raw is None:
        return None, ["debts (each with kind, balance, rate_percent and minimum_payment_per_year)"]
    missing: list[str] = []
    if isinstance(raw, Mapping):
        raw = [raw]
    if not isinstance(raw, (list, tuple)):
        total = _number(raw, "debts")
        if total is None:
            return None, ["debts"]
        missing.extend(["debts: rate_percent (the total was stated without a rate)", "debts: minimum_payment_per_year (the total was stated without a payment)"])
        return (DebtEntry(kind="debts (total as stated)", balance=_money(total)),), missing
    entries: list[DebtEntry] = []
    for index, item in enumerate(raw):
        if not isinstance(item, Mapping):
            raise AdviceStrategyError("FACT_NOT_NUMERIC", f"debts[{index}] must be an object with kind, balance, rate_percent and minimum_payment_per_year")
        bad = sorted(str(key) for key in item if str(key).lower() in FORBIDDEN_DEBT_KEYS or str(key).lower() in _PERSONAL_DEBT_KEYS)
        if bad:
            raise AdviceStrategyError("DEBT_CARRIES_IDENTIFIER", f"debts[{index}] carries {', '.join(bad)}; a debt is a kind, a balance, a rate and a payment, never an account identifier or personal data")
        kind = str(item.get("kind") or f"debt {index + 1}")[:300]
        balance = _number(item.get("balance"), f"debts[{index}].balance")
        if balance is None:
            raise AdviceStrategyError("FACT_NOT_NUMERIC", f"debts[{index}] ({kind}) states no balance")
        rate = _number(item.get("rate_percent"), f"debts[{index}].rate_percent")
        minimum = _number(item.get("minimum_payment_per_year"), f"debts[{index}].minimum_payment_per_year")
        if rate is None:
            missing.append(f"debts[{kind}].rate_percent")
        if minimum is None:
            missing.append(f"debts[{kind}].minimum_payment_per_year")
        entries.append(DebtEntry(kind=kind, balance=_money(balance), rate_percent=rate, minimum_payment_per_year=None if minimum is None else _money(minimum)))
    return tuple(entries), missing


def _minimums_per_month(debts: Sequence[DebtEntry] | None) -> Decimal:
    return sum((item.minimum_payment_per_year / Decimal(12) for item in (debts or ()) if item.minimum_payment_per_year is not None), Decimal("0"))


# --------------------------------------------------------------------------- #
# Assumptions: every default written down
# --------------------------------------------------------------------------- #


def _assumptions(overrides: Mapping[str, Any] | None) -> tuple[dict[str, Any], list[str]]:
    given = dict(overrides or {})
    unknown = sorted(str(key) for key in given if key not in STRATEGY_DEFAULTS)
    if unknown:
        raise AdviceStrategyError("ASSUMPTION_UNKNOWN", "unknown assumption keys: " + ", ".join(unknown) + "; the projection knows " + ", ".join(sorted(STRATEGY_DEFAULTS)))
    values: dict[str, Any] = {}
    lines: list[str] = []
    for key, default in STRATEGY_DEFAULTS.items():
        if key in given:
            value = _percent(given[key], key)
            if key == "emergency_fund_months":
                if value != value.to_integral_value() or not 1 <= value <= MAX_EMERGENCY_FUND_MONTHS:
                    raise AdviceStrategyError("HORIZON_OUT_OF_RANGE", f"emergency_fund_months must be a whole number from 1 to {MAX_EMERGENCY_FUND_MONTHS}; got {given[key]!r}")
                value = int(value)
            elif not Decimal("-100") <= value <= Decimal("100"):
                raise AdviceStrategyError("FACT_NOT_NUMERIC", f"{key} must be a percentage from -100 to 100; got {value}")
            origin = "supplied by the caller; not an operator-confirmed rule"
        else:
            value = default
            origin = "default"
        values[key] = value
        unit = " months" if key == "emergency_fund_months" else "% a year"
        lines.append(f"{key}: {value}{unit} ({origin})")
    lines.append("figures_as_stated: income is stated annual take-home pay; expenses exclude tax and payroll deductions already removed from that pay")
    return values, lines


# --------------------------------------------------------------------------- #
# Cash flow
# --------------------------------------------------------------------------- #


class CashflowYear(StrictModel):
    year: int = Field(ge=1, le=MAX_HORIZON_YEARS)
    income: Decimal
    expenses: Decimal
    debt_payments: Decimal
    surplus: Decimal
    savings_balance: Decimal | None = None
    debts_outstanding: Decimal
    emergency_fund_months: Decimal | None = None

    @field_validator("income", "expenses", "debt_payments", "surplus", "savings_balance", "debts_outstanding", "emergency_fund_months", mode="before")
    @classmethod
    def _amounts(cls, value: Any) -> Any:
        return _decimals(value)


class GoalVerdict(StrictModel):
    goal: GoalKind
    kind: str | None = None
    status: GoalStatus
    year_met: int | None = None
    figure: Decimal | None = None
    target: Decimal | None = None
    basis: ShortText
    assumption_key: str

    @field_validator("figure", "target", mode="before")
    @classmethod
    def _amounts(cls, value: Any) -> Any:
        return _decimals(value)


class CashflowProjection(StrictModel):
    """Year by year, from the disclosed figures only, with the goals the rows settle and every assumption named."""

    schema_id: str = Field(default=CASHFLOW_SCHEMA, alias="schema")
    state_digest: Sha256Digest
    jurisdiction: str
    vertical_id: str
    horizon_years: int = Field(ge=1, le=MAX_HORIZON_YEARS)
    currency: str
    rows: tuple[CashflowYear, ...] = Field(default_factory=tuple)
    goals: tuple[GoalVerdict, ...] = Field(default_factory=tuple)
    debts: tuple[DebtEntry, ...] = Field(default_factory=tuple)
    assumptions: tuple[str, ...] = Field(default_factory=tuple)
    missing: tuple[str, ...] = Field(default_factory=tuple)
    prepared_at: str
    projection_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("rows", "goals", "debts", "assumptions", "missing", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _tuples(value)

    @model_validator(mode="after")
    def _seal(self, info: ValidationInfo) -> CashflowProjection:
        if not skip_digests(info) and self.projection_digest != sealed_digest(CashflowProjection, self, "projection_digest"):
            raise ValueError("projection_digest must commit the exact projection")
        return self

    def goal(self, kind: str) -> GoalVerdict | None:
        return next((item for item in self.goals if item.goal == kind), None)


def _horizon(horizon_years: Any) -> int:
    if isinstance(horizon_years, bool) or not isinstance(horizon_years, int) or not 1 <= horizon_years <= MAX_HORIZON_YEARS:
        raise AdviceStrategyError("HORIZON_OUT_OF_RANGE", f"horizon_years must be an integer from 1 to {MAX_HORIZON_YEARS}; got {horizon_years!r}")
    return horizon_years


def _amortise_year(balance: Decimal, rate_percent: Decimal, minimum_per_year: Decimal) -> tuple[Decimal, Decimal, Decimal]:
    """Twelve months at the stated minimum: (closing balance, paid, interest)."""

    monthly_rate = rate_percent / Decimal(1200)
    payment = minimum_per_year / Decimal(12)
    paid = Decimal("0")
    interest = Decimal("0")
    for _ in range(12):
        if balance <= 0:
            break
        month_interest = balance * monthly_rate
        interest += month_interest
        due = min(payment, balance + month_interest)
        paid += due
        balance = balance + month_interest - due
    return max(balance, Decimal("0")), paid, interest


def _goal(goal: str, status: str, basis: str, key: str, *, kind: str | None = None, year_met: int | None = None, figure: Decimal | None = None, target: Decimal | None = None) -> GoalVerdict:
    return GoalVerdict(goal=goal, kind=kind, status=status, year_met=year_met, figure=None if figure is None else _money(figure), target=None if target is None else _money(target), basis=basis[:300], assumption_key=key)


def cashflow_projection(state: ClientState | Mapping[str, Any], *, horizon_years: int = 5, assumptions: Mapping[str, Any] | None = None, as_of: str) -> CashflowProjection:
    """The disclosed income, expenses, debts and savings carried year by year; a missing fact is listed, never estimated."""

    s = _state(state)
    stamp = timestamp(as_of, field_name="as_of")
    horizon = _horizon(horizon_years)
    values, notes = _assumptions(assumptions)
    income, income_note, income_missing = _spendable_income(s)
    notes.append(income_note)
    expenses = _expenses(s)
    savings = _savings(s)
    debts, missing = _debts(s)
    if income is None:
        missing.insert(0, income_missing)
    if expenses is None:
        missing.insert(1 if income is None else 0, "expenses (annual)")
    if savings is None:
        missing.append("savings (the balance held today)")
    entries = list(debts or ())
    incomplete = [item for item in entries if not item.complete]
    if incomplete:
        notes.append("debt_payments_as_stated: a debt without a stated rate and minimum payment is carried flat and paid nothing in the projection: " + ", ".join(item.kind for item in incomplete))
    else:
        notes.append("debt_payments_as_stated: each debt is paid its stated minimum every month at its stated rate; no extra payments are projected")
    if debts is None:
        notes.append("debt_payments_as_stated: no debts fact was given, so the projection carries no debt payments")
    rows: list[CashflowYear] = []
    goals: list[GoalVerdict] = []
    months = values["emergency_fund_months"]
    if income is not None and expenses is not None:
        wage = Decimal(1) + values["wage_growth_percent"] / Decimal(100)
        inflation = Decimal(1) + values["inflation_percent"] / Decimal(100)
        growth = Decimal(1) + values["savings_growth_percent"] / Decimal(100)
        balances = {index: item.balance for index, item in enumerate(entries)}
        savings_balance = savings
        income_year = income
        expenses_year = expenses
        for year in range(1, horizon + 1):
            if year > 1:
                income_year = income_year * wage
                expenses_year = expenses_year * inflation
            paid_total = Decimal("0")
            for index, item in enumerate(entries):
                if item.complete and balances[index] > 0:
                    balances[index], paid, _ = _amortise_year(balances[index], item.rate_percent, item.minimum_payment_per_year)
                    paid_total += paid
            surplus = income_year - expenses_year - paid_total
            if savings_balance is not None:
                savings_balance = savings_balance * growth + surplus
            outstanding = sum(balances.values(), Decimal("0"))
            ef_months = None if savings_balance is None or expenses_year <= 0 else (savings_balance / (expenses_year / Decimal(12))).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)
            rows.append(CashflowYear(year=year, income=_money(income_year), expenses=_money(expenses_year), debt_payments=_money(paid_total), surplus=_money(surplus), savings_balance=None if savings_balance is None else _money(savings_balance), debts_outstanding=_money(outstanding), emergency_fund_months=ef_months))
        if any(row.surplus < 0 for row in rows):
            notes.append("negative_surplus: a year whose expenses and debt payments exceed income draws on savings; no borrowing is projected")
    # emergency fund
    if expenses is None or savings is None:
        goals.append(_goal("emergency_fund", "unassessed", "the emergency fund needs the annual expenses and the savings held: " + ", ".join(item for item in ("expenses" if expenses is None else "", "savings" if savings is None else "") if item) + " not stated", "emergency_fund_months"))
    else:
        target = expenses / Decimal(12) * Decimal(months)
        if savings >= target:
            goals.append(_goal("emergency_fund", "met", f"savings of {_money(savings)} cover {months} months of expenses ({_money(target)}) today", "emergency_fund_months", year_met=0, figure=savings, target=target))
        else:
            reached = next((row for row in rows if row.savings_balance is not None and row.savings_balance >= target), None)
            if reached is not None:
                goals.append(_goal("emergency_fund", "met_by_year", f"savings reach {months} months of expenses ({_money(target)}) in year {reached.year} at the projected surplus", "emergency_fund_months", year_met=reached.year, figure=reached.savings_balance, target=target))
            else:
                last = rows[-1].savings_balance if rows and rows[-1].savings_balance is not None else savings
                goals.append(_goal("emergency_fund", "short", f"savings of {_money(last)} at year {rows[-1].year if rows else 0} are {_money(target - last)} short of {months} months of expenses ({_money(target)})", "emergency_fund_months", figure=last, target=target))
    # debt free
    if debts is None:
        goals.append(_goal("debt_free", "unassessed", "no debts fact was given; the fact find asks for the debts with kind, balance, rate and minimum payment", "debt_payments_as_stated"))
    elif not entries:
        goals.append(_goal("debt_free", "met", "the fact find states no debts", "debt_payments_as_stated", year_met=0, figure=Decimal("0"), target=Decimal("0")))
    elif all(item.balance <= 0 for item in entries):
        goals.append(_goal("debt_free", "met", "the stated debts carry no balance", "debt_payments_as_stated", year_met=0, figure=Decimal("0"), target=Decimal("0")))
    elif incomplete or not rows:
        goals.append(_goal("debt_free", "unassessed", "a debt without a stated rate and minimum payment cannot be projected: " + ", ".join(item.kind for item in incomplete) if incomplete else "the cash flow needs income and expenses before debts can be projected", "debt_payments_as_stated", figure=sum((item.balance for item in entries), Decimal("0")), target=Decimal("0")))
    else:
        cleared = next((row for row in rows if row.debts_outstanding == 0), None)
        if cleared is not None:
            goals.append(_goal("debt_free", "met_by_year", f"every debt is cleared by year {cleared.year} at the stated minimum payments", "debt_payments_as_stated", year_met=cleared.year, figure=Decimal("0"), target=Decimal("0")))
        else:
            goals.append(_goal("debt_free", "short", f"{_money(rows[-1].debts_outstanding)} of debt remains at year {rows[-1].year} at the stated minimum payments", "debt_payments_as_stated", figure=rows[-1].debts_outstanding, target=Decimal("0")))
    return seal(CashflowProjection, {"state_digest": s.state_digest, "jurisdiction": s.jurisdiction, "vertical_id": s.vertical_id, "horizon_years": horizon, "currency": "AUD" if s.jurisdiction == "AU" else "CAD", "rows": [row.to_dict() for row in rows], "goals": [item.to_dict() for item in goals], "debts": [item.to_dict() for item in entries], "assumptions": list(dict.fromkeys(notes)), "missing": list(dict.fromkeys(missing)), "prepared_at": stamp}, "projection_digest")


def goal_lines(projection: CashflowProjection | Mapping[str, Any]) -> tuple[str, ...]:
    """Plain sentences the record can cite as cashflow:<n>, each ending with the assumption key it rests on."""

    p = projection if isinstance(projection, CashflowProjection) else CashflowProjection.model_validate(dict(detached(projection)))
    lines: list[str] = []
    if p.rows:
        first = p.rows[0]
        lines.append(f"Year 1: income {first.income} {p.currency}, expenses {first.expenses}, debt payments {first.debt_payments}, surplus {first.surplus} (assumption: figures_as_stated)")
        if len(p.rows) > 1:
            last = p.rows[-1]
            lines.append(f"Year {last.year}: income {last.income} {p.currency}, expenses {last.expenses}, surplus {last.surplus}, debts outstanding {last.debts_outstanding} (assumption: wage_growth_percent)")
            if last.savings_balance is not None:
                lines.append(f"Savings of {last.savings_balance} {p.currency} at year {last.year} (assumption: savings_growth_percent)")
    for goal in p.goals:
        lines.append(f"{goal.goal.replace('_', ' ')}: {goal.status.replace('_', ' ')}; {goal.basis} (assumption: {goal.assumption_key})")
    for item in p.missing:
        lines.append(f"Not projected: {item} was not stated (assumption: figures_as_stated)")
    return tuple(lines)


# --------------------------------------------------------------------------- #
# Debt paydown
# --------------------------------------------------------------------------- #


class DebtOrderEntry(StrictModel):
    kind: ShortText
    balance: Decimal
    rate_percent: Decimal | None = None
    minimum_payment_per_year: Decimal | None = None
    reason: ShortText

    @field_validator("balance", "rate_percent", "minimum_payment_per_year", mode="before")
    @classmethod
    def _amounts(cls, value: Any) -> Any:
        return _decimals(value)


class DebtPlan(StrictModel):
    """The debts in paydown order with the reason for the order, and the months and interest the order takes at a stated surplus."""

    schema_id: str = Field(default=DEBT_PLAN_SCHEMA, alias="schema")
    state_digest: Sha256Digest
    strategy: PaydownStrategy
    order: tuple[DebtOrderEntry, ...] = Field(default_factory=tuple)
    total_balance: Decimal
    months_to_clear: int | None = None
    interest_paid: Decimal | None = None
    total_paid: Decimal | None = None
    surplus_per_month: Decimal | None = None
    assumptions: tuple[str, ...] = Field(default_factory=tuple)
    missing: tuple[str, ...] = Field(default_factory=tuple)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("order", "assumptions", "missing", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _tuples(value)

    @field_validator("total_balance", "interest_paid", "total_paid", "surplus_per_month", mode="before")
    @classmethod
    def _amounts(cls, value: Any) -> Any:
        return _decimals(value)

    @model_validator(mode="after")
    def _seal(self, info: ValidationInfo) -> DebtPlan:
        if not skip_digests(info) and self.plan_digest != sealed_digest(DebtPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self


def _ordered(entries: Sequence[DebtEntry], strategy: str) -> list[DebtOrderEntry]:
    if strategy == "avalanche":
        ranked = sorted(entries, key=lambda item: (item.rate_percent is None, -(item.rate_percent or Decimal("0")), -item.balance, item.kind))
        return [DebtOrderEntry(kind=item.kind, balance=item.balance, rate_percent=item.rate_percent, minimum_payment_per_year=item.minimum_payment_per_year, reason=(f"rate {item.rate_percent}% is the highest still owed; interest costs most here" if index == 0 else f"rate {item.rate_percent}% is next by rate") if item.rate_percent is not None else "rate not stated; placed last until it is") for index, item in enumerate(ranked)]
    ranked = sorted(entries, key=lambda item: (item.balance, item.kind))
    return [DebtOrderEntry(kind=item.kind, balance=item.balance, rate_percent=item.rate_percent, minimum_payment_per_year=item.minimum_payment_per_year, reason=(f"balance {item.balance} is the smallest; clearing it first frees its payment" if index == 0 else f"balance {item.balance} is next by size")) for index, item in enumerate(ranked)]


def _surplus_per_month(state: ClientState, debts: Sequence[DebtEntry] | None, given: Decimal | str | None) -> tuple[Decimal | None, str]:
    if given is not None:
        surplus = _number(given, "surplus_per_month")
        if surplus is None:
            raise AdviceStrategyError("FACT_NOT_NUMERIC", f"surplus_per_month must be a number; got {given!r}")
        return surplus, f"surplus_per_month: {_money(surplus)} a month supplied by the caller over the stated minimum payments"
    income, income_note, _ = _spendable_income(state)
    expenses = _expenses(state)
    if income is None or expenses is None:
        return None, "surplus_per_month: not stated and not derivable without net income and expenses; " + income_note
    derived = (income - expenses) / Decimal(12) - _minimums_per_month(debts)
    if derived <= 0:
        return Decimal("0"), f"surplus_per_month: 0 because income less expenses and the stated minimum payments leaves {_money(derived)} a month"
    return derived, f"surplus_per_month: {_money(derived)} a month derived from net income less expenses less the stated minimum payments; " + income_note


def _simulate(order: Sequence[DebtOrderEntry], surplus: Decimal) -> tuple[int | None, Decimal, Decimal]:
    balances = [item.balance for item in order]
    minimums = [item.minimum_payment_per_year / Decimal(12) for item in order]
    budget = surplus + sum(minimums, Decimal("0"))
    interest_total = Decimal("0")
    paid_total = Decimal("0")
    if all(balance <= 0 for balance in balances):
        return 0, interest_total, paid_total
    for month in range(1, MAX_PAYDOWN_MONTHS + 1):
        for index, item in enumerate(order):
            if balances[index] > 0:
                interest = balances[index] * item.rate_percent / Decimal(1200)
                balances[index] += interest
                interest_total += interest
        left = budget
        for index in range(len(order)):
            if balances[index] > 0:
                due = min(minimums[index], balances[index], left)
                balances[index] -= due
                left -= due
                paid_total += due
        for index in range(len(order)):
            if left <= 0:
                break
            if balances[index] > 0:
                due = min(balances[index], left)
                balances[index] -= due
                left -= due
                paid_total += due
        if all(balance <= 0 for balance in balances):
            return month, _money(interest_total), _money(paid_total)
    return None, _money(interest_total), _money(paid_total)


def debt_paydown_plan(state: ClientState | Mapping[str, Any], *, strategy: PaydownStrategy = "avalanche", surplus_per_month: Decimal | str | None = None) -> DebtPlan:
    """The debts ordered by rate (avalanche) or by balance (snowball), and the months and interest the order takes at the stated surplus."""

    if strategy not in ("avalanche", "snowball"):
        raise AdviceStrategyError("STRATEGY_UNKNOWN", f"strategy must be avalanche or snowball; got {strategy!r}")
    s = _state(state)
    debts, missing = _debts(s)
    entries = list(debts or ())
    order = _ordered(entries, strategy)
    total = _money(sum((item.balance for item in entries), Decimal("0")))
    surplus, surplus_note = _surplus_per_month(s, debts, surplus_per_month)
    notes = [f"order: {'highest rate first, each cleared debt frees its payment for the next' if strategy == 'avalanche' else 'smallest balance first, each cleared debt frees its payment for the next'}", surplus_note, "rates_as_stated: every rate and minimum payment is held as stated; no new borrowing and no rate change is projected"]
    months: int | None = None
    interest: Decimal | None = None
    paid: Decimal | None = None
    if not entries:
        months, interest, paid = 0, Decimal("0"), Decimal("0")
    elif all(item.complete for item in entries) and surplus is not None:
        months, interest, paid = _simulate(order, surplus)
        if months is None:
            notes.append(f"not_cleared: the debts are not cleared within {MAX_PAYDOWN_MONTHS} months at the stated payments")
    return seal(DebtPlan, {"state_digest": s.state_digest, "strategy": strategy, "order": [item.to_dict() for item in order], "total_balance": total, "months_to_clear": months, "interest_paid": interest, "total_paid": paid, "surplus_per_month": None if surplus is None else _money(surplus), "assumptions": notes, "missing": list(dict.fromkeys(missing))}, "plan_digest")


# --------------------------------------------------------------------------- #
# Emergency fund
# --------------------------------------------------------------------------- #


class EmergencyFundGap(StrictModel):
    schema_id: str = Field(default=EMERGENCY_FUND_SCHEMA, alias="schema")
    state_digest: Sha256Digest
    months: int = Field(ge=1, le=MAX_EMERGENCY_FUND_MONTHS)
    target: Decimal | None = None
    held: Decimal | None = None
    gap: Decimal | None = None
    surplus_per_month: Decimal | None = None
    months_to_close: int | None = None
    status: FundStatus
    assumptions: tuple[str, ...] = Field(default_factory=tuple)
    missing: tuple[str, ...] = Field(default_factory=tuple)
    gap_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("assumptions", "missing", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _tuples(value)

    @field_validator("target", "held", "gap", "surplus_per_month", mode="before")
    @classmethod
    def _amounts(cls, value: Any) -> Any:
        return _decimals(value)

    @model_validator(mode="after")
    def _seal(self, info: ValidationInfo) -> EmergencyFundGap:
        if not skip_digests(info) and self.gap_digest != sealed_digest(EmergencyFundGap, self, "gap_digest"):
            raise ValueError("gap_digest must commit the exact gap")
        return self


def emergency_fund_gap(state: ClientState | Mapping[str, Any], *, months: int = 3) -> EmergencyFundGap:
    """Target = months of expenses; held = savings; the gap and the months to close it at the stated surplus."""

    if isinstance(months, bool) or not isinstance(months, int) or not 1 <= months <= MAX_EMERGENCY_FUND_MONTHS:
        raise AdviceStrategyError("HORIZON_OUT_OF_RANGE", f"months must be an integer from 1 to {MAX_EMERGENCY_FUND_MONTHS}; got {months!r}")
    s = _state(state)
    expenses = _expenses(s)
    savings = _savings(s)
    missing = [item for item, value in (("expenses (annual)", expenses), ("savings (the balance held today)", savings)) if value is None]
    notes = [f"emergency_fund_months: {months} months of expenses ({'default' if months == STRATEGY_DEFAULTS['emergency_fund_months'] else 'supplied by the caller'})"]
    if missing:
        return seal(EmergencyFundGap, {"state_digest": s.state_digest, "months": months, "status": "unassessed", "assumptions": notes, "missing": missing}, "gap_digest")
    target = _money(expenses / Decimal(12) * Decimal(months))
    gap = max(_money(target - savings), Decimal("0"))
    debts, debt_missing = _debts(s)
    surplus, surplus_note = _surplus_per_month(s, debts, None)
    notes.append(surplus_note)
    if debts is None:
        notes.append("debt_payments_as_stated: no debts fact was given, so no minimum payments reduce the surplus")
    to_close: int | None = None
    if gap > 0 and surplus is not None and surplus > 0:
        to_close = int((gap / surplus).quantize(Decimal("1"), rounding=ROUND_CEILING))
    elif gap > 0 and surplus is not None:
        notes.append("months_to_close: none at a surplus of 0; the gap does not close at the stated figures")
    return seal(EmergencyFundGap, {"state_digest": s.state_digest, "months": months, "target": target, "held": _money(savings), "gap": gap, "surplus_per_month": None if surplus is None else _money(surplus), "months_to_close": to_close, "status": "met" if gap == 0 else "short", "assumptions": notes, "missing": []}, "gap_digest")


# --------------------------------------------------------------------------- #
# Serviceability
# --------------------------------------------------------------------------- #


class Serviceability(StrictModel):
    """One credit product's repayment at the buffered rate against the disclosed income and expenses; an arithmetic verdict, not an approval."""

    schema_id: str = Field(default=SERVICEABILITY_SCHEMA, alias="schema")
    state_digest: Sha256Digest
    product_ref: OpaqueRef
    family: str
    amount: Decimal | None = None
    contract_rate_percent: Decimal | None = None
    rate_item: str | None = None
    buffer_percent: Decimal
    assessed_rate_percent: Decimal | None = None
    buffer_source: ShortText
    rule_ref: str | None = None
    rule_confirmed: bool = False
    term_years: int = Field(ge=1, le=50)
    monthly_repayment: Decimal | None = None
    monthly_income: Decimal | None = None
    monthly_expenses: Decimal | None = None
    monthly_existing_debt_payments: Decimal | None = None
    monthly_surplus_after: Decimal | None = None
    repayment_to_income_percent: Decimal | None = None
    verdict: ServiceabilityVerdict
    reasons: tuple[str, ...] = Field(default_factory=tuple)
    assumptions: tuple[str, ...] = Field(default_factory=tuple)
    missing: tuple[str, ...] = Field(default_factory=tuple)
    as_of: str
    serviceability_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("reasons", "assumptions", "missing", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _tuples(value)

    @field_validator("amount", "contract_rate_percent", "buffer_percent", "assessed_rate_percent", "monthly_repayment", "monthly_income", "monthly_expenses", "monthly_existing_debt_payments", "monthly_surplus_after", "repayment_to_income_percent", mode="before")
    @classmethod
    def _amounts(cls, value: Any) -> Any:
        return _decimals(value)

    @model_validator(mode="after")
    def _seal(self, info: ValidationInfo) -> Serviceability:
        if not skip_digests(info) and self.serviceability_digest != sealed_digest(Serviceability, self, "serviceability_digest"):
            raise ValueError("serviceability_digest must commit the exact verdict")
        return self


def buffer_rule(jurisdiction: str, *, vertical_id: str | None = None) -> JurisdictionRule | None:
    """The RULES row the verdict cites for the jurisdiction (the module's own copy until finance_advice_rules carries it); with a vertical, only when the row names it."""

    ref = AU_SERVICEABILITY_BUFFER_REF if jurisdiction == "AU" else CA_STRESS_TEST_REF if jurisdiction == "CA" else None
    if ref is None:
        return None
    rule = next((rule for rule in RULES if rule.rule_ref == ref), None) or next((rule for rule in BUFFER_RULES if rule.rule_ref == ref), None)
    if rule is not None and vertical_id is not None and rule.verticals and vertical_id not in rule.verticals:
        return None
    return rule


def _matches(item: str, patterns: Sequence[str]) -> bool:
    lower = item.strip().lower()
    return any(lower == pattern or lower.startswith(pattern + " ") or lower.startswith(pattern + "/") or lower == pattern.replace(" ", "_") for pattern in patterns)


def _contract_rate(product: Product, *, is_card: bool) -> tuple[PricingFact | None, str]:
    rankable = [fact for fact in product.rankable_pricing if fact.unit_kind in _RATE_KINDS]
    if is_card:
        facts = [fact for fact in rankable if _matches(fact.item, _CARD_RATE_ITEMS)]
        if facts:
            fact = min(facts, key=lambda item: item.value)
            return fact, f"the purchase rate {fact.item} {fact.value}% is the contract rate (cited)"
        return None, "no supported purchase rate fact"
    comparisons = [fact for fact in rankable if _matches(fact.item, _COMPARISON_ITEMS)]
    if comparisons:
        fact = min(comparisons, key=lambda item: item.value)
        return fact, f"the comparison rate {fact.item} {fact.value}% stands in for the contract rate: the provider's all-in figure, fees inside (cited)"
    phases = rate_phases(product)
    if phases is not None and phases.revert is not None and phases.revert.rankable:
        return phases.revert, f"the stated revert rate {phases.revert.item} {phases.revert.value}% is assessed, not the {phases.kind} rate {phases.first.value}% that ends"
    nominal = [fact for fact in rankable if _matches(fact.item, _RATE_ITEMS) and "revert" not in fact.item.lower() and "comparison" not in fact.item.lower()]
    if nominal:
        fact = min(nominal, key=lambda item: item.value)
        return fact, f"the interest rate {fact.item} {fact.value}% is the contract rate; no comparison rate is stated (cited)"
    return None, "no supported interest rate fact"


def serviceability(state: ClientState | Mapping[str, Any], product: Product | Mapping[str, Any], *, family: str = "credit", buffer_rate_percent: Decimal | str | None = None, term_years: int | None = None, as_of: str) -> Serviceability:
    """Repayment at the contract rate plus the jurisdiction's buffer against the monthly income, expenses and existing minimum payments."""

    if family != "credit":
        raise AdviceStrategyError("FAMILY_UNSUPPORTED", f"serviceability is assessed for credit products; got {family!r}")
    s = _state(state)
    p = product if isinstance(product, Product) else Product.model_validate(dict(detached(product)))
    stamp = timestamp(as_of, field_name="as_of")
    is_card = "card" in p.taxonomy_class.lower() or "card" in p.product_name.lower()
    reasons: list[str] = []
    notes: list[str] = []
    missing: list[str] = []
    rate_fact, rate_basis = _contract_rate(p, is_card=is_card)
    contract = rate_fact.value if rate_fact is not None else None
    if rate_fact is None:
        missing.append("an interest rate fact the provider supports")
    else:
        notes.append(f"contract_rate: {rate_basis}")
    rule = buffer_rule(s.jurisdiction, vertical_id=s.vertical_id)
    rule_ref: str | None = None
    confirmed = False
    if buffer_rate_percent is not None:
        buffer = _number(buffer_rate_percent, "buffer_rate_percent")
        if buffer is None:
            raise AdviceStrategyError("FACT_NOT_NUMERIC", f"buffer_rate_percent must be a number; got {buffer_rate_percent!r}")
        assessed = None if contract is None else contract + buffer
        source = f"a buffer of {buffer} percentage points supplied by the caller; no rule cited"
    elif rule is None:
        buffer = Decimal("0")
        assessed = contract
        source = f"no buffer rule names {s.jurisdiction} {s.vertical_id}; the contract rate is assessed unbuffered"
        missing.append(f"a serviceability buffer rule for {s.jurisdiction} {s.vertical_id}")
        notes.append(f"buffer: no rules-table row names {s.vertical_id}; the rules-table buffer is not applied beyond the verticals its row names")
    else:
        rule_ref = rule.rule_ref
        confirmed = rule.confirmed
        points = Decimal(str(rule.parameters.get("buffer_percentage_points", "0")))
        floor = rule.parameters.get("floor_percent")
        if contract is None:
            buffer, assessed = points, None
        elif floor is not None and contract + points < Decimal(str(floor)):
            assessed = Decimal(str(floor))
            buffer = assessed - contract
        else:
            assessed = contract + points
            buffer = points
        confirmation = "confirmed by the operator" if confirmed else NOT_CONFIRMED
        source = (f"{buffer} percentage points from the rule {rule.rule_ref} ({rule.title}): the greater of the contract rate plus {points} points and {floor}%; {confirmation}" if floor is not None else f"{buffer} percentage points from the rule {rule.rule_ref} ({rule.title}); {confirmation}")
        notes.append(f"buffer: {rule.title} as published at {rule.source_url}, effective {rule.effective_from}; {confirmation}")
    term = term_years if term_years is not None else s.term_years
    if term is None:
        term = CARD_ASSESSMENT_TERM_YEARS if is_card else DEFAULT_LOAN_TERM_YEARS
        notes.append(f"term_years: {term} because the fact find states no term" + (" (a card limit is assessed as repaid over that period)" if is_card else ""))
    if isinstance(term, bool) or not isinstance(term, int) or not 1 <= term <= 50:
        raise AdviceStrategyError("HORIZON_OUT_OF_RANGE", f"term_years must be an integer from 1 to 50; got {term!r}")
    amount = s.amount
    if amount is None:
        missing.append("the client's amount")
    income, income_note, income_missing = _spendable_income(s)
    notes.append(income_note)
    expenses = _expenses(s)
    if income is None:
        missing.append(income_missing)
    if expenses is None:
        missing.append("expenses (annual)")
    debts, debt_missing = _debts(s)
    minimums = _minimums_per_month(debts)
    if debts is None:
        notes.append("existing_debts: no debts fact was given, so no existing minimum payments are deducted")
    elif debt_missing:
        missing.extend(item for item in debt_missing if "minimum_payment_per_year" in item)
        notes.append("existing_debts: only debts with a stated minimum payment are deducted")
    else:
        notes.append(f"existing_debts: {_money(minimums)} a month of stated minimum payments is deducted")
    repayment = None if amount is None or assessed is None else monthly_payment(amount, assessed, term)
    monthly_income = None if income is None else _money(income / Decimal(12))
    monthly_expenses = None if expenses is None else _money(expenses / Decimal(12))
    surplus_after = None
    ratio = None
    if repayment is not None and income is not None and expenses is not None:
        surplus_after = _money(income / Decimal(12) - expenses / Decimal(12) - minimums - repayment)
        ratio = (repayment * Decimal(12) / income * Decimal(100)).quantize(_CENTS, rounding=ROUND_HALF_UP) if income > 0 else None
        verdict: str = "serviceable" if surplus_after >= 0 else "not_serviceable"
        reasons.append(f"repayment of {repayment} a month on {amount} over {term} years at {assessed}% ({contract}% + {buffer} points) against income {monthly_income} and expenses {monthly_expenses} a month" + (f" and existing payments {_money(minimums)}" if minimums > 0 else "") + f" leaves {surplus_after} a month")
        if ratio is not None:
            reasons.append(f"repayments are {ratio}% of net take-home income; this is not a gross-income lender ratio")
        if not confirmed and rule_ref is not None:
            reasons.append(f"the buffer is the rule {rule_ref}, {NOT_CONFIRMED}")
    else:
        verdict = "unassessed"
        reasons.append("not assessed: " + ", ".join(dict.fromkeys(missing)) + " not stated")
    reasons.append("an arithmetic statement at the stated figures; the lender's own assessment and the adviser's approval decide")
    return seal(Serviceability, {"state_digest": s.state_digest, "product_ref": p.product_ref, "family": family, "amount": amount, "contract_rate_percent": contract, "rate_item": rate_fact.item if rate_fact else None, "buffer_percent": buffer, "assessed_rate_percent": assessed, "buffer_source": source[:300], "rule_ref": rule_ref, "rule_confirmed": confirmed, "term_years": term, "monthly_repayment": repayment, "monthly_income": monthly_income, "monthly_expenses": monthly_expenses, "monthly_existing_debt_payments": None if debts is None else _money(minimums), "monthly_surplus_after": surplus_after, "repayment_to_income_percent": ratio, "verdict": verdict, "reasons": reasons, "assumptions": notes, "missing": list(dict.fromkeys(missing)), "as_of": stamp}, "serviceability_digest")


# --------------------------------------------------------------------------- #
# Scenarios
# --------------------------------------------------------------------------- #


class ScenarioRow(StrictModel):
    label: ShortText
    overrides: dict[str, Any] = Field(default_factory=dict)
    projection_digest: Sha256Digest


class ScenarioDifference(StrictModel):
    year: int = Field(ge=1, le=MAX_HORIZON_YEARS)
    field: str
    values: dict[str, Decimal]

    @field_validator("values", mode="before")
    @classmethod
    def _amounts(cls, value: Any) -> Any:
        return {str(key): _decimals(item) for key, item in dict(value).items()} if isinstance(value, Mapping) else value


class ScenarioComparison(StrictModel):
    """The base projection against scenarios that change only the facts they name; every difference by year and field."""

    schema_id: str = Field(default=SCENARIO_SCHEMA, alias="schema")
    base_digest: Sha256Digest
    state_digest: Sha256Digest
    horizon_years: int = Field(ge=1, le=MAX_HORIZON_YEARS)
    scenarios: tuple[ScenarioRow, ...] = Field(default_factory=tuple)
    differences: tuple[ScenarioDifference, ...] = Field(default_factory=tuple)
    assumptions: tuple[str, ...] = Field(default_factory=tuple)
    prepared_at: str
    comparison_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("scenarios", "differences", "assumptions", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _tuples(value)

    @model_validator(mode="after")
    def _seal(self, info: ValidationInfo) -> ScenarioComparison:
        if not skip_digests(info) and self.comparison_digest != sealed_digest(ScenarioComparison, self, "comparison_digest"):
            raise ValueError("comparison_digest must commit the exact comparison")
        return self


def _with_facts(state: ClientState, facts: Mapping[str, Any], *, vertical_id: str | None = None) -> ClientState:
    """A hypothetical copy of the state with the named facts changed; re-sealed, never the client's own digest."""

    payload = state.to_dict()
    payload.pop("state_digest", None)
    payload["facts"] = {**dict(payload.get("facts") or {}), **{key: detached(value) for key, value in facts.items()}}
    if vertical_id is not None:
        payload["vertical_id"] = vertical_id
    return seal(ClientState, payload, "state_digest")


def scenario_compare(state: ClientState | Mapping[str, Any], scenarios: Sequence[Mapping[str, Any]], *, horizon_years: int = 5, as_of: str) -> ScenarioComparison:
    """Each scenario names a label and the facts or assumptions it overrides; anything else is refused."""

    s = _state(state)
    horizon = _horizon(horizon_years)
    base = cashflow_projection(s, horizon_years=horizon, as_of=as_of)
    projections: dict[str, CashflowProjection] = {"base": base}
    rows: list[ScenarioRow] = []
    for index, raw in enumerate(scenarios):
        item = dict(detached(raw))
        label = str(item.get("label") or "").strip()
        if not label:
            raise AdviceStrategyError("SCENARIO_LABEL_MISSING", f"scenarios[{index}] needs a label")
        if label in projections:
            raise AdviceStrategyError("SCENARIO_LABEL_DUPLICATE", f"scenario label {label!r} is used twice (base is reserved)")
        overrides = dict(item.get("overrides") or {})
        extra = sorted(str(key) for key in item if key not in ("label", "overrides"))
        unknown = sorted(str(key) for key in overrides if key not in _SCENARIO_FACTS and key not in STRATEGY_DEFAULTS)
        if extra or unknown:
            raise AdviceStrategyError("SCENARIO_UNKNOWN_FIELD", f"scenario {label!r} names fields the projection does not read: " + ", ".join(extra + unknown) + "; overrides may name " + ", ".join(sorted(_SCENARIO_FACTS)) + " or " + ", ".join(sorted(STRATEGY_DEFAULTS)))
        facts = {key: value for key, value in overrides.items() if key in _SCENARIO_FACTS}
        assumptions = {key: value for key, value in overrides.items() if key in STRATEGY_DEFAULTS}
        scenario_state = _with_facts(s, facts) if facts else s
        projection = cashflow_projection(scenario_state, horizon_years=horizon, assumptions=assumptions or None, as_of=as_of)
        projections[label] = projection
        rows.append(ScenarioRow(label=label, overrides=overrides, projection_digest=projection.projection_digest))
    differences: list[ScenarioDifference] = []
    for year in range(1, horizon + 1):
        for field in _ROW_FIELDS:
            values: dict[str, Decimal] = {}
            for label, projection in projections.items():
                row = next((row for row in projection.rows if row.year == year), None)
                value = getattr(row, field, None) if row is not None else None
                if value is not None:
                    values[label] = value
            if len(values) > 1 and len(set(values.values())) > 1:
                differences.append(ScenarioDifference(year=year, field=field, values=values))
    notes = ["scenarios: each scenario changes only the facts and assumptions it names; every other figure is the base state's", "figures_as_stated: a scenario is arithmetic on stated figures, not a forecast and not a recommendation"]
    return seal(ScenarioComparison, {"base_digest": base.projection_digest, "state_digest": s.state_digest, "horizon_years": horizon, "scenarios": [row.to_dict() for row in rows], "differences": [item.to_dict() for item in differences], "assumptions": notes, "prepared_at": base.prepared_at}, "comparison_digest")


# --------------------------------------------------------------------------- #
# Insurance sufficiency and the plan
# --------------------------------------------------------------------------- #


def _age_known(state: ClientState) -> bool:
    if _decimal(_fact(state, "age")) is not None:
        return True
    return any(ch.isdigit() for ch in (state.age_band or ""))


def insurance_sufficiency(state: ClientState | Mapping[str, Any]) -> tuple[NeedsAssessment, ...]:
    """assess_needs for every cover kind the facts support (life needs income and debts; income protection needs income and age; TPD and trauma need income)."""

    s = _state(state)
    income = _income(s)
    debts, _ = _debts(s)
    total_debts = None if debts is None else sum((item.balance for item in debts), Decimal("0"))
    extra: dict[str, Any] = {} if total_debts is None or not isinstance(_fact(s, "debts"), (list, tuple, Mapping)) else {"total_debts": str(_money(total_debts))}
    verticals = _INSURANCE_VERTICALS.get(s.jurisdiction, {})
    supported: list[str] = []
    own = needs_kind(s.vertical_id)
    if own in _INSURANCE_KINDS:
        supported.append(own)
    for kind in _INSURANCE_KINDS:
        if kind in supported or kind not in verticals or income is None:
            continue
        if kind == "life" and total_debts is None:
            continue
        if kind == "income_protection" and not _age_known(s):
            continue
        supported.append(kind)
    out: list[NeedsAssessment] = []
    for kind in supported:
        vertical_id = s.vertical_id if kind == own else verticals[kind]
        copy = _with_facts(s, extra, vertical_id=vertical_id) if extra or vertical_id != s.vertical_id else s
        out.append(assess_needs(copy))
    return tuple(out)


def _needs_from(item: Mapping[str, Any]) -> NeedsAssessment:
    """A NeedsAssessment back from its portable form (strict Decimal fields need the strings converted)."""

    raw = dict(item)
    for key in ("need", "existing_cover"):
        if raw.get(key) is not None:
            raw[key] = Decimal(str(raw[key]))
    raw["components"] = {str(key): Decimal(str(value)) for key, value in dict(raw.get("components") or {}).items()}
    return NeedsAssessment.model_validate(raw)


def _insurance_goal(assessment: NeedsAssessment) -> GoalVerdict:
    label = assessment.kind.replace("_", " ")
    kind = assessment.kind
    if assessment.need is None:
        return _goal("insurance_sufficiency", "unassessed", f"{label}: the need is not assessable; missing " + ", ".join(assessment.missing), "needs_defaults", kind=kind)
    if assessment.kind in ("life", "tpd", "trauma"):
        if assessment.need <= 0:
            return _goal("insurance_sufficiency", "met", f"{label}: existing cover of {assessment.existing_cover} {assessment.unit} meets the assessed need", "needs_defaults", kind=kind, year_met=0, figure=assessment.existing_cover, target=assessment.need)
        return _goal("insurance_sufficiency", "short", f"{label}: the assessed need is {assessment.need} {assessment.unit} after existing cover of {assessment.existing_cover}", "needs_defaults", kind=kind, figure=assessment.existing_cover, target=assessment.need)
    return _goal("insurance_sufficiency", "short" if assessment.existing_cover < assessment.need else "met", f"{label}: the assessed monthly benefit is {assessment.need} {assessment.unit}; existing cover {assessment.existing_cover}", "needs_defaults", kind=kind, year_met=0 if assessment.existing_cover >= assessment.need else None, figure=assessment.existing_cover, target=assessment.need)


class OrderedGoal(StrictModel):
    goal: GoalKind
    kind: str | None = None
    slot: str
    reason: ShortText
    status: GoalStatus
    basis: ShortText


class StrategyPlan(StrictModel):
    """One sealed strategy for one client state: the cash flow, the debt plan, the emergency fund, insurance sufficiency, the serviceability verdicts offered, and the goals in the order of conversation."""

    schema_id: str = Field(default=STRATEGY_SCHEMA, alias="schema")
    client_ref: OpaqueRef
    personal_data_sha256: Sha256Digest
    state_digest: Sha256Digest
    jurisdiction: str
    vertical_id: str
    horizon_years: int = Field(ge=1, le=MAX_HORIZON_YEARS)
    cashflow: CashflowProjection
    tax: TaxEstimate | None = None
    retirement: RetirementProjection | None = None
    debt_plan: DebtPlan | None = None
    emergency_fund: EmergencyFundGap
    insurance: tuple[dict[str, Any], ...] = Field(default_factory=tuple)
    serviceability: tuple[Serviceability, ...] = Field(default_factory=tuple)
    goals: tuple[GoalVerdict, ...] = Field(default_factory=tuple)
    goals_in_order: tuple[OrderedGoal, ...] = Field(default_factory=tuple)
    assumptions: tuple[str, ...] = Field(default_factory=tuple)
    missing: tuple[str, ...] = Field(default_factory=tuple)
    disclosures: tuple[str, ...] = Field(default_factory=tuple)
    prepared_at: str
    strategy_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("insurance", "serviceability", "goals", "goals_in_order", "assumptions", "missing", "disclosures", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _tuples(value)

    @model_validator(mode="after")
    def _seal(self, info: ValidationInfo) -> StrategyPlan:
        for evidence in (self.tax, self.retirement):
            if evidence is not None and (evidence.state_digest != self.state_digest or evidence.jurisdiction != self.jurisdiction):
                raise ValueError("tax and retirement evidence must belong to the strategy's exact state and jurisdiction")
        if not skip_digests(info) and self.strategy_digest != sealed_digest(StrategyPlan, self, "strategy_digest"):
            raise ValueError("strategy_digest must commit the exact plan")
        return self

    def needs(self) -> tuple[NeedsAssessment, ...]:
        return tuple(_needs_from(item) for item in self.insurance)


_GOAL_SLOTS: dict[str, str] = {"emergency_fund": "emergency_fund", "debt_free": "high_cost_debt", "insurance_sufficiency": "life_and_tpd"}
_INSURANCE_SLOTS: dict[str, str] = {"income_protection": "income_protection", "life": "life_and_tpd", "tpd": "life_and_tpd", "trauma": "life_and_tpd"}
_ORDER_INDEX = {key: index for index, (key, _, _) in enumerate(ORDER)}
_ORDER_REASON = {key: why for key, why, _ in ORDER}


def strategy_plan(client_ref: str, state: ClientState | Mapping[str, Any], *, prepared_at: str, horizon_years: int = 5, assumptions: Mapping[str, Any] | None = None, serviceability_verdicts: Sequence[Serviceability | Mapping[str, Any]] = ()) -> StrategyPlan:
    """Compose the strategy for one state; serviceability verdicts are read by digest and must belong to this state."""

    s = _state(state)
    stamp = timestamp(prepared_at, field_name="prepared_at")
    values, _ = _assumptions(assumptions)
    cashflow = cashflow_projection(s, horizon_years=horizon_years, assumptions=assumptions, as_of=stamp)
    debts, _ = _debts(s)
    plan = debt_paydown_plan(s) if debts else None
    fund = emergency_fund_gap(s, months=values["emergency_fund_months"])
    insurance = insurance_sufficiency(s)
    tax = income_tax_estimate(s, as_of=stamp) if "taxable_income" in s.facts or "tax_residency" in s.facts else None
    retirement = retirement_projection(s, as_of=stamp) if has_retirement_facts(s) else None
    verdicts: list[Serviceability] = []
    for raw in serviceability_verdicts:
        verdict = raw if isinstance(raw, Serviceability) else Serviceability.model_validate(dict(detached(raw)))
        if verdict.state_digest != s.state_digest:
            raise AdviceStrategyError("SERVICEABILITY_STATE_MISMATCH", f"the serviceability verdict for {verdict.product_ref} was assessed on another state")
        verdicts.append(verdict)
    goals = list(cashflow.goals) + [_insurance_goal(item) for item in insurance]
    ordered: list[OrderedGoal] = []
    seen: set[str] = set()
    for goal in goals:
        if goal.goal in seen and goal.goal != "insurance_sufficiency":
            continue
        seen.add(goal.goal)
        slot = _INSURANCE_SLOTS.get(goal.kind or "", _GOAL_SLOTS[goal.goal]) if goal.goal == "insurance_sufficiency" else _GOAL_SLOTS[goal.goal]
        ordered.append(OrderedGoal(goal=goal.goal, kind=goal.kind, slot=slot, reason=_ORDER_REASON.get(slot, "no ordering rule"), status=goal.status, basis=goal.basis))
    ordered.sort(key=lambda item: (_ORDER_INDEX.get(item.slot, len(ORDER)), item.goal, item.kind or ""))
    notes = list(cashflow.assumptions) + (list(plan.assumptions) if plan else []) + list(fund.assumptions) + [f"needs_defaults ({item.kind}): {line}" for item in insurance for line in item.assumptions] + [line for verdict in verdicts for line in verdict.assumptions]
    missing = list(cashflow.missing) + (list(plan.missing) if plan else []) + list(fund.missing) + [f"{item.kind}: {line}" for item in insurance for line in item.missing] + [line for verdict in verdicts for line in verdict.missing]
    if tax:
        missing.extend(tax.missing)
    if retirement:
        notes.extend(retirement.assumptions)
        missing.extend(retirement.missing)
    disclosures = [
        "Every figure is the client's own as stated or a provider's cited fact; every default is written in the assumptions; nothing is forecast.",
        "The goals and their order are the suggested sequence of conversation with its reason; they are not a recommendation.",
        "A serviceability verdict is an arithmetic statement at the buffered rate; the lender's own assessment and the licensed adviser's approval decide.",
    ]
    if any(not verdict.rule_confirmed and verdict.rule_ref for verdict in verdicts):
        disclosures.append(f"The serviceability buffer is a rules-table figure {NOT_CONFIRMED}.")
    disclosures.extend(tax.disclosures if tax else ())
    disclosures.extend(retirement.disclosures if retirement else ())
    return seal(StrategyPlan, {"client_ref": client_ref, "personal_data_sha256": s.personal_data_sha256, "state_digest": s.state_digest, "jurisdiction": s.jurisdiction, "vertical_id": s.vertical_id, "horizon_years": cashflow.horizon_years, "cashflow": cashflow.to_dict(), "tax": tax.to_dict() if tax else None, "retirement": retirement.to_dict() if retirement else None, "debt_plan": plan.to_dict() if plan else None, "emergency_fund": fund.to_dict(), "insurance": [item.to_dict() for item in insurance], "serviceability": [item.to_dict() for item in verdicts], "goals": [item.to_dict() for item in goals], "goals_in_order": [item.to_dict() for item in ordered], "assumptions": list(dict.fromkeys(notes)), "missing": list(dict.fromkeys(missing)), "disclosures": disclosures, "prepared_at": stamp}, "strategy_digest")


STRATEGY_MANIFEST: dict[str, Any] = {
    "kind": "lightbulb.finance_advice_strategy.v1",
    "schemas": {"plan": STRATEGY_SCHEMA, "cashflow": CASHFLOW_SCHEMA, "debt_plan": DEBT_PLAN_SCHEMA, "emergency_fund": EMERGENCY_FUND_SCHEMA, "serviceability": SERVICEABILITY_SCHEMA, "scenarios": SCENARIO_SCHEMA},
    "defaults": {key: str(value) for key, value in STRATEGY_DEFAULTS.items()},
    "facts_read": ["income", "expenses", "debts (kind, balance, rate_percent, minimum_payment_per_year)", "savings", "amount", "term_years", "age or age_band", "dependants", "existing_cover"],
    "forbidden_debt_keys": sorted(FORBIDDEN_DEBT_KEYS),
    "forbidden_personal_keys_on_debts": sorted(_PERSONAL_DEBT_KEYS),
    "buffer_rules": [{"rule_ref": rule.rule_ref, "jurisdiction": rule.jurisdiction, "source_url": rule.source_url, "effective_from": rule.effective_from, "confirmed": rule.confirmed, "parameters": rule.parameters} for rule in BUFFER_RULES],
    "refusals": ["HORIZON_OUT_OF_RANGE", "FACT_NOT_NUMERIC", "NEGATIVE_FIGURE", "DEBT_CARRIES_IDENTIFIER", "ASSUMPTION_UNKNOWN", "STRATEGY_UNKNOWN", "FAMILY_UNSUPPORTED", "SCENARIO_LABEL_MISSING", "SCENARIO_LABEL_DUPLICATE", "SCENARIO_UNKNOWN_FIELD", "SERVICEABILITY_STATE_MISMATCH"],
    "hard_rules": [
        "every figure is a disclosed decision fact or a cited provider fact; a missing fact is listed and never estimated",
        "every default is written into the assumptions with its origin; growth, inflation and returns default to zero and any other figure is named as the caller's",
        "the serviceability buffer is a rules-table row carried unconfirmed and named 'not yet confirmed by the operator' in every verdict until the operator confirms it",
        "a debt is a kind, a balance, a rate and a payment; account identifiers and personal-data keys on a debt entry are refused",
        "the buffer rule is cited only for the verticals its row names; other credit is assessed unbuffered with the gap listed as missing",
        "deterministic Decimal arithmetic; no model, no randomness, no clock: every function takes as_of or prepared_at",
        "nothing here recommends or ranks a product; the verdicts are arithmetic statements the adviser reads and the compliance checklist cites",
    ],
    "not_claimed": "retirement adequacy, return and inflation forecasts, total tax liability, scheme eligibility or future contribution room; retirement and bracket tax are dated arithmetic illustrations only; a verdict is not a lender's assessment and not advice",
}

__all__ = [
    "AU_SERVICEABILITY_BUFFER_REF",
    "BUFFER_RULES",
    "CASHFLOW_SCHEMA",
    "CA_STRESS_TEST_REF",
    "DEBT_PLAN_SCHEMA",
    "EMERGENCY_FUND_SCHEMA",
    "FORBIDDEN_DEBT_KEYS",
    "MAX_EMERGENCY_FUND_MONTHS",
    "MAX_HORIZON_YEARS",
    "SCENARIO_SCHEMA",
    "SERVICEABILITY_SCHEMA",
    "STRATEGY_DEFAULTS",
    "STRATEGY_MANIFEST",
    "STRATEGY_SCHEMA",
    "AdviceStrategyError",
    "CashflowProjection",
    "CashflowYear",
    "DebtEntry",
    "DebtOrderEntry",
    "DebtPlan",
    "EmergencyFundGap",
    "GoalVerdict",
    "OrderedGoal",
    "ScenarioComparison",
    "ScenarioDifference",
    "ScenarioRow",
    "Serviceability",
    "StrategyPlan",
    "buffer_rule",
    "cashflow_projection",
    "debt_paydown_plan",
    "emergency_fund_gap",
    "goal_lines",
    "insurance_sufficiency",
    "scenario_compare",
    "serviceability",
    "strategy_plan",
]
