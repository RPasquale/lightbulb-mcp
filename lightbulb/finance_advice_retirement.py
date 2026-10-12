"""Bounded retirement and tax arithmetic on disclosed facts, with dated rule evidence.

Tax is a bracket illustration before reliefs, never a liability or a cash-flow deduction.
Retirement uses net contributions and net returns supplied by the adviser, carries every
assumption, and never establishes scheme access, pension entitlement or contribution room.
"""

from __future__ import annotations

from collections.abc import Mapping
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, Sha256Digest, decimal_value, detached, seal, sealed_digest, skip_digests, timestamp
from lightbulb.finance_advice_identity import AdviceIdentityModel as StrictModel
from lightbulb.finance_advice_catalog import load_vertical_registry
from lightbulb.finance_advice_engine import ClientState
from lightbulb.finance_advice_rules import RETIREMENT_TAX_RULES, JurisdictionRule

TAX_SCHEMA = "lightbulb.finance_advice_tax_estimate.v1"
RETIREMENT_SCHEMA = "lightbulb.finance_advice_retirement_projection.v1"
MAX_RETIREMENT_YEARS = 80
_ZERO = Decimal("0")
_CENTS = Decimal("0.01")


class AdviceRetirementError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _state(value: ClientState | Mapping[str, Any]) -> ClientState:
    return ClientState.model_validate(dict(detached(value)))


def _figure(facts: Mapping[str, Any], name: str, *, negative: bool = False) -> Decimal | None:
    value = facts.get(name)
    if value is None:
        return None
    try:
        return decimal_value(value, field_name=name, allow_negative=negative)
    except ValueError as exc:
        raise AdviceRetirementError("RETIREMENT_FACT_INVALID", f"{name} must be a finite bounded number") from exc


def _age(facts: Mapping[str, Any], name: str) -> int | None:
    value = _figure(facts, name)
    if value is None:
        return None
    if value != value.to_integral_value() or not 18 <= value <= 120:
        raise AdviceRetirementError("RETIREMENT_AGE_INVALID", f"{name} must be a whole age from 18 to 120")
    return int(value)


def _active_rules(jurisdiction: str, as_of: str) -> tuple[JurisdictionRule, ...]:
    day = as_of[:10]
    return tuple(row for row in RETIREMENT_TAX_RULES if row.jurisdiction == jurisdiction and row.effective_from <= day and (row.effective_to is None or day <= row.effective_to))


def _stamp(row: JurisdictionRule) -> str:
    return f"{row.title}: {row.statement} Source: {row.source_url}; effective {row.effective_from}" + (f" to {row.effective_to}" if row.effective_to else "") + f"; reviewed {row.reviewed_at}; " + ("operator confirmed" if row.confirmed else "not yet confirmed by the operator") + "."


class TaxBand(StrictModel):
    taxable_portion: Decimal
    rate_percent: Decimal
    tax: Decimal

    @field_validator("taxable_portion", "rate_percent", "tax", mode="before")
    @classmethod
    def _numbers(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="tax band")


class TaxEstimate(StrictModel):
    schema_id: Literal["lightbulb.finance_advice_tax_estimate.v1"] = TAX_SCHEMA
    state_digest: Sha256Digest
    jurisdiction: Literal["AU", "CA"]
    status: Literal["illustrated", "unassessed"]
    taxable_income: Decimal | None = None
    bracket_tax_before_reliefs: Decimal | None = None
    bands: tuple[TaxBand, ...] = ()
    rule: dict[str, Any] | None = None
    missing: tuple[str, ...] = ()
    disclosures: tuple[str, ...]
    as_of: str
    tax_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("taxable_income", "bracket_tax_before_reliefs", mode="before")
    @classmethod
    def _numbers(cls, value: Any) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name="tax figure")

    @model_validator(mode="after")
    def _seal(self, info: ValidationInfo) -> TaxEstimate:
        if self.status == "illustrated" and (self.missing or self.bracket_tax_before_reliefs is None or self.rule is None):
            raise ValueError("a tax illustration requires the taxable income, residency and dated rule")
        if not skip_digests(info) and self.tax_digest != sealed_digest(TaxEstimate, self, "tax_digest"):
            raise ValueError("tax_digest does not match the tax estimate")
        return self


def income_tax_estimate(state: ClientState | Mapping[str, Any], *, as_of: str) -> TaxEstimate:
    s = _state(state)
    stamp = timestamp(as_of, field_name="as_of")
    income = _figure(s.facts, "taxable_income")
    rule = next((row for row in _active_rules(s.jurisdiction, stamp) if ".income_tax." in row.rule_ref), None)
    missing = []
    if income is None:
        missing.append("taxable_income (do not substitute gross or household income)")
    if s.facts.get("tax_residency") != "resident_full_year":
        missing.append("tax_residency: resident_full_year (other tax residency cases are unassessed)")
    if rule is None:
        missing.append("a dated income tax table for the stated year")
    bands = []
    total = None
    if not missing and income is not None and rule is not None:
        total, lower = _ZERO, _ZERO
        for upper, raw_rate in rule.parameters["brackets"]:
            portion = max(_ZERO, min(income, Decimal(str(upper))) - lower) if upper is not None else max(_ZERO, income - lower)
            if portion:
                rate = Decimal(str(raw_rate))
                tax = (portion * rate / 100).quantize(_CENTS)
                bands.append(TaxBand(taxable_portion=portion, rate_percent=rate, tax=tax))
                total += tax
            if upper is not None:
                lower = Decimal(str(upper))
    disclosures = [
        "Bracket illustration only; no tax liability, refund, deduction entitlement or after-tax cash flow is calculated.",
        "AU excludes Medicare levy, surcharge, offsets, HELP and other liabilities; CA excludes all credits, provincial/territorial taxes, Quebec abatement, CPP/QPP and EI.",
        "Tax is not deducted from the client's stated income in the separate cash-flow projection.",
    ]
    if rule is not None:
        disclosures.append(_stamp(rule))
    return seal(TaxEstimate, {"state_digest": s.state_digest, "jurisdiction": s.jurisdiction, "status": "unassessed" if missing else "illustrated", "taxable_income": income, "bracket_tax_before_reliefs": total, "bands": bands, "rule": detached(rule) if rule else None, "missing": missing, "disclosures": disclosures, "as_of": stamp}, "tax_digest")


class ContributionCheck(StrictModel):
    scheme: Literal["super_concessional", "rrsp", "tfsa"]
    proposed: Decimal | None = None
    available_room: Decimal | None = None
    general_limit: Decimal | None = None
    status: Literal["within_disclosed_room", "exceeds_disclosed_room", "unassessed"]
    evidence_sha256: Sha256Digest | None = None
    rule_ref: str | None = None
    basis: str

    @field_validator("proposed", "available_room", "general_limit", mode="before")
    @classmethod
    def _numbers(cls, value: Any) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name="contribution")


def _contributions(state: ClientState, rules: tuple[JurisdictionRule, ...]) -> tuple[ContributionCheck, ...]:
    result = []
    schemes = ("super_concessional",) if state.jurisdiction == "AU" else ("rrsp", "tfsa")
    for scheme in schemes:
        if not any(str(key).startswith(scheme + "_") for key in state.facts):
            continue
        proposed = _figure(state.facts, scheme + "_proposed_contribution")
        room = _figure(state.facts, scheme + "_available_room")
        evidence = state.facts.get(scheme + "_room_evidence_sha256")
        row = next((r for r in rules if r.parameters.get("scheme") == scheme), None)
        assessed = proposed is not None and room is not None and evidence is not None and row is not None
        result.append(ContributionCheck(scheme=scheme, proposed=proposed, available_room=room, general_limit=Decimal(row.parameters["general_cap"]) if row else None, evidence_sha256=evidence, rule_ref=row.rule_ref if row else None, status=("within_disclosed_room" if proposed <= room else "exceeds_disclosed_room") if assessed else "unassessed", basis="Compare the proposed contribution with individually reconciled remaining room, supported by its document commitment; the general annual limit is never substituted for personal room. Deduction eligibility, access and future years require adviser confirmation."))
    return tuple(result)


class RetirementYear(StrictModel):
    year: int = Field(ge=1, le=MAX_RETIREMENT_YEARS)
    end_age: int = Field(ge=19, le=120)
    phase: Literal["accumulation", "drawdown"]
    opening_balance: Decimal
    net_growth: Decimal
    net_contribution: Decimal
    requested_draw: Decimal
    paid_draw: Decimal
    unfunded_draw: Decimal
    closing_balance: Decimal

    @field_validator("opening_balance", "net_growth", "net_contribution", "requested_draw", "paid_draw", "unfunded_draw", "closing_balance", mode="before")
    @classmethod
    def _numbers(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="retirement row", allow_negative=True)


class RetirementProjection(StrictModel):
    schema_id: Literal["lightbulb.finance_advice_retirement_projection.v1"] = RETIREMENT_SCHEMA
    state_digest: Sha256Digest
    jurisdiction: Literal["AU", "CA"]
    status: Literal["funded_in_illustration", "short_in_illustration", "unassessed"]
    rows: tuple[RetirementYear, ...] = Field(default_factory=tuple, max_length=MAX_RETIREMENT_YEARS)
    contribution_checks: tuple[ContributionCheck, ...] = ()
    rules: tuple[dict[str, Any], ...] = ()
    missing: tuple[str, ...] = ()
    assumptions: tuple[str, ...]
    disclosures: tuple[str, ...]
    as_of: str
    retirement_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _seal(self, info: ValidationInfo) -> RetirementProjection:
        expected = "unassessed" if not self.rows else ("short_in_illustration" if any(row.unfunded_draw for row in self.rows) else "funded_in_illustration")
        if self.status != expected:
            raise ValueError("retirement status must match the retained rows")
        if not skip_digests(info) and self.retirement_digest != sealed_digest(RetirementProjection, self, "retirement_digest"):
            raise ValueError("retirement_digest does not match the projection")
        return self


def retirement_projection(state: ClientState | Mapping[str, Any], *, as_of: str) -> RetirementProjection:
    s = _state(state)
    stamp = timestamp(as_of, field_name="as_of")
    rules = tuple(r for r in _active_rules(s.jurisdiction, stamp) if ".income_tax." not in r.rule_ref)
    figures = {key: _figure(s.facts, key) for key in ("retirement_balance", "retirement_net_contributions_per_year", "retirement_spending_per_year", "retirement_other_income_per_year")}
    ages = {key: _age(s.facts, key) for key in ("age", "retirement_age", "retirement_end_age")}
    missing = [key for key, value in {**figures, **ages}.items() if value is None]
    defaults = {"retirement_net_return_percent": _ZERO, "retirement_inflation_percent": _ZERO}
    rates = {}
    assumptions = []
    for key, default in defaults.items():
        value = _figure(s.facts, key, negative=True)
        rate = default if value is None else value
        if not -100 <= rate <= 100:
            raise AdviceRetirementError("RETIREMENT_RATE_INVALID", f"{key} must be between -100 and 100 percent")
        rates[key] = rate
        assumptions.append(f"{key}: {rate}% each year ({'default' if value is None else 'caller-supplied scenario, not a forecast'})")
    assumptions.extend([
        "Net contributions are explicitly stated after contribution tax; returns are net of fund fees and fund tax; neither is inferred from a general contribution limit.",
        "Full years from the stated age: opening balance grows first, fixed net contributions arrive at year end until retirement, then withdrawals occur at year end.",
        "Spending and other retirement income are stated in today's money and both grow by the scenario inflation rate; pension eligibility and indexation are not inferred.",
        "Drawdown is before personal withdrawal tax. Tax, access conditions, pension eligibility, life expectancy and future rule changes need separate adviser assessment.",
    ])
    rows = []
    if not missing:
        current, retire, end = ages["age"], ages["retirement_age"], ages["retirement_end_age"]
        if not current <= retire < end or end - current > MAX_RETIREMENT_YEARS:
            raise AdviceRetirementError("RETIREMENT_HORIZON_INVALID", "require age <= retirement_age < retirement_end_age and at most 80 years")
        balance = figures["retirement_balance"]
        for year in range(1, end - current + 1):
            accumulation = current + year - 1 < retire
            growth = (balance * rates["retirement_net_return_percent"] / 100).quantize(_CENTS)
            contribution = figures["retirement_net_contributions_per_year"] if accumulation else _ZERO
            requested_raw = _ZERO if accumulation else max(_ZERO, figures["retirement_spending_per_year"] - figures["retirement_other_income_per_year"]) * (1 + rates["retirement_inflation_percent"] / 100) ** (year - 1)
            if not requested_raw.is_finite() or requested_raw > Decimal("1000000000000"):
                raise AdviceRetirementError("RETIREMENT_FIGURE_OUT_OF_RANGE", "scenario exceeds the bounded financial figure range")
            requested = requested_raw.quantize(_CENTS)
            paid = min(balance + growth + contribution, requested)
            closing = balance + growth + contribution - paid
            if max(abs(closing), abs(requested)) > Decimal("1000000000000"):
                raise AdviceRetirementError("RETIREMENT_FIGURE_OUT_OF_RANGE", "scenario exceeds the bounded financial figure range")
            rows.append(RetirementYear(year=year, end_age=current + year, phase="accumulation" if accumulation else "drawdown", opening_balance=balance, net_growth=growth, net_contribution=contribution, requested_draw=requested, paid_draw=paid, unfunded_draw=requested - paid, closing_balance=closing))
            balance = closing
    checks = _contributions(s, rules)
    missing.extend(f"{item.scheme}: reconciled individual room, proposed contribution, evidence commitment and a current dated rule" for item in checks if item.status == "unassessed")
    disclosures = ["This is a bounded arithmetic illustration, not retirement adequacy, contribution eligibility or a recommendation.", *(_stamp(rule) for rule in rules)]
    return seal(RetirementProjection, {"state_digest": s.state_digest, "jurisdiction": s.jurisdiction, "status": "unassessed" if not rows else ("short_in_illustration" if any(row.unfunded_draw for row in rows) else "funded_in_illustration"), "rows": rows, "contribution_checks": checks, "rules": [detached(rule) for rule in rules], "missing": missing, "assumptions": assumptions, "disclosures": disclosures, "as_of": stamp}, "retirement_digest")


def has_retirement_facts(state: ClientState) -> bool:
    # Retirement age alone also appears in income-protection fact finding.
    sector = load_vertical_registry().vertical(state.vertical_id).sector.lower()
    return "retirement" in sector or "superannuation" in sector or any(str(key).startswith(("retirement_", "super_concessional_", "rrsp_", "tfsa_")) and key != "retirement_age" for key in state.facts)


RETIREMENT_MANIFEST = {"schemas": {"tax": TAX_SCHEMA, "retirement": RETIREMENT_SCHEMA}, "authority": "SDK preview arithmetic; Spring owns scoped custody and human approval", "rules": "Dated primary-source tables; unsupported years remain unassessed; operator confirmation remains explicit", "not_claimed": "tax liability, contribution or pension eligibility, permission to withdraw, retirement adequacy or forecasts"}

__all__ = ["AdviceRetirementError", "ContributionCheck", "RETIREMENT_MANIFEST", "RETIREMENT_SCHEMA", "TAX_SCHEMA", "RetirementProjection", "RetirementYear", "TaxBand", "TaxEstimate", "has_retirement_facts", "income_tax_estimate", "retirement_projection"]
