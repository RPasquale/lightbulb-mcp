"""Holistic cases: one client, several verticals, the interactions between them and one adviser decision over the set.

A client rarely has one need. The home loan, the life cover that protects it, the income
protection that keeps the loan paid, the emergency deposit and the health cover interact: the
loan amount is a debt the life need must clear; the deposit balance is the savings that bridge
the income protection waiting period; the high loan-to-value ratio costs lenders mortgage
insurance; facts the client gave on one line must agree with the same facts on another. This
module composes the per-vertical work (states, shortlists, recommendations, needs, switching,
rule adjustments) into one sealed plan: the lines in a suggested order of conversation with the
reason for the order, every cross-line interaction stated with what it asks the adviser to do,
the annual cost where it is known, and one bundle the adviser approves as a set (or a named
subset). Nothing here recommends a product; it is the strategy the adviser's recommendations
sit inside, written down so the record can carry it.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, Sha256Digest, StrictModel, detached, seal, sealed_digest, skip_digests, stable_digest, timestamp
from lightbulb.finance_advice_engine import ClientState
from lightbulb.finance_advice_needs import needs_kind
from lightbulb.finance_advice_rules import apply_rules

HOLISTIC_SCHEMA = "lightbulb.finance_advice_holistic_plan.v1"
BUNDLE_SCHEMA = "lightbulb.finance_advice_bundle_approval_request.v1"
Family = Literal["credit", "deposits", "insurance", "investments", "unknown"]
LineStatus = Literal["fact_find", "shortlisted", "recommended", "approved", "presented", "implemented"]
InteractionKind = Literal["debts_omit_loan", "savings_from_deposits", "facts_disagree", "rule_costs", "cover_without_income_protection"]

# the suggested order of conversation, with the reason; a table, not advice
ORDER: tuple[tuple[str, str, str], ...] = (
    ("income_protection", "Protect the income first: every other line is paid from it.", "insurance:income_protection"),
    ("high_cost_debt", "Clear the high-cost revolving debt before adding anything that costs money.", "credit:revolving"),
    ("emergency_fund", "An emergency deposit bridges waiting periods and keeps the loan paid through a gap.", "deposits"),
    ("home_loan", "The home loan is the largest debt and the largest cost; it sets the life and TPD need.", "credit:secured"),
    ("life_and_tpd", "Life, TPD and trauma cover clear the debt and replace the income the loan relied on.", "insurance:life"),
    ("health", "Health cover and its rebate, loading and surcharge follow the income and the family.", "insurance:health"),
    ("general_insurance", "The home, its contents, the car, the trip and the pet.", "insurance:general"),
    ("investments", "Investments come after protection and debt.", "investments"),
)
_ORDER_INDEX = {key: index for index, (key, _, _) in enumerate(ORDER)}
_HOME_LOAN_VERTICALS = frozenset({"AU-05", "CA-05"})
_REVOLVING_VERTICALS = frozenset({"AU-04", "CA-04"})
_FAMILY_BY_VERTICAL: dict[str, str] = {"AU-01": "deposits", "AU-02": "deposits", "AU-03": "deposits", "AU-04": "credit", "AU-05": "credit", "CA-01": "deposits", "CA-02": "deposits", "CA-03": "deposits", "CA-04": "credit", "CA-05": "credit"}
_INSURANCE_KINDS = frozenset({"life", "income_protection", "tpd", "trauma", "health"})
_SHARED_FACTS: tuple[str, ...] = ("income", "dependants", "age_band", "region", "residency", "smoker", "income_band")
_CENTS = Decimal("0.01")


def _decimal(value: Any) -> Decimal | None:
    if value is None or value == "":
        return None
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError):
        return None


def _fact(state: ClientState, key: str) -> Any:
    if hasattr(state, key) and getattr(state, key) is not None:
        return getattr(state, key)
    return (state.facts or {}).get(key)


def _family_for(vertical_id: str, family: str | None) -> str:
    if family:
        return family
    if vertical_id in _FAMILY_BY_VERTICAL:
        return _FAMILY_BY_VERTICAL[vertical_id]
    kind = needs_kind(vertical_id)
    if kind in _INSURANCE_KINDS:
        return "insurance"
    number = vertical_id.split("-")[-1]
    return "insurance" if number.isdigit() and int(number) >= 31 else "unknown"


def _slot(vertical_id: str, family: str) -> str:
    kind = needs_kind(vertical_id) if family == "insurance" else None
    if family == "insurance":
        if kind == "income_protection":
            return "income_protection"
        if kind in ("life", "tpd", "trauma"):
            return "life_and_tpd"
        if kind == "health":
            return "health"
        return "general_insurance"
    if family == "credit":
        return "home_loan" if vertical_id in _HOME_LOAN_VERTICALS else "high_cost_debt"
    if family == "deposits":
        return "emergency_fund"
    if family == "investments":
        return "investments"
    return "general_insurance"


class HolisticLine(StrictModel):
    """One vertical's contribution to the client's plan, by digest."""

    vertical_id: str = Field(min_length=1)
    family: Family
    slot: str
    status: LineStatus = "fact_find"
    state_digest: Sha256Digest
    shortlist_digest: Sha256Digest | None = None
    recommendation_digest: Sha256Digest | None = None
    recommended_product_ref: str | None = None
    annual_cost: Decimal | None = None
    currency: str | None = None
    need: Decimal | None = None
    need_unit: str | None = None
    benefit_fit: str | None = None
    switch_verdict: str | None = None
    rule_adjustment_per_year: Decimal | None = None
    facts: dict[str, Any] = Field(default_factory=dict)

    @field_validator("annual_cost", "need", "rule_adjustment_per_year", mode="before")
    @classmethod
    def _amounts(cls, value: Any) -> Any:
        return _decimal(value) if value is not None else None


class Interaction(StrictModel):
    kind: InteractionKind
    verticals: tuple[str, ...]
    statement: str
    asks: str
    figures: dict[str, str] = Field(default_factory=dict)

    @field_validator("verticals", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value


class HolisticPlan(StrictModel):
    """The client's lines in order, the interactions between them, and the bundle the adviser decides on."""

    schema_id: Literal["lightbulb.finance_advice_holistic_plan.v1"] = HOLISTIC_SCHEMA
    client_ref: str
    jurisdiction: str
    personal_data_sha256: Sha256Digest
    lines: tuple[HolisticLine, ...]
    order_reasons: tuple[str, ...] = Field(default_factory=tuple)
    interactions: tuple[Interaction, ...] = Field(default_factory=tuple)
    annual_cost_known: Decimal | None = None
    annual_cost_lines: int = 0
    currency: str | None = None
    ready_for_bundle: bool = False
    bundle_digest: Sha256Digest | None = None
    disclosures: tuple[str, ...] = Field(default_factory=tuple)
    prepared_at: str
    holistic_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("lines", "order_reasons", "interactions", "disclosures", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("annual_cost_known", mode="before")
    @classmethod
    def _amount(cls, value: Any) -> Any:
        return _decimal(value) if value is not None else None

    @model_validator(mode="after")
    def _seal(self, info: ValidationInfo) -> HolisticPlan:
        if not skip_digests(info) and self.holistic_digest != sealed_digest(HolisticPlan, self, "holistic_digest"):
            raise ValueError("holistic_digest does not match the plan")
        return self

    def line(self, vertical_id: str) -> HolisticLine | None:
        return next((item for item in self.lines if item.vertical_id == vertical_id), None)


def holistic_line(state: ClientState | Mapping[str, Any], *, family: str | None = None, status: str = "fact_find", shortlist: Mapping[str, Any] | Any = None, recommendation: Mapping[str, Any] | Any = None, needs: Mapping[str, Any] | Any = None, benefit_fit: Mapping[str, Any] | Any = None, switching: Mapping[str, Any] | Any = None, annual_cost: Decimal | str | None = None, currency: str | None = None, horizon_years: int = 1) -> HolisticLine:
    """One line from the per-vertical objects; digests are read, objects are not re-derived."""
    s = state if isinstance(state, ClientState) else ClientState.model_validate(dict(state))
    fam = _family_for(s.vertical_id, family)
    sl = dict(detached(shortlist)) if shortlist is not None else {}
    rec = dict(detached(recommendation)) if recommendation is not None else {}
    nd = dict(detached(needs)) if needs is not None else {}
    fit = dict(detached(benefit_fit)) if benefit_fit is not None else {}
    sw = dict(detached(switching)) if switching is not None else {}
    adjustments, _ = apply_rules(s, None, vertical_id=s.vertical_id, horizon_years=horizon_years)
    per_year = sum((_decimal(getattr(item, "per_year", None) if not isinstance(item, Mapping) else item.get("per_year")) or Decimal("0") for item in adjustments), Decimal("0")) if adjustments else None
    facts = {key: _fact(s, key) for key in (*_SHARED_FACTS, "amount", "lvr_percent", "debts", "savings_months", "existing_cover") if _fact(s, key) is not None}
    return HolisticLine(vertical_id=s.vertical_id, family=fam, slot=_slot(s.vertical_id, fam), status=status, state_digest=s.state_digest, shortlist_digest=sl.get("shortlist_digest"), recommendation_digest=rec.get("recommendation_digest"), recommended_product_ref=rec.get("primary_product_ref"), annual_cost=annual_cost, currency=currency, need=nd.get("need"), need_unit=nd.get("unit"), benefit_fit=fit.get("fit"), switch_verdict=sw.get("verdict"), rule_adjustment_per_year=per_year, facts=facts)


def _interactions(lines: Sequence[HolisticLine], states: Mapping[str, ClientState]) -> list[Interaction]:
    out: list[Interaction] = []
    loans = [item for item in lines if item.family == "credit" and item.vertical_id in _HOME_LOAN_VERTICALS and _decimal(item.facts.get("amount"))]
    deposits = [item for item in lines if item.family == "deposits" and _decimal(item.facts.get("amount"))]
    protections = [item for item in lines if item.family == "insurance" and needs_kind(item.vertical_id) in ("life", "tpd", "trauma")]
    income_lines = [item for item in lines if item.family == "insurance" and needs_kind(item.vertical_id) == "income_protection"]
    for loan in loans:
        amount = _decimal(loan.facts.get("amount")) or Decimal("0")
        for cover in protections:
            debts = _decimal(cover.facts.get("debts"))
            if debts is None or debts < amount:
                out.append(Interaction(kind="debts_omit_loan", verticals=[loan.vertical_id, cover.vertical_id], statement=f"the {cover.vertical_id} need counts debts of {debts if debts is not None else 'nothing'} while the {loan.vertical_id} loan is {amount}", asks="confirm the debts fact on the cover line includes the loan, then reassess the need", figures={"loan_amount": str(amount), "debts_on_cover_line": str(debts) if debts is not None else "unstated"}))
        if loans and not income_lines:
            out.append(Interaction(kind="cover_without_income_protection", verticals=[loan.vertical_id], statement=f"the {loan.vertical_id} loan of {amount} is on the plan and no income protection line is", asks="ask whether the client's income is protected; the loan is paid from it", figures={"loan_amount": str(amount)}))
            break
    for cover in income_lines:
        if cover.facts.get("savings_months") is not None:
            continue
        income = _decimal(cover.facts.get("income"))
        for deposit in deposits:
            balance = _decimal(deposit.facts.get("amount")) or Decimal("0")
            if income and income > 0:
                months = (balance / (income / Decimal("12"))).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)
                out.append(Interaction(kind="savings_from_deposits", verticals=[deposit.vertical_id, cover.vertical_id], statement=f"the {deposit.vertical_id} balance of {balance} is {months} months of income; the {cover.vertical_id} line has no savings_months fact", asks="confirm savings_months on the income protection line from the deposit balance before choosing the waiting period", figures={"deposit_balance": str(balance), "months_of_income": str(months)}))
    for key in _SHARED_FACTS:
        seen: dict[str, list[str]] = {}
        for item in lines:
            value = item.facts.get(key)
            if value is not None:
                seen.setdefault(str(value), []).append(item.vertical_id)
        if len(seen) > 1:
            out.append(Interaction(kind="facts_disagree", verticals=[v for group in seen.values() for v in group], statement=f"{key} differs between lines: " + "; ".join(f"{value} on {', '.join(group)}" for value, group in seen.items()), asks=f"confirm one {key} with the client and correct the lines that differ", figures={value: ", ".join(group) for value, group in seen.items()}))
    for item in lines:
        state = states.get(item.vertical_id)
        if state is None:
            continue
        adjustments, disclosures = apply_rules(state, None, vertical_id=item.vertical_id, horizon_years=1)
        if adjustments:
            out.append(Interaction(kind="rule_costs", verticals=[item.vertical_id], statement="; ".join(disclosures) if disclosures else f"the jurisdiction's rules adjust the {item.vertical_id} line", asks="carry the rule's figure into the line's projection and confirm it with the operator", figures={str(getattr(adj, "rule_ref", "rule")): str(getattr(adj, "amount", "")) for adj in adjustments}))
    return out


def holistic_plan(client_ref: str, states: Sequence[ClientState | Mapping[str, Any]], lines: Sequence[HolisticLine | Mapping[str, Any]], *, prepared_at: str) -> HolisticPlan:
    """Compose the client's lines into one plan; every state must belong to the same client and jurisdiction."""
    parsed = [s if isinstance(s, ClientState) else ClientState.model_validate(dict(s)) for s in states]
    if not parsed:
        raise ValueError("a holistic plan needs at least one client state")
    commitments = {s.personal_data_sha256 for s in parsed}
    if len(commitments) != 1:
        raise ValueError("every state in a holistic plan must carry the same personal_data_sha256 commitment")
    jurisdictions = {s.jurisdiction for s in parsed}
    if len(jurisdictions) != 1:
        raise ValueError("a holistic plan spans one jurisdiction")
    items = [item if isinstance(item, HolisticLine) else HolisticLine.model_validate(dict(item)) for item in lines]
    by_vertical = {s.vertical_id: s for s in parsed}
    for item in items:
        state = by_vertical.get(item.vertical_id)
        if state is None or state.state_digest != item.state_digest:
            raise ValueError(f"line {item.vertical_id} does not match a state in the plan")
    ordered = sorted(items, key=lambda item: (_ORDER_INDEX.get(item.slot, len(ORDER)), item.vertical_id))
    reasons = [f"{index + 1}. {item.vertical_id} ({item.slot}): {next((why for key, why, _ in ORDER if key == item.slot), 'no ordering rule')}" for index, item in enumerate(ordered)]
    interactions = _interactions(ordered, by_vertical)
    costs = [item.annual_cost for item in ordered if item.annual_cost is not None]
    currencies = {item.currency for item in ordered if item.currency}
    ready = bool(ordered) and all(item.recommendation_digest for item in ordered)
    bundle = stable_digest({"recommendations": {item.vertical_id: item.recommendation_digest for item in ordered}}) if ready else None
    disclosures = ["The order is a suggested sequence of conversation with its reason; it is not a recommendation.", "Every interaction asks the adviser to confirm a fact or carry a figure; none changes a line by itself.", f"Annual cost is known for {len(costs)} of {len(ordered)} lines; the total omits the rest."]
    if len(currencies) > 1:
        disclosures.append("Lines carry different currencies; the total is not summed.")
    total = sum(costs, Decimal("0")).quantize(_CENTS) if costs and len(currencies) <= 1 else None
    return seal(HolisticPlan, {"client_ref": client_ref, "jurisdiction": parsed[0].jurisdiction, "personal_data_sha256": parsed[0].personal_data_sha256, "lines": [item.to_dict() for item in ordered], "order_reasons": reasons, "interactions": [item.to_dict() for item in interactions], "annual_cost_known": total, "annual_cost_lines": len(costs), "currency": next(iter(currencies)) if len(currencies) == 1 else None, "ready_for_bundle": ready, "bundle_digest": bundle, "disclosures": disclosures, "prepared_at": timestamp(prepared_at, field_name="prepared_at")}, "holistic_digest")


def bundle_approval_request(plan: HolisticPlan | Mapping[str, Any], *, requested_by_ref: str, requested_at: str) -> dict[str, Any]:
    """One adviser decision over every recommendation in the plan, each named by digest."""
    p = plan if isinstance(plan, HolisticPlan) else HolisticPlan.model_validate(dict(plan))
    if not p.ready_for_bundle or p.bundle_digest is None:
        missing = [item.vertical_id for item in p.lines if not item.recommendation_digest]
        raise ValueError("the bundle is not ready: no recommendation yet for " + ", ".join(missing))
    return {"schema": BUNDLE_SCHEMA, "holistic_digest": p.holistic_digest, "bundle_digest": p.bundle_digest, "client_ref": p.client_ref, "recommendation_digests": {item.vertical_id: item.recommendation_digest for item in p.lines}, "interactions_open": len(p.interactions), "requested_by_ref": requested_by_ref, "requested_at": timestamp(requested_at, field_name="requested_at"), "decision": "the adviser approves the set, or names the recommendation digests approved; each named digest resumes its own case with this approval"}


def bundle_approval_covers(plan: HolisticPlan | Mapping[str, Any], approval: Mapping[str, Any]) -> tuple[str, ...]:
    """Which lines an approval reaches: the whole bundle by its digest, or the recommendation digests it names."""
    p = plan if isinstance(plan, HolisticPlan) else HolisticPlan.model_validate(dict(plan))
    if approval.get("bundle_digest") == p.bundle_digest and p.bundle_digest is not None:
        return tuple(item.vertical_id for item in p.lines)
    named = list(approval.get("recommendation_digests") or [])
    known = {item.recommendation_digest: item.vertical_id for item in p.lines if item.recommendation_digest}
    unknown = [digest for digest in named if digest not in known]
    if unknown:
        raise ValueError("the approval names recommendations that are not in this plan: " + ", ".join(str(item)[:16] for item in unknown))
    return tuple(known[digest] for digest in named)


HOLISTIC_MANIFEST: dict[str, Any] = {
    "schemas": {"plan": HOLISTIC_SCHEMA, "bundle_request": BUNDLE_SCHEMA},
    "order": [{"slot": key, "why": why, "matches": matches} for key, why, matches in ORDER],
    "interactions": ["debts_omit_loan", "savings_from_deposits", "facts_disagree", "rule_costs", "cover_without_income_protection"],
    "bundle": "one adviser decision over every recommendation digest; a subset is approved by naming digests; each resumes its own case",
    "not_claimed": "the order and the interactions are a strategy written down for the adviser; nothing here recommends a product",
}

__all__ = ["BUNDLE_SCHEMA", "HOLISTIC_MANIFEST", "HOLISTIC_SCHEMA", "ORDER", "HolisticLine", "HolisticPlan", "Interaction", "bundle_approval_covers", "bundle_approval_request", "holistic_line", "holistic_plan"]
