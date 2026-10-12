"""Stay or switch: the client's current holding against a candidate, with every one-off cost and lost feature on the table.

Real advice is rarely "which product"; it is "should this client leave the one they have". A
current holding is a decision fact like any other (the rate or premium paid, the balance, the
fixed period, the exit and re-entry costs, the features relied on), never an account number. The
switching analysis projects the cost of staying and the cost of switching over the same horizon
with the same projection rules the shortlist uses, adds the one-off costs a switch triggers, names
the features the client would lose, finds the month the switch pays for itself, and gives a
verdict a person can check: switch, stay, or undecided with the reason.

Nothing here recommends. It is the arithmetic and the disclosure the adviser's recommendation
rests on, and the record of advice carries it as the "why switch" or "why not".
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import ROUND_HALF_UP, Decimal
from typing import Any, Literal

from pydantic import ConfigDict, Field, field_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, OpaqueRef, Sha256Digest, detached, seal, sealed_digest, skip_digests, timestamp
from lightbulb.finance_advice_identity import AdviceIdentityModel as StrictModel
from lightbulb.finance_advice_identity import reject_identity_payload
from lightbulb.finance_advice_catalog import Product, ResearchModel
from lightbulb.finance_advice_engine import ClientState
from lightbulb.finance_advice_projection import DEFAULT_HORIZON_YEARS, CostComponent, CostProjection, interest_over, project_cost

from pydantic import ValidationInfo, model_validator

HOLDING_SCHEMA = "lightbulb.finance_advice_current_holding.v1"
SWITCH_SCHEMA = "lightbulb.finance_advice_switch_analysis.v1"
FORBIDDEN_HOLDING_KEYS = frozenset({"account_number", "policy_number", "member_number", "bsb", "iban", "card_number", "name", "email", "phone"})

Verdict = Literal["switch", "stay", "undecided"]
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


class CurrentHolding(ResearchModel):
    """What the client has today, as decision facts: the price paid, the balance, the exit costs, the features relied on."""

    model_config = ConfigDict(hide_input_in_errors=True)

    schema_id: str = Field(default=HOLDING_SCHEMA, alias="schema")
    holding_ref: OpaqueRef
    vertical_id: str
    provider_name: str
    product_name: str
    product_ref: OpaqueRef | None = None
    balance: Decimal | None = Field(default=None, ge=0)
    rate_percent: Decimal | None = Field(default=None, ge=0)
    premium: Decimal | None = Field(default=None, ge=0)
    premium_unit: str | None = None
    ongoing_fee_per_year: Decimal = Field(default=Decimal("0"), ge=0)
    remaining_term_years: int | None = Field(default=None, ge=1, le=50)
    fixed_until: str | None = None
    exit_costs: dict[str, Decimal] = Field(default_factory=dict)
    features: tuple[str, ...] = Field(default_factory=tuple)
    sum_insured: Decimal | None = Field(default=None, ge=0)
    loyalty_or_loading_note: str | None = None

    @model_validator(mode="before")
    @classmethod
    def _no_free_text_identity(cls, value: Any) -> Any:
        reject_identity_payload(value)
        return value

    @field_validator("features", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("balance", "rate_percent", "premium", "ongoing_fee_per_year", "sum_insured", mode="before")
    @classmethod
    def _amounts(cls, value: Any) -> Any:
        return value if value is None or isinstance(value, Decimal) else _decimal(value)

    @field_validator("exit_costs", mode="before")
    @classmethod
    def _costs(cls, value: Any) -> dict[str, Decimal]:
        out: dict[str, Decimal] = {}
        for key, raw in dict(value or {}).items():
            if str(key).lower() in FORBIDDEN_HOLDING_KEYS:
                raise ValueError(f"a holding carries decision facts, never {key}")
            amount = _decimal(raw)
            if amount is None or amount < 0:
                raise ValueError(f"exit cost {key} is a non-negative amount")
            out[str(key)] = amount
        return out

    @model_validator(mode="after")
    def _guard(self) -> CurrentHolding:
        for key in (self.provider_name, self.product_name):
            if any(marker in key.lower() for marker in ("@", "account no", "policy no")):
                raise ValueError("a holding names the product, never an account or policy number")
        return self


def current_holding(holding_ref: str, *, vertical_id: str, provider_name: str, product_name: str, **facts: Any) -> CurrentHolding:
    return CurrentHolding(holding_ref=holding_ref, vertical_id=vertical_id, provider_name=provider_name, product_name=product_name, **facts)


class SwitchAnalysis(StrictModel):
    schema_id: str = Field(default=SWITCH_SCHEMA, alias="schema")
    holding_ref: OpaqueRef
    candidate_product_ref: OpaqueRef
    candidate_product_name: str
    family: str
    horizon_years: int = Field(ge=1, le=40)
    currency: str | None = None
    stay_total: Decimal
    switch_total: Decimal
    one_off_costs: tuple[CostComponent, ...] = Field(default_factory=tuple)
    saving_over_horizon: Decimal
    breakeven_months: int | None = None
    features_lost: tuple[str, ...] = Field(default_factory=tuple)
    features_gained: tuple[str, ...] = Field(default_factory=tuple)
    verdict: Verdict
    reasons: tuple[str, ...] = Field(default_factory=tuple)
    assumptions: tuple[str, ...] = Field(default_factory=tuple)
    missing: tuple[str, ...] = Field(default_factory=tuple)
    prepared_at: str
    analysis_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("one_off_costs", "features_lost", "features_gained", "reasons", "assumptions", "missing", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("stay_total", "switch_total", "saving_over_horizon", mode="before")
    @classmethod
    def _amounts(cls, value: Any) -> Any:
        return value if isinstance(value, Decimal) else Decimal(str(value))

    @model_validator(mode="after")
    def _seal(self, info: ValidationInfo) -> SwitchAnalysis:
        if not skip_digests(info) and self.analysis_digest != sealed_digest(SwitchAnalysis, self, "analysis_digest"):
            raise ValueError("analysis_digest must commit the exact analysis")
        return self


def _stay_projection(holding: CurrentHolding, family: str, horizon_years: int) -> tuple[Decimal, list[str], list[str]]:
    """The cost of staying over the horizon, from the holding's own facts and the projection's own arithmetic."""

    assumptions: list[str] = []
    missing: list[str] = []
    total = Decimal("0")
    if family == "credit":
        if holding.balance is None or holding.rate_percent is None:
            missing.append("the holding's balance and rate are needed to project the cost of staying")
            return Decimal("0"), assumptions, missing
        term = holding.remaining_term_years or 25
        if holding.remaining_term_years is None:
            assumptions.append("remaining term assumed 25 years")
        total = interest_over(holding.balance, holding.rate_percent, term, min(horizon_years, term)) + holding.ongoing_fee_per_year * horizon_years
        assumptions.append(f"staying costs interest at {holding.rate_percent}% p.a. on {holding.balance} over {min(horizon_years, term)} of {term} years plus {holding.ongoing_fee_per_year}/year in fees; rate held constant")
    elif family == "insurance":
        if holding.premium is None:
            missing.append("the holding's premium is needed to project the cost of staying")
            return Decimal("0"), assumptions, missing
        per_year = holding.premium * (Decimal("12") if (holding.premium_unit or "").endswith("/month") else Decimal("1"))
        total = per_year * horizon_years + holding.ongoing_fee_per_year * horizon_years
        assumptions.append(f"staying costs the current premium {holding.premium} {holding.premium_unit or 'per year'} held flat for {horizon_years} years; no age-stepped or inflation increase applied")
    elif family == "deposits":
        if holding.balance is None or holding.rate_percent is None:
            missing.append("the holding's balance and rate are needed to project the return of staying")
            return Decimal("0"), assumptions, missing
        earned = holding.balance * (holding.rate_percent / Decimal("100")) * horizon_years
        total = -earned + holding.ongoing_fee_per_year * horizon_years
        assumptions.append(f"staying earns {holding.rate_percent}% p.a. simple on {holding.balance} for {horizon_years} years (negative cost)")
    else:
        if holding.balance is None:
            missing.append("the holding's balance is needed to project the cost of staying")
            return Decimal("0"), assumptions, missing
        fee = holding.ongoing_fee_per_year
        total = fee * horizon_years
        assumptions.append(f"staying costs {fee}/year in fees for {horizon_years} years; returns are not forecast")
    return _money(total), assumptions, missing


def _one_off_costs(holding: CurrentHolding, candidate: Product, family: str, *, as_of: str) -> tuple[list[CostComponent], list[str]]:
    costs: list[CostComponent] = []
    assumptions: list[str] = []
    for label, amount in sorted(holding.exit_costs.items()):
        if amount > 0:
            costs.append(CostComponent(label=f"exit: {label}", amount=_money(amount), basis="stated by the client's current provider", item=None, support=None, cited=False))
    if holding.fixed_until and holding.fixed_until > as_of[:10] and not any("break" in key.lower() for key in holding.exit_costs):
        assumptions.append(f"the holding is fixed until {holding.fixed_until}; a break cost applies and is not stated, so the switch total understates the cost until the provider quotes it")
    upfront = [fact for fact in candidate.pricing if fact.value is not None and (("once-off" in (fact.unit or "").lower()) or any(word in fact.item.lower() for word in ("application fee", "establishment fee", "settlement fee", "upfront", "valuation")))]
    for fact in upfront:
        costs.append(CostComponent(label=f"entry: {fact.item}", amount=_money(Decimal(str(fact.value))), basis="the candidate's stated one-off fee", item=fact.item, support=fact.support, cited=fact.support != "unsupported"))
    if family == "credit" and holding.balance is not None:
        lvr_note = "lenders mortgage insurance applies again on a refinance above 80% LVR; it is not in this total unless stated"
        assumptions.append(lvr_note)
    return costs, assumptions


def switching_analysis(holding: CurrentHolding | Mapping[str, Any], candidate: Product | Mapping[str, Any], state: ClientState | Mapping[str, Any], *, family: str | None = None, horizon_years: int | None = None, currency: str | None = None, prepared_at: str) -> SwitchAnalysis:
    """Stay against switch over one horizon: totals, one-off costs, breakeven, features lost, and a verdict with its reasons."""

    h = holding if isinstance(holding, CurrentHolding) else CurrentHolding.model_validate(dict(detached(holding)))
    c = candidate if isinstance(candidate, Product) else Product.model_validate(dict(detached(candidate)))
    s = state if isinstance(state, ClientState) else ClientState.model_validate(dict(detached(state)))
    stamp = timestamp(prepared_at, field_name="prepared_at")
    fam = family or ("credit" if h.rate_percent is not None and h.balance is not None else ("insurance" if h.premium is not None else "credit"))
    horizon = horizon_years or DEFAULT_HORIZON_YEARS.get(fam, 5)
    projection: CostProjection = project_cost(c, s, family=fam, horizon_years=horizon, currency=currency)
    stay_total, assumptions, missing = _stay_projection(h, fam, horizon)
    one_off, more = _one_off_costs(h, c, fam, as_of=stamp)
    assumptions.extend(more)
    assumptions.extend(projection.assumptions)
    missing.extend(projection.missing)
    switch_total = _money(projection.total + sum((item.amount for item in one_off), Decimal("0")))
    features_lost = tuple(feature for feature in h.features if not any(feature.lower() in (term.term + " " + str(term.value)).lower() or feature.lower() in " ".join(c.eligibility).lower() for term in c.key_terms))
    features_gained = tuple(str(term.term) for term in c.key_terms if term.term in ("offset_available", "features") and str(term.value) not in ("", "[]", "False"))
    reasons: list[str] = []
    verdict: Verdict
    saving = _money(stay_total - switch_total)
    if missing or not projection.rankable:
        verdict = "undecided"
        reasons.append("the arithmetic is incomplete: " + "; ".join(missing or ("the candidate's price is not rankable",)))
    elif saving > 0 and not features_lost:
        verdict = "switch"
        reasons.append(f"switching saves {saving} {projection.currency or ''} over {horizon} years after {len(one_off)} one-off cost(s)".strip())
    elif saving > 0 and features_lost:
        verdict = "undecided"
        reasons.append(f"switching saves {saving} {projection.currency or ''} over {horizon} years but loses {', '.join(features_lost)}; the client weighs the features against the saving".strip())
    else:
        verdict = "stay"
        reasons.append(f"staying is cheaper by {-saving} {projection.currency or ''} over {horizon} years once one-off costs are counted".strip())
    breakeven: int | None = None
    if saving > 0 and one_off:
        one_off_total = sum((item.amount for item in one_off), Decimal("0"))
        monthly_saving = (stay_total - projection.total) / Decimal(horizon * 12)
        if monthly_saving > 0:
            breakeven = int((one_off_total / monthly_saving).to_integral_value(rounding=ROUND_HALF_UP))
            reasons.append(f"the one-off costs are recovered after about {breakeven} month(s)")
    if h.fixed_until and h.fixed_until > stamp[:10]:
        reasons.append(f"the current product is fixed until {h.fixed_until}; leaving early triggers the provider's break cost")
    return seal(SwitchAnalysis, {"holding_ref": h.holding_ref, "candidate_product_ref": c.product_ref, "candidate_product_name": c.product_name, "family": fam, "horizon_years": horizon, "currency": projection.currency or currency, "stay_total": stay_total, "switch_total": switch_total, "one_off_costs": [item.to_dict() for item in one_off], "saving_over_horizon": saving, "breakeven_months": breakeven, "features_lost": list(features_lost), "features_gained": list(features_gained), "verdict": verdict, "reasons": reasons, "assumptions": list(dict.fromkeys(assumptions)), "missing": list(dict.fromkeys(missing)), "prepared_at": stamp}, "analysis_digest")


def switching_table(analyses: Sequence[SwitchAnalysis | Mapping[str, Any]]) -> dict[str, Any]:
    rows = []
    for raw in analyses:
        item = raw if isinstance(raw, SwitchAnalysis) else SwitchAnalysis.model_validate(dict(detached(raw)))
        rows.append({"candidate": item.candidate_product_name, "stay": str(item.stay_total), "switch": str(item.switch_total), "saving": str(item.saving_over_horizon), "breakeven_months": item.breakeven_months, "features_lost": list(item.features_lost), "verdict": item.verdict, "reasons": list(item.reasons)})
    return {"schema": "lightbulb.finance_advice_switching_table.v1", "rows": rows, "disclosure": "stay-or-switch arithmetic over one horizon with stated one-off costs; a break cost the provider has not quoted is not in it; nothing here is a recommendation"}


def holdings_from_state(state: ClientState | Mapping[str, Any]) -> tuple[CurrentHolding, ...]:
    """The holdings a client state carries in its facts under ``holdings``: decision facts, sealed as holdings."""

    s = state if isinstance(state, ClientState) else ClientState.model_validate(dict(detached(state)))
    raw = s.facts.get("holdings") if isinstance(s.facts, Mapping) else None
    out: list[CurrentHolding] = []
    for index, item in enumerate(raw or ()):
        if isinstance(item, Mapping):
            payload = dict(item)
            payload.setdefault("holding_ref", f"holding:{s.client_ref}:{index + 1}")
            payload.setdefault("vertical_id", s.vertical_id)
            out.append(CurrentHolding.model_validate(payload))
    return tuple(out)


__all__ = ["HOLDING_SCHEMA", "SWITCH_SCHEMA", "CurrentHolding", "SwitchAnalysis", "Verdict", "current_holding", "holdings_from_state", "switching_analysis", "switching_table"]
