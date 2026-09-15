"""Rate card: the bill rate each role needs once cost, overhead, and the hours nobody can bill are counted, against what it bills and what the market pays.

The services margin says what a role earned per billed hour.  A rate
card has to price the hours that are not billed too: at a target
utilisation of 75%, every billed hour carries a third of an unbilled one.
``build_rate_card`` seals per role, from the services margin document:

* the loaded cost of a billable hour: cost rate, plus overhead, divided
  by the target utilisation;
* the bill rate the target margin needs on that loaded cost, the current
  bill rate, the gap, and the margin the current rate really earns at
  target utilisation;
* the market position when a market rate is typed (below, at, above),
  and the utilisation the market rate would need to hit the target;
* a recommendation: hold, raise to the required rate, raise in steps when
  the increase exceeds the plan's cap, or fix cost or utilisation when
  the required rate sits above the market.

Every number is arithmetic on the sealed margin and typed inputs;
nothing here estimates demand, reads a provider, or persists anything.
"""

from __future__ import annotations

from collections.abc import Mapping
from decimal import ROUND_HALF_UP, Decimal
from typing import Any, Literal

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
    seal,
    sealed_digest,
    skip_digests,
    timestamp,
)
from lightbulb.services_margin import verify_services_margin

RATE_CARD_PLAN_SCHEMA = "lightbulb.rate_card_plan.v1"
RATE_CARD_SCHEMA = "lightbulb.rate_card.v1"
RATE_ACTIONS: tuple[str, ...] = ("hold", "raise", "raise_in_steps", "fix_cost_or_utilisation")
MARKET_POSITIONS: tuple[str, ...] = ("below", "at", "above", "unknown")
RateAction = Literal["hold", "raise", "raise_in_steps", "fix_cost_or_utilisation"]
MarketPosition = Literal["below", "at", "above", "unknown"]
_HUNDRED = Decimal("100")
_PCT = Decimal("0.01")


class RateCardError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise RateCardError(code, message)


def _money(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


def _pct(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(_PCT, rounding=ROUND_HALF_UP)


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


class RateCardPlan(StrictModel):
    schema_id: str = Field(default=RATE_CARD_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    target_margin_percent: Decimal = Field(default=Decimal("35"), validate_default=True)
    target_utilisation_percent: Decimal = Field(default=Decimal("75"), validate_default=True)
    overhead_percent: Decimal = Field(default=Decimal("0"), validate_default=True)
    maximum_increase_percent: Decimal = Field(default=Decimal("15"), validate_default=True)
    market_band_percent: Decimal = Field(default=Decimal("5"), validate_default=True)
    market_rates: dict[str, Decimal] = Field(default_factory=dict)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("target_margin_percent", "target_utilisation_percent", "overhead_percent", "maximum_increase_percent", "market_band_percent", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        result = decimal_value(value, field_name=str(info.field_name))
        if info.field_name == "target_margin_percent" and result >= _HUNDRED:
            raise ValueError("target_margin_percent is below 100")
        if info.field_name == "target_utilisation_percent" and not Decimal("0") < result <= _HUNDRED:
            raise ValueError("target_utilisation_percent is in (0, 100]")
        return result

    @field_validator("market_rates", mode="before")
    @classmethod
    def _rates(cls, value: object) -> object:
        if isinstance(value, Mapping):
            out = {str(key): decimal_value(rate, field_name=f"market_rates[{key}]") for key, rate in value.items()}
            if any(rate <= 0 for rate in out.values()):
                raise ValueError("a market rate is positive")
            return out
        return value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "RateCardPlan":
        if not skip_digests(info) and self.plan_digest != sealed_digest(RateCardPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self


def compile_rate_card_plan(company_ref: str, *, currency: str, market_rates: Mapping[str, Any] | None = None, overrides: Mapping[str, Any] | None = None) -> RateCardPlan:
    return seal(RateCardPlan, {"company_ref": company_ref, "currency": str(currency).upper(), "market_rates": {str(key): str(value) for key, value in dict(market_rates or {}).items()}, **dict(overrides or {})}, "plan_digest")


class RateCardRow(StrictModel):
    role_ref: OpaqueRef
    hours: Decimal
    cost_rate: Decimal
    loaded_cost_rate: Decimal
    bill_rate: Decimal
    required_bill_rate: Decimal
    gap_percent: Decimal
    margin_at_target_utilisation_percent: Decimal | None = None
    market_rate: Decimal | None = None
    market_position: MarketPosition
    utilisation_for_market_percent: Decimal | None = None
    action: RateAction
    recommended_bill_rate: Decimal
    rationale: ShortText

    @field_validator("hours", "cost_rate", "loaded_cost_rate", "bill_rate", "required_bill_rate", "gap_percent", "margin_at_target_utilisation_percent", "market_rate", "utilisation_for_market_percent", "recommended_bill_rate", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class RateCard(StrictModel):
    schema_id: str = Field(default=RATE_CARD_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    as_of: str
    plan_digest: Sha256Digest
    margin_digest: Sha256Digest
    rows: tuple[RateCardRow, ...] = Field(default_factory=tuple, max_length=500)
    by_action: dict[str, int] = Field(default_factory=dict)
    recommendations: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=24)
    card_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("rows", "recommendations", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "RateCard":
        if sum(self.by_action.values()) != len(self.rows):
            raise ValueError("every role is counted once by action")
        if not skip_digests(info) and self.card_digest != sealed_digest(RateCard, self, "card_digest"):
            raise ValueError("card_digest must commit the exact rate card")
        return self

    def row(self, role_ref: str) -> RateCardRow | None:
        return next((row for row in self.rows if row.role_ref == role_ref), None)

    def render(self) -> str:
        lines = [f"**Rate card {self.company_ref}** as of {self.as_of[:10]}: {len(self.rows)} role(s); " + ", ".join(f"{count} {action}" for action, count in self.by_action.items() if count) + "."]
        for row in self.rows:
            lines.append(f"- {row.role_ref} [{row.action}]: bills {row.bill_rate}/h, loaded cost {row.loaded_cost_rate}/h, needs {row.required_bill_rate}/h; {row.rationale}")
        return "\n".join(lines)


def build_rate_card(plan: RateCardPlan | Mapping[str, Any], *, services_margin: Mapping[str, Any] | Any, as_of: str) -> RateCard:
    """The sealed rate card from a services margin document: loaded cost, required bill rate, market position, and one recommendation per role."""

    parsed_plan = plan if isinstance(plan, RateCardPlan) else RateCardPlan.model_validate(detached(plan))
    margin = verify_services_margin(services_margin)
    _require(margin.company_ref == parsed_plan.company_ref and margin.currency == parsed_plan.currency, "SOURCE_SCOPE_MISMATCH", "the services margin names another company or currency")
    at = timestamp(as_of, field_name="as_of")
    utilisation = parsed_plan.target_utilisation_percent / _HUNDRED
    keep = Decimal("1") - parsed_plan.target_margin_percent / _HUNDRED
    rows: list[dict[str, Any]] = []
    counts: dict[str, int] = {}
    for role in margin.roles:
        cost = Decimal(str(role.cost_rate))
        bill = Decimal(str(role.bill_rate))
        loaded = _money(cost * (Decimal("1") + parsed_plan.overhead_percent / _HUNDRED) / utilisation)
        required = _money(loaded / keep)
        gap = _pct((required - bill) / bill * _HUNDRED) if bill > 0 else Decimal("0")
        real_margin = None if bill <= 0 else _pct((bill - loaded) / bill * _HUNDRED)
        market = parsed_plan.market_rates.get(role.role_ref)
        position = "unknown"
        for_market = None
        if market is not None:
            band = market * parsed_plan.market_band_percent / _HUNDRED
            position = "below" if bill < market - band else "above" if bill > market + band else "at"
            base = cost * (Decimal("1") + parsed_plan.overhead_percent / _HUNDRED)
            for_market = _pct(base / (market * keep) * _HUNDRED) if market * keep > 0 else None
        if required <= bill:
            action, recommended = "hold", bill
            rationale = f"{bill}/h earns {real_margin}% at {parsed_plan.target_utilisation_percent}% utilisation, at or above the {parsed_plan.target_margin_percent}% target" + (f"; {position} market {market}" if market is not None else "")
        elif market is not None and required > market * (Decimal("1") + parsed_plan.market_band_percent / _HUNDRED):
            action, recommended = "fix_cost_or_utilisation", _money(min(market, bill * (Decimal("1") + parsed_plan.maximum_increase_percent / _HUNDRED)) if market > bill else bill)
            rationale = f"the {parsed_plan.target_margin_percent}% target needs {required}/h but the market pays {market}/h; at {market}/h the target needs {for_market}% utilisation" + (f" (or a lower cost rate than {cost}/h)")
        elif gap > parsed_plan.maximum_increase_percent:
            action, recommended = "raise_in_steps", _money(bill * (Decimal("1") + parsed_plan.maximum_increase_percent / _HUNDRED))
            rationale = f"{required}/h is {gap}% above {bill}/h; first step to {recommended}/h within the {parsed_plan.maximum_increase_percent}% cap, then again"
        else:
            action, recommended = "raise", required
            rationale = f"{bill}/h earns {real_margin}% at {parsed_plan.target_utilisation_percent}% utilisation; {required}/h ({gap}% up) earns the {parsed_plan.target_margin_percent}% target" + (f"; {position} market {market}" if market is not None else "")
        counts[action] = counts.get(action, 0) + 1
        rows.append({"role_ref": role.role_ref, "hours": str(role.hours), "cost_rate": str(cost), "loaded_cost_rate": str(loaded), "bill_rate": str(bill), "required_bill_rate": str(required), "gap_percent": str(gap), "margin_at_target_utilisation_percent": None if real_margin is None else str(real_margin), "market_rate": None if market is None else str(_money(market)), "market_position": position, "utilisation_for_market_percent": None if for_market is None else str(for_market), "action": action, "recommended_bill_rate": str(recommended), "rationale": rationale[:300]})
    rows.sort(key=lambda row: (-Decimal(row["gap_percent"]), row["role_ref"]))
    recommendations = [f"{row['role_ref']}: {row['action']} at {row['recommended_bill_rate']}/h; {row['rationale']}" for row in rows if row["action"] != "hold"][:24]
    if not recommendations:
        recommendations.append("every role's bill rate earns the target margin at the target utilisation" if rows else "no billed hours in the margin window, so there is nothing to price")
    payload = {"company_ref": parsed_plan.company_ref, "currency": parsed_plan.currency, "as_of": at, "plan_digest": parsed_plan.plan_digest, "margin_digest": margin.margin_digest, "rows": rows, "by_action": counts, "recommendations": [item[:300] for item in recommendations]}
    return seal(RateCard, payload, "card_digest")


def verify_rate_card(value: Any) -> RateCard:
    return value if isinstance(value, RateCard) else RateCard.model_validate(dict(detached(value)))


RATE_CARD_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "rate_card",
    "golden_loop": "services.quote_to_cash@0.1.0",
    "stages": ["verify_services_margin", "load_cost_for_unbilled_hours", "required_bill_rate", "market_position", "recommend", "seal_card"],
    "actions": list(RATE_ACTIONS),
    "required_connectors": ["lightbulb.sdk_engine_state"],
    "hard_rules": [
        "the loaded cost of a billable hour is cost rate plus overhead over the target utilisation; the required bill rate is that over one minus the target margin",
        "market rates are typed; a required rate above the market band is a cost or utilisation problem, not a price to charge",
        "an increase beyond the cap is taken in steps",
        "nothing here estimates demand, reads a provider, or persists anything",
    ],
}

__all__ = ["MARKET_POSITIONS", "RATE_ACTIONS", "RATE_CARD_MANIFEST", "RATE_CARD_PLAN_SCHEMA", "RATE_CARD_SCHEMA", "RateCard", "RateCardError", "RateCardPlan", "RateCardRow", "build_rate_card", "compile_rate_card_plan", "verify_rate_card"]
