"""The FX exposure chain: one replay-fenced lifecycle per foreign-currency balance, from the balance read to settled company currency.

Every other chain runs in the company currency.  A balance held in another
currency (a USD Stripe payout account for an AUD company, a EUR marketplace
wallet) was invisible: nothing carried the exposure, revalued it against an
observed rate, ordered a conversion under authority, or said what the
conversion actually cost.  ``FX_EXPOSURE_LIFECYCLE`` does:

    exposed -> (revalue)* -> conversion_ordered -> convert -> exposed | settled   (settled terminal)
    exposed -> written_off                                                     (terminal, with a reason)

* ``exposure_receipt`` opens the exposure from a balance read for the foreign
  currency; ``rate_receipt`` values it at an observed rate no older than the
  plan allows.
* ``revalue`` re-marks the exposure at a newer rate; the unrealised gain or
  loss is computed against the opening rate.
* ``order_conversion`` names the foreign amount and the quoted rate; above the
  plan's threshold it is a ``disbursement`` authority decision.
* ``conversion_receipt`` consumes the provider's transaction read for the
  executed conversion: the sold amount must equal the order, the bought
  currency must be the company currency, and the executed rate must sit
  inside the plan's tolerance of the quote.  The realised gain or loss and
  the conversion cost (quote minus proceeds) are computed, never typed.

``conversion_cost_receipt`` hands the cost register one conversion's cost
as a proven source; ``company_currency_receipt`` is what another chain
attaches to a foreign settlement to state its company-currency amount.
Nothing here moves money, reads a provider, or persists anything.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import timedelta
from decimal import ROUND_HALF_UP, Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    MONEY_QUANTUM,
    BoundedText,
    CurrencyCode,
    LifecycleSpec,
    OpaqueRef,
    Sha256Digest,
    StrictModel,
    decimal_value,
    detached,
    parsed,
    require,
    seal,
    sealed_digest,
    skip_digests,
    stable_digest,
    timestamp,
    unique,
)

FX_EXPOSURE_KIND = "fx_exposure_chain"
FX_EXPOSURE_GOLDEN_LOOP = "finance.foreign_balance_to_settled_company_currency@0.1.0"
FX_EXPOSURE_PLAN_SCHEMA = "lightbulb.fx_exposure_plan.v1"
FX_CONVERSION_RECEIPT_SCHEMA = "lightbulb.fx_conversion_receipt.v1"
MAX_FX_TRANSITIONS = 400
BALANCE_TOOLS: frozenset[str] = frozenset({"airwallex.list_balances", "xero.list_bank_transactions", "quickbooks.list_accounts", "host.bank_balances", "stripe.list_balance_transactions", "paypal.list_transactions"})
RATE_TOOLS: frozenset[str] = frozenset({"host.fx_rate", "airwallex.fx_quote", "wise.fx_rate", "xero.list_currencies"})
CONVERSION_TOOLS: frozenset[str] = frozenset({"airwallex.list_transactions", "host.bank_transfer", "wise.list_transfers", "stripe.list_balance_transactions"})
RATE_QUANTUM = Decimal("0.000001")
_HUNDRED = Decimal("100")

FX_STATUSES: tuple[str, ...] = ("exposed", "conversion_ordered", "settled", "written_off")
TERMINAL_FX_STATUSES: frozenset[str] = frozenset({"settled", "written_off"})
FX_EVENTS: tuple[str, ...] = ("expose", "revalue", "order_conversion", "convert", "write_off")
_FX_TABLE: dict[tuple[str, str], str] = {
    ("new", "expose"): "exposed",
    ("exposed", "revalue"): "exposed",
    ("exposed", "order_conversion"): "conversion_ordered",
    ("conversion_ordered", "convert"): "exposed",
    ("exposed", "write_off"): "written_off",
}


class FxExposureError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise FxExposureError(code, message)


def _money(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


def _rate(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(RATE_QUANTUM, rounding=ROUND_HALF_UP)


def _percent(value: Decimal) -> Decimal:
    return value.quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


# --------------------------------------------------------------------------- #
# Plan
# --------------------------------------------------------------------------- #


class FxExposurePlan(StrictModel):
    """What the chain enforces: which currencies may be held, how fresh a rate must be, how far an execution may drift from its quote, and when a conversion needs a human."""

    schema_id: str = Field(default=FX_EXPOSURE_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    exposure_currencies: tuple[CurrencyCode, ...] = Field(min_length=1, max_length=20)
    rate_max_age_hours: int = Field(default=24, ge=1, le=720)
    spread_tolerance_percent: Decimal = Field(default=Decimal("1"), validate_default=True)
    authority_threshold: Decimal = Field(default=Decimal("10000"), validate_default=True)
    exposure_limit: Decimal | None = None
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("exposure_currencies", mode="before")
    @classmethod
    def _currencies(cls, value: Any) -> Any:
        return tuple(str(item).upper() for item in value) if isinstance(value, (list, tuple)) else value

    @field_validator("spread_tolerance_percent", "authority_threshold", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @field_validator("exposure_limit", mode="before")
    @classmethod
    def _limit(cls, value: Any) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name="exposure_limit")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "FxExposurePlan":
        unique(list(self.exposure_currencies), label="exposure currencies")
        if self.currency in self.exposure_currencies:
            raise ValueError("the company currency is not a foreign exposure")
        if not skip_digests(info) and self.plan_digest != sealed_digest(FxExposurePlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self


def compile_fx_exposure_chain(company_ref: str, *, currency: str, exposure_currencies: Sequence[str], overrides: Mapping[str, Any] | None = None) -> FxExposurePlan:
    raw: dict[str, Any] = {"company_ref": company_ref, "currency": str(currency).upper(), "exposure_currencies": [str(item).upper() for item in exposure_currencies], **dict(overrides or {})}
    return seal(FxExposurePlan, raw, "plan_digest")


# --------------------------------------------------------------------------- #
# Receipts, ledger, lifecycle
# --------------------------------------------------------------------------- #


class ConversionRecord(StrictModel):
    conversion_ref: OpaqueRef
    foreign_amount: Decimal
    company_amount: Decimal
    executed_rate: Decimal
    quoted_rate: Decimal
    conversion_cost: Decimal
    realised_gain_loss: Decimal
    converted_at: str
    conversion_digest: Sha256Digest

    @field_validator("foreign_amount", "company_amount", "conversion_cost", "realised_gain_loss", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name), allow_negative=True)

    @field_validator("executed_rate", "quoted_rate", mode="before")
    @classmethod
    def _rates(cls, value: Any) -> Decimal:
        return _rate(value)


class FxReceipt(StrictModel):
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    exposure_currency: CurrencyCode | None = None
    account_ref: OpaqueRef | None = None
    balance_provenance: dict[str, Any] | None = None
    balance_digest: Sha256Digest | None = None
    foreign_amount: Decimal | None = None
    balance_observed_at: str | None = None
    rate_provenance: dict[str, Any] | None = None
    rate_digest: Sha256Digest | None = None
    rate: Decimal | None = None
    rate_observed_at: str | None = None
    order_ref: OpaqueRef | None = None
    ordered_foreign: Decimal | None = None
    authorization_proof: dict[str, Any] | None = None
    conversion_provenance: dict[str, Any] | None = None
    conversion_digest: Sha256Digest | None = None
    conversion_ref: OpaqueRef | None = None
    sold_amount: Decimal | None = None
    sold_currency: CurrencyCode | None = None
    bought_amount: Decimal | None = None
    bought_currency: CurrencyCode | None = None
    converted_at: str | None = None
    detail: BoundedText | None = None

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("foreign_amount", "ordered_foreign", "sold_amount", "bought_amount", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))

    @field_validator("rate", mode="before")
    @classmethod
    def _rate_value(cls, value: Any) -> Decimal | None:
        return None if value is None else _rate(value)

    @field_validator("balance_observed_at", "rate_observed_at", "converted_at")
    @classmethod
    def _stamps(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))


class FxLedger(StrictModel):
    exposure_currency: str | None = None
    account_ref: str | None = None
    balance_digest: str | None = None
    opened_foreign: Decimal = Field(default=Decimal("0"), validate_default=True)
    remaining_foreign: Decimal = Field(default=Decimal("0"), validate_default=True)
    opening_rate: Decimal = Field(default=Decimal("0"), validate_default=True)
    opening_value: Decimal = Field(default=Decimal("0"), validate_default=True)
    current_rate: Decimal = Field(default=Decimal("0"), validate_default=True)
    current_value: Decimal = Field(default=Decimal("0"), validate_default=True)
    rate_observed_at: str | None = None
    rate_digest: str | None = None
    unrealised_gain_loss: Decimal = Field(default=Decimal("0"), validate_default=True)
    revaluations: int = 0
    order_ref: str | None = None
    ordered_foreign: Decimal = Field(default=Decimal("0"), validate_default=True)
    quoted_rate: Decimal = Field(default=Decimal("0"), validate_default=True)
    quote_digest: str | None = None
    order_authority_ref: str | None = None
    conversions: tuple[ConversionRecord, ...] = Field(default_factory=tuple, max_length=200)
    converted_foreign_total: Decimal = Field(default=Decimal("0"), validate_default=True)
    proceeds_total: Decimal = Field(default=Decimal("0"), validate_default=True)
    conversion_cost_total: Decimal = Field(default=Decimal("0"), validate_default=True)
    realised_gain_loss: Decimal = Field(default=Decimal("0"), validate_default=True)
    last_conversion_ref: str | None = None
    last_conversion_cost: Decimal = Field(default=Decimal("0"), validate_default=True)
    last_converted_at: str | None = None
    write_off_reason: str | None = None
    outcome: Literal["open", "settled", "written_off"] = "open"

    @field_validator("conversions", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("opened_foreign", "remaining_foreign", "opening_value", "current_value", "unrealised_gain_loss", "ordered_foreign", "converted_foreign_total", "proceeds_total", "conversion_cost_total", "realised_gain_loss", "last_conversion_cost", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name), allow_negative=True)

    @field_validator("opening_rate", "current_rate", "quoted_rate", mode="before")
    @classmethod
    def _rates(cls, value: Any) -> Decimal:
        return _rate(value)


class FxEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    money_moved: Literal[False] = False
    conversion_executed: Literal[False] = False
    provider_read: Literal[False] = False


def _fresh_rate(plan: FxExposurePlan, r: FxReceipt, at: str, code: str) -> None:
    require(r.rate_provenance is not None and r.rate_digest is not None and r.rate is not None and r.rate_observed_at is not None, code, "a rate arrives as a governed rate read with its provenance, digest, value, and time")
    require(str(dict(r.rate_provenance or {}).get("output_digest")) == r.rate_digest, code, "the provenance does not seal this rate read")
    assert r.rate is not None and r.rate_observed_at is not None
    require(r.rate > 0, code, "a rate is positive")
    observed = parsed(str(r.rate_observed_at))
    require(observed <= parsed(at), "RATE_FROM_FUTURE", "the rate cannot come from the future")
    require(parsed(at) - observed <= timedelta(hours=plan.rate_max_age_hours), "RATE_STALE", f"the rate is older than {plan.rate_max_age_hours} hour(s) at the time of use")


def _apply_fx(plan: FxExposurePlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event, at = command.receipt, command.event, command.occurred_at
    if event == "expose":
        require(r.exposure_currency is not None and r.account_ref is not None and r.balance_provenance is not None and r.balance_digest is not None and r.foreign_amount is not None and r.balance_observed_at is not None, "EXPOSURE_NOT_PROVEN", "an exposure opens from a balance read for one foreign currency in one account")
        require(str(r.exposure_currency) in plan.exposure_currencies, "CURRENCY_NOT_ALLOWED", f"{r.exposure_currency} is not an exposure currency of this plan")
        require(str(dict(r.balance_provenance or {}).get("output_digest")) == r.balance_digest, "EXPOSURE_NOT_PROVEN", "the provenance does not seal this balance read")
        assert r.foreign_amount is not None
        require(r.foreign_amount > 0, "EXPOSURE_EMPTY", "an exposure is a positive foreign balance")
        require(parsed(str(r.balance_observed_at)) <= parsed(at), "BALANCE_FROM_FUTURE", "the balance cannot come from the future")
        _fresh_rate(plan, r, at, "RATE_NOT_PROVEN")
        assert r.rate is not None
        value = _money(r.foreign_amount * r.rate)
        data.update({"exposure_currency": r.exposure_currency, "account_ref": r.account_ref, "balance_digest": r.balance_digest, "opened_foreign": str(_money(r.foreign_amount)), "remaining_foreign": str(_money(r.foreign_amount)), "opening_rate": str(r.rate), "opening_value": str(value), "current_rate": str(r.rate), "current_value": str(value), "rate_observed_at": r.rate_observed_at, "rate_digest": r.rate_digest})
    elif event == "revalue":
        _fresh_rate(plan, r, at, "RATE_NOT_PROVEN")
        assert r.rate is not None
        require(data.get("rate_observed_at") is None or parsed(str(r.rate_observed_at)) > parsed(str(data["rate_observed_at"])), "RATE_NOT_NEWER", "a revaluation uses a rate observed after the current one")
        remaining = Decimal(str(data["remaining_foreign"]))
        value = _money(remaining * r.rate)
        data.update({"current_rate": str(r.rate), "current_value": str(value), "rate_observed_at": r.rate_observed_at, "rate_digest": r.rate_digest, "unrealised_gain_loss": str(_money(value - remaining * Decimal(str(data["opening_rate"])))), "revaluations": int(data.get("revaluations", 0)) + 1})
    elif event == "order_conversion":
        require(r.order_ref is not None and r.ordered_foreign is not None, "ORDER_MISSING", "a conversion order names itself and the foreign amount")
        assert r.ordered_foreign is not None
        remaining = Decimal(str(data["remaining_foreign"]))
        require(0 < r.ordered_foreign <= remaining, "ORDER_EXCEEDS_EXPOSURE", f"the order of {r.ordered_foreign} exceeds the remaining exposure {remaining}")
        _fresh_rate(plan, r, at, "QUOTE_NOT_PROVEN")
        assert r.rate is not None
        company_value = _money(r.ordered_foreign * r.rate)
        authority_ref = None
        if company_value >= plan.authority_threshold:
            require(r.authorization_proof is not None, "CONVERSION_NOT_AUTHORIZED", f"converting {r.ordered_foreign} {data['exposure_currency']} (about {company_value} {plan.currency}) is a disbursement decision; a human decides it", "await_approval")
            from lightbulb.authority_matrix import require_authorization_proof

            proof = require_authorization_proof(r.authorization_proof, category="disbursement", amount=company_value, currency=plan.currency, command=command, plan_digest=plan.plan_digest, company_ref=plan.company_ref)
            require(proof.engine == FX_EXPOSURE_KIND, "APPROVAL_TRANSITION_MISMATCH", "the proof authorizes another engine")
            authority_ref = proof.approval_task_id
        data.update({"order_ref": r.order_ref, "ordered_foreign": str(_money(r.ordered_foreign)), "quoted_rate": str(r.rate), "quote_digest": r.rate_digest, "order_authority_ref": authority_ref})
    elif event == "convert":
        require(r.conversion_provenance is not None and r.conversion_digest is not None and r.conversion_ref is not None and r.sold_amount is not None and r.bought_amount is not None and r.converted_at is not None, "CONVERSION_NOT_PROVEN", "a conversion is the provider's transaction read: what was sold, what was bought, when")
        require(str(dict(r.conversion_provenance or {}).get("output_digest")) == r.conversion_digest, "CONVERSION_NOT_PROVEN", "the provenance does not seal this transaction read")
        require(str(r.sold_currency) == str(data["exposure_currency"]) and str(r.bought_currency) == plan.currency, "CONVERSION_CURRENCY_MISMATCH", f"the conversion must sell {data['exposure_currency']} and buy {plan.currency}")
        assert r.sold_amount is not None and r.bought_amount is not None
        ordered = Decimal(str(data["ordered_foreign"]))
        require(_money(r.sold_amount) == ordered, "CONVERSION_AMOUNT_MISMATCH", f"the order was for {ordered} {data['exposure_currency']}; the provider sold {r.sold_amount}")
        require(r.bought_amount > 0, "CONVERSION_PROCEEDS_MISSING", "a conversion produces company currency")
        require(parsed(str(r.converted_at)) <= parsed(at), "CONVERSION_FROM_FUTURE", "the conversion cannot come from the future")
        require(all(str(r.conversion_ref) != item["conversion_ref"] for item in data.get("conversions", ())), "CONVERSION_ALREADY_RECORDED", f"{r.conversion_ref} already converted this exposure")
        quoted = Decimal(str(data["quoted_rate"]))
        executed = _rate(r.bought_amount / r.sold_amount)
        adverse = _percent((quoted - executed) / quoted * _HUNDRED)
        require(adverse <= plan.spread_tolerance_percent, "EXECUTION_OUTSIDE_TOLERANCE", f"the executed rate {executed} is {adverse}% below the quote {quoted}; the plan tolerates {plan.spread_tolerance_percent}%")
        proceeds = _money(r.bought_amount)
        cost = _money(max(ordered * quoted - proceeds, Decimal("0")))
        realised = _money(proceeds - ordered * Decimal(str(data["opening_rate"])))
        record = ConversionRecord(conversion_ref=str(r.conversion_ref), foreign_amount=ordered, company_amount=proceeds, executed_rate=executed, quoted_rate=quoted, conversion_cost=cost, realised_gain_loss=realised, converted_at=str(r.converted_at), conversion_digest=str(r.conversion_digest)).to_dict()
        remaining = _money(Decimal(str(data["remaining_foreign"])) - ordered)
        data.update({
            "conversions": [*[dict(item) for item in data.get("conversions", ())], record],
            "remaining_foreign": str(remaining), "current_value": str(_money(remaining * Decimal(str(data["current_rate"])))), "unrealised_gain_loss": str(_money(remaining * (Decimal(str(data["current_rate"])) - Decimal(str(data["opening_rate"]))))),
            "converted_foreign_total": str(_money(Decimal(str(data["converted_foreign_total"])) + ordered)), "proceeds_total": str(_money(Decimal(str(data["proceeds_total"])) + proceeds)),
            "conversion_cost_total": str(_money(Decimal(str(data["conversion_cost_total"])) + cost)), "realised_gain_loss": str(_money(Decimal(str(data["realised_gain_loss"])) + realised)),
            "last_conversion_ref": r.conversion_ref, "last_conversion_cost": str(cost), "last_converted_at": r.converted_at,
            "order_ref": None, "ordered_foreign": "0", "quoted_rate": "0", "quote_digest": None, "order_authority_ref": None,
        })
        if remaining == 0:
            data["outcome"] = "settled"
            return "settled", data
    elif event == "write_off":
        data.update({"write_off_reason": str(command.reason)[:300], "outcome": "written_off"})
    return next_status, data


FX_EXPOSURE_LIFECYCLE = LifecycleSpec(entity="fx_exposure", schema_prefix=FX_EXPOSURE_KIND, statuses=FX_STATUSES, terminal=TERMINAL_FX_STATUSES, events=FX_EVENTS, table=_FX_TABLE, opening_event="expose", reason_events=("write_off",), apply=_apply_fx, ledger_model=FxLedger, receipt_model=FxReceipt, effect_boundary_model=FxEffectBoundary, plan_model=FxExposurePlan, max_transitions=MAX_FX_TRANSITIONS)
FxExposureState = FX_EXPOSURE_LIFECYCLE.State


def open_fx_exposure(plan: FxExposurePlan | Mapping[str, Any], scope: Mapping[str, Any], *, receipt: Mapping[str, Any], opened_at: str, actor_ref: str) -> Any:
    return FX_EXPOSURE_LIFECYCLE.open(plan, scope, opened_at=opened_at, actor_ref=actor_ref, receipt=receipt)


def advance_fx_exposure(plan: FxExposurePlan | Mapping[str, Any], state: Any, command: Any) -> Any:
    return FX_EXPOSURE_LIFECYCLE.advance(plan, state, command)


# --------------------------------------------------------------------------- #
# Receipts
# --------------------------------------------------------------------------- #


def _bound(provenance: Mapping[str, Any] | Any, payload: Any, *, tools: frozenset[str], code: str) -> tuple[dict[str, Any], dict[str, Any]]:
    prov = dict(detached(provenance))
    _require(str(prov.get("source_tool", "")) in tools, code, f"expected a read from {sorted(tools)}, got {prov.get('source_tool')!r}")
    for key in ("observation_ref", "provenance_digest", "output_digest", "completed_at"):
        _require(bool(prov.get(key)), code, f"the provenance lacks {key}")
    raw = detached(payload)
    _require(str(prov["output_digest"]) == stable_digest(raw), code, "the provenance does not seal this exact read")
    return prov, raw if isinstance(raw, dict) else {"items": raw}


def exposure_receipt(provenance: Mapping[str, Any] | Any, payload: Any, *, currency: str, account_ref: str) -> dict[str, Any]:
    """From a balance read: the available amount in ``currency`` for ``account_ref`` (the row's account or the whole read)."""

    prov, raw = _bound(provenance, payload, tools=BALANCE_TOOLS, code="EXPOSURE_NOT_PROVEN")
    rows = raw.get("items") if "items" in raw else raw.get("data") if "data" in raw else [raw]
    _require(isinstance(rows, Sequence) and not isinstance(rows, str), "EXPOSURE_NOT_PROVEN", "balances arrive as a list (or {items: [...]})")
    code = str(currency).upper()
    amount = None
    for item in rows:  # type: ignore[union-attr]
        row = dict(detached(item))
        if str(row.get("currency") or row.get("currency_code") or "").upper() != code:
            continue
        if row.get("account_ref") is not None and str(row["account_ref"]) != account_ref:
            continue
        amount = (amount or Decimal("0")) + decimal_value(row.get("available_amount", row.get("available", row.get("balance", row.get("amount", "0")))), field_name="available", allow_negative=True)
    _require(amount is not None, "NO_BALANCE_IN_CURRENCY", f"no balance row in {code} for {account_ref}")
    assert amount is not None
    return {"exposure_currency": code, "account_ref": account_ref, "balance_provenance": prov, "balance_digest": str(prov["output_digest"]), "foreign_amount": str(_money(amount)), "balance_observed_at": timestamp(str(prov.get("window_end") or prov["completed_at"]), field_name="balance_observed_at"), "evidence_refs": [f"balance:{prov['observation_ref']}"]}


def rate_receipt(provenance: Mapping[str, Any] | Any, payload: Mapping[str, Any] | Any, *, base: str, quote: str) -> dict[str, Any]:
    """From a governed rate read: how many units of ``quote`` (the company currency) one unit of ``base`` (the foreign currency) buys."""

    prov, raw = _bound(provenance, payload, tools=RATE_TOOLS, code="RATE_NOT_PROVEN")
    _require(str(raw.get("base") or raw.get("from_currency") or "").upper() == str(base).upper() and str(raw.get("quote") or raw.get("to_currency") or "").upper() == str(quote).upper(), "RATE_PAIR_MISMATCH", f"the read prices {raw.get('base')}/{raw.get('quote')}, not {base}/{quote}")
    rate = raw.get("rate") if raw.get("rate") is not None else raw.get("mid")
    stamp = raw.get("quoted_at") or raw.get("observed_at") or raw.get("timestamp") or prov["completed_at"]
    _require(rate is not None, "RATE_MISSING", "a rate read carries the rate")
    return {"rate_provenance": prov, "rate_digest": str(prov["output_digest"]), "rate": str(_rate(decimal_value(rate, field_name="rate"))), "rate_observed_at": timestamp(str(stamp), field_name="rate_observed_at"), "evidence_refs": [f"rate:{prov['observation_ref']}"]}


def conversion_order_receipt(quote: Mapping[str, Any], *, order_ref: str, foreign_amount: Any) -> dict[str, Any]:
    """The quote (a ``rate_receipt``) plus the order: which foreign amount to sell at that quote."""

    return {**dict(quote), "order_ref": order_ref, "ordered_foreign": str(_money(decimal_value(foreign_amount, field_name="foreign_amount"))), "evidence_refs": [*quote.get("evidence_refs", ()), f"order:{order_ref}"]}


def approval_receipt(proof: Mapping[str, Any] | Any) -> dict[str, Any]:
    from lightbulb.authority_matrix import authorization_evidence

    evidence = authorization_evidence(proof)
    return {"authorization_proof": evidence["authorization_proof"], "evidence_refs": list(evidence["evidence_refs"])}


def conversion_receipt(provenance: Mapping[str, Any] | Any, payload: Mapping[str, Any] | Any) -> dict[str, Any]:
    """From the provider's transaction read: the executed conversion, both legs and the time."""

    prov, raw = _bound(provenance, payload, tools=CONVERSION_TOOLS, code="CONVERSION_NOT_PROVEN")
    ref = raw.get("id") or raw.get("transaction_ref") or raw.get("transfer_ref")
    sold, sold_ccy = raw.get("sell_amount", raw.get("source_amount")), raw.get("sell_currency", raw.get("source_currency"))
    bought, bought_ccy = raw.get("buy_amount", raw.get("target_amount")), raw.get("buy_currency", raw.get("target_currency"))
    stamp = raw.get("completed_at") or raw.get("settled_at") or raw.get("created_at")
    _require(all(item is not None for item in (ref, sold, sold_ccy, bought, bought_ccy, stamp)), "CONVERSION_INCOMPLETE", "a conversion read carries its reference, both legs with their currencies, and the completion time")
    return {"conversion_provenance": prov, "conversion_digest": str(prov["output_digest"]), "conversion_ref": str(ref), "sold_amount": str(_money(decimal_value(sold, field_name="sell_amount"))), "sold_currency": str(sold_ccy).upper(), "bought_amount": str(_money(decimal_value(bought, field_name="buy_amount"))), "bought_currency": str(bought_ccy).upper(), "converted_at": timestamp(str(stamp), field_name="converted_at"), "evidence_refs": [f"conversion:{prov['observation_ref']}"]}


# --------------------------------------------------------------------------- #
# What the chain hands to the other engines
# --------------------------------------------------------------------------- #


def conversion_cost_receipt(state: Any, *, source_plan: Any, centre_ref: str, engine: str | None = None, category: str | None = None) -> dict[str, Any]:
    """The cost register's source receipt for the last conversion: the spread and fees the company actually paid, replayed and keyed by conversion."""

    plan, bound = FX_EXPOSURE_LIFECYCLE.bind(source_plan, state)
    ledger = bound.ledger
    _require(ledger.last_conversion_ref is not None and ledger.last_converted_at is not None, "NO_CONVERSION_RECORDED", "the exposure has not been converted")
    _require(ledger.last_conversion_cost > 0, "NO_CONVERSION_COST", "the last conversion beat its quote; there is no cost to register")
    return {"source_kind": "fx_cost", "source_ref": f"fx_cost:{ledger.exposure_currency}:{ledger.last_conversion_ref}", "source_digest": bound.state_digest, "centre_ref": centre_ref, "amount": str(ledger.last_conversion_cost), "currency": plan.currency, "occurred_at": ledger.last_converted_at, "engine": engine, "category": category, "operator_supplied": engine is not None or category is not None, "source_state": bound.to_dict(), "source_plan": plan.to_dict(), "evidence_refs": [f"fx_exposure:{bound.scope.entity_ref}:{bound.state_digest[:16]}"]}


def company_currency_receipt(state: Any, *, source_plan: Any, foreign_amount: Any) -> dict[str, Any]:
    """What another chain attaches to a foreign-currency settlement: the company-currency amount at this exposure's current observed rate."""

    plan, bound = FX_EXPOSURE_LIFECYCLE.bind(source_plan, state)
    ledger = bound.ledger
    _require(bound.status not in TERMINAL_FX_STATUSES, "EXPOSURE_CLOSED", f"the exposure is {bound.status}")
    amount = _money(decimal_value(foreign_amount, field_name="foreign_amount"))
    _require(amount <= ledger.remaining_foreign, "AMOUNT_EXCEEDS_EXPOSURE", f"{amount} {ledger.exposure_currency} exceeds the remaining exposure {ledger.remaining_foreign}")
    return {"schema": FX_CONVERSION_RECEIPT_SCHEMA, "foreign_amount": str(amount), "foreign_currency": ledger.exposure_currency, "company_amount": str(_money(amount * ledger.current_rate)), "currency": plan.currency, "rate": str(ledger.current_rate), "rate_observed_at": ledger.rate_observed_at, "rate_digest": ledger.rate_digest, "exposure_ref": bound.scope.entity_ref, "source_digest": bound.state_digest}


def fx_exposure_signal(states: Sequence[Any], *, source_plan: Any, emitted_at: str) -> dict[str, Any] | None:
    """``signals.fx_exposure_high`` when the open exposures in one currency exceed the plan's limit, valued at their current rates."""

    plan = FxExposurePlan.model_validate(detached(source_plan)) if not isinstance(source_plan, FxExposurePlan) else source_plan
    if plan.exposure_limit is None:
        return None
    by_currency: dict[str, Decimal] = {}
    refs: dict[str, list[str]] = {}
    for state in states:
        bound_plan, bound = FX_EXPOSURE_LIFECYCLE.bind(source_plan, state)
        if bound.status in TERMINAL_FX_STATUSES:
            continue
        code = str(bound.ledger.exposure_currency)
        by_currency[code] = by_currency.get(code, Decimal("0")) + bound.ledger.current_value
        refs.setdefault(code, []).append(bound.scope.entity_ref)
    worst = max(by_currency.items(), key=lambda item: item[1], default=None)
    if worst is None or worst[1] <= plan.exposure_limit:
        return None
    code, value = worst
    return {"name": "signals.fx_exposure_high", "producer": FX_EXPOSURE_KIND, "emitted_at": timestamp(emitted_at, field_name="emitted_at"), "payload": {"exposure_currency": code, "exposure_value": str(_money(value)), "currency": plan.currency, "exposure_limit": str(plan.exposure_limit), "exposure_refs": sorted(refs[code]), "source_digest": stable_digest(sorted(refs[code]))}}


def exposure_summary(states: Sequence[Any]) -> dict[str, Any]:
    counts = {status: sum(1 for state in states if state.status == status) for status in FX_STATUSES}
    open_states = [state for state in states if state.status not in TERMINAL_FX_STATUSES]
    by_currency: dict[str, dict[str, str]] = {}
    for state in open_states:
        row = by_currency.setdefault(str(state.ledger.exposure_currency), {"foreign": "0.00", "value": "0.00", "unrealised_gain_loss": "0.00"})
        row["foreign"] = str(_money(Decimal(row["foreign"]) + state.ledger.remaining_foreign))
        row["value"] = str(_money(Decimal(row["value"]) + state.ledger.current_value))
        row["unrealised_gain_loss"] = str(_money(Decimal(row["unrealised_gain_loss"]) + state.ledger.unrealised_gain_loss))
    return {"exposures": len(states), "by_status": counts, "by_currency": by_currency, "exposure_value": str(_money(sum((state.ledger.current_value for state in open_states), Decimal("0")))), "conversion_cost_total": str(_money(sum((state.ledger.conversion_cost_total for state in states), Decimal("0")))), "realised_gain_loss": str(_money(sum((state.ledger.realised_gain_loss for state in states), Decimal("0"))))}


FX_EXPOSURE_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": FX_EXPOSURE_KIND,
    "golden_loop": FX_EXPOSURE_GOLDEN_LOOP,
    "stages": ["expose", "revalue", "order_conversion", "convert"],
    "statuses": list(FX_STATUSES),
    "events": list(FX_EVENTS),
    "hops": {"expose": "a balance read for one foreign currency and a fresh governed rate", "revalue": "a newer fresh rate; the unrealised gain or loss computed against the opening rate", "order_conversion": "the foreign amount and the quote; disbursement authority above the threshold", "convert": "the provider's transaction read for the executed conversion, inside the tolerance of the quote"},
    "tools": {"balances": sorted(BALANCE_TOOLS), "rates": sorted(RATE_TOOLS), "conversions": sorted(CONVERSION_TOOLS)},
    "required_connectors": ["airwallex", "lightbulb.sdk_engine_state"],
    "hard_rules": [
        "an exposure is a balance read, never a typed amount; a rate is a governed read no older than the plan allows",
        "the sold amount equals the order and the bought currency is the company currency",
        "the conversion cost is the quote minus the proceeds and lands in the cost register once per conversion",
        "nothing here executes a conversion",
    ],
}

__all__ = ["BALANCE_TOOLS", "CONVERSION_TOOLS", "FX_CONVERSION_RECEIPT_SCHEMA", "FX_EVENTS", "FX_EXPOSURE_GOLDEN_LOOP", "FX_EXPOSURE_KIND", "FX_EXPOSURE_LIFECYCLE", "FX_EXPOSURE_MANIFEST", "FX_STATUSES", "RATE_TOOLS", "TERMINAL_FX_STATUSES", "ConversionRecord", "FxEffectBoundary", "FxExposureError", "FxExposurePlan", "FxExposureState", "FxLedger", "FxReceipt", "advance_fx_exposure", "approval_receipt", "company_currency_receipt", "compile_fx_exposure_chain", "conversion_cost_receipt", "conversion_order_receipt", "conversion_receipt", "exposure_receipt", "exposure_summary", "fx_exposure_signal", "open_fx_exposure", "rate_receipt"]
