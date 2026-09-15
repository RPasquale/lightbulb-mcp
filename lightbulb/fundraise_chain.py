"""The fundraise chain: one replay-fenced lifecycle per capital round, from the plan to funds in the bank.

``fundraise_readiness`` says whether the company is default alive and what
its burn multiple is; ``grant_discovery`` finds non-dilutive money.  Nothing
held the round itself: the instrument, the terms and the dilution they
imply against the sealed cap table, each investor's commitment with its
signed paper, the closing decision, and the wires that actually arrived.
``FUNDRAISE_LIFECYCLE`` does:

    planned -> terms_set -> committed -> closed -> funded     (funded terminal)
    planned | terms_set | committed -> abandoned               (terminal, with a reason)

* ``round_receipt`` names the round, its lead, the instrument, and the
  target inside the plan's instruments and minimum size.
* ``terms_receipt`` sets the valuation (pre-money for priced equity, a cap
  and discount for a SAFE or note); the price per share, the shares to issue,
  and the dilution are computed from the sealed cap table and refused above
  the plan's maximum.
* ``commitment_receipt`` records one investor's commitment with the digest
  of the signed subscription; the total never exceeds the target plus the
  allowed oversubscription.
* ``close_round`` is a ``capital`` authority decision for the committed
  total by someone other than the lead, with the closing set's digest.
* ``funds_receipt`` consumes a bank read per investor for exactly their
  commitment; the round is funded when every commitment has arrived.

``expected_inflows`` hands treasury the committed-not-received wires and
``cap_table_after`` states the post-money table.  Nothing here issues
shares, files anything, or persists anything.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import timedelta
from decimal import ROUND_DOWN, ROUND_HALF_UP, Decimal
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
    ShortText,
    StrictModel,
    decimal_value,
    detached,
    iso,
    parsed,
    require,
    seal,
    sealed_digest,
    skip_digests,
    stable_digest,
    timestamp,
    unique,
)

FUNDRAISE_KIND = "fundraise_chain"
FUNDRAISE_GOLDEN_LOOP = "capital.round_planned_to_funds_received@0.1.0"
FUNDRAISE_PLAN_SCHEMA = "lightbulb.fundraise_plan.v1"
EXPECTED_INFLOW_SCHEMA = "lightbulb.fundraise_expected_inflow.v1"
CAP_TABLE_SCHEMA = "lightbulb.cap_table.v1"
MAX_FUNDRAISE_TRANSITIONS = 200
FUNDS_TOOLS: frozenset[str] = frozenset({"xero.list_bank_transactions", "quickbooks.list_deposits", "host.bank_transfer", "airwallex.list_transactions", "host.bank_balances"})
Instrument = Literal["priced_equity", "safe", "convertible_note"]
INSTRUMENTS: tuple[str, ...] = ("priced_equity", "safe", "convertible_note")
PRICE_QUANTUM = Decimal("0.0001")
_HUNDRED = Decimal("100")

FUNDRAISE_STATUSES: tuple[str, ...] = ("planned", "terms_set", "committed", "closed", "funded", "abandoned")
TERMINAL_FUNDRAISE_STATUSES: frozenset[str] = frozenset({"funded", "abandoned"})
FUNDRAISE_EVENTS: tuple[str, ...] = ("plan_round", "set_terms", "record_commitment", "close_round", "receive_funds", "abandon")
_FUNDRAISE_TABLE: dict[tuple[str, str], str] = {
    ("new", "plan_round"): "planned",
    ("planned", "set_terms"): "terms_set",
    ("terms_set", "record_commitment"): "committed",
    ("committed", "record_commitment"): "committed",
    ("committed", "close_round"): "closed",
    ("closed", "receive_funds"): "closed",
    ("planned", "abandon"): "abandoned",
    ("terms_set", "abandon"): "abandoned",
    ("committed", "abandon"): "abandoned",
}


class FundraiseError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise FundraiseError(code, message)


def _money(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


def _percent(value: Decimal) -> Decimal:
    return value.quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


# --------------------------------------------------------------------------- #
# Plan
# --------------------------------------------------------------------------- #


class Holding(StrictModel):
    holder_ref: OpaqueRef
    share_class: ShortText = "ordinary"
    shares: int = Field(ge=1, le=10_000_000_000)


class FundraisePlan(StrictModel):
    """What the chain enforces: the sealed cap table, the instruments the company may use, the dilution it will bear, and the round sizes it will run."""

    schema_id: str = Field(default=FUNDRAISE_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    cap_table: tuple[Holding, ...] = Field(min_length=1, max_length=500)
    instruments: tuple[Instrument, ...] = Field(default=INSTRUMENTS, validate_default=True)
    max_dilution_percent: Decimal = Field(default=Decimal("25"), validate_default=True)
    min_round_size: Decimal = Field(default=Decimal("50000"), validate_default=True)
    oversubscription_percent: Decimal = Field(default=Decimal("20"), validate_default=True)
    settlement_days: int = Field(default=10, ge=1, le=120)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("cap_table", "instruments", mode="before")
    @classmethod
    def _sequences(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("max_dilution_percent", "min_round_size", "oversubscription_percent", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "FundraisePlan":
        unique([f"{item.holder_ref}:{item.share_class}" for item in self.cap_table], label="cap table holdings")
        if not self.instruments:
            raise ValueError("a fundraise plan allows at least one instrument")
        if self.max_dilution_percent >= _HUNDRED:
            raise ValueError("max dilution is a percentage below 100")
        if not skip_digests(info) and self.plan_digest != sealed_digest(FundraisePlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self

    @property
    def fully_diluted_shares(self) -> int:
        return sum(item.shares for item in self.cap_table)


def compile_fundraise_chain(company_ref: str, *, currency: str, cap_table: Sequence[Mapping[str, Any]], overrides: Mapping[str, Any] | None = None) -> FundraisePlan:
    raw: dict[str, Any] = {"company_ref": company_ref, "currency": str(currency).upper(), "cap_table": [dict(detached(item)) for item in cap_table], **dict(overrides or {})}
    return seal(FundraisePlan, raw, "plan_digest")


# --------------------------------------------------------------------------- #
# Receipts, ledger, lifecycle
# --------------------------------------------------------------------------- #


class Commitment(StrictModel):
    investor_ref: OpaqueRef
    amount: Decimal
    evidence_sha256: Sha256Digest
    committed_at: str
    received_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    received_at: str | None = None
    funds_digest: str | None = None

    @field_validator("amount", "received_amount", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))


class FundraiseReceipt(StrictModel):
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    round_ref: OpaqueRef | None = None
    lead_ref: OpaqueRef | None = None
    instrument: Instrument | None = None
    target_amount: Decimal | None = None
    purpose: BoundedText | None = None
    pre_money_valuation: Decimal | None = None
    valuation_cap: Decimal | None = None
    discount_percent: Decimal | None = None
    term_sheet_sha256: Sha256Digest | None = None
    investor_ref: OpaqueRef | None = None
    amount: Decimal | None = None
    evidence_sha256: Sha256Digest | None = None
    authorization_proof: dict[str, Any] | None = None
    closing_sha256: Sha256Digest | None = None
    funds_provenance: dict[str, Any] | None = None
    funds_digest: Sha256Digest | None = None
    received_amount: Decimal | None = None
    received_at: str | None = None
    detail: BoundedText | None = None

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("target_amount", "pre_money_valuation", "valuation_cap", "discount_percent", "amount", "received_amount", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))

    @field_validator("received_at")
    @classmethod
    def _stamps(cls, value: str | None) -> str | None:
        return None if value is None else timestamp(value, field_name="received_at")


class FundraiseLedger(StrictModel):
    round_ref: str | None = None
    lead_ref: str | None = None
    instrument: str | None = None
    target_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    purpose: str | None = None
    planned_at: str | None = None
    pre_money_valuation: Decimal = Field(default=Decimal("0"), validate_default=True)
    valuation_cap: Decimal = Field(default=Decimal("0"), validate_default=True)
    discount_percent: Decimal = Field(default=Decimal("0"), validate_default=True)
    price_per_share: Decimal = Field(default=Decimal("0"), validate_default=True)
    fully_diluted_before: int = 0
    shares_to_issue: int = 0
    dilution_percent: Decimal = Field(default=Decimal("0"), validate_default=True)
    post_money_valuation: Decimal = Field(default=Decimal("0"), validate_default=True)
    term_sheet_sha256: str | None = None
    terms_set_at: str | None = None
    commitments: tuple[Commitment, ...] = Field(default_factory=tuple, max_length=200)
    committed_total: Decimal = Field(default=Decimal("0"), validate_default=True)
    closed_at: str | None = None
    closing_sha256: str | None = None
    closing_authority_ref: str | None = None
    closing_approver_ref: str | None = None
    received_total: Decimal = Field(default=Decimal("0"), validate_default=True)
    funded_at: str | None = None
    abandon_reason: str | None = None
    outcome: Literal["open", "funded", "abandoned"] = "open"

    @field_validator("commitments", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("target_amount", "pre_money_valuation", "valuation_cap", "discount_percent", "dilution_percent", "post_money_valuation", "committed_total", "received_total", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @field_validator("price_per_share", mode="before")
    @classmethod
    def _price(cls, value: Any) -> Decimal:
        return Decimal(str(value)).quantize(PRICE_QUANTUM, rounding=ROUND_HALF_UP)


class FundraiseEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    shares_issued: Literal[False] = False
    filing_made: Literal[False] = False
    money_moved: Literal[False] = False
    provider_read: Literal[False] = False


def _terms(plan: FundraisePlan, instrument: str, target: Decimal, r: FundraiseReceipt) -> dict[str, Any]:
    diluted = plan.fully_diluted_shares
    if instrument == "priced_equity":
        require(r.pre_money_valuation is not None and r.pre_money_valuation > 0, "VALUATION_MISSING", "priced equity names a positive pre-money valuation")
        assert r.pre_money_valuation is not None
        basis = r.pre_money_valuation
        pre_money, cap, discount = r.pre_money_valuation, Decimal("0"), Decimal("0")
    else:
        require(r.valuation_cap is not None and r.valuation_cap > 0, "VALUATION_CAP_MISSING", f"a {instrument} names a positive valuation cap")
        assert r.valuation_cap is not None
        discount = r.discount_percent if r.discount_percent is not None else Decimal("0")
        require(Decimal("0") <= discount < _HUNDRED, "DISCOUNT_INVALID", "a discount is a percentage below 100")
        basis = r.valuation_cap
        pre_money, cap = Decimal("0"), r.valuation_cap
    price = (basis / Decimal(diluted)).quantize(PRICE_QUANTUM, rounding=ROUND_HALF_UP)
    require(price > 0, "PRICE_PER_SHARE_ZERO", "the valuation is too small for the cap table")
    shares = int((target / price).to_integral_value(rounding=ROUND_DOWN))
    dilution = _percent(Decimal(shares) / Decimal(diluted + shares) * _HUNDRED)
    require(dilution <= plan.max_dilution_percent, "DILUTION_ABOVE_PLAN", f"the round dilutes {dilution}%; the plan allows {plan.max_dilution_percent}%")
    return {"pre_money_valuation": str(_money(pre_money)), "valuation_cap": str(_money(cap)), "discount_percent": str(_percent(discount)), "price_per_share": str(price), "fully_diluted_before": diluted, "shares_to_issue": shares, "dilution_percent": str(dilution), "post_money_valuation": str(_money(basis + target))}


def _apply_fundraise(plan: FundraisePlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event, at = command.receipt, command.event, command.occurred_at
    if event == "plan_round":
        require(r.round_ref is not None and r.lead_ref is not None and r.instrument is not None and r.target_amount is not None, "ROUND_MISSING", "a round names itself, its lead, its instrument, and its target")
        require(r.instrument in plan.instruments, "INSTRUMENT_NOT_ALLOWED", f"{r.instrument} is not an instrument this plan allows")
        assert r.target_amount is not None
        require(r.target_amount >= plan.min_round_size, "ROUND_BELOW_MINIMUM", f"a round of {r.target_amount} is below the plan's minimum {plan.min_round_size}")
        data.update({"round_ref": r.round_ref, "lead_ref": r.lead_ref, "instrument": r.instrument, "target_amount": str(_money(r.target_amount)), "purpose": r.purpose, "planned_at": at})
    elif event == "set_terms":
        require(r.term_sheet_sha256 is not None, "TERM_SHEET_MISSING", "terms are set from a term sheet's digest")
        data.update({**_terms(plan, str(data["instrument"]), Decimal(str(data["target_amount"])), r), "term_sheet_sha256": r.term_sheet_sha256, "terms_set_at": at})
    elif event == "record_commitment":
        require(r.investor_ref is not None and r.amount is not None and r.evidence_sha256 is not None, "COMMITMENT_MISSING", "a commitment names the investor, the amount, and the digest of the signed paper")
        assert r.amount is not None
        require(r.amount > 0, "COMMITMENT_INVALID", "a commitment is a positive amount")
        require(all(str(r.investor_ref) != item["investor_ref"] for item in data.get("commitments", ())), "INVESTOR_ALREADY_COMMITTED", f"{r.investor_ref} has already committed to this round")
        target = Decimal(str(data["target_amount"]))
        ceiling = _money(target * (_HUNDRED + plan.oversubscription_percent) / _HUNDRED)
        total = _money(Decimal(str(data["committed_total"])) + r.amount)
        require(total <= ceiling, "ROUND_OVERSUBSCRIBED", f"commitments of {total} exceed the target {target} plus {plan.oversubscription_percent}% oversubscription")
        record = Commitment(investor_ref=str(r.investor_ref), amount=_money(r.amount), evidence_sha256=str(r.evidence_sha256), committed_at=at).to_dict()
        data.update({"commitments": [*[dict(item) for item in data.get("commitments", ())], record], "committed_total": str(total)})
    elif event == "close_round":
        total = Decimal(str(data["committed_total"]))
        require(total >= plan.min_round_size, "ROUND_BELOW_MINIMUM", f"commitments of {total} are below the plan's minimum {plan.min_round_size}")
        require(r.closing_sha256 is not None, "CLOSING_SET_MISSING", "a closing names the digest of the executed closing set")
        require(r.authorization_proof is not None, "CLOSE_NOT_AUTHORIZED", f"closing a {data['instrument']} round for {total} {plan.currency} is a capital decision; a human decides it", "await_approval")
        from lightbulb.authority_matrix import require_authorization_proof

        proof = require_authorization_proof(r.authorization_proof, category="capital", amount=total, currency=plan.currency, command=command, plan_digest=plan.plan_digest, company_ref=plan.company_ref)
        require(proof.engine == FUNDRAISE_KIND, "APPROVAL_TRANSITION_MISMATCH", "the proof authorizes another engine")
        require(proof.approver_ref != data.get("lead_ref"), "SEGREGATION_VIOLATED", "the round's lead cannot approve its closing")
        # the closed round's shares are what the commitments actually buy at the set price
        price = Decimal(str(data["price_per_share"]))
        shares = int((total / price).to_integral_value(rounding=ROUND_DOWN))
        diluted = int(data["fully_diluted_before"])
        data.update({"closed_at": at, "closing_sha256": r.closing_sha256, "closing_authority_ref": proof.approval_task_id, "closing_approver_ref": proof.approver_ref, "shares_to_issue": shares, "dilution_percent": str(_percent(Decimal(shares) / Decimal(diluted + shares) * _HUNDRED))})
    elif event == "receive_funds":
        require(r.investor_ref is not None and r.funds_provenance is not None and r.funds_digest is not None and r.received_amount is not None and r.received_at is not None, "FUNDS_NOT_PROVEN", "funds arrive as a bank read for one investor")
        require(str(dict(r.funds_provenance or {}).get("output_digest")) == r.funds_digest, "FUNDS_NOT_PROVEN", "the provenance does not seal this bank read")
        commitments = [dict(item) for item in data.get("commitments", ())]
        match = next((item for item in commitments if item["investor_ref"] == str(r.investor_ref)), None)
        require(match is not None, "INVESTOR_NOT_COMMITTED", f"{r.investor_ref} has no commitment in this round")
        assert match is not None and r.received_amount is not None
        require(match.get("received_at") is None, "FUNDS_ALREADY_RECEIVED", f"{r.investor_ref}'s funds are already recorded")
        require(_money(r.received_amount) == Decimal(str(match["amount"])), "FUNDS_AMOUNT_MISMATCH", f"{r.investor_ref} committed {match['amount']}; the bank shows {r.received_amount}")
        require(parsed(str(data["closed_at"])) <= parsed(str(r.received_at)) <= parsed(at), "FUNDS_TIME_INVALID", "funds arrive after the closing and before the recording")
        match.update({"received_amount": str(_money(r.received_amount)), "received_at": r.received_at, "funds_digest": r.funds_digest})
        received = _money(sum(Decimal(str(item["received_amount"])) for item in commitments))
        data.update({"commitments": commitments, "received_total": str(received)})
        if all(item.get("received_at") is not None for item in commitments):
            data.update({"funded_at": at, "outcome": "funded"})
            return "funded", data
    elif event == "abandon":
        data.update({"abandon_reason": str(command.reason)[:300], "outcome": "abandoned"})
    return next_status, data


FUNDRAISE_LIFECYCLE = LifecycleSpec(entity="fundraise_round", schema_prefix=FUNDRAISE_KIND, statuses=FUNDRAISE_STATUSES, terminal=TERMINAL_FUNDRAISE_STATUSES, events=FUNDRAISE_EVENTS, table=_FUNDRAISE_TABLE, opening_event="plan_round", reason_events=("abandon",), apply=_apply_fundraise, ledger_model=FundraiseLedger, receipt_model=FundraiseReceipt, effect_boundary_model=FundraiseEffectBoundary, plan_model=FundraisePlan, max_transitions=MAX_FUNDRAISE_TRANSITIONS)
FundraiseState = FUNDRAISE_LIFECYCLE.State


def open_fundraise_round(plan: FundraisePlan | Mapping[str, Any], scope: Mapping[str, Any], *, receipt: Mapping[str, Any], opened_at: str, actor_ref: str) -> Any:
    return FUNDRAISE_LIFECYCLE.open(plan, scope, opened_at=opened_at, actor_ref=actor_ref, receipt=receipt)


def advance_fundraise_round(plan: FundraisePlan | Mapping[str, Any], state: Any, command: Any) -> Any:
    return FUNDRAISE_LIFECYCLE.advance(plan, state, command)


# --------------------------------------------------------------------------- #
# Receipts
# --------------------------------------------------------------------------- #


def round_receipt(*, round_ref: str, lead_ref: str, instrument: str, target_amount: Any, purpose: str | None = None) -> dict[str, Any]:
    _require(instrument in INSTRUMENTS, "INSTRUMENT_UNKNOWN", f"{instrument} is not one of {INSTRUMENTS}")
    return {"round_ref": round_ref, "lead_ref": lead_ref, "instrument": instrument, "target_amount": str(_money(decimal_value(target_amount, field_name="target_amount"))), "purpose": purpose, "evidence_refs": [f"round:{round_ref}"]}


def terms_receipt(*, term_sheet_sha256: str, pre_money_valuation: Any = None, valuation_cap: Any = None, discount_percent: Any = None) -> dict[str, Any]:
    receipt: dict[str, Any] = {"term_sheet_sha256": term_sheet_sha256, "evidence_refs": [f"term_sheet:{term_sheet_sha256[:16]}"]}
    if pre_money_valuation is not None:
        receipt["pre_money_valuation"] = str(_money(decimal_value(pre_money_valuation, field_name="pre_money_valuation")))
    if valuation_cap is not None:
        receipt["valuation_cap"] = str(_money(decimal_value(valuation_cap, field_name="valuation_cap")))
    if discount_percent is not None:
        receipt["discount_percent"] = str(_percent(decimal_value(discount_percent, field_name="discount_percent")))
    return receipt


def commitment_receipt(*, investor_ref: str, amount: Any, evidence_sha256: str) -> dict[str, Any]:
    return {"investor_ref": investor_ref, "amount": str(_money(decimal_value(amount, field_name="amount"))), "evidence_sha256": evidence_sha256, "evidence_refs": [f"subscription:{investor_ref}:{evidence_sha256[:16]}"]}


def closing_receipt(proof: Mapping[str, Any] | Any, *, closing_sha256: str) -> dict[str, Any]:
    from lightbulb.authority_matrix import authorization_evidence

    evidence = authorization_evidence(proof)
    return {"authorization_proof": evidence["authorization_proof"], "closing_sha256": closing_sha256, "evidence_refs": [*evidence["evidence_refs"], f"closing_set:{closing_sha256[:16]}"]}


def funds_receipt(provenance: Mapping[str, Any] | Any, payload: Mapping[str, Any] | Any, *, investor_ref: str) -> dict[str, Any]:
    """From a bank read: one investor's wire."""

    prov = dict(detached(provenance))
    _require(str(prov.get("source_tool", "")) in FUNDS_TOOLS, "FUNDS_NOT_PROVEN", f"expected a read from {sorted(FUNDS_TOOLS)}, got {prov.get('source_tool')!r}")
    for key in ("observation_ref", "provenance_digest", "output_digest", "completed_at"):
        _require(bool(prov.get(key)), "FUNDS_NOT_PROVEN", f"the provenance lacks {key}")
    raw = dict(detached(payload))
    _require(str(prov["output_digest"]) == stable_digest(raw), "FUNDS_NOT_PROVEN", "the provenance does not seal this exact bank read")
    amount = raw.get("amount") if raw.get("amount") is not None else (None if raw.get("amount_minor") is None else Decimal(str(raw["amount_minor"])) / 100)
    stamp = raw.get("received_at") or raw.get("date") or raw.get("completed_at")
    _require(amount is not None and stamp is not None, "FUNDS_INCOMPLETE", "a bank read carries the amount and the time")
    return {"investor_ref": investor_ref, "funds_provenance": prov, "funds_digest": str(prov["output_digest"]), "received_amount": str(_money(decimal_value(amount, field_name="amount"))), "received_at": timestamp(str(stamp), field_name="received_at"), "evidence_refs": [f"funds:{prov['observation_ref']}"]}


# --------------------------------------------------------------------------- #
# What the chain hands to the other engines
# --------------------------------------------------------------------------- #


def expected_inflows(state: Any, *, source_plan: Any) -> list[dict[str, Any]]:
    """Treasury ``receivable`` flows for every commitment in a closed round whose wire has not arrived."""

    plan, bound = FUNDRAISE_LIFECYCLE.bind(source_plan, state)
    _require(bound.status == "closed", "NO_INFLOW_EXPECTED", f"a round that is {bound.status} expects no wires")
    expected_at = iso(parsed(str(bound.ledger.closed_at)) + timedelta(days=plan.settlement_days))
    return [
        {"schema": EXPECTED_INFLOW_SCHEMA, "kind": "receivable", "flow_ref": f"fundraise:{bound.scope.entity_ref}:{item.investor_ref}", "amount": str(item.amount), "currency": plan.currency, "expected_at": expected_at, "basis": f"{bound.ledger.instrument} commitment in the closed round {bound.ledger.round_ref}", "source_digest": bound.state_digest}
        for item in bound.ledger.commitments if item.received_at is None
    ]


def cap_table_after(state: Any, *, source_plan: Any) -> dict[str, Any]:
    """The post-money table: existing holdings plus what each investor's commitment buys at the set price (priced equity), or the convertible instruments outstanding."""

    plan, bound = FUNDRAISE_LIFECYCLE.bind(source_plan, state)
    ledger = bound.ledger
    _require(bound.status in ("closed", "funded"), "ROUND_NOT_CLOSED", f"a round that is {bound.status} has no post-money table")
    holdings = [{"holder_ref": item.holder_ref, "share_class": item.share_class, "shares": item.shares, "instrument": None} for item in plan.cap_table]
    convertibles = []
    if ledger.instrument == "priced_equity":
        for item in ledger.commitments:
            holdings.append({"holder_ref": item.investor_ref, "share_class": f"round:{ledger.round_ref}", "shares": int((item.amount / ledger.price_per_share).to_integral_value(rounding=ROUND_DOWN)), "instrument": "priced_equity"})
    else:
        convertibles = [{"holder_ref": item.investor_ref, "instrument": ledger.instrument, "amount": str(item.amount), "valuation_cap": str(ledger.valuation_cap), "discount_percent": str(ledger.discount_percent)} for item in ledger.commitments]
    total = sum(int(item["shares"]) for item in holdings)
    for item in holdings:
        item["ownership_percent"] = str(_percent(Decimal(item["shares"]) / Decimal(total) * _HUNDRED))
    return {"schema": CAP_TABLE_SCHEMA, "round_ref": ledger.round_ref, "instrument": ledger.instrument, "fully_diluted_shares": total, "holdings": holdings, "convertibles": convertibles, "post_money_valuation": str(ledger.post_money_valuation), "source_digest": bound.state_digest}


def fundraise_summary(states: Sequence[Any]) -> dict[str, Any]:
    counts = {status: sum(1 for state in states if state.status == status) for status in FUNDRAISE_STATUSES}
    return {"rounds": len(states), "by_status": counts, "committed_total": str(_money(sum((state.ledger.committed_total for state in states if state.status in ("committed", "closed", "funded")), Decimal("0")))), "received_total": str(_money(sum((state.ledger.received_total for state in states), Decimal("0")))), "awaiting_funds": [state.scope.entity_ref for state in states if state.status == "closed"]}


FUNDRAISE_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": FUNDRAISE_KIND,
    "golden_loop": FUNDRAISE_GOLDEN_LOOP,
    "stages": ["plan_round", "set_terms", "record_commitment", "close_round", "receive_funds"],
    "statuses": list(FUNDRAISE_STATUSES),
    "events": list(FUNDRAISE_EVENTS),
    "hops": {"plan_round": "the round, its lead, an allowed instrument, a target at or above the minimum", "set_terms": "the term sheet digest and valuation; price, shares, and dilution computed from the sealed cap table", "record_commitment": "one investor, the amount, the signed paper's digest; never beyond the oversubscription ceiling", "close_round": "capital authority for the committed total by someone other than the lead, with the closing set's digest", "receive_funds": "a bank read per investor for exactly their commitment"},
    "tools": {"funds": sorted(FUNDS_TOOLS)},
    "required_connectors": ["xero", "lightbulb.sdk_engine_state"],
    "hard_rules": [
        "dilution is computed from the sealed cap table and never exceeds the plan",
        "the lead never approves the closing",
        "a round is funded only when every commitment's wire is observed for exactly its amount",
        "nothing here issues shares or files anything",
    ],
}

__all__ = ["CAP_TABLE_SCHEMA", "EXPECTED_INFLOW_SCHEMA", "FUNDRAISE_EVENTS", "FUNDRAISE_GOLDEN_LOOP", "FUNDRAISE_KIND", "FUNDRAISE_LIFECYCLE", "FUNDRAISE_MANIFEST", "FUNDRAISE_STATUSES", "FUNDS_TOOLS", "INSTRUMENTS", "TERMINAL_FUNDRAISE_STATUSES", "Commitment", "FundraiseEffectBoundary", "FundraiseError", "FundraiseLedger", "FundraisePlan", "FundraiseReceipt", "FundraiseState", "Holding", "advance_fundraise_round", "cap_table_after", "closing_receipt", "commitment_receipt", "compile_fundraise_chain", "expected_inflows", "funds_receipt", "fundraise_summary", "open_fundraise_round", "round_receipt", "terms_receipt"]
