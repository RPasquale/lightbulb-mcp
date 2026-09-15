"""The insurance claim chain: one replay-fenced lifecycle per insured loss, from the loss to the settlement in the bank.

``obligation_paper`` keeps the company's covers current and proves the
premium was paid.  Nothing held what happened when the cover was needed: the
loss, the policy it fell under, the notice the insurer had to receive in
time, the claim as lodged, what the insurer assessed, and whether the money
arrived.  ``INSURANCE_CLAIM_LIFECYCLE`` does:

    loss_recorded -> notified -> lodged -> assessed -> settled   (terminal)
    lodged | assessed -> declined                                 (terminal)
    loss_recorded | notified | lodged -> withdrawn                (terminal, with a reason)

* ``asset_loss_receipt`` / ``repair_loss_receipt`` open the loss from a
  replayed fixed asset written off or impaired, or from the supplier's
  replayed repair bill; ``cover_receipt`` binds the replayed standing item
  (the policy) that was in force on the loss date, with its limit and excess.
  The claimable amount is computed: the loss less the excess, capped at the
  limit.
* ``notify`` needs the insurer's notice inside the plan's notification
  window; ``lodge`` names the lodgement and never claims above the claimable
  amount; ``assess`` is the insurer's notice; ``settle`` is a bank read for
  exactly the assessed amount.

``expected_inflow`` hands treasury the claim receivable and
``net_loss_receipt`` hands the cost register the loss the company actually
bore.  Nothing here notifies anyone, lodges anything, or persists anything.
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
)

INSURANCE_CLAIM_KIND = "insurance_claim_chain"
INSURANCE_CLAIM_GOLDEN_LOOP = "risk.insured_loss_to_settled_claim@0.1.0"
INSURANCE_CLAIM_PLAN_SCHEMA = "lightbulb.insurance_claim_plan.v1"
EXPECTED_INFLOW_SCHEMA = "lightbulb.insurance_expected_inflow.v1"
MAX_CLAIM_TRANSITIONS = 40
COVER_IN_FORCE_STATUSES: frozenset[str] = frozenset({"current", "renewal_due", "action_prepared", "lodged"})
LOSS_PAYABLE_STATUSES: frozenset[str] = frozenset({"approved", "scheduled", "paid", "cleared"})
SETTLEMENT_TOOLS: frozenset[str] = frozenset({"xero.list_bank_transactions", "quickbooks.list_deposits", "host.bank_transfer", "airwallex.list_transactions", "host.bank_balances"})
LossKind = Literal["asset_write_off", "asset_impairment", "repair_bill"]

CLAIM_STATUSES: tuple[str, ...] = ("loss_recorded", "notified", "lodged", "assessed", "settled", "declined", "withdrawn")
TERMINAL_CLAIM_STATUSES: frozenset[str] = frozenset({"settled", "declined", "withdrawn"})
CLAIM_EVENTS: tuple[str, ...] = ("record_loss", "notify", "lodge", "assess", "settle", "decline", "withdraw")
_CLAIM_TABLE: dict[tuple[str, str], str] = {
    ("new", "record_loss"): "loss_recorded",
    ("loss_recorded", "notify"): "notified",
    ("notified", "lodge"): "lodged",
    ("lodged", "assess"): "assessed",
    ("assessed", "settle"): "settled",
    ("lodged", "decline"): "declined",
    ("assessed", "decline"): "declined",
    ("loss_recorded", "withdraw"): "withdrawn",
    ("notified", "withdraw"): "withdrawn",
    ("lodged", "withdraw"): "withdrawn",
}


class InsuranceClaimError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise InsuranceClaimError(code, message)


def _money(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


# --------------------------------------------------------------------------- #
# Plan
# --------------------------------------------------------------------------- #


class InsuranceClaimPlan(StrictModel):
    """What the chain enforces: how quickly the insurer must be notified, whether cover must be proven, and the smallest loss worth claiming."""

    schema_id: str = Field(default=INSURANCE_CLAIM_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    notification_days: int = Field(default=30, ge=1, le=365)
    require_cover: bool = True
    minimum_claim: Decimal = Field(default=Decimal("0"), validate_default=True)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("minimum_claim", mode="before")
    @classmethod
    def _minimum(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="minimum_claim")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "InsuranceClaimPlan":
        if not skip_digests(info) and self.plan_digest != sealed_digest(InsuranceClaimPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self


def compile_insurance_claim_chain(company_ref: str, *, currency: str, overrides: Mapping[str, Any] | None = None) -> InsuranceClaimPlan:
    raw: dict[str, Any] = {"company_ref": company_ref, "currency": str(currency).upper(), **dict(overrides or {})}
    return seal(InsuranceClaimPlan, raw, "plan_digest")


# --------------------------------------------------------------------------- #
# Receipts, ledger, lifecycle
# --------------------------------------------------------------------------- #


class ClaimReceipt(StrictModel):
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    loss_kind: LossKind | None = None
    loss_ref: OpaqueRef | None = None
    loss_source: dict[str, Any] | None = None
    loss_plan: dict[str, Any] | None = None
    loss_at: str | None = None
    description: BoundedText | None = None
    cover_source: dict[str, Any] | None = None
    cover_plan: dict[str, Any] | None = None
    notified_at: str | None = None
    notice_sha256: Sha256Digest | None = None
    lodgement_ref: OpaqueRef | None = None
    lodged_at: str | None = None
    claimed_amount: Decimal | None = None
    claim_sha256: Sha256Digest | None = None
    assessed_amount: Decimal | None = None
    assessed_at: str | None = None
    assessment_sha256: Sha256Digest | None = None
    settlement_provenance: dict[str, Any] | None = None
    settlement_digest: Sha256Digest | None = None
    settled_amount: Decimal | None = None
    settled_at: str | None = None
    detail: BoundedText | None = None

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("claimed_amount", "assessed_amount", "settled_amount", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))

    @field_validator("loss_at", "notified_at", "lodged_at", "assessed_at", "settled_at")
    @classmethod
    def _stamps(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))


class ClaimLedger(StrictModel):
    loss_kind: str | None = None
    loss_ref: str | None = None
    loss_digest: str | None = None
    loss_at: str | None = None
    description: str | None = None
    loss_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    cover_ref: str | None = None
    cover_kind: str | None = None
    insurer_ref: str | None = None
    cover_digest: str | None = None
    cover_limit: Decimal = Field(default=Decimal("0"), validate_default=True)
    excess: Decimal = Field(default=Decimal("0"), validate_default=True)
    claimable_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    notify_by: str | None = None
    notified_at: str | None = None
    notice_sha256: str | None = None
    lodgement_ref: str | None = None
    lodged_at: str | None = None
    claimed_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    assessed_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    assessed_at: str | None = None
    settled_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    settled_at: str | None = None
    settlement_digest: str | None = None
    net_loss: Decimal = Field(default=Decimal("0"), validate_default=True)
    decline_reason: str | None = None
    withdraw_reason: str | None = None
    outcome: Literal["open", "settled", "declined", "withdrawn"] = "open"

    @field_validator("loss_amount", "cover_limit", "excess", "claimable_amount", "claimed_amount", "assessed_amount", "settled_amount", "net_loss", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))


class ClaimEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    insurer_notified: Literal[False] = False
    claim_lodged: Literal[False] = False
    money_moved: Literal[False] = False
    provider_read: Literal[False] = False


def _bind_loss(plan: InsuranceClaimPlan, r: ClaimReceipt, at: str) -> tuple[Decimal, str]:
    """Replay the loss evidence and return (loss amount, state digest)."""

    if r.loss_kind in ("asset_write_off", "asset_impairment"):
        from lightbulb.fixed_asset_chain import FIXED_ASSET_LIFECYCLE

        try:
            asset_plan, asset = FIXED_ASSET_LIFECYCLE.bind(r.loss_plan, r.loss_source)
        except (ValueError, TypeError, KeyError) as exc:
            require(False, "LOSS_NOT_PROVEN", f"the asset must replay against its exact plan: {exc}"[:300])
            raise AssertionError from exc
        require(asset_plan.company_ref == plan.company_ref and asset_plan.currency == plan.currency, "LOSS_SCOPE_MISMATCH", "the asset belongs to another company or currency")
        require(parsed(asset.transition_history[-1].command.occurred_at) <= parsed(at), "LOSS_FROM_FUTURE", "the loss cannot come from the future")
        if r.loss_kind == "asset_write_off":
            require(asset.status == "written_off", "LOSS_NOT_PROVEN", f"the asset is {asset.status}, not written off")
            return _money(-asset.ledger.gain_loss), asset.state_digest
        require(asset.ledger.impairments > 0, "LOSS_NOT_PROVEN", "the asset carries no impairment")
        return _money(asset.ledger.impairments), asset.state_digest
    from lightbulb.payables_chain import PAYABLES_CHAIN_LIFECYCLE

    try:
        bill_plan, bill = PAYABLES_CHAIN_LIFECYCLE.bind(r.loss_plan, r.loss_source)
    except (ValueError, TypeError, KeyError) as exc:
        require(False, "LOSS_NOT_PROVEN", f"the repair bill must replay against its exact plan: {exc}"[:300])
        raise AssertionError from exc
    require(bill_plan.company_ref == plan.company_ref and bill.scope.currency == plan.currency, "LOSS_SCOPE_MISMATCH", "the bill belongs to another company or currency")
    require(bill.status in LOSS_PAYABLE_STATUSES, "LOSS_NOT_PROVEN", f"the repair bill is {bill.status}; a loss is an approved bill")
    require(parsed(bill.transition_history[-1].command.occurred_at) <= parsed(at), "LOSS_FROM_FUTURE", "the loss cannot come from the future")
    return _money(bill.ledger.amount), bill.state_digest


def _bind_cover(plan: InsuranceClaimPlan, r: ClaimReceipt, loss_at: str) -> dict[str, Any]:
    from lightbulb.obligation_paper import INSURANCE_KINDS, STANDING_LIFECYCLE

    try:
        paper_plan, cover = STANDING_LIFECYCLE.bind(r.cover_plan, r.cover_source)
    except (ValueError, TypeError, KeyError) as exc:
        require(False, "COVER_NOT_PROVEN", f"the cover must replay against its exact plan: {exc}"[:300])
        raise AssertionError from exc
    ledger = cover.ledger
    require(paper_plan.company_ref == plan.company_ref and paper_plan.currency == plan.currency, "COVER_SCOPE_MISMATCH", "the cover belongs to another company or currency")
    require(ledger.kind in INSURANCE_KINDS, "COVER_NOT_INSURANCE", f"{ledger.kind} is not an insurance cover")
    require(cover.status in COVER_IN_FORCE_STATUSES, "COVER_NOT_IN_FORCE", f"the cover is {cover.status}")
    require(ledger.premium_digest is not None, "PREMIUM_NOT_PAID", "the cover's premium has not been proven paid")
    require(ledger.period_start is not None and ledger.period_end is not None and parsed(str(ledger.period_start)) <= parsed(loss_at) < parsed(str(ledger.period_end)), "LOSS_OUTSIDE_COVER_PERIOD", "the loss falls outside the cover period")
    return {"cover_ref": ledger.item_ref, "cover_kind": ledger.kind, "insurer_ref": ledger.insurer_ref, "cover_digest": cover.state_digest, "cover_limit": str(_money(ledger.limit)), "excess": str(_money(ledger.excess))}


def _apply_claim(plan: InsuranceClaimPlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event, at = command.receipt, command.event, command.occurred_at
    if event == "record_loss":
        require(r.loss_kind is not None and r.loss_ref is not None and r.loss_source is not None and r.loss_plan is not None and r.loss_at is not None, "LOSS_NOT_PROVEN", "a loss is a replayed asset write-off, impairment, or repair bill with the date it happened")
        require(parsed(str(r.loss_at)) <= parsed(at), "LOSS_FROM_FUTURE", "the loss cannot come from the future")
        loss, loss_digest = _bind_loss(plan, r, at)
        require(loss > 0, "LOSS_EMPTY", "a loss is a positive amount")
        cover: dict[str, Any] = {"cover_limit": "0", "excess": "0"}
        if plan.require_cover or r.cover_source is not None:
            require(r.cover_source is not None and r.cover_plan is not None, "COVER_NOT_PROVEN", "the plan requires the replayed cover the loss falls under")
            cover = _bind_cover(plan, r, str(r.loss_at))
        claimable = _money(max(min(loss - Decimal(cover["excess"]), Decimal(cover["cover_limit"])), Decimal("0"))) if cover.get("cover_ref") else Decimal("0.00")
        require(claimable >= plan.minimum_claim, "BELOW_MINIMUM_CLAIM", f"the claimable amount {claimable} is below the plan's minimum {plan.minimum_claim}", "correct_input")
        data.update({"loss_kind": r.loss_kind, "loss_ref": r.loss_ref, "loss_digest": loss_digest, "loss_at": r.loss_at, "description": r.description, "loss_amount": str(loss), "claimable_amount": str(claimable), "net_loss": str(loss), "notify_by": (parsed(str(r.loss_at)) + timedelta(days=plan.notification_days)).isoformat().replace("+00:00", "Z"), **cover})
    elif event == "notify":
        require(r.notified_at is not None and r.notice_sha256 is not None, "NOTICE_MISSING", "notification names when the insurer was told and the notice's digest")
        require(parsed(str(data["loss_at"])) <= parsed(str(r.notified_at)) <= parsed(at), "NOTICE_TIME_INVALID", "the notice follows the loss and precedes the recording")
        require(parsed(str(r.notified_at)) <= parsed(str(data["notify_by"])), "NOTIFICATION_LATE", f"the insurer had to be notified by {data['notify_by']}", "manual_reconciliation")
        data.update({"notified_at": r.notified_at, "notice_sha256": r.notice_sha256})
    elif event == "lodge":
        require(r.lodgement_ref is not None and r.lodged_at is not None and r.claimed_amount is not None and r.claim_sha256 is not None, "LODGEMENT_MISSING", "a lodgement names its reference, time, amount, and the claim's digest")
        assert r.claimed_amount is not None
        require(0 < r.claimed_amount <= Decimal(str(data["claimable_amount"])), "CLAIM_ABOVE_CLAIMABLE", f"the claim of {r.claimed_amount} exceeds the claimable {data['claimable_amount']} (loss less excess, capped at the limit)")
        require(parsed(str(data["notified_at"])) <= parsed(str(r.lodged_at)) <= parsed(at), "LODGEMENT_TIME_INVALID", "the lodgement follows the notice")
        data.update({"lodgement_ref": r.lodgement_ref, "lodged_at": r.lodged_at, "claimed_amount": str(_money(r.claimed_amount))})
    elif event == "assess":
        require(r.assessed_amount is not None and r.assessed_at is not None and r.assessment_sha256 is not None, "ASSESSMENT_MISSING", "an assessment is the insurer's notice: amount, time, digest")
        assert r.assessed_amount is not None
        require(0 < r.assessed_amount <= Decimal(str(data["claimed_amount"])), "ASSESSED_ABOVE_CLAIMED", "the insurer never assesses more than was claimed; a zero assessment is a decline")
        require(parsed(str(data["lodged_at"])) <= parsed(str(r.assessed_at)) <= parsed(at), "ASSESSMENT_TIME_INVALID", "the assessment follows the lodgement")
        data.update({"assessed_amount": str(_money(r.assessed_amount)), "assessed_at": r.assessed_at})
    elif event == "settle":
        require(r.settlement_provenance is not None and r.settlement_digest is not None and r.settled_amount is not None and r.settled_at is not None, "SETTLEMENT_NOT_PROVEN", "a settlement is a bank read")
        require(str(dict(r.settlement_provenance or {}).get("output_digest")) == r.settlement_digest, "SETTLEMENT_NOT_PROVEN", "the provenance does not seal this bank read")
        assert r.settled_amount is not None
        require(_money(r.settled_amount) == Decimal(str(data["assessed_amount"])), "SETTLEMENT_AMOUNT_MISMATCH", f"the insurer assessed {data['assessed_amount']}; the bank shows {r.settled_amount}")
        require(parsed(str(data["assessed_at"])) <= parsed(str(r.settled_at)) <= parsed(at), "SETTLEMENT_TIME_INVALID", "the settlement follows the assessment")
        data.update({"settled_amount": str(_money(r.settled_amount)), "settled_at": r.settled_at, "settlement_digest": r.settlement_digest, "net_loss": str(_money(Decimal(str(data["loss_amount"])) - r.settled_amount)), "outcome": "settled"})
    elif event == "decline":
        data.update({"decline_reason": str(command.reason)[:300], "outcome": "declined"})
    elif event == "withdraw":
        data.update({"withdraw_reason": str(command.reason)[:300], "outcome": "withdrawn"})
    return next_status, data


INSURANCE_CLAIM_LIFECYCLE = LifecycleSpec(entity="insurance_claim", schema_prefix=INSURANCE_CLAIM_KIND, statuses=CLAIM_STATUSES, terminal=TERMINAL_CLAIM_STATUSES, events=CLAIM_EVENTS, table=_CLAIM_TABLE, opening_event="record_loss", reason_events=("decline", "withdraw"), apply=_apply_claim, ledger_model=ClaimLedger, receipt_model=ClaimReceipt, effect_boundary_model=ClaimEffectBoundary, plan_model=InsuranceClaimPlan, max_transitions=MAX_CLAIM_TRANSITIONS)
InsuranceClaimState = INSURANCE_CLAIM_LIFECYCLE.State


def open_insurance_claim(plan: InsuranceClaimPlan | Mapping[str, Any], scope: Mapping[str, Any], *, receipt: Mapping[str, Any], opened_at: str, actor_ref: str) -> Any:
    return INSURANCE_CLAIM_LIFECYCLE.open(plan, scope, opened_at=opened_at, actor_ref=actor_ref, receipt=receipt)


def advance_insurance_claim(plan: InsuranceClaimPlan | Mapping[str, Any], state: Any, command: Any) -> Any:
    return INSURANCE_CLAIM_LIFECYCLE.advance(plan, state, command)


# --------------------------------------------------------------------------- #
# Receipts
# --------------------------------------------------------------------------- #


def asset_loss_receipt(asset_state: Any, *, source_plan: Any, loss_at: str, kind: str = "asset_write_off", description: str | None = None) -> dict[str, Any]:
    from lightbulb.fixed_asset_chain import FIXED_ASSET_LIFECYCLE

    _require(kind in ("asset_write_off", "asset_impairment"), "LOSS_KIND_UNKNOWN", "an asset loss is a write-off or an impairment")
    try:
        plan, state = FIXED_ASSET_LIFECYCLE.bind(source_plan, asset_state)
    except (ValueError, TypeError, KeyError) as exc:
        raise InsuranceClaimError("LOSS_NOT_PROVEN", "retain the original asset state and its sealed plan") from exc
    return {"loss_kind": kind, "loss_ref": f"asset:{state.scope.entity_ref}", "loss_source": state.to_dict(), "loss_plan": plan.to_dict(), "loss_at": timestamp(loss_at, field_name="loss_at"), "description": description, "evidence_refs": [f"fixed_asset:{state.scope.entity_ref}:{state.state_digest[:16]}"]}


def repair_loss_receipt(payable_state: Any, *, source_plan: Any, loss_at: str, description: str | None = None) -> dict[str, Any]:
    from lightbulb.payables_chain import PAYABLES_CHAIN_LIFECYCLE

    try:
        plan, state = PAYABLES_CHAIN_LIFECYCLE.bind(source_plan, payable_state)
    except (ValueError, TypeError, KeyError) as exc:
        raise InsuranceClaimError("LOSS_NOT_PROVEN", "retain the original payable state and its sealed plan") from exc
    _require(state.status in LOSS_PAYABLE_STATUSES, "LOSS_NOT_PROVEN", f"the repair bill is {state.status}")
    return {"loss_kind": "repair_bill", "loss_ref": f"payable:{state.scope.entity_ref}", "loss_source": state.to_dict(), "loss_plan": plan.to_dict(), "loss_at": timestamp(loss_at, field_name="loss_at"), "description": description, "evidence_refs": [f"payable:{state.scope.entity_ref}:{state.state_digest[:16]}"]}


def cover_receipt(standing_state: Any, *, source_plan: Any) -> dict[str, Any]:
    """The replayed standing item (policy) the loss falls under; merge with the loss receipt to open the claim."""

    from lightbulb.obligation_paper import STANDING_LIFECYCLE

    try:
        plan, state = STANDING_LIFECYCLE.bind(source_plan, standing_state)
    except (ValueError, TypeError, KeyError) as exc:
        raise InsuranceClaimError("COVER_NOT_PROVEN", "retain the original standing item state and its sealed plan") from exc
    return {"cover_source": state.to_dict(), "cover_plan": plan.to_dict(), "evidence_refs": [f"cover:{state.scope.entity_ref}:{state.state_digest[:16]}"]}


def notice_receipt(*, notified_at: str, notice_sha256: str) -> dict[str, Any]:
    return {"notified_at": timestamp(notified_at, field_name="notified_at"), "notice_sha256": notice_sha256, "evidence_refs": [f"notice:{notice_sha256[:16]}"]}


def lodgement_receipt(*, lodgement_ref: str, lodged_at: str, claimed_amount: Any, claim_sha256: str) -> dict[str, Any]:
    return {"lodgement_ref": lodgement_ref, "lodged_at": timestamp(lodged_at, field_name="lodged_at"), "claimed_amount": str(_money(decimal_value(claimed_amount, field_name="claimed_amount"))), "claim_sha256": claim_sha256, "evidence_refs": [f"lodgement:{lodgement_ref}"]}


def assessment_receipt(*, assessed_amount: Any, assessed_at: str, assessment_sha256: str) -> dict[str, Any]:
    return {"assessed_amount": str(_money(decimal_value(assessed_amount, field_name="assessed_amount"))), "assessed_at": timestamp(assessed_at, field_name="assessed_at"), "assessment_sha256": assessment_sha256, "evidence_refs": [f"assessment:{assessment_sha256[:16]}"]}


def settlement_receipt(provenance: Mapping[str, Any] | Any, payload: Mapping[str, Any] | Any) -> dict[str, Any]:
    """From a bank read: the insurer's settlement."""

    prov = dict(detached(provenance))
    _require(str(prov.get("source_tool", "")) in SETTLEMENT_TOOLS, "SETTLEMENT_NOT_PROVEN", f"expected a read from {sorted(SETTLEMENT_TOOLS)}, got {prov.get('source_tool')!r}")
    for key in ("observation_ref", "provenance_digest", "output_digest", "completed_at"):
        _require(bool(prov.get(key)), "SETTLEMENT_NOT_PROVEN", f"the provenance lacks {key}")
    raw = dict(detached(payload))
    _require(str(prov["output_digest"]) == stable_digest(raw), "SETTLEMENT_NOT_PROVEN", "the provenance does not seal this exact bank read")
    amount = raw.get("amount") if raw.get("amount") is not None else (None if raw.get("amount_minor") is None else Decimal(str(raw["amount_minor"])) / 100)
    stamp = raw.get("received_at") or raw.get("date") or raw.get("completed_at")
    _require(amount is not None and stamp is not None, "SETTLEMENT_INCOMPLETE", "a bank read carries the amount and the time")
    return {"settlement_provenance": prov, "settlement_digest": str(prov["output_digest"]), "settled_amount": str(_money(decimal_value(amount, field_name="amount"))), "settled_at": timestamp(str(stamp), field_name="settled_at"), "evidence_refs": [f"settlement:{prov['observation_ref']}"]}


# --------------------------------------------------------------------------- #
# What the chain hands to the other engines
# --------------------------------------------------------------------------- #


def expected_inflow(state: Any, *, source_plan: Any, expected_at: str) -> dict[str, Any]:
    """A treasury ``receivable`` for a lodged or assessed claim: the assessed amount when known, else the amount claimed."""

    plan, bound = INSURANCE_CLAIM_LIFECYCLE.bind(source_plan, state)
    ledger = bound.ledger
    _require(bound.status in ("lodged", "assessed"), "NO_INFLOW_EXPECTED", f"a claim that is {bound.status} expects no settlement")
    amount = ledger.assessed_amount if bound.status == "assessed" else ledger.claimed_amount
    return {"schema": EXPECTED_INFLOW_SCHEMA, "kind": "receivable", "flow_ref": f"insurance:{bound.scope.entity_ref}", "amount": str(_money(amount)), "currency": plan.currency, "expected_at": timestamp(expected_at, field_name="expected_at"), "basis": "assessed by the insurer" if bound.status == "assessed" else "claimed; not yet assessed", "source_digest": bound.state_digest}


def net_loss_receipt(state: Any, *, source_plan: Any, centre_ref: str, engine: str | None = None, category: str | None = None) -> dict[str, Any]:
    """The cost register's source receipt for the loss the company bore after the insurer paid (or declined): replayed, keyed by claim."""

    plan, bound = INSURANCE_CLAIM_LIFECYCLE.bind(source_plan, state)
    ledger = bound.ledger
    _require(bound.status in ("settled", "declined"), "CLAIM_NOT_FINAL", f"a claim that is {bound.status} has no final net loss")
    _require(ledger.net_loss > 0, "NO_NET_LOSS", "the insurer covered the whole loss")
    occurred_at = ledger.settled_at or bound.transition_history[-1].command.occurred_at
    return {"source_kind": "insured_loss", "source_ref": f"insured_loss:{bound.scope.entity_ref}", "source_digest": bound.state_digest, "centre_ref": centre_ref, "amount": str(ledger.net_loss), "currency": plan.currency, "occurred_at": occurred_at, "engine": engine, "category": category, "operator_supplied": engine is not None or category is not None, "source_state": bound.to_dict(), "source_plan": plan.to_dict(), "evidence_refs": [f"insurance_claim:{bound.scope.entity_ref}:{bound.state_digest[:16]}"]}


def notification_due_signal(states: Sequence[Any], *, source_plan: Any, now: str, within_days: int = 7) -> dict[str, Any] | None:
    """``signals.claim_notification_due`` for recorded losses whose insurer notice is due within ``within_days`` (or already late)."""

    plan = InsuranceClaimPlan.model_validate(detached(source_plan)) if not isinstance(source_plan, InsuranceClaimPlan) else source_plan
    stamp = timestamp(now, field_name="now")
    horizon = parsed(stamp) + timedelta(days=within_days)
    due = []
    for state in states:
        _plan, bound = INSURANCE_CLAIM_LIFECYCLE.bind(source_plan, state)
        if bound.status == "loss_recorded" and bound.ledger.notify_by is not None and parsed(str(bound.ledger.notify_by)) <= horizon:
            due.append({"claim_ref": bound.scope.entity_ref, "notify_by": bound.ledger.notify_by, "claimable_amount": str(bound.ledger.claimable_amount), "late": parsed(str(bound.ledger.notify_by)) < parsed(stamp)})
    if not due:
        return None
    due.sort(key=lambda item: str(item["notify_by"]))
    return {"name": "signals.claim_notification_due", "producer": INSURANCE_CLAIM_KIND, "emitted_at": stamp, "payload": {"claim_refs": [item["claim_ref"] for item in due], "earliest_notify_by": due[0]["notify_by"], "claimable_total": str(_money(sum(Decimal(item["claimable_amount"]) for item in due))), "currency": plan.currency, "late_count": sum(1 for item in due if item["late"]), "source_digest": stable_digest(due)}}


def claims_summary(states: Sequence[Any]) -> dict[str, Any]:
    counts = {status: sum(1 for state in states if state.status == status) for status in CLAIM_STATUSES}
    return {"claims": len(states), "by_status": counts, "loss_total": str(_money(sum((state.ledger.loss_amount for state in states), Decimal("0")))), "claimable_total": str(_money(sum((state.ledger.claimable_amount for state in states), Decimal("0")))), "recovered_total": str(_money(sum((state.ledger.settled_amount for state in states), Decimal("0")))), "net_loss_total": str(_money(sum((state.ledger.net_loss for state in states if state.status in ("settled", "declined")), Decimal("0")))), "awaiting_insurer": [state.scope.entity_ref for state in states if state.status in ("lodged", "assessed")]}


INSURANCE_CLAIM_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": INSURANCE_CLAIM_KIND,
    "golden_loop": INSURANCE_CLAIM_GOLDEN_LOOP,
    "stages": ["record_loss", "notify", "lodge", "assess", "settle"],
    "statuses": list(CLAIM_STATUSES),
    "events": list(CLAIM_EVENTS),
    "hops": {"record_loss": "a replayed asset write-off, impairment, or repair bill, under the replayed cover in force on the loss date; claimable computed", "notify": "the insurer's notice inside the notification window", "lodge": "the lodgement, never above the claimable amount", "assess": "the insurer's assessment notice, never above the claim", "settle": "a bank read for exactly the assessed amount"},
    "tools": {"settlements": sorted(SETTLEMENT_TOOLS)},
    "required_connectors": ["xero", "lightbulb.sdk_engine_state"],
    "hard_rules": [
        "a loss is a replayed asset or bill, never a typed amount; the cover is the replayed policy in force on the loss date with its premium proven paid",
        "claimable is the loss less the excess capped at the limit, and the claim never exceeds it",
        "the net loss the company bore reaches the cost register once, after the insurer's final answer",
        "nothing here notifies an insurer or lodges a claim",
    ],
}

__all__ = ["CLAIM_EVENTS", "CLAIM_STATUSES", "COVER_IN_FORCE_STATUSES", "EXPECTED_INFLOW_SCHEMA", "INSURANCE_CLAIM_GOLDEN_LOOP", "INSURANCE_CLAIM_KIND", "INSURANCE_CLAIM_LIFECYCLE", "INSURANCE_CLAIM_MANIFEST", "LOSS_PAYABLE_STATUSES", "SETTLEMENT_TOOLS", "TERMINAL_CLAIM_STATUSES", "ClaimEffectBoundary", "ClaimLedger", "ClaimReceipt", "InsuranceClaimError", "InsuranceClaimPlan", "InsuranceClaimState", "advance_insurance_claim", "assessment_receipt", "asset_loss_receipt", "claims_summary", "compile_insurance_claim_chain", "cover_receipt", "expected_inflow", "lodgement_receipt", "net_loss_receipt", "notice_receipt", "notification_due_signal", "open_insurance_claim", "repair_loss_receipt", "settlement_receipt"]
