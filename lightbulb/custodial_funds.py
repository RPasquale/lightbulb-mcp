"""Recorded seller liabilities reserved against a replayed bank balance.

Custody is a liability register, not revenue. Only a cleared payout can reduce
a recorded seller liability. Treasury receives bank cash less that liability.
The host is responsible for supplying the complete scoped transaction inventory.
"""
from __future__ import annotations

from collections.abc import Mapping
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST, CurrencyCode, EngineScope, LifecycleSpec, OpaqueRef, Sha256Digest,
    StrictModel, decimal_value, detached, parsed, require, seal, sealed_digest,
    skip_digests, stable_digest, timestamp,
)

CUSTODY_KIND = "custodial_funds"
CUSTODY_GOLDEN_LOOP = "marketplace.seller_liability_to_reserved_custody@0.1.0"
CUSTODY_STATUSES = ("balance_recorded", "liabilities_recorded", "reconciled", "shortfall", "closed")
CUSTODY_EVENTS = ("record_balance", "record_liability", "record_payout", "record_refund", "reconcile_custody", "close")


class CustodyError(ValueError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(f"{code}: {message}")


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise CustodyError(code, message)


class CustodyPlan(StrictModel):
    schema_id: Literal["lightbulb.custodial_funds_plan.v1"] = Field(default="lightbulb.custodial_funds_plan.v1", alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    account_ref: OpaqueRef
    max_balance_age_days: int = Field(default=7, ge=0, le=31)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> CustodyPlan:
        if not skip_digests(info) and self.plan_digest != sealed_digest(CustodyPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the custody account and policy")
        return self


def compile_custodial_funds(company_ref: str, *, currency: str, account_ref: str, overrides: Mapping[str, Any] | None = None) -> CustodyPlan:
    changes = dict(overrides or {})
    _require(not set(changes) & {"schema", "plan_digest", "company_ref", "currency", "account_ref"}, "PLAN_OVERRIDE_INVALID", "identity and seals cannot be overridden")
    return seal(CustodyPlan, {"company_ref": company_ref, "currency": currency, "account_ref": account_ref, **changes}, "plan_digest")


class CustodySource(StrictModel):
    state: dict[str, Any]
    plan: dict[str, Any]


def _source(state: Any, plan: Any) -> CustodySource:
    return CustodySource(state=detached(state), plan=detached(plan))


def _scope(left: Any, right: Any) -> bool:
    return all(getattr(left, key) == getattr(right, key) for key in ("tenant_ref", "company_ref", "project_ref", "project_id", "currency"))


def _bank(source: CustodySource) -> tuple[Any, Any]:
    from lightbulb.bank_reconciliation import BANK_REC_LIFECYCLE
    try:
        plan, state = BANK_REC_LIFECYCLE.bind(source.plan, source.state)
    except (ValueError, KeyError) as exc:
        raise CustodyError("CUSTODY_SOURCE_INVALID", "bank balance needs its replayable source state and plan") from exc
    _require(state.status == "reconciled", "BANK_NOT_RECONCILED", "custody needs a reconciled bank balance")
    return plan, state


def balance_receipt(state: Any, *, source_plan: Any) -> dict[str, Any]:
    source = _source(state, source_plan)
    _, bank = _bank(source)
    return {"bank_source": source.to_dict(), "evidence_refs": [f"bank:{bank.state_digest}"]}


def liability_receipt(transaction: Any, *, source_plan: Any) -> dict[str, Any]:
    from lightbulb.marketplace_supply_engine import verify_settled_transaction
    state = verify_settled_transaction(transaction, source_plan=source_plan)
    return {"transaction_source": _source(state, source_plan).to_dict(), "evidence_refs": [f"transaction:{state.state_digest}"]}


def payout_receipt(state: Any, *, source_plan: Any) -> dict[str, Any]:
    from lightbulb.payout_chain import verify_payout_cleared
    payout = verify_payout_cleared(state, source_plan=source_plan)
    return {"payout_source": _source(payout, source_plan).to_dict(), "evidence_refs": [f"payout:{payout.state_digest}"]}


def refund_receipt(state: Any, *, source_plan: Any) -> dict[str, Any]:
    from lightbulb.refund_and_dispute_chain import verify_cleared_refund
    refund = verify_cleared_refund(state, source_plan=source_plan)
    return {"refund_source": _source(refund, source_plan).to_dict(), "evidence_refs": [f"refund:{refund.state_digest}"]}


class CustodyReceipt(StrictModel):
    refund_source: CustodySource | None = None
    entity_scope: EngineScope | None = None
    bank_source: CustodySource | None = None
    transaction_source: CustodySource | None = None
    payout_source: CustodySource | None = None
    evidence_refs: tuple[OpaqueRef, ...] = ()


class SellerLiability(StrictModel):
    refunded: Decimal = Decimal("0.00")
    transaction_ref: OpaqueRef
    seller_ref: OpaqueRef
    source_digest: Sha256Digest
    amount: Decimal
    paid: Decimal = Decimal("0.00")
    settled_at: str

    @field_validator("amount", "paid", "refunded", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @field_validator("settled_at")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="settled_at")


class CustodyLedger(StrictModel):
    refund_sources: tuple[CustodySource, ...] = ()
    refund_refs: tuple[OpaqueRef, ...] = ()
    last_refund_at: str | None = None
    entity_scope: EngineScope | None = None
    bank_source: CustodySource | None = None
    bank_state_digest: Sha256Digest | None = None
    bank_balance: Decimal = Decimal("0.00")
    balance_as_of: str | None = None
    liabilities: tuple[SellerLiability, ...] = ()
    transaction_sources: tuple[CustodySource, ...] = ()
    payout_sources: tuple[CustodySource, ...] = ()
    payout_refs: tuple[OpaqueRef, ...] = ()
    last_payout_at: str | None = None
    liability_total: Decimal = Decimal("0.00")
    custody_shortfall: Decimal = Decimal("0.00")
    operating_cash: Decimal = Decimal("0.00")
    reconciled_at: str | None = None
    source_digests: tuple[Sha256Digest, ...] = ()

    @field_validator("bank_balance", "liability_total", "custody_shortfall", "operating_cash", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class CustodyEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    money_moved: Literal[False] = False
    provider_read: Literal[False] = False


def _apply(plan: CustodyPlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event, at = command.receipt, command.event, command.occurred_at
    if event == "record_balance":
        if status == "new":
            require(r.entity_scope is not None, "CUSTODY_SCOPE_MISSING", "opening custody requires the actual engine scope")
            require(command.expected_state_digest == CUSTODY_LIFECYCLE.state_digest(plan.plan_digest, r.entity_scope, ()), "CUSTODY_SCOPE_MISMATCH", "opening scope belongs to this lifecycle")
            data["entity_scope"] = r.entity_scope.to_dict()
        require(r.bank_source is not None, "CUSTODY_SOURCE_INVALID", "recorded cash comes from a replayed bank balance")
        bp, bank = _bank(r.bank_source)
        scope = EngineScope.model_validate(data["entity_scope"])
        require(_scope(bank.scope, scope) and bp.company_ref == plan.company_ref and bp.currency == plan.currency and bp.account_ref == plan.account_ref, "CUSTODY_SCOPE_MISMATCH", "bank balance belongs to the designated custody account and company")
        moment = bank.ledger.coverage_end or bank.ledger.period_end
        age = (parsed(at) - parsed(moment)).total_seconds() / 86400
        require(0 <= age <= plan.max_balance_age_days, "CUSTODY_BALANCE_STALE", "custody requires a current bank statement")
        data.update(bank_source=r.bank_source.to_dict(), bank_state_digest=bank.state_digest,
                    bank_balance=str(bank.ledger.statement_closing), balance_as_of=moment, reconciled_at=None)
    elif event == "record_liability":
        from lightbulb.marketplace_supply_engine import verify_settled_transaction
        require(r.transaction_source is not None, "LIABILITY_SOURCE_MISSING", "a seller liability comes from a settled transaction")
        source = r.transaction_source
        state = verify_settled_transaction(source.state, source_plan=source.plan, company_ref=plan.company_ref,
                                          currency=plan.currency, expected_scope=data["entity_scope"], at=at)
        rows = list(data.get("liabilities", ()))
        require(state.scope.entity_ref not in {row["transaction_ref"] for row in rows}, "LIABILITY_ALREADY_RECORDED", "a transaction liability is recorded once", "do_not_replay")
        rows.append({"transaction_ref": state.scope.entity_ref, "seller_ref": state.ledger.seller_ref,
                     "source_digest": state.state_digest, "amount": str(state.ledger.seller_liability),
                     "paid": "0.00", "settled_at": state.ledger.settled_at})
        data.update(liabilities=rows, transaction_sources=[*data.get("transaction_sources", ()), source.to_dict()], reconciled_at=None)
    elif event == "record_payout":
        from lightbulb.payout_chain import verify_payout_cleared
        require(r.payout_source is not None, "PAYOUT_SOURCE_MISSING", "seller funds leave custody only on a bank-cleared payout")
        source = r.payout_source
        payout = verify_payout_cleared(source.state, source_plan=source.plan, company_ref=plan.company_ref,
                                       currency=plan.currency, expected_scope=data["entity_scope"], at=at)
        require(payout.scope.entity_ref not in data.get("payout_refs", ()), "PAYOUT_ALREADY_RECORDED", "a payout reduces the liability once", "do_not_replay")
        rows = {row["transaction_ref"]: dict(row) for row in data.get("liabilities", ())}
        for allocation in payout.ledger.allocations:
            allocation = detached(allocation)
            ref = allocation["transaction_ref"]
            require(ref in rows and rows[ref]["seller_ref"] == allocation["seller_ref"], "PAYOUT_LIABILITY_MISMATCH", "the payout must reduce this seller's recorded transaction")
            paid = Decimal(rows[ref]["paid"]) + Decimal(allocation["amount"])
            require(paid <= Decimal(rows[ref]["amount"]) - Decimal(rows[ref].get("refunded", "0")), "PAYOUT_EXCEEDS_LIABILITY", "the seller cannot receive more than the unrefunded recorded liability", "manual_reconciliation")
            rows[ref]["paid"] = str(paid)
        data.update(liabilities=list(rows.values()), payout_sources=[*data.get("payout_sources", ()), source.to_dict()],
                    payout_refs=[*data.get("payout_refs", ()), payout.scope.entity_ref], last_payout_at=max(data.get("last_payout_at") or payout.ledger.settled_at, payout.ledger.settled_at), reconciled_at=None)
    elif event == "record_refund":
        from lightbulb.refund_and_dispute_chain import verify_cleared_refund
        require(r.refund_source is not None, "REFUND_NOT_PROVEN", "a custody adjustment needs its cleared refund and source plan")
        source = r.refund_source
        refund = verify_cleared_refund(source.state, source_plan=source.plan, company_ref=plan.company_ref, currency=plan.currency, expected_scope=data["entity_scope"], at=at)
        require(refund.ledger.origin_kind == "marketplace", "REFUND_SOURCE_MISMATCH", "only marketplace seller liabilities are reserved in custody")
        require(refund.ledger.refund_ref not in data.get("refund_refs", ()), "REFUND_ALREADY_RECORDED", "this refund adjusted custody already", "do_not_replay")
        rows = list(data.get("liabilities", ()))
        matches = [row for row in rows if row["transaction_ref"] == refund.ledger.transaction_ref and row["source_digest"] == refund.ledger.source_transaction_digest]
        require(len(matches) == 1, "REFUND_SOURCE_MISMATCH", "the refund must bind one recorded transaction")
        row = matches[0]
        reduction = refund.ledger.seller_liability_reduction
        remaining = Decimal(row["amount"]) - Decimal(row["paid"]) - Decimal(row.get("refunded", "0"))
        require(reduction <= remaining, "REFUND_EXCEEDS_LIABILITY", "paid seller recovery is a receivable; it cannot release custody twice")
        row["refunded"] = str(Decimal(row.get("refunded", "0")) + reduction)
        data.update(liabilities=rows, refund_sources=[*data.get("refund_sources", ()), source.to_dict()], refund_refs=[*data.get("refund_refs", ()), refund.ledger.refund_ref],
            last_refund_at=max(data.get("last_refund_at") or refund.ledger.cleared_at, refund.ledger.cleared_at), reconciled_at=None)
    elif event == "reconcile_custody":
        require(bool(data.get("liabilities")), "LIABILITIES_MISSING", "reconciliation names the recorded seller liabilities")
        require(all(parsed(row["settled_at"]) <= parsed(data["balance_as_of"]) for row in data["liabilities"]), "BALANCE_BEFORE_LIABILITY", "refresh the bank balance after the recorded settlements")
        require(data.get("last_payout_at") is None or parsed(data["last_payout_at"]) <= parsed(data["balance_as_of"]), "BALANCE_BEFORE_PAYOUT", "refresh the bank balance after a payout before releasing its liability reserve")
        require(data.get("last_refund_at") is None or parsed(data["last_refund_at"]) <= parsed(data["balance_as_of"]), "BALANCE_BEFORE_REFUND", "refresh the bank balance after cash refunds before releasing custody")
        require((parsed(at) - parsed(data["balance_as_of"])).total_seconds() <= plan.max_balance_age_days * 86400, "CUSTODY_BALANCE_STALE", "refresh the custody balance before reconciliation")
        data["reconciled_at"] = at
    elif event == "close":
        require(Decimal(data.get("liability_total", "0")) == 0, "CUSTODY_LIABILITIES_OPEN", "close the register only after every recorded seller liability is paid")
    liability = sum((Decimal(row["amount"]) - Decimal(row["paid"]) - Decimal(row.get("refunded", "0")) for row in data.get("liabilities", ())), Decimal(0))
    balance = Decimal(data.get("bank_balance", "0"))
    data.update(liability_total=str(liability), custody_shortfall=str(max(Decimal(0), liability - balance)), operating_cash=str(balance - liability))
    data["source_digests"] = sorted({data["bank_state_digest"], *[row["source_digest"] for row in data.get("liabilities", ())], *[s["state"]["state_digest"] for s in (*data.get("payout_sources", ()), *data.get("refund_sources", ()))]})
    if event == "reconcile_custody" and liability > balance:
        next_status = "shortfall"
    return next_status, data


def _guarded_apply(plan: Any, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    from lightbulb.company_engine_core import Rejected
    try:
        return _apply(plan, next_status, status, data, command)
    except Rejected:
        raise
    except (ValueError, TypeError, KeyError) as exc:
        require(False, getattr(exc, "code", "CUSTODY_SOURCE_INVALID"), str(exc))


_TABLE = {("new", "record_balance"): "balance_recorded",
          **{(s, "record_balance"): "balance_recorded" for s in CUSTODY_STATUSES if s != "closed"},
          **{(s, "record_liability"): "liabilities_recorded" for s in CUSTODY_STATUSES if s != "closed"},
          **{(s, "record_payout"): "liabilities_recorded" for s in CUSTODY_STATUSES if s != "closed"},
          **{(s, "record_refund"): "liabilities_recorded" for s in CUSTODY_STATUSES if s != "closed"},
          **{(s, "reconcile_custody"): "reconciled" for s in CUSTODY_STATUSES if s != "closed"},
          ("reconciled", "close"): "closed"}
CUSTODY_LIFECYCLE = LifecycleSpec(entity="custody_register", schema_prefix="custodial_funds", statuses=CUSTODY_STATUSES,
    terminal=("closed",), events=CUSTODY_EVENTS, table=_TABLE, opening_event="record_balance", reason_events=(),
    apply=_guarded_apply, ledger_model=CustodyLedger, receipt_model=CustodyReceipt, effect_boundary_model=CustodyEffectBoundary,
    plan_model=CustodyPlan, max_transitions=120)
CustodyState = CUSTODY_LIFECYCLE.State


def open_custody(plan: Any, scope: Mapping[str, Any], *, receipt: Mapping[str, Any], opened_at: str, actor_ref: str) -> Any:
    return CUSTODY_LIFECYCLE.open(plan, scope, receipt={**receipt, "entity_scope": detached(scope)}, opened_at=opened_at, actor_ref=actor_ref)


def advance_custody(plan: Any, state: Any, command: Any) -> Any:
    return CUSTODY_LIFECYCLE.advance(plan, state, command)


def operating_cash_position(state: Any, *, source_plan: Any, at: str) -> Any:
    from lightbulb.company_treasury import CashPosition
    plan, custody = CUSTODY_LIFECYCLE.bind(source_plan, state)
    _require(custody.status in ("reconciled", "closed") and custody.ledger.custody_shortfall == 0, "CUSTODY_SHORTFALL", "unreconciled or underfunded custody cannot fund operations")
    age = (parsed(at) - parsed(custody.ledger.balance_as_of)).total_seconds() / 86400
    _require(0 <= age <= plan.max_balance_age_days and parsed(at) >= parsed(custody.transition_history[-1].command.occurred_at), "CUSTODY_BALANCE_STALE", "operating cash needs a fresh custody balance")
    return CashPosition(source_tool=CUSTODY_KIND, provenance_digest=custody.state_digest,
                        observed_at=custody.ledger.balance_as_of, currency=plan.currency,
                        available=custody.ledger.operating_cash, pending="0.00", accounts=1)


def seller_payable_source_balance(state: Any, *, source_plan: Any) -> Any:
    """Unpaid seller funds in the replayed custody register, for the books."""
    from lightbulb.finance_close_observations import SourceBalance

    _, custody = CUSTODY_LIFECYCLE.bind(source_plan, state)
    _require(custody.status in ("reconciled", "closed"), "CUSTODY_SHORTFALL", "the books consume reconciled custody liabilities")
    return SourceBalance(kind="seller_payable", source_ref=f"custody:{custody.scope.entity_ref}",
                         source_tool=CUSTODY_KIND, provenance_digest=custody.state_digest,
                         balance=custody.ledger.liability_total, items=len(custody.ledger.liabilities),
                         window_end=custody.ledger.balance_as_of)


def custody_summary(state: Any, *, plan: Any) -> dict[str, Any]:
    _, custody = CUSTODY_LIFECYCLE.bind(plan, state)
    return {"custody_ref": custody.scope.entity_ref, "status": custody.status,
            "bank_balance": str(custody.ledger.bank_balance), "seller_liability": str(custody.ledger.liability_total),
            "custody_shortfall": str(custody.ledger.custody_shortfall), "operating_cash": str(custody.ledger.operating_cash),
            "source_digest": custody.state_digest, "source_digests": list(custody.ledger.source_digests),
            "inventory_boundary": "recorded scoped transactions supplied by the host", "effects_executed": False}


CUSTODY_MANIFEST = {"schema": "lightbulb.company_engine_manifest.v1", "engine": CUSTODY_KIND,
    "golden_loop": CUSTODY_GOLDEN_LOOP, "statuses": list(CUSTODY_STATUSES), "events": list(CUSTODY_EVENTS),
    "hard_rules": ["seller liabilities are not company revenue", "operating cash is bank cash less unpaid seller liabilities",
                   "a cleared payout reduces each seller transaction once", "the platform supplies the complete scoped transaction inventory"]}
__all__ = ["CUSTODY_KIND", "CUSTODY_GOLDEN_LOOP", "CUSTODY_STATUSES", "CUSTODY_EVENTS", "CUSTODY_MANIFEST", "CUSTODY_LIFECYCLE",
           "CustodyPlan", "CustodyState", "CustodyReceipt", "CustodyLedger", "CustodySource", "SellerLiability", "CustodyEffectBoundary",
           "CustodyError", "compile_custodial_funds", "open_custody", "advance_custody", "balance_receipt", "liability_receipt",
           "payout_receipt", "refund_receipt", "operating_cash_position", "seller_payable_source_balance", "custody_summary"]
