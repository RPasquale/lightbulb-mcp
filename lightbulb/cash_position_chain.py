"""The cash position chain: one replay-fenced lifecycle per treasury period, from observed balances to a reviewed cash forecast.

``company_treasury`` can lay a weekly forecast from a balance read and a
list of flows; ``cash_runway`` turns observed burn into a budget envelope.
Neither held the period: which accounts were read and when, which of the
other chains' expectations (an incentive claim's inflow, a refund a
returned order now owes, the supplier bill a purchase will attract, the
wires a closed round is waiting for) went into the forecast, who prepared
it, and who reviewed the breach.  ``CASH_POSITION_LIFECYCLE`` does:

    opened -> balances_observed -> (bind_expectation)* -> projected -> reviewed -> closed   (terminal)
    projected -> bind_expectation -> balances_observed   (a new expectation invalidates the forecast)

* ``balance_receipt`` binds one account's balance read; every account in
  the plan must be observed, inside the freshness window, before the period
  projects.
* ``expectation_receipt`` binds another chain's hand-off to the replayed
  state that produced it: the digest must match, the currency must be the
  company's, and each flow enters once.
* ``project`` computes the weekly forecast through ``company_treasury``
  from the summed balances and the bound expectations; the floor comes from
  the plan and the forecast digest is sealed into the ledger.
* ``review`` is by someone other than the preparer; a forecast that breaches
  the floor is reviewed only with a stated response.

``cash_floor_signal`` emits ``signals.cash_floor_breach`` and
``cash_cover_receipt`` answers whether one more outflow is covered.  Nothing
here moves money, reads a provider, or persists anything.
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
    ShortText,
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

CASH_POSITION_KIND = "cash_position_chain"
CASH_POSITION_GOLDEN_LOOP = "finance.observed_balances_to_reviewed_cash_forecast@0.1.0"
CASH_POSITION_PLAN_SCHEMA = "lightbulb.cash_position_plan.v1"
MAX_CASH_POSITION_TRANSITIONS = 400
BALANCE_TOOLS: frozenset[str] = frozenset({"airwallex.list_balances", "xero.list_bank_transactions", "quickbooks.list_accounts", "host.bank_balances"})
#: Hand-off schemas the period accepts, with the engine whose replayed state proves them and the flow direction.
EXPECTATION_SCHEMAS: Mapping[str, tuple[str, str]] = {
    "lightbulb.incentive_expected_inflow.v1": ("incentive_claim_chain", "receivable"),
    "lightbulb.fundraise_expected_inflow.v1": ("fundraise_chain", "receivable"),
    "lightbulb.fulfilment_refund_expectation.v1": ("fulfilment_chain", "payable"),
    "lightbulb.inventory_expected_bill.v1": ("inventory_chain", "payable"),
    "lightbulb.insurance_expected_inflow.v1": ("insurance_claim_chain", "receivable"),
    "lightbulb.compliance_expected_outflow.v1": ("compliance_obligation", "payable"),
    "lightbulb.commission_expected_outflow.v1": ("partner_commission_chain", "payable"),
    "lightbulb.payroll_expected_outflow.v1": ("payroll_run_chain", "payable"),
    "lightbulb.prepayment_expected_outflow.v1": ("prepayment_chain", "payable"),
    "lightbulb.payable_expected_outflow.v1": ("payables_chain", "payable"),
    "lightbulb.receivable_expected_inflow.v1": ("collections_chain", "receivable"),
    "lightbulb.commitment_expected_outflow.v1": ("vendor_commitment", "payable"),
}
#: How each lifecycle hand-off is re-derived from the replayed state: schema -> (module, producer, takes expected_at).
EXPECTATION_PRODUCERS: Mapping[str, tuple[str, str, bool]] = {
    "lightbulb.incentive_expected_inflow.v1": ("lightbulb.incentive_claim_chain", "expected_inflow", True),
    "lightbulb.fundraise_expected_inflow.v1": ("lightbulb.fundraise_chain", "expected_inflows", False),
    "lightbulb.fulfilment_refund_expectation.v1": ("lightbulb.fulfilment_chain", "refund_expectation", False),
    "lightbulb.inventory_expected_bill.v1": ("lightbulb.inventory_chain", "expected_bill", False),
    "lightbulb.insurance_expected_inflow.v1": ("lightbulb.insurance_claim_chain", "expected_inflow", True),
    "lightbulb.compliance_expected_outflow.v1": ("lightbulb.compliance_calendar", "obligation_expectation", False),
    "lightbulb.commission_expected_outflow.v1": ("lightbulb.partner_commission_chain", "commission_expectation", True),
    "lightbulb.payroll_expected_outflow.v1": ("lightbulb.payroll_run_chain", "pay_run_expectation", False),
    "lightbulb.prepayment_expected_outflow.v1": ("lightbulb.prepayment_chain", "refund_expectation", False),
    "lightbulb.payable_expected_outflow.v1": ("lightbulb.payables_chain", "bill_expectation", False),
    "lightbulb.receivable_expected_inflow.v1": ("lightbulb.collections_chain", "receivable_expectation", False),
    "lightbulb.commitment_expected_outflow.v1": ("lightbulb.spend_control_chain", "commitment_expectation", False),
}
#: Sealed documents (not lifecycles) whose hand-offs the period accepts: schema -> (module, model class, digest field, direction).
EXPECTATION_DOCUMENTS: Mapping[str, tuple[str, str, str, str]] = {
    "lightbulb.revenue_expected_inflow.v1": ("growth_revenue_model", "RevenueModel", "model_digest", "receivable"),
}
FlowDirection = Literal["receivable", "payable"]

CASH_STATUSES: tuple[str, ...] = ("opened", "balances_observed", "projected", "reviewed", "closed")
TERMINAL_CASH_STATUSES: frozenset[str] = frozenset({"closed"})
CASH_EVENTS: tuple[str, ...] = ("open_period", "observe_balance", "bind_expectation", "project", "review", "close")
_CASH_TABLE: dict[tuple[str, str], str] = {
    ("new", "open_period"): "opened",
    ("opened", "observe_balance"): "balances_observed",
    ("balances_observed", "observe_balance"): "balances_observed",
    ("balances_observed", "bind_expectation"): "balances_observed",
    ("balances_observed", "project"): "projected",
    ("projected", "bind_expectation"): "balances_observed",
    ("projected", "review"): "reviewed",
    ("reviewed", "close"): "closed",
}


class CashPositionError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise CashPositionError(code, message)


def _money(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


# --------------------------------------------------------------------------- #
# Plan
# --------------------------------------------------------------------------- #


class AccountSpec(StrictModel):
    account_ref: OpaqueRef
    source_tool: ShortText

    @model_validator(mode="after")
    def _guard(self) -> "AccountSpec":
        if self.source_tool not in BALANCE_TOOLS:
            raise ValueError(f"{self.source_tool} is not a balance read")
        return self


class CashPositionPlan(StrictModel):
    """What the chain enforces: which accounts make up cash, how fresh their reads must be, the floor, and the horizon."""

    schema_id: str = Field(default=CASH_POSITION_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    accounts: tuple[AccountSpec, ...] = Field(min_length=1, max_length=40)
    floor: Decimal = Field(default=Decimal("0"), validate_default=True)
    horizon_weeks: int = Field(default=13, ge=1, le=104)
    balance_max_age_hours: int = Field(default=72, ge=1, le=720)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("accounts", mode="before")
    @classmethod
    def _sequences(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("floor", mode="before")
    @classmethod
    def _floor(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="floor")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "CashPositionPlan":
        unique([item.account_ref for item in self.accounts], label="accounts")
        if not skip_digests(info) and self.plan_digest != sealed_digest(CashPositionPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self

    def account(self, account_ref: str) -> AccountSpec | None:
        return next((item for item in self.accounts if item.account_ref == account_ref), None)


def compile_cash_position_chain(company_ref: str, *, currency: str, accounts: Sequence[Mapping[str, Any]], overrides: Mapping[str, Any] | None = None) -> CashPositionPlan:
    raw: dict[str, Any] = {"company_ref": company_ref, "currency": str(currency).upper(), "accounts": [dict(detached(item)) for item in accounts], **dict(overrides or {})}
    return seal(CashPositionPlan, raw, "plan_digest")


# --------------------------------------------------------------------------- #
# Receipts, ledger, lifecycle
# --------------------------------------------------------------------------- #


class ObservedBalance(StrictModel):
    account_ref: OpaqueRef
    source_tool: ShortText
    available: Decimal
    pending: Decimal = Field(default=Decimal("0"), validate_default=True)
    observed_at: str
    balance_digest: Sha256Digest

    @field_validator("available", "pending", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class BoundExpectation(StrictModel):
    flow_ref: OpaqueRef
    schema_ref: ShortText
    source_engine: ShortText
    direction: FlowDirection
    amount: Decimal
    due_at: str
    source_digest: Sha256Digest
    basis: BoundedText | None = None

    @field_validator("amount", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="amount")


class CashReceipt(StrictModel):
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    period_ref: OpaqueRef | None = None
    as_of: str | None = None
    preparer_ref: OpaqueRef | None = None
    account_ref: OpaqueRef | None = None
    balance_provenance: dict[str, Any] | None = None
    balance_digest: Sha256Digest | None = None
    available: Decimal | None = None
    pending: Decimal | None = None
    observed_at: str | None = None
    expectation: dict[str, Any] | None = None
    source_engine: ShortText | None = None
    source_state: dict[str, Any] | None = None
    source_plan: dict[str, Any] | None = None
    due_at: str | None = None
    reviewer_ref: OpaqueRef | None = None
    breach_response: BoundedText | None = None
    detail: BoundedText | None = None

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("available", "pending", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)

    @field_validator("as_of", "observed_at", "due_at")
    @classmethod
    def _stamps(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))


class CashLedger(StrictModel):
    period_ref: str | None = None
    as_of: str | None = None
    preparer_ref: str | None = None
    balances: tuple[ObservedBalance, ...] = Field(default_factory=tuple, max_length=40)
    available_total: Decimal = Field(default=Decimal("0"), validate_default=True)
    pending_total: Decimal = Field(default=Decimal("0"), validate_default=True)
    expectations: tuple[BoundExpectation, ...] = Field(default_factory=tuple, max_length=2000)
    expected_inflows: Decimal = Field(default=Decimal("0"), validate_default=True)
    expected_outflows: Decimal = Field(default=Decimal("0"), validate_default=True)
    forecast: dict[str, Any] | None = None
    forecast_digest: str | None = None
    projected_at: str | None = None
    projected_by: str | None = None
    first_breach_week: int | None = None
    runway_weeks: int | None = None
    minimum_balance: Decimal = Field(default=Decimal("0"), validate_default=True)
    reviewed_at: str | None = None
    reviewer_ref: str | None = None
    breach_response: str | None = None
    closed_at: str | None = None

    @field_validator("balances", "expectations", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("available_total", "pending_total", "expected_inflows", "expected_outflows", "minimum_balance", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class CashEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    money_moved: Literal[False] = False
    provider_read: Literal[False] = False


def _bind_source(engine: str, source_plan: Mapping[str, Any], source_state: Mapping[str, Any]) -> Any:
    from lightbulb.company_plan_migration import lifecycle_for

    try:
        lifecycle = lifecycle_for(engine)
    except (LookupError, ValueError, KeyError) as exc:
        raise CashPositionError("SOURCE_ENGINE_UNKNOWN", f"{engine} has no registered lifecycle") from exc
    try:
        _plan, bound = lifecycle.spec.bind(source_plan, source_state)
    except (ValueError, TypeError, KeyError) as exc:
        raise CashPositionError("EXPECTATION_NOT_PROVEN", f"the source state must replay against its exact plan: {exc}"[:300]) from exc
    return bound


def _rederive(schema: str, source_plan: Mapping[str, Any], source_state: Mapping[str, Any], handoff: Mapping[str, Any]) -> Mapping[str, Any] | None:
    """The hand-off the replayed state itself offers for this schema, or None when no producer is registered."""

    import importlib

    entry = EXPECTATION_PRODUCERS.get(schema)
    if entry is None:
        return None
    module_name, function_name, takes_expected_at = entry
    producer = getattr(importlib.import_module(module_name), function_name)
    kwargs: dict[str, Any] = {"source_plan": source_plan}
    if takes_expected_at:
        kwargs["expected_at"] = str(handoff.get("expected_at") or handoff.get("due_at") or "")
    try:
        produced = producer(source_state, **kwargs)
    except (ValueError, TypeError, KeyError) as exc:
        raise CashPositionError("EXPECTATION_NOT_PROVEN", f"the replayed state offers no such hand-off: {exc}"[:300]) from exc
    rows = list(produced) if isinstance(produced, (list, tuple)) else [produced]
    wanted = str(handoff.get("flow_ref") or "")
    for row in rows:
        if str(dict(row).get("flow_ref") or "") == wanted:
            return dict(row)
    raise CashPositionError("EXPECTATION_NOT_PROVEN", f"the replayed state offers no hand-off {wanted}")


def _bind_document(schema: str, source_plan: Mapping[str, Any] | None, source_state: Mapping[str, Any]) -> tuple[str, str, str, str]:
    """A sealed document re-validated from its dict: returns (engine label, digest, company_ref, currency)."""

    import importlib

    module_name, model_name, digest_field, _direction = EXPECTATION_DOCUMENTS[schema]
    model = getattr(importlib.import_module(f"lightbulb.{module_name}"), model_name)
    try:
        document = model.model_validate(dict(source_state))
    except (ValueError, TypeError) as exc:
        raise CashPositionError("EXPECTATION_NOT_PROVEN", f"the document must validate as sealed: {exc}"[:300]) from exc
    return module_name, str(getattr(document, digest_field)), str(document.company_ref), str(document.currency)


def _apply_cash(plan: CashPositionPlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event, at = command.receipt, command.event, command.occurred_at
    if event == "open_period":
        require(r.period_ref is not None and r.as_of is not None and r.preparer_ref is not None, "PERIOD_MISSING", "a period names itself, its forecast start, and its preparer")
        data.update({"period_ref": r.period_ref, "as_of": r.as_of, "preparer_ref": r.preparer_ref})
    elif event == "observe_balance":
        require(r.account_ref is not None and r.balance_provenance is not None and r.balance_digest is not None and r.available is not None and r.observed_at is not None, "BALANCE_NOT_PROVEN", "a balance arrives as a balance read for one account of the plan")
        spec = plan.account(str(r.account_ref))
        require(spec is not None, "ACCOUNT_UNKNOWN", f"{r.account_ref} is not an account of this plan")
        assert spec is not None
        prov = dict(r.balance_provenance or {})
        require(str(prov.get("output_digest")) == r.balance_digest, "BALANCE_NOT_PROVEN", "the provenance does not seal this balance read")
        require(str(prov.get("source_tool")) == spec.source_tool, "BALANCE_TOOL_MISMATCH", f"{r.account_ref} is read through {spec.source_tool}, not {prov.get('source_tool')}")
        require(all(str(r.account_ref) != item["account_ref"] for item in data.get("balances", ())), "ACCOUNT_ALREADY_OBSERVED", f"{r.account_ref} is already observed in this period")
        observed = parsed(str(r.observed_at))
        as_of = parsed(str(data["as_of"]))
        require(observed <= parsed(at), "BALANCE_FROM_FUTURE", "the balance cannot come from the future")
        require(abs(as_of - observed) <= timedelta(hours=plan.balance_max_age_hours), "BALANCE_STALE", f"the balance was read more than {plan.balance_max_age_hours} hour(s) from the forecast start")
        assert r.available is not None
        record = ObservedBalance(account_ref=str(r.account_ref), source_tool=spec.source_tool, available=r.available, pending=r.pending or Decimal("0"), observed_at=str(r.observed_at), balance_digest=str(r.balance_digest)).to_dict()
        balances = [*[dict(item) for item in data.get("balances", ())], record]
        data.update({"balances": balances, "available_total": str(_money(sum(Decimal(str(item["available"])) for item in balances))), "pending_total": str(_money(sum(Decimal(str(item["pending"])) for item in balances)))})
    elif event == "bind_expectation":
        require(r.expectation is not None and r.source_engine is not None and r.source_state is not None and r.due_at is not None, "EXPECTATION_MISSING", "an expectation is another chain's hand-off, the replayed state (or sealed document) that produced it, its plan, and the date it lands")
        handoff = dict(r.expectation or {})
        schema = str(handoff.get("schema", ""))
        if schema in EXPECTATION_DOCUMENTS:
            engine, direction = EXPECTATION_DOCUMENTS[schema][0], EXPECTATION_DOCUMENTS[schema][3]
            require(str(r.source_engine) == engine, "EXPECTATION_ENGINE_MISMATCH", f"{schema} is produced by {engine}, not {r.source_engine}")
            try:
                _engine, digest, company_ref, currency = _bind_document(schema, r.source_plan, dict(r.source_state or {}))
            except CashPositionError as exc:
                require(False, exc.code, str(exc))
                raise AssertionError from exc
            require(str(handoff.get("source_digest")) == digest, "EXPECTATION_NOT_PROVEN", "the hand-off does not name the sealed document's digest")
            require(company_ref == plan.company_ref and currency == plan.currency, "EXPECTATION_SCOPE_MISMATCH", "the document belongs to another company or currency")
            source_digest, source_ref = digest, f"{engine}:{digest[:16]}"
        else:
            require(schema in EXPECTATION_SCHEMAS, "EXPECTATION_SCHEMA_UNKNOWN", f"{schema} is not a hand-off treasury accepts")
            require(r.source_plan is not None, "EXPECTATION_MISSING", "a chain hand-off carries the plan its state replays against")
            engine, direction = EXPECTATION_SCHEMAS[schema]
            require(str(r.source_engine) == engine, "EXPECTATION_ENGINE_MISMATCH", f"{schema} is produced by {engine}, not {r.source_engine}")
            try:
                bound = _bind_source(engine, dict(r.source_plan or {}), dict(r.source_state or {}))
            except CashPositionError as exc:
                require(False, exc.code, str(exc))
                raise AssertionError from exc
            require(str(handoff.get("source_digest")) == bound.state_digest, "EXPECTATION_NOT_PROVEN", "the hand-off does not name the replayed state's digest")
            try:
                produced = _rederive(schema, dict(r.source_plan or {}), dict(r.source_state or {}), handoff)
            except CashPositionError as exc:
                require(False, exc.code, str(exc))
                raise AssertionError from exc
            if produced is not None:
                require(_money(decimal_value(produced.get("amount"), field_name="amount")) == _money(decimal_value(handoff.get("amount"), field_name="amount")), "EXPECTATION_NOT_PROVEN", "the hand-off's amount is not what the replayed state offers")
            source_digest, source_ref = bound.state_digest, bound.scope.entity_ref
        require(str(handoff.get("currency", "")).upper() == plan.currency, "EXPECTATION_CURRENCY_MISMATCH", f"the hand-off is in {handoff.get('currency')}, not {plan.currency}")
        amount = decimal_value(handoff.get("amount"), field_name="amount")
        require(amount > 0, "EXPECTATION_EMPTY", "an expectation is a positive amount")
        flow_ref = str(handoff.get("flow_ref") or f"{schema}:{source_ref}")
        require(all(flow_ref != item["flow_ref"] for item in data.get("expectations", ())), "EXPECTATION_ALREADY_BOUND", f"{flow_ref} is already in this period")
        require(parsed(str(r.due_at)) >= parsed(str(data["as_of"])), "EXPECTATION_BEFORE_PERIOD", "an expectation lands at or after the forecast start")
        record = BoundExpectation(flow_ref=flow_ref, schema_ref=schema, source_engine=engine, direction=direction, amount=_money(amount), due_at=str(r.due_at), source_digest=source_digest, basis=(str(handoff.get("basis") or handoff.get("reason") or "")[:600] or None)).to_dict()
        rows = [*[dict(item) for item in data.get("expectations", ())], record]
        data.update({"expectations": rows, "expected_inflows": str(_money(sum(Decimal(str(item["amount"])) for item in rows if item["direction"] == "receivable"))), "expected_outflows": str(_money(sum(Decimal(str(item["amount"])) for item in rows if item["direction"] == "payable"))), "forecast": None, "forecast_digest": None, "projected_at": None, "projected_by": None, "first_breach_week": None, "runway_weeks": None})
    elif event == "project":
        observed = {item["account_ref"] for item in data.get("balances", ())}
        missing = sorted(spec.account_ref for spec in plan.accounts if spec.account_ref not in observed)
        require(not missing, "ACCOUNTS_NOT_OBSERVED", f"every account is read before the period projects; missing {missing}")
        from lightbulb.company_treasury import CashPosition, forecast_cash

        balances = [dict(item) for item in data.get("balances", ())]
        position = CashPosition(source_tool=CASH_POSITION_KIND, provenance_digest=stable_digest([item["balance_digest"] for item in balances]), observed_at=max(str(item["observed_at"]) for item in balances), currency=plan.currency, available=str(data["available_total"]), pending=str(data["pending_total"]), accounts=len(balances))
        flows = [{"kind": item["direction"], "ref": item["flow_ref"], "due_at": item["due_at"], "amount": str(item["amount"]), "source": item["source_engine"]} for item in data.get("expectations", ())]
        forecast = forecast_cash(position, as_of=str(data["as_of"]), horizon_weeks=plan.horizon_weeks, flows=flows, floor=str(plan.floor))
        data.update({"forecast": forecast.to_dict(), "forecast_digest": forecast.forecast_digest, "projected_at": at, "projected_by": command.actor_ref, "first_breach_week": forecast.first_breach_week, "runway_weeks": forecast.runway_weeks, "minimum_balance": str(forecast.minimum_balance)})
    elif event == "review":
        require(r.reviewer_ref is not None, "REVIEWER_MISSING", "a review names the reviewer")
        require(str(r.reviewer_ref) != str(data.get("projected_by")) and str(r.reviewer_ref) != str(data.get("preparer_ref")), "SEGREGATION_VIOLATED", "the preparer cannot review their own forecast")
        if data.get("first_breach_week") is not None:
            require(bool(r.breach_response), "BREACH_RESPONSE_MISSING", f"the forecast breaches the floor in week {data['first_breach_week']}; the review states the response", "correct_input")
        data.update({"reviewed_at": at, "reviewer_ref": r.reviewer_ref, "breach_response": r.breach_response})
    elif event == "close":
        data.update({"closed_at": at})
    return next_status, data


CASH_POSITION_LIFECYCLE = LifecycleSpec(entity="cash_position", schema_prefix=CASH_POSITION_KIND, statuses=CASH_STATUSES, terminal=TERMINAL_CASH_STATUSES, events=CASH_EVENTS, table=_CASH_TABLE, opening_event="open_period", reason_events=(), apply=_apply_cash, ledger_model=CashLedger, receipt_model=CashReceipt, effect_boundary_model=CashEffectBoundary, plan_model=CashPositionPlan, max_transitions=MAX_CASH_POSITION_TRANSITIONS)
CashPositionState = CASH_POSITION_LIFECYCLE.State


def open_cash_period(plan: CashPositionPlan | Mapping[str, Any], scope: Mapping[str, Any], *, receipt: Mapping[str, Any], opened_at: str, actor_ref: str) -> Any:
    return CASH_POSITION_LIFECYCLE.open(plan, scope, opened_at=opened_at, actor_ref=actor_ref, receipt=receipt)


def advance_cash_period(plan: CashPositionPlan | Mapping[str, Any], state: Any, command: Any) -> Any:
    return CASH_POSITION_LIFECYCLE.advance(plan, state, command)


# --------------------------------------------------------------------------- #
# Receipts
# --------------------------------------------------------------------------- #


def period_receipt(*, period_ref: str, as_of: str, preparer_ref: str) -> dict[str, Any]:
    return {"period_ref": period_ref, "as_of": timestamp(as_of, field_name="as_of"), "preparer_ref": preparer_ref, "evidence_refs": [f"period:{period_ref}"]}


def balance_receipt(provenance: Mapping[str, Any] | Any, payload: Any, *, account_ref: str, currency: str) -> dict[str, Any]:
    """From a balance read: one account's available and pending cash in the company currency."""

    prov = dict(detached(provenance))
    _require(str(prov.get("source_tool", "")) in BALANCE_TOOLS, "BALANCE_NOT_PROVEN", f"expected a read from {sorted(BALANCE_TOOLS)}, got {prov.get('source_tool')!r}")
    for key in ("observation_ref", "provenance_digest", "output_digest", "completed_at"):
        _require(bool(prov.get(key)), "BALANCE_NOT_PROVEN", f"the provenance lacks {key}")
    raw = detached(payload)
    _require(str(prov["output_digest"]) == stable_digest(raw), "BALANCE_NOT_PROVEN", "the provenance does not seal this exact balance read")
    rows = raw.get("items") if isinstance(raw, dict) and "items" in raw else raw.get("data") if isinstance(raw, dict) and "data" in raw else raw if isinstance(raw, list) else [raw]
    code = str(currency).upper()
    available = pending = Decimal("0")
    counted = 0
    for item in rows:
        row = dict(detached(item))
        if str(row.get("currency") or row.get("currency_code") or "").upper() != code:
            continue
        if row.get("account_ref") is not None and str(row["account_ref"]) != account_ref:
            continue
        available += decimal_value(row.get("available_amount", row.get("available", row.get("balance", row.get("amount", "0")))), field_name="available", allow_negative=True)
        pending += decimal_value(row.get("pending_amount", row.get("pending", "0")), field_name="pending", allow_negative=True)
        counted += 1
    _require(counted > 0, "NO_BALANCE_IN_CURRENCY", f"no balance row in {code} for {account_ref}")
    return {"account_ref": account_ref, "balance_provenance": prov, "balance_digest": str(prov["output_digest"]), "available": str(_money(available)), "pending": str(_money(pending)), "observed_at": timestamp(str(prov.get("window_end") or prov["completed_at"]), field_name="observed_at"), "evidence_refs": [f"balance:{account_ref}:{prov['observation_ref']}"]}


def expectation_receipt(handoff: Mapping[str, Any], *, source_engine: str, source_state: Any, source_plan: Any = None, due_at: str | None = None) -> dict[str, Any]:
    """Another chain's hand-off with the replayed state that produced it; ``due_at`` defaults to the hand-off's own expected date."""

    payload = dict(detached(handoff))
    schema = str(payload.get("schema", ""))
    _require(schema in EXPECTATION_SCHEMAS or schema in EXPECTATION_DOCUMENTS, "EXPECTATION_SCHEMA_UNKNOWN", f"{schema} is not a hand-off treasury accepts; one of {sorted((*EXPECTATION_SCHEMAS, *EXPECTATION_DOCUMENTS))}")
    when = due_at or payload.get("expected_at") or payload.get("due_at")
    _require(when is not None, "DUE_DATE_MISSING", "the hand-off carries no date; pass due_at")
    state = source_state if isinstance(source_state, Mapping) else source_state.to_dict()
    plan = None if source_plan is None else (source_plan if isinstance(source_plan, Mapping) else source_plan.to_dict())
    return {"expectation": payload, "source_engine": source_engine, "source_state": dict(state), **({"source_plan": dict(plan)} if plan is not None else {}), "due_at": timestamp(str(when), field_name="due_at"), "evidence_refs": [f"expectation:{payload.get('flow_ref') or payload.get('order_ref') or payload.get('po_ref') or schema}"]}


def review_receipt(*, reviewer_ref: str, breach_response: str | None = None) -> dict[str, Any]:
    receipt: dict[str, Any] = {"reviewer_ref": reviewer_ref, "evidence_refs": [f"review:{reviewer_ref}"]}
    if breach_response:
        receipt["breach_response"] = breach_response[:600]
    return receipt


# --------------------------------------------------------------------------- #
# What the chain hands to the other engines
# --------------------------------------------------------------------------- #


def cash_floor_signal(state: Any, *, source_plan: Any, emitted_at: str) -> dict[str, Any] | None:
    """``signals.cash_floor_breach`` when the projected period breaches the floor inside the horizon."""

    plan, bound = CASH_POSITION_LIFECYCLE.bind(source_plan, state)
    ledger = bound.ledger
    if ledger.forecast_digest is None or ledger.first_breach_week is None:
        return None
    return {"name": "signals.cash_floor_breach", "producer": CASH_POSITION_KIND, "emitted_at": timestamp(emitted_at, field_name="emitted_at"), "payload": {"period_ref": ledger.period_ref, "first_breach_week": ledger.first_breach_week, "runway_weeks": ledger.runway_weeks or 0, "minimum_balance": str(ledger.minimum_balance), "floor": str(plan.floor), "currency": plan.currency, "source_digest": bound.state_digest}}


def cash_cover_receipt(state: Any, *, source_plan: Any, amount: Any, at: str) -> dict[str, Any]:
    """Whether one more outflow is covered by the period's reviewed forecast: ``company_treasury.assess_cash_cover`` on the sealed forecast."""

    from lightbulb.company_treasury import assess_cash_cover

    _plan, bound = CASH_POSITION_LIFECYCLE.bind(source_plan, state)
    _require(bound.ledger.forecast is not None and bound.status in ("projected", "reviewed", "closed"), "NO_FORECAST", f"a period that is {bound.status} has no forecast")
    cover = assess_cash_cover(bound.ledger.forecast, amount=amount, at=at)
    return {**cover.to_dict(), "period_ref": bound.ledger.period_ref, "reviewed": bound.ledger.reviewed_at is not None, "source_digest": bound.state_digest}


def treasury_summary(states: Sequence[Any]) -> dict[str, Any]:
    counts = {status: sum(1 for state in states if state.status == status) for status in CASH_STATUSES}
    latest = max((state for state in states if state.ledger.forecast_digest is not None), key=lambda state: str(state.ledger.as_of), default=None)
    return {"periods": len(states), "by_status": counts, "latest_period": None if latest is None else latest.ledger.period_ref, "available_total": None if latest is None else str(latest.ledger.available_total), "first_breach_week": None if latest is None else latest.ledger.first_breach_week, "runway_weeks": None if latest is None else latest.ledger.runway_weeks, "expected_inflows": None if latest is None else str(latest.ledger.expected_inflows), "expected_outflows": None if latest is None else str(latest.ledger.expected_outflows), "unreviewed_breaches": [state.scope.entity_ref for state in states if state.status == "projected" and state.ledger.first_breach_week is not None]}


CASH_POSITION_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": CASH_POSITION_KIND,
    "golden_loop": CASH_POSITION_GOLDEN_LOOP,
    "stages": ["open_period", "observe_balance", "bind_expectation", "project", "review"],
    "statuses": list(CASH_STATUSES),
    "events": list(CASH_EVENTS),
    "hops": {"open_period": "the period, the forecast start, the preparer", "observe_balance": "a balance read per plan account, inside the freshness window", "bind_expectation": "another chain's hand-off bound to the replayed state that produced it", "project": "the weekly forecast computed from the summed balances and the bound expectations against the plan's floor", "review": "someone other than the preparer; a breach needs a stated response"},
    "tools": {"balances": sorted(BALANCE_TOOLS)},
    "accepted_handoffs": {**{schema: {"engine": engine, "direction": direction} for schema, (engine, direction) in EXPECTATION_SCHEMAS.items()}, **{schema: {"document": f"{module}.{model}", "direction": direction} for schema, (module, model, _field, direction) in EXPECTATION_DOCUMENTS.items()}},
    "required_connectors": ["airwallex", "xero", "lightbulb.sdk_engine_state"],
    "hard_rules": [
        "cash is the sum of observed account balances, never a typed number",
        "an expectation enters once and only with the replayed state whose digest it names",
        "a new expectation after projection invalidates the forecast",
        "the preparer never reviews their own forecast; a floor breach is reviewed with a response",
        "nothing here moves money",
    ],
}

_WEEKS_PER_MONTH = Decimal("52") / Decimal("12")


def budget_envelope_from_period(state: Any, *, source_plan: Any, runway_floor_months: Any = "6") -> dict[str, Any]:
    """The cash budget envelope the growth loop needs, derived from a projected treasury period: cash on hand is the observed balances, net monthly burn is the bound outflows less inflows over the plan's horizon, and the floor identity is the runway module's own (hold ``floor`` months of burn; spend the rest).

    The envelope names the replayed period's digest as its runway digest, so the allocation it feeds is bound to the
    balances and hand-offs the period actually bound. A period with nothing bound has an unknown burn and grants
    nothing; a period whose bound inflows cover its outflows is not burn-limited.
    """

    from lightbulb.cash_runway import CashBudgetEnvelope

    plan, bound = CASH_POSITION_LIFECYCLE.bind(source_plan, state)
    ledger = bound.ledger
    _require(bound.status in ("projected", "reviewed", "closed"), "PERIOD_NOT_PROJECTED", f"a period that is {bound.status} has no forecast to size an envelope from")
    floor = decimal_value(runway_floor_months, field_name="runway_floor_months")
    _require(floor > 0, "FLOOR_INVALID", "the runway floor is a positive number of months")
    cash = _money(ledger.available_total)
    horizon_months = Decimal(plan.horizon_weeks) / _WEEKS_PER_MONTH
    net_burn = _money((Decimal(str(ledger.expected_outflows)) - Decimal(str(ledger.expected_inflows))) / horizon_months)
    ref = f"envelope-{str(ledger.period_ref or bound.scope.entity_ref).lower()}"
    ref = "".join(char if char.isalnum() or char in "-_" else "-" for char in ref)[:64]
    base = {"envelope_ref": ref, "analysis_as_of": ledger.as_of or bound.transition_history[-1].command.occurred_at, "currency": plan.currency, "runway_digest": bound.state_digest, "runway_floor_months": str(floor), "cash_on_hand": str(cash), "net_monthly_burn": str(net_burn)}
    def checked(envelope: dict[str, Any]) -> dict[str, Any]:
        return CashBudgetEnvelope.model_validate(envelope).model_dump(mode="json", by_alias=True, exclude_none=True)

    if not ledger.expectations:
        return checked({**base, "status": "unknown", "complete": False, "rationale": f"period {ledger.period_ref} bound no hand-offs, so its burn is unknown and no discretionary capacity is granted"})
    if net_burn <= 0:
        return checked({**base, "status": "not_burning", "one_time_discretionary_capacity": str(cash), "complete": True, "rationale": f"period {ledger.period_ref} expects inflows of {ledger.expected_inflows} against outflows of {ledger.expected_outflows}; runway is not burn-limited"})
    runway = (cash / net_burn).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    affordable = _money(cash / floor - net_burn)
    one_time = _money(cash - net_burn * floor)
    if runway > floor:
        status, shortfall = "healthy_surplus", None
    elif runway == floor:
        status, shortfall = "at_floor", None
    else:
        status, shortfall = "below_floor", (floor - runway).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    rationale = f"period {ledger.period_ref}: {cash} on hand, {net_burn} a month net burn from {len(ledger.expectations)} bound hand-off(s) over {plan.horizon_weeks} week(s); runway {runway} month(s) against a {floor}-month floor"
    return checked({**base, "status": status, "current_runway_months": str(runway), "affordable_incremental_monthly_burn": str(affordable), "one_time_discretionary_capacity": str(one_time), "runway_shortfall_months": None if shortfall is None else str(shortfall), "complete": True, "rationale": rationale[:300]})


__all__ = ["budget_envelope_from_period", "EXPECTATION_PRODUCERS", "BALANCE_TOOLS", "CASH_EVENTS", "EXPECTATION_DOCUMENTS", "CASH_POSITION_GOLDEN_LOOP", "CASH_POSITION_KIND", "CASH_POSITION_LIFECYCLE", "CASH_POSITION_MANIFEST", "CASH_STATUSES", "EXPECTATION_SCHEMAS", "TERMINAL_CASH_STATUSES", "AccountSpec", "BoundExpectation", "CashEffectBoundary", "CashLedger", "CashPositionError", "CashPositionPlan", "CashPositionState", "CashReceipt", "ObservedBalance", "advance_cash_period", "balance_receipt", "cash_cover_receipt", "cash_floor_signal", "compile_cash_position_chain", "expectation_receipt", "open_cash_period", "period_receipt", "review_receipt", "treasury_summary"]
