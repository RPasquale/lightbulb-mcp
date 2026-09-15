"""The fixed asset chain: one replay-fenced lifecycle per capitalised asset, from the paid bill to disposal.

Equipment, vehicles, and fit-outs were paid through the payables chain and
then vanished: nothing held the asset, its class, its depreciation period
by period, an impairment, or what came back when it was sold.  The cost
register never saw depreciation and the wind-down chain had no asset list
to dispose of.  ``FIXED_ASSET_LIFECYCLE`` does:

    acquired -> in_service -> (depreciate | impair)* -> disposed | written_off   (terminal)
    acquired -> written_off                                                       (terminal, with a reason)

* ``acquisition_receipt`` opens the asset from the supplier's replayed
  payable case (approved or further along); the cost is the bill's, plus
  operator-supplied capitalised costs with evidence.
* ``place_in_service`` fixes the date depreciation starts.
* ``depreciation_receipt`` names one whole calendar month; the charge is
  computed from the class's method, life, and residual, never typed, and
  months are contiguous.
* ``impairment_receipt`` writes the carrying amount down with evidence.
* ``disposal_receipt`` consumes a bank read for the proceeds; the gain or
  loss is computed against the carrying amount.

``depreciation_cost_receipt`` hands the cost register one month's charge
as a proven source.  Nothing here posts a journal, sells anything, or
persists anything.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
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

FIXED_ASSET_KIND = "fixed_asset_chain"
FIXED_ASSET_GOLDEN_LOOP = "finance.acquired_asset_to_disposed_asset@0.1.0"
FIXED_ASSET_PLAN_SCHEMA = "lightbulb.fixed_asset_plan.v1"
MAX_ASSET_TRANSITIONS = 400
COSTABLE_PAYABLE_STATUSES: frozenset[str] = frozenset({"approved", "scheduled", "paid", "cleared"})
PROCEEDS_TOOLS: frozenset[str] = frozenset({"xero.list_bank_transactions", "quickbooks.list_deposits", "host.bank_transfer", "stripe.list_balance_transactions"})
Method = Literal["straight_line", "diminishing_value"]
_HUNDRED = Decimal("100")

ASSET_STATUSES: tuple[str, ...] = ("acquired", "in_service", "disposed", "written_off")
TERMINAL_ASSET_STATUSES: frozenset[str] = frozenset({"disposed", "written_off"})
ASSET_EVENTS: tuple[str, ...] = ("acquire", "place_in_service", "depreciate", "impair", "dispose", "write_off")
_ASSET_TABLE: dict[tuple[str, str], str] = {
    ("new", "acquire"): "acquired",
    ("acquired", "place_in_service"): "in_service",
    ("in_service", "depreciate"): "in_service",
    ("in_service", "impair"): "in_service",
    ("in_service", "dispose"): "disposed",
    ("acquired", "write_off"): "written_off",
    ("in_service", "write_off"): "written_off",
}


class FixedAssetError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise FixedAssetError(code, message)


def _money(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


def _month_bounds(period_ref: str) -> tuple[str, str]:
    """``YYYY-MM`` -> the first instant of that month and of the next, as timestamps."""

    try:
        year, month = (int(part) for part in str(period_ref).split("-"))
        start = datetime(year, month, 1, tzinfo=timezone.utc)
        end = datetime(year + (month == 12), (month % 12) + 1, 1, tzinfo=timezone.utc)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"{period_ref} is not a YYYY-MM month") from exc
    return iso(start), iso(end)


def _next_month(period_ref: str) -> str:
    year, month = (int(part) for part in str(period_ref).split("-"))
    return f"{year + (month == 12):04d}-{(month % 12) + 1:02d}"


# --------------------------------------------------------------------------- #
# Plan
# --------------------------------------------------------------------------- #


class AssetClass(StrictModel):
    class_ref: OpaqueRef
    method: Method
    useful_life_months: int = Field(ge=1, le=600)
    residual_percent: Decimal = Field(default=Decimal("0"), validate_default=True)
    diminishing_rate_percent: Decimal | None = None

    @field_validator("residual_percent", mode="before")
    @classmethod
    def _residual(cls, value: Any) -> Decimal:
        result = decimal_value(value, field_name="residual_percent")
        if result >= _HUNDRED:
            raise ValueError("residual is a percentage below 100")
        return result

    @field_validator("diminishing_rate_percent", mode="before")
    @classmethod
    def _rate(cls, value: Any) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name="diminishing_rate_percent")

    @model_validator(mode="after")
    def _guard(self) -> "AssetClass":
        if self.method == "diminishing_value" and (self.diminishing_rate_percent is None or self.diminishing_rate_percent <= 0):
            raise ValueError("a diminishing-value class names its annual rate")
        return self


class FixedAssetPlan(StrictModel):
    """What the chain enforces: the asset classes and their methods, and the capitalisation threshold."""

    schema_id: str = Field(default=FIXED_ASSET_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    classes: tuple[AssetClass, ...] = Field(min_length=1, max_length=40)
    capitalisation_threshold: Decimal = Field(default=Decimal("1000"), validate_default=True)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("classes", mode="before")
    @classmethod
    def _classes(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("capitalisation_threshold", mode="before")
    @classmethod
    def _threshold(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="capitalisation_threshold")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "FixedAssetPlan":
        unique([item.class_ref for item in self.classes], label="asset classes")
        if not skip_digests(info) and self.plan_digest != sealed_digest(FixedAssetPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self

    def asset_class(self, class_ref: str) -> AssetClass | None:
        return next((item for item in self.classes if item.class_ref == class_ref), None)


DEFAULT_CLASSES: tuple[dict[str, Any], ...] = (
    {"class_ref": "computer_equipment", "method": "straight_line", "useful_life_months": 36, "residual_percent": "0"},
    {"class_ref": "office_fitout", "method": "straight_line", "useful_life_months": 60, "residual_percent": "0"},
    {"class_ref": "vehicles", "method": "diminishing_value", "useful_life_months": 96, "residual_percent": "10", "diminishing_rate_percent": "25"},
    {"class_ref": "plant", "method": "straight_line", "useful_life_months": 120, "residual_percent": "5"},
)


def compile_fixed_asset_chain(company_ref: str, *, currency: str, classes: Sequence[Mapping[str, Any]] | None = None, overrides: Mapping[str, Any] | None = None) -> FixedAssetPlan:
    raw: dict[str, Any] = {"company_ref": company_ref, "currency": str(currency).upper(), "classes": [dict(detached(item)) for item in (classes or DEFAULT_CLASSES)], **dict(overrides or {})}
    return seal(FixedAssetPlan, raw, "plan_digest")


# --------------------------------------------------------------------------- #
# Receipts, ledger, lifecycle
# --------------------------------------------------------------------------- #


class DepreciationRecord(StrictModel):
    period_ref: OpaqueRef
    period_start: str
    period_end: str
    charge: Decimal
    carrying_amount_after: Decimal

    @field_validator("charge", "carrying_amount_after", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))


class AssetReceipt(StrictModel):
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    asset_ref: OpaqueRef | None = None
    class_ref: OpaqueRef | None = None
    description: ShortText | None = None
    payable_source: dict[str, Any] | None = None
    payable_plan: dict[str, Any] | None = None
    capitalised_costs: Decimal | None = None
    in_service_at: str | None = None
    period_ref: OpaqueRef | None = None
    impairment_amount: Decimal | None = None
    impairment_sha256: Sha256Digest | None = None
    proceeds_provenance: dict[str, Any] | None = None
    proceeds_digest: Sha256Digest | None = None
    proceeds: Decimal | None = None
    disposed_at: str | None = None
    detail: BoundedText | None = None

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("capitalised_costs", "impairment_amount", "proceeds", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))

    @field_validator("in_service_at", "disposed_at")
    @classmethod
    def _stamps(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))


class AssetLedger(StrictModel):
    asset_ref: str | None = None
    class_ref: str | None = None
    description: str | None = None
    supplier_ref: str | None = None
    payable_ref: str | None = None
    payable_digest: str | None = None
    acquired_at: str | None = None
    cost: Decimal = Field(default=Decimal("0"), validate_default=True)
    residual_value: Decimal = Field(default=Decimal("0"), validate_default=True)
    in_service_at: str | None = None
    depreciation: tuple[DepreciationRecord, ...] = Field(default_factory=tuple, max_length=600)
    accumulated_depreciation: Decimal = Field(default=Decimal("0"), validate_default=True)
    impairments: Decimal = Field(default=Decimal("0"), validate_default=True)
    carrying_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    last_period_ref: str | None = None
    last_charge: Decimal = Field(default=Decimal("0"), validate_default=True)
    last_period_end: str | None = None
    fully_depreciated: bool = False
    proceeds: Decimal = Field(default=Decimal("0"), validate_default=True)
    gain_loss: Decimal = Field(default=Decimal("0"), validate_default=True)
    disposed_at: str | None = None
    proceeds_digest: str | None = None
    write_off_reason: str | None = None
    outcome: Literal["open", "disposed", "written_off"] = "open"

    @field_validator("depreciation", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("cost", "residual_value", "accumulated_depreciation", "impairments", "carrying_amount", "last_charge", "proceeds", "gain_loss", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class AssetEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    journal_posted: Literal[False] = False
    asset_sold: Literal[False] = False
    provider_read: Literal[False] = False


def _charge(asset_class: AssetClass, cost: Decimal, residual: Decimal, carrying: Decimal, months_elapsed: int) -> Decimal:
    if asset_class.method == "straight_line":
        monthly = (cost - residual) / Decimal(asset_class.useful_life_months)
        remaining_months = asset_class.useful_life_months - months_elapsed
        charge = monthly if remaining_months > 1 else carrying - residual
    else:
        assert asset_class.diminishing_rate_percent is not None
        charge = carrying * asset_class.diminishing_rate_percent / _HUNDRED / Decimal(12)
    return _money(min(max(charge, Decimal("0")), carrying - residual))


def _apply_asset(plan: FixedAssetPlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event, at = command.receipt, command.event, command.occurred_at
    if event == "acquire":
        require(r.asset_ref is not None and r.class_ref is not None and r.payable_source is not None and r.payable_plan is not None, "ACQUISITION_NOT_PROVEN", "an asset opens from its reference, its class, and the supplier's replayed payable case")
        asset_class = plan.asset_class(str(r.class_ref))
        require(asset_class is not None, "CLASS_UNKNOWN", f"{r.class_ref} is not an asset class of this plan")
        assert asset_class is not None
        from lightbulb.payables_chain import PAYABLES_CHAIN_LIFECYCLE

        try:
            bill_plan, bill = PAYABLES_CHAIN_LIFECYCLE.bind(r.payable_plan, r.payable_source)
        except (ValueError, TypeError, KeyError) as exc:
            require(False, "ACQUISITION_NOT_PROVEN", f"the payable must replay against its exact plan: {exc}"[:300])
            raise AssertionError from exc
        require(bill_plan.company_ref == plan.company_ref and bill.scope.currency == plan.currency, "BILL_SCOPE_MISMATCH", "the bill belongs to another company or currency")
        require(bill.status in COSTABLE_PAYABLE_STATUSES, "BILL_NOT_APPROVED", f"the payable case is {bill.status}; an asset is capitalised from an approved bill")
        require(parsed(bill.transition_history[-1].command.occurred_at) <= parsed(at), "BILL_FROM_FUTURE", "the bill cannot come from the future")
        extra = _money(r.capitalised_costs or 0)
        require(extra >= 0, "CAPITALISED_COSTS_INVALID", "capitalised costs are never negative")
        cost = _money(Decimal(str(bill.ledger.amount)) + extra)
        require(cost >= plan.capitalisation_threshold, "BELOW_CAPITALISATION_THRESHOLD", f"{cost} is below the {plan.capitalisation_threshold} threshold; expense it instead", "correct_input")
        residual = _money(cost * asset_class.residual_percent / _HUNDRED)
        data.update({"asset_ref": r.asset_ref, "class_ref": r.class_ref, "description": r.description, "supplier_ref": str(bill.ledger.supplier_ref), "payable_ref": bill.scope.entity_ref, "payable_digest": bill.state_digest, "acquired_at": at, "cost": str(cost), "residual_value": str(residual), "carrying_amount": str(cost)})
    elif event == "place_in_service":
        require(r.in_service_at is not None, "IN_SERVICE_DATE_MISSING", "placing an asset in service names the date")
        require(parsed(str(data["acquired_at"])) <= parsed(str(r.in_service_at)) <= parsed(at), "IN_SERVICE_TIME_INVALID", "an asset enters service after acquisition and before the recording")
        data.update({"in_service_at": r.in_service_at})
    elif event == "depreciate":
        require(r.period_ref is not None, "PERIOD_MISSING", "depreciation names one calendar month")
        try:
            start, end = _month_bounds(str(r.period_ref))
        except ValueError as exc:
            require(False, "PERIOD_INVALID", str(exc))
            raise AssertionError from exc
        require(not data.get("fully_depreciated"), "FULLY_DEPRECIATED", "the asset is fully depreciated")
        last = data.get("last_period_ref")
        if last is None:
            require(parsed(str(data["in_service_at"])) < parsed(end), "PERIOD_BEFORE_SERVICE", f"{r.period_ref} ends before the asset entered service")
        else:
            require(str(r.period_ref) == _next_month(str(last)), "PERIOD_NOT_CONTIGUOUS", f"the next month after {last} is {_next_month(str(last))}, not {r.period_ref}")
        require(parsed(end) <= parsed(at), "PERIOD_NOT_ENDED", f"{r.period_ref} has not ended")
        asset_class = plan.asset_class(str(data["class_ref"]))
        assert asset_class is not None
        cost, residual, carrying = Decimal(str(data["cost"])), Decimal(str(data["residual_value"])), Decimal(str(data["carrying_amount"]))
        elapsed = len(data.get("depreciation", ()))
        charge = _charge(asset_class, cost, residual, carrying, elapsed)
        after = _money(carrying - charge)
        record = DepreciationRecord(period_ref=str(r.period_ref), period_start=start, period_end=end, charge=charge, carrying_amount_after=after).to_dict()
        data.update({"depreciation": [*[dict(item) for item in data.get("depreciation", ())], record], "accumulated_depreciation": str(_money(Decimal(str(data["accumulated_depreciation"])) + charge)), "carrying_amount": str(after), "last_period_ref": r.period_ref, "last_charge": str(charge), "last_period_end": end, "fully_depreciated": after <= residual})
    elif event == "impair":
        require(r.impairment_amount is not None and r.impairment_amount > 0 and r.impairment_sha256 is not None, "IMPAIRMENT_MISSING", "an impairment names a positive amount and the digest of its evidence")
        carrying = Decimal(str(data["carrying_amount"]))
        residual = Decimal(str(data["residual_value"]))
        require(_money(r.impairment_amount) <= carrying - residual, "IMPAIRMENT_EXCEEDS_CARRYING", f"an impairment of {r.impairment_amount} exceeds the depreciable carrying amount {carrying - residual}")
        after = _money(carrying - r.impairment_amount)
        data.update({"impairments": str(_money(Decimal(str(data["impairments"])) + r.impairment_amount)), "carrying_amount": str(after), "fully_depreciated": after <= residual})
    elif event == "dispose":
        require(r.proceeds_provenance is not None and r.proceeds_digest is not None and r.proceeds is not None and r.disposed_at is not None, "PROCEEDS_EVIDENCE_MISSING", "a disposal carries the bank read provenance, its digest, the proceeds, and the date")
        require(str(dict(r.proceeds_provenance or {}).get("output_digest")) == r.proceeds_digest, "PROCEEDS_NOT_BOUND", "the provenance does not seal this bank read")
        require(parsed(str(data["in_service_at"])) <= parsed(str(r.disposed_at)) <= parsed(at), "DISPOSAL_TIME_INVALID", "a disposal follows service and precedes its recording")
        carrying = Decimal(str(data["carrying_amount"]))
        proceeds = _money(r.proceeds)
        data.update({"proceeds": str(proceeds), "gain_loss": str(_money(proceeds - carrying)), "disposed_at": r.disposed_at, "proceeds_digest": r.proceeds_digest, "carrying_amount": "0", "outcome": "disposed"})
    elif event == "write_off":
        carrying = Decimal(str(data["carrying_amount"]))
        data.update({"write_off_reason": str(command.reason)[:300], "gain_loss": str(_money(-carrying)), "carrying_amount": "0", "outcome": "written_off"})
    return next_status, data


FIXED_ASSET_LIFECYCLE = LifecycleSpec(entity="fixed_asset", schema_prefix=FIXED_ASSET_KIND, statuses=ASSET_STATUSES, terminal=TERMINAL_ASSET_STATUSES, events=ASSET_EVENTS, table=_ASSET_TABLE, opening_event="acquire", reason_events=("write_off",), apply=_apply_asset, ledger_model=AssetLedger, receipt_model=AssetReceipt, effect_boundary_model=AssetEffectBoundary, plan_model=FixedAssetPlan, max_transitions=MAX_ASSET_TRANSITIONS)
FixedAssetState = FIXED_ASSET_LIFECYCLE.State


def open_fixed_asset(plan: FixedAssetPlan | Mapping[str, Any], scope: Mapping[str, Any], *, receipt: Mapping[str, Any], opened_at: str, actor_ref: str) -> Any:
    return FIXED_ASSET_LIFECYCLE.open(plan, scope, opened_at=opened_at, actor_ref=actor_ref, receipt=receipt)


def advance_fixed_asset(plan: FixedAssetPlan | Mapping[str, Any], state: Any, command: Any) -> Any:
    return FIXED_ASSET_LIFECYCLE.advance(plan, state, command)


# --------------------------------------------------------------------------- #
# Receipts
# --------------------------------------------------------------------------- #


def acquisition_receipt(payable_state: Any, *, source_plan: Any, asset_ref: str, class_ref: str, description: str | None = None, capitalised_costs: Any = "0", evidence_refs: Sequence[str] = ()) -> dict[str, Any]:
    from lightbulb.payables_chain import PAYABLES_CHAIN_LIFECYCLE

    try:
        plan, state = PAYABLES_CHAIN_LIFECYCLE.bind(source_plan, payable_state)
    except (ValueError, TypeError, KeyError) as exc:
        raise FixedAssetError("ACQUISITION_NOT_PROVEN", "retain the original payable state and its sealed plan") from exc
    _require(state.status in COSTABLE_PAYABLE_STATUSES, "BILL_NOT_APPROVED", f"the payable case is {state.status}")
    return {"asset_ref": asset_ref, "class_ref": class_ref, "description": description, "payable_source": state.to_dict(), "payable_plan": plan.to_dict(), "capitalised_costs": str(_money(decimal_value(capitalised_costs, field_name="capitalised_costs"))), "evidence_refs": [f"payable:{state.scope.entity_ref}:{state.state_digest[:16]}", *evidence_refs]}


def depreciation_receipt(*, period_ref: str) -> dict[str, Any]:
    _month_bounds(period_ref)
    return {"period_ref": period_ref, "evidence_refs": [f"period:{period_ref}"]}


def impairment_receipt(*, amount: Any, evidence_sha256: str) -> dict[str, Any]:
    return {"impairment_amount": str(_money(decimal_value(amount, field_name="amount"))), "impairment_sha256": evidence_sha256, "evidence_refs": [f"impairment:{evidence_sha256[:16]}"]}


def disposal_receipt(provenance: Mapping[str, Any] | Any, payload: Mapping[str, Any] | Any) -> dict[str, Any]:
    """From a bank read: the proceeds of the sale (zero proceeds is a scrap disposal, still proven by the read)."""

    prov = dict(detached(provenance))
    _require(str(prov.get("source_tool", "")) in PROCEEDS_TOOLS, "PROCEEDS_NOT_BOUND", f"expected a read from {sorted(PROCEEDS_TOOLS)}, got {prov.get('source_tool')!r}")
    for key in ("observation_ref", "provenance_digest", "output_digest", "completed_at"):
        _require(bool(prov.get(key)), "PROCEEDS_NOT_BOUND", f"the provenance lacks {key}")
    raw = dict(detached(payload))
    _require(str(prov["output_digest"]) == stable_digest(raw), "PROCEEDS_NOT_BOUND", "the provenance does not seal this exact bank read")
    amount = raw.get("amount") if raw.get("amount") is not None else (None if raw.get("amount_minor") is None else Decimal(str(raw["amount_minor"])) / 100)
    stamp = raw.get("received_at") or raw.get("date") or raw.get("completed_at")
    _require(amount is not None and stamp is not None, "PROCEEDS_INCOMPLETE", "a bank read carries the amount and the time")
    return {"proceeds_provenance": prov, "proceeds_digest": str(prov["output_digest"]), "proceeds": str(_money(decimal_value(amount, field_name="amount"))), "disposed_at": timestamp(str(stamp), field_name="disposed_at"), "evidence_refs": [f"proceeds:{prov['observation_ref']}"]}


# --------------------------------------------------------------------------- #
# What the chain hands to the other engines
# --------------------------------------------------------------------------- #


def depreciation_cost_receipt(state: Any, *, source_plan: Any, centre_ref: str, engine: str | None = None, category: str | None = None) -> dict[str, Any]:
    """The cost register's source receipt for the last month this asset depreciated: replayed, keyed by asset and month."""

    plan, bound = FIXED_ASSET_LIFECYCLE.bind(source_plan, state)
    ledger = bound.ledger
    _require(ledger.last_period_ref is not None and ledger.last_period_end is not None, "NO_DEPRECIATION_RECORDED", "the asset has not depreciated")
    # The charge belongs to the month it depreciates, so it is dated at the month's last instant, inside the register period that holds that month.
    occurred_at = iso(parsed(str(ledger.last_period_end)) - timedelta(seconds=1))
    return {"source_kind": "depreciation", "source_ref": f"depreciation:{ledger.asset_ref}:{ledger.last_period_ref}", "source_digest": bound.state_digest, "centre_ref": centre_ref, "amount": str(ledger.last_charge), "currency": plan.currency, "occurred_at": occurred_at, "engine": engine, "category": category, "operator_supplied": engine is not None or category is not None, "source_state": bound.to_dict(), "source_plan": plan.to_dict(), "evidence_refs": [f"fixed_asset:{bound.scope.entity_ref}:{bound.state_digest[:16]}"]}


def asset_register_summary(states: Sequence[Any]) -> dict[str, Any]:
    open_states = [state for state in states if state.status not in TERMINAL_ASSET_STATUSES]
    counts = {status: sum(1 for state in states if state.status == status) for status in ASSET_STATUSES}
    by_class: dict[str, dict[str, str]] = {}
    for state in open_states:
        row = by_class.setdefault(str(state.ledger.class_ref), {"cost": "0.00", "carrying_amount": "0.00"})
        row["cost"] = str(_money(Decimal(row["cost"]) + state.ledger.cost))
        row["carrying_amount"] = str(_money(Decimal(row["carrying_amount"]) + state.ledger.carrying_amount))
    return {"assets": len(states), "by_status": counts, "cost": str(_money(sum((state.ledger.cost for state in open_states), Decimal("0")))), "accumulated_depreciation": str(_money(sum((state.ledger.accumulated_depreciation for state in open_states), Decimal("0")))), "impairments": str(_money(sum((state.ledger.impairments for state in open_states), Decimal("0")))), "carrying_amount": str(_money(sum((state.ledger.carrying_amount for state in open_states), Decimal("0")))), "by_class": by_class, "disposal_gain_loss": str(_money(sum((state.ledger.gain_loss for state in states if state.status in TERMINAL_ASSET_STATUSES), Decimal("0"))))}


FIXED_ASSET_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": FIXED_ASSET_KIND,
    "golden_loop": FIXED_ASSET_GOLDEN_LOOP,
    "stages": ["acquire", "place_in_service", "depreciate", "dispose"],
    "statuses": list(ASSET_STATUSES),
    "events": list(ASSET_EVENTS),
    "hops": {"acquire": "the supplier's replayed payable case plus evidenced capitalised costs, at or above the threshold", "place_in_service": "the in-service date", "depreciate": "one contiguous calendar month; the charge computed from the class", "dispose": "a bank read for the proceeds; gain or loss computed against the carrying amount"},
    "required_connectors": ["xero", "lightbulb.sdk_engine_state"],
    "hard_rules": [
        "cost is the replayed bill's amount plus evidenced capitalised costs; nothing below the threshold is an asset",
        "depreciation is computed from the class and never skips or repeats a month",
        "an impairment never takes the carrying amount below residual",
        "the cost register receives depreciation as a replayed source keyed by asset and month",
    ],
}

__all__ = ["ASSET_EVENTS", "ASSET_STATUSES", "COSTABLE_PAYABLE_STATUSES", "DEFAULT_CLASSES", "FIXED_ASSET_GOLDEN_LOOP", "FIXED_ASSET_KIND", "FIXED_ASSET_LIFECYCLE", "FIXED_ASSET_MANIFEST", "PROCEEDS_TOOLS", "TERMINAL_ASSET_STATUSES", "AssetClass", "AssetLedger", "AssetReceipt", "DepreciationRecord", "FixedAssetError", "FixedAssetPlan", "FixedAssetState", "acquisition_receipt", "advance_fixed_asset", "asset_register_summary", "compile_fixed_asset_chain", "depreciation_cost_receipt", "depreciation_receipt", "disposal_receipt", "impairment_receipt", "open_fixed_asset"]
