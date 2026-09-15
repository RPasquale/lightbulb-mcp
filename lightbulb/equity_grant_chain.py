"""The equity grant chain: one replay-fenced lifecycle per option grant, from the board's resolution to shares issued or options lapsed.

``fundraise_chain`` seals the cap table and the pool it carries.  Nothing
held what was done with the pool: who was granted what, on whose authority,
how it vests month by month, what was forfeited on leaving, what was
exercised for cash that actually arrived, and what lapsed.
``EQUITY_GRANT_LIFECYCLE`` does:

    granted -> vesting -> (vest)* -> fully_vested -> exercised   (terminal)
    vesting | fully_vested -> terminate -> (exercise)* -> lapsed  (terminal)
    granted | vesting -> cancelled                               (terminal, with a reason)

* ``grant_receipt`` names the grant, the holder, the units, the strike, and
  the schedule; when the plan requires it, the grant binds the replayed
  board meeting whose carried resolution names it.  The units never exceed
  the plan's pool.
* ``vest`` names one calendar month, contiguous with the last; the vested
  units are computed from the cliff and the vesting period, never typed.
* ``terminate`` forfeits the unvested units and opens the exercise window.
* ``exercise_receipt`` consumes a bank read for exactly the strike times the
  units, inside the window when one is open.
* ``lapse`` closes a terminated grant whose window passed.

``issued_shares`` hands the cap table the shares an exercise created, and
``pool_summary`` states what the pool has left.  Nothing here issues shares,
files anything, or persists anything.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
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
)

EQUITY_GRANT_KIND = "equity_grant_chain"
EQUITY_GRANT_GOLDEN_LOOP = "capital.option_grant_to_shares_or_lapse@0.1.0"
EQUITY_PLAN_SCHEMA = "lightbulb.equity_plan.v1"
ISSUED_SHARES_SCHEMA = "lightbulb.equity_issued_shares.v1"
MAX_GRANT_TRANSITIONS = 200
PROCEEDS_TOOLS: frozenset[str] = frozenset({"xero.list_bank_transactions", "quickbooks.list_deposits", "host.bank_transfer", "airwallex.list_transactions", "host.bank_balances"})
PRICE_QUANTUM = Decimal("0.0001")

GRANT_STATUSES: tuple[str, ...] = ("granted", "vesting", "fully_vested", "exercised", "lapsed", "cancelled")
TERMINAL_GRANT_STATUSES: frozenset[str] = frozenset({"exercised", "lapsed", "cancelled"})
GRANT_EVENTS: tuple[str, ...] = ("grant", "vest", "terminate", "exercise", "lapse", "cancel")
_GRANT_TABLE: dict[tuple[str, str], str] = {
    ("new", "grant"): "granted",
    ("granted", "vest"): "vesting",
    ("vesting", "vest"): "vesting",
    ("vesting", "terminate"): "vesting",
    ("fully_vested", "terminate"): "fully_vested",
    ("vesting", "exercise"): "vesting",
    ("fully_vested", "exercise"): "fully_vested",
    ("vesting", "lapse"): "lapsed",
    ("fully_vested", "lapse"): "lapsed",
    ("granted", "cancel"): "cancelled",
    ("vesting", "cancel"): "cancelled",
}


class EquityGrantError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise EquityGrantError(code, message)


def _money(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


def _month_bounds(period_ref: str) -> tuple[str, str]:
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


class EquityPlan(StrictModel):
    """What the chain enforces: the pool, the default schedule, the exercise window after leaving, and whether a grant needs the board."""

    schema_id: str = Field(default=EQUITY_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    pool_units: int = Field(ge=1, le=10_000_000_000)
    pool_holder_ref: OpaqueRef = "esop"
    share_class: ShortText = "ordinary"
    default_cliff_months: int = Field(default=12, ge=0, le=60)
    default_vesting_months: int = Field(default=48, ge=1, le=120)
    exercise_window_days: int = Field(default=90, ge=1, le=3650)
    require_board_resolution: bool = True
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "EquityPlan":
        if self.default_cliff_months > self.default_vesting_months:
            raise ValueError("the cliff sits inside the vesting period")
        if not skip_digests(info) and self.plan_digest != sealed_digest(EquityPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self


def compile_equity_plan(company_ref: str, *, currency: str, pool_units: int, overrides: Mapping[str, Any] | None = None) -> EquityPlan:
    raw: dict[str, Any] = {"company_ref": company_ref, "currency": str(currency).upper(), "pool_units": pool_units, **dict(overrides or {})}
    return seal(EquityPlan, raw, "plan_digest")


# --------------------------------------------------------------------------- #
# Receipts, ledger, lifecycle
# --------------------------------------------------------------------------- #


class VestingRecord(StrictModel):
    period_ref: OpaqueRef
    months_elapsed: int = Field(ge=0)
    units_vested: int = Field(ge=0)
    cumulative_vested: int = Field(ge=0)


class ExerciseRecord(StrictModel):
    exercise_ref: OpaqueRef
    units: int = Field(ge=1)
    proceeds: Decimal
    exercised_at: str
    proceeds_digest: Sha256Digest

    @field_validator("proceeds", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="proceeds")


class GrantReceipt(StrictModel):
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    grant_ref: OpaqueRef | None = None
    holder_ref: OpaqueRef | None = None
    units: int | None = None
    strike_price: Decimal | None = None
    granted_at: str | None = None
    cliff_months: int | None = None
    vesting_months: int | None = None
    resolution_ref: OpaqueRef | None = None
    board_source: dict[str, Any] | None = None
    board_plan: dict[str, Any] | None = None
    period_ref: OpaqueRef | None = None
    terminated_at: str | None = None
    exercise_ref: OpaqueRef | None = None
    exercise_units: int | None = None
    proceeds_provenance: dict[str, Any] | None = None
    proceeds_digest: Sha256Digest | None = None
    proceeds: Decimal | None = None
    exercised_at: str | None = None
    detail: BoundedText | None = None

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("strike_price", mode="before")
    @classmethod
    def _price(cls, value: Any) -> Decimal | None:
        return None if value is None else Decimal(str(value)).quantize(PRICE_QUANTUM, rounding=ROUND_HALF_UP)

    @field_validator("proceeds", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name="proceeds")

    @field_validator("granted_at", "terminated_at", "exercised_at")
    @classmethod
    def _stamps(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))


class GrantLedger(StrictModel):
    grant_ref: str | None = None
    holder_ref: str | None = None
    units: int = 0
    strike_price: Decimal = Field(default=Decimal("0"), validate_default=True)
    granted_at: str | None = None
    cliff_months: int = 0
    vesting_months: int = 0
    resolution_ref: str | None = None
    board_digest: str | None = None
    vesting: tuple[VestingRecord, ...] = Field(default_factory=tuple, max_length=200)
    last_period_ref: str | None = None
    months_elapsed: int = 0
    vested_units: int = 0
    unvested_units: int = 0
    forfeited_units: int = 0
    terminated_at: str | None = None
    exercise_deadline: str | None = None
    exercises: tuple[ExerciseRecord, ...] = Field(default_factory=tuple, max_length=100)
    exercised_units: int = 0
    proceeds_total: Decimal = Field(default=Decimal("0"), validate_default=True)
    lapsed_units: int = 0
    cancel_reason: str | None = None
    outcome: Literal["open", "exercised", "lapsed", "cancelled"] = "open"

    @field_validator("vesting", "exercises", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("strike_price", mode="before")
    @classmethod
    def _price(cls, value: Any) -> Decimal:
        return Decimal(str(value)).quantize(PRICE_QUANTUM, rounding=ROUND_HALF_UP)

    @field_validator("proceeds_total", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="proceeds_total")


class GrantEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    shares_issued: Literal[False] = False
    filing_made: Literal[False] = False
    money_moved: Literal[False] = False
    provider_read: Literal[False] = False


def _vested_through(units: int, cliff: int, vesting: int, months: int) -> int:
    if months < cliff or months <= 0:
        return 0
    if months >= vesting:
        return units
    return int((Decimal(units) * Decimal(months) / Decimal(vesting)).to_integral_value(rounding=ROUND_DOWN))


def _apply_grant(plan: EquityPlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event, at = command.receipt, command.event, command.occurred_at
    if event == "grant":
        require(r.grant_ref is not None and r.holder_ref is not None and r.units is not None and r.strike_price is not None and r.granted_at is not None, "GRANT_MISSING", "a grant names itself, the holder, the units, the strike, and the grant date")
        assert r.units is not None and r.strike_price is not None
        require(0 < r.units <= plan.pool_units, "GRANT_EXCEEDS_POOL", f"{r.units} units exceed the pool of {plan.pool_units}")
        require(r.strike_price > 0, "STRIKE_INVALID", "a strike price is positive")
        require(parsed(str(r.granted_at)) <= parsed(at), "GRANT_FROM_FUTURE", "the grant cannot come from the future")
        cliff = plan.default_cliff_months if r.cliff_months is None else r.cliff_months
        vesting = plan.default_vesting_months if r.vesting_months is None else r.vesting_months
        require(0 <= cliff <= vesting and vesting >= 1, "SCHEDULE_INVALID", "the cliff sits inside a vesting period of at least one month")
        board_digest = None
        if plan.require_board_resolution:
            require(r.resolution_ref is not None and r.board_source is not None and r.board_plan is not None, "RESOLUTION_MISSING", "the plan requires the replayed board meeting whose carried resolution approves this grant", "await_approval")
            from lightbulb.board_cadence_chain import BOARD_CADENCE_LIFECYCLE

            try:
                board_plan, meeting = BOARD_CADENCE_LIFECYCLE.bind(r.board_plan, r.board_source)
            except (ValueError, TypeError, KeyError) as exc:
                require(False, "RESOLUTION_NOT_PROVEN", f"the meeting must replay against its exact plan: {exc}"[:300])
                raise AssertionError from exc
            require(board_plan.company_ref == plan.company_ref, "RESOLUTION_SCOPE_MISMATCH", "the meeting belongs to another company")
            require(meeting.status in ("minuted", "closed"), "MEETING_NOT_MINUTED", f"the meeting is {meeting.status}; a grant rests on minuted resolutions")
            resolution = next((item for item in meeting.ledger.resolutions if item.resolution_ref == str(r.resolution_ref)), None)
            require(resolution is not None and resolution.carried, "RESOLUTION_NOT_CARRIED", f"{r.resolution_ref} was not carried at {meeting.ledger.meeting_ref}")
            assert resolution is not None
            require(str(r.grant_ref) in resolution.text or str(r.holder_ref) in resolution.text, "RESOLUTION_NOT_FOR_GRANT", f"{r.resolution_ref} does not name this grant or its holder")
            require(parsed(str(meeting.ledger.held_at)) <= parsed(str(r.granted_at)), "GRANT_BEFORE_RESOLUTION", "the grant follows the meeting that approved it")
            board_digest = meeting.state_digest
        data.update({"grant_ref": r.grant_ref, "holder_ref": r.holder_ref, "units": r.units, "strike_price": str(r.strike_price), "granted_at": r.granted_at, "cliff_months": cliff, "vesting_months": vesting, "resolution_ref": r.resolution_ref, "board_digest": board_digest, "unvested_units": r.units})
    elif event == "vest":
        require(r.period_ref is not None, "PERIOD_MISSING", "vesting names one calendar month")
        require(data.get("terminated_at") is None, "GRANT_TERMINATED", "a terminated grant vests no further")
        try:
            start, end = _month_bounds(str(r.period_ref))
        except ValueError as exc:
            require(False, "PERIOD_INVALID", str(exc))
            raise AssertionError from exc
        last = data.get("last_period_ref")
        if last is None:
            require(parsed(str(data["granted_at"])) < parsed(end), "PERIOD_BEFORE_GRANT", f"{r.period_ref} ends before the grant")
        else:
            require(str(r.period_ref) == _next_month(str(last)), "PERIOD_NOT_CONTIGUOUS", f"the next month after {last} is {_next_month(str(last))}, not {r.period_ref}")
        require(parsed(end) <= parsed(at), "PERIOD_NOT_ENDED", f"{r.period_ref} has not ended")
        months = int(data.get("months_elapsed", 0)) + 1
        units, cliff, vesting = int(data["units"]), int(data["cliff_months"]), int(data["vesting_months"])
        cumulative = _vested_through(units, cliff, vesting, months)
        delta = cumulative - int(data.get("vested_units", 0))
        record = VestingRecord(period_ref=str(r.period_ref), months_elapsed=months, units_vested=delta, cumulative_vested=cumulative).to_dict()
        data.update({"vesting": [*[dict(item) for item in data.get("vesting", ())], record], "last_period_ref": r.period_ref, "months_elapsed": months, "vested_units": cumulative, "unvested_units": units - cumulative})
        if cumulative >= units:
            return "fully_vested", data
    elif event == "terminate":
        require(r.terminated_at is not None, "TERMINATION_MISSING", "a termination names the leaving date")
        require(data.get("terminated_at") is None, "ALREADY_TERMINATED", "the grant is already terminated")
        require(parsed(str(data["granted_at"])) <= parsed(str(r.terminated_at)) <= parsed(at), "TERMINATION_TIME_INVALID", "the termination follows the grant and precedes the recording")
        forfeited = int(data.get("unvested_units", 0))
        data.update({"terminated_at": r.terminated_at, "forfeited_units": forfeited, "unvested_units": 0, "exercise_deadline": iso(parsed(str(r.terminated_at)) + timedelta(days=plan.exercise_window_days))})
        if int(data.get("vested_units", 0)) - int(data.get("exercised_units", 0)) <= 0:
            data.update({"lapsed_units": 0, "outcome": "lapsed"})
            return "lapsed", data
    elif event == "exercise":
        require(r.exercise_ref is not None and r.exercise_units is not None and r.proceeds_provenance is not None and r.proceeds_digest is not None and r.proceeds is not None and r.exercised_at is not None, "EXERCISE_NOT_PROVEN", "an exercise is a bank read for the strike times the units")
        require(str(dict(r.proceeds_provenance or {}).get("output_digest")) == r.proceeds_digest, "EXERCISE_NOT_PROVEN", "the provenance does not seal this bank read")
        assert r.exercise_units is not None and r.proceeds is not None
        exercisable = int(data.get("vested_units", 0)) - int(data.get("exercised_units", 0))
        require(0 < r.exercise_units <= exercisable, "EXERCISE_EXCEEDS_VESTED", f"{r.exercise_units} units requested; {exercisable} vested and unexercised")
        expected = _money(Decimal(str(data["strike_price"])) * r.exercise_units)
        require(_money(r.proceeds) == expected, "PROCEEDS_MISMATCH", f"exercising {r.exercise_units} units at {data['strike_price']} is {expected}; the bank shows {r.proceeds}")
        require(parsed(str(data["granted_at"])) <= parsed(str(r.exercised_at)) <= parsed(at), "EXERCISE_TIME_INVALID", "the exercise follows the grant and precedes the recording")
        deadline = data.get("exercise_deadline")
        require(deadline is None or parsed(str(r.exercised_at)) <= parsed(str(deadline)), "EXERCISE_WINDOW_CLOSED", f"the exercise window closed at {deadline}")
        require(all(str(r.exercise_ref) != item["exercise_ref"] for item in data.get("exercises", ())), "EXERCISE_ALREADY_RECORDED", f"{r.exercise_ref} is already recorded")
        record = ExerciseRecord(exercise_ref=str(r.exercise_ref), units=r.exercise_units, proceeds=_money(r.proceeds), exercised_at=str(r.exercised_at), proceeds_digest=str(r.proceeds_digest)).to_dict()
        exercised = int(data.get("exercised_units", 0)) + r.exercise_units
        data.update({"exercises": [*[dict(item) for item in data.get("exercises", ())], record], "exercised_units": exercised, "proceeds_total": str(_money(Decimal(str(data["proceeds_total"])) + r.proceeds))})
        if exercised >= int(data["units"]) or (data.get("terminated_at") is not None and exercised >= int(data.get("vested_units", 0))):
            data["outcome"] = "exercised"
            return "exercised", data
    elif event == "lapse":
        deadline = data.get("exercise_deadline")
        require(deadline is not None, "NOT_TERMINATED", "only a terminated grant lapses; a live grant is cancelled with a reason")
        require(parsed(str(deadline)) < parsed(at), "WINDOW_STILL_OPEN", f"the exercise window runs until {deadline}")
        data.update({"lapsed_units": int(data.get("vested_units", 0)) - int(data.get("exercised_units", 0)), "outcome": "lapsed"})
    elif event == "cancel":
        data.update({"cancel_reason": str(command.reason)[:300], "forfeited_units": int(data.get("units", 0)) - int(data.get("exercised_units", 0)), "unvested_units": 0, "outcome": "cancelled"})
    return next_status, data


EQUITY_GRANT_LIFECYCLE = LifecycleSpec(entity="equity_grant", schema_prefix=EQUITY_GRANT_KIND, statuses=GRANT_STATUSES, terminal=TERMINAL_GRANT_STATUSES, events=GRANT_EVENTS, table=_GRANT_TABLE, opening_event="grant", reason_events=("cancel",), apply=_apply_grant, ledger_model=GrantLedger, receipt_model=GrantReceipt, effect_boundary_model=GrantEffectBoundary, plan_model=EquityPlan, max_transitions=MAX_GRANT_TRANSITIONS)
EquityGrantState = EQUITY_GRANT_LIFECYCLE.State


def open_equity_grant(plan: EquityPlan | Mapping[str, Any], scope: Mapping[str, Any], *, receipt: Mapping[str, Any], opened_at: str, actor_ref: str) -> Any:
    return EQUITY_GRANT_LIFECYCLE.open(plan, scope, opened_at=opened_at, actor_ref=actor_ref, receipt=receipt)


def advance_equity_grant(plan: EquityPlan | Mapping[str, Any], state: Any, command: Any) -> Any:
    return EQUITY_GRANT_LIFECYCLE.advance(plan, state, command)


# --------------------------------------------------------------------------- #
# Receipts
# --------------------------------------------------------------------------- #


def grant_receipt(*, grant_ref: str, holder_ref: str, units: int, strike_price: Any, granted_at: str, cliff_months: int | None = None, vesting_months: int | None = None) -> dict[str, Any]:
    receipt: dict[str, Any] = {"grant_ref": grant_ref, "holder_ref": holder_ref, "units": int(units), "strike_price": str(Decimal(str(strike_price)).quantize(PRICE_QUANTUM, rounding=ROUND_HALF_UP)), "granted_at": timestamp(granted_at, field_name="granted_at"), "evidence_refs": [f"grant:{grant_ref}"]}
    if cliff_months is not None:
        receipt["cliff_months"] = int(cliff_months)
    if vesting_months is not None:
        receipt["vesting_months"] = int(vesting_months)
    return receipt


def resolution_receipt(meeting_state: Any, *, source_plan: Any, resolution_ref: str) -> dict[str, Any]:
    """The replayed board meeting whose carried resolution approves the grant; merge with ``grant_receipt``."""

    from lightbulb.board_cadence_chain import BOARD_CADENCE_LIFECYCLE

    try:
        plan, state = BOARD_CADENCE_LIFECYCLE.bind(source_plan, meeting_state)
    except (ValueError, TypeError, KeyError) as exc:
        raise EquityGrantError("RESOLUTION_NOT_PROVEN", "retain the original meeting state and its sealed plan") from exc
    _require(any(item.resolution_ref == resolution_ref and item.carried for item in state.ledger.resolutions), "RESOLUTION_NOT_CARRIED", f"{resolution_ref} was not carried at {state.ledger.meeting_ref}")
    return {"resolution_ref": resolution_ref, "board_source": state.to_dict(), "board_plan": plan.to_dict(), "evidence_refs": [f"resolution:{state.scope.entity_ref}:{resolution_ref}"]}


def vest_receipt(*, period_ref: str) -> dict[str, Any]:
    _month_bounds(period_ref)
    return {"period_ref": period_ref, "evidence_refs": [f"period:{period_ref}"]}


def termination_receipt(*, terminated_at: str) -> dict[str, Any]:
    return {"terminated_at": timestamp(terminated_at, field_name="terminated_at"), "evidence_refs": [f"termination:{terminated_at[:10]}"]}


def exercise_receipt(provenance: Mapping[str, Any] | Any, payload: Mapping[str, Any] | Any, *, exercise_ref: str, units: int) -> dict[str, Any]:
    """From a bank read: the holder's payment of the strike for ``units``."""

    prov = dict(detached(provenance))
    _require(str(prov.get("source_tool", "")) in PROCEEDS_TOOLS, "EXERCISE_NOT_PROVEN", f"expected a read from {sorted(PROCEEDS_TOOLS)}, got {prov.get('source_tool')!r}")
    for key in ("observation_ref", "provenance_digest", "output_digest", "completed_at"):
        _require(bool(prov.get(key)), "EXERCISE_NOT_PROVEN", f"the provenance lacks {key}")
    raw = dict(detached(payload))
    _require(str(prov["output_digest"]) == stable_digest(raw), "EXERCISE_NOT_PROVEN", "the provenance does not seal this exact bank read")
    amount = raw.get("amount") if raw.get("amount") is not None else (None if raw.get("amount_minor") is None else Decimal(str(raw["amount_minor"])) / 100)
    stamp = raw.get("received_at") or raw.get("date") or raw.get("completed_at")
    _require(amount is not None and stamp is not None, "EXERCISE_INCOMPLETE", "a bank read carries the amount and the time")
    return {"exercise_ref": exercise_ref, "exercise_units": int(units), "proceeds_provenance": prov, "proceeds_digest": str(prov["output_digest"]), "proceeds": str(_money(decimal_value(amount, field_name="amount"))), "exercised_at": timestamp(str(stamp), field_name="exercised_at"), "evidence_refs": [f"exercise:{prov['observation_ref']}"]}


# --------------------------------------------------------------------------- #
# What the chain hands to the other engines
# --------------------------------------------------------------------------- #


def issued_shares(state: Any, *, source_plan: Any) -> dict[str, Any]:
    """The cap table row an exercise created: the holder, the class, the shares, and the cash that paid for them."""

    plan, bound = EQUITY_GRANT_LIFECYCLE.bind(source_plan, state)
    ledger = bound.ledger
    _require(ledger.exercised_units > 0, "NOTHING_EXERCISED", "no shares have been issued on this grant")
    return {"schema": ISSUED_SHARES_SCHEMA, "grant_ref": ledger.grant_ref, "holder_ref": ledger.holder_ref, "share_class": plan.share_class, "shares": ledger.exercised_units, "proceeds": str(ledger.proceeds_total), "currency": plan.currency, "from_pool": plan.pool_holder_ref, "source_digest": bound.state_digest}


def pool_summary(states: Sequence[Any], *, source_plan: Any) -> dict[str, Any]:
    plan = EquityPlan.model_validate(detached(source_plan)) if not isinstance(source_plan, EquityPlan) else source_plan
    granted = vested = exercised = forfeited = lapsed = 0
    live = 0
    for state in states:
        _plan, bound = EQUITY_GRANT_LIFECYCLE.bind(source_plan, state)
        ledger = bound.ledger
        if bound.status != "cancelled":
            granted += ledger.units
        vested += ledger.vested_units
        exercised += ledger.exercised_units
        forfeited += ledger.forfeited_units
        lapsed += ledger.lapsed_units
        if bound.status in ("granted", "vesting", "fully_vested"):
            live += ledger.units - ledger.forfeited_units - ledger.exercised_units
    committed = live + exercised
    return {"pool_units": plan.pool_units, "granted_units": granted, "outstanding_units": live, "vested_units": vested, "exercised_units": exercised, "forfeited_units": forfeited, "lapsed_units": lapsed, "pool_remaining": plan.pool_units - committed, "over_pool": committed > plan.pool_units}


def exercise_window_signal(states: Sequence[Any], *, source_plan: Any, now: str, within_days: int = 14) -> dict[str, Any] | None:
    """``signals.option_window_closing`` for terminated grants with vested, unexercised options whose window closes within ``within_days``."""

    stamp = timestamp(now, field_name="now")
    horizon = parsed(stamp) + timedelta(days=within_days)
    rows = []
    for state in states:
        _plan, bound = EQUITY_GRANT_LIFECYCLE.bind(source_plan, state)
        ledger = bound.ledger
        if bound.status in ("vesting", "fully_vested") and ledger.exercise_deadline is not None and parsed(str(ledger.exercise_deadline)) <= horizon and ledger.vested_units - ledger.exercised_units > 0:
            rows.append({"grant_ref": ledger.grant_ref, "holder_ref": ledger.holder_ref, "exercise_deadline": ledger.exercise_deadline, "exercisable_units": ledger.vested_units - ledger.exercised_units})
    if not rows:
        return None
    rows.sort(key=lambda row: (str(row["exercise_deadline"]), str(row["grant_ref"])))
    return {"name": "signals.option_window_closing", "producer": EQUITY_GRANT_KIND, "emitted_at": stamp, "payload": {"grant_refs": [row["grant_ref"] for row in rows], "holder_refs": sorted({str(row["holder_ref"]) for row in rows}), "earliest_deadline": rows[0]["exercise_deadline"], "exercisable_units": sum(int(row["exercisable_units"]) for row in rows), "source_digest": stable_digest(rows)}}


def equity_summary(states: Sequence[Any]) -> dict[str, Any]:
    counts = {status: sum(1 for state in states if state.status == status) for status in GRANT_STATUSES}
    return {"grants": len(states), "by_status": counts, "holders": sorted({str(state.ledger.holder_ref) for state in states if state.status not in ("cancelled",)}), "proceeds_total": str(_money(sum((state.ledger.proceeds_total for state in states), Decimal("0")))), "awaiting_exercise": [state.scope.entity_ref for state in states if state.status in ("vesting", "fully_vested") and state.ledger.exercise_deadline is not None]}


EQUITY_GRANT_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": EQUITY_GRANT_KIND,
    "golden_loop": EQUITY_GRANT_GOLDEN_LOOP,
    "stages": ["grant", "vest", "terminate", "exercise", "lapse"],
    "statuses": list(GRANT_STATUSES),
    "events": list(GRANT_EVENTS),
    "hops": {"grant": "the grant inside the pool, on the replayed board meeting's carried resolution when the plan requires it", "vest": "one contiguous calendar month; vested units computed from the cliff and the period", "terminate": "the leaving date; unvested units forfeited and the exercise window opened", "exercise": "a bank read for exactly the strike times the units, inside the window", "lapse": "a terminated grant whose window has passed"},
    "tools": {"proceeds": sorted(PROCEEDS_TOOLS)},
    "required_connectors": ["xero", "lightbulb.sdk_engine_state"],
    "hard_rules": [
        "a grant never exceeds the pool and, when the plan says so, rests on a minuted, carried board resolution that names it",
        "vesting is computed month by month and never skips or repeats a month",
        "shares are issued only for cash observed at exactly the strike",
        "nothing here issues shares or files anything",
    ],
}

__all__ = ["EQUITY_GRANT_GOLDEN_LOOP", "EQUITY_GRANT_KIND", "EQUITY_GRANT_LIFECYCLE", "EQUITY_GRANT_MANIFEST", "GRANT_EVENTS", "GRANT_STATUSES", "ISSUED_SHARES_SCHEMA", "PROCEEDS_TOOLS", "TERMINAL_GRANT_STATUSES", "EquityGrantError", "EquityGrantState", "EquityPlan", "ExerciseRecord", "GrantEffectBoundary", "GrantLedger", "GrantReceipt", "VestingRecord", "advance_equity_grant", "compile_equity_plan", "equity_summary", "exercise_receipt", "exercise_window_signal", "grant_receipt", "issued_shares", "open_equity_grant", "pool_summary", "resolution_receipt", "termination_receipt", "vest_receipt"]
