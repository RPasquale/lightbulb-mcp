"""The 13-week cash-flow forecast: the CFO's operating liquidity calendar.

Runway answers "how many months until zero at today's average burn." Default-
alive answers "do we reach profitability before the money runs out." Neither
tells an operator the thing they check every Monday: **will we make payroll in
week 6, and does the big customer payment land before rent is due?** That is the
13-week cash-flow forecast — the discrete, dated, week-by-week cash calendar
every startup CFO runs — and this module builds it.

It projects an opening cash balance forward over a horizon (13 weeks by default)
across the caller's *scheduled* receipts and payments, optionally plus an
assumed weekly operating run-rate for opex that has not been itemized. It is a
scenario calculator, not a forecast in the fortune-telling sense: it computes
the deterministic consequence of the cash movements the caller states, and it is
scrupulous about the direction of its own error. If ongoing opex is neither
itemized nor asserted complete nor covered by a run-rate, the outflow side is
understated, the balances are an **optimistic ceiling**, and the result says so
in as many words — the same honesty rule the runway engine lives by, because a
liquidity forecast that reads rosier than reality is how a company misses
payroll while believing it was fine.

Holds no keyring, does no I/O. Deterministic and digest-bound.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from typing import Annotated, Any, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
)

from .primitive_runtime import (
    BusinessProcessPrimitive,
    PrimitiveEvent,
    PrimitiveEvidence,
    PrimitiveExecutionContext,
    PrimitiveExecutionResult,
    PrimitiveExecutionStatus,
)

CASH_FLOW_FORECAST_SCHEMA = "lightbulb.cash_flow_forecast.v1"

_MONEY_QUANTUM = Decimal("0.01")

_PORTABLE_REF_PATTERN = r"^[a-z][a-z0-9_-]{0,63}$"
_CURRENCY_PATTERN = r"^[A-Z]{3}$"

CashEventDirection = Literal["inflow", "outflow"]
ForecastCoverage = Literal[
    "asserted_complete", "run_rate_estimated", "itemized_only_incomplete"
]
ForecastReliability = Literal["projection", "optimistic_ceiling"]


class CashForecastError(ValueError):
    """The forecast inputs cannot produce an honest cash calendar."""


def _stable_digest(value: Any) -> str:
    canonical = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _bounded_text(value: str) -> str:
    if value != value.strip():
        raise ValueError("content must not contain surrounding whitespace")
    if any(ord(character) < 32 for character in value):
        raise ValueError("content contains an unsupported control character")
    return value


ShortText = Annotated[
    str,
    StringConstraints(min_length=1, max_length=300),
    AfterValidator(_bounded_text),
]
PortableRef = Annotated[str, StringConstraints(pattern=_PORTABLE_REF_PATTERN)]
CurrencyCode = Annotated[str, StringConstraints(pattern=_CURRENCY_PATTERN)]


def _normalized_timestamp(value: str) -> str:
    clean = value.strip()
    try:
        parsed = datetime.fromisoformat(clean.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamp must be valid ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must include a UTC offset")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _iso_z(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _decimal(
    value: Any, *, quantum: Decimal | None = None, allow_negative: bool = False
) -> Decimal:
    if not isinstance(value, (str, Decimal, int, float)) or isinstance(value, bool):
        raise ValueError("decimal values must be supplied as strings or JSON numbers")
    lexical = str(value)
    if len(lexical) > 48 or lexical != lexical.strip():
        raise ValueError("value must use bounded decimal notation")
    try:
        parsed = Decimal(lexical)
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("value must be a finite decimal") from exc
    if not parsed.is_finite():
        raise ValueError("value must be a finite decimal")
    if not allow_negative and parsed < 0:
        raise ValueError("value must be non-negative")
    if quantum is not None:
        try:
            normalized = parsed.quantize(quantum)
        except InvalidOperation as exc:
            raise ValueError(
                "value cannot be represented at the required precision"
            ) from exc
        if parsed != normalized:
            raise ValueError(
                f"value supports at most {-quantum.as_tuple().exponent} decimal places"
            )
        return normalized
    return parsed


def _immutable_sequence(value: Any) -> Any:
    if isinstance(value, list):
        return tuple(value)
    return value


def _quantized_money(value: Decimal) -> Decimal:
    return value.quantize(_MONEY_QUANTUM, rounding=ROUND_HALF_UP)


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=False,
        serialize_by_alias=True,
        strict=True,
    )


# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------


class ScheduledCashEvent(_StrictModel):
    """One known, dated cash movement: a receipt or a payment in a given week."""

    event_ref: ShortText
    week_index: int = Field(ge=1, le=52)
    direction: CashEventDirection
    amount: Decimal = Field(gt=0)
    category: ShortText | None = None

    @field_validator("amount", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_MONEY_QUANTUM)


class CashFlowForecastInput(_StrictModel):
    forecast_ref: PortableRef
    as_of: str
    currency: CurrencyCode
    opening_cash: Decimal = Field(ge=0)
    horizon_weeks: int = Field(default=13, ge=1, le=52)
    scheduled_events: tuple[ScheduledCashEvent, ...] = Field(
        default_factory=tuple, max_length=500
    )
    # An assumed weekly run-rate for ongoing opex that has NOT been itemized as
    # events. Supplying it models opex as a labeled estimate; omitting it (with
    # events_are_complete False) means opex is unmodeled and balances are a
    # dangerous ceiling.
    assumed_weekly_operating_outflow: Decimal | None = None
    # The caller asserts the scheduled events fully capture cash movement, so no
    # run-rate is needed. Use only when the events truly are the whole picture.
    events_are_complete: bool = False

    @field_validator("as_of")
    @classmethod
    def _valid_as_of(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator("opening_cash", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_MONEY_QUANTUM)

    @field_validator("assumed_weekly_operating_outflow", mode="before")
    @classmethod
    def _opt_money(cls, value: Any) -> Decimal | None:
        if value is None:
            return None
        return _decimal(value, quantum=_MONEY_QUANTUM)

    @field_validator("scheduled_events", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _immutable_sequence(value)


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


class WeekProjection(_StrictModel):
    week_index: int = Field(ge=1, le=52)
    week_ending: str
    inflows: Decimal = Field(ge=0)
    outflows: Decimal = Field(ge=0)
    net_change: Decimal
    ending_cash: Decimal

    @field_validator("inflows", "outflows", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_MONEY_QUANTUM)

    @field_validator("net_change", "ending_cash", mode="before")
    @classmethod
    def _signed_money(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_MONEY_QUANTUM, allow_negative=True)


class CashFlowForecast(_StrictModel):
    """A dated, week-by-week cash calendar with an honest reliability flag."""

    schema_id: Literal["lightbulb.cash_flow_forecast.v1"] = Field(
        default=CASH_FLOW_FORECAST_SCHEMA,
        alias="schema",
    )
    forecast_ref: PortableRef
    as_of: str
    currency: CurrencyCode
    opening_cash: Decimal = Field(ge=0)
    horizon_weeks: int = Field(ge=1, le=52)
    weeks: tuple[WeekProjection, ...] = Field(default_factory=tuple)
    closing_cash: Decimal
    total_inflows: Decimal = Field(ge=0)
    total_outflows: Decimal = Field(ge=0)
    lowest_cash: Decimal
    lowest_cash_week: int | None = None
    first_negative_week: int | None = None
    coverage: ForecastCoverage
    reliability: ForecastReliability
    assumed_weekly_operating_outflow: Decimal | None = None
    notes: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=12)
    forecast_digest: str = "0" * 64

    @field_validator("as_of")
    @classmethod
    def _valid_as_of(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator("opening_cash", "total_inflows", "total_outflows", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_MONEY_QUANTUM)

    @field_validator("closing_cash", "lowest_cash", mode="before")
    @classmethod
    def _signed_money(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_MONEY_QUANTUM, allow_negative=True)

    @field_validator("assumed_weekly_operating_outflow", mode="before")
    @classmethod
    def _opt_money(cls, value: Any) -> Decimal | None:
        if value is None:
            return None
        return _decimal(value, quantum=_MONEY_QUANTUM, allow_negative=True)

    @field_validator("weeks", "notes", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def build_cash_flow_forecast(
    inputs: CashFlowForecastInput | Mapping[str, Any],
) -> CashFlowForecast:
    """Project opening cash forward, week by week, over the scheduled events.

    Each week's ending balance is the prior balance plus scheduled inflows less
    scheduled outflows less any assumed operating run-rate. The result surfaces
    the trough (lowest projected cash and the week it hits) and the first week
    the balance goes negative — the liquidity cliff. When ongoing opex is neither
    itemized, asserted complete, nor covered by a run-rate, the forecast is
    marked an ``optimistic_ceiling``: its balances are the best case, not a plan.
    """

    parsed = (
        inputs
        if isinstance(inputs, CashFlowForecastInput)
        else CashFlowForecastInput.model_validate(inputs)
    )

    horizon = parsed.horizon_weeks
    over_horizon = [e for e in parsed.scheduled_events if e.week_index > horizon]
    if over_horizon:
        raise CashForecastError(
            f"{len(over_horizon)} scheduled event(s) fall beyond the "
            f"{horizon}-week horizon; extend the horizon or drop them"
        )

    run_rate = parsed.assumed_weekly_operating_outflow or Decimal("0")
    start = _parse_utc(parsed.as_of)

    inflow_by_week: dict[int, Decimal] = {}
    outflow_by_week: dict[int, Decimal] = {}
    for event in parsed.scheduled_events:
        bucket = inflow_by_week if event.direction == "inflow" else outflow_by_week
        bucket[event.week_index] = bucket.get(event.week_index, Decimal("0")) + event.amount

    weeks: list[WeekProjection] = []
    balance = parsed.opening_cash
    lowest_cash = parsed.opening_cash
    lowest_week: int | None = None
    first_negative: int | None = None
    total_in = Decimal("0")
    total_out = Decimal("0")

    for week in range(1, horizon + 1):
        week_in = inflow_by_week.get(week, Decimal("0"))
        week_out = outflow_by_week.get(week, Decimal("0")) + run_rate
        net = week_in - week_out
        balance = balance + net
        total_in += week_in
        total_out += week_out
        if balance < lowest_cash:
            lowest_cash = balance
            lowest_week = week
        if balance < 0 and first_negative is None:
            first_negative = week
        weeks.append(
            WeekProjection(
                week_index=week,
                week_ending=_iso_z(start + timedelta(weeks=week)),
                inflows=_quantized_money(week_in),
                outflows=_quantized_money(week_out),
                net_change=_quantized_money(net),
                ending_cash=_quantized_money(balance),
            )
        )

    if parsed.events_are_complete:
        coverage: ForecastCoverage = "asserted_complete"
    elif parsed.assumed_weekly_operating_outflow is not None:
        coverage = "run_rate_estimated"
    else:
        coverage = "itemized_only_incomplete"
    reliability: ForecastReliability = (
        "optimistic_ceiling" if coverage == "itemized_only_incomplete" else "projection"
    )

    notes: list[str] = []
    if coverage == "itemized_only_incomplete":
        notes.append(
            "ongoing opex is not modeled (no run-rate, events not asserted complete); "
            "balances are an optimistic ceiling, not a plan"
        )
    elif coverage == "run_rate_estimated":
        notes.append(
            f"ongoing opex modeled at an assumed {run_rate} {parsed.currency}/week "
            "run-rate; refine by itemizing real payments"
        )
    else:
        notes.append("caller asserts the scheduled events are the complete cash picture")
    if first_negative is not None:
        notes.append(
            f"cash goes negative in week {first_negative}; act before then, not after"
        )
    if not parsed.scheduled_events:
        if parsed.assumed_weekly_operating_outflow is not None:
            notes.append("no scheduled events supplied; this is a run-rate-only projection")
        else:
            notes.append(
                "no scheduled events and no run-rate; the balance is held flat — "
                "supply cash movements to make this useful"
            )

    forecast = CashFlowForecast(
        forecast_ref=parsed.forecast_ref,
        as_of=parsed.as_of,
        currency=parsed.currency,
        opening_cash=parsed.opening_cash,
        horizon_weeks=horizon,
        weeks=tuple(weeks),
        closing_cash=_quantized_money(balance),
        total_inflows=_quantized_money(total_in),
        total_outflows=_quantized_money(total_out),
        lowest_cash=_quantized_money(lowest_cash),
        lowest_cash_week=lowest_week,
        first_negative_week=first_negative,
        coverage=coverage,
        reliability=reliability,
        assumed_weekly_operating_outflow=parsed.assumed_weekly_operating_outflow,
        notes=tuple(dict.fromkeys(notes))[:12],
    )
    digest = _stable_digest(
        forecast.model_dump(mode="json", exclude={"forecast_digest"})
    )
    return forecast.model_copy(update={"forecast_digest": digest})


# ---------------------------------------------------------------------------
# Executable primitive
# ---------------------------------------------------------------------------


class BuildCashFlowForecastPrimitive(
    BusinessProcessPrimitive[CashFlowForecastInput, CashFlowForecast]
):
    """Build the 13-week cash-flow forecast — the CFO's liquidity calendar."""

    primitive_ref = "cash.build_cash_flow_forecast"
    version = "1.0.0"
    title = "Build the 13-week cash-flow forecast"
    description = (
        "Project an opening cash balance forward week by week over a horizon "
        "(13 weeks by default) across the caller's scheduled receipts and "
        "payments, plus an optional assumed weekly operating run-rate. Returns a "
        "dated week-by-week calendar, the cash trough and the week it hits, and "
        "the first week the balance goes negative. It is a scenario calculator, "
        "not a prediction: when ongoing opex is neither itemized nor asserted "
        "complete nor covered by a run-rate, the balances are flagged an "
        "optimistic ceiling rather than a plan."
    )
    input_model = CashFlowForecastInput
    output_model = CashFlowForecast
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs = {
        "forecast_ref": "q3-13week-example",
        "as_of": "2026-08-02T00:00:00Z",
        "currency": "USD",
        "opening_cash": "80000.00",
        "horizon_weeks": 13,
        "assumed_weekly_operating_outflow": "5000.00",
        "scheduled_events": (
            {
                "event_ref": "payroll-w2",
                "week_index": 2,
                "direction": "outflow",
                "amount": "42000.00",
                "category": "payroll",
            },
            {
                "event_ref": "quarterly-rent",
                "week_index": 3,
                "direction": "outflow",
                "amount": "18000.00",
                "category": "rent",
            },
            {
                "event_ref": "enterprise-receivable",
                "week_index": 6,
                "direction": "inflow",
                "amount": "150000.00",
                "category": "customer_payment",
            },
            {
                "event_ref": "payroll-w8",
                "week_index": 8,
                "direction": "outflow",
                "amount": "42000.00",
                "category": "payroll",
            },
            {
                "event_ref": "payroll-w11",
                "week_index": 11,
                "direction": "outflow",
                "amount": "42000.00",
                "category": "payroll",
            },
        ),
    }

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: CashFlowForecastInput,
    ) -> PrimitiveExecutionResult[CashFlowForecast]:
        try:
            forecast = build_cash_flow_forecast(inputs)
        except ValueError as exc:
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.FAILED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary=f"cash-flow forecast rejected: {exc}",
                output=None,
            )
        cliff = (
            f"; negative in week {forecast.first_negative_week}"
            if forecast.first_negative_week is not None
            else ""
        )
        return PrimitiveExecutionResult[CashFlowForecast](
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                f"{forecast.forecast_ref}: {forecast.horizon_weeks}-week forecast, "
                f"closing {forecast.closing_cash} {forecast.currency}, "
                f"trough {forecast.lowest_cash} ({forecast.reliability}){cliff}."
            ),
            output=forecast,
            events=[
                PrimitiveEvent(
                    type="cash.cash_flow_forecast_built",
                    payload={
                        "forecast_ref": forecast.forecast_ref,
                        "reliability": forecast.reliability,
                        "first_negative_week": forecast.first_negative_week,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="deterministic_plan",
                    summary="Scenario over caller-scheduled cash events, not a prediction.",
                )
            ],
        )


__all__ = [
    "CASH_FLOW_FORECAST_SCHEMA",
    "BuildCashFlowForecastPrimitive",
    "CashEventDirection",
    "CashFlowForecast",
    "CashFlowForecastInput",
    "CashForecastError",
    "ForecastCoverage",
    "ForecastReliability",
    "ScheduledCashEvent",
    "WeekProjection",
    "build_cash_flow_forecast",
]
