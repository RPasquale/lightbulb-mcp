"""The 13-week cash calendar from the books alone: what the ledger's balances do to cash, under assumptions that are stated, never implied.

The cash forecast engine projects an opening balance across dated receipts
and payments.  A company with only its ledger connected has no dated
receivables or bills, but its books snapshot does carry the balances that
decide the next quarter: cash, what customers owe, what suppliers are owed,
the tax liability, and the recorded cost run-rate.  ``build_books_cash_forecast``
turns those into the engine's input and seals the result.

Every timing is an assumption the caller supplies and the document echoes:
the days in which receivables are collected, payables are paid and the tax
is paid.  A balance with no assumption is not scheduled and is named as
unscheduled, because a guessed date is worse than a visible gap.  The
recorded cost run-rate becomes the weekly operating outflow only when the
books record enough cost for it to mean anything; otherwise the engine's own
honesty rule marks the balances an optimistic ceiling.  Future sales are left
out unless the caller asks for receipts at the books' run-rate, and the
verdict says which calendar it is.  The document keeps the exact inputs and
re-runs the engine when it is verified, so the calendar cannot drift from
what produced it.  Nothing here reads a provider or persists anything.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from decimal import ROUND_HALF_UP, Decimal
from typing import Any

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
    parsed,
    seal,
    sealed_digest,
    skip_digests,
    timestamp,
)

BOOKS_CASH_FORECAST_SCHEMA = "lightbulb.books_cash_forecast.v1"
BOOKS_CASH_FORECAST_MANIFEST: dict[str, Any] = {"engine": "books_cash_forecast", "kind": "intelligence_document", "reads": ("books_snapshot",), "writes": ()}
_WEEK = Decimal("7")


class BooksCashForecastError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise BooksCashForecastError(code, message)


def _money(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


def _engine(inputs: Mapping[str, Any]) -> dict[str, Any]:
    from lightbulb.cash_forecast import build_cash_flow_forecast

    return build_cash_flow_forecast(dict(inputs)).to_dict()


class BooksCashForecast(StrictModel):
    schema_id: str = Field(default=BOOKS_CASH_FORECAST_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    as_of: str
    books_digest: Sha256Digest
    balances_as_at: str
    horizon_weeks: int = Field(ge=1, le=52)
    assumptions: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=12)
    unscheduled: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=12)
    forecast_inputs: dict[str, Any]
    forecast: dict[str, Any]
    opening_cash: Decimal
    closing_cash: Decimal
    lowest_cash: Decimal
    lowest_cash_week: int | None = None
    first_negative_week: int | None = None
    reliability: ShortText
    verdict: ShortText
    recommendations: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=12)
    source_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=4)
    cash_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("assumptions", "unscheduled", "recommendations", "source_digests", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("opening_cash", "closing_cash", "lowest_cash", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name), allow_negative=True)

    @field_validator("as_of", "balances_as_at")
    @classmethod
    def _stamps(cls, value: str, info: ValidationInfo) -> str:
        return timestamp(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "BooksCashForecast":
        if _engine(self.forecast_inputs) != self.forecast:
            raise ValueError("the calendar is the engine's answer to the retained inputs, exactly")
        calendar = self.forecast
        if (str(self.opening_cash), str(self.closing_cash), str(self.lowest_cash), self.lowest_cash_week, self.first_negative_week, self.reliability) != (str(_money(calendar["opening_cash"])), str(_money(calendar["closing_cash"])), str(_money(calendar["lowest_cash"])), calendar.get("lowest_cash_week"), calendar.get("first_negative_week"), calendar["reliability"]):
            raise ValueError("the headline figures are the calendar's own")
        if not skip_digests(info) and self.cash_digest != sealed_digest(BooksCashForecast, self, "cash_digest"):
            raise ValueError("cash_digest must commit the exact document")
        return self

    def render(self) -> str:
        lines = [f"**Cash calendar from the books** ({self.company_ref}, {self.horizon_weeks} weeks from {self.as_of[:10]}): {self.verdict}"]
        lines.extend(f"- assumed: {item}" for item in self.assumptions)
        lines.extend(f"- not scheduled: {item}" for item in self.unscheduled)
        return "\n".join(lines)


def build_books_cash_forecast(books: Mapping[str, Any] | Any, *, as_of: str, horizon_weeks: int = 13, receivables_collected_in_days: int | None = None, payables_paid_in_days: int | None = None, tax_paid_in_days: int | None = None, weekly_receipts_at_run_rate: bool = False, max_age_days: int = 45) -> BooksCashForecast:
    """The sealed cash calendar from one books snapshot and the caller's stated timings."""

    from lightbulb.books_snapshot import verify_books_snapshot

    snapshot = verify_books_snapshot(books)
    at = timestamp(as_of, field_name="as_of")
    _require(1 <= horizon_weeks <= 52, "HORIZON_INVALID", "the horizon is 1 to 52 weeks")
    _require(snapshot.balances_as_at is not None and snapshot.cash is not None, "BALANCES_MISSING", "the snapshot was taken without a balance sheet, so there is no opening cash")
    assert snapshot.balances_as_at is not None and snapshot.cash is not None
    age = (parsed(at) - parsed(snapshot.balances_as_at)).days
    _require(age <= max_age_days, "BOOKS_STALE", f"the balances are as at {snapshot.balances_as_at[:10]}, {age} day(s) before {at[:10]}; record fresh books first")
    _require(snapshot.cash >= 0, "OPENING_CASH_NEGATIVE", f"the books show cash of {snapshot.cash}; an overdrawn company needs its facility modelled, not a calendar from a negative opening balance")
    for name, value in (("receivables_collected_in_days", receivables_collected_in_days), ("payables_paid_in_days", payables_paid_in_days), ("tax_paid_in_days", tax_paid_in_days)):
        _require(value is None or 0 <= value <= 365, "ASSUMPTION_INVALID", f"{name} is 0 to 365 days")

    events: list[dict[str, Any]] = []
    assumptions: list[str] = []
    unscheduled: list[str] = []

    def schedule(label: str, balance: Decimal | None, days: int | None, direction: str, setting: str, verb: str) -> None:
        if balance is None:
            unscheduled.append(f"{label}: unknown in the books (no account is mapped to it)")
            return
        if balance <= 0:
            return
        if days is None:
            unscheduled.append(f"{label} of {balance} {snapshot.currency}: no {setting} was given, so it is left out rather than dated by guesswork")
            return
        week = max(1, math.ceil(days / 7))
        if week > horizon_weeks:
            unscheduled.append(f"{label} of {balance} {snapshot.currency}: {verb} in {days} day(s) falls after the {horizon_weeks}-week horizon")
            return
        events.append({"event_ref": f"books:{label.replace(' ', '_')}", "week_index": week, "direction": direction, "amount": str(balance), "category": label})
        assumptions.append(f"{label} of {balance} {snapshot.currency} {verb} in {days} day(s), week {week}")

    schedule("receivables", snapshot.receivables, receivables_collected_in_days, "inflow", "receivables_collected_in_days", "collected")
    schedule("payables", snapshot.payables, payables_paid_in_days, "outflow", "payables_paid_in_days", "paid")
    schedule("tax owed", snapshot.tax_owed, tax_paid_in_days, "outflow", "tax_paid_in_days", "paid")

    thin = snapshot.finding("NO_COSTS_RECORDED") is not None or snapshot.finding("COSTS_IMPLAUSIBLY_LOW") is not None
    weekly_cost = None if thin or snapshot.cost_per_day <= 0 else _money(snapshot.cost_per_day * _WEEK)
    if weekly_cost is not None:
        assumptions.append(f"operating costs continue at the books' recorded rate of {weekly_cost} {snapshot.currency} a week ({snapshot.cost_per_day} a day over {snapshot.period_label})")
    else:
        unscheduled.append("operating costs: the books record too little cost for a run-rate to mean anything, so none is assumed and every balance below is a ceiling")
    if weekly_receipts_at_run_rate:
        weekly_revenue = _money(snapshot.revenue / snapshot.days_in_window * _WEEK)
        if weekly_revenue > 0:
            for week in range(1, horizon_weeks + 1):
                events.append({"event_ref": f"books:receipts_week_{week}", "week_index": week, "direction": "inflow", "amount": str(weekly_revenue), "category": "receipts at run-rate"})
            assumptions.append(f"new sales are received at the books' run-rate of {weekly_revenue} {snapshot.currency} a week; this is an assumption about customers, not a fact in the ledger")
    else:
        assumptions.append("no new sales are assumed: this is what the balances already in the books do to cash")
    if age > 0:
        assumptions.append(f"opening cash is the ledger balance as at {snapshot.balances_as_at[:10]}, {age} day(s) before the calendar starts")
    elif age < 0:
        assumptions.append(f"opening cash is the ledger balance as at {snapshot.balances_as_at[:10]}, the month end the ledger reported, {-age} day(s) after the calendar starts")

    inputs: dict[str, Any] = {"forecast_ref": f"books-{snapshot.window_end[:10]}", "as_of": at, "currency": snapshot.currency, "opening_cash": str(snapshot.cash), "horizon_weeks": horizon_weeks, "scheduled_events": events}
    if weekly_cost is not None:
        inputs["assumed_weekly_operating_outflow"] = str(weekly_cost)
    calendar = _engine(inputs)
    lowest, low_week, negative_week = _money(calendar["lowest_cash"]), calendar.get("lowest_cash_week"), calendar.get("first_negative_week")
    ceiling = calendar["reliability"] == "optimistic_ceiling"
    if negative_week is not None:
        verdict = f"cash of {snapshot.cash} {snapshot.currency} runs out in week {negative_week} (lowest {lowest} in week {low_week})"
    else:
        verdict = f"cash of {snapshot.cash} {snapshot.currency} stays positive for {horizon_weeks} weeks, lowest {lowest}" + (f" in week {low_week}" if low_week is not None else "") + f", closing {_money(calendar['closing_cash'])}"
    verdict += "; an optimistic ceiling, because operating costs are not modelled" if ceiling else ""
    recommendations: list[str] = []
    if negative_week is not None:
        recommendations.append(f"cash is short by {abs(lowest)} {snapshot.currency} at its lowest: collect receivables sooner, defer what can be deferred, or arrange cover before week {negative_week}")
    if ceiling:
        recommendations.append("enter the costs the business really pays so the calendar can model them; until then it overstates every balance")
    recommendations.extend(f"give {item.split(':')[0]} a date: {item.split(': ', 1)[1]}" for item in unscheduled if "no " in item and " was given" in item)
    if not recommendations:
        recommendations.append("the balances in the books carry the company through the horizon under the stated assumptions")
    payload = {"company_ref": snapshot.company_ref, "currency": snapshot.currency, "as_of": at, "books_digest": snapshot.snapshot_digest, "balances_as_at": snapshot.balances_as_at, "horizon_weeks": horizon_weeks, "assumptions": [item[:300] for item in assumptions][:12], "unscheduled": [item[:300] for item in unscheduled][:12], "forecast_inputs": inputs, "forecast": calendar, "opening_cash": str(_money(calendar["opening_cash"])), "closing_cash": str(_money(calendar["closing_cash"])), "lowest_cash": str(lowest), "lowest_cash_week": low_week, "first_negative_week": negative_week, "reliability": calendar["reliability"], "verdict": verdict[:300], "recommendations": [item[:300] for item in recommendations][:12], "source_digests": [snapshot.snapshot_digest]}
    return seal(BooksCashForecast, {key: value for key, value in payload.items() if value is not None}, "cash_digest")


def verify_books_cash_forecast(value: Any) -> BooksCashForecast:
    return value if isinstance(value, BooksCashForecast) else BooksCashForecast.model_validate(dict(detached(value)))


__all__ = ["BOOKS_CASH_FORECAST_MANIFEST", "BOOKS_CASH_FORECAST_SCHEMA", "BooksCashForecast", "BooksCashForecastError", "build_books_cash_forecast", "verify_books_cash_forecast"]
