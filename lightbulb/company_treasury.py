"""Treasury: a weekly cash forecast from what the company actually owes, is owed, and plans to spend, and the guard that keeps a period from opening on cash it does not have.

Inputs are sealed observations and explicit schedules, never estimates typed
into a chat:

* ``cash_position`` from a balance read (Airwallex balances, or any bank
  balance payload with a currency and an available amount) with provenance;
* ``payables`` from the provider's bill page (Xero close source page or the
  QuickBooks QueryResponse) with open balances and due dates;
* ``receivables`` from the provider's invoice page the same way (or from
  ``accounting.assess_receivables`` expected collections);
* ``PayrollSchedule`` and ``FixedCostSchedule`` as explicit operator inputs;
* the operating plan's period budget as the discretionary outflow.

``forecast_cash`` lays those into weekly buckets over the horizon and seals a
``CashForecast`` with the balance at the end of every week, the first week
the balance goes below the floor, and the runway.  ``assess_cash_cover`` is
the guard: it says whether an outflow of a given amount at a given time is
covered without breaching the floor, so bring-up and the cadence can refuse
to open a period the cash cannot carry.  Nothing here moves money.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import timedelta
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, MONEY_QUANTUM, BoundedText, OpaqueRef, Sha256Digest, ShortText, StrictModel, decimal_value, detached, parsed, seal, sealed_digest, skip_digests, stable_digest, timestamp
from lightbulb.company_execution_bridge import BridgeError, ObservationProvenance
from lightbulb.inference_cost_register import InferenceCostRegister, verify_register
from lightbulb.company_operating_system import CompanyOperatingPlan

CASH_FORECAST_SCHEMA = "lightbulb.company_cash_forecast.v1"
CASH_COVER_SCHEMA = "lightbulb.company_cash_cover.v1"
BALANCE_TOOLS: tuple[str, ...] = ("airwallex.list_balances", "xero.list_bank_transactions", "quickbooks.list_accounts", "host.bank_balances")
BILL_TOOLS: tuple[str, ...] = ("xero.list_bills", "quickbooks.list_bills", "billcom.list_bills")
INVOICE_TOOLS: tuple[str, ...] = ("xero.list_invoices", "quickbooks.list_invoices")
FlowKind = Literal["opening_balance", "payable", "receivable", "merchant_payout", "payroll", "fixed_cost", "operating_budget", "tax_reservation", "inference_cost"]
_WEEK = timedelta(days=7)


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise BridgeError(code, message)


def _expect_tool(provenance: ObservationProvenance, *tools: str) -> None:
    _require(provenance.source_tool in tools, "OBSERVATION_TOOL_MISMATCH", f"this adapter reads {tools}; provenance names {provenance.source_tool}")


def _money(value: Any, name: str) -> Decimal:
    return decimal_value(str(value if value not in (None, "") else "0"), field_name=name, allow_negative=True)


def _date(value: Any, name: str) -> str:
    text = str(value)
    return timestamp(text if "T" in text else f"{text}T00:00:00Z", field_name=name)


# --------------------------------------------------------------------------- #
# Observations
# --------------------------------------------------------------------------- #


class CashPosition(StrictModel):
    source_tool: ShortText
    provenance_digest: Sha256Digest
    observed_at: str
    currency: ShortText
    available: Decimal
    pending: Decimal = Field(default=Decimal("0"), validate_default=True)
    accounts: int = Field(ge=1)

    @field_validator("observed_at")
    @classmethod
    def _observed(cls, value: str) -> str:
        return timestamp(value, field_name="observed_at")

    @field_validator("available", "pending", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _money(value, str(info.field_name))


def cash_position(provenance: ObservationProvenance, payload: Mapping[str, Any] | Sequence[Mapping[str, Any]], *, currency: str) -> CashPosition:
    """Available cash in ``currency`` from a balance read; rows in other currencies are ignored, not converted."""

    _expect_tool(provenance, *BALANCE_TOOLS)
    _require(stable_digest(payload) == provenance.output_digest, "OBSERVATION_DIGEST_MISMATCH", "cash balances must match the original provider read")
    rows = payload.get("items") if isinstance(payload, Mapping) and "items" in payload else (payload.get("data") if isinstance(payload, Mapping) and "data" in payload else payload)
    _require(isinstance(rows, Sequence) and not isinstance(rows, str), "PAYLOAD_INCONSISTENT", "balances arrive as a list (or {items: [...]})")
    available = pending = Decimal("0")
    counted = 0
    for raw in rows:  # type: ignore[union-attr]
        item = dict(detached(raw))
        code = str(item.get("currency") or item.get("currency_code") or "").upper()
        if code != currency.upper():
            continue
        available += _money(item.get("available_amount", item.get("available", item.get("balance", item.get("amount", "0")))), "available")
        pending += _money(item.get("pending_amount", item.get("pending", "0")), "pending")
        counted += 1
    _require(counted > 0, "NO_BALANCE_IN_CURRENCY", f"no balance row in {currency}")
    return CashPosition(source_tool=provenance.source_tool, provenance_digest=provenance.provenance_digest, observed_at=provenance.observed_through, currency=currency.upper(), available=str(available.quantize(MONEY_QUANTUM)), pending=str(pending.quantize(MONEY_QUANTUM)), accounts=counted)


class ScheduledFlow(StrictModel):
    kind: FlowKind
    ref: OpaqueRef
    due_at: str
    amount: Decimal
    source: ShortText

    @field_validator("amount", mode="before")
    @classmethod
    def _amount(cls, value: Any) -> Decimal:
        return _money(value, "amount")

    @field_validator("due_at")
    @classmethod
    def _due(cls, value: str) -> str:
        return timestamp(value, field_name="due_at")


def _page_records(payload: Mapping[str, Any], *, kind: str, currency: str, provenance: ObservationProvenance, default_terms_days: int) -> list[dict[str, Any]]:
    raw = dict(detached(payload))
    out: list[dict[str, Any]] = []
    if raw.get("schema") == "lightbulb.xero_close_source_page.v1":
        for record in raw.get("records") or []:
            item = dict(detached(record))
            if str(item.get("currency", "")).upper() != currency.upper():
                continue
            balance = _money(item.get("open_balance", "0"), "open_balance")
            if balance <= 0:
                continue
            due = item.get("due_date") or item.get("due_at")
            when = _date(due, "due_date") if due else timestamp(_add_days(_date(item.get("transaction_date"), "transaction_date"), default_terms_days), field_name="due_date")
            out.append({"kind": kind, "ref": f"{kind}:{item.get('source_ref')}", "due_at": when, "amount": str(balance.quantize(MONEY_QUANTUM)), "source": provenance.source_tool})
    else:
        query = raw.get("QueryResponse") if isinstance(raw.get("QueryResponse"), Mapping) else raw
        key = "Bill" if kind == "payable" else "Invoice"
        for record in query.get(key) or []:
            item = dict(detached(record))
            code = str(((item.get("CurrencyRef") or {}).get("value")) or currency).upper()
            if code != currency.upper():
                continue
            balance = _money(item.get("Balance", "0"), "Balance")
            if balance <= 0:
                continue
            due = item.get("DueDate") or item.get("TxnDate")
            _require(bool(due), "PAYLOAD_FIELD_INVALID", f"each {key} names DueDate or TxnDate")
            out.append({"kind": kind, "ref": f"{kind}:{item.get('Id')}", "due_at": _date(due, "DueDate"), "amount": str(balance.quantize(MONEY_QUANTUM)), "source": provenance.source_tool})
    return out


def _add_days(stamp: str, days: int) -> str:
    return (parsed(stamp) + timedelta(days=days)).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def payables(provenance: ObservationProvenance, payload: Mapping[str, Any], *, currency: str, default_terms_days: int = 30) -> list[ScheduledFlow]:
    _expect_tool(provenance, *BILL_TOOLS)
    _require(stable_digest(payload) == provenance.output_digest, "OBSERVATION_DIGEST_MISMATCH", "bills must match the original provider read")
    return [ScheduledFlow.model_validate(row) for row in _page_records(payload, kind="payable", currency=currency, provenance=provenance, default_terms_days=default_terms_days)]


def receivables(provenance: ObservationProvenance, payload: Mapping[str, Any], *, currency: str, default_terms_days: int = 30) -> list[ScheduledFlow]:
    _expect_tool(provenance, *INVOICE_TOOLS)
    _require(stable_digest(payload) == provenance.output_digest, "OBSERVATION_DIGEST_MISMATCH", "invoices must match the original provider read")
    return [ScheduledFlow.model_validate(row) for row in _page_records(payload, kind="receivable", currency=currency, provenance=provenance, default_terms_days=default_terms_days)]


class PayrollSchedule(StrictModel):
    """Explicit payroll: amount per run and the run dates inside the horizon."""

    amount_per_run: Decimal
    run_dates: tuple[str, ...] = Field(min_length=1, max_length=60)

    @field_validator("amount_per_run", mode="before")
    @classmethod
    def _amount(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="amount_per_run")

    @field_validator("run_dates", mode="before")
    @classmethod
    def _dates(cls, value: object) -> object:
        return tuple(timestamp(str(item) if "T" in str(item) else f"{item}T00:00:00Z", field_name="run_dates") for item in value) if isinstance(value, (list, tuple)) else value


class FixedCostSchedule(StrictModel):
    amount_per_week: Decimal

    @field_validator("amount_per_week", mode="before")
    @classmethod
    def _amount(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="amount_per_week")


# --------------------------------------------------------------------------- #
# Forecast
# --------------------------------------------------------------------------- #


class WeekBucket(StrictModel):
    week: int = Field(ge=1, le=104)
    starts_at: str
    inflows: Decimal
    outflows: Decimal
    closing_balance: Decimal
    below_floor: bool

    @field_validator("inflows", "outflows", "closing_balance", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _money(value, str(info.field_name))


class CashForecast(StrictModel):
    schema_id: str = Field(default=CASH_FORECAST_SCHEMA, alias="schema")
    currency: ShortText
    as_of: str
    horizon_weeks: int = Field(ge=1, le=104)
    opening_balance: Decimal
    floor: Decimal
    position_digest: Sha256Digest
    plan_digest: Sha256Digest | None = None
    flows: tuple[ScheduledFlow, ...] = Field(default_factory=tuple, max_length=5000)
    weeks: tuple[WeekBucket, ...] = Field(min_length=1, max_length=104)
    first_breach_week: int | None = None
    minimum_balance: Decimal
    runway_weeks: int | None = None
    total_inflows: Decimal
    total_outflows: Decimal
    forecast_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("opening_balance", "floor", "minimum_balance", "total_inflows", "total_outflows", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _money(value, str(info.field_name))

    @field_validator("flows", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> CashForecast:
        if not skip_digests(info) and self.forecast_digest != sealed_digest(CashForecast, self, "forecast_digest"):
            raise ValueError("forecast_digest must commit the exact forecast")
        return self


def forecast_cash(position: CashPosition, *, as_of: str, horizon_weeks: int, flows: Sequence[ScheduledFlow | Mapping[str, Any]] = (), operating_plan: CompanyOperatingPlan | Mapping[str, Any] | None = None, payroll: PayrollSchedule | Mapping[str, Any] | None = None, fixed_costs: FixedCostSchedule | Mapping[str, Any] | None = None, floor: Any = "0", period_starts: Sequence[str] = (), inference_cost_registers: Sequence[Mapping[str, Any] | Any] = ()) -> CashForecast:
    """Weekly cash buckets from the position plus every scheduled flow; the operating budget lands on each period start.

    A reconciled inference cost register schedules the prior period's ACTUAL provider bill as an ``inference_cost``
    outflow once on the first supplied period start and reduces that period's operating budget by the same amount, so agent spend
    is no longer modelled as a slice of the planned budget once the provider has said what it was.
    """

    stamp = timestamp(as_of, field_name="as_of")
    start = parsed(stamp)
    rows: list[ScheduledFlow] = [item if isinstance(item, ScheduledFlow) else ScheduledFlow.model_validate(dict(detached(item))) for item in flows]
    for row in rows:
        _require(row.source, "FLOW_SOURCE_MISSING", "every flow names its source")
    if payroll is not None:
        schedule = payroll if isinstance(payroll, PayrollSchedule) else PayrollSchedule.model_validate(dict(detached(payroll)))
        rows.extend(ScheduledFlow(kind="payroll", ref=f"payroll:{when}", due_at=when, amount=str(-schedule.amount_per_run), source="payroll_schedule") for when in schedule.run_dates)
    if fixed_costs is not None:
        fixed = fixed_costs if isinstance(fixed_costs, FixedCostSchedule) else FixedCostSchedule.model_validate(dict(detached(fixed_costs)))
        for week in range(horizon_weeks):
            when = (start + _WEEK * week).isoformat().replace("+00:00", "Z")
            rows.append(ScheduledFlow(kind="fixed_cost", ref=f"fixed:{week + 1}", due_at=when, amount=str(-fixed.amount_per_week), source="fixed_cost_schedule"))
    plan_digest = None
    _require(not inference_cost_registers or operating_plan is not None, "OPERATING_PLAN_REQUIRED", "inference costs require a matching operating plan")
    if operating_plan is not None:
        plan = CompanyOperatingPlan.model_validate(detached(operating_plan))
        plan_digest = plan.plan_digest
        budget = Decimal(str(plan.blueprint.operating_budget_per_period))
        starts = [timestamp(item, field_name="period_starts") for item in period_starts] or [stamp]
        starts = sorted(set(starts), key=parsed)
        actual_inference = Decimal("0")
        seen_statements: set[tuple[str, str, str]] = set()
        for record in inference_cost_registers:
            register = verify_register(record)
            _require(register.currency == position.currency == plan.blueprint.currency, "CURRENCY_MISMATCH", "inference costs, cash and the operating plan must use the same currency")
            _require(parsed(register.period_end) <= start, "INFERENCE_COST_FROM_FUTURE", "only completed statement periods may enter the forecast")
            source = register.source_statement
            observed_at = source.observation_provenance.completed_at if source.observation_provenance else source.operator_receipt.attested_at
            _require(parsed(observed_at) <= start, "INFERENCE_COST_FROM_FUTURE", "the original cost statement must exist at forecast time")
            _require(parsed(starts[0]) >= start, "INFERENCE_COST_BEFORE_FORECAST", "the payment date cannot precede the forecast")
            key = (register.provider, register.period_start, register.period_end)
            _require(key not in seen_statements, "AI_COST_STATEMENT_DUPLICATE", "one provider statement may be scheduled only once")
            seen_statements.add(key)
            actual_inference += Decimal(str(register.total))
            rows.append(ScheduledFlow(kind="inference_cost", ref=f"inference_cost:{register.provider}:{register.statement_digest}", due_at=starts[0], amount=str(-Decimal(str(register.total))), source="inference_cost_register"))
        residual_budget = max(budget - actual_inference, Decimal("0"))
        rows.extend(ScheduledFlow(kind="operating_budget", ref=f"period:{when}", due_at=when, amount=str(-(residual_budget if index == 0 else budget)), source="operating_plan") for index, when in enumerate(starts))
    for row in rows:
        if row.kind == "payable" and row.amount > 0:
            row = row.model_copy(update={"amount": -row.amount})  # payables are outflows regardless of sign supplied
    normalized: list[ScheduledFlow] = []
    for row in rows:
        amount = -row.amount.copy_abs() if row.kind in ("payable", "payroll", "fixed_cost", "operating_budget", "tax_reservation", "inference_cost") else row.amount.copy_abs()
        normalized.append(row.model_copy(update={"amount": amount}))
    floor_value = decimal_value(floor, field_name="floor", allow_negative=True)
    balance = position.available
    weeks: list[dict[str, Any]] = []
    first_breach = None
    minimum = balance
    total_in = total_out = Decimal("0")
    for week in range(1, horizon_weeks + 1):
        bucket_start = start + _WEEK * (week - 1)
        bucket_end = bucket_start + _WEEK
        inflow = sum((row.amount for row in normalized if row.amount > 0 and bucket_start <= parsed(row.due_at) < bucket_end), Decimal("0"))
        outflow = sum((-row.amount for row in normalized if row.amount < 0 and bucket_start <= parsed(row.due_at) < bucket_end), Decimal("0"))
        if week == 1:
            inflow += sum((row.amount for row in normalized if row.amount > 0 and parsed(row.due_at) < start), Decimal("0"))
            outflow += sum((-row.amount for row in normalized if row.amount < 0 and parsed(row.due_at) < start), Decimal("0"))
        balance = (balance + inflow - outflow).quantize(MONEY_QUANTUM)
        total_in += inflow
        total_out += outflow
        minimum = min(minimum, balance)
        below = balance < floor_value
        if below and first_breach is None:
            first_breach = week
        weeks.append({"week": week, "starts_at": bucket_start.isoformat().replace("+00:00", "Z"), "inflows": str(inflow.quantize(MONEY_QUANTUM)), "outflows": str(outflow.quantize(MONEY_QUANTUM)), "closing_balance": str(balance), "below_floor": below})
    runway = None if first_breach is None else first_breach - 1
    return seal(CashForecast, {"currency": position.currency, "as_of": stamp, "horizon_weeks": horizon_weeks, "opening_balance": str(position.available), "floor": str(floor_value), "position_digest": position.provenance_digest, "plan_digest": plan_digest, "flows": [row.to_dict() for row in normalized], "weeks": weeks, "first_breach_week": first_breach, "minimum_balance": str(minimum), "runway_weeks": runway, "total_inflows": str(total_in.quantize(MONEY_QUANTUM)), "total_outflows": str(total_out.quantize(MONEY_QUANTUM))}, "forecast_digest")


class CashCover(StrictModel):
    schema_id: str = Field(default=CASH_COVER_SCHEMA, alias="schema")
    forecast_digest: Sha256Digest
    amount: Decimal
    at: str
    week: int = Field(ge=1, le=104)
    balance_before: Decimal
    balance_after: Decimal
    floor: Decimal
    covered: bool
    shortfall: Decimal
    detail: BoundedText
    cover_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("amount", "balance_before", "balance_after", "floor", "shortfall", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _money(value, str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> CashCover:
        if self.covered != (self.shortfall == 0):
            raise ValueError("covered must mean no shortfall")
        if not skip_digests(info) and self.cover_digest != sealed_digest(CashCover, self, "cover_digest"):
            raise ValueError("cover_digest must commit the exact cover")
        return self


def assess_cash_cover(forecast: CashForecast | Mapping[str, Any], *, amount: Any, at: str) -> CashCover:
    """Can an additional outflow of ``amount`` at ``at`` be paid without any later week breaching the floor?"""

    parsed_forecast = forecast if isinstance(forecast, CashForecast) else CashForecast.model_validate(dict(detached(forecast)))
    stamp = timestamp(at, field_name="at")
    when = parsed(stamp)
    start = parsed(parsed_forecast.as_of)
    _require(when >= start, "COVER_BEFORE_FORECAST", "the outflow precedes the forecast start")
    week = min(parsed_forecast.horizon_weeks, max(1, int((when - start) / _WEEK) + 1))
    outflow = decimal_value(amount, field_name="amount")
    before = parsed_forecast.weeks[week - 1].closing_balance
    worst_after = min(bucket.closing_balance for bucket in parsed_forecast.weeks[week - 1:]) - outflow
    shortfall = max(Decimal("0"), parsed_forecast.floor - worst_after).quantize(MONEY_QUANTUM)
    covered = shortfall == 0
    detail = f"{outflow} {parsed_forecast.currency} in week {week}: worst subsequent balance {worst_after.quantize(MONEY_QUANTUM)} against floor {parsed_forecast.floor}" + ("" if covered else f"; short by {shortfall}")
    return seal(CashCover, {"forecast_digest": parsed_forecast.forecast_digest, "amount": str(outflow), "at": stamp, "week": week, "balance_before": str(before), "balance_after": str((before - outflow).quantize(MONEY_QUANTUM)), "floor": str(parsed_forecast.floor), "covered": covered, "shortfall": str(shortfall), "detail": detail}, "cover_digest")


def render_forecast(forecast: CashForecast | Mapping[str, Any], *, weeks: int = 13) -> str:
    parsed_forecast = forecast if isinstance(forecast, CashForecast) else CashForecast.model_validate(dict(detached(forecast)))
    lines = [f"**Cash {parsed_forecast.currency}** from {parsed_forecast.as_of[:10]}: opening {parsed_forecast.opening_balance}, floor {parsed_forecast.floor}, " + (f"breaches the floor in week {parsed_forecast.first_breach_week} (runway {parsed_forecast.runway_weeks} week(s))" if parsed_forecast.first_breach_week else f"no breach in {parsed_forecast.horizon_weeks} week(s)")]
    for bucket in parsed_forecast.weeks[:weeks]:
        lines.append(f"- week {bucket.week} ({bucket.starts_at[:10]}): +{bucket.inflows} / -{bucket.outflows} = {bucket.closing_balance}{' (below floor)' if bucket.below_floor else ''}")
    return "\n".join(lines)


TREASURY_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "company_treasury",
    "golden_loop": "company.blueprint_to_governed_operating_cadence@0.1.0",
    "stages": ["read_position", "read_payables_and_receivables", "schedule_payroll_and_fixed_costs", "reserve_tax_obligations", "lay_operating_budget", "forecast_weeks", "assess_cover"],
    "tools": {"balances": list(BALANCE_TOOLS), "bills": list(BILL_TOOLS), "invoices": list(INVOICE_TOOLS)},
    "required_connectors": ["airwallex", "xero", "quickbooks"],
    "hard_rules": [
        "the opening balance comes from a balance read with provenance; other currencies are ignored, never converted",
        "payables and receivables come from the provider's own pages; payroll and fixed costs are explicit schedules",
        "the operating budget is laid on each period start so the forecast shows the cost of running the plan",
        "cash cover is judged on the worst subsequent week against the floor, not on the balance today",
        "nothing here moves money",
    ],
}

__all__ = ["BALANCE_TOOLS", "BILL_TOOLS", "CASH_COVER_SCHEMA", "CASH_FORECAST_SCHEMA", "INVOICE_TOOLS", "TREASURY_MANIFEST", "CashCover", "CashForecast", "CashPosition", "FixedCostSchedule", "PayrollSchedule", "ScheduledFlow", "WeekBucket", "assess_cash_cover", "cash_position", "forecast_cash", "payables", "receivables", "render_forecast"]
