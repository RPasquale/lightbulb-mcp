"""Stockouts: the days each stock position sat empty inside the window, the sales that walked, what they were worth, and the reorder point that would have held, from the replayed inventory chain.

The portfolio says a SKU is overstocked or run down; the open-to-buy
sizes the next order; neither says what an empty shelf cost.
``build_stockouts`` replays every stock position's transition history
into an on-hand timeline and seals:

* per position: the days inside the window with nothing on hand, the
  number of stockout spells, the units the chain recorded as oversold
  (sold with nothing held), the velocity while stocked (units sold per
  stocked day), the units lost while empty at that velocity plus the
  oversold units, and the contribution lost at the margin report's
  contribution per unit (revenue lost at the realised price when a
  report is supplied, else counted in units only);
* the reorder point the policy would have needed: the velocity over the
  policy's lead time plus its safety stock, against the reorder point it
  carries, and the spells a higher point would have prevented;
* totals and recommendations naming the positions that lost the most.

Velocity is measured only while the position held stock, so an empty
shelf never argues for its own demand; a position that never held stock
in the window is unmeasured.  Nothing here reads a provider or persists
anything.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
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

STOCKOUT_PLAN_SCHEMA = "lightbulb.stockout_plan.v1"
STOCKOUTS_SCHEMA = "lightbulb.stockouts.v1"
_QTY = Decimal("0.01")
_HUNDRED = Decimal("100")


class StockoutError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise StockoutError(code, message)


def _money(value: Any) -> Decimal:
    result = Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)
    return Decimal("0.00") if result == 0 else result


def _qty(value: Any) -> Decimal:
    result = Decimal(str(value)).quantize(_QTY, rounding=ROUND_HALF_UP)
    return Decimal("0.00") if result == 0 else result


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


class StockoutPlan(StrictModel):
    schema_id: str = Field(default=STOCKOUT_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    service_level_days: int = Field(default=0, ge=0, le=90)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "StockoutPlan":
        if not skip_digests(info) and self.plan_digest != sealed_digest(StockoutPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self


def compile_stockout_plan(company_ref: str, *, currency: str, overrides: Mapping[str, Any] | None = None) -> StockoutPlan:
    return seal(StockoutPlan, {"company_ref": company_ref, "currency": str(currency).upper(), **dict(overrides or {})}, "plan_digest")


class StockoutSpell(StrictModel):
    empty_from: str
    empty_until: str
    days: Decimal
    ended_by: ShortText

    @field_validator("days", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class StockoutRow(StrictModel):
    position_ref: OpaqueRef
    sku_ref: OpaqueRef
    location_ref: OpaqueRef | None = None
    window_days: int = Field(ge=1)
    stocked_days: Decimal
    empty_days: Decimal
    spells: tuple[StockoutSpell, ...] = Field(default_factory=tuple, max_length=200)
    units_sold: Decimal
    oversold_units: Decimal
    velocity_per_day: Decimal | None = None
    lost_units: Decimal | None = None
    unit_contribution: Decimal | None = None
    realised_price: Decimal | None = None
    lost_revenue: Decimal | None = None
    lost_contribution: Decimal | None = None
    reorder_point: Decimal
    lead_time_days: int = Field(ge=0)
    safety_stock: Decimal
    reorder_point_needed: Decimal | None = None
    measured: bool
    verdict: ShortText

    @field_validator("spells", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("stocked_days", "empty_days", "units_sold", "oversold_units", "velocity_per_day", "lost_units", "unit_contribution", "realised_price", "lost_revenue", "lost_contribution", "reorder_point", "safety_stock", "reorder_point_needed", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class Stockouts(StrictModel):
    schema_id: str = Field(default=STOCKOUTS_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    window_start: str
    window_end: str
    as_of: str
    plan_digest: Sha256Digest
    margin_report_digest: Sha256Digest | None = None
    rows: tuple[StockoutRow, ...] = Field(default_factory=tuple, max_length=5000)
    positions: int = Field(ge=0)
    positions_with_stockouts: int = Field(ge=0)
    empty_days: Decimal
    lost_units: Decimal
    lost_revenue: Decimal | None = None
    lost_contribution: Decimal | None = None
    recommendations: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=24)
    source_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=6000)
    stockouts_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("rows", "recommendations", "source_digests", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("empty_days", "lost_units", "lost_revenue", "lost_contribution", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "Stockouts":
        if self.positions != len(self.rows) or self.positions_with_stockouts != sum(1 for row in self.rows if row.spells):
            raise ValueError("positions counts every row and positions_with_stockouts the rows with a spell")
        if not skip_digests(info) and self.stockouts_digest != sealed_digest(Stockouts, self, "stockouts_digest"):
            raise ValueError("stockouts_digest must commit the exact document")
        return self

    def row(self, position_ref: str) -> StockoutRow | None:
        return next((row for row in self.rows if row.position_ref == position_ref), None)

    def render(self) -> str:
        lost = f"{self.lost_units} unit(s)" + (f" worth {self.lost_contribution} {self.currency} of contribution" if self.lost_contribution is not None else "")
        lines = [f"**Stockouts {self.company_ref}** {self.window_start[:10]} to {self.window_end[:10]}: {self.positions_with_stockouts} of {self.positions} position(s) ran empty for {self.empty_days} day(s); {lost} lost."]
        lines.extend(f"- {row.position_ref}: {row.verdict}" for row in self.rows)
        return "\n".join(lines)


def _timeline(state: Any) -> list[tuple[str, str, Decimal]]:
    """(occurred_at, event, on_hand after the event) replayed from the receipts, oldest first."""

    on_hand = Decimal("0")
    points: list[tuple[str, str, Decimal]] = []
    for item in state.transition_history:
        command = detached(item.command) if not isinstance(item, Mapping) else dict(item["command"])
        event = str(command.get("event"))
        receipt = dict(command.get("receipt") or {})
        at = str(command.get("occurred_at"))
        if event in ("count", "recount") and receipt.get("on_hand") is not None:
            on_hand = Decimal(str(receipt["on_hand"]))
        elif event == "receive" and receipt.get("received_quantity") is not None:
            on_hand += Decimal(str(receipt["received_quantity"]))
        elif event == "recognise_cogs" and receipt.get("units_sold") is not None:
            on_hand = max(on_hand - Decimal(str(receipt["units_sold"])), Decimal("0"))
        elif event == "write_down" and receipt.get("write_down_units") is not None:
            on_hand = max(on_hand - Decimal(str(receipt["write_down_units"])), Decimal("0"))
        elif event == "restock" and receipt.get("restock_units") is not None:
            on_hand += Decimal(str(receipt["restock_units"]))
        elif event == "issue" and receipt.get("issue_units") is not None:
            on_hand = max(on_hand - Decimal(str(receipt["issue_units"])), Decimal("0"))
        else:
            continue
        points.append((at, event, on_hand))
    return points


def build_stockouts(plan: StockoutPlan | Mapping[str, Any], *, inventory_states: Sequence[tuple[Any, Any]], margin_report: Mapping[str, Any] | Any | None = None, window_start: str, window_end: str, as_of: str) -> Stockouts:
    """The sealed stockout ledger over the window from the replayed stock positions, priced at the margin report's contribution per unit when a report is supplied."""

    from lightbulb.inventory_chain import INVENTORY_LIFECYCLE

    parsed_plan = plan if isinstance(plan, StockoutPlan) else StockoutPlan.model_validate(detached(plan))
    start, end = timestamp(window_start, field_name="window_start"), timestamp(window_end, field_name="window_end")
    _require(parsed(end) > parsed(start), "WINDOW_EMPTY", "window_end must follow window_start")
    at = timestamp(as_of, field_name="as_of")
    window_days = (parsed(end) - parsed(start)).days
    _require(window_days > 0, "WINDOW_EMPTY", "the window spans at least one day")
    digests: list[str] = []
    per_unit: dict[str, tuple[Decimal | None, Decimal | None]] = {}
    report_digest = None
    if margin_report is not None:
        from lightbulb.product_margin import verify_product_margin

        report = verify_product_margin(margin_report)
        _require(report.company_ref == parsed_plan.company_ref and report.currency == parsed_plan.currency, "SOURCE_SCOPE_MISMATCH", "the margin report names another company or currency")
        _require(report.window_start == start and report.window_end == end, "REPORT_WINDOW_MISMATCH", "the margin report must cover exactly this window")
        for item in report.rows:
            units = Decimal(str(item.units_sold))
            price = None if not item.priced or units <= 0 else _money(Decimal(str(item.net_revenue)) / units)
            contribution = None if item.contribution_per_unit is None else Decimal(str(item.contribution_per_unit))
            per_unit[item.sku_ref] = (price, contribution)
        report_digest = report.report_digest
        digests.append(report_digest)
    rows: list[dict[str, Any]] = []
    seconds_per_day = Decimal(86400)
    for plan_doc, state_doc in inventory_states:
        chain_plan, state = INVENTORY_LIFECYCLE.bind(plan_doc, state_doc)
        _require(chain_plan.company_ref == parsed_plan.company_ref and chain_plan.currency == parsed_plan.currency, "SOURCE_SCOPE_MISMATCH", f"stock position {state.scope.entity_ref} belongs to another company or currency")
        digests.append(state.state_digest)
        sku_ref = str(state.ledger.sku_ref)
        policy = next((item for item in chain_plan.policies if item.sku_ref == sku_ref and item.location_ref == state.ledger.location_ref), None)
        reorder_point = Decimal(str(policy.reorder_point)) if policy is not None else Decimal(str(state.ledger.reorder_point))
        lead_days = int(policy.lead_time_days) if policy is not None else 0
        safety = Decimal(str(policy.safety_stock)) if policy is not None else Decimal("0")
        points = _timeline(state)
        # the level at the window start is the last point before it; before the first count the position is unknown, not empty
        level: Decimal | None = None
        first_known: str | None = None
        for stamp, _event, on_hand in points:
            if parsed(stamp) <= parsed(start):
                level = on_hand
                first_known = start
        segments: list[tuple[str, str, Decimal | None]] = []
        cursor = start
        for stamp, event, on_hand in points:
            if parsed(stamp) <= parsed(start):
                continue
            if parsed(stamp) >= parsed(end):
                break
            segments.append((cursor, stamp, level))
            cursor, level = stamp, on_hand
            if first_known is None:
                first_known = stamp
        segments.append((cursor, end, level))
        stocked = Decimal("0")
        empty = Decimal("0")
        spells: list[dict[str, Any]] = []
        for seg_start, seg_end, seg_level in segments:
            days = Decimal((parsed(seg_end) - parsed(seg_start)).total_seconds()) / seconds_per_day
            if seg_level is None or days <= 0:
                continue
            if seg_level > 0:
                stocked += days
            else:
                empty += days
                ended = next((event for stamp, event, _level in points if stamp == seg_end), "window_end")
                if spells and spells[-1]["empty_until"] == seg_start:
                    spells[-1]["empty_until"] = seg_end
                    spells[-1]["days"] = str(_qty(Decimal(spells[-1]["days"]) + days))
                    spells[-1]["ended_by"] = ended
                else:
                    spells.append({"empty_from": seg_start, "empty_until": seg_end, "days": str(_qty(days)), "ended_by": ended})
        sold = Decimal("0")
        cogs_in_window = False
        for item in state.transition_history:
            command = detached(item.command) if not isinstance(item, Mapping) else dict(item["command"])
            if str(command.get("event")) != "recognise_cogs":
                continue
            stamp = str(command.get("occurred_at"))
            if not (parsed(start) <= parsed(stamp) < parsed(end)):
                continue
            cogs_in_window = True
            sold += Decimal(str(dict(command.get("receipt") or {}).get("units_sold") or "0"))
        oversold = Decimal(str(state.ledger.oversold_units or "0")) if cogs_in_window else Decimal("0")
        measured = stocked > 0
        velocity = None if not measured else _qty(sold / stocked)
        lost_units = None if velocity is None else _qty(velocity * empty + oversold)
        price, contribution = per_unit.get(sku_ref, (None, None))
        lost_revenue = None if lost_units is None or price is None else _money(lost_units * price)
        lost_contribution = None if lost_units is None or contribution is None else _money(max(lost_units * contribution, Decimal("0")))
        earns_nothing = contribution is not None and contribution <= 0
        needed = None if velocity is None else _qty(velocity * (lead_days + parsed_plan.service_level_days) + safety)
        if not measured:
            verdict = f"held no stock inside the window ({_qty(empty)} day(s) empty); demand cannot be measured"
        elif not spells:
            verdict = f"in stock all {_qty(stocked)} day(s); {velocity} a day sold, reorder point {_qty(reorder_point)} against {needed} needed for {lead_days} day(s) of lead time"
        else:
            verdict = f"empty {_qty(empty)} of {window_days} day(s) across {len(spells)} spell(s); {velocity} a day while stocked, {lost_units} unit(s) lost" + (f" ({oversold} oversold)" if oversold > 0 else "") + ((f" worth {lost_contribution} of contribution" if not earns_nothing else f" but no contribution (the SKU earns {_money(contribution)} a unit)") if lost_contribution is not None else "") + f"; reorder point {_qty(reorder_point)} against {needed} needed for {lead_days} day(s) of lead time"
        rows.append({"position_ref": state.scope.entity_ref, "sku_ref": sku_ref, "location_ref": state.ledger.location_ref, "window_days": window_days, "stocked_days": str(_qty(stocked)), "empty_days": str(_qty(empty)), "spells": spells, "units_sold": str(_qty(sold)), "oversold_units": str(_qty(oversold)), "velocity_per_day": None if velocity is None else str(velocity), "lost_units": None if lost_units is None else str(lost_units), "unit_contribution": None if contribution is None else str(_money(contribution)), "realised_price": None if price is None else str(price), "lost_revenue": None if lost_revenue is None else str(lost_revenue), "lost_contribution": None if lost_contribution is None else str(lost_contribution), "reorder_point": str(_qty(reorder_point)), "lead_time_days": lead_days, "safety_stock": str(_qty(safety)), "reorder_point_needed": None if needed is None else str(needed), "measured": measured, "verdict": verdict[:300]})
    rows.sort(key=lambda row: (-Decimal(row["lost_contribution"] or row["lost_units"] or "0"), -Decimal(row["empty_days"]), row["position_ref"]))
    total_empty = _qty(sum((Decimal(row["empty_days"]) for row in rows), Decimal("0")))
    total_lost = _qty(sum((Decimal(row["lost_units"]) for row in rows if row["lost_units"] is not None), Decimal("0")))
    priced = [row for row in rows if row["lost_revenue"] is not None]
    costed = [row for row in rows if row["lost_contribution"] is not None]
    total_revenue = None if margin_report is None else _money(sum((Decimal(row["lost_revenue"]) for row in priced), Decimal("0")))
    total_contribution = None if margin_report is None else _money(sum((Decimal(row["lost_contribution"]) for row in costed), Decimal("0")))
    recommendations: list[str] = []
    for row in rows:
        if row["spells"] and row["reorder_point_needed"] is not None and Decimal(row["reorder_point_needed"]) > Decimal(row["reorder_point"]):
            recommendations.append(f"{row['position_ref']}: raise the reorder point from {row['reorder_point']} to {row['reorder_point_needed']} ({row['velocity_per_day']} a day over {row['lead_time_days']} day(s) of lead time plus {row['safety_stock']} safety); {row['lost_units']} unit(s) lost" + (f" worth {row['lost_contribution']}" if row["lost_contribution"] is not None else ""))
        elif row["spells"]:
            recommendations.append(f"{row['position_ref']}: {row['empty_days']} day(s) empty with the reorder point {row['reorder_point']} already at or above the {row['reorder_point_needed']} needed; the order was late, not small")
    if not recommendations:
        recommendations.append("no position ran empty inside the window" if rows else "no stock position replayed")
    payload = {"company_ref": parsed_plan.company_ref, "currency": parsed_plan.currency, "window_start": start, "window_end": end, "as_of": at, "plan_digest": parsed_plan.plan_digest, "margin_report_digest": report_digest, "rows": rows, "positions": len(rows), "positions_with_stockouts": sum(1 for row in rows if row["spells"]), "empty_days": str(total_empty), "lost_units": str(total_lost), "lost_revenue": None if total_revenue is None else str(total_revenue), "lost_contribution": None if total_contribution is None else str(total_contribution), "recommendations": [row[:300] for row in recommendations[:24]], "source_digests": digests}
    return seal(Stockouts, payload, "stockouts_digest")


def verify_stockouts(value: Any) -> Stockouts:
    return value if isinstance(value, Stockouts) else Stockouts.model_validate(dict(detached(value)))


STOCKOUTS_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "stockouts",
    "golden_loop": "commerce.product_truth_to_measured_income@0.1.0",
    "stages": ["replay_on_hand_timeline", "empty_spells_inside_the_window", "velocity_while_stocked", "lost_units_and_contribution", "reorder_point_needed", "seal_document"],
    "required_connectors": ["lightbulb.sdk_engine_state"],
    "hard_rules": [
        "velocity is measured only while the position held stock, so an empty shelf never argues for its own demand",
        "lost units are the velocity over the empty days plus the units the chain recorded as oversold; priced only at a sealed margin report's contribution per unit",
        "nothing here reads a provider or persists anything",
    ],
}

__all__ = ["STOCKOUTS_MANIFEST", "STOCKOUTS_SCHEMA", "STOCKOUT_PLAN_SCHEMA", "StockoutError", "StockoutPlan", "StockoutRow", "StockoutSpell", "Stockouts", "build_stockouts", "compile_stockout_plan", "verify_stockouts"]
