"""Supplier scorecard: how every goods supplier actually performed, from the purchases, receipts, and landed costs the inventory chain recorded.

Procurement of goods is the twin of procurement of labour.  The
inventory chain already holds the truth per stock position: the reorder
it proposed and when the goods were expected, the purchase it committed
at what price, what arrived and when, the freight and duty that landed
on top, and the shrinkage and write-downs afterwards.
``build_supplier_scorecard`` reads that history per supplier and seals:

* purchases in the window, units committed and received, the fill rate,
  and the open orders still inbound;
* on-time receipts against the expected date, the days late or early,
  and the actual lead time against the policy's;
* the price paid against the policy's standard unit cost, and the landed
  premium (freight plus duty over the committed amount);
* shrinkage and write-downs on the SKUs the supplier feeds, and the
  supplier's share of the positions (single-source exposure);
* a grade (reliable, watch, replace) against the plan's targets and one
  recommendation per supplier that names the number.

Everything is arithmetic on replayed states; nothing here reads a
provider, rates anyone by opinion, or persists anything.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import ROUND_HALF_UP, Decimal
from typing import Any, Literal

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

SUPPLIER_SCORECARD_PLAN_SCHEMA = "lightbulb.supplier_scorecard_plan.v1"
SUPPLIER_SCORECARD_SCHEMA = "lightbulb.supplier_scorecard.v1"
SUPPLIER_GRADES: tuple[str, ...] = ("reliable", "watch", "replace", "unproven")
SupplierGrade = Literal["reliable", "watch", "replace", "unproven"]
_HUNDRED = Decimal("100")
_PCT = Decimal("0.01")


class SupplierScorecardError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise SupplierScorecardError(code, message)


def _money(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


def _pct(numerator: Decimal, denominator: Decimal) -> Decimal | None:
    return None if denominator <= 0 else (numerator / denominator * _HUNDRED).quantize(_PCT, rounding=ROUND_HALF_UP)


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


class SupplierScorecardPlan(StrictModel):
    schema_id: str = Field(default=SUPPLIER_SCORECARD_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    on_time_target_percent: Decimal = Field(default=Decimal("90"), validate_default=True)
    fill_rate_target_percent: Decimal = Field(default=Decimal("95"), validate_default=True)
    landed_premium_threshold_percent: Decimal = Field(default=Decimal("10"), validate_default=True)
    price_variance_threshold_percent: Decimal = Field(default=Decimal("5"), validate_default=True)
    single_source_share_percent: Decimal = Field(default=Decimal("50"), validate_default=True)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("on_time_target_percent", "fill_rate_target_percent", "landed_premium_threshold_percent", "price_variance_threshold_percent", "single_source_share_percent", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        result = decimal_value(value, field_name=str(info.field_name))
        if result > _HUNDRED:
            raise ValueError(f"{info.field_name} is at most 100")
        return result

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "SupplierScorecardPlan":
        if not skip_digests(info) and self.plan_digest != sealed_digest(SupplierScorecardPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self


def compile_supplier_scorecard_plan(company_ref: str, *, currency: str, overrides: Mapping[str, Any] | None = None) -> SupplierScorecardPlan:
    return seal(SupplierScorecardPlan, {"company_ref": company_ref, "currency": str(currency).upper(), **dict(overrides or {})}, "plan_digest")


class PurchaseRecord(StrictModel):
    po_ref: OpaqueRef
    sku_ref: OpaqueRef
    committed_at: str
    expected_at: str | None = None
    quantity: Decimal
    unit_price: Decimal
    standard_unit_cost: Decimal
    received_quantity: Decimal
    received_at: str | None = None
    days_late: int | None = None
    lead_days: int | None = None
    policy_lead_days: int
    freight: Decimal
    duty: Decimal

    @field_validator("quantity", "unit_price", "standard_unit_cost", "received_quantity", "freight", "duty", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))


class SupplierRow(StrictModel):
    supplier_ref: OpaqueRef
    positions: int = Field(ge=0)
    share_of_positions_percent: Decimal
    purchases: int = Field(ge=0)
    open_purchases: int = Field(ge=0)
    committed_units: Decimal
    received_units: Decimal
    fill_rate_percent: Decimal | None = None
    receipts: int = Field(ge=0)
    on_time_receipts: int = Field(ge=0)
    on_time_percent: Decimal | None = None
    average_days_late: Decimal | None = None
    average_lead_days: Decimal | None = None
    policy_lead_days: Decimal | None = None
    committed_amount: Decimal
    price_variance_percent: Decimal | None = None
    landed_premium: Decimal
    landed_premium_percent: Decimal | None = None
    shrinkage_value: Decimal
    write_down_total: Decimal
    grade: SupplierGrade
    rationale: ShortText
    purchases_detail: tuple[PurchaseRecord, ...] = Field(default_factory=tuple, max_length=500)

    @field_validator("purchases_detail", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("share_of_positions_percent", "committed_units", "received_units", "fill_rate_percent", "on_time_percent", "average_days_late", "average_lead_days", "policy_lead_days", "committed_amount", "price_variance_percent", "landed_premium", "landed_premium_percent", "shrinkage_value", "write_down_total", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class SupplierScorecard(StrictModel):
    schema_id: str = Field(default=SUPPLIER_SCORECARD_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    window_start: str
    window_end: str
    as_of: str
    plan_digest: Sha256Digest
    suppliers: tuple[SupplierRow, ...] = Field(default_factory=tuple, max_length=2000)
    positions: int = Field(ge=0)
    purchases: int = Field(ge=0)
    committed_amount: Decimal
    landed_premium: Decimal
    by_grade: dict[str, int] = Field(default_factory=dict)
    recommendations: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=24)
    source_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=6000)
    scorecard_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("suppliers", "recommendations", "source_digests", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("committed_amount", "landed_premium", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "SupplierScorecard":
        if sum(self.by_grade.values()) != len(self.suppliers):
            raise ValueError("every supplier is counted once by grade")
        if not skip_digests(info) and self.scorecard_digest != sealed_digest(SupplierScorecard, self, "scorecard_digest"):
            raise ValueError("scorecard_digest must commit the exact scorecard")
        return self

    def supplier(self, supplier_ref: str) -> SupplierRow | None:
        return next((row for row in self.suppliers if row.supplier_ref == supplier_ref), None)

    def render(self) -> str:
        lines = [f"**Supplier scorecard {self.company_ref}** {self.window_start[:10]} to {self.window_end[:10]}: {len(self.suppliers)} supplier(s) over {self.positions} position(s), {self.purchases} purchase(s) for {self.committed_amount} {self.currency}, landed premium {self.landed_premium}; " + ", ".join(f"{count} {grade}" for grade, count in self.by_grade.items() if count) + "."]
        for row in self.suppliers:
            lines.append(f"- {row.supplier_ref} [{row.grade}]: {row.rationale}")
        return "\n".join(lines)


def _purchases(state: Any, policy: Any) -> list[dict[str, Any]]:
    """Every purchase the position committed, paired with its proposal, receipts, and landed costs from the replayed history."""

    orders: list[dict[str, Any]] = []
    expected: str | None = None
    for item in state.transition_history:
        command = detached(item.command) if not isinstance(item, Mapping) else dict(item["command"])
        event = str(command.get("event"))
        receipt = dict(command.get("receipt") or {})
        at = str(command.get("occurred_at"))
        if event == "propose_reorder":
            expected = receipt.get("expected_receipt_at")
        elif event == "commit_purchase":
            orders.append({"po_ref": str(receipt["po_ref"]), "sku_ref": str(state.ledger.sku_ref), "committed_at": at, "expected_at": expected, "quantity": Decimal(str(receipt["quantity"])), "unit_price": Decimal(str(receipt["unit_price"])), "standard_unit_cost": Decimal(str(policy.standard_unit_cost)), "received_quantity": Decimal("0"), "received_at": None, "days_late": None, "lead_days": None, "policy_lead_days": int(policy.lead_time_days), "freight": Decimal("0"), "duty": Decimal("0")})
            expected = None
        elif event == "receive" and orders:
            order = next((row for row in reversed(orders) if row["po_ref"] == str(receipt.get("po_ref"))), orders[-1])
            order["received_quantity"] += Decimal(str(receipt["received_quantity"]))
            order["received_at"] = str(receipt["received_at"])
            if order["expected_at"]:
                order["days_late"] = (parsed(order["received_at"]) - parsed(str(order["expected_at"]))).days
            order["lead_days"] = (parsed(order["received_at"]) - parsed(order["committed_at"])).days
        elif event == "record_landed_cost" and orders:
            orders[-1]["freight"] += Decimal(str(receipt.get("freight_amount") or "0"))
            orders[-1]["duty"] += Decimal(str(receipt.get("duty_amount") or "0"))
    return orders


def build_supplier_scorecard(plan: SupplierScorecardPlan | Mapping[str, Any], *, inventory_states: Sequence[tuple[Any, Any]], window_start: str, window_end: str, as_of: str) -> SupplierScorecard:
    """The sealed scorecard: every supplier the replayed stock positions bought from, graded on the purchases committed inside the window."""

    from lightbulb.inventory_chain import INVENTORY_LIFECYCLE

    parsed_plan = plan if isinstance(plan, SupplierScorecardPlan) else SupplierScorecardPlan.model_validate(detached(plan))
    start, end = timestamp(window_start, field_name="window_start"), timestamp(window_end, field_name="window_end")
    _require(parsed(end) > parsed(start), "WINDOW_EMPTY", "window_end must follow window_start")
    at = timestamp(as_of, field_name="as_of")
    suppliers: dict[str, dict[str, Any]] = {}
    digests: list[str] = []
    positions = 0
    for plan_doc, state_doc in inventory_states:
        iplan, state = INVENTORY_LIFECYCLE.bind(plan_doc, state_doc)
        _require(iplan.company_ref == parsed_plan.company_ref and iplan.currency == parsed_plan.currency, "SOURCE_SCOPE_MISMATCH", f"stock position {state.scope.entity_ref} belongs to another company or currency")
        digests.append(state.state_digest)
        ledger = state.ledger
        if not ledger.sku_ref or not ledger.supplier_ref:
            continue
        positions += 1
        policy = iplan.policy(str(ledger.sku_ref), str(ledger.location_ref))
        row = suppliers.setdefault(str(ledger.supplier_ref), {"positions": 0, "orders": [], "shrinkage": Decimal("0"), "write_down": Decimal("0"), "policy_lead": []})
        row["positions"] += 1
        row["shrinkage"] += Decimal(str(ledger.shrinkage_value))
        row["write_down"] += Decimal(str(ledger.write_down_total))
        if policy is not None:
            row["policy_lead"].append(int(policy.lead_time_days))
            row["orders"].extend(order for order in _purchases(state, policy) if parsed(start) <= parsed(order["committed_at"]) < parsed(end))
    rows: list[dict[str, Any]] = []
    counts: dict[str, int] = {}
    for supplier_ref, row in sorted(suppliers.items()):
        orders = row["orders"]
        received = [order for order in orders if order["received_at"] is not None]
        committed_units = sum((order["quantity"] for order in orders), Decimal("0"))
        received_units = sum((order["received_quantity"] for order in orders), Decimal("0"))
        fill = _pct(received_units, sum((order["quantity"] for order in received), Decimal("0")))
        timed = [order for order in received if order["days_late"] is not None]
        on_time = sum(1 for order in timed if order["days_late"] <= 0)
        on_time_pct = _pct(Decimal(on_time), Decimal(len(timed)))
        avg_late = None if not timed else (sum((Decimal(order["days_late"]) for order in timed), Decimal("0")) / len(timed)).quantize(_PCT, rounding=ROUND_HALF_UP)
        leads = [order for order in received if order["lead_days"] is not None]
        avg_lead = None if not leads else (sum((Decimal(order["lead_days"]) for order in leads), Decimal("0")) / len(leads)).quantize(_PCT, rounding=ROUND_HALF_UP)
        policy_lead = None if not row["policy_lead"] else (sum((Decimal(days) for days in row["policy_lead"]), Decimal("0")) / len(row["policy_lead"])).quantize(_PCT, rounding=ROUND_HALF_UP)
        committed_amount = _money(sum((order["quantity"] * order["unit_price"] for order in orders), Decimal("0")))
        standard_amount = sum((order["quantity"] * order["standard_unit_cost"] for order in orders), Decimal("0"))
        price_variance = _pct(committed_amount - standard_amount, standard_amount)
        premium = _money(sum((order["freight"] + order["duty"] for order in orders), Decimal("0")))
        premium_pct = _pct(premium, committed_amount)
        share = _pct(Decimal(row["positions"]), Decimal(positions)) or Decimal("0")
        problems: list[str] = []
        if on_time_pct is not None and on_time_pct < parsed_plan.on_time_target_percent:
            problems.append(f"on time {on_time_pct}% against a {parsed_plan.on_time_target_percent}% target (average {avg_late} day(s) late)")
        if fill is not None and fill < parsed_plan.fill_rate_target_percent:
            problems.append(f"fill rate {fill}% against a {parsed_plan.fill_rate_target_percent}% target")
        if premium_pct is not None and premium_pct > parsed_plan.landed_premium_threshold_percent:
            problems.append(f"freight and duty add {premium_pct}% ({premium}) over the {parsed_plan.landed_premium_threshold_percent}% threshold")
        if price_variance is not None and price_variance > parsed_plan.price_variance_threshold_percent:
            problems.append(f"paid {price_variance}% over the standard cost")
        if not orders:
            grade = "unproven"
            rationale = f"no purchases committed in the window across {row['positions']} position(s)"
        elif len(problems) >= 2 or (on_time_pct is not None and fill is not None and on_time_pct < parsed_plan.on_time_target_percent and fill < parsed_plan.fill_rate_target_percent):
            grade = "replace"
            rationale = "; ".join(problems) + "; second-source the SKUs"
        elif problems:
            grade = "watch"
            rationale = problems[0]
        else:
            grade = "reliable"
            rationale = f"{len(orders)} purchase(s), {on_time}/{len(timed)} on time" + (f" ({avg_late} day(s) against the expected date)" if avg_late is not None else "") + (f", fill {fill}%" if fill is not None else "") + (f", lead {avg_lead} day(s) against a {policy_lead}-day policy" if avg_lead is not None and policy_lead is not None else "") + (f", landed premium {premium_pct}%" if premium_pct is not None else "")
        if share > parsed_plan.single_source_share_percent:
            rationale += f"; single-source exposure: {share}% of positions"
        counts[grade] = counts.get(grade, 0) + 1
        rows.append({"supplier_ref": supplier_ref, "positions": row["positions"], "share_of_positions_percent": str(share), "purchases": len(orders), "open_purchases": len(orders) - len(received), "committed_units": str(committed_units), "received_units": str(received_units), "fill_rate_percent": None if fill is None else str(fill), "receipts": len(received), "on_time_receipts": on_time, "on_time_percent": None if on_time_pct is None else str(on_time_pct), "average_days_late": None if avg_late is None else str(avg_late), "average_lead_days": None if avg_lead is None else str(avg_lead), "policy_lead_days": None if policy_lead is None else str(policy_lead), "committed_amount": str(committed_amount), "price_variance_percent": None if price_variance is None else str(price_variance), "landed_premium": str(premium), "landed_premium_percent": None if premium_pct is None else str(premium_pct), "shrinkage_value": str(_money(row["shrinkage"])), "write_down_total": str(_money(row["write_down"])), "grade": grade, "rationale": rationale[:300], "purchases_detail": [{**order, "quantity": str(order["quantity"]), "unit_price": str(order["unit_price"]), "standard_unit_cost": str(order["standard_unit_cost"]), "received_quantity": str(order["received_quantity"]), "freight": str(_money(order["freight"])), "duty": str(_money(order["duty"]))} for order in orders]})
    order = {"replace": 0, "watch": 1, "unproven": 2, "reliable": 3}
    rows.sort(key=lambda row: (order[row["grade"]], -Decimal(row["committed_amount"]), row["supplier_ref"]))
    recommendations = [f"{row['supplier_ref']}: {row['grade']}; {row['rationale']}" for row in rows if row["grade"] in ("replace", "watch") or "single-source" in row["rationale"]][:24]
    if not recommendations:
        recommendations.append("every supplier with purchases in the window is reliable" if rows else "no stock positions with a supplier")
    payload = {"company_ref": parsed_plan.company_ref, "currency": parsed_plan.currency, "window_start": start, "window_end": end, "as_of": at, "plan_digest": parsed_plan.plan_digest, "suppliers": rows, "positions": positions, "purchases": sum(row["purchases"] for row in rows), "committed_amount": str(_money(sum((Decimal(row["committed_amount"]) for row in rows), Decimal("0")))), "landed_premium": str(_money(sum((Decimal(row["landed_premium"]) for row in rows), Decimal("0")))), "by_grade": {grade: counts[grade] for grade in SUPPLIER_GRADES if counts.get(grade)}, "recommendations": [item[:300] for item in recommendations], "source_digests": digests}
    return seal(SupplierScorecard, payload, "scorecard_digest")


def verify_supplier_scorecard(value: Any) -> SupplierScorecard:
    return value if isinstance(value, SupplierScorecard) else SupplierScorecard.model_validate(dict(detached(value)))


SUPPLIER_SCORECARD_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "supplier_scorecard",
    "golden_loop": "commerce.product_truth_to_measured_income@0.1.0",
    "stages": ["replay_stock_positions", "pair_proposal_purchase_receipts_landed_cost", "score_on_time_fill_price_premium", "grade", "seal_scorecard"],
    "grades": list(SUPPLIER_GRADES),
    "required_connectors": ["lightbulb.sdk_engine_state"],
    "hard_rules": [
        "every purchase, receipt, and landed cost is the inventory chain's own replayed history; nothing is typed here",
        "on time is received at or before the date the policy expected when the reorder was proposed; fill rate is received over committed",
        "the landed premium is freight plus duty over the committed amount; price variance is against the policy's standard unit cost",
        "a grade is a fixed rule on the plan's targets and every rationale names the number",
    ],
}

__all__ = ["SUPPLIER_GRADES", "SUPPLIER_SCORECARD_MANIFEST", "SUPPLIER_SCORECARD_PLAN_SCHEMA", "SUPPLIER_SCORECARD_SCHEMA", "PurchaseRecord", "SupplierRow", "SupplierScorecard", "SupplierScorecardError", "SupplierScorecardPlan", "build_supplier_scorecard", "compile_supplier_scorecard_plan", "verify_supplier_scorecard"]
