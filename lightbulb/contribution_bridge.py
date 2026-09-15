"""Contribution bridge: exactly why contribution moved between two windows, SKU by SKU.

Price / volume / mix explains revenue.  Contribution also moves when the
landed cost, the fee rate, the fulfilment cost, or the return handling
per unit moves.  ``build_contribution_bridge`` decomposes the change in
contribution between two sealed product margin reports into effects that
sum exactly to the change:

* **volume**: the units the SKU would have sold had its share of total
  volume held, times last window's unit contribution;
* **mix**: the units it sold beyond (or short of) that held share, times
  last window's unit contribution;
* **price**: the change in realised price per unit (net of discounts and
  returns), times this window's units;
* **fees**, **cost of goods**, **fulfilment**, **return handling**: the
  change in each unit cost, times this window's units, with the sign
  that a rising cost lowers contribution;
* a SKU that is new or dropped carries its whole contribution as volume.

Every effect is arithmetic on the two reports; nothing here estimates,
predicts, reads a provider, or persists anything.
"""

from __future__ import annotations

from collections.abc import Mapping
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
)
from lightbulb.product_margin import verify_product_margin

CONTRIBUTION_BRIDGE_SCHEMA = "lightbulb.contribution_bridge.v1"
BRIDGE_EFFECTS: tuple[str, ...] = ("volume", "mix", "price", "fees", "cost_of_goods", "fulfilment", "return_handling")
SkuStatus = Literal["continuing", "new", "dropped"]
_HUNDRED = Decimal("100")


class ContributionBridgeError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise ContributionBridgeError(code, message)


def _money(value: Any) -> Decimal:
    result = Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)
    return Decimal("0.00") if result == 0 else result


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


class BridgeRow(StrictModel):
    sku_ref: OpaqueRef
    status: SkuStatus
    previous_units: Decimal
    current_units: Decimal
    previous_contribution: Decimal
    current_contribution: Decimal
    change: Decimal
    volume: Decimal
    mix: Decimal
    price: Decimal
    fees: Decimal
    cost_of_goods: Decimal
    fulfilment: Decimal
    return_handling: Decimal
    largest_driver: ShortText

    @field_validator("previous_units", "current_units", "previous_contribution", "current_contribution", "change", "volume", "mix", "price", "fees", "cost_of_goods", "fulfilment", "return_handling", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class ContributionBridge(StrictModel):
    schema_id: str = Field(default=CONTRIBUTION_BRIDGE_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    previous_window_start: str
    previous_window_end: str
    current_window_start: str
    current_window_end: str
    previous_report_digest: Sha256Digest
    current_report_digest: Sha256Digest
    previous_contribution: Decimal
    current_contribution: Decimal
    change: Decimal
    effects: dict[str, Decimal] = Field(default_factory=dict)
    rows: tuple[BridgeRow, ...] = Field(default_factory=tuple, max_length=5000)
    explanation: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=24)
    bridge_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("rows", "explanation", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("previous_contribution", "current_contribution", "change", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name), allow_negative=True)

    @field_validator("effects", mode="before")
    @classmethod
    def _effects(cls, value: object) -> object:
        return {str(key): decimal_value(item, field_name=f"effects[{key}]", allow_negative=True) for key, item in value.items()} if isinstance(value, Mapping) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "ContributionBridge":
        if set(self.effects) != set(BRIDGE_EFFECTS) or sum(self.effects.values(), Decimal("0")) != self.change or self.change != self.current_contribution - self.previous_contribution:
            raise ValueError("the effects must sum exactly to the change in contribution")
        for row in self.rows:
            if row.volume + row.mix + row.price + row.fees + row.cost_of_goods + row.fulfilment + row.return_handling != row.change:
                raise ValueError(f"{row.sku_ref}: the effects must sum exactly to the SKU's change")
        if not skip_digests(info) and self.bridge_digest != sealed_digest(ContributionBridge, self, "bridge_digest"):
            raise ValueError("bridge_digest must commit the exact bridge")
        return self

    def row(self, sku_ref: str) -> BridgeRow | None:
        return next((row for row in self.rows if row.sku_ref == sku_ref), None)

    def render(self) -> str:
        lines = [f"**Contribution bridge {self.company_ref}** {self.previous_window_start[:10]} to {self.current_window_end[:10]}: {self.previous_contribution} to {self.current_contribution} {self.currency} ({'+' if self.change >= 0 else ''}{self.change}); " + ", ".join(f"{name} {'+' if amount >= 0 else ''}{amount}" for name, amount in self.effects.items()) + "."]
        lines.extend(f"- {item}" for item in self.explanation)
        return "\n".join(lines)


def _unit(row: Any, field: str) -> Decimal:
    units = Decimal(str(row.units_sold))
    return Decimal("0") if units <= 0 else Decimal(str(getattr(row, field))) / units


def build_contribution_bridge(previous: Mapping[str, Any] | Any, current: Mapping[str, Any] | Any) -> ContributionBridge:
    """The exact decomposition of the change in contribution between two sealed product margin reports."""

    before, after = verify_product_margin(previous), verify_product_margin(current)
    _require(before.company_ref == after.company_ref and before.currency == after.currency, "SOURCE_SCOPE_MISMATCH", "both reports must name the same company and currency")
    _require(parsed(before.window_end) <= parsed(after.window_start), "WINDOWS_OVERLAP", "the previous window must end before the current one starts")
    prior = {row.sku_ref: row for row in before.rows}
    now = {row.sku_ref: row for row in after.rows}
    total_prev = sum((Decimal(str(row.units_sold)) for row in before.rows), Decimal("0"))
    total_now = sum((Decimal(str(row.units_sold)) for row in after.rows), Decimal("0"))
    rows: list[dict[str, Any]] = []
    totals = {name: Decimal("0") for name in BRIDGE_EFFECTS}
    for sku_ref in sorted(set(prior) | set(now)):
        p, c = prior.get(sku_ref), now.get(sku_ref)
        units_prev = Decimal(str(p.units_sold)) if p else Decimal("0")
        units_now = Decimal(str(c.units_sold)) if c else Decimal("0")
        contrib_prev = Decimal(str(p.contribution)) if p else Decimal("0")
        contrib_now = Decimal(str(c.contribution)) if c else Decimal("0")
        change = _money(contrib_now - contrib_prev)
        effects = {name: Decimal("0") for name in BRIDGE_EFFECTS}
        if p is None or c is None or units_prev <= 0 or units_now <= 0:
            status = "new" if p is None or units_prev <= 0 else "dropped"
            effects["volume"] = change
        else:
            status = "continuing"
            uc_prev = contrib_prev / units_prev
            held = total_now * (units_prev / total_prev) if total_prev > 0 else units_prev
            volume = _money((held - units_prev) * uc_prev)
            mix = _money((units_now - held) * uc_prev)
            price = _money((_unit(c, "net_revenue") - _unit(p, "net_revenue")) * units_now)
            fees = _money(-(_unit(c, "fees") - _unit(p, "fees")) * units_now)
            cogs = _money(-(_unit(c, "cost_of_goods") - _unit(p, "cost_of_goods")) * units_now)
            fulfilment = _money(-(_unit(c, "fulfilment_cost") - _unit(p, "fulfilment_cost")) * units_now)
            returns = _money(-(_unit(c, "return_handling") - _unit(p, "return_handling")) * units_now)
            effects.update({"volume": volume, "mix": mix, "price": price, "fees": fees, "cost_of_goods": cogs, "fulfilment": fulfilment, "return_handling": returns})
            # rounding lands on the largest effect so the row ties exactly
            drift = change - sum(effects.values(), Decimal("0"))
            if drift != 0:
                biggest = max(effects, key=lambda name: (abs(effects[name]), name))
                effects[biggest] += drift
        for name, amount in effects.items():
            totals[name] += amount
        driver = max(effects, key=lambda name: (abs(effects[name]), name))
        rows.append({"sku_ref": sku_ref, "status": status, "previous_units": str(units_prev), "current_units": str(units_now), "previous_contribution": str(_money(contrib_prev)), "current_contribution": str(_money(contrib_now)), "change": str(change), **{name: str(amount) for name, amount in effects.items()}, "largest_driver": f"{driver} ({'+' if effects[driver] >= 0 else ''}{effects[driver]})" if change != 0 else "unchanged"})
    rows.sort(key=lambda row: (-abs(Decimal(row["change"])), row["sku_ref"]))
    change = _money(Decimal(str(after.contribution)) - Decimal(str(before.contribution)))
    drift = change - sum(totals.values(), Decimal("0"))
    if drift != 0:
        # contribution the reports carry outside the rows (nothing today) lands on volume
        totals["volume"] += drift
    driver = max(totals, key=lambda name: (abs(totals[name]), name))
    explanation = [f"contribution {'rose' if change > 0 else 'fell' if change < 0 else 'held'} {abs(change)}; the largest driver is {driver} ({'+' if totals[driver] >= 0 else ''}{totals[driver]})"]
    explanation += [f"{row['sku_ref']}: {row['status']}; " + ", ".join(f"{name} {'+' if Decimal(row[name]) >= 0 else ''}{row[name]}" for name in BRIDGE_EFFECTS if Decimal(row[name]) != 0) for row in rows[:20] if Decimal(row["change"]) != 0]
    payload = {
        "company_ref": after.company_ref, "currency": after.currency, "previous_window_start": before.window_start, "previous_window_end": before.window_end, "current_window_start": after.window_start, "current_window_end": after.window_end,
        "previous_report_digest": before.report_digest, "current_report_digest": after.report_digest, "previous_contribution": str(_money(before.contribution)), "current_contribution": str(_money(after.contribution)), "change": str(change),
        "effects": {name: str(amount) for name, amount in totals.items()}, "rows": rows, "explanation": [item[:300] for item in explanation[:24]],
    }
    return seal(ContributionBridge, payload, "bridge_digest")


def verify_contribution_bridge(value: Any) -> ContributionBridge:
    return value if isinstance(value, ContributionBridge) else ContributionBridge.model_validate(dict(detached(value)))


CONTRIBUTION_BRIDGE_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "contribution_bridge",
    "golden_loop": "commerce.product_truth_to_measured_income@0.1.0",
    "stages": ["verify_reports", "held_share_volume", "mix", "unit_price_and_unit_costs", "tie_exactly", "seal_bridge"],
    "effects": list(BRIDGE_EFFECTS),
    "required_connectors": ["lightbulb.sdk_engine_state"],
    "hard_rules": [
        "volume and mix are priced at last window's unit contribution; price and unit costs at this window's units",
        "the effects sum exactly to the change, per SKU and in total; rounding lands on the largest effect",
        "a new or dropped SKU is all volume",
        "nothing here estimates, predicts, reads a provider, or persists anything",
    ],
}

__all__ = ["BRIDGE_EFFECTS", "CONTRIBUTION_BRIDGE_MANIFEST", "CONTRIBUTION_BRIDGE_SCHEMA", "BridgeRow", "ContributionBridge", "ContributionBridgeError", "build_contribution_bridge", "verify_contribution_bridge"]
