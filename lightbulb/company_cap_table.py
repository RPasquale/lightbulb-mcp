"""The cap table register: one sealed table from the base holdings, the funded rounds, and the exercised options.

``fundraise_chain`` seals the cap table a round starts from and
``equity_grant_chain`` issues shares out of the pool.  Nothing joined them:
who owns what today, on which replayed rounds and grants, with what still
reserved for options.  ``build_cap_table`` does, and seals the result so the
board pack, the next round, and the next grant all read the same table.

* base holdings come from the sealed fundraise plan;
* a funded round adds the shares each wire bought at the set price (priced
  equity) or lists the convertible instruments outstanding (SAFE, note);
* an exercised grant moves shares from the pool holder to the option holder;
  live grants reserve their unexercised units against the pool.

Nothing here issues shares or persists anything.
"""

from __future__ import annotations

from collections.abc import Sequence
from decimal import ROUND_DOWN, ROUND_HALF_UP, Decimal
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
    detached,
    seal,
    sealed_digest,
    skip_digests,
    timestamp,
)

CAP_TABLE_REGISTER_SCHEMA = "lightbulb.company_cap_table_register.v1"
_HUNDRED = Decimal("100")


class CapTableError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise CapTableError(code, message)


class CapHolding(StrictModel):
    holder_ref: OpaqueRef
    share_class: ShortText
    shares: int = Field(ge=0)
    ownership_percent: Decimal = Field(default=Decimal("0"), validate_default=True)
    sources: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=200)

    @field_validator("sources", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("ownership_percent", mode="before")
    @classmethod
    def _percent(cls, value: Any) -> Decimal:
        return Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


class Convertible(StrictModel):
    holder_ref: OpaqueRef
    instrument: Literal["safe", "convertible_note"]
    amount: Decimal
    valuation_cap: Decimal
    discount_percent: Decimal
    round_ref: OpaqueRef
    received: bool

    @field_validator("amount", "valuation_cap", "discount_percent", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


class CapTableRegister(StrictModel):
    schema_id: str = Field(default=CAP_TABLE_REGISTER_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    as_of: str
    holdings: tuple[CapHolding, ...] = Field(min_length=1, max_length=1000)
    convertibles: tuple[Convertible, ...] = Field(default_factory=tuple, max_length=500)
    fully_diluted_shares: int = Field(ge=1)
    pool_holder_ref: OpaqueRef
    pool_shares: int = Field(ge=0)
    options_outstanding: int = Field(ge=0)
    options_exercised: int = Field(ge=0)
    pool_unallocated: int
    rounds_funded: int = Field(ge=0)
    rounds_open: int = Field(ge=0)
    cash_raised: Decimal
    base_plan_digest: Sha256Digest
    source_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=1500)
    register_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("holdings", "convertibles", "source_digests", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("cash_raised", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)

    @field_validator("as_of")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="as_of")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "CapTableRegister":
        if sum(item.shares for item in self.holdings) != self.fully_diluted_shares:
            raise ValueError("fully diluted shares must equal the holdings")
        if not skip_digests(info) and self.register_digest != sealed_digest(CapTableRegister, self, "register_digest"):
            raise ValueError("register_digest must commit the exact register")
        return self

    def holding(self, holder_ref: str, share_class: str | None = None) -> CapHolding | None:
        return next((item for item in self.holdings if item.holder_ref == holder_ref and (share_class is None or item.share_class == share_class)), None)

    def render(self) -> str:
        lines = [f"**Cap table {self.company_ref}** as of {self.as_of[:10]}: {self.fully_diluted_shares} fully diluted share(s), {self.options_outstanding} option(s) outstanding, {self.pool_unallocated} unallocated in {self.pool_holder_ref}"]
        for item in sorted(self.holdings, key=lambda row: (-row.shares, row.holder_ref)):
            lines.append(f"- {item.holder_ref} ({item.share_class}): {item.shares} ({item.ownership_percent}%)")
        for item in self.convertibles:
            lines.append(f"- convertible {item.holder_ref}: {item.instrument} {item.amount} {self.currency} at cap {item.valuation_cap}{' (received)' if item.received else ' (committed)'}")
        return "\n".join(lines)


def build_cap_table(base_plan: Any, *, rounds: Sequence[tuple[Any, Any]] = (), grants: Sequence[tuple[Any, Any]] = (), as_of: str, pool_holder_ref: str | None = None) -> CapTableRegister:
    """The sealed table from the fundraise plan's holdings, the replayed rounds (plan, state), and the replayed grants (plan, state)."""

    from lightbulb.equity_grant_chain import EQUITY_GRANT_LIFECYCLE
    from lightbulb.fundraise_chain import FUNDRAISE_LIFECYCLE, FundraisePlan

    base = base_plan if isinstance(base_plan, FundraisePlan) else FundraisePlan.model_validate(detached(base_plan))
    stamp = timestamp(as_of, field_name="as_of")
    holdings: dict[tuple[str, str], dict[str, Any]] = {}

    def add(holder: str, share_class: str, shares: int, source: str) -> None:
        row = holdings.setdefault((holder, share_class), {"holder_ref": holder, "share_class": share_class, "shares": 0, "sources": []})
        row["shares"] += shares
        if source not in row["sources"]:
            row["sources"].append(source)

    for item in base.cap_table:
        add(item.holder_ref, item.share_class, item.shares, "base")
    convertibles: list[dict[str, Any]] = []
    digests: list[str] = []
    funded = open_rounds = 0
    cash = Decimal("0")
    for plan_doc, state_doc in rounds:
        plan, state = FUNDRAISE_LIFECYCLE.bind(plan_doc, state_doc)
        _require(plan.company_ref == base.company_ref and plan.currency == base.currency, "ROUND_SCOPE_MISMATCH", f"round {state.scope.entity_ref} belongs to another company or currency")
        _require(plan.plan_digest == base.plan_digest, "ROUND_BASE_MISMATCH", f"round {state.scope.entity_ref} was priced off a different cap table")
        digests.append(state.state_digest)
        ledger = state.ledger
        if state.status not in ("closed", "funded"):
            if state.status in ("planned", "terms_set", "committed"):
                open_rounds += 1
            continue
        funded += 1 if state.status == "funded" else 0
        open_rounds += 1 if state.status == "closed" else 0
        for commitment in ledger.commitments:
            received = commitment.received_at is not None
            if ledger.instrument == "priced_equity":
                if received:
                    shares = int((commitment.amount / ledger.price_per_share).to_integral_value(rounding=ROUND_DOWN))
                    add(commitment.investor_ref, f"round:{ledger.round_ref}", shares, f"round:{state.scope.entity_ref}")
                    cash += commitment.amount
            else:
                convertibles.append({"holder_ref": commitment.investor_ref, "instrument": ledger.instrument, "amount": str(commitment.amount), "valuation_cap": str(ledger.valuation_cap), "discount_percent": str(ledger.discount_percent), "round_ref": str(ledger.round_ref), "received": received})
                if received:
                    cash += commitment.amount
    pool_ref = pool_holder_ref
    outstanding = exercised = 0
    for plan_doc, state_doc in grants:
        plan, state = EQUITY_GRANT_LIFECYCLE.bind(plan_doc, state_doc)
        _require(plan.company_ref == base.company_ref and plan.currency == base.currency, "GRANT_SCOPE_MISMATCH", f"grant {state.scope.entity_ref} belongs to another company or currency")
        pool_ref = pool_ref or plan.pool_holder_ref
        _require(pool_ref == plan.pool_holder_ref, "POOL_MISMATCH", "every grant draws on the same pool holder")
        digests.append(state.state_digest)
        ledger = state.ledger
        if ledger.exercised_units > 0:
            pool_row = holdings.get((plan.pool_holder_ref, next((item.share_class for item in base.cap_table if item.holder_ref == plan.pool_holder_ref), plan.share_class)))
            _require(pool_row is not None and pool_row["shares"] >= ledger.exercised_units, "POOL_EXHAUSTED", f"the pool {plan.pool_holder_ref} cannot cover {ledger.exercised_units} exercised option(s)")
            assert pool_row is not None
            pool_row["shares"] -= ledger.exercised_units
            pool_row["sources"].append(f"grant:{state.scope.entity_ref}")
            add(str(ledger.holder_ref), plan.share_class, ledger.exercised_units, f"grant:{state.scope.entity_ref}")
            exercised += ledger.exercised_units
            cash += ledger.proceeds_total
        if state.status in ("granted", "vesting", "fully_vested"):
            outstanding += ledger.units - ledger.forfeited_units - ledger.exercised_units
    pool_ref = pool_ref or "esop"
    pool_shares = sum(row["shares"] for (holder, _cls), row in holdings.items() if holder == pool_ref)
    total = sum(row["shares"] for row in holdings.values())
    _require(total > 0, "EMPTY_TABLE", "the table holds no shares")
    rows = []
    for row in holdings.values():
        rows.append({**row, "ownership_percent": str((Decimal(row["shares"]) / Decimal(total) * _HUNDRED).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP))})
    rows.sort(key=lambda row: (-int(row["shares"]), str(row["holder_ref"]), str(row["share_class"])))
    return seal(CapTableRegister, {"company_ref": base.company_ref, "currency": base.currency, "as_of": stamp, "holdings": rows, "convertibles": convertibles, "fully_diluted_shares": total, "pool_holder_ref": pool_ref, "pool_shares": pool_shares, "options_outstanding": outstanding, "options_exercised": exercised, "pool_unallocated": pool_shares - outstanding, "rounds_funded": funded, "rounds_open": open_rounds, "cash_raised": str(cash.quantize(MONEY_QUANTUM)), "base_plan_digest": base.plan_digest, "source_digests": sorted(set(digests))}, "register_digest")


CAP_TABLE_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "company_cap_table",
    "golden_loop": "capital.round_planned_to_funds_received@0.1.0",
    "stages": ["base_holdings", "funded_rounds", "exercised_grants", "seal_register"],
    "required_connectors": ["lightbulb.sdk_engine_state"],
    "hard_rules": [
        "the base holdings are the sealed fundraise plan's; every round must have been priced off that plan",
        "a round adds shares only for wires that arrived; a grant moves shares only for options exercised for cash",
        "live grants reserve their unexercised units against the pool; the register says what is unallocated",
        "nothing here issues shares or persists anything",
    ],
}

__all__ = ["CAP_TABLE_MANIFEST", "CAP_TABLE_REGISTER_SCHEMA", "CapHolding", "CapTableError", "CapTableRegister", "Convertible", "build_cap_table"]
