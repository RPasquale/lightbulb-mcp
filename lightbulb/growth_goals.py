"""Growth goals: the owner's target broken into the drivers the books already hold, with the gap each must close and the levers that move it.

"Grow revenue 30% this year" is a wish until it is arithmetic.  The books
give the run rate; the customer ledger gives how many customers carry it
and what each brings; together they give the drivers revenue is made of:
customers x revenue per customer (and, when the books are monthly, the
months of run rate to the horizon).  ``set_growth_goal`` seals the goal:
the baseline per month from the latest recorded window, the run rate the
horizon needs, the gap, and the split of that gap across the drivers in
the mix the owner states (equal when they state none), each with its own
target and the SDK documents and levers that move it (what_if for price,
customers and cohorts for retention and frequency, sourcing and capacity
for volume, market_rates and rate_card for the rate charged).

Nothing is forecast.  The goal states what would have to be true, not
that it will be; ``progress`` later puts each driver's latest recorded
value beside its target so the owner sees which driver is carrying the
growth and which is not.  Deterministic; reads nothing.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import ROUND_CEILING, ROUND_HALF_UP, Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, CurrencyCode, OpaqueRef, Sha256Digest, ShortText, StrictModel, decimal_value, detached, parsed, seal, sealed_digest, skip_digests, timestamp

GROWTH_GOAL_SCHEMA = "lightbulb.growth_goal.v1"
GOAL_PROGRESS_SCHEMA = "lightbulb.growth_goal_progress.v1"
GROWTH_GOALS_MANIFEST: dict[str, Any] = {"engine": "growth_goals", "kind": "intelligence_document", "reads": ("books_snapshot", "customer_ledger", "intelligence_history"), "writes": ()}
GoalMetric = Literal["revenue", "net_profit"]
# driver -> (what moves it, the documents that inform it)
DRIVERS: dict[str, tuple[str, tuple[str, ...]]] = {
    "customers": ("win more customers, lose fewer", ("customers", "customer_cohorts", "pipeline_coverage", "growth_review")),
    "revenue_per_customer": ("charge more per customer: price, rate, scope, frequency", ("what_if", "rate_card", "price_probes", "customer_profitability")),
    "revenue": ("sell more: volume, price, capacity to deliver", ("what_if", "workforce_capacity", "sourcing", "price_probes")),
    "net_margin_percent": ("keep more of each sale: cost of sales, fixed cost, price", ("break_even", "product_margin", "services_margin", "what_if")),
}
_CENT = Decimal("0.01")
_PCT = Decimal("0.1")


class GrowthGoalError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise GrowthGoalError(code, message)


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


def _per_month(books: Mapping[str, Any], field: str) -> Decimal:
    days = (parsed(str(books["window_end"])) - parsed(str(books["window_start"]))).days
    _require(days > 0, "WINDOW_EMPTY", "the books window is empty")
    return (Decimal(str(books[field])) * Decimal(30) / Decimal(days)).quantize(_CENT, rounding=ROUND_HALF_UP)


class GoalDriver(StrictModel):
    driver: ShortText
    baseline: Decimal
    share_of_gap_percent: Decimal
    target: Decimal
    moved_by: ShortText
    documents: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=8)

    @field_validator("documents", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("baseline", "share_of_gap_percent", "target", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class GrowthGoal(StrictModel):
    schema_id: str = Field(default=GROWTH_GOAL_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    goal_ref: OpaqueRef
    metric: GoalMetric
    set_at: str
    horizon_months: int = Field(ge=1, le=36)
    target_growth_percent: Decimal
    baseline_per_month: Decimal
    required_per_month: Decimal
    gap_per_month: Decimal
    drivers: tuple[GoalDriver, ...] = Field(min_length=1, max_length=6)
    basis: ShortText
    verdict: ShortText
    source_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=4)
    goal_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("drivers", "source_digests", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("target_growth_percent", "baseline_per_month", "required_per_month", "gap_per_month", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name), allow_negative=True)

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "GrowthGoal":
        if sum((driver.share_of_gap_percent for driver in self.drivers), Decimal("0")) != Decimal("100"):
            raise ValueError("the drivers share the whole gap")
        if not skip_digests(info) and self.goal_digest != sealed_digest(GrowthGoal, self, "goal_digest"):
            raise ValueError("goal_digest must commit the exact goal")
        return self

    def render(self) -> str:
        lines = [f"**Growth goal** ({self.company_ref}, {self.goal_ref}): {self.verdict}"]
        lines.extend(f"- {driver.driver}: {driver.baseline} now, {driver.target} needed ({driver.share_of_gap_percent}% of the gap); {driver.moved_by}" for driver in self.drivers)
        return "\n".join(lines)


def set_growth_goal(*, company_ref: str, currency: str, goal_ref: str, metric: str, target_growth_percent: Any, horizon_months: int, as_of: str, books: Mapping[str, Any], customer_ledger: Mapping[str, Any] | None = None, mix: Mapping[str, Any] | None = None) -> GrowthGoal:
    """The sealed goal: baseline and required run rate per month, the gap, and the drivers that must close it."""

    from lightbulb.books_snapshot import verify_books_snapshot

    _require(metric in ("revenue", "net_profit"), "METRIC_UNKNOWN", "a goal is set on revenue or net_profit")
    _require(1 <= int(horizon_months) <= 36, "HORIZON_INVALID", "the horizon is 1 to 36 months")
    growth = decimal_value(target_growth_percent, field_name="target_growth_percent", allow_negative=True)
    _require(growth > 0, "TARGET_INVALID", "the target is a growth percentage above zero")
    snapshot = verify_books_snapshot({key: value for key, value in dict(detached(books)).items() if key not in {"version", "summary", "provider_effect_executed"}})
    _require(snapshot.company_ref == company_ref and snapshot.currency == str(currency).upper(), "SOURCE_SCOPE_MISMATCH", "the books name another company or currency")
    baseline = _per_month(snapshot.to_dict(), metric)
    _require(baseline > 0, "BASELINE_NOT_POSITIVE", f"the latest books give a {metric} of {baseline} a month; a growth goal needs a positive baseline")
    required = (baseline * (Decimal(100) + growth) / Decimal(100)).quantize(_CENT, rounding=ROUND_HALF_UP)
    gap = (required - baseline).quantize(_CENT)
    digests = [snapshot.snapshot_digest]

    # the drivers the evidence supports
    drivers: list[dict[str, Any]] = []
    ledger = None if customer_ledger is None else dict(detached(customer_ledger))
    if metric == "revenue" and ledger is not None and int(ledger.get("customers", 0)) > 0:
        from lightbulb.customer_ledger import verify_customer_ledger

        parsed_ledger = verify_customer_ledger({key: value for key, value in ledger.items() if key not in {"version", "summary", "provider_effect_executed"}})
        _require(parsed_ledger.company_ref == company_ref, "SOURCE_SCOPE_MISMATCH", "the customer ledger names another company")
        digests.append(parsed_ledger.ledger_digest)
        customers = Decimal(parsed_ledger.customers)
        per_customer = (baseline / customers).quantize(_CENT, rounding=ROUND_HALF_UP)
        names = ["customers", "revenue_per_customer"]
        basis = f"revenue = {customers} customer(s) x {per_customer} a month each, from the customer ledger for {parsed_ledger.window_start[:10]} to {parsed_ledger.window_end[:10]}"
        baselines = {"customers": customers, "revenue_per_customer": per_customer}
    elif metric == "revenue":
        names, basis, baselines = ["revenue"], "revenue alone: no customer ledger is recorded, so customers and revenue per customer cannot be told apart", {"revenue": baseline}
    else:
        margin = snapshot.net_margin_percent if snapshot.net_margin_percent is not None else Decimal("0")
        names, basis, baselines = ["revenue", "net_margin_percent"], f"net result = revenue x net margin ({margin}%)", {"revenue": _per_month(snapshot.to_dict(), "revenue"), "net_margin_percent": margin}
    shares = {name: decimal_value(value, field_name=f"mix.{name}") for name, value in dict(mix or {}).items()}
    _require(set(shares) <= set(names), "MIX_UNKNOWN_DRIVER", f"the mix names drivers other than {names}")
    if not shares:
        even = (Decimal(100) / Decimal(len(names))).quantize(_PCT, rounding=ROUND_HALF_UP)
        shares = {name: even for name in names}
        shares[names[-1]] = Decimal(100) - sum(shares[name] for name in names[:-1])
    _require(sum(shares.values()) == Decimal(100), "MIX_NOT_WHOLE", "the mix shares the whole gap (100%)")
    for name in names:
        base = baselines[name]
        share = shares[name]
        # each driver carries its share of the growth in its own units: a 30% goal split 50/50 asks 15% of each
        raw_target = base * (Decimal(1) + (growth / Decimal(100)) * share / Decimal(100))
        # customers are whole, and a share of growth that needs part of a customer needs a whole one: round up
        target = raw_target.quantize(Decimal("1"), rounding=ROUND_CEILING) if name == "customers" else raw_target.quantize(_PCT if name == "net_margin_percent" else _CENT, rounding=ROUND_HALF_UP)
        moved_by, documents = DRIVERS[name]
        drivers.append({"driver": name, "baseline": str(base), "share_of_gap_percent": str(share), "target": str(target), "moved_by": moved_by, "documents": list(documents)})
    verdict = f"{metric} {baseline}/month now, {required}/month needed in {int(horizon_months)} month(s) (+{growth}%, a gap of {gap}/month); {basis}"
    return seal(GrowthGoal, {"company_ref": company_ref, "currency": str(currency).upper(), "goal_ref": goal_ref, "metric": metric, "set_at": timestamp(as_of, field_name="as_of"), "horizon_months": int(horizon_months), "target_growth_percent": str(growth), "baseline_per_month": str(baseline), "required_per_month": str(required), "gap_per_month": str(gap), "drivers": drivers, "basis": basis[:300], "verdict": verdict[:300], "source_digests": digests}, "goal_digest")


class DriverProgress(StrictModel):
    driver: ShortText
    baseline: Decimal
    target: Decimal
    latest: Decimal | None = None
    progress_percent: Decimal | None = None
    status: Literal["on_track", "behind", "ahead", "unknown"]

    @field_validator("baseline", "target", "latest", "progress_percent", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class GoalProgress(StrictModel):
    schema_id: str = Field(default=GOAL_PROGRESS_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    goal_ref: OpaqueRef
    goal_digest: Sha256Digest
    as_of: str
    months_elapsed: int = Field(ge=0)
    months_remaining: int = Field(ge=0)
    expected_progress_percent: Decimal
    drivers: tuple[DriverProgress, ...] = Field(min_length=1, max_length=6)
    verdict: ShortText
    progress_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("drivers", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("expected_progress_percent", mode="before")
    @classmethod
    def _numbers(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="expected_progress_percent", allow_negative=True)

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "GoalProgress":
        if not skip_digests(info) and self.progress_digest != sealed_digest(GoalProgress, self, "progress_digest"):
            raise ValueError("progress_digest must commit the exact progress")
        return self

    def render(self) -> str:
        lines = [f"**Goal progress** ({self.goal_ref}, {self.as_of[:10]}): {self.verdict}"]
        lines.extend(f"- {row.driver}: {row.status}" + (f", {row.latest} against {row.target} ({row.progress_percent}% of the way)" if row.latest is not None else " (no reading yet)") for row in self.drivers)
        return "\n".join(lines)


def goal_progress(goal: GrowthGoal | Mapping[str, Any], *, as_of: str, books: Mapping[str, Any] | None = None, customer_ledger: Mapping[str, Any] | None = None) -> GoalProgress:
    """Each driver's latest recorded value against its target, beside where a straight line to the horizon would put it."""

    parsed_goal = goal if isinstance(goal, GrowthGoal) else GrowthGoal.model_validate({key: value for key, value in dict(detached(goal)).items() if key not in {"summary", "provider_effect_executed", "version"}})
    at = timestamp(as_of, field_name="as_of")
    start, now = parsed(parsed_goal.set_at), parsed(at)
    elapsed = max(0, (now.year - start.year) * 12 + now.month - start.month)
    remaining = max(0, parsed_goal.horizon_months - elapsed)
    expected = min(Decimal(100), (Decimal(elapsed) * Decimal(100) / Decimal(parsed_goal.horizon_months))).quantize(_PCT, rounding=ROUND_HALF_UP)
    latest: dict[str, Decimal] = {}
    if books is not None:
        from lightbulb.books_snapshot import verify_books_snapshot

        snapshot = verify_books_snapshot({key: value for key, value in dict(detached(books)).items() if key not in {"version", "summary", "provider_effect_executed"}})
        latest["revenue"] = _per_month(snapshot.to_dict(), "revenue")
        if snapshot.net_margin_percent is not None:
            latest["net_margin_percent"] = snapshot.net_margin_percent
    if customer_ledger is not None:
        ledger = dict(detached(customer_ledger))
        if int(ledger.get("customers", 0)) > 0 and "revenue" in latest:
            latest["customers"] = Decimal(int(ledger["customers"]))
            latest["revenue_per_customer"] = (latest["revenue"] / latest["customers"]).quantize(_CENT, rounding=ROUND_HALF_UP)
    rows: list[dict[str, Any]] = []
    behind = 0
    for driver in parsed_goal.drivers:
        value = latest.get(driver.driver)
        if value is None:
            rows.append({"driver": driver.driver, "baseline": str(driver.baseline), "target": str(driver.target), "status": "unknown"})
            continue
        span = driver.target - driver.baseline
        progress = Decimal(100) if span == 0 else ((value - driver.baseline) * Decimal(100) / span).quantize(_PCT, rounding=ROUND_HALF_UP)
        status = "on_track" if span == 0 else ("ahead" if progress > expected + Decimal(10) else ("behind" if progress < expected - Decimal(10) else "on_track"))
        behind += int(status == "behind")
        rows.append({"driver": driver.driver, "baseline": str(driver.baseline), "target": str(driver.target), "latest": str(value), "progress_percent": str(progress), "status": status})
    verdict = f"{elapsed} of {parsed_goal.horizon_months} month(s) gone, {expected}% of the way expected; " + (f"{behind} driver(s) behind" if behind else "no driver behind") + f"; {sum(1 for row in rows if row['status'] == 'unknown')} without a reading"
    return seal(GoalProgress, {"company_ref": parsed_goal.company_ref, "goal_ref": parsed_goal.goal_ref, "goal_digest": parsed_goal.goal_digest, "as_of": at, "months_elapsed": elapsed, "months_remaining": remaining, "expected_progress_percent": str(expected), "drivers": rows, "verdict": verdict[:300]}, "progress_digest")


def verify_growth_goal(value: Any) -> GrowthGoal:
    return value if isinstance(value, GrowthGoal) else GrowthGoal.model_validate({key: item for key, item in dict(detached(value)).items() if key not in {"summary", "provider_effect_executed", "version", "documents_built"}})


__all__ = ["DRIVERS", "GOAL_PROGRESS_SCHEMA", "GROWTH_GOALS_MANIFEST", "GROWTH_GOAL_SCHEMA", "DriverProgress", "GoalDriver", "GoalProgress", "GrowthGoal", "GrowthGoalError", "goal_progress", "set_growth_goal", "verify_growth_goal"]
