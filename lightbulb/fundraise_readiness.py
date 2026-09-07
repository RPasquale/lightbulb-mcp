"""Fundraise readiness: default alive or dead, and the burn multiple.

Runway answers "how long until zero at today's burn." The sharper question a
fast-growing startup lives or dies by is Paul Graham's: **given your cash, your
costs, and how fast revenue is growing, do you reach profitability before the
money runs out?** That is default-alive vs default-dead, and this module
computes it — alongside the burn multiple investors actually judge efficiency
by (net burn per dollar of net new revenue).

These are inherently forward-looking, so they are built as **scenario
calculators, not forecasts**: the engine computes the deterministic consequence
of assumptions the caller states out loud (a monthly revenue growth rate, an
optional cost growth rate). It never predicts the growth rate itself, never
dresses a projection as a fact, and every verdict is explicitly conditional on
its assumptions, which it echoes back. Change the growth assumption and the
verdict changes — that honesty is the point.

Holds no keyring, does no I/O. Deterministic and digest-bound.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import datetime, timezone
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

DEFAULT_ALIVE_ASSESSMENT_SCHEMA = "lightbulb.default_alive_assessment.v1"
BURN_MULTIPLE_SCHEMA = "lightbulb.burn_multiple.v1"

_MONEY_QUANTUM = Decimal("0.01")
_RATE_QUANTUM = Decimal("0.000001")
_MULTIPLE_QUANTUM = Decimal("0.01")

_PORTABLE_REF_PATTERN = r"^[a-z][a-z0-9_-]{0,63}$"
_CURRENCY_PATTERN = r"^[A-Z]{3}$"

DefaultAliveVerdict = Literal["already_profitable", "default_alive", "default_dead"]
BurnMultipleRating = Literal[
    "cash_generating", "excellent", "great", "ok", "concerning", "unknown"
]

# Burn-multiple bands (net burn per $ of net new revenue). Heuristic reference,
# labeled as such — not an industry truth. Loosely after the Sacks framework.
_BURN_BANDS: tuple[tuple[Decimal, str], ...] = (
    (Decimal("1.00"), "excellent"),
    (Decimal("1.50"), "great"),
    (Decimal("2.00"), "ok"),
)


class FundraiseReadinessError(ValueError):
    """The readiness inputs cannot produce an honest assessment."""


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


def _decimal(value: Any, *, quantum: Decimal | None = None, allow_negative: bool = False) -> Decimal:
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
            raise ValueError("value cannot be represented at the required precision") from exc
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


def _quantized_multiple(value: Decimal) -> Decimal:
    return value.quantize(_MULTIPLE_QUANTUM, rounding=ROUND_HALF_UP)


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=False,
        serialize_by_alias=True,
        strict=True,
    )


# ---------------------------------------------------------------------------
# Default alive / default dead
# ---------------------------------------------------------------------------


class DefaultAliveInput(_StrictModel):
    assessment_ref: PortableRef
    as_of: str
    currency: CurrencyCode
    cash_on_hand: Decimal = Field(gt=0)
    monthly_revenue: Decimal = Field(ge=0)
    monthly_costs: Decimal = Field(ge=0)
    monthly_revenue_growth_rate: Decimal = Field(ge=0, le=Decimal("1"))
    monthly_cost_growth_rate: Decimal = Field(default=Decimal("0"), ge=0, le=Decimal("1"))
    horizon_months: int = Field(default=60, ge=1, le=120)

    @field_validator("as_of")
    @classmethod
    def _valid_as_of(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator("cash_on_hand", "monthly_revenue", "monthly_costs", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_MONEY_QUANTUM)

    @field_validator("monthly_revenue_growth_rate", "monthly_cost_growth_rate", mode="before")
    @classmethod
    def _rate(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_RATE_QUANTUM)


class DefaultAliveAssessment(_StrictModel):
    """A conditional 'do we reach profitability before the money runs out?'."""

    schema_id: Literal["lightbulb.default_alive_assessment.v1"] = Field(
        default=DEFAULT_ALIVE_ASSESSMENT_SCHEMA,
        alias="schema",
    )
    assessment_ref: PortableRef
    as_of: str
    currency: CurrencyCode
    verdict: DefaultAliveVerdict
    months_to_breakeven: int | None = None
    cash_out_month: int | None = None
    naive_runway_months: Decimal | None = None
    lowest_projected_cash: Decimal
    horizon_months: int = Field(ge=1, le=120)
    assumed_monthly_revenue_growth_rate: Decimal
    assumed_monthly_cost_growth_rate: Decimal
    notes: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=10)
    assessment_digest: str = "0" * 64

    @field_validator("as_of")
    @classmethod
    def _valid_as_of(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator(
        "naive_runway_months",
        "lowest_projected_cash",
        "assumed_monthly_revenue_growth_rate",
        "assumed_monthly_cost_growth_rate",
        mode="before",
    )
    @classmethod
    def _decimals(cls, value: Any) -> Decimal | None:
        if value is None:
            return None
        return _decimal(value, allow_negative=True)

    @field_validator("notes", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def assess_default_alive(
    inputs: DefaultAliveInput | Mapping[str, Any],
) -> DefaultAliveAssessment:
    """Decide default-alive vs default-dead under the caller's growth assumptions.

    Projects revenue and costs forward month by month at the stated growth rates
    and reports whether the company reaches breakeven (revenue >= costs) before
    cash hits zero. The verdict is CONDITIONAL on those assumptions, which are
    echoed back; it is a what-if, not a prediction.
    """

    parsed = (
        inputs
        if isinstance(inputs, DefaultAliveInput)
        else DefaultAliveInput.model_validate(inputs)
    )

    notes: list[str] = []
    g = parsed.monthly_revenue_growth_rate
    c = parsed.monthly_cost_growth_rate
    revenue = parsed.monthly_revenue
    costs = parsed.monthly_costs

    if revenue >= costs:
        return _finalize(
            parsed,
            verdict="already_profitable",
            months_to_breakeven=0,
            cash_out_month=None,
            naive_runway=None,
            lowest_cash=parsed.cash_on_hand,
            notes=["revenue already covers costs; not burn-limited at current levels"],
        )

    current_burn = costs - revenue  # > 0 here
    naive_runway = _quantized_multiple(parsed.cash_on_hand / current_burn)

    cash = parsed.cash_on_hand
    lowest_cash = cash
    breakeven_month: int | None = None
    cash_out_month: int | None = None
    r_t = revenue
    c_t = costs
    for month in range(1, parsed.horizon_months + 1):
        r_t = r_t * (Decimal("1") + g)
        c_t = c_t * (Decimal("1") + c)
        month_net = c_t - r_t  # burn if positive, profit if negative
        cash = cash - month_net
        if cash < lowest_cash:
            lowest_cash = cash
        if cash <= 0 and breakeven_month is None:
            cash_out_month = month
            break
        if r_t >= c_t and breakeven_month is None:
            breakeven_month = month
            break

    if breakeven_month is not None:
        verdict: DefaultAliveVerdict = "default_alive"
        notes.append(
            f"reaches breakeven in ~{breakeven_month} month(s) with cash to spare — "
            "under the stated growth assumptions"
        )
    elif cash_out_month is not None:
        verdict = "default_dead"
        notes.append(
            f"cash runs out in ~{cash_out_month} month(s) before breakeven — "
            "raise, cut burn, or grow faster"
        )
    else:
        verdict = "default_dead"
        notes.append(
            f"no breakeven within the {parsed.horizon_months}-month horizon at this "
            "growth rate; not on a path to profitability without change"
        )
    notes.append("conditional on the stated growth rates; change them and this changes")

    return _finalize(
        parsed,
        verdict=verdict,
        months_to_breakeven=breakeven_month,
        cash_out_month=cash_out_month,
        naive_runway=naive_runway,
        lowest_cash=_quantized_money(lowest_cash),
        notes=notes,
    )


def _finalize(
    parsed: DefaultAliveInput,
    *,
    verdict: DefaultAliveVerdict,
    months_to_breakeven: int | None,
    cash_out_month: int | None,
    naive_runway: Decimal | None,
    lowest_cash: Decimal,
    notes: list[str],
) -> DefaultAliveAssessment:
    assessment = DefaultAliveAssessment(
        assessment_ref=parsed.assessment_ref,
        as_of=parsed.as_of,
        currency=parsed.currency,
        verdict=verdict,
        months_to_breakeven=months_to_breakeven,
        cash_out_month=cash_out_month,
        naive_runway_months=naive_runway,
        lowest_projected_cash=lowest_cash,
        horizon_months=parsed.horizon_months,
        assumed_monthly_revenue_growth_rate=parsed.monthly_revenue_growth_rate,
        assumed_monthly_cost_growth_rate=parsed.monthly_cost_growth_rate,
        notes=tuple(dict.fromkeys(notes))[:10],
    )
    digest = _stable_digest(
        assessment.model_dump(mode="json", exclude={"assessment_digest"})
    )
    return assessment.model_copy(update={"assessment_digest": digest})


# ---------------------------------------------------------------------------
# Burn multiple
# ---------------------------------------------------------------------------


class BurnMultipleInput(_StrictModel):
    metric_ref: PortableRef
    as_of: str
    currency: CurrencyCode
    net_burn: Decimal = Field(allow_inf_nan=False)
    net_new_revenue: Decimal = Field(allow_inf_nan=False)

    @field_validator("as_of")
    @classmethod
    def _valid_as_of(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator("net_burn", "net_new_revenue", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_MONEY_QUANTUM, allow_negative=True)


class BurnMultiple(_StrictModel):
    """Net burn per dollar of net new revenue — with a labeled heuristic rating."""

    schema_id: Literal["lightbulb.burn_multiple.v1"] = Field(
        default=BURN_MULTIPLE_SCHEMA,
        alias="schema",
    )
    metric_ref: PortableRef
    as_of: str
    currency: CurrencyCode
    net_burn: Decimal
    net_new_revenue: Decimal
    burn_multiple: Decimal | None = None
    rating: BurnMultipleRating
    reference_quality: Literal["default_heuristic"] = "default_heuristic"
    notes: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=6)
    metric_digest: str = "0" * 64

    @field_validator("as_of")
    @classmethod
    def _valid_as_of(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator("net_burn", "net_new_revenue", "burn_multiple", mode="before")
    @classmethod
    def _decimals(cls, value: Any) -> Decimal | None:
        if value is None:
            return None
        return _decimal(value, allow_negative=True)

    @field_validator("notes", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def compute_burn_multiple(
    inputs: BurnMultipleInput | Mapping[str, Any],
) -> BurnMultiple:
    """Compute the burn multiple and a labeled-heuristic efficiency rating."""

    parsed = (
        inputs
        if isinstance(inputs, BurnMultipleInput)
        else BurnMultipleInput.model_validate(inputs)
    )

    notes: list[str] = []
    multiple: Decimal | None = None
    if parsed.net_burn <= 0:
        rating: BurnMultipleRating = "cash_generating"
        notes.append("net burn is non-positive; the company generated cash this period")
    elif parsed.net_new_revenue <= 0:
        rating = "unknown"
        notes.append(
            "net new revenue is non-positive; burn multiple is undefined (no growth "
            "to divide by) — a burning company that did not grow"
        )
    else:
        multiple = _quantized_multiple(parsed.net_burn / parsed.net_new_revenue)
        rating = "concerning"
        for bound, label in _BURN_BANDS:
            if multiple <= bound:
                rating = label
                break
        notes.append("rating is a heuristic band, not an industry benchmark")

    metric = BurnMultiple(
        metric_ref=parsed.metric_ref,
        as_of=parsed.as_of,
        currency=parsed.currency,
        net_burn=parsed.net_burn,
        net_new_revenue=parsed.net_new_revenue,
        burn_multiple=multiple,
        rating=rating,
        notes=tuple(dict.fromkeys(notes))[:6],
    )
    digest = _stable_digest(metric.model_dump(mode="json", exclude={"metric_digest"}))
    return metric.model_copy(update={"metric_digest": digest})


# ---------------------------------------------------------------------------
# Executable primitives
# ---------------------------------------------------------------------------


class AssessDefaultAlivePrimitive(
    BusinessProcessPrimitive[DefaultAliveInput, DefaultAliveAssessment]
):
    """Default alive or default dead, under stated growth assumptions."""

    primitive_ref = "accounting.assess_default_alive"
    version = "1.0.0"
    title = "Assess default alive vs default dead"
    description = (
        "Project revenue and costs forward at the caller's stated monthly growth "
        "rates and decide whether the company reaches breakeven before cash runs "
        "out (default alive) or not (default dead) — or is already profitable. "
        "Reports months to breakeven, the naive runway, and the lowest projected "
        "cash. It is a scenario calculator, not a forecast: the verdict is "
        "conditional on the assumptions, which it echoes; change them and it changes."
    )
    input_model = DefaultAliveInput
    output_model = DefaultAliveAssessment
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs = {
        "assessment_ref": "default-alive-example",
        "as_of": "2026-08-02T00:00:00Z",
        "currency": "USD",
        "cash_on_hand": "600000.00",
        "monthly_revenue": "40000.00",
        "monthly_costs": "70000.00",
        "monthly_revenue_growth_rate": "0.15",
        "monthly_cost_growth_rate": "0.03",
        "horizon_months": 60,
    }

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: DefaultAliveInput,
    ) -> PrimitiveExecutionResult[DefaultAliveAssessment]:
        try:
            assessment = assess_default_alive(inputs)
        except ValueError as exc:
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.FAILED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary=f"default-alive assessment rejected: {exc}",
                output=None,
            )
        return PrimitiveExecutionResult[DefaultAliveAssessment](
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                f"{assessment.assessment_ref}: {assessment.verdict}"
                + (
                    f" (breakeven ~{assessment.months_to_breakeven} mo)"
                    if assessment.months_to_breakeven
                    else ""
                )
            ),
            output=assessment,
            events=[
                PrimitiveEvent(
                    type="accounting.default_alive_assessed",
                    payload={
                        "assessment_ref": assessment.assessment_ref,
                        "verdict": assessment.verdict,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="deterministic_plan",
                    summary="Scenario under stated growth assumptions, not a forecast.",
                )
            ],
        )


class ComputeBurnMultiplePrimitive(
    BusinessProcessPrimitive[BurnMultipleInput, BurnMultiple]
):
    """Net burn per dollar of net new revenue, with a labeled rating."""

    primitive_ref = "accounting.compute_burn_multiple"
    version = "1.0.0"
    title = "Compute the burn multiple"
    description = (
        "Compute the burn multiple — net burn divided by net new revenue for the "
        "period — the capital-efficiency metric investors judge growth by, with a "
        "labeled-heuristic rating (excellent / great / ok / concerning). Handles "
        "the honest edge cases: cash-generating when burn is non-positive, and "
        "undefined when there was no net new revenue to divide by. The rating is "
        "a heuristic band, not an industry benchmark."
    )
    input_model = BurnMultipleInput
    output_model = BurnMultiple
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs = {
        "metric_ref": "burn-multiple-example",
        "as_of": "2026-08-02T00:00:00Z",
        "currency": "USD",
        "net_burn": "120000.00",
        "net_new_revenue": "90000.00",
    }

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: BurnMultipleInput,
    ) -> PrimitiveExecutionResult[BurnMultiple]:
        try:
            metric = compute_burn_multiple(inputs)
        except ValueError as exc:
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.FAILED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary=f"burn multiple rejected: {exc}",
                output=None,
            )
        return PrimitiveExecutionResult[BurnMultiple](
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                f"{metric.metric_ref}: burn multiple "
                + (str(metric.burn_multiple) if metric.burn_multiple is not None else "n/a")
                + f" ({metric.rating})"
            ),
            output=metric,
            events=[
                PrimitiveEvent(
                    type="accounting.burn_multiple_computed",
                    payload={"metric_ref": metric.metric_ref, "rating": metric.rating},
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="deterministic_plan",
                    summary="Heuristic rating band, not an industry benchmark.",
                )
            ],
        )


__all__ = [
    "BURN_MULTIPLE_SCHEMA",
    "DEFAULT_ALIVE_ASSESSMENT_SCHEMA",
    "AssessDefaultAlivePrimitive",
    "BurnMultiple",
    "BurnMultipleInput",
    "BurnMultipleRating",
    "ComputeBurnMultiplePrimitive",
    "DefaultAliveAssessment",
    "DefaultAliveInput",
    "DefaultAliveVerdict",
    "FundraiseReadinessError",
    "assess_default_alive",
    "compute_burn_multiple",
]
