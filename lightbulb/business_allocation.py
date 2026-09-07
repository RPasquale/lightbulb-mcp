"""Business allocation: where the runway floor governs growth ambition.

The growth engine tells you what closing a gap is *worth*; the cash engine
tells you what you can *afford*. Left unconnected, an agent will happily
approve a paid growth push that shortens the runway past the wall. This module
is the seam that stops that: it takes a sealed growth-objective assessment and
a cash budget envelope and returns one honest funding gate — whether paid
growth is permitted at all, and how much discretionary cash may be deployed
toward the objective without breaching the runway floor.

The single load-bearing rule: **a runway below its floor overrides the growth
objective.** No matter how attractive the contribution gap, when the envelope
reports below-floor (or unknown) runway the gate refuses paid growth and points
at the zero-cost levers (price, cost) instead. Survival outranks growth, by
construction.

Design rules:

- **Spend capacity is not a contribution promise.** The gate reports the
  monthly contribution gap and the deployable spend capacity as two separate,
  honestly-labeled facts. It never multiplies a spend by an invented
  return-on-spend to claim the gap is "funded" — that number is the operator's
  to estimate, not this module's to guess.
- **Unknown is unknown.** An unknown-runway envelope yields an ``unknown`` gate,
  not a permissive default. The objective's own completeness flows through.
- **The floor is law.** Below floor -> defer; at floor -> hold (zero new burn);
  only a surplus or a cash-generating business permits deployment.
- **Bound to its inputs.** The gate pins both the assessment digest and the
  runway digest, so it cannot be quietly re-associated with different numbers.

This module depends on both leaf engines (``cash_runway`` and
``growth_objectives``); neither depends on it. It holds no keyring and does no
I/O — the gate is a deterministic decision, deliberately unsealed (no module
enforces it, so a seal would manufacture the appearance of governance).
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
    model_validator,
)

from .cash_runway import CashBudgetEnvelope
from .growth_objectives import ObjectiveAssessment
from .primitive_runtime import (
    BusinessProcessPrimitive,
    PrimitiveEvent,
    PrimitiveEvidence,
    PrimitiveExecutionContext,
    PrimitiveExecutionResult,
    PrimitiveExecutionStatus,
)

OBJECTIVE_FUNDING_GATE_SCHEMA = "lightbulb.objective_funding_gate.v1"

_MONEY_QUANTUM = Decimal("0.01")
_RATE_QUANTUM = Decimal("0.000001")
_DAYS_PER_MONTH = Decimal("30.4375")

_PORTABLE_REF_PATTERN = r"^[a-z][a-z0-9_-]{0,63}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_CURRENCY_PATTERN = r"^[A-Z]{3}$"

FundingGateVerdict = Literal[
    "deploy_permitted",
    "hold_at_floor",
    "defer_protect_runway",
    "unknown",
]


class BusinessAllocationValidationError(ValueError):
    """Inputs cannot produce an honest funding gate."""


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
Sha256Digest = Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)]
CurrencyCode = Annotated[str, StringConstraints(pattern=_CURRENCY_PATTERN)]


def _parse_timestamp(value: str) -> datetime:
    clean = value.strip()
    try:
        parsed = datetime.fromisoformat(clean.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamp must be valid ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def _normalized_timestamp(value: str) -> str:
    return _parse_timestamp(value).isoformat().replace("+00:00", "Z")


def _decimal(value: Any, *, quantum: Decimal | None = None) -> Decimal:
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
    if quantum is not None:
        try:
            normalized = parsed.quantize(quantum)
        except InvalidOperation as exc:
            # e.g. a huge exponent overflows the quantize; surface as ValueError
            # so it is caught by the same handlers as every other bad input.
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


class FundingGatePolicy(_StrictModel):
    """How much of the envelope's capacity may be aimed at growth.

    Heuristic, deliberately unsealed. ``deploy_fraction`` reserves part of the
    discretionary capacity for non-growth needs (hiring, inventory); the
    default deploys all of it toward the objective.
    """

    deploy_fraction: Decimal = Field(
        default=Decimal("1.000000"), gt=0, le=Decimal("1"), multiple_of=_RATE_QUANTUM
    )

    @field_validator("deploy_fraction", mode="before")
    @classmethod
    def _rate_decimal(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_RATE_QUANTUM)


class ObjectiveFundingGate(_StrictModel):
    """One deterministic answer to 'may we spend to chase this objective?'."""

    schema_id: Literal["lightbulb.objective_funding_gate.v1"] = Field(
        default=OBJECTIVE_FUNDING_GATE_SCHEMA,
        alias="schema",
    )
    gate_ref: PortableRef
    as_of: str
    currency: CurrencyCode
    objective_ref: PortableRef
    objective_verdict: Literal[
        "on_track", "at_risk", "off_track", "achieved", "expired_missed"
    ]
    assessment_digest: Sha256Digest
    runway_digest: Sha256Digest
    runway_status: Literal["burning", "not_burning", "unknown"]
    verdict: FundingGateVerdict
    zero_cost_levers_only: bool
    monthly_contribution_gap: Decimal = Field(ge=0, multiple_of=_MONEY_QUANTUM)
    current_runway_months: Decimal | None = None
    runway_floor_months: Decimal = Field(gt=0)
    deployable_monthly: Decimal | None = None
    deployable_one_time: Decimal | None = None
    rationale: ShortText
    notes: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=10)
    gate_digest: Sha256Digest = "0" * 64

    @field_validator("as_of")
    @classmethod
    def _valid_as_of(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator("monthly_contribution_gap", mode="before")
    @classmethod
    def _money_decimal(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_MONEY_QUANTUM)

    @field_validator("runway_floor_months", mode="before")
    @classmethod
    def _floor_decimal(cls, value: Any) -> Decimal:
        return _decimal(value)

    @field_validator(
        "current_runway_months",
        "deployable_monthly",
        "deployable_one_time",
        mode="before",
    )
    @classmethod
    def _optional_decimal(cls, value: Any) -> Decimal | None:
        if value is None:
            return None
        return _decimal(value)

    @field_validator("notes", mode="before")
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _coherent(self) -> "ObjectiveFundingGate":
        if self.zero_cost_levers_only and self.verdict == "deploy_permitted":
            raise ValueError("deploy_permitted cannot also be zero-cost-levers-only")
        return self


class GateObjectiveFundingInput(_StrictModel):
    gate_ref: PortableRef
    as_of: str
    objective_assessment: ObjectiveAssessment
    budget_envelope: CashBudgetEnvelope
    policy: FundingGatePolicy = Field(default_factory=FundingGatePolicy)

    @field_validator("as_of")
    @classmethod
    def _valid_as_of(cls, value: str) -> str:
        return _normalized_timestamp(value)


def gate_objective_funding(
    inputs: GateObjectiveFundingInput | Mapping[str, Any],
) -> ObjectiveFundingGate:
    """Decide whether — and how much — paid growth the runway floor allows."""

    parsed = (
        inputs
        if isinstance(inputs, GateObjectiveFundingInput)
        else GateObjectiveFundingInput.model_validate(inputs)
    )
    assessment = parsed.objective_assessment
    envelope = parsed.budget_envelope

    if assessment.currency != envelope.currency:
        raise BusinessAllocationValidationError(
            "objective and budget must share a currency; got "
            f"{assessment.currency} and {envelope.currency}"
        )

    # Normalize the objective's per-period contribution gap to a monthly figure
    # so it reads on the same clock as the envelope's monthly capacity.
    monthly_gap = _quantized_money(
        assessment.remaining_gap_per_period
        * (_DAYS_PER_MONTH / Decimal(assessment.period_days))
    )

    notes: list[str] = []
    deploy_fraction = parsed.policy.deploy_fraction
    deployable_monthly: Decimal | None = None
    deployable_one_time: Decimal | None = None

    status = envelope.status
    if status in ("unknown",):
        verdict: FundingGateVerdict = "unknown"
        # Cannot measure runway -> cannot justify paid spend; restrict to
        # zero-cost levers, same conservatism as below/at floor.
        zero_cost_only = True
        rationale = "runway is unknown; measure cash before committing paid growth"
        notes.append("connect a cash source so the floor can govern spend")
    elif status == "below_floor":
        verdict = "defer_protect_runway"
        zero_cost_only = True
        rationale = (
            "runway is below its floor; defer paid growth and protect runway first"
        )
        notes.append("pursue zero-cost levers (price, cost) until runway is restored")
    elif status == "at_floor":
        verdict = "hold_at_floor"
        zero_cost_only = True
        rationale = "runway sits exactly at the floor; hold — no new burn"
        notes.append("only zero-cost levers keep runway from dropping below the floor")
    else:
        # not_burning or healthy_surplus: deployment is permitted.
        verdict = "deploy_permitted"
        zero_cost_only = False
        one_time = envelope.one_time_discretionary_capacity
        if one_time is not None and one_time > 0:
            deployable_one_time = _quantized_money(one_time * deploy_fraction)
        incremental = envelope.affordable_incremental_monthly_burn
        if incremental is not None and incremental > 0:
            deployable_monthly = _quantized_money(incremental * deploy_fraction)
        if status == "not_burning":
            rationale = (
                "cash flow is non-negative; paid growth is permitted within the "
                "discretionary capacity"
            )
        else:
            rationale = (
                "runway clears the floor; the surplus is deployable toward the "
                "objective"
            )

    # Cross-reference the objective's own verdict for a decision-useful note.
    if assessment.verdict in ("off_track", "at_risk"):
        if zero_cost_only:
            notes.append(
                "objective is at risk but runway comes first; lean on non-cash levers"
            )
        elif verdict == "deploy_permitted":
            notes.append(
                "objective is at risk and runway has room; investing to close the gap "
                "is affordable"
            )
    elif assessment.verdict == "achieved":
        notes.append("objective already achieved; deployment is optional, not needed")

    if not assessment.complete:
        notes.append("objective assessment is incomplete; the gap may be understated")
    if not envelope.complete and status not in ("unknown",):
        notes.append("budget envelope is incomplete; treat capacity as a soft ceiling")
    # Spend capacity is not a contribution promise — say so whenever we deploy.
    if verdict == "deploy_permitted":
        notes.append(
            "deployable is spend capacity, not a guaranteed contribution gain"
        )

    gate = ObjectiveFundingGate(
        gate_ref=parsed.gate_ref,
        as_of=parsed.as_of,
        currency=assessment.currency,
        objective_ref=assessment.objective_ref,
        objective_verdict=assessment.verdict,
        assessment_digest=assessment.assessment_digest,
        runway_digest=envelope.runway_digest,
        runway_status=status if status in ("burning", "not_burning") else (
            "unknown" if status == "unknown" else "burning"
        ),
        verdict=verdict,
        zero_cost_levers_only=zero_cost_only,
        monthly_contribution_gap=monthly_gap,
        current_runway_months=envelope.current_runway_months,
        runway_floor_months=envelope.runway_floor_months,
        deployable_monthly=deployable_monthly,
        deployable_one_time=deployable_one_time,
        rationale=_bounded_text(rationale)[:300],
        notes=tuple(dict.fromkeys(notes))[:10],
    )
    digest = _stable_digest(gate.model_dump(mode="json", exclude={"gate_digest"}))
    return gate.model_copy(update={"gate_digest": digest})


# ---------------------------------------------------------------------------
# Executable primitive
# ---------------------------------------------------------------------------


def _build_example() -> dict[str, Any]:
    from .cash_runway import build_runway_snapshot, derive_budget_envelope
    from .growth_objectives import (
        GrowthObjective,
        assess_objective_progress,
    )
    from .growth_profit import build_unit_economics

    economics = build_unit_economics(
        {
            "analysis_as_of": "2026-08-19T00:00:00Z",
            "economics_ref": "econ-gate-example",
            "currency": "USD",
            "evidence": (
                {
                    "observation_ref": "shopify-gate-example",
                    "connector_account_ref": "acct.shopify.example",
                    "provider": "shopify",
                    "source_capability": "shopify.analytics_query",
                    "currency": "USD",
                    "observed_at": "2026-08-18T00:00:00Z",
                    "window_start": "2026-08-01T00:00:00Z",
                    "window_end": "2026-08-15T00:00:00Z",
                    "metrics": {
                        "gross_sales": "12000.00",
                        "discounts": "600.00",
                        "cogs": "4800.00",
                        "orders": 300,
                    },
                    "evidence_digest": "6" * 64,
                },
            ),
        }
    )
    objective = GrowthObjective.model_validate(
        {
            "objective_ref": "q3-contribution",
            "metric": "contribution_profit",
            "currency": "USD",
            "period_days": 30,
            "baseline_per_period": "10178.57",
            "target_per_period": "14000.00",
            "baseline_economics_digest": economics.economics_digest,
            "baseline_economics_as_of": "2026-08-19T00:00:00Z",
            "baseline_window_days": "14.000000",
            "baseline_complete": True,
            "committed_at": "2026-08-19T00:00:00Z",
            "target_by": "2026-11-17T00:00:00Z",
            "rationale": "Reach 14k monthly contribution before the holiday buy.",
        }
    )
    assessment = assess_objective_progress(
        {
            "as_of": "2026-09-18T00:00:00Z",
            "objective": objective,
            "current_economics": economics,
        }
    )
    snapshot = build_runway_snapshot(
        {
            "analysis_as_of": "2026-09-18T00:00:00Z",
            "runway_ref": "biz-runway-gate-example",
            "currency": "USD",
            "evidence": (
                {
                    "observation_ref": "bank-gate-example",
                    "connector_account_ref": "acct.bank.operating",
                    "provider": "bank",
                    "source_capability": "bank.statement_import",
                    "currency": "USD",
                    "observed_at": "2026-09-18T00:00:00Z",
                    "window_start": "2026-08-18T00:00:00Z",
                    "window_end": "2026-09-18T00:00:00Z",
                    "metrics": {
                        "cash_inflows": "30000.00",
                        "cash_outflows": "60000.00",
                        "ending_cash_balance": "600000.00",
                    },
                    "evidence_digest": "c" * 64,
                },
            ),
        }
    )
    envelope = derive_budget_envelope(
        {
            "envelope_ref": "biz-budget-gate-example",
            "analysis_as_of": "2026-09-18T00:00:00Z",
            "runway_snapshot": snapshot,
            "runway_floor_months": "12",
        }
    )
    return {
        "gate_ref": "q3-funding-gate-example",
        "as_of": "2026-09-18T00:00:00Z",
        "objective_assessment": assessment.model_dump(mode="json", by_alias=True),
        "budget_envelope": envelope.model_dump(mode="json", by_alias=True, exclude_none=True),
    }


_EXAMPLE_GATE_INPUT: dict[str, Any] = _build_example()


class GateObjectiveFundingPrimitive(
    BusinessProcessPrimitive[GateObjectiveFundingInput, ObjectiveFundingGate]
):
    """Let the runway floor govern whether paid growth is affordable."""

    primitive_ref = "business.gate_objective_funding"
    version = "1.0.0"
    title = "Gate objective funding on runway"
    description = (
        "Cross the growth objective with the cash budget envelope and decide "
        "whether paid growth is permitted: deploy when runway clears the floor "
        "(reporting the deployable monthly and one-time capacity), hold at the "
        "floor, or defer and protect runway when below it — survival outranks "
        "growth by construction. Reports the monthly contribution gap and the "
        "deployable spend as separate facts; deployable is spend capacity, "
        "never a promised contribution gain. Binds the assessment and runway "
        "digests."
    )
    input_model = GateObjectiveFundingInput
    output_model = ObjectiveFundingGate
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs = _EXAMPLE_GATE_INPUT

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: GateObjectiveFundingInput,
    ) -> PrimitiveExecutionResult[ObjectiveFundingGate]:
        try:
            gate = gate_objective_funding(inputs)
        except ValueError as exc:
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.FAILED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary=f"funding gate rejected: {exc}",
                output=None,
            )
        return PrimitiveExecutionResult[ObjectiveFundingGate](
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                f"Funding gate {gate.gate_ref}: {gate.verdict} "
                f"(objective {gate.objective_verdict}, runway {gate.runway_status})."
            ),
            output=gate,
            events=[
                PrimitiveEvent(
                    type="business.objective_funding_gated",
                    payload={"gate_ref": gate.gate_ref, "verdict": gate.verdict},
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="deterministic_plan",
                    summary="Gate bound to assessment "
                    + gate.assessment_digest[:16]
                    + "… and runway "
                    + gate.runway_digest[:16]
                    + "…",
                )
            ],
        )


__all__ = [
    "OBJECTIVE_FUNDING_GATE_SCHEMA",
    "BusinessAllocationValidationError",
    "FundingGatePolicy",
    "FundingGateVerdict",
    "GateObjectiveFundingInput",
    "GateObjectiveFundingPrimitive",
    "ObjectiveFundingGate",
    "gate_objective_funding",
]
