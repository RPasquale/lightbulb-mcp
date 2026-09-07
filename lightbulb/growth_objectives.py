"""Growth objectives: the sealed target the whole engine drives toward.

A maximization machine needs an objective function. The Growth Engine
measures demand, prices opportunities in contribution dollars, preregisters
experiments, banks learnings, and conducts the weekly loop — this module
gives all of that a *destination*: a cryptographically committed target
("reach this contribution profit per period by this date") plus an honest,
re-derivable answer to the operator's governing question: **are we on
track, and if not, what funds the gap?**

The engine's strongest idea, applied to goals: **the seal is the
commitment.** A :class:`GrowthObjective` is HMAC-sealed at commit time with
its baseline derived from a VERIFIED unit-economics snapshot — never
caller-typed — so the starting line and the target cannot quietly move.
Changing the target is a new objective that names what it supersedes,
exactly like preregistration.

Honesty rules specific to this module:

- **The glide path is an assumption, not a truth.** Progress verdicts
  compare the observed contribution run-rate against a *linear* path from
  baseline to target; every assessment says so, and the at-risk tolerance
  is a caller policy knob labeled heuristic.
- **Funded is not achieved.** Gap decomposition sums the dollar-priced,
  non-blocked opportunities from the profit and customer-value reviews as
  a conservative scenario range (sum of lows .. sum of highs). It reports
  how much of the remaining gap those opportunities *could* fund — never
  that they will.
- **Run-rates are window-normalized.** Contribution is observed over an
  evidence window; the assessment normalizes by that window's actual span
  and refuses windows it cannot measure.
- **Advice stays advice.** Assessments are digest-pinned re-derivable
  artifacts (the GrowthDiagnosis custody class); only the objective itself
  carries a seal, because only the commitment is authority.

Naming note: ``lightbulb/growth_primitives.py`` predates the Growth Engine
and holds unrelated catalog primitives; the Growth Engine lives in the
``growth_funnel`` … ``growth_objectives`` module family.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping
from datetime import datetime, timezone
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from typing import Annotated, Any, Literal, Protocol

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from .dynamic_workflows import DynamicWorkflowScope
from .growth_customers import CustomerValueReview
from .growth_profit import (
    ProfitReview,
    UnitEconomicsSnapshot,
    build_unit_economics,
    verify_unit_economics_snapshot,
)
from .primitive_runtime import (
    BusinessProcessPrimitive,
    PrimitiveBlocker,
    PrimitiveEvent,
    PrimitiveEvidence,
    PrimitiveExecutionContext,
    PrimitiveExecutionResult,
    PrimitiveExecutionStatus,
)

GROWTH_OBJECTIVE_SCHEMA = "lightbulb.growth_objective.v1"
GROWTH_OBJECTIVE_ASSESSMENT_SCHEMA = "lightbulb.growth_objective_assessment.v1"

_OBJECTIVE_HMAC_DOMAIN = GROWTH_OBJECTIVE_SCHEMA

_RATE_QUANTUM = Decimal("0.000001")
_MONEY_QUANTUM = Decimal("0.01")

_PORTABLE_REF_PATTERN = r"^[a-z][a-z0-9_-]{0,63}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_CURRENCY_PATTERN = r"^[A-Z]{3}$"

ObjectiveMetric = Literal["contribution_profit"]
ObjectiveVerdict = Literal[
    "on_track",
    "at_risk",
    "off_track",
    "achieved",
    "expired_missed",
]


class GrowthObjectivesValidationError(ValueError):
    """Objective or assessment content violates the commitment contract."""


def _stable_digest(value: Any) -> str:
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
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
LongText = Annotated[
    str,
    StringConstraints(min_length=1, max_length=10_000),
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


def _quantized_ratio(value: Decimal) -> Decimal:
    return value.quantize(_RATE_QUANTUM, rounding=ROUND_HALF_UP)


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=False,
        serialize_by_alias=True,
        strict=True,
    )


class ExactScopeDigestProvider(Protocol):
    """Host-held keyed scope digester; raw authority never enters artifacts."""

    active_key_id: str

    def exact_scope_digest(
        self,
        *,
        key_id: str,
        scope: DynamicWorkflowScope,
    ) -> str: ...

    def sign(self, key_id: str, domain: str, payload: Any) -> bytes: ...


def _keyring_signature(
    scope_keyring: ExactScopeDigestProvider,
    *,
    key_id: str,
    domain: str,
    payload: Any,
) -> str:
    try:
        return scope_keyring.sign(key_id, domain, payload).hex()
    except GrowthObjectivesValidationError:
        raise
    except Exception as exc:
        raise GrowthObjectivesValidationError(
            "the objectives signing key is unavailable"
        ) from exc


def _keyring_scope_digest(
    scope_keyring: ExactScopeDigestProvider,
    *,
    key_id: str,
    scope: DynamicWorkflowScope,
) -> str:
    try:
        return scope_keyring.exact_scope_digest(key_id=key_id, scope=scope)
    except GrowthObjectivesValidationError:
        raise
    except Exception as exc:
        raise GrowthObjectivesValidationError(
            "the objectives signing key is unavailable"
        ) from exc


def _workflow_scope(
    scope: DynamicWorkflowScope | Mapping[str, Any],
) -> DynamicWorkflowScope:
    if isinstance(scope, DynamicWorkflowScope):
        return scope
    return DynamicWorkflowScope.model_validate(scope)


def _economics_run_rate(
    economics: UnitEconomicsSnapshot,
    period_days: int,
) -> tuple[Decimal, Decimal, bool, tuple[str, ...], datetime]:
    """(run_rate, window_days, complete, missing, span_end) from a snapshot.

    Contribution is observed over the snapshot's admitted evidence windows;
    the run-rate normalizes it to the objective's period length using the
    UNION of covered time. Windows that leave holes are refused outright:
    a hull with gaps would silently deflate the rate (a 5x sealed-baseline
    gaming vector) and a union over discontiguous time would silently
    inflate it — neither is a number this module will sign its name to.
    """

    contribution = economics.component("contribution_profit")
    if contribution is None:
        raise GrowthObjectivesValidationError(
            "the economics snapshot carries no contribution_profit component; "
            "supply ledger evidence covering revenue and variable costs"
        )
    windows = sorted(
        (
            _parse_timestamp(evidence.window_start),
            _parse_timestamp(evidence.window_end),
        )
        for evidence in economics.admitted_evidence
    )
    if not windows:
        raise GrowthObjectivesValidationError(
            "the economics snapshot admitted no evidence; a run-rate needs a "
            "measured window"
        )
    merged: list[tuple[datetime, datetime]] = []
    for start, end in windows:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    if len(merged) > 1:
        raise GrowthObjectivesValidationError(
            "the economics snapshot's evidence windows leave gaps; a "
            "run-rate cannot be honestly normalized over uncovered time — "
            "supply contiguous windows"
        )
    span_start, span_end = merged[0]
    span_seconds = (span_end - span_start).total_seconds()
    if span_seconds <= 0:
        raise GrowthObjectivesValidationError(
            "the economics snapshot's evidence span is zero-width; a run-rate "
            "cannot be normalized from it"
        )
    window_days = Decimal(str(span_seconds / 86_400))
    run_rate = _quantized_money(
        contribution.value * Decimal(period_days) / window_days
    )
    return (
        run_rate,
        _quantized_ratio(window_days),
        contribution.complete,
        contribution.missing_inputs,
        span_end,
    )


# ---------------------------------------------------------------------------
# The sealed objective
# ---------------------------------------------------------------------------


class GrowthObjective(_StrictModel):
    """A sealed growth commitment. The HMAC is what makes it binding."""

    schema_id: Literal["lightbulb.growth_objective.v1"] = Field(
        default=GROWTH_OBJECTIVE_SCHEMA,
        alias="schema",
    )
    objective_ref: PortableRef
    metric: ObjectiveMetric
    currency: CurrencyCode
    period_days: int = Field(ge=7, le=365)
    baseline_per_period: Decimal = Field(multiple_of=_MONEY_QUANTUM)
    target_per_period: Decimal = Field(gt=0, multiple_of=_MONEY_QUANTUM)
    baseline_economics_digest: Sha256Digest
    baseline_economics_as_of: str
    baseline_window_days: Decimal = Field(gt=0, multiple_of=_RATE_QUANTUM)
    baseline_complete: bool
    committed_at: str
    target_by: str
    rationale: LongText
    supersedes: Sha256Digest | None = None
    objective_digest: Sha256Digest = "0" * 64
    receipt_key_id: str | None = Field(
        default=None,
        min_length=8,
        max_length=80,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{7,79}$",
    )
    exact_scope_digest: Sha256Digest | None = None
    objective_hmac: Sha256Digest | None = None

    @field_validator("baseline_per_period", "target_per_period", mode="before")
    @classmethod
    def _money_decimals(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_MONEY_QUANTUM)

    @field_validator("baseline_window_days", mode="before")
    @classmethod
    def _window_decimal(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_RATE_QUANTUM)

    @field_validator("committed_at", "target_by", "baseline_economics_as_of")
    @classmethod
    def _valid_timestamps(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @model_validator(mode="after")
    def _commitment_shape(self) -> "GrowthObjective":
        if _parse_timestamp(self.target_by) <= _parse_timestamp(self.committed_at):
            raise ValueError("target_by must follow committed_at")
        if self.target_per_period <= self.baseline_per_period:
            raise ValueError(
                "a growth objective must target more than its baseline; a "
                "hold-steady or decline target is not a growth commitment"
            )
        binding_fields = (
            self.receipt_key_id,
            self.exact_scope_digest,
            self.objective_hmac,
        )
        if any(value is not None for value in binding_fields) and not all(
            value is not None for value in binding_fields
        ):
            raise ValueError(
                "objective attestation fields must be supplied together"
            )
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"objective_digest", "objective_hmac"},
            exclude_none=True,
        )
        expected = _stable_digest(payload)
        if self.objective_digest != "0" * 64 and self.objective_digest != expected:
            raise ValueError("objective_digest does not match the canonical payload")
        object.__setattr__(self, "objective_digest", expected)
        return self

    @property
    def is_sealed(self) -> bool:
        return self.objective_hmac is not None

    def hmac_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"objective_hmac", "objective_digest"},
            exclude_none=True,
        )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


class CommitGrowthObjectiveInput(_StrictModel):
    objective_ref: PortableRef
    target_per_period: Decimal = Field(gt=0, multiple_of=_MONEY_QUANTUM)
    period_days: int = Field(default=30, ge=7, le=365)
    committed_at: str
    target_by: str
    rationale: LongText
    baseline_economics: UnitEconomicsSnapshot
    supersedes: Sha256Digest | None = None

    @field_validator("target_per_period", mode="before")
    @classmethod
    def _money_decimal(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_MONEY_QUANTUM)

    @field_validator("committed_at", "target_by")
    @classmethod
    def _valid_timestamps(cls, value: str) -> str:
        return _normalized_timestamp(value)


def commit_growth_objective(
    inputs: CommitGrowthObjectiveInput | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ExactScopeDigestProvider,
    scope_key_id: str | None = None,
) -> GrowthObjective:
    """Seal a growth commitment; the baseline comes from verified economics.

    The baseline run-rate is DERIVED from a verified
    :class:`UnitEconomicsSnapshot` at commit time and pinned by digest —
    a caller cannot type a flattering starting line. The seal is the
    commitment: any later change of target is a new objective naming
    ``supersedes``.
    """

    parsed = (
        inputs
        if isinstance(inputs, CommitGrowthObjectiveInput)
        else CommitGrowthObjectiveInput.model_validate(inputs)
    )
    workflow_scope = _workflow_scope(scope)
    economics = verify_unit_economics_snapshot(
        parsed.baseline_economics, scope=workflow_scope, scope_keyring=scope_keyring
    )
    baseline, window_days, complete, _, _ = _economics_run_rate(
        economics, parsed.period_days
    )
    if _parse_timestamp(economics.analysis_as_of) > _parse_timestamp(
        parsed.committed_at
    ):
        raise GrowthObjectivesValidationError(
            "the baseline economics are from the future of the commitment"
        )
    key_id = scope_key_id or str(scope_keyring.active_key_id).strip()
    exact_scope_digest = _keyring_scope_digest(
        scope_keyring, key_id=key_id, scope=workflow_scope
    )
    draft = GrowthObjective.model_validate(
        {
            "objective_ref": parsed.objective_ref,
            "metric": "contribution_profit",
            "currency": economics.currency,
            "period_days": parsed.period_days,
            "baseline_per_period": baseline,
            "target_per_period": parsed.target_per_period,
            "baseline_economics_digest": economics.economics_digest,
            "baseline_economics_as_of": economics.analysis_as_of,
            "baseline_window_days": window_days,
            "baseline_complete": complete,
            "committed_at": parsed.committed_at,
            "target_by": parsed.target_by,
            "rationale": parsed.rationale,
            **(
                {"supersedes": parsed.supersedes}
                if parsed.supersedes is not None
                else {}
            ),
            "receipt_key_id": key_id,
            "exact_scope_digest": exact_scope_digest,
            "objective_hmac": "0" * 64,
        }
    )
    signature = _keyring_signature(
        scope_keyring,
        key_id=key_id,
        domain=_OBJECTIVE_HMAC_DOMAIN,
        payload=draft.hmac_payload(),
    )
    sealed = draft.model_dump(
        mode="python",
        by_alias=True,
        exclude={"objective_digest"},
        exclude_none=True,
    )
    sealed["objective_hmac"] = signature
    return GrowthObjective.model_validate(sealed)


def verify_growth_objective(
    value: GrowthObjective | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ExactScopeDigestProvider,
) -> GrowthObjective:
    """Re-validate and verify one sealed objective; raise on failure."""

    objective = GrowthObjective.model_validate(
        value.model_dump(mode="python", by_alias=True, exclude_none=True)
        if isinstance(value, GrowthObjective)
        else value
    )
    if (
        objective.receipt_key_id is None
        or objective.exact_scope_digest is None
        or objective.objective_hmac is None
    ):
        raise GrowthObjectivesValidationError(
            "the objective carries no commitment seal"
        )
    workflow_scope = _workflow_scope(scope)
    expected_scope_digest = _keyring_scope_digest(
        scope_keyring,
        key_id=objective.receipt_key_id,
        scope=workflow_scope,
    )
    if not hmac.compare_digest(objective.exact_scope_digest, expected_scope_digest):
        raise GrowthObjectivesValidationError(
            "objective attestation failed verification"
        )
    expected_hmac = _keyring_signature(
        scope_keyring,
        key_id=objective.receipt_key_id,
        domain=_OBJECTIVE_HMAC_DOMAIN,
        payload=objective.hmac_payload(),
    )
    if not hmac.compare_digest(objective.objective_hmac, expected_hmac):
        raise GrowthObjectivesValidationError(
            "objective attestation failed verification"
        )
    return objective


# ---------------------------------------------------------------------------
# Assessment (advisory)
# ---------------------------------------------------------------------------


class ObjectivePolicy(_StrictModel):
    """Assessment tolerances. Heuristics, not truths; deliberately unsealed."""

    at_risk_shortfall_ratio: Decimal = Field(
        default=Decimal("0.100000"),
        gt=0,
        le=Decimal("0.5"),
        multiple_of=_RATE_QUANTUM,
    )

    @field_validator("at_risk_shortfall_ratio", mode="before")
    @classmethod
    def _rate_decimal(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_RATE_QUANTUM)


class AssessObjectiveInput(_StrictModel):
    as_of: str
    objective: GrowthObjective
    current_economics: UnitEconomicsSnapshot
    profit_review: ProfitReview | None = None
    customer_value_review: CustomerValueReview | None = None
    policy: ObjectivePolicy = Field(default_factory=ObjectivePolicy)

    @field_validator("as_of")
    @classmethod
    def _valid_as_of(cls, value: str) -> str:
        return _normalized_timestamp(value)


class GapFunding(_StrictModel):
    """What the reviews' opportunities could fund, per period. Not a plan.

    Only opportunities whose money is measured over the SAME economics
    window as the observed run-rate are summed (price moves, cost leaks);
    their deltas are normalized to the objective's period. Opportunities on
    other time bases (funnel-window experiment closes, LTV-horizon ceiling
    moves) are counted in ``excluded_incomparable`` and named in the
    assessment notes — listed, never silently summed. The sum assumes
    independent, additive levers; overlapping levers overstate it.
    """

    opportunities_counted: int = Field(ge=0)
    excluded_incomparable: int = Field(ge=0)
    funded_low: Decimal = Field(ge=0, multiple_of=_MONEY_QUANTUM)
    funded_expected: Decimal = Field(ge=0, multiple_of=_MONEY_QUANTUM)
    funded_high: Decimal = Field(ge=0, multiple_of=_MONEY_QUANTUM)
    shortfall_after_expected: Decimal = Field(ge=0, multiple_of=_MONEY_QUANTUM)
    source_digests: tuple[Sha256Digest, ...] = Field(
        default_factory=tuple, max_length=4
    )

    @field_validator(
        "funded_low",
        "funded_expected",
        "funded_high",
        "shortfall_after_expected",
        mode="before",
    )
    @classmethod
    def _money_decimals(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_MONEY_QUANTUM)

    @field_validator("source_digests", mode="before")
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _ordered_range(self) -> "GapFunding":
        if not (self.funded_low <= self.funded_expected <= self.funded_high):
            raise ValueError("funding range must be ordered low <= expected <= high")
        return self


class ObjectiveAssessment(_StrictModel):
    """One deterministic answer to "are we on track, and what funds the gap"."""

    schema_id: Literal["lightbulb.growth_objective_assessment.v1"] = Field(
        default=GROWTH_OBJECTIVE_ASSESSMENT_SCHEMA,
        alias="schema",
    )
    as_of: str
    objective_digest: Sha256Digest
    objective_ref: PortableRef
    currency: CurrencyCode
    evidence_scope_status: Literal[
        "caller_supplied_unverified", "host_hmac_verified"
    ]
    period_days: int = Field(ge=7, le=365)
    baseline_per_period: Decimal = Field(multiple_of=_MONEY_QUANTUM)
    target_per_period: Decimal = Field(gt=0, multiple_of=_MONEY_QUANTUM)
    observed_per_period: Decimal = Field(multiple_of=_MONEY_QUANTUM)
    observed_window_days: Decimal = Field(gt=0, multiple_of=_RATE_QUANTUM)
    glide_expected_per_period: Decimal = Field(multiple_of=_MONEY_QUANTUM)
    elapsed_ratio: Decimal = Field(ge=0, multiple_of=_RATE_QUANTUM)
    remaining_gap_per_period: Decimal = Field(ge=0, multiple_of=_MONEY_QUANTUM)
    verdict: ObjectiveVerdict
    complete: bool
    missing_inputs: tuple[ShortText, ...] = Field(default_factory=tuple)
    gap_funding: GapFunding | None = None
    economics_digest: Sha256Digest
    data_quality_notes: tuple[ShortText, ...] = Field(
        default_factory=tuple, max_length=20
    )
    assessment_digest: Sha256Digest = "0" * 64

    @field_validator("as_of")
    @classmethod
    def _valid_as_of(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator(
        "baseline_per_period",
        "target_per_period",
        "observed_per_period",
        "glide_expected_per_period",
        "remaining_gap_per_period",
        mode="before",
    )
    @classmethod
    def _money_decimals(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_MONEY_QUANTUM)

    @field_validator("observed_window_days", "elapsed_ratio", mode="before")
    @classmethod
    def _rate_decimals(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_RATE_QUANTUM)

    @field_validator("missing_inputs", "data_quality_notes", mode="before")
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _pinned_digest(self) -> "ObjectiveAssessment":
        if self.verdict == "achieved" and self.remaining_gap_per_period > 0:
            raise ValueError("an achieved verdict cannot carry a remaining gap")
        if self.complete and self.missing_inputs:
            raise ValueError("complete assessments cannot list missing inputs")
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"assessment_digest"},
            exclude_none=True,
        )
        expected = _stable_digest(payload)
        if self.assessment_digest != "0" * 64 and (
            self.assessment_digest != expected
        ):
            raise ValueError(
                "assessment_digest does not match the canonical payload"
            )
        object.__setattr__(self, "assessment_digest", expected)
        return self

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


# Profit-review opportunity kinds whose money is measured over the SAME
# economics evidence window the run-rate uses, making per-period
# normalization honest. Everything else lives on another time base.
_ECONOMICS_WINDOW_KINDS = frozenset({"plan_price_move", "reduce_cost_leak"})


def _check_review_coherence(
    review: ProfitReview | CustomerValueReview,
    *,
    label: str,
    objective: GrowthObjective,
    economics: UnitEconomicsSnapshot,
    as_of_at: datetime,
) -> None:
    if review.currency != objective.currency:
        raise GrowthObjectivesValidationError(
            f"the {label} carries currency {review.currency} against the "
            f"objective's {objective.currency}; cross-currency funding is "
            "not a thing that can honestly exist"
        )
    if _parse_timestamp(review.as_of) > as_of_at:
        raise GrowthObjectivesValidationError(
            f"the {label} is from the future of the assessment as_of"
        )
    review_economics = getattr(review, "economics_digest", None)
    if (
        review_economics is not None
        and review_economics != economics.economics_digest
    ):
        raise GrowthObjectivesValidationError(
            f"the {label} derives from different unit economics than the "
            "ones being assessed; re-run the review against the current "
            "economics before funding the gap with it"
        )


def _review_funding(
    profit_review: ProfitReview | None,
    customer_value_review: CustomerValueReview | None,
    *,
    objective: GrowthObjective,
    economics: UnitEconomicsSnapshot,
    as_of_at: datetime,
    window_days: Decimal,
) -> GapFunding | None:
    counted = 0
    incomparable = 0
    low = Decimal("0")
    expected = Decimal("0")
    high = Decimal("0")
    sources: list[str] = []
    factor = Decimal(objective.period_days) / window_days
    if profit_review is not None:
        _check_review_coherence(
            profit_review,
            label="profit review",
            objective=objective,
            economics=economics,
            as_of_at=as_of_at,
        )
        sources.append(profit_review.review_digest)
        for opportunity in profit_review.opportunities:
            if opportunity.expected_contribution_delta is None:
                continue
            if opportunity.kind not in _ECONOMICS_WINDOW_KINDS:
                incomparable += 1
                continue
            counted += 1
            low += opportunity.delta_low * factor
            expected += opportunity.expected_contribution_delta * factor
            high += opportunity.delta_high * factor
    if customer_value_review is not None:
        _check_review_coherence(
            customer_value_review,
            label="customer value review",
            objective=objective,
            economics=economics,
            as_of_at=as_of_at,
        )
        sources.append(customer_value_review.review_digest)
        for opportunity in customer_value_review.opportunities:
            if opportunity.expected_contribution_delta is None:
                continue
            # Ceiling moves realize over LTV horizons, not the economics
            # window; they are named, never summed into a per-period figure.
            incomparable += 1
    if not sources:
        return None
    return GapFunding(
        opportunities_counted=counted,
        excluded_incomparable=incomparable,
        funded_low=_quantized_money(low),
        funded_expected=_quantized_money(expected),
        funded_high=_quantized_money(high),
        shortfall_after_expected=Decimal("0.00"),  # recomputed by the caller
        source_digests=tuple(sources),
    )


def assess_objective_progress(
    inputs: AssessObjectiveInput | Mapping[str, Any],
) -> ObjectiveAssessment:
    """Deterministically judge progress against the sealed commitment.

    Pure advice: verification of the objective and economics is the
    caller's job (the workspace host path does it); the assessment echoes
    the LOWER of their trust labels and never upgrades. The glide path is
    linear and labeled; the at-risk band is the caller's policy heuristic;
    gap funding is a conservative scenario sum, never a promise.
    """

    parsed = (
        inputs
        if isinstance(inputs, AssessObjectiveInput)
        else AssessObjectiveInput.model_validate(inputs)
    )
    objective = parsed.objective
    economics = parsed.current_economics
    as_of_at = _parse_timestamp(parsed.as_of)
    committed_at = _parse_timestamp(objective.committed_at)
    target_at = _parse_timestamp(objective.target_by)
    if as_of_at < committed_at:
        raise GrowthObjectivesValidationError(
            "the assessment as_of precedes the commitment"
        )
    if _parse_timestamp(economics.analysis_as_of) > as_of_at:
        raise GrowthObjectivesValidationError(
            "the economics snapshot is from the future of the assessment as_of"
        )
    if economics.currency != objective.currency:
        raise GrowthObjectivesValidationError(
            "the economics currency does not match the objective's currency"
        )

    observed, window_days, complete, missing, span_end = _economics_run_rate(
        economics, objective.period_days
    )

    total_seconds = (target_at - committed_at).total_seconds()
    elapsed_seconds = min((as_of_at - committed_at).total_seconds(), total_seconds)
    elapsed_ratio = _quantized_ratio(
        Decimal(str(elapsed_seconds)) / Decimal(str(total_seconds))
    )
    glide_expected = _quantized_money(
        objective.baseline_per_period
        + (objective.target_per_period - objective.baseline_per_period)
        * elapsed_ratio
    )
    remaining_gap = _quantized_money(
        max(objective.target_per_period - observed, Decimal("0"))
    )

    notes: list[str] = [
        "the glide path is a LINEAR assumption from baseline to target; "
        "real growth is rarely linear",
        "the run-rate normalizes one evidence window "
        f"({window_days} days) to the {objective.period_days}-day period",
    ]
    if not objective.baseline_complete:
        notes.append(
            "the committed baseline was derived from incomplete economics; "
            "the starting line understates costs"
        )
    if not complete:
        notes.append(
            "the observed run-rate excludes unknown costs: "
            + ", ".join(missing)
        )

    expired = as_of_at >= target_at
    if observed >= objective.target_per_period:
        # Achieved is judged against the deadline, not just the number: a
        # run-rate measured on a window that closed AFTER target_by cannot
        # retroactively convert a missed commitment into a win.
        if expired and span_end > target_at:
            verdict: ObjectiveVerdict = "expired_missed"
            notes.append(
                "the run-rate reached target on evidence measured after the "
                "deadline; the commitment window itself closed short — "
                "commit the next objective from this stronger baseline"
            )
        else:
            verdict = "achieved"
            remaining_gap = Decimal("0.00")
    elif expired:
        verdict = "expired_missed"
    else:
        # Band measured DOWNWARD from the glide by |glide| so it stays
        # below the path even when a turnaround objective's glide is <= 0.
        shortfall_band = glide_expected - abs(glide_expected) * (
            parsed.policy.at_risk_shortfall_ratio
        )
        if glide_expected <= 0:
            notes.append(
                "the glide path is at or below zero (a turnaround "
                "objective); the at_risk band is measured in absolute "
                "distance below it"
            )
        if observed >= glide_expected:
            verdict = "on_track"
        elif observed >= shortfall_band:
            verdict = "at_risk"
            notes.append(
                "at_risk band is the caller's policy heuristic "
                f"({parsed.policy.at_risk_shortfall_ratio} below the glide path)"
            )
        else:
            verdict = "off_track"

    gap_funding = _review_funding(
        parsed.profit_review,
        parsed.customer_value_review,
        objective=objective,
        economics=economics,
        as_of_at=as_of_at,
        window_days=window_days,
    )
    if gap_funding is not None:
        shortfall = _quantized_money(
            max(remaining_gap - gap_funding.funded_expected, Decimal("0"))
        )
        gap_funding = GapFunding(
            **{
                **gap_funding.model_dump(mode="python"),
                "shortfall_after_expected": shortfall,
            }
        )
        notes.append(
            "gap funding sums only economics-window opportunities, "
            f"normalized to the {objective.period_days}-day period, and "
            "assumes independent additive levers — overlapping levers "
            "overstate it; funded is not achieved"
        )
        if gap_funding.excluded_incomparable > 0:
            notes.append(
                f"{gap_funding.excluded_incomparable} priced opportunity(ies) "
                "on other time bases (funnel windows, LTV horizons) are "
                "listed in their reviews but not summed here"
            )
        if shortfall > 0:
            notes.append(
                f"even at expected funding, {shortfall} {objective.currency} "
                "per period remains unfunded; new levers or a superseding "
                "objective are the honest options"
            )
    elif remaining_gap > 0 and verdict in {"at_risk", "off_track"}:
        notes.append(
            "no reviews were supplied; run growth.review_profit and "
            "growth.review_customer_value to price what could fund the gap"
        )

    review_statuses = [
        review.evidence_scope_status
        for review in (parsed.profit_review, parsed.customer_value_review)
        if review is not None
    ]
    both_verified = (
        objective.is_sealed
        and economics.evidence_scope_status == "host_hmac_verified"
        and all(status == "host_hmac_verified" for status in review_statuses)
    )
    if both_verified:
        notes.append(
            "trust label echoed from the sealed inputs without verification "
            "here; verify the objective and economics seals before acting"
        )
    return ObjectiveAssessment(
        as_of=parsed.as_of,
        objective_digest=objective.objective_digest,
        objective_ref=objective.objective_ref,
        currency=objective.currency,
        evidence_scope_status=(
            "host_hmac_verified" if both_verified else "caller_supplied_unverified"
        ),
        period_days=objective.period_days,
        baseline_per_period=objective.baseline_per_period,
        target_per_period=objective.target_per_period,
        observed_per_period=observed,
        observed_window_days=window_days,
        glide_expected_per_period=glide_expected,
        elapsed_ratio=elapsed_ratio,
        remaining_gap_per_period=remaining_gap,
        verdict=verdict,
        complete=complete,
        missing_inputs=tuple(missing),
        gap_funding=gap_funding,
        economics_digest=economics.economics_digest,
        data_quality_notes=tuple(notes[:20]),
    )


# ---------------------------------------------------------------------------
# Executable primitive (read-only; unverified path by design)
# ---------------------------------------------------------------------------

_EXAMPLE_ECONOMICS: dict[str, Any] = build_unit_economics(
    {
        "analysis_as_of": "2026-08-19T00:00:00Z",
        "economics_ref": "econ-objective-example",
        "currency": "USD",
        "evidence": (
            {
                "observation_ref": "shopify-ledger-example",
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
                    "refunds": "350.00",
                    "cogs": "4800.00",
                    "fulfillment_cost": "900.00",
                    "payment_fees": "360.00",
                    "service_cost": "240.00",
                    "orders": 300,
                },
                "evidence_digest": "6" * 64,
            },
        ),
    }
).to_dict()

# Contribution 4,750.00 over a 14-day window -> 10,178.57 per 30 days.
_EXAMPLE_OBJECTIVE: dict[str, Any] = {
    "objective_ref": "q3-contribution",
    "metric": "contribution_profit",
    "currency": "USD",
    "period_days": 30,
    "baseline_per_period": "10178.57",
    "target_per_period": "14000.00",
    "baseline_economics_digest": _EXAMPLE_ECONOMICS["economics_digest"],
    "baseline_economics_as_of": "2026-08-19T00:00:00Z",
    "baseline_window_days": "14.000000",
    "baseline_complete": True,
    "committed_at": "2026-08-19T00:00:00Z",
    "target_by": "2026-11-17T00:00:00Z",
    "rationale": "Reach 14k monthly contribution before the holiday inventory buy.",
}


def _planner_failure(
    primitive_ref: str,
    version: str,
    exc: ValueError,
) -> PrimitiveExecutionResult[Any]:
    return PrimitiveExecutionResult(
        status=PrimitiveExecutionStatus.FAILED,
        primitive_ref=primitive_ref,
        primitive_version=version,
        summary="The objectives engine rejected the inputs.",
        blockers=[
            PrimitiveBlocker(
                code="growth_objectives_invalid",
                message=str(exc)[:500],
            )
        ],
        retryable=False,
    )


class AssessObjectivePrimitive(
    BusinessProcessPrimitive[AssessObjectiveInput, ObjectiveAssessment]
):
    """Judge progress against a sealed growth objective."""

    primitive_ref = "growth.assess_objective"
    version = "1.0.0"
    title = "Assess growth objective"
    description = (
        "Compare the current contribution run-rate (window-normalized from "
        "sealed unit economics) against a sealed growth commitment: verdict "
        "on the labeled linear glide path (on_track / at_risk / off_track / "
        "achieved / expired), the remaining money gap per period, and — when "
        "profit and customer-value reviews are supplied — a conservative "
        "scenario sum of what their dollar-priced opportunities could fund. "
        "Funded is not achieved; every projection names its assumptions."
    )
    input_model = AssessObjectiveInput
    output_model = ObjectiveAssessment
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs = {
        "as_of": "2026-09-18T00:00:00Z",
        "objective": _EXAMPLE_OBJECTIVE,
        "current_economics": _EXAMPLE_ECONOMICS,
    }

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: AssessObjectiveInput,
    ) -> PrimitiveExecutionResult[ObjectiveAssessment]:
        try:
            assessment = assess_objective_progress(inputs)
        except ValueError as exc:
            return _planner_failure(self.primitive_ref, self.version, exc)
        return PrimitiveExecutionResult[ObjectiveAssessment](
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                f"Objective {assessment.objective_ref}: {assessment.verdict}; "
                f"gap {assessment.remaining_gap_per_period} "
                f"{assessment.currency}/period."
            ),
            output=assessment,
            events=[
                PrimitiveEvent(
                    type="growth.objective_assessed",
                    payload={
                        "objective_ref": assessment.objective_ref,
                        "verdict": assessment.verdict,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="deterministic_plan",
                    summary="Assessment bound to objective "
                    + assessment.objective_digest[:16]
                    + "… and economics "
                    + assessment.economics_digest[:16]
                    + "…",
                )
            ],
        )


__all__ = [
    "GROWTH_OBJECTIVE_ASSESSMENT_SCHEMA",
    "GROWTH_OBJECTIVE_SCHEMA",
    "AssessObjectiveInput",
    "AssessObjectivePrimitive",
    "CommitGrowthObjectiveInput",
    "GapFunding",
    "GrowthObjective",
    "GrowthObjectivesValidationError",
    "ObjectiveAssessment",
    "ObjectivePolicy",
    "assess_objective_progress",
    "commit_growth_objective",
    "verify_growth_objective",
]
