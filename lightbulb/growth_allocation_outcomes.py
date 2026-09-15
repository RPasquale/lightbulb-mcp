"""Allocation outcomes: did the tranche the allocation proposed pay back the way the cohort table said it would?

An allocation is a prediction (each line carries the CAC, payback, and
LTV/CAC it was decided on); a later cohort table is the observation.
Nothing compared them.  ``score_allocation`` does, from the two sealed
documents only: for every line, the cohorts acquired from the allocation
month on, what was actually spent against what was budgeted, the realised
CAC, payback, and LTV/CAC against the predicted, and a verdict
(``paid_back``, ``on_track``, ``missed``, ``no_customers``, ``unspent``).
The outcome hands the operating memory one sample per line so the next
allocation's floors can be set from what happened, not from what was hoped.
Nothing here reads a provider, persists anything, or re-allocates: the
outcome is the consequence of the two documents it read.
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
    timestamp,
)

ALLOCATION_OUTCOME_SCHEMA = "lightbulb.allocation_outcome.v1"
LINE_VERDICTS: tuple[str, ...] = ("paid_back", "on_track", "missed", "no_customers", "unspent")
LineVerdict = Literal["paid_back", "on_track", "missed", "no_customers", "unspent"]
OutcomeVerdict = Literal["held", "mixed", "missed", "too_early"]
_RATE_QUANTUM = Decimal("0.01")
_HUNDRED = Decimal("100")


class AllocationOutcomeError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise AllocationOutcomeError(code, message)


def _money(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


def _rate(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(_RATE_QUANTUM, rounding=ROUND_HALF_UP)


def _months_between(start: str, end: str) -> int:
    a, b = parsed(start), parsed(end)
    return max(0, (b.year - a.year) * 12 + (b.month - a.month))


class ChannelOutcome(StrictModel):
    channel: ShortText
    budgeted_monthly: Decimal
    budgeted_to_date: Decimal
    observed_spend: Decimal
    spend_ratio_percent: Decimal | None = None
    cohorts_counted: int = Field(ge=0)
    customers: int = Field(ge=0)
    predicted_cac: Decimal
    realised_cac: Decimal | None = None
    predicted_payback_months: int = Field(ge=0)
    payback_met: bool
    predicted_ltv_cac: Decimal
    realised_ltv_cac: Decimal | None = None
    verdict: LineVerdict

    @field_validator("budgeted_monthly", "budgeted_to_date", "observed_spend", "spend_ratio_percent", "predicted_cac", "realised_cac", "predicted_ltv_cac", "realised_ltv_cac", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))


class MemorySample(StrictModel):
    """One evidence-weighted observation for the operating memory: what the channel actually returned."""

    metric: Literal["channel_ltv_cac", "channel_cac", "channel_spend_ratio"]
    channel: ShortText
    value: Decimal
    weight: int = Field(ge=1)

    @field_validator("value", mode="before")
    @classmethod
    def _value(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="value")


class AllocationOutcome(StrictModel):
    schema_id: str = Field(default=ALLOCATION_OUTCOME_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    as_of: str
    allocation_ref: OpaqueRef
    allocation_digest: Sha256Digest
    allocated_at: str
    cohort_report_digest: Sha256Digest
    months_elapsed: int = Field(ge=0)
    lines: tuple[ChannelOutcome, ...] = Field(default_factory=tuple, max_length=13)
    paid_back: int = Field(ge=0)
    on_track: int = Field(ge=0)
    missed: int = Field(ge=0)
    verdict: OutcomeVerdict
    samples: tuple[MemorySample, ...] = Field(default_factory=tuple, max_length=40)
    learnings: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=13)
    outcome_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("lines", "samples", "learnings", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "AllocationOutcome":
        if self.paid_back != sum(1 for item in self.lines if item.verdict == "paid_back") or self.missed != sum(1 for item in self.lines if item.verdict == "missed"):
            raise ValueError("the counts must match the lines")
        if not skip_digests(info) and self.outcome_digest != sealed_digest(AllocationOutcome, self, "outcome_digest"):
            raise ValueError("outcome_digest must commit the exact outcome")
        return self

    def line(self, channel: str) -> ChannelOutcome | None:
        return next((item for item in self.lines if item.channel == channel), None)

    def render(self) -> str:
        lines = [f"**Allocation outcome {self.allocation_ref}** as of {self.as_of[:10]} ({self.months_elapsed} month(s) on): {self.verdict}; {self.paid_back} paid back, {self.on_track} on track, {self.missed} missed."]
        for item in self.lines:
            realised = "n/a" if item.realised_cac is None else str(item.realised_cac)
            lines.append(f"- {item.channel}: {item.verdict}; spent {item.observed_spend} of {item.budgeted_to_date} {self.currency}, CAC {realised} against {item.predicted_cac} predicted, {item.customers} customer(s)")
        lines.extend(f"- {item}" for item in self.learnings)
        return "\n".join(lines)


def score_allocation(allocation: Mapping[str, Any] | Any, *, cohorts: Mapping[str, Any] | Any, as_of: str) -> AllocationOutcome:
    """The sealed outcome of one allocation against a later cohort table."""

    from lightbulb.growth_channel_allocation import verify_channel_allocation
    from lightbulb.growth_channel_cohorts import ChannelCohortReport

    verified = verify_channel_allocation(allocation)
    report = cohorts if isinstance(cohorts, ChannelCohortReport) else ChannelCohortReport.model_validate(dict(detached(cohorts)))
    at = timestamp(as_of, field_name="as_of")
    _require(report.company_ref == verified.company_ref and report.currency == verified.currency, "SOURCE_SCOPE_MISMATCH", "the cohort report names another company or currency")
    _require(parsed(report.as_of) >= parsed(verified.as_of), "REPORT_TOO_EARLY", "the cohort report predates the allocation; nothing has been observed since")
    _require(parsed(at) >= parsed(report.as_of), "REPORT_FROM_FUTURE", "the cohort report is dated after the outcome")
    _require(verified.verdict == "allocated" and verified.lines, "NOTHING_ALLOCATED", "the allocation proposed no budget; there is nothing to score")
    start_month = verified.as_of[:7]
    months = max(1, _months_between(verified.as_of, report.as_of))
    lines: list[dict[str, Any]] = []
    samples: list[dict[str, Any]] = []
    learnings: list[str] = []
    for line in verified.lines:
        rows = [row for row in report.cohorts if row.channel == line.channel and row.cohort >= start_month]
        spend = _money(sum((row.acquisition_cost for row in rows), Decimal("0")))
        customers = sum(row.customers for row in rows)
        budgeted = _money(line.monthly_budget * months)
        ratio = None if budgeted <= 0 else _rate(spend / budgeted * _HUNDRED)
        realised_cac = None if not customers or spend <= 0 else _money(spend / customers)
        ltv = sum((row.lifetime_value for row in rows if row.lifetime_value is not None), Decimal("0"))
        realised_ltv_cac = None if spend <= 0 else _rate(ltv / spend)
        met = any(row.payback_met for row in rows)
        if ratio is not None and ratio < Decimal("50"):
            verdict = "unspent"
        elif spend > 0 and not customers:
            verdict = "no_customers" if months >= line.payback_months else "on_track"
        elif met:
            verdict = "paid_back"
        elif months < max(1, line.payback_months):
            verdict = "on_track"
        else:
            verdict = "missed"
        lines.append({"channel": line.channel, "budgeted_monthly": str(line.monthly_budget), "budgeted_to_date": str(budgeted), "observed_spend": str(spend), "spend_ratio_percent": None if ratio is None else str(ratio), "cohorts_counted": len(rows), "customers": customers, "predicted_cac": str(line.cac), "realised_cac": None if realised_cac is None else str(realised_cac), "predicted_payback_months": line.payback_months, "payback_met": met, "predicted_ltv_cac": str(line.ltv_cac), "realised_ltv_cac": None if realised_ltv_cac is None else str(realised_ltv_cac), "verdict": verdict})
        if realised_ltv_cac is not None and customers:
            samples.append({"metric": "channel_ltv_cac", "channel": line.channel, "value": str(realised_ltv_cac), "weight": customers})
        if realised_cac is not None:
            samples.append({"metric": "channel_cac", "channel": line.channel, "value": str(realised_cac), "weight": customers})
        if ratio is not None:
            samples.append({"metric": "channel_spend_ratio", "channel": line.channel, "value": str(ratio), "weight": months})
        if verdict == "unspent":
            learnings.append(f"{line.channel} spent {spend} of the {budgeted} budgeted; the allocation was not executed")
        elif verdict == "missed":
            learnings.append(f"{line.channel} has not paid back after {months} month(s) against {line.payback_months} predicted; realised CAC {realised_cac} against {line.cac}")
        elif verdict == "paid_back" and realised_cac is not None and realised_cac > line.cac:
            learnings.append(f"{line.channel} paid back but CAC rose to {realised_cac} from {line.cac}; the next allocation should use the realised figure")
    paid = sum(1 for item in lines if item["verdict"] == "paid_back")
    on_track = sum(1 for item in lines if item["verdict"] == "on_track")
    missed = sum(1 for item in lines if item["verdict"] in {"missed", "no_customers"})
    if paid and missed:
        verdict = "mixed"
    elif paid:
        verdict = "held"
    elif missed:
        verdict = "missed"
    else:
        verdict = "too_early"
    payload = {
        "company_ref": verified.company_ref, "currency": verified.currency, "as_of": at, "allocation_ref": verified.allocation_ref, "allocation_digest": verified.allocation_digest, "allocated_at": verified.as_of,
        "cohort_report_digest": report.report_digest, "months_elapsed": months, "lines": lines, "paid_back": paid, "on_track": on_track, "missed": sum(1 for item in lines if item["verdict"] == "missed"), "verdict": verdict, "samples": samples, "learnings": learnings[:13],
    }
    return seal(AllocationOutcome, payload, "outcome_digest")


def verify_allocation_outcome(value: Any) -> AllocationOutcome:
    return value if isinstance(value, AllocationOutcome) else AllocationOutcome.model_validate(dict(detached(value)))


ALLOCATION_OUTCOME_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "growth_allocation_outcomes",
    "golden_loop": "growth.attributed_revenue_to_next_tranche@0.1.0",
    "stages": ["verify_allocation", "verify_cohorts", "score_lines", "seal_outcome"],
    "line_verdicts": list(LINE_VERDICTS),
    "required_connectors": [],
    "hard_rules": [
        "the prediction is the allocation's own line; the observation is a later sealed cohort table; nothing is retyped",
        "a line is scored only on cohorts acquired from the allocation month on",
        "an unexecuted allocation is reported as unspent, never as a channel that failed",
        "samples are handed to the operating memory with their customer counts as weights; no model is fitted",
    ],
}

__all__ = ["ALLOCATION_OUTCOME_MANIFEST", "ALLOCATION_OUTCOME_SCHEMA", "LINE_VERDICTS", "AllocationOutcome", "AllocationOutcomeError", "ChannelOutcome", "MemorySample", "score_allocation", "verify_allocation_outcome"]
