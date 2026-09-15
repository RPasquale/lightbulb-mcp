"""Review outcomes: what happened to last review's actions by this one, and how much of the money at stake was released.

The intelligence review names the actions and the money behind them;
the next review either still carries them or not.  ``score_review_outcomes``
lines two sealed reviews up, action by action (same source, kind, and
subject), and seals:

* per action: carried (still open, with the money then and now and the
  change) or cleared (gone from this review, its money released);
* per source document: actions, cleared, carried, the money then and
  now;
* the totals: the money at stake then and now, the money released, the
  clearance rate, and the actions this review raised that last week's
  did not;
* a verdict that names the number: how much of last week's money at
  stake this week no longer carries.

Nothing here judges why an action cleared; a cleared action is one the
documents stopped raising.  Nothing reads a provider or persists.
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
from lightbulb.intelligence_review import verify_intelligence_review

REVIEW_OUTCOMES_SCHEMA = "lightbulb.review_outcomes.v1"
OUTCOME_STATUSES: tuple[str, ...] = ("carried", "cleared")
OutcomeStatus = Literal["carried", "cleared"]
_HUNDRED = Decimal("100")
_PCT = Decimal("0.01")


class ReviewOutcomesError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise ReviewOutcomesError(code, message)


def _money(value: Any) -> Decimal:
    result = Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)
    return Decimal("0.00") if result == 0 else result


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


class ActionOutcome(StrictModel):
    source: ShortText
    kind: ShortText
    subject: ShortText
    severity_then: ShortText
    status: OutcomeStatus
    money_then: Decimal
    money_now: Decimal
    change: Decimal
    first_raised_in: OpaqueRef
    decision: ShortText | None = None
    decision_due_at: str | None = None
    outcome: ShortText | None = None
    overdue: bool = False

    @field_validator("money_then", "money_now", "change", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class SourceOutcome(StrictModel):
    source: ShortText
    actions: int = Field(ge=0)
    cleared: int = Field(ge=0)
    carried: int = Field(ge=0)
    money_then: Decimal
    money_now: Decimal

    @field_validator("money_then", "money_now", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class ReviewOutcomes(StrictModel):
    schema_id: str = Field(default=REVIEW_OUTCOMES_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    previous_review_ref: OpaqueRef
    previous_review_digest: Sha256Digest
    current_review_ref: OpaqueRef
    current_review_digest: Sha256Digest
    days_between: int = Field(ge=0)
    actions: tuple[ActionOutcome, ...] = Field(default_factory=tuple, max_length=200)
    sources: tuple[SourceOutcome, ...] = Field(default_factory=tuple, max_length=32)
    cleared: int = Field(ge=0)
    carried: int = Field(ge=0)
    new_actions: int = Field(ge=0)
    cleared_accepted: int = Field(default=0, ge=0)
    cleared_undecided: int = Field(default=0, ge=0)
    carried_overdue: int = Field(default=0, ge=0)
    cleared_done: int = Field(default=0, ge=0)
    decisions_digest: Sha256Digest | None = None
    money_then: Decimal
    money_now: Decimal
    money_released: Decimal
    clearance_rate_percent: Decimal | None = None
    verdict: ShortText
    outcomes_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("actions", "sources", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("money_then", "money_now", "money_released", "clearance_rate_percent", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "ReviewOutcomes":
        if self.cleared + self.carried != len(self.actions) or self.money_released != self.money_then - self.money_now:
            raise ValueError("cleared plus carried is every action, and released is then less now")
        if not skip_digests(info) and self.outcomes_digest != sealed_digest(ReviewOutcomes, self, "outcomes_digest"):
            raise ValueError("outcomes_digest must commit the exact document")
        return self

    def render(self) -> str:
        lines = [f"**Review outcomes {self.previous_review_ref} to {self.current_review_ref}** ({self.company_ref}, {self.days_between} day(s)): {self.verdict}"]
        for row in self.actions:
            lines.append(f"- [{row.status}] {row.subject} ({row.source}, {row.kind}): {row.money_then} then, {row.money_now} now" + (f", first raised in {row.first_raised_in}" if row.first_raised_in != self.previous_review_ref else ""))
        return "\n".join(lines)


def score_review_outcomes(previous: Mapping[str, Any] | Any, current: Mapping[str, Any] | Any, *, decisions: Mapping[str, Any] | Any | None = None) -> ReviewOutcomes:
    """The sealed outcomes of every action the previous review raised, judged by whether the current review still carries it and for how much."""

    before, after = verify_intelligence_review(previous), verify_intelligence_review(current)
    _require(before.company_ref == after.company_ref and before.currency == after.currency, "REVIEW_SCOPE_MISMATCH", "both reviews must name the same company and currency")
    _require(before.review_digest != after.review_digest, "SAME_REVIEW", "score two different reviews")
    _require(parsed(before.as_of) < parsed(after.as_of), "REVIEWS_OUT_OF_ORDER", "the previous review must be dated before the current one")
    now = {f"{row.source}:{row.kind}:{row.subject}": row for row in after.actions}
    ledger = None
    if decisions is not None:
        from lightbulb.review_decisions import verify_review_decisions

        ledger = verify_review_decisions(decisions)
        _require(ledger.review_digest == before.review_digest, "DECISIONS_NOT_BOUND", "the decisions answer another review than the previous one")
    rows: list[dict[str, Any]] = []
    for action in before.actions:
        key = f"{action.source}:{action.kind}:{action.subject}"
        match = now.get(key)
        money_then = _money(action.money_at_stake)
        money_now = _money(match.money_at_stake) if match is not None else Decimal("0.00")
        decided = None if ledger is None else ledger.action(key)
        decision = None if decided is None else decided.decision
        due_at = None if decided is None else decided.due_at
        overdue = bool(match is not None and decision in ("accept", "defer") and due_at is not None and parsed(due_at) < parsed(after.as_of))
        rows.append({"source": action.source, "kind": action.kind, "subject": action.subject, "severity_then": action.severity, "status": "carried" if match is not None else "cleared", "money_then": str(money_then), "money_now": str(money_now), "change": str(_money(money_now - money_then)), "first_raised_in": action.carried_from or before.review_ref, "decision": decision, "decision_due_at": due_at, "outcome": None if decided is None else getattr(decided, "outcome", None), "overdue": overdue})
    rows.sort(key=lambda row: (row["status"] != "cleared", -Decimal(row["money_then"]), row["subject"]))
    sources: list[dict[str, Any]] = []
    for source in sorted({row["source"] for row in rows}):
        group = [row for row in rows if row["source"] == source]
        sources.append({"source": source, "actions": len(group), "cleared": sum(1 for row in group if row["status"] == "cleared"), "carried": sum(1 for row in group if row["status"] == "carried"), "money_then": str(_money(sum((Decimal(row["money_then"]) for row in group), Decimal("0")))), "money_now": str(_money(sum((Decimal(row["money_now"]) for row in group), Decimal("0"))))})
    money_then = _money(sum((Decimal(row["money_then"]) for row in rows), Decimal("0")))
    money_now = _money(sum((Decimal(row["money_now"]) for row in rows), Decimal("0")))
    cleared = sum(1 for row in rows if row["status"] == "cleared")
    keys_before = {f"{row.source}:{row.kind}:{row.subject}" for row in before.actions}
    new_actions = sum(1 for row in after.actions if f"{row.source}:{row.kind}:{row.subject}" not in keys_before)
    rate = None if not rows else (Decimal(cleared) / Decimal(len(rows)) * _HUNDRED).quantize(_PCT, rounding=ROUND_HALF_UP)
    days = (parsed(after.as_of) - parsed(before.as_of)).days
    cleared_accepted = sum(1 for row in rows if row["status"] == "cleared" and row["decision"] == "accept")
    cleared_undecided = sum(1 for row in rows if row["status"] == "cleared" and row["decision"] is None)
    carried_overdue = sum(1 for row in rows if row["overdue"])
    cleared_done = sum(1 for row in rows if row["status"] == "cleared" and row["outcome"] == "done")
    if not rows:
        verdict = f"the previous review raised nothing; this one raises {new_actions} action(s)"
    else:
        verdict = f"{cleared} of {len(rows)} action(s) cleared ({rate}%), {_money(money_then - money_now)} of {money_then} {before.currency} at stake released; {new_actions} new action(s) this review"
        if ledger is not None:
            verdict += f"; {cleared_accepted} cleared after acceptance, {cleared_undecided} cleared undecided, {carried_overdue} carried past due" + (f", {cleared_done} closed as done" if cleared_done else "")
    payload = {"company_ref": before.company_ref, "currency": before.currency, "previous_review_ref": before.review_ref, "previous_review_digest": before.review_digest, "current_review_ref": after.review_ref, "current_review_digest": after.review_digest, "days_between": days, "actions": rows, "sources": sources, "cleared": cleared, "carried": len(rows) - cleared, "new_actions": new_actions, "cleared_accepted": cleared_accepted, "cleared_undecided": cleared_undecided, "carried_overdue": carried_overdue, "cleared_done": cleared_done, "decisions_digest": None if ledger is None else ledger.decisions_digest, "money_then": str(money_then), "money_now": str(money_now), "money_released": str(_money(money_then - money_now)), "clearance_rate_percent": None if rate is None else str(rate), "verdict": verdict[:300]}
    return seal(ReviewOutcomes, payload, "outcomes_digest")


def verify_review_outcomes(value: Any) -> ReviewOutcomes:
    return value if isinstance(value, ReviewOutcomes) else ReviewOutcomes.model_validate(dict(detached(value)))


REVIEW_OUTCOMES_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "review_outcomes",
    "golden_loop": "company.operating_review@0.1.0",
    "stages": ["verify_both_reviews", "match_actions_by_key", "money_then_and_now", "roll_up_sources", "seal_outcomes"],
    "statuses": list(OUTCOME_STATUSES),
    "required_connectors": ["lightbulb.sdk_engine_state"],
    "hard_rules": [
        "an action is matched by its source, kind, and subject; cleared means the current review's documents stopped raising it",
        "money released is the money at stake then less now, taken from the reviews themselves",
        "nothing here judges why an action cleared, reads a provider, or persists anything",
    ],
}

__all__ = ["OUTCOME_STATUSES", "REVIEW_OUTCOMES_MANIFEST", "REVIEW_OUTCOMES_SCHEMA", "ActionOutcome", "ReviewOutcomes", "ReviewOutcomesError", "SourceOutcome", "score_review_outcomes", "verify_review_outcomes"]
