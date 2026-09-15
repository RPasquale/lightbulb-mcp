"""Review decisions: what the operator decided about each action a sealed intelligence review raised, sealed against that review, with the owner, the due date, and what is overdue.

The review names the actions and the money behind them; the operator
accepts, defers, or declines each one.  ``decide_review_actions`` seals
that ledger against the review it answers:

* every decision names an action the review actually raised (by source,
  kind, and subject), decides it once, and carries the owner, the due
  date for an accepted or deferred action, and a note;
* actions the operator has not decided are listed as undecided, never
  assumed accepted;
* the ledger sums the money at stake by decision, names the accepted
  and deferred actions past due at ``as_of``, and recommends the next
  step: decide the undecided, chase the overdue.

The next review carries these decisions on the actions it still raises,
and the review outcomes tell a cleared action that was accepted from one
that merely stopped being raised.  Nothing here reads a provider or
persists anything; the console persists the ledger under the review.
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

REVIEW_DECISIONS_SCHEMA = "lightbulb.review_decisions.v1"
DECISIONS: tuple[str, ...] = ("accept", "defer", "decline")
Decision = Literal["accept", "defer", "decline"]
_PCT = Decimal("0.01")
_HUNDRED = Decimal("100")


class ReviewDecisionsError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise ReviewDecisionsError(code, message)


def _money(value: Any) -> Decimal:
    result = Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)
    return Decimal("0.00") if result == 0 else result


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


def action_key(source: str, kind: str, subject: str) -> str:
    return f"{source}:{kind}:{subject}"


class ActionDecision(StrictModel):
    key: ShortText
    source: ShortText
    kind: ShortText
    subject: ShortText
    severity: ShortText
    money_at_stake: Decimal
    decision: Decision | None = None
    owner_ref: OpaqueRef | None = None
    due_at: str | None = None
    decided_at: str | None = None
    note: ShortText | None = None
    outcome: Literal["done", "dropped"] | None = None
    closed_at: str | None = None
    outcome_note: ShortText | None = None
    overdue: bool = False

    @field_validator("money_at_stake", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class ReviewDecisions(StrictModel):
    schema_id: str = Field(default=REVIEW_DECISIONS_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    review_ref: OpaqueRef
    review_digest: Sha256Digest
    as_of: str
    actions: tuple[ActionDecision, ...] = Field(default_factory=tuple, max_length=200)
    decided: int = Field(ge=0)
    undecided: int = Field(ge=0)
    by_decision: dict[str, int] = Field(default_factory=dict)
    money_accepted: Decimal
    money_deferred: Decimal
    money_declined: Decimal
    money_undecided: Decimal
    overdue: int = Field(ge=0)
    closed: int = Field(default=0, ge=0)
    by_outcome: dict[str, int] = Field(default_factory=dict)
    verdict: ShortText
    recommendations: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=24)
    decisions_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("actions", "recommendations", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("money_accepted", "money_deferred", "money_declined", "money_undecided", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name), allow_negative=True)

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "ReviewDecisions":
        if self.decided + self.undecided != len(self.actions) or sum(self.by_decision.values()) != self.decided or self.overdue != sum(1 for row in self.actions if row.overdue) or self.closed != sum(1 for row in self.actions if row.outcome is not None) or sum(self.by_outcome.values()) != self.closed:
            raise ValueError("decided plus undecided is every action, by_decision counts the decided ones, overdue counts the overdue ones, and closed counts the outcomes")
        if not skip_digests(info) and self.decisions_digest != sealed_digest(ReviewDecisions, self, "decisions_digest"):
            raise ValueError("decisions_digest must commit the exact ledger")
        return self

    def action(self, key: str) -> ActionDecision | None:
        return next((row for row in self.actions if row.key == key), None)

    def decision_for(self, source: str, kind: str, subject: str) -> ActionDecision | None:
        return self.action(action_key(source, kind, subject))

    def render(self) -> str:
        lines = [f"**Review decisions {self.review_ref}** ({self.company_ref}, as of {self.as_of[:10]}): {self.verdict}"]
        for row in self.actions:
            state = row.decision or "undecided"
            lines.append(f"- [{state}{' overdue' if row.overdue else ''}] {row.subject} ({row.source}, {row.kind}): {row.money_at_stake}" + (f"; {row.owner_ref}" if row.owner_ref else "") + (f" by {row.due_at[:10]}" if row.due_at else "") + (f"; {row.note}" if row.note else ""))
        return "\n".join(lines)


def decide_review_actions(review: Mapping[str, Any] | Any, decisions: Sequence[Mapping[str, Any]], *, as_of: str) -> ReviewDecisions:
    """The sealed ledger of the operator's decisions on the actions a sealed review raised."""

    from lightbulb.intelligence_review import verify_intelligence_review

    verified = verify_intelligence_review(review)
    at = timestamp(as_of, field_name="as_of")
    _require(parsed(verified.as_of) <= parsed(at), "REVIEW_FROM_FUTURE", "the review is dated after as_of")
    raised = {action_key(action.source, action.kind, action.subject): action for action in verified.actions}
    chosen: dict[str, dict[str, Any]] = {}
    for raw in decisions:
        item = dict(detached(raw))
        key = str(item.get("key") or action_key(str(item.get("source", "")), str(item.get("kind", "")), str(item.get("subject", ""))))
        _require(key in raised, "ACTION_UNKNOWN", f"the review did not raise {key}")
        _require(key not in chosen, "ACTION_DECIDED_TWICE", f"{key} is decided twice")
        decision = str(item.get("decision", ""))
        _require(decision in DECISIONS, "DECISION_UNKNOWN", f"{key}: decision must be one of {', '.join(DECISIONS)}")
        decided_at = timestamp(str(item.get("decided_at") or verified.as_of), field_name="decided_at")
        _require(parsed(verified.as_of) <= parsed(decided_at) <= parsed(at), "DECIDED_OUT_OF_ORDER", f"{key}: decided_at must fall between the review and as_of")
        due_at = None if item.get("due_at") in (None, "") else timestamp(str(item["due_at"]), field_name="due_at")
        if decision in ("accept", "defer"):
            _require(due_at is not None, "DUE_DATE_MISSING", f"{key}: an accepted or deferred action needs a due_at")
            _require(parsed(due_at) >= parsed(decided_at), "DUE_BEFORE_DECIDED", f"{key}: due_at falls before decided_at")
        else:
            due_at = None
        owner = item.get("owner_ref")
        _require(decision != "accept" or bool(owner), "OWNER_MISSING", f"{key}: an accepted action needs an owner_ref")
        note = item.get("note")
        outcome = item.get("outcome")
        closed_at = None
        if outcome not in (None, ""):
            _require(str(outcome) in ("done", "dropped"), "OUTCOME_UNKNOWN", f"{key}: outcome must be done or dropped")
            _require(decision in ("accept", "defer"), "OUTCOME_WITHOUT_DECISION", f"{key}: only an accepted or deferred action closes with an outcome")
            closed_at = timestamp(str(item.get("closed_at") or at), field_name="closed_at")
            _require(parsed(decided_at) <= parsed(closed_at) <= parsed(at), "CLOSED_OUT_OF_ORDER", f"{key}: closed_at must fall between decided_at and as_of")
        outcome_note = item.get("outcome_note")
        chosen[key] = {"decision": decision, "owner_ref": None if owner in (None, "") else str(owner), "due_at": due_at, "decided_at": decided_at, "note": None if note in (None, "") else str(note)[:300], "outcome": None if outcome in (None, "") else str(outcome), "closed_at": closed_at, "outcome_note": None if outcome_note in (None, "") else str(outcome_note)[:300]}
    rows: list[dict[str, Any]] = []
    for key, action in raised.items():
        row = chosen.get(key)
        overdue = bool(row and row["decision"] in ("accept", "defer") and row["due_at"] is not None and row["outcome"] is None and parsed(row["due_at"]) < parsed(at))
        rows.append({"key": key, "source": action.source, "kind": action.kind, "subject": action.subject, "severity": action.severity, "money_at_stake": str(_money(action.money_at_stake)), **(row or {"decision": None, "owner_ref": None, "due_at": None, "decided_at": None, "note": None, "outcome": None, "closed_at": None, "outcome_note": None}), "overdue": overdue})
    order = {"accept": 0, "defer": 1, None: 2, "decline": 3}
    rows.sort(key=lambda row: (not row["overdue"], order[row["decision"]], -Decimal(row["money_at_stake"]), row["key"]))
    decided = sum(1 for row in rows if row["decision"] is not None)
    by_decision = {kind: sum(1 for row in rows if row["decision"] == kind) for kind in DECISIONS if any(row["decision"] == kind for row in rows)}
    money = {kind: _money(sum((Decimal(row["money_at_stake"]) for row in rows if row["decision"] == kind), Decimal("0"))) for kind in DECISIONS}
    undecided_money = _money(sum((Decimal(row["money_at_stake"]) for row in rows if row["decision"] is None), Decimal("0")))
    overdue_rows = [row for row in rows if row["overdue"]]
    recommendations: list[str] = []
    for row in overdue_rows:
        recommendations.append(f"{row['subject']} ({row['source']}): {'accepted' if row['decision'] == 'accept' else 'deferred'} for {row['due_at'][:10]}" + (f" by {row['owner_ref']}" if row["owner_ref"] else "") + f", now overdue with {row['money_at_stake']} {verified.currency} at stake")
    undecided_rows = [row for row in rows if row["decision"] is None]
    if undecided_rows:
        recommendations.append(f"decide the {len(undecided_rows)} undecided action(s) carrying {undecided_money} {verified.currency}: " + ", ".join(f"{row['subject']} ({row['source']})" for row in undecided_rows[:5]))
    if not recommendations:
        recommendations.append("every action is decided and nothing accepted or deferred is overdue" if rows else "the review raised nothing to decide")
    closed_rows = [row for row in rows if row["outcome"] is not None]
    by_outcome = {name: sum(1 for row in closed_rows if row["outcome"] == name) for name in ("done", "dropped") if any(row["outcome"] == name for row in closed_rows)}
    verdict = f"{decided} of {len(rows)} action(s) decided ({by_decision.get('accept', 0)} accepted for {money['accept']} {verified.currency}, {by_decision.get('defer', 0)} deferred for {money['defer']}, {by_decision.get('decline', 0)} declined for {money['decline']}); {len(undecided_rows)} undecided carrying {undecided_money}; {len(overdue_rows)} overdue"
    if closed_rows:
        verdict += f"; {len(closed_rows)} closed (" + ", ".join(f"{count} {name}" for name, count in by_outcome.items()) + ")"
    payload = {"company_ref": verified.company_ref, "currency": verified.currency, "review_ref": verified.review_ref, "review_digest": verified.review_digest, "as_of": at, "actions": rows, "decided": decided, "undecided": len(rows) - decided, "by_decision": by_decision, "money_accepted": str(money["accept"]), "money_deferred": str(money["defer"]), "money_declined": str(money["decline"]), "money_undecided": str(undecided_money), "overdue": len(overdue_rows), "closed": len(closed_rows), "by_outcome": by_outcome, "verdict": verdict[:300], "recommendations": [row[:300] for row in recommendations[:24]]}
    return seal(ReviewDecisions, payload, "decisions_digest")


def verify_review_decisions(value: Any) -> ReviewDecisions:
    return value if isinstance(value, ReviewDecisions) else ReviewDecisions.model_validate(dict(detached(value)))


REVIEW_DECISIONS_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "review_decisions",
    "golden_loop": "company.operating_review@0.1.0",
    "stages": ["verify_review", "bind_each_decision_to_a_raised_action", "owner_and_due_date", "overdue_at_as_of", "seal_ledger"],
    "decisions": list(DECISIONS),
    "required_connectors": ["lightbulb.sdk_engine_state"],
    "hard_rules": [
        "a decision names an action the review raised, once; an undecided action stays undecided, never assumed accepted",
        "an accepted action needs an owner and a due date; a deferred one a due date; a declined one neither",
        "an accepted or deferred action closes with an outcome of done or dropped and a closed_at between the decision and as_of; a closed action is never overdue",
        "nothing here reads a provider or persists anything; the console persists the ledger under its review",
    ],
}

__all__ = ["DECISIONS", "REVIEW_DECISIONS_MANIFEST", "REVIEW_DECISIONS_SCHEMA", "ActionDecision", "ReviewDecisions", "ReviewDecisionsError", "action_key", "decide_review_actions", "verify_review_decisions"]
