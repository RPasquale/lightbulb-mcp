"""Decision work items: every accepted or deferred review decision that is still open, as a work item with its owner, due date, and the money behind it, so the cadence can raise it and the operator can close it.

The decisions ledger says what the operator chose; nothing followed it
up.  ``plan_decision_work_items`` reads a sealed ledger at a moment and
seals:

* one item per accepted or deferred action not yet closed, with a
  stable item ref, the decision, the owner, the due date, the money at
  stake, whether it is overdue and by how many days, and the receipt
  that closes it (an outcome of done or dropped with a note);
* the closed items as a count by outcome, the money still open, and a
  verdict that names the overdue items first.

The cadence planner raises each open item as a work item and the runner
closes it by amending the ledger with the supplied outcome; nothing here
reads a provider or persists anything.
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
    stable_digest,
    timestamp,
)

DECISION_WORK_ITEMS_SCHEMA = "lightbulb.decision_work_items.v1"
ITEM_STATUSES: tuple[str, ...] = ("open", "overdue")
ItemStatus = Literal["open", "overdue"]
CLOSE_RECEIPT_FIELDS: tuple[str, ...] = ("outcome",)


class DecisionWorkItemsError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise DecisionWorkItemsError(code, message)


def _money(value: Any) -> Decimal:
    result = Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)
    return Decimal("0.00") if result == 0 else result


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


def item_ref_for(review_ref: str, key: str) -> str:
    """The stable work item ref for one decided action: the review and a short digest of the action key."""

    return f"decision:{review_ref}:{stable_digest({'key': key})[:12]}"


class DecisionWorkItem(StrictModel):
    item_ref: OpaqueRef
    review_ref: OpaqueRef
    key: ShortText
    source: ShortText
    kind: ShortText
    subject: ShortText
    severity: ShortText
    decision: ShortText
    owner_ref: OpaqueRef | None = None
    decided_at: str | None = None
    due_at: str
    days_to_due: int
    status: ItemStatus
    money_at_stake: Decimal
    note: ShortText | None = None
    summary: ShortText

    @field_validator("money_at_stake", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class DecisionWorkItems(StrictModel):
    schema_id: str = Field(default=DECISION_WORK_ITEMS_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    review_ref: OpaqueRef
    decisions_digest: Sha256Digest
    as_of: str
    items: tuple[DecisionWorkItem, ...] = Field(default_factory=tuple, max_length=200)
    open: int = Field(ge=0)
    overdue: int = Field(ge=0)
    closed: int = Field(ge=0)
    by_outcome: dict[str, int] = Field(default_factory=dict)
    money_open: Decimal
    money_overdue: Decimal
    verdict: ShortText
    work_items_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("items", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("money_open", "money_overdue", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name), allow_negative=True)

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "DecisionWorkItems":
        if self.open != len(self.items) or self.overdue != sum(1 for row in self.items if row.status == "overdue") or sum(self.by_outcome.values()) != self.closed:
            raise ValueError("open counts every item, overdue the overdue ones, and by_outcome the closed ones")
        if not skip_digests(info) and self.work_items_digest != sealed_digest(DecisionWorkItems, self, "work_items_digest"):
            raise ValueError("work_items_digest must commit the exact document")
        return self

    def item(self, item_ref: str) -> DecisionWorkItem | None:
        return next((row for row in self.items if row.item_ref == item_ref), None)

    def render(self) -> str:
        lines = [f"**Decision work items {self.review_ref}** ({self.company_ref}, as of {self.as_of[:10]}): {self.verdict}"]
        lines.extend(f"- [{row.status}] {row.summary}" for row in self.items)
        return "\n".join(lines)


def plan_decision_work_items(decisions: Mapping[str, Any] | Any, *, as_of: str) -> DecisionWorkItems:
    """The sealed open work items of one decisions ledger at ``as_of``: every accepted or deferred action not yet closed."""

    from lightbulb.review_decisions import verify_review_decisions

    ledger = verify_review_decisions(decisions)
    at = timestamp(as_of, field_name="as_of")
    now = parsed(at)
    rows: list[dict[str, Any]] = []
    closed = 0
    by_outcome: dict[str, int] = {}
    for action in ledger.actions:
        if action.decision not in ("accept", "defer"):
            continue
        outcome = getattr(action, "outcome", None)
        if outcome is not None:
            closed += 1
            by_outcome[str(outcome)] = by_outcome.get(str(outcome), 0) + 1
            continue
        _require(action.due_at is not None, "DUE_DATE_MISSING", f"{action.key} is {action.decision}ed without a due date")
        days = (parsed(str(action.due_at)) - now).days
        status = "overdue" if parsed(str(action.due_at)) < now else "open"
        who = f" for {action.owner_ref}" if action.owner_ref else ""
        when = f"{abs(days)} day(s) overdue" if status == "overdue" else f"due in {days} day(s)"
        summary = f"{'accepted' if action.decision == 'accept' else 'deferred'}: {action.subject} ({action.source}, {action.kind}){who}, {when} ({str(action.due_at)[:10]}); {_money(action.money_at_stake)} {ledger.currency} at stake" + (f"; {action.note}" if action.note else "")
        rows.append({"item_ref": item_ref_for(ledger.review_ref, action.key), "review_ref": ledger.review_ref, "key": action.key, "source": action.source, "kind": action.kind, "subject": action.subject, "severity": action.severity, "decision": action.decision, "owner_ref": action.owner_ref, "decided_at": action.decided_at, "due_at": str(action.due_at), "days_to_due": days, "status": status, "money_at_stake": str(_money(action.money_at_stake)), "note": action.note, "summary": summary[:300]})
    rows.sort(key=lambda row: (row["status"] != "overdue", row["due_at"], -Decimal(row["money_at_stake"]), row["item_ref"]))
    overdue = [row for row in rows if row["status"] == "overdue"]
    money_open = _money(sum((Decimal(row["money_at_stake"]) for row in rows), Decimal("0")))
    money_overdue = _money(sum((Decimal(row["money_at_stake"]) for row in overdue), Decimal("0")))
    if not rows and not closed:
        verdict = "nothing accepted or deferred; no work item to raise"
    else:
        verdict = f"{len(rows)} open item(s) carrying {money_open} {ledger.currency}, {len(overdue)} overdue carrying {money_overdue}; {closed} closed" + (" (" + ", ".join(f"{count} {name}" for name, count in sorted(by_outcome.items())) + ")" if by_outcome else "")
        if overdue:
            verdict += "; first: " + overdue[0]["summary"][:120]
    payload = {"company_ref": ledger.company_ref, "currency": ledger.currency, "review_ref": ledger.review_ref, "decisions_digest": ledger.decisions_digest, "as_of": at, "items": rows, "open": len(rows), "overdue": len(overdue), "closed": closed, "by_outcome": by_outcome, "money_open": str(money_open), "money_overdue": str(money_overdue), "verdict": verdict[:300]}
    return seal(DecisionWorkItems, payload, "work_items_digest")


def verify_decision_work_items(value: Any) -> DecisionWorkItems:
    return value if isinstance(value, DecisionWorkItems) else DecisionWorkItems.model_validate(dict(detached(value)))


DECISION_WORK_ITEMS_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "decision_work_items",
    "golden_loop": "company.blueprint_to_governed_operating_cadence@0.1.0",
    "stages": ["verify_ledger", "open_accepted_and_deferred", "overdue_at_as_of", "seal_items"],
    "statuses": list(ITEM_STATUSES),
    "close_receipt_fields": list(CLOSE_RECEIPT_FIELDS),
    "required_connectors": ["lightbulb.sdk_engine_state"],
    "hard_rules": [
        "an item exists for every accepted or deferred decision without an outcome; declined and undecided actions raise nothing",
        "an item closes only by amending the ledger with an outcome (done or dropped) through the cadence runner or the console; nothing here persists",
        "nothing here reads a provider",
    ],
}

__all__ = ["CLOSE_RECEIPT_FIELDS", "DECISION_WORK_ITEMS_MANIFEST", "DECISION_WORK_ITEMS_SCHEMA", "ITEM_STATUSES", "DecisionWorkItem", "DecisionWorkItems", "DecisionWorkItemsError", "item_ref_for", "plan_decision_work_items", "verify_decision_work_items"]
