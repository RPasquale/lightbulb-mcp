"""The get-paid loop: overdue money found, the right reminder drafted, the mandate asked, the send described, and the result scored from the next ledger.

The customer ledgers say who is overdue and by how long; the collections
plan's ladder says which reminder is due at that age (a friendly note at
three days, a second at fourteen, a final notice at thirty, a letter at
forty-five), on which channel, and whether the owner signs it off.
``plan_chases`` puts the two together for every overdue customer: the
rung due now (never a rung already sent, and never sooner than the
ladder's lead time since the last one), the message drafted from a fixed
template, the mandate's answer (a rung the plan marks for approval asks
whatever the mandate says), and the send the platform would make once
allowed (an opaque recipient reference, never an address).  Nothing is
sent here.

What the agent then sends is recorded in the mandate log with the rung it
sent; ``score_chases`` later reads those entries beside the ledger as it
stands now and reports, per chase, what was overdue then, what is
overdue now, the money recovered and the days it took, and overall how
much of the chased money came back.  That is the loop: detect, draft,
gate, send (elsewhere), observe, score.  Deterministic throughout.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import ROUND_HALF_UP, Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, CurrencyCode, OpaqueRef, Sha256Digest, ShortText, StrictModel, decimal_value, detached, parsed, seal, sealed_digest, skip_digests, timestamp

CHASE_PLAN_SCHEMA = "lightbulb.chase_plan.v1"
CHASE_OUTCOMES_SCHEMA = "lightbulb.chase_outcomes.v1"
COLLECTIONS_LOOP_MANIFEST: dict[str, Any] = {"engine": "collections_loop", "kind": "intelligence_document", "reads": ("customer_ledger", "collections_chain", "owner_mandate", "mandate_log"), "writes": ()}
ChaseStatus = Literal["due", "wait", "sent_all", "not_yet_due"]
# rung -> (subject line, body); {customer}, {amount}, {currency}, {days} and {company} are filled from the record
TEMPLATES: dict[int, tuple[str, str]] = {
    1: ("A friendly reminder from {company}", "Hi {customer},\n\nJust a reminder that {currency} {amount} on your account is now {days} day(s) past its due date. If it has already been paid, thank you and please ignore this note.\n\nKind regards,\n{company}"),
    2: ("Second reminder: {currency} {amount} overdue", "Hi {customer},\n\n{currency} {amount} on your account is now {days} day(s) overdue. Could you let us know when we can expect payment, or if anything is holding it up?\n\nThanks,\n{company}"),
    3: ("Final notice: {currency} {amount} overdue", "Hi {customer},\n\nDespite our reminders, {currency} {amount} remains unpaid {days} day(s) past due. Please pay within 7 days or contact us to agree a plan; otherwise we will have to consider further steps.\n\nRegards,\n{company}"),
    4: ("Letter of demand: {currency} {amount}", "Dear {customer},\n\nThis is a formal demand for {currency} {amount}, now {days} day(s) overdue. Payment is required within 7 days of this letter.\n\n{company}"),
}
_CENT = Decimal("0.01")
_CHANNEL_CAPABILITY = {"email": "gmail.send_email", "sms": "sms.send", "voice": "voice.call", "letter": "post.send_letter"}


class CollectionsLoopError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise CollectionsLoopError(code, message)


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


def _money(value: Any) -> Decimal:
    return decimal_value(value, field_name="money", allow_negative=True).quantize(_CENT, rounding=ROUND_HALF_UP)


class ChaseDraft(StrictModel):
    customer_ref: OpaqueRef
    customer: ShortText
    overdue: Decimal
    oldest_overdue_days: int = Field(ge=0)
    status: ChaseStatus
    rung: int | None = Field(default=None, ge=1, le=16)
    channel: ShortText | None = None
    subject: ShortText | None = None
    body: str | None = Field(default=None, max_length=2000)
    autonomy: Literal["act", "ask", "never"] | None = None
    mandate_reason: ShortText | None = None
    delivery: dict[str, Any] | None = None
    record_as: dict[str, Any] | None = None
    note: ShortText

    @field_validator("overdue", mode="before")
    @classmethod
    def _numbers(cls, value: Any) -> Decimal:
        return _money(value)


class ChasePlan(StrictModel):
    schema_id: str = Field(default=CHASE_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    as_of: str
    collections_plan_digest: Sha256Digest
    mandate_digest: Sha256Digest | None = None
    drafts: tuple[ChaseDraft, ...] = Field(default_factory=tuple, max_length=500)
    overdue_total: Decimal
    due_now: int = Field(ge=0)
    act_alone: int = Field(ge=0)
    verdict: ShortText
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("drafts", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("overdue_total", mode="before")
    @classmethod
    def _numbers(cls, value: Any) -> Decimal:
        return _money(value)

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "ChasePlan":
        if self.due_now != sum(1 for row in self.drafts if row.status == "due") or self.act_alone != sum(1 for row in self.drafts if row.status == "due" and row.autonomy == "act"):
            raise ValueError("due_now and act_alone count the drafts")
        if not skip_digests(info) and self.plan_digest != sealed_digest(ChasePlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact chase plan")
        return self

    def render(self) -> str:
        lines = [f"**Chase plan** ({self.company_ref}, {self.as_of[:10]}): {self.verdict}"]
        lines.extend(f"- {row.customer}: {row.overdue} overdue, {row.oldest_overdue_days} day(s); {row.status}" + (f" rung {row.rung} by {row.channel} [{row.autonomy}]" if row.status == "due" else "") + f"; {row.note}" for row in self.drafts)
        return "\n".join(lines)


def plan_chases(*, company_ref: str, currency: str, company_name: str, as_of: str, overdue_customers: Sequence[Mapping[str, Any]], collections_plan: Mapping[str, Any] | Any, mandate: Mapping[str, Any] | None = None, spent_this_month: Any = "0", chased: Sequence[Mapping[str, Any]] = ()) -> ChasePlan:
    """For every overdue customer, the rung due now under the ladder, the draft, the mandate's answer and the send to make; ``chased`` is what was already sent (customer_ref, rung, at)."""

    from lightbulb.collections_chain import CollectionsChainPlan
    from lightbulb.owner_mandate import authorise, verify_mandate

    at = timestamp(as_of, field_name="as_of")
    plan = collections_plan if isinstance(collections_plan, CollectionsChainPlan) else CollectionsChainPlan.model_validate(dict(detached(collections_plan)))
    _require(plan.company_ref == company_ref, "SOURCE_SCOPE_MISMATCH", "the collections plan names another company")
    parsed_mandate = None if mandate is None else verify_mandate(mandate)
    history: dict[str, list[dict[str, Any]]] = {}
    for item in chased:
        item = dict(detached(item))
        history.setdefault(str(item["customer_ref"]), []).append({"rung": int(item["rung"]), "at": timestamp(str(item["at"]), field_name="at")})
    drafts: list[dict[str, Any]] = []
    total = Decimal("0")
    for raw in sorted((dict(detached(row)) for row in overdue_customers), key=lambda row: (-_money(row.get("overdue", "0")), str(row.get("customer_ref")))):
        overdue = _money(raw.get("overdue", "0"))
        if overdue <= 0:
            continue
        total += overdue
        days = int(raw.get("oldest_overdue_days", 0) or 0)
        ref, name = str(raw["customer_ref"]), str(raw.get("name") or raw["customer_ref"])
        sent = sorted(history.get(ref, ()), key=lambda item: item["rung"])
        sent_rungs = {item["rung"] for item in sent}
        last_at = max((item["at"] for item in sent), default=None)
        base = {"customer_ref": ref, "customer": name[:300], "overdue": str(overdue), "oldest_overdue_days": days}
        eligible = [step for step in plan.ladder if step.days_past_due <= days and step.rung not in sent_rungs and all(step.rung > item["rung"] for item in sent)]
        if not eligible:
            if sent and all(step.rung in sent_rungs or any(step.rung < item["rung"] for item in sent) for step in plan.ladder if step.days_past_due <= days):
                drafts.append({**base, "status": "sent_all", "note": f"every rung due at {days} day(s) has been sent; the next rung falls due later or the ladder is exhausted"})
            else:
                first = plan.ladder[0]
                drafts.append({**base, "status": "not_yet_due", "note": f"the first reminder falls due at {first.days_past_due} day(s) past due; this is {days}"})
            continue
        step = eligible[0]
        if last_at is not None and (parsed(at) - parsed(last_at)).days < step.min_lead_days:
            drafts.append({**base, "status": "wait", "rung": step.rung, "channel": step.channel, "note": f"rung {step.rung} waits {step.min_lead_days} day(s) after the last reminder on {last_at[:10]}"})
            continue
        subject, body = TEMPLATES.get(step.rung, TEMPLATES[max(TEMPLATES)])
        fill = {"customer": name, "amount": f"{overdue:,.2f}", "currency": str(currency).upper(), "days": days, "company": company_name}
        subject, body = subject.format(**fill), body.format(**fill)
        if parsed_mandate is None:
            autonomy, reason = "ask", "no mandate is in the bundle; the owner sends or approves every reminder"
        else:
            decision = authorise(parsed_mandate, action_kind="chase_overdue", money=overdue, now=at, spent_this_month=spent_this_month, subject=ref)
            autonomy, reason = decision.autonomy, decision.reason
        if step.requires_approval and autonomy == "act":
            autonomy, reason = "ask", f"the collections plan marks rung {step.rung} for the owner's approval"
        delivery = {"capability": _CHANNEL_CAPABILITY.get(step.channel, "gmail.send_email"), "requires_approval": autonomy != "act", "recipient_ref": ref, "subject": subject, "text": body, "effect": "none until sent by the platform" + ("" if autonomy == "act" else " after the owner approves")}
        record_as = {"action_kind": "chase_overdue", "subject": ref, "money": str(overdue), "note": f"rung:{step.rung}", "tool": delivery["capability"]}
        drafts.append({**base, "status": "due", "rung": step.rung, "channel": step.channel, "subject": subject[:300], "body": body[:2000], "autonomy": autonomy, "mandate_reason": reason[:300], "delivery": delivery, "record_as": record_as, "note": f"rung {step.rung} ({step.template_ref}) is due at {step.days_past_due} day(s) past due"})
    due = sum(1 for row in drafts if row["status"] == "due")
    alone = sum(1 for row in drafts if row["status"] == "due" and row.get("autonomy") == "act")
    verdict = f"{total} overdue across {len(drafts)} customer(s); {due} reminder(s) due now, {alone} the agent can send alone" if drafts else "nothing is overdue"
    return seal(ChasePlan, {"company_ref": company_ref, "currency": str(currency).upper(), "as_of": at, "collections_plan_digest": plan.plan_digest, "mandate_digest": None if parsed_mandate is None else parsed_mandate.mandate_digest, "drafts": [{key: value for key, value in row.items() if value is not None} for row in drafts], "overdue_total": str(total), "due_now": due, "act_alone": alone, "verdict": verdict[:300]}, "plan_digest")


class ChaseOutcome(StrictModel):
    customer_ref: OpaqueRef
    rung: int | None = None
    chased_at: str
    overdue_then: Decimal
    overdue_now: Decimal
    recovered: Decimal
    days_since: int = Field(ge=0)

    @field_validator("overdue_then", "overdue_now", "recovered", mode="before")
    @classmethod
    def _numbers(cls, value: Any) -> Decimal:
        return _money(value)


class ChaseOutcomes(StrictModel):
    schema_id: str = Field(default=CHASE_OUTCOMES_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    as_of: str
    outcomes: tuple[ChaseOutcome, ...] = Field(default_factory=tuple, max_length=500)
    chased_total: Decimal
    recovered_total: Decimal
    recovery_percent: Decimal | None = None
    verdict: ShortText
    outcomes_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("outcomes", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("chased_total", "recovered_total", "recovery_percent", mode="before")
    @classmethod
    def _numbers(cls, value: Any) -> Decimal | None:
        return None if value is None else _money(value)

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "ChaseOutcomes":
        if not skip_digests(info) and self.outcomes_digest != sealed_digest(ChaseOutcomes, self, "outcomes_digest"):
            raise ValueError("outcomes_digest must commit the exact outcomes")
        return self

    def render(self) -> str:
        lines = [f"**Chase outcomes** ({self.company_ref}, {self.as_of[:10]}): {self.verdict}"]
        lines.extend(f"- {row.customer_ref}: rung {row.rung} on {row.chased_at[:10]}; {row.overdue_then} then, {row.overdue_now} now, {row.recovered} recovered in {row.days_since} day(s)" for row in self.outcomes)
        return "\n".join(lines)


def score_chases(*, company_ref: str, as_of: str, chased: Sequence[Mapping[str, Any]], overdue_customers: Sequence[Mapping[str, Any]]) -> ChaseOutcomes:
    """Each chase sent (customer_ref, rung, at, money overdue then) against the customer's overdue now: what came back and how fast."""

    at = timestamp(as_of, field_name="as_of")
    now_by_customer = {str(dict(row)["customer_ref"]): _money(dict(row).get("overdue", "0")) for row in overdue_customers}
    rows: list[dict[str, Any]] = []
    chased_total = recovered_total = Decimal("0")
    for item in sorted((dict(detached(row)) for row in chased), key=lambda row: (str(row["at"]), str(row["customer_ref"]))):
        then = _money(item.get("money", "0"))
        now = now_by_customer.get(str(item["customer_ref"]), Decimal("0"))
        recovered = max(Decimal("0"), then - now)
        chased_total += then
        recovered_total += recovered
        rows.append({"customer_ref": str(item["customer_ref"]), "rung": None if item.get("rung") is None else int(item["rung"]), "chased_at": timestamp(str(item["at"]), field_name="at"), "overdue_then": str(then), "overdue_now": str(now), "recovered": str(recovered), "days_since": max(0, (parsed(at) - parsed(timestamp(str(item["at"]), field_name="at"))).days)})
    percent = None if chased_total == 0 else (recovered_total * Decimal(100) / chased_total).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)
    verdict = f"{len(rows)} reminder(s) sent for {chased_total}; {recovered_total} recovered" + (f" ({percent}%)" if percent is not None else "") if rows else "no reminder has been sent yet"
    return seal(ChaseOutcomes, {"company_ref": company_ref, "as_of": at, "outcomes": [{key: value for key, value in row.items() if value is not None} for row in rows], "chased_total": str(chased_total), "recovered_total": str(recovered_total), "recovery_percent": None if percent is None else str(percent), "verdict": verdict[:300]}, "outcomes_digest")


def verify_chase_plan(value: Any) -> ChasePlan:
    return value if isinstance(value, ChasePlan) else ChasePlan.model_validate({key: item for key, item in dict(detached(value)).items() if key not in {"summary", "provider_effect_executed", "documents_built"}})


__all__ = ["CHASE_OUTCOMES_SCHEMA", "CHASE_PLAN_SCHEMA", "COLLECTIONS_LOOP_MANIFEST", "TEMPLATES", "ChaseDraft", "ChaseOutcome", "ChaseOutcomes", "ChasePlan", "CollectionsLoopError", "plan_chases", "score_chases", "verify_chase_plan"]
