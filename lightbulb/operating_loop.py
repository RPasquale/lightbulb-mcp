"""The operating loop: one call that tells an agent running the company what to do next, under the owner's mandate, and what the last session promised.

An agent arriving at the company has close to two hundred tools and no
place to start.  ``plan_next_actions`` gathers every open thread the sealed
documents already hold (the weekly review's actions, the decisions the owner
accepted and their due dates, the hand-offs drafted for the chains, the
books that have gone stale, the hygiene findings, the digest that is due),
turns each into one candidate with the tool to call and the effect to
expect, passes each through the mandate (``act`` alone, ``ask`` the owner,
or ``never``), ranks them by urgency and the money at stake, and returns
the next one with the queue behind it.

The step opens with a briefing: cash and revenue as the books last said,
what is open and overdue, and what the previous session did and promised,
so the next agent picks up exactly where the last one stopped.  Promises
that can be checked against the documents (a customer no longer overdue, a month of
books recorded) are checked and reported.  Nothing here executes anything;
the agent does, and records what it did in the journal.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, CurrencyCode, OpaqueRef, Sha256Digest, StrictModel, decimal_value, detached, parsed, seal, sealed_digest, skip_digests, timestamp
from lightbulb.owner_mandate import authorise, verify_mandate

OPERATING_STEP_SCHEMA = "lightbulb.operating_step.v1"
OPERATOR_JOURNAL_SCHEMA = "lightbulb.operator_journal.v1"
OPERATING_LOOP_MANIFEST: dict[str, Any] = {"engine": "operating_loop", "kind": "intelligence_document", "reads": ("intelligence_review", "review_decisions", "decision_work_items", "sourcing_hand_offs", "books_snapshot", "books_hygiene", "customer_ledger", "operator_journal", "mandate_log", "change_candidate", "software_production_request"), "writes": ("operator_journal",)}
Urgency = Literal["high", "medium", "low"]
StepKind = Literal["do", "decide", "open", "read", "send", "fix", "tell_owner"]
BOOKS_STALE_DAYS = 40
DIGEST_EVERY_DAYS = 7
MAX_QUEUE = 12

# review action kind -> the mandate action kind an agent would need to act on it; anything unlisted is the owner's call
REVIEW_TO_MANDATE: dict[str, str] = {
    "chase_overdue": "chase_overdue",
    "tighten_terms": "message_customer",
    "chase_late_order": "message_supplier",
    "query_contractor_bills": "message_supplier",
    "buy_stock": "reorder_stock",
    "raise_reorder_point": "reorder_stock",
    "buy_deferred": "reorder_stock",
    "reprice_to_floor": "change_price",
    "price_the_sku": "change_price",
    "revert_price": "change_price",
    "apply_price_probe": "change_price",
    "price_probe": "change_price",
    "staff_the_job": "open_requisition",
    "unstaffed_job": "open_requisition",
    "open_requisition": "open_requisition",
    "source_hire": "open_requisition",
    "source_contract": "engage_contractor",
    "cut_returns": "message_supplier",
}
_URGENCY_RANK = {"high": 0, "medium": 1, "low": 2}
_CENT = Decimal("0.01")


class OperatingLoopError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


def _num(value: Any) -> Decimal:
    try:
        return Decimal(str(value)).copy_abs()
    except Exception:
        return Decimal("0")


class NextAction(StrictModel):
    rank: int = Field(ge=1, le=MAX_QUEUE)
    step: StepKind
    key: str = Field(max_length=300)
    source: str = Field(max_length=300)
    subject: str = Field(max_length=300)
    why: str = Field(max_length=300)
    money_at_stake: Decimal
    urgency: Urgency
    action_kind: str | None = Field(default=None, max_length=300)
    autonomy: Literal["act", "ask", "never"]
    mandate_reason: str = Field(max_length=300)
    tool: str = Field(max_length=300)
    operation: str = Field(max_length=300)
    payload_hint: dict[str, Any] = Field(default_factory=dict)
    verify: str = Field(max_length=300)

    @field_validator("money_at_stake", mode="before")
    @classmethod
    def _numbers(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="money_at_stake")


class Briefing(StrictModel):
    period_label: str | None = Field(default=None, max_length=300)
    revenue: Decimal | None = None
    net_profit: Decimal | None = None
    cash: Decimal | None = None
    overdue_receivables: Decimal | None = None
    books_age_days: int | None = None
    open_decisions: int = Field(default=0, ge=0)
    overdue_decisions: int = Field(default=0, ge=0)
    trust: str | None = Field(default=None, max_length=300)
    last_session: dict[str, Any] | None = None
    checked_promises: tuple[str, ...] = Field(default_factory=tuple, max_length=24)

    @field_validator("checked_promises", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("revenue", "net_profit", "cash", "overdue_receivables", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class OperatingStep(StrictModel):
    schema_id: str = Field(default=OPERATING_STEP_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    as_of: str
    mandate_digest: Sha256Digest | None = None
    envelope_spent: Decimal
    briefing: Briefing
    next: NextAction | None = None
    queue: tuple[NextAction, ...] = Field(default_factory=tuple, max_length=MAX_QUEUE)
    by_autonomy: dict[str, int] = Field(default_factory=dict)
    verdict: str = Field(max_length=300)
    step_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("queue", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("envelope_spent", mode="before")
    @classmethod
    def _numbers(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="envelope_spent")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "OperatingStep":
        if [item.rank for item in self.queue] != list(range(1, len(self.queue) + 1)) or (self.next is None) != (len(self.queue) == 0) or (self.next is not None and self.next != self.queue[0]):
            raise ValueError("the queue is ranked from one and next is its head")
        if sum(self.by_autonomy.values()) != len(self.queue):
            raise ValueError("by_autonomy counts the queue")
        if not skip_digests(info) and self.step_digest != sealed_digest(OperatingStep, self, "step_digest"):
            raise ValueError("step_digest must commit the exact step")
        return self

    def render(self) -> str:
        head = f"**Next** ({self.company_ref}, {self.as_of[:10]}): {self.verdict}"
        if self.next is None:
            return head
        lines = [head, f"1. [{self.next.autonomy}] {self.next.step}: {self.next.subject}; {self.next.why}; tool {self.next.tool} {self.next.operation}"]
        lines.extend(f"{item.rank}. [{item.autonomy}] {item.step}: {item.subject}; {item.why}" for item in self.queue[1:])
        return "\n".join(lines)


def plan_next_actions(*, company_ref: str, currency: str, as_of: str, mandate: Mapping[str, Any] | None, spent_this_month: Any = "0", review: Mapping[str, Any] | None = None, work_items: Mapping[str, Any] | None = None, hand_offs: Mapping[str, Any] | None = None, hygiene: Mapping[str, Any] | None = None, books: Mapping[str, Any] | None = None, customer_ledger: Mapping[str, Any] | None = None, journal: Mapping[str, Any] | None = None, last_digest_at: str | None = None, overdue_customers: Sequence[Mapping[str, Any]] = (), changes: Mapping[str, Any] | None = None, releases: Sequence[Mapping[str, Any]] = ()) -> OperatingStep:
    """Every open thread as one ranked queue under the mandate, with the briefing and the last session's promises checked."""

    at = timestamp(as_of, field_name="as_of")
    currency = str(currency).upper()
    parsed_mandate = None if mandate is None else verify_mandate(mandate)
    spent = decimal_value(spent_this_month, field_name="spent_this_month")
    review, work_items, hand_offs, hygiene, books, customer_ledger, journal = (None if item is None else dict(detached(item)) for item in (review, work_items, hand_offs, hygiene, books, customer_ledger, journal))
    candidates: list[dict[str, Any]] = []

    def gate(action_kind: str | None, money: Decimal, subject: str) -> tuple[str, str]:
        if action_kind is None:
            return "ask", "no mandate covers advice the owner has to weigh; it is their call"
        if parsed_mandate is None:
            from lightbulb.owner_mandate import ACTION_KINDS

            if ACTION_KINDS.get(action_kind, {}).get("effect") == "read":
                return "act", "reads never need a mandate"
            return "ask", "no mandate is in the bundle; until the owner gives one the agent asks about everything but reads"
        decision = authorise(parsed_mandate, action_kind=action_kind, money=money, now=at, spent_this_month=spent, subject=subject)
        return decision.autonomy, decision.reason

    def add(step: str, key: str, source: str, subject: str, why: str, money: Decimal, urgency: str, action_kind: str | None, tool: str, operation: str, payload: Mapping[str, Any], verify: str, reason: str | None = None) -> None:
        autonomy, gate_reason = gate(action_kind, money, subject)
        reason = gate_reason if reason is None else reason
        candidates.append({"step": step, "key": key[:300], "source": source, "subject": subject[:300], "why": why[:300], "money_at_stake": str(money.quantize(_CENT)), "urgency": urgency, "action_kind": action_kind, "autonomy": autonomy, "mandate_reason": reason[:300], "tool": tool, "operation": operation, "payload_hint": dict(payload), "verify": verify[:300]})

    # the books: read before anything else when they are stale or missing
    books_age = None
    if books is None:
        add("read", "books:record", "books_snapshot", "the books", "no month of books is on record, so nothing else can be trusted", Decimal("0"), "high", "read_ledger", "company_backfill", "plan", {"months": 12}, "company_books list shows at least one month")
    else:
        books_age = (parsed(at) - parsed(str(books["window_end"]))).days
        if books_age > BOOKS_STALE_DAYS:
            add("read", f"books:record:{str(books['window_end'])[:10]}", "books_snapshot", "the books", f"the latest month on record ended {books_age} days ago; read the months since", Decimal("0"), "high", "read_ledger", "company_backfill", "record", {"sources": "the reads the backfill plan lists for the missing months"}, "company_books list shows the missing months recorded")

    # accepted decisions with a date: do them, overdue first
    open_items = overdue_items = 0
    if work_items is not None:
        for item in work_items.get("items", ()):
            open_items += 1
            overdue = item.get("status") == "overdue"
            overdue_items += int(overdue)
            kind = REVIEW_TO_MANDATE.get(str(item.get("kind")))
            add("do", str(item.get("item_ref") or item.get("key")), "decision_work_items", f"{item.get('kind')}: {item.get('subject')}", ("overdue since " if overdue else "due ") + str(item.get("due_at", ""))[:10] + "; the owner accepted this", _num(item.get("money_at_stake")), "high" if overdue else "medium", kind, "company_supply", "supply", {"action_id": item.get("item_ref"), "receipt": {"outcome": "done", "note": "what was done"}}, "the work item closes with an outcome in company_decision_work_items")

    # hand-offs the owner accepted and the chains can open
    if hand_offs is not None:
        for draft in hand_offs.get("drafts", ()):
            if draft.get("status") != "drafted":
                continue
            chain = "company_hiring" if draft.get("chain") == "hiring_chain" else "company_contractors"
            kind = "open_requisition" if draft.get("chain") == "hiring_chain" else "engage_contractor"
            add("open", str(draft.get("key")), "sourcing_hand_offs", f"{draft.get('route')}: {draft.get('subject')}", str(draft.get("next_step", ""))[:300], _num(dict(draft.get("brief") or {}).get("monthly_cap") or dict(draft.get("receipt") or {}).get("pay_rate")), "medium", kind, chain, "open", {"receipt": draft.get("receipt") or draft.get("brief")}, f"{chain} list shows the new case")

    # the review's actions the owner has not decided: do the ones the mandate covers, ask about the rest
    if review is not None:
        for action in review.get("actions", ()):
            if action.get("decision") is not None:
                continue
            kind = REVIEW_TO_MANDATE.get(str(action.get("kind")))
            key = f"{action.get('source')}:{action.get('kind')}:{action.get('subject')}"
            tool, operation, payload = ("company_review_decisions", "record", {"decisions": [{"key": key, "decision": "accept", "owner_ref": "the owner", "due_at": "a date"}]})
            add("decide" if kind is None else "do", key, str(action.get("source")), f"{action.get('kind')}: {action.get('subject')}", str(action.get("detail", ""))[:300], _num(action.get("money_at_stake")), str(action.get("severity", "medium")), kind, tool, operation, payload, "the action carries a decision in the next review, and its subject clears in the document that raised it")

    # money overdue across every recorded month's ledger (a month page only shows its own invoices, so the latest review alone would miss last quarter's)
    raised = {row["key"] for row in candidates}
    for customer in overdue_customers:
        customer = dict(customer)
        key = f"customer_ledger:chase_overdue:{customer.get('name')}"
        if key in raised or _num(customer.get("overdue")) <= 0:
            continue
        oldest = int(customer.get("oldest_overdue_days", 0) or 0)
        add("do", key, "customer_ledger", f"chase_overdue: {customer.get('name')}", f"{customer.get('overdue')} overdue, the oldest {oldest} day(s) past due ({customer.get('windows', '')})", _num(customer.get("overdue")), "high" if oldest > 45 else "medium", "chase_overdue", "company_act", "plan", {"then": "dispatch with connector_account_refs {gmail.send_email: the project's account}; the platform asks the owner unless the mandate lets the agent act, sends once, and the action records the receipt (sends under act are logged in the mandate log)"}, "the customer's overdue balance falls in the re-read ledger for those months")
    # the software: requests waiting on the owner's budget, requests the platform has not run yet, and what users reported that no one has looked at
    if changes is not None:
        for row in changes.get("requests", ()):
            row = dict(row)
            decision = dict(row.get("decision") or {})
            digest = str(row.get("request_digest", ""))
            if decision.get("autonomy") == "ask":
                add("decide", f"change:{digest[:12]}", "change_candidate", f"open_change: {row.get('title')}", f"a coding budget of {decision.get('money')} needs the owner's yes: {decision.get('reason')}", _num(decision.get("money")), "medium", "open_change", "company_changes", "compile", {"candidate_ref": row.get("candidate_ref"), "coding_budget": "the budget the owner approves, or decline the candidate"}, "the request's decision says act and the mandate log carries the run")
            elif decision.get("autonomy") == "act" and not row.get("dispatched"):
                add("do", f"change:{digest[:12]}:dispatch", "change_candidate", f"open_change: {row.get('title')}", "the mandate lets the agent open this change; the platform issues the grant and runs it", _num(decision.get("money")), "medium", "open_change", "platform.software_factory", "dispatch", {"request_digest": digest, "decision_digest": decision.get("decision_digest")}, "the mandate log carries the open_change decision with the run as its effect")
        for row in changes.get("candidates", ()):
            row = dict(row)
            if row.get("lifecycle") != "new":
                continue
            needs = ", ".join(str(item) for item in row.get("needs", ()))
            add("decide", f"candidate:{str(row.get('candidate_ref', ''))[:12]}", "change_candidate", f"{row.get('kind')}: {row.get('title')}", f"reported through {row.get('source')} on {str(row.get('received_at', ''))[:10]}; still needs {needs or 'nothing'}" + ("; carries instruction-like phrases" if row.get("injection_flags") else ""), Decimal("0"), "high" if row.get("source") in {"incident", "error_signal"} else "low", None, "company_changes", "compile", {"candidate_ref": row.get("candidate_ref"), "acceptance_criteria": "when the change is done", "coding_budget": "what it may cost", "workspace_binding_ref": "the workspace"}, "the candidate shows as compiled or declined in company_changes status", reason="the owner decides whether it is built at all: compile it with a budget, or decline it")

    # a release that regressed: rolling back is a deploy, the owner's call, which the platform performs
    for health in releases:
        health = dict(health)
        if health.get("verdict") != "regressed":
            continue
        release = dict(health.get("release") or {})
        add("decide", f"release:{health.get('app_ref')}:{release.get('release_ref')}", "app_signals", f"roll back {health.get('app_ref')} to {health.get('rollback_to')}", f"release {release.get('release_ref')} regressed: {health.get('reason')}", Decimal("0"), "high", "deploy", "platform.software_factory", "roll_back", {"app_ref": health.get("app_ref"), "to_release": health.get("rollback_to")}, "the next release health reads healthy, or the owner declines with a reason", reason="rolling back is a deploy; the owner decides it and the platform performs it")

    # the books' hygiene: the owner or their bookkeeper fixes these, so they are told, not acted on
    trust = None
    if hygiene is not None:
        trust = str(hygiene.get("trust") or "")
        for finding in hygiene.get("findings", ()):
            add("fix", f"hygiene:{finding.get('code')}", "books_hygiene", str(finding.get("what", ""))[:300], str(finding.get("fix", ""))[:300], _num(finding.get("money")), str(finding.get("severity", "medium")), None, "company_hygiene", "build", {}, "the finding is gone from the next hygiene run")

    # the weekly digest, when a week has passed since the last one
    if last_digest_at is None or (parsed(at) - parsed(last_digest_at)).days >= DIGEST_EVERY_DAYS:
        add("send", "digest:weekly", "owner_digest", "the owner's weekly digest", "a week has passed since the last digest" if last_digest_at else "the owner has not had a digest yet", Decimal("0"), "low", "send_digest", "company_act", "plan", {"digest_channel": "in_app", "then": "dispatch; the platform delivers the week's digest to the owner inside the platform once (email and Slack stay blocked until the communication lane has a source for internal recipients)"}, "the digest action is done with the platform's receipt")

    candidates.sort(key=lambda row: (_URGENCY_RANK[row["urgency"]], {"act": 0, "ask": 1, "never": 2}[row["autonomy"]], -Decimal(row["money_at_stake"]), row["key"]))
    queue = [{**row, "rank": index + 1} for index, row in enumerate(candidates[:MAX_QUEUE])]
    by_autonomy: dict[str, int] = {}
    for row in queue:
        by_autonomy[row["autonomy"]] = by_autonomy.get(row["autonomy"], 0) + 1

    # the briefing and the last session's promises, checked where a document can check them
    checked: list[str] = []
    last_session = None
    if journal is not None:
        last_session = {"at": journal.get("at"), "agent_ref": journal.get("agent_ref"), "did": list(journal.get("did", ()))[:12], "promised": list(journal.get("promised", ()))[:12]}
        for promise in journal.get("promised", ()):
            promise = dict(promise)
            kind, subject = str(promise.get("check", "")), str(promise.get("subject", ""))
            if kind == "customer_paid" and customer_ledger is not None:
                row = next((row for row in customer_ledger.get("rows", ()) if str(row.get("customer_ref")) == subject or str(row.get("name")) == subject), None)
                checked.append(f"{subject}: " + ("not in the customer ledger" if row is None else (f"still {row.get('overdue')} overdue" if Decimal(str(row.get("overdue", "0"))) > 0 else "nothing overdue in the customer ledger")))
            elif kind == "books_recorded" and books is not None:
                checked.append(f"books for {subject}: " + ("recorded" if str(books.get("window_start", ""))[:7] <= subject <= str(books.get("window_end", ""))[:7] else "not yet on record"))
            else:
                checked.append(f"{kind} {subject}: cannot be checked from the documents; the agent confirms it")
    briefing = {"period_label": None if books is None else books.get("period_label"), "revenue": None if books is None else books.get("revenue"), "net_profit": None if books is None else books.get("net_profit"), "cash": None if books is None else books.get("cash"), "overdue_receivables": None if customer_ledger is None else customer_ledger.get("overdue"), "books_age_days": books_age, "open_decisions": open_items, "overdue_decisions": overdue_items, "trust": trust, "last_session": last_session, "checked_promises": checked[:24]}
    acts = by_autonomy.get("act", 0)
    verdict = (f"{len(queue)} thing(s) to do; {acts} the agent can do alone, {by_autonomy.get('ask', 0)} to ask the owner about" + (f", {by_autonomy['never']} the owner ruled out" if by_autonomy.get("never") else "") if queue else "nothing is waiting: the books are current, no decision is open and the digest has gone") + ("" if parsed_mandate is not None else "; no mandate is in the bundle")
    return seal(OperatingStep, {"company_ref": company_ref, "currency": currency, "as_of": at, "mandate_digest": None if parsed_mandate is None else parsed_mandate.mandate_digest, "envelope_spent": str(spent), "briefing": briefing, "next": queue[0] if queue else None, "queue": queue, "by_autonomy": by_autonomy, "verdict": verdict[:300]}, "step_digest")


class OperatorJournal(StrictModel):
    schema_id: str = Field(default=OPERATOR_JOURNAL_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    at: str
    agent_ref: OpaqueRef
    step_digest: Sha256Digest | None = None
    did: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=100)
    promised: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=100)
    handover: str = Field(max_length=2000)
    journal_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("did", "promised", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("at")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="at")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "OperatorJournal":
        for promise in self.promised:
            if not promise.get("check") or not promise.get("subject"):
                raise ValueError("a promise names what to check and its subject")
        if not skip_digests(info) and self.journal_digest != sealed_digest(OperatorJournal, self, "journal_digest"):
            raise ValueError("journal_digest must commit the exact entry")
        return self


def write_journal(*, company_ref: str, at: str, agent_ref: str, handover: str, did: Sequence[Mapping[str, Any]] = (), promised: Sequence[Mapping[str, Any]] = (), step_digest: str | None = None) -> OperatorJournal:
    """One session's entry: what the agent did (each with the key it acted on and the result), what it promised to check next time, and the handover in its own words."""

    return seal(OperatorJournal, {"company_ref": company_ref, "at": timestamp(at, field_name="at"), "agent_ref": agent_ref, "step_digest": step_digest, "did": [dict(detached(item)) for item in did], "promised": [dict(detached(item)) for item in promised], "handover": str(handover)[:2000]}, "journal_digest")


def verify_operating_step(value: Any) -> OperatingStep:
    return value if isinstance(value, OperatingStep) else OperatingStep.model_validate({key: item for key, item in dict(detached(value)).items() if key not in {"summary", "provider_effect_executed", "documents_built"}})


def verify_operator_journal(value: Any) -> OperatorJournal:
    return value if isinstance(value, OperatorJournal) else OperatorJournal.model_validate({key: item for key, item in dict(detached(value)).items() if key not in {"summary", "provider_effect_executed", "version"}})


__all__ = ["BOOKS_STALE_DAYS", "DIGEST_EVERY_DAYS", "OPERATING_LOOP_MANIFEST", "OPERATING_STEP_SCHEMA", "OPERATOR_JOURNAL_SCHEMA", "REVIEW_TO_MANDATE", "Briefing", "NextAction", "OperatingLoopError", "OperatingStep", "OperatorJournal", "plan_next_actions", "verify_operating_step", "verify_operator_journal", "write_journal"]
