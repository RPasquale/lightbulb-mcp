"""The owner's weekly digest: the week's documents said in plain words, with the three things worth doing and what we cannot tell yet.

Every document the SDK builds is exact, sealed and written for the record.
None of it is written for an owner reading on a phone on Monday morning.
``build_owner_digest`` takes the documents already built for the week (the
latest books, the history across the recorded months, the cash calendar,
the weekly review and the open decision work items) and says what they
mean: how the last period went against the one before, the figures that
matter with their change, the three actions ranked by the money at stake
(each with a one-tap accept, defer or decline keyed to the review's own
action key), the figures that have moved the wrong way three periods
running, and the things the digest cannot say yet and why.

Nothing is invented and nothing is estimated here.  Every sentence is a
fixed template filled from a sealed figure, and every figure keeps the
document it came from in ``source_digests``.  A document that was not built
is left out and named in ``unknowns``; a figure the books do not hold is
never shown as zero.  The digest sends nothing: delivery is a separate,
approval-gated send the platform performs.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import ROUND_HALF_UP, Decimal
from typing import Any

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, CurrencyCode, OpaqueRef, Sha256Digest, ShortText, StrictModel, decimal_value, detached, parsed, seal, sealed_digest, skip_digests, timestamp

OWNER_DIGEST_SCHEMA = "lightbulb.owner_digest.v1"
OWNER_DIGEST_MANIFEST: dict[str, Any] = {"engine": "owner_digest", "kind": "intelligence_document", "reads": ("books_snapshot", "intelligence_history", "books_cash_forecast", "intelligence_review", "decision_work_items"), "writes": ()}
MAX_ACTIONS = 3
CHOICES: tuple[str, ...] = ("accept", "defer", "decline")

# metric -> (what the owner calls it, unit, the direction that is good)
METRIC_WORDS: dict[str, tuple[str, str, str]] = {
    "revenue": ("Sales", "money", "up"),
    "net_margin_percent": ("What you keep from each sale", "percent", "up"),
    "cash": ("Cash in the bank", "money", "up"),
    "cash_net_of_tax": ("Cash after the tax you owe", "money", "up"),
    "cost_share_percent": ("Costs as a share of sales", "percent", "flat"),
    "cash_conversion_days": ("Days from paying for work to being paid for it", "days", "down"),
    "overdue_receivables": ("Money owed to you that is overdue", "money", "down"),
    "top_customer_share_percent": ("Your biggest customer's share of sales", "percent", "down"),
    "margin_of_safety_percent": ("How far sales could fall before you lose money", "percent", "up"),
    "lowest_cash_13_weeks": ("Lowest cash over the next 13 weeks", "money", "up"),
    "hours_short": ("Hours of work nobody is free to do", "hours", "down"),
    "tie_out_differences": ("Figures that disagree with your books", "count", "down"),
    "open_actions": ("Decisions still open", "count", "down"),
}
# review action kind -> the sentence an owner reads ({subject} is the customer, product, job or account it concerns; the books' own findings carry a code as subject, so their sentences leave it out)
ACTION_WORDS: dict[str, str] = {
    "chase_overdue": "Chase {subject} for what they owe",
    "tighten_terms": "Ask {subject} to pay sooner",
    "reduce_concentration": "Win work beyond {subject}, who carries too much of your sales",
    "reconcile_to_the_books": "Check why {subject} disagrees with your books",
    "close_break_even_gap": "Close the gap to break-even",
    "thin_margin_of_safety": "Build a cushion: sales are close to the point where you lose money",
    "free_working_capital": "Free up cash tied up in {subject}",
    "staff_the_job": "Find the hours for {subject}",
    "unstaffed_job": "Find someone for {subject}",
    "capacity_shortfall": "Plan for the hours {subject} will need",
    "key_person_risk": "Train a second person in {subject}",
    "licence_lapsing": "Renew the licence for {subject} before it lapses",
    "quote_underquoted": "Reprice work like {subject}: it was quoted too low",
    "quote_overran": "Look at why {subject} ran over its quote",
    "reprice_to_floor": "Raise the price of {subject} to at least its floor",
    "losing_sku": "Stop selling {subject} at a loss",
    "buy_stock": "Reorder {subject}",
    "raise_reorder_point": "Reorder {subject} earlier",
    "chase_late_order": "Chase the late order {subject}",
    "fix_drain_customer": "Fix or reprice {subject}, who costs more to serve than they bring",
    "grow_customer": "Grow {subject}, who is profitable to serve",
    "complete_the_books": "Complete your books",
    "stop_the_loss": "Stop the loss",
    "cover_the_overdraft": "Cover the overdraft",
    "reserve_the_tax": "Put aside the tax you owe",
    "single_source_supplier": "Find a second supplier for {subject}",
    "query_contractor_bills": "Query the contractor bills for {subject}",
}
# document kind -> what the owner cannot be told without it
UNKNOWN_WORDS: dict[str, str] = {
    "books_snapshot": "how the business did, until your books are read",
    "intelligence_history": "whether things are getting better or worse, until more than one month is on record",
    "books_cash_forecast": "when cash runs lowest, until a balance sheet is read with your books",
    "intelligence_review": "what to do this week, until the weekly review has run",
    "customer_ledger": "who owes you money and how late they pay, until your sales invoices are read",
    "working_capital": "how much cash is tied up in unpaid invoices and stock",
    "break_even": "how far sales could fall before you lose money",
    "skills_match": "who can do which job",
}
_FINDING_WORDS: dict[str, str] = {
    "NO_COSTS_RECORDED": "Your books show no costs at all, so every margin here looks better than it really is.",
    "COSTS_IMPLAUSIBLY_LOW": "Your books show very few costs, so margins here likely look better than they really are.",
    "NO_LABOUR_COST_RECORDED": "Your books record no wages or contractor costs, so the cost of your time is missing.",
    "SUSPENSE_BALANCE": "Some money sits in a suspense account and has not been put anywhere yet.",
}
_ZERO = Decimal("0")


class OwnerDigestError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise OwnerDigestError(code, message)


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


def _num(value: Any) -> Decimal | None:
    if value is None:
        return None
    try:
        return Decimal(str(value))
    except Exception:
        return None


def money(value: Decimal, currency: str) -> str:
    """Whole units with thousands separators and the currency code, e.g. ``AUD 84,500``; negatives read ``-AUD 1,200``."""

    rounded = value.quantize(Decimal("1"), rounding=ROUND_HALF_UP)
    return ("-" if rounded < 0 else "") + f"{currency} {abs(rounded):,}"


def _figure(value: Decimal, unit: str, currency: str) -> str:
    if unit == "money":
        return money(value, currency)
    if unit == "percent":
        return f"{value.quantize(Decimal('0.1'), rounding=ROUND_HALF_UP)}%"
    if unit == "days":
        return f"{value.quantize(Decimal('1'), rounding=ROUND_HALF_UP)} days"
    if unit == "hours":
        return f"{value.quantize(Decimal('1'), rounding=ROUND_HALF_UP)} hours"
    return f"{value.quantize(Decimal('1'), rounding=ROUND_HALF_UP)}"


def _change(delta: Decimal, unit: str, currency: str) -> str:
    sign = "+" if delta > 0 else ("-" if delta < 0 else "")
    if unit == "money":
        return sign + money(abs(delta), currency)
    if unit == "percent":
        return f"{sign}{abs(delta).quantize(Decimal('0.1'), rounding=ROUND_HALF_UP)} points"
    return f"{sign}{_figure(abs(delta), unit, currency)}"


class DigestFigure(StrictModel):
    metric: ShortText
    label: ShortText
    value: ShortText
    change: ShortText | None = None
    verdict: ShortText


class DigestAction(StrictModel):
    rank: int = Field(ge=1, le=MAX_ACTIONS)
    key: ShortText
    headline: ShortText
    why: ShortText
    money_at_stake: Decimal
    severity: ShortText
    choices: tuple[ShortText, ...] = CHOICES
    decided: ShortText | None = None

    @field_validator("money_at_stake", mode="before")
    @classmethod
    def _numbers(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="money_at_stake", allow_negative=True)

    @field_validator("choices", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)


class OwnerDigest(StrictModel):
    schema_id: str = Field(default=OWNER_DIGEST_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    company_name: ShortText
    currency: CurrencyCode
    as_of: str
    subject: ShortText
    opening: ShortText
    figures: tuple[DigestFigure, ...] = Field(default_factory=tuple, max_length=8)
    actions: tuple[DigestAction, ...] = Field(default_factory=tuple, max_length=MAX_ACTIONS)
    warnings: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=6)
    cautions: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=6)
    decisions_line: ShortText | None = None
    software_line: ShortText | None = None
    due_this_month: tuple[dict[str, Any], ...] | None = None
    missing_calendar_facts: tuple[str, ...] | None = None
    unknowns: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=6)
    source_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=12)
    digest_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("figures", "actions", "warnings", "cautions", "unknowns", "source_digests", "due_this_month", "missing_calendar_facts", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("as_of")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="as_of")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "OwnerDigest":
        if [action.rank for action in self.actions] != list(range(1, len(self.actions) + 1)):
            raise ValueError("the actions are ranked one, two, three")
        if len({action.key for action in self.actions}) != len(self.actions):
            raise ValueError("each action appears once")
        if not skip_digests(info) and self.digest_digest != sealed_digest(OwnerDigest, self, "digest_digest"):
            raise ValueError("digest_digest must commit the exact digest")
        return self

    def render_text(self) -> str:
        """The digest as a plain-text message: the subject line, then short paragraphs an owner reads in under a minute."""

        lines = [self.subject, "", self.opening]
        if self.figures:
            lines += [""] + [f"- {row.label}: {row.value}" + (f" ({row.change})" if row.change else "") for row in self.figures]
        if self.actions:
            lines += ["", "This week:"] + [f"{row.rank}. {row.headline}" + (f" ({money(row.money_at_stake, self.currency)} at stake)" if row.money_at_stake > 0 else "") + f". {row.why}" for row in self.actions]
        if self.warnings:
            lines += ["", "Keep an eye on:"] + [f"- {item}" for item in self.warnings]
        if self.cautions:
            lines += [""] + list(self.cautions)
        if self.decisions_line:
            lines += ["", self.decisions_line]
        if self.software_line:
            lines += ["", self.software_line]
        if self.due_this_month:
            lines += ["", "Due this month (amounts require a liability read):"] + [f"- {row['due_on']}: {row['kind']}" + (" [needs confirmation]" if row.get("status") == "needs_confirmation" else "") + f" ({row['basis']})" for row in self.due_this_month]
        if self.missing_calendar_facts:
            lines += ["", "Calendar facts to confirm:"] + [f"- {item}" for item in self.missing_calendar_facts]
        if self.unknowns:
            lines += ["", "What we can't tell you yet:"] + [f"- {item}" for item in self.unknowns]
        return "\n".join(lines)

    def render(self) -> str:
        return f"**Owner digest** ({self.company_ref}, {self.as_of[:10]}): {self.subject}"


_PRESENTATION = frozenset({"summary", "provider_effect_executed", "documents_built", "gaps", "text", "delivery", "version"})


def _verified(kind: str, value: Mapping[str, Any] | None) -> dict[str, Any] | None:
    """The document re-verified against its own seal (display fields a console adds are dropped), as a plain dict; ``None`` stays ``None``."""

    if value is None:
        return None
    raw = {key: item for key, item in dict(detached(value)).items() if key not in _PRESENTATION}
    if kind == "books_snapshot":
        from lightbulb.books_snapshot import verify_books_snapshot as verify
    elif kind == "intelligence_history":
        from lightbulb.intelligence_history import verify_intelligence_history as verify
    elif kind == "books_cash_forecast":
        from lightbulb.books_cash_forecast import verify_books_cash_forecast as verify
    elif kind == "intelligence_review":
        from lightbulb.intelligence_review import verify_intelligence_review as verify
    else:
        return raw
    return verify(raw).to_dict()


def build_owner_digest(*, company_ref: str, company_name: str, currency: str, as_of: str, books: Mapping[str, Any] | None = None, history: Mapping[str, Any] | None = None, cash_calendar: Mapping[str, Any] | None = None, review: Mapping[str, Any] | None = None, work_items: Mapping[str, Any] | None = None, missing: Sequence[str] = (), changes: Mapping[str, Any] | None = None, releases: Sequence[Mapping[str, Any]] = (), australia_calendar: Mapping[str, Any] | None = None, canada_calendar: Mapping[str, Any] | None = None) -> OwnerDigest:
    """The week's documents said plainly: the opening, the figures with their change, three ranked actions, the warnings, and what cannot be said yet."""

    at = timestamp(as_of, field_name="as_of")
    currency = str(currency).upper()
    books, history, cash_calendar, review = _verified("books_snapshot", books), _verified("intelligence_history", history), _verified("books_cash_forecast", cash_calendar), _verified("intelligence_review", review)
    work_items = _verified("decision_work_items", work_items)
    for kind, document in (("books_snapshot", books), ("intelligence_history", history), ("books_cash_forecast", cash_calendar), ("intelligence_review", review)):
        if document is not None:
            _require(document.get("company_ref") == company_ref, "SOURCE_SCOPE_MISMATCH", f"the {kind} names another company")
            if document.get("currency") is not None:
                _require(str(document["currency"]).upper() == currency, "SOURCE_SCOPE_MISMATCH", f"the {kind} is in {document['currency']}, not {currency}")
    digests: list[str] = []
    for document in (books, history, cash_calendar, review):
        if document is not None:
            found = next((value for key, value in document.items() if key.endswith("_digest") and key not in {"plan_digest", "books_digest", "margin_report_digest", "history_digest_before"} and isinstance(value, str) and len(value) == 64), None)
            if found:
                digests.append(found)
    unknowns: list[str] = []

    # the opening: how the last period went, and against the one before when the history holds it
    series = {row["metric"]: row for row in (history or {}).get("series", ())}
    if books is not None:
        revenue, net = _num(books.get("revenue")) or _ZERO, _num(books.get("net_profit")) or _ZERO
        margin = _num(books.get("net_margin_percent"))
        opening = f"In {books.get('period_label')} you took in {money(revenue, currency)} and " + (f"kept {money(net, currency)}" if net >= 0 else f"lost {money(-net, currency)}") + (f" ({_figure(margin, 'percent', currency)} of sales)." if margin is not None and net >= 0 else ".")
        change = _num(series.get("revenue", {}).get("change"))
        if change is not None and change != 0:
            opening += f" Sales were {money(abs(change), currency)} {'up' if change > 0 else 'down'} on the month before."
    else:
        opening = "Your books have not been read yet, so this digest can only say what is below."
        unknowns.append(f"We can't tell you {UNKNOWN_WORDS['books_snapshot']}.")

    # the figures: the history's latest with its change, else the books alone
    figures: list[dict[str, Any]] = []
    wanted = ("revenue", "net_margin_percent", "cash", "overdue_receivables", "lowest_cash_13_weeks")
    for metric in wanted:
        label, unit, good = METRIC_WORDS[metric]
        row = series.get(metric)
        value = _num(row.get("latest")) if row else None
        if value is None and metric == "cash" and books is not None:
            value = _num(books.get("cash"))
        if value is None and metric == "revenue" and books is not None:
            value = _num(books.get("revenue"))
        if value is None and metric == "lowest_cash_13_weeks" and cash_calendar is not None:
            value = _num(cash_calendar.get("lowest_cash"))
        if value is None:
            continue
        delta = _num(row.get("change")) if row else None
        if delta is None or delta == 0 or good == "flat":
            verdict = "steady" if delta == 0 else "first reading" if delta is None else "changed"
        else:
            verdict = "better" if (delta > 0) == (good == "up") else "worse"
        figures.append({"metric": metric, "label": label, "value": _figure(value, unit, currency), "change": None if delta is None or delta == 0 else _change(delta, unit, currency), "verdict": verdict})

    # cash: say plainly when the calendar runs short
    cautions: list[str] = []
    if cash_calendar is not None:
        lowest = _num(cash_calendar.get("lowest_cash"))
        week = cash_calendar.get("lowest_cash_week")
        if lowest is not None and lowest < 0:
            cautions.append(f"On the payments we know about, you would be {money(-lowest, currency)} short" + (f" in week {week} of the next 13." if week else "."))
    elif books is not None:
        unknowns.append(f"We can't tell you {UNKNOWN_WORDS['books_cash_forecast']}.")
    for finding in (books or {}).get("findings", ()):
        words = _FINDING_WORDS.get(str(dict(finding).get("code")))
        if words and words not in cautions:
            cautions.append(words)

    # the three actions: undecided first, then by the review's rank (money at stake)
    actions: list[dict[str, Any]] = []
    if review is not None:
        from lightbulb.review_decisions import action_key

        ranked = sorted(review.get("actions", ()), key=lambda row: (row.get("decision") is not None, int(row.get("rank", 0))))
        for row in ranked[:MAX_ACTIONS]:
            template = ACTION_WORDS.get(str(row["kind"]))
            subject = str(row["subject"])
            headline = template.format(subject=subject) if template else f"{str(row['kind']).replace('_', ' ').capitalize()}: {subject}"
            actions.append({"rank": len(actions) + 1, "key": action_key(str(row["source"]), str(row["kind"]), subject), "headline": headline[:300], "why": str(row["detail"])[:300], "money_at_stake": str(row["money_at_stake"]), "severity": str(row["severity"]), "decided": row.get("decision")})
        for kind in list(review.get("blind_spots", ()))[:4]:
            if kind in UNKNOWN_WORDS and len(unknowns) < 6:
                unknowns.append(f"We can't tell you {UNKNOWN_WORDS[kind]}.")
    else:
        unknowns.append(f"We can't tell you {UNKNOWN_WORDS['intelligence_review']}.")

    # the software: a change waiting on the owner's budget is an action; the rest is one line
    software_line = None
    if changes is not None:
        changes = dict(detached(changes))
        requests = [dict(row) for row in changes.get("requests", ())]
        waiting = [row for row in requests if dict(row.get("decision") or {}).get("autonomy") == "ask"]
        building = [row for row in requests if dict(row.get("decision") or {}).get("autonomy") == "act" and row.get("dispatched")]
        ready = [row for row in requests if dict(row.get("decision") or {}).get("autonomy") == "act" and not row.get("dispatched")]
        new = [dict(row) for row in changes.get("candidates", ()) if dict(row).get("lifecycle") == "new"]
        for row in waiting:
            if len(actions) >= MAX_ACTIONS:
                break
            decision = dict(row["decision"])
            amount = _num(decision.get("money")) or _ZERO
            actions.append({"rank": len(actions) + 1, "key": f"change:{str(row.get('request_digest', ''))[:12]}", "headline": f"Approve {money(amount, currency)} to build: {row.get('title')}"[:300], "why": str(decision.get("reason", ""))[:300], "money_at_stake": str(amount), "severity": "medium", "decided": None})
        parts = []
        if waiting:
            parts.append(f"{len(waiting)} change(s) waiting on your budget ({money(sum((_num(dict(row['decision']).get('money')) or _ZERO for row in waiting), _ZERO), currency)})")
        if building:
            parts.append(f"{len(building)} being built")
        if ready:
            parts.append(f"{len(ready)} ready to build")
        if new:
            parts.append(f"{len(new)} new report(s) from users not yet looked at")
        if parts:
            software_line = ("Software: " + ", ".join(parts) + ".")[:300]

    # the warnings: a release that regressed first, then what has moved the wrong way three periods running, in the owner's words
    warnings: list[str] = []
    for health in releases:
        health = dict(detached(health))
        if health.get("verdict") == "regressed":
            release = dict(health.get("release") or {})
            warnings.append(f"The latest release of {health.get('app_ref')} ({release.get('release_ref')}) is failing more than the one before: {health.get('reason')}. Say if you want it rolled back to {health.get('rollback_to')}."[:300])
    for metric, row in series.items():
        if int(row.get("declining_windows", 0)) >= 3 and metric in METRIC_WORDS:
            label, unit, _good = METRIC_WORDS[metric]
            values = [Decimal(str(value)) for value in row.get("values", ())]
            count = int(row["declining_windows"])
            first, last = values[-count - 1], values[-1]
            verb = "have" if label.split()[0].endswith("s") else "has"
            warnings.append(f"{label} {verb} moved the wrong way {count} months running, from {_figure(first, unit, currency)} to {_figure(last, unit, currency)}.")
    if history is None and books is not None:
        unknowns.append(f"We can't tell you {UNKNOWN_WORDS['intelligence_history']}.")
    for kind in missing:
        if kind in UNKNOWN_WORDS and len(unknowns) < 6:
            sentence = f"We can't tell you {UNKNOWN_WORDS[kind]}."
            if sentence not in unknowns:
                unknowns.append(sentence)

    decisions_line = None
    if work_items is not None:
        open_count, overdue = int(work_items.get("open", 0)), int(work_items.get("overdue", 0))
        if open_count:
            decisions_line = f"You have {open_count} decision(s) you said you would act on" + (f", {overdue} of them overdue." if overdue else ", none overdue.")

    calendar_fields = {"missing_calendar_facts": ["The compliance calendar could not be read; statutory deadlines are unavailable."]} if "compliance_calendar" in missing else {}
    if australia_calendar is not None:
        from lightbulb.australia_obligations import AustraliaObligationsCalendar, due_this_month
        au = AustraliaObligationsCalendar.model_validate(detached(australia_calendar))
        due = due_this_month(au, company_ref=company_ref, as_of=at)
        gaps = list(au.missing_facts)
        if not au.start_on <= at[:10] < au.end_on:
            gaps.append("Refresh the statutory calendar: this digest is outside its coverage")
        calendar_fields = {"due_this_month": due, "missing_calendar_facts": gaps}
        digests.insert(0, au.calendar_digest)
    if canada_calendar is not None:
        from lightbulb.canada_obligations import CanadaObligationsCalendar, due_this_month
        ca = CanadaObligationsCalendar.model_validate(detached(canada_calendar))
        due = due_this_month(ca, company_ref=company_ref, as_of=at)
        gaps = list(ca.missing_facts)
        if not ca.start_on <= at[:10] < ca.end_on:
            gaps.append("Refresh the statutory calendar: this digest is outside its coverage")
        calendar_fields = {"due_this_month": due, "missing_calendar_facts": gaps}
        digests.insert(0, ca.calendar_digest)
    headline = actions[0]["headline"] if actions else (warnings[0] if warnings else "nothing needs you this week")
    subject = f"{company_name}: {headline}"[:300]
    return seal(OwnerDigest, {**calendar_fields, "company_ref": company_ref, "company_name": company_name[:300], "currency": currency, "as_of": at, "subject": subject, "opening": opening[:300], "figures": figures, "actions": actions, "warnings": [item[:300] for item in warnings][:6], "cautions": [item[:300] for item in cautions][:6], "decisions_line": decisions_line, "software_line": software_line, "unknowns": [item[:300] for item in unknowns][:6], "source_digests": digests[:12]}, "digest_digest")


def verify_owner_digest(value: Any) -> OwnerDigest:
    return value if isinstance(value, OwnerDigest) else OwnerDigest.model_validate({key: item for key, item in dict(detached(value)).items() if key not in {"summary", "provider_effect_executed", "documents_built", "text", "delivery"}})


def delivery_brief(digest: OwnerDigest | Mapping[str, Any], *, channel: str, recipient_ref: str) -> dict[str, Any]:
    """The send the platform would make once an owner approves it: the channel, an opaque recipient reference (never an address), the subject and the text.  Nothing here sends."""

    parsed_digest = verify_owner_digest(digest)
    _require(channel in ("email", "slack"), "CHANNEL_UNSUPPORTED", "the digest goes by email or slack")
    _require(bool(recipient_ref) and "@" not in recipient_ref and ":/" not in recipient_ref, "RECIPIENT_REF_INVALID", "the recipient is an opaque reference the platform resolves, never an address")
    capability = "gmail.send_email" if channel == "email" else "slack.post_message"
    return {"capability": capability, "requires_approval": True, "recipient_ref": recipient_ref, "subject": parsed_digest.subject, "text": parsed_digest.render_text(), "digest_digest": parsed_digest.digest_digest, "effect": "none until an owner approves the send"}


__all__ = ["ACTION_WORDS", "CHOICES", "METRIC_WORDS", "OWNER_DIGEST_MANIFEST", "OWNER_DIGEST_SCHEMA", "UNKNOWN_WORDS", "DigestAction", "DigestFigure", "OwnerDigest", "OwnerDigestError", "build_owner_digest", "delivery_brief", "money", "verify_owner_digest"]
