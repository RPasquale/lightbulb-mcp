"""The owner's mandate: what an agent running the company may do alone, what it must ask about, and what it may never do.

Every effect the SDK can cause is today either impossible or waits on a
click, so an agent cannot run anything; it can only queue requests.  The
mandate is the owner's standing answer, set once and sealed: per kind of
action, whether the agent ``act``s, ``ask``s or ``never`` does it, a cap per
action, a monthly envelope for everything it does alone, and a date the
mandate must be renewed by.  Reads never need a mandate.

``authorise`` is the one gate every action passes: the rule for its kind,
the cap, the envelope less what the month already spent, and the expiry.
It returns a decision with the reason, never a side effect.  What the
agent then did under the mandate is written to a monthly log through the
console, so the envelope is counted from the record and the owner can see
every unattended action.  Nothing here executes anything.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, CurrencyCode, OpaqueRef, Sha256Digest, ShortText, StrictModel, decimal_value, detached, parsed, seal, sealed_digest, skip_digests, timestamp

OWNER_MANDATE_SCHEMA = "lightbulb.owner_mandate.v1"
MANDATE_DECISION_SCHEMA = "lightbulb.mandate_decision.v1"
MANDATE_LOG_SCHEMA = "lightbulb.mandate_log.v1"
MANDATE_MANIFEST: dict[str, Any] = {"engine": "owner_mandate", "kind": "policy", "reads": (), "writes": ("mandate_log",)}
Autonomy = Literal["act", "ask", "never"]
AUTONOMY: tuple[str, ...] = ("act", "ask", "never")
Effect = Literal["read", "message", "payment", "commitment", "price", "spend", "record", "release", "sale"]
# the effects that consume the monthly envelope: money leaves or is committed; a message, a price change or a sale (money comes in) costs nothing against it
ENVELOPE_EFFECTS: frozenset[str] = frozenset({"payment", "commitment", "spend"})

# every kind of action an agent can take on the company: its effect and what it means in the owner's words
ACTION_KINDS: dict[str, dict[str, str]] = {
    "read_ledger": {"effect": "read", "means": "read the books, invoices, bills and bank lines"},
    "record_document": {"effect": "record", "means": "record a document the SDK built (books, ledgers, reviews, decisions) in the project"},
    "chase_overdue": {"effect": "message", "means": "send a customer a reminder about an overdue invoice"},
    "send_digest": {"effect": "message", "means": "send the owner the weekly digest"},
    "message_customer": {"effect": "message", "means": "send a customer any other message"},
    "message_supplier": {"effect": "message", "means": "send a supplier a message"},
    "pay_bill": {"effect": "payment", "means": "pay a supplier bill that is due"},
    "issue_credit": {"effect": "payment", "means": "credit or refund a customer"},
    "write_off": {"effect": "payment", "means": "write off a receivable as bad debt"},
    "open_requisition": {"effect": "commitment", "means": "open a hiring requisition"},
    "engage_contractor": {"effect": "commitment", "means": "engage a contractor"},
    "sign_agreement": {"effect": "commitment", "means": "sign a supplier or customer agreement"},
    "reorder_stock": {"effect": "commitment", "means": "place a stock order"},
    "change_price": {"effect": "price", "means": "change a price or a rate"},
    "spend_marketing": {"effect": "spend", "means": "spend on advertising or a growth experiment"},
    "spend_other": {"effect": "spend", "means": "any other spend"},
    "open_change": {"effect": "spend", "means": "ask a coding agent to build a change to the company's software; its cost counts against the envelope"},
    "open_pr": {"effect": "release", "means": "open a draft pull request with a built change for review"},
    "merge_pr": {"effect": "release", "means": "merge a reviewed change into the software (not executable yet)"},
    "deploy": {"effect": "release", "means": "release merged software to the people using it (not executable yet)"},
    "send_quote": {"effect": "sale", "means": "send another business a quote priced from the published catalog; the cap limits the quote's value"},
    "accept_order": {"effect": "sale", "means": "accept another business's purchase order, committing to deliver it; the cap limits the order's value"},
    "send_invoice": {"effect": "sale", "means": "send another business the invoice for an order it placed and the company accepted"},
    "place_order": {"effect": "commitment", "means": "place a purchase order with another business, accepting its quote; it counts against the envelope"},
    "take_new_customer": {"effect": "record", "means": "take on a business that asked for a quote as a new customer (register it on the exchange) so the agent can answer it; its orders are still held to accept_order's cap"},
    "post_to_ledger": {"effect": "record", "means": "post a bill or invoice traded through the exchange into the accounting ledger; the platform's financial reviewer still approves the write"},
}
_CENT = Decimal("0.01")


class MandateError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise MandateError(code, message)


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


class MandateRule(StrictModel):
    action_kind: ShortText
    autonomy: Autonomy
    cap_per_action: Decimal | None = None
    note: ShortText | None = None

    @field_validator("cap_per_action", mode="before")
    @classmethod
    def _numbers(cls, value: Any) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name="cap_per_action")

    @model_validator(mode="after")
    def _known(self) -> "MandateRule":
        if self.action_kind not in ACTION_KINDS:
            raise ValueError(f"{self.action_kind} is not an action kind the mandate knows; the kinds are {', '.join(ACTION_KINDS)}")
        if ACTION_KINDS[self.action_kind]["effect"] == "read" and self.autonomy != "act":
            raise ValueError("reads never need a mandate; they are always allowed")
        if self.cap_per_action is not None and self.autonomy != "act":
            raise ValueError("a cap only means something on a rule the agent acts under")
        return self


class OwnerMandate(StrictModel):
    schema_id: str = Field(default=OWNER_MANDATE_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    owner_ref: OpaqueRef
    as_of: str
    valid_until: str
    default_autonomy: Autonomy = "ask"
    monthly_envelope: Decimal = Field(default=Decimal("0"), validate_default=True)
    rules: tuple[MandateRule, ...] = Field(default_factory=tuple, max_length=len(ACTION_KINDS))
    mandate_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("rules", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("monthly_envelope", mode="before")
    @classmethod
    def _numbers(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="monthly_envelope")

    @field_validator("as_of", "valid_until")
    @classmethod
    def _stamps(cls, value: str, info: ValidationInfo) -> str:
        return timestamp(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "OwnerMandate":
        if len({rule.action_kind for rule in self.rules}) != len(self.rules):
            raise ValueError("one rule per action kind")
        if parsed(self.valid_until) <= parsed(self.as_of):
            raise ValueError("the mandate must be valid for some time after it is given")
        if self.default_autonomy == "act":
            raise ValueError("the default is ask or never; acting alone is granted per action kind")
        if not skip_digests(info) and self.mandate_digest != sealed_digest(OwnerMandate, self, "mandate_digest"):
            raise ValueError("mandate_digest must commit the exact mandate")
        return self

    def rule(self, action_kind: str) -> MandateRule | None:
        return next((rule for rule in self.rules if rule.action_kind == action_kind), None)

    def render(self) -> str:
        lines = [f"**Owner mandate** ({self.company_ref}, given {self.as_of[:10]}, renew by {self.valid_until[:10]}): the agent acts alone on what is listed as act, up to {self.monthly_envelope} {self.currency} a month in total; everything else it {'asks about' if self.default_autonomy == 'ask' else 'never does'}"]
        for rule in self.rules:
            lines.append(f"- {rule.action_kind} ({ACTION_KINDS[rule.action_kind]['means']}): {rule.autonomy}" + (f" up to {rule.cap_per_action}" if rule.cap_per_action is not None else "") + (f"; {rule.note}" if rule.note else ""))
        return "\n".join(lines)


def compile_mandate(company_ref: str, *, currency: str, owner_ref: str, as_of: str, rules: Sequence[Mapping[str, Any]] = (), default_autonomy: str = "ask", monthly_envelope: Any = "0", months_valid: int = 6) -> OwnerMandate:
    """The sealed mandate; every action kind not ruled on takes the default, and reads are always allowed."""

    _require(1 <= int(months_valid) <= 24, "VALIDITY_INVALID", "a mandate runs for 1 to 24 months before it is renewed")
    at = timestamp(as_of, field_name="as_of")
    start = parsed(at)
    month, year = start.month - 1 + int(months_valid), start.year
    year, month = year + month // 12, month % 12 + 1
    valid_until = start.replace(year=year, month=month, day=min(start.day, 28)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return seal(OwnerMandate, {"company_ref": company_ref, "currency": str(currency).upper(), "owner_ref": owner_ref, "as_of": at, "valid_until": valid_until, "default_autonomy": default_autonomy, "monthly_envelope": str(decimal_value(monthly_envelope, field_name="monthly_envelope")), "rules": [dict(detached(rule)) for rule in rules]}, "mandate_digest")


def verify_mandate(value: Any) -> OwnerMandate:
    return value if isinstance(value, OwnerMandate) else OwnerMandate.model_validate({key: item for key, item in dict(detached(value)).items() if key not in {"summary", "provider_effect_executed"}})


class MandateDecision(StrictModel):
    schema_id: str = Field(default=MANDATE_DECISION_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    mandate_digest: Sha256Digest
    action_kind: ShortText
    subject: ShortText | None = None
    money: Decimal
    at: str
    autonomy: Autonomy
    reason: ShortText
    envelope_remaining: Decimal | None = None
    decision_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("money", "envelope_remaining", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "MandateDecision":
        if not skip_digests(info) and self.decision_digest != sealed_digest(MandateDecision, self, "decision_digest"):
            raise ValueError("decision_digest must commit the exact decision")
        return self


def authorise(mandate: OwnerMandate | Mapping[str, Any], *, action_kind: str, money: Any = "0", now: str, spent_this_month: Any = "0", subject: str | None = None) -> MandateDecision:
    """The one gate: act, ask or never, with the reason; reads always act, an expired mandate asks, and a cap or the envelope turns act into ask."""

    parsed_mandate = verify_mandate(mandate)
    _require(action_kind in ACTION_KINDS, "ACTION_KIND_UNKNOWN", f"{action_kind} is not an action kind the mandate knows")
    at = timestamp(now, field_name="now")
    amount = decimal_value(money, field_name="money", allow_negative=True).copy_abs()
    spent = decimal_value(spent_this_month, field_name="spent_this_month")
    remaining = (parsed_mandate.monthly_envelope - spent).quantize(_CENT)
    effect = ACTION_KINDS[action_kind]["effect"]
    rule = parsed_mandate.rule(action_kind)

    def decide(autonomy: str, reason: str) -> MandateDecision:
        return seal(MandateDecision, {"company_ref": parsed_mandate.company_ref, "mandate_digest": parsed_mandate.mandate_digest, "action_kind": action_kind, "subject": None if subject is None else str(subject)[:300], "money": str(amount), "at": at, "autonomy": autonomy, "reason": reason[:300], "envelope_remaining": None if effect == "read" else str(remaining)}, "decision_digest")

    if effect == "read":
        return decide("act", "reads never need a mandate")
    if parsed(at) > parsed(parsed_mandate.valid_until):
        return decide("ask", f"the mandate expired on {parsed_mandate.valid_until[:10]}; the owner renews it before the agent acts alone again")
    autonomy = rule.autonomy if rule is not None else parsed_mandate.default_autonomy
    if autonomy == "never":
        return decide("never", f"the owner ruled that the agent never does this" + ("" if rule is not None else " (the mandate's default)"))
    if autonomy == "ask":
        return decide("ask", "the owner asks to decide this" + ("" if rule is not None else " (the mandate's default: no rule names this action)"))
    assert rule is not None
    if rule.cap_per_action is not None and amount > rule.cap_per_action:
        return decide("ask", f"{amount} is over the {rule.cap_per_action} cap the owner set for {action_kind}")
    counts = effect in ENVELOPE_EFFECTS
    if counts and amount > 0 and amount > remaining:
        return decide("ask", f"{amount} would take the month past the {parsed_mandate.monthly_envelope} envelope ({remaining} left)")
    return decide("act", f"the owner lets the agent do this alone" + (f" up to {rule.cap_per_action}" if rule.cap_per_action is not None else "") + (f"; {remaining - amount if amount else remaining} of the month's envelope stays after it" if counts else "; it costs nothing against the envelope"))


class MandateLogEntry(StrictModel):
    at: str
    action_kind: ShortText
    subject: ShortText | None = None
    money: Decimal
    tool: ShortText | None = None
    decision_digest: Sha256Digest
    effect_ref: ShortText | None = None
    note: ShortText | None = None
    # the mandate the entry was decided under, written once the month's log outlives it; absent, it is the log's own
    mandate_digest: Sha256Digest | None = None

    @field_validator("money", mode="before")
    @classmethod
    def _numbers(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="money")


class MandateLog(StrictModel):
    schema_id: str = Field(default=MANDATE_LOG_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    month: ShortText
    mandate_digest: Sha256Digest
    entries: tuple[MandateLogEntry, ...] = Field(default_factory=tuple, max_length=2000)
    spent: Decimal
    log_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("entries", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("spent", mode="before")
    @classmethod
    def _numbers(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="spent")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "MandateLog":
        if self.spent != sum((entry.money for entry in self.entries if ACTION_KINDS.get(entry.action_kind, {}).get("effect") in ENVELOPE_EFFECTS), Decimal("0")).quantize(_CENT):
            raise ValueError("spent is the sum of the entries that consume the envelope")
        if not skip_digests(info) and self.log_digest != sealed_digest(MandateLog, self, "log_digest"):
            raise ValueError("log_digest must commit the exact log")
        return self


def append_mandate_log(log: MandateLog | Mapping[str, Any] | None, *, company_ref: str, mandate_digest: str, decision: MandateDecision | Mapping[str, Any], tool: str | None = None, effect_ref: str | None = None, note: str | None = None) -> MandateLog:
    """The month's log with one more unattended action; only a decision that said ``act`` may be logged, and a decision already logged is refused.

    The envelope is the month's, whatever the owner changes during it: when the owner gives a new mandate
    mid-month, the month's log carries on under it, every earlier entry keeping the mandate it was decided
    under, and what the month already spent still counts against the new envelope.
    """

    parsed_decision = decision if isinstance(decision, MandateDecision) else MandateDecision.model_validate(dict(detached(decision)))
    _require(parsed_decision.autonomy == "act", "NOT_AUTHORISED", "only an action the mandate let the agent take alone is logged under it")
    _require(parsed_decision.mandate_digest == mandate_digest and parsed_decision.company_ref == company_ref, "MANDATE_MISMATCH", "the decision was made under another mandate")
    current = None if log is None else (log if isinstance(log, MandateLog) else MandateLog.model_validate({key: value for key, value in dict(detached(log)).items() if key not in {"version"}}))
    month = parsed_decision.at[:7]
    entries = [] if current is None else [entry.to_dict() for entry in current.entries]
    if current is not None:
        _require(current.month == month and current.company_ref == company_ref, "MANDATE_MISMATCH", "the log belongs to another month or company")
        _require(all(entry["decision_digest"] != parsed_decision.decision_digest for entry in entries), "ALREADY_LOGGED", "this decision is already in the month's log")
        if current.mandate_digest != mandate_digest:
            # the owner replaced the mandate during the month: the entries before it name the mandate they were decided under
            entries = [{**entry, "mandate_digest": entry.get("mandate_digest") or current.mandate_digest} for entry in entries]
    entries.append({"at": parsed_decision.at, "action_kind": parsed_decision.action_kind, "subject": parsed_decision.subject, "money": str(parsed_decision.money), "tool": tool, "decision_digest": parsed_decision.decision_digest, "effect_ref": effect_ref, "note": None if note is None else str(note)[:300]})
    spent = sum((Decimal(entry["money"]) for entry in entries if ACTION_KINDS.get(str(entry["action_kind"]), {}).get("effect") in ENVELOPE_EFFECTS), Decimal("0")).quantize(_CENT)
    return seal(MandateLog, {"company_ref": company_ref, "month": month, "mandate_digest": mandate_digest, "entries": [{key: value for key, value in entry.items() if value is not None} for entry in entries], "spent": str(spent)}, "log_digest")


def verify_mandate_log(value: Any) -> MandateLog:
    return value if isinstance(value, MandateLog) else MandateLog.model_validate({key: item for key, item in dict(detached(value)).items() if key not in {"summary", "provider_effect_executed", "version"}})


__all__ = ["ACTION_KINDS", "AUTONOMY", "ENVELOPE_EFFECTS", "MANDATE_DECISION_SCHEMA", "MANDATE_LOG_SCHEMA", "MANDATE_MANIFEST", "OWNER_MANDATE_SCHEMA", "MandateDecision", "MandateError", "MandateLog", "MandateLogEntry", "MandateRule", "OwnerMandate", "append_mandate_log", "authorise", "compile_mandate", "verify_mandate", "verify_mandate_log"]
