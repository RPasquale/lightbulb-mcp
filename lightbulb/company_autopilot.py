"""The autopilot: one loop per company that runs it on a heartbeat, under a switch only the owner turns on.

An autonomous company's worst failure is not a wrong answer but a loop nobody
can see or stop.  So the autopilot is built around the owner's switch:

* **One loop.**  It is the only thing that acts on its own schedule.  It
  creates no schedules, timers or other loops, and it stores nothing to fire
  later: each tick works out what is due from the recorded documents (the
  ``next`` queue), so once the loop stops nothing else happens.
* **One switch, held by the owner.**  It is off until the owner named in the
  mandate turns it on, and that grant lasts a stated number of days (at most
  90, never past the mandate) before it switches itself off.  Anyone may
  pause or stop it; only that owner starts or resumes it.  The autopilot
  pauses itself or switches itself off, and never turns itself on.
* **Stop is immediate.**  The switch is read again before every effect, so a
  stop halfway through a tick ends the tick at its next step, and a stop can
  withdraw every action still waiting.
* **Bounded.**  One tick per interval however often it is called, and one at
  a time; a cap on actions per tick and per day; one message per person per
  cooldown and one open request per person; the mandate's cap and monthly
  envelope on every action; a breaker that pauses it after failures in a row.
* **Traceable.**  Every tick is sealed and kept: what it read, what it did,
  what it held back and why, what waits on the owner, and the version of the
  switch that let it run.  ``status`` shows all of it in one place.

A tick reads the books when they are stale (when the host holds read
accounts for them), plans the actions that are due (reminders to overdue
customers and the week's digest) and hands them to the platform, which still
asks the owner before any write reaches a customer; it answers its turn in
exchanges with other businesses (quotes, order acknowledgements and orders,
each under the mandate) and orders from the best quote of each sourcing request
whose quotes are in (the other quotes of a sourcing request are never ordered on
their own); it asks for and orders each standing order's cycle within the
ceilings the owner approved; it tells the owner once about what needs them, and
writes the journal the next session starts from.
Nothing here reaches a provider except through the console's connector
executor and owner notifier.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
import time
from datetime import timedelta
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, OpaqueRef, Sha256Digest, ShortText, StrictModel, decimal_value, detached, parsed, seal, sealed_digest, skip_digests, stable_digest, timestamp

AUTOPILOT_ENGINE = "company_autopilot"
AUTOPILOT_CONTROL_SCHEMA = "lightbulb.autopilot_control.v1"
AUTOPILOT_LEDGER_SCHEMA = "lightbulb.autopilot_ledger.v1"
AUTOPILOT_TICK_SCHEMA = "lightbulb.autopilot_tick.v1"
AUTOPILOT_STATUS_SCHEMA = "lightbulb.autopilot_status.v1"
AUTOPILOT_RECORD_SCHEMA = "lightbulb.autopilot_record.v1"
AUTOPILOT_MANIFEST: dict[str, Any] = {"engine": AUTOPILOT_ENGINE, "kind": "operating_loop", "reads": ("operating_loop", "owner_mandate", "owner_action", "books_snapshot"), "writes": ("company_autopilot", "owner_action", "books_snapshot", "operator_journal", "mandate_log")}
CONTROL_ENTITY = "control:current"
LEDGER_ENTITY = "ledger:current"
AUTOPILOT_AGENT = "agent:autopilot"
DEFAULT_BY = "agent:operator"
SwitchState = Literal["on", "paused", "off"]
TickOutcome = Literal["ran", "stopped", "paused_itself", "failed"]
EntryOutcome = Literal["done", "awaiting_approval", "blocked", "failed", "reconcile", "declined", "recorded", "held", "asked", "ruled_out", "waiting"]
DEFAULT_LEASE_DAYS = 14
MAX_LEASE_DAYS = 90
LEASE_REMINDER_DAYS = 3
RUNNING_STALE_MINUTES = 15
MAX_CHANGES = 50
MAX_RECENT = 14
MAX_NOTIFIED = 50
MAX_CONTACTS = 500
MAX_ENTRIES = 60
BOOKS_MONTHS_WHEN_EMPTY = 12
# the owner actions a tick hands to the platform; everything else in ``next`` is the owner's, a person's or the platform's
DISPATCHED_KINDS: frozenset[str] = frozenset({"chase_overdue", "send_digest", "post_to_ledger"})
# the actions that message a person outside the company, so the cooldown and the one-open-request rule apply
CONTACT_KINDS: frozenset[str] = frozenset({"chase_overdue"})
# the documents a tick answers in an exchange when it is this company's turn, each under the mandate (an invoice stays a
# deliberate step: many businesses invoice on delivery, not on acceptance)
EXCHANGE_ANSWERS: dict[str, str] = {"quote": "quote_request", "order_acknowledgement": "acknowledge_order", "purchase_order": "order_from_quote", "remittance": "remit_invoice"}
LIMIT_FIELDS: tuple[str, ...] = ("tick_every_hours", "max_actions_per_tick", "max_actions_per_day", "contact_cooldown_days", "max_failures_in_a_row", "read_books", "send_digest")


class AutopilotError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise AutopilotError(code, message)


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


def _plus(stamp: str, **delta: float) -> str:
    return (parsed(stamp) + timedelta(**delta)).isoformat().replace("+00:00", "Z")


class AutopilotLimits(StrictModel):
    """What the owner lets one tick, and one day, do."""

    tick_every_hours: int = Field(default=24, ge=1, le=168)
    max_actions_per_tick: int = Field(default=5, ge=1, le=50)
    max_actions_per_day: int = Field(default=20, ge=1, le=200)
    contact_cooldown_days: int = Field(default=7, ge=0, le=90)
    max_failures_in_a_row: int = Field(default=3, ge=1, le=20)
    read_books: bool = True
    send_digest: bool = True

    @model_validator(mode="after")
    def _guard(self) -> "AutopilotLimits":
        if self.max_actions_per_tick > self.max_actions_per_day:
            raise ValueError("a tick cannot do more than the day allows")
        return self

    def render(self) -> str:
        return (f"a tick every {self.tick_every_hours}h; at most {self.max_actions_per_tick} action(s) a tick and {self.max_actions_per_day} a day; one message per person per {self.contact_cooldown_days} day(s); paused after {self.max_failures_in_a_row} failure(s) in a row"
                + ("" if self.read_books else "; book reads off") + ("" if self.send_digest else "; the digest off"))


class ControlChange(StrictModel):
    at: str
    state: SwitchState
    by: OpaqueRef
    reason: ShortText

    @field_validator("at")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="at")


class AutopilotControl(StrictModel):
    """The owner's switch: on, paused or off, who set it and why, when the owner's grant ends, the limits, and every change."""

    schema_id: str = Field(default=AUTOPILOT_CONTROL_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    owner_ref: OpaqueRef
    state: SwitchState
    since: str
    by: OpaqueRef
    reason: ShortText
    on_until: str | None = None
    limits: AutopilotLimits
    mandate_digest: Sha256Digest | None = None
    changes: tuple[ControlChange, ...] = Field(min_length=1, max_length=MAX_CHANGES)
    control_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("changes", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("since", "on_until")
    @classmethod
    def _stamps(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "AutopilotControl":
        if self.state != "off" and self.on_until is None:
            raise ValueError("a switch that is on or paused carries the date the owner's grant ends")
        if self.state == "on" and self.by != self.owner_ref:
            raise ValueError("only the owner turns the autopilot on")
        last = self.changes[-1]
        if (last.at, last.state, last.by, last.reason) != (self.since, self.state, self.by, self.reason):
            raise ValueError("the last change is the switch as it stands")
        if not skip_digests(info) and self.control_digest != sealed_digest(AutopilotControl, self, "control_digest"):
            raise ValueError("control_digest must commit the exact switch")
        return self

    def render(self) -> str:
        head = f"**Autopilot** ({self.company_ref}): {self.state.upper()} since {self.since[:16]} ({self.by}): {self.reason}"
        if self.state != "off":
            head += f"; the owner's grant ends {str(self.on_until)[:16]}"
        return head + f"\n- limits: {self.limits.render()}"


class ContactMark(StrictModel):
    subject: ShortText
    at: str

    @field_validator("at")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="at")


class TickLine(StrictModel):
    at: str
    outcome: TickOutcome
    did: int = Field(ge=0)
    held: int = Field(ge=0)
    asks: int = Field(ge=0)
    tick_digest: Sha256Digest


class AutopilotLedger(StrictModel):
    """The running counts: the day's actions, when each person was last messaged, failures in a row, the tick in progress, and what the owner has been told."""

    schema_id: str = Field(default=AUTOPILOT_LEDGER_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    day: str | None = None
    actions_today: int = Field(default=0, ge=0)
    contacts: tuple[ContactMark, ...] = Field(default_factory=tuple, max_length=MAX_CONTACTS)
    failures_in_a_row: int = Field(default=0, ge=0)
    ticks: int = Field(default=0, ge=0)
    last_tick_at: str | None = None
    running_since: str | None = None
    running_tick: OpaqueRef | None = None
    asks_digest: Sha256Digest | None = None
    notified: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=MAX_NOTIFIED)
    recent: tuple[TickLine, ...] = Field(default_factory=tuple, max_length=MAX_RECENT)
    ledger_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("contacts", "notified", "recent", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("last_tick_at", "running_since")
    @classmethod
    def _stamps(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "AutopilotLedger":
        if (self.running_since is None) != (self.running_tick is None):
            raise ValueError("a tick in progress names its time and its reference")
        if not skip_digests(info) and self.ledger_digest != sealed_digest(AutopilotLedger, self, "ledger_digest"):
            raise ValueError("ledger_digest must commit the exact ledger")
        return self


class TickEntry(StrictModel):
    key: ShortText
    step: ShortText
    subject: ShortText
    outcome: EntryOutcome
    detail: ShortText | None = None
    action_ref: OpaqueRef | None = None
    money: Decimal = Field(default=Decimal("0"), validate_default=True)

    @field_validator("money", mode="before")
    @classmethod
    def _numbers(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="money", allow_negative=True)

    def render(self) -> str:
        return f"{self.step} {self.subject}" + (f" ({self.money})" if self.money else "") + f": {self.outcome}" + (f"; {self.detail}" if self.detail else "")


class AutopilotTick(StrictModel):
    """One tick as it happened: the switch that allowed it, what it did, held back, left to the owner, found ruled out or left waiting."""

    schema_id: str = Field(default=AUTOPILOT_TICK_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    at: str
    control_digest: Sha256Digest
    mandate_digest: Sha256Digest | None = None
    step_digest: Sha256Digest | None = None
    outcome: TickOutcome
    stopped_because: ShortText | None = None
    did: tuple[TickEntry, ...] = Field(default_factory=tuple, max_length=MAX_ENTRIES)
    held: tuple[TickEntry, ...] = Field(default_factory=tuple, max_length=MAX_ENTRIES)
    asks: tuple[TickEntry, ...] = Field(default_factory=tuple, max_length=MAX_ENTRIES)
    ruled_out: tuple[TickEntry, ...] = Field(default_factory=tuple, max_length=MAX_ENTRIES)
    waiting: tuple[TickEntry, ...] = Field(default_factory=tuple, max_length=MAX_ENTRIES)
    notified: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=10)
    actions_today: int = Field(ge=0)
    failures_in_a_row: int = Field(ge=0)
    next_tick_at: str | None = None
    tick_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("did", "held", "asks", "ruled_out", "waiting", "notified", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("at", "next_tick_at")
    @classmethod
    def _stamps(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "AutopilotTick":
        if (self.outcome == "ran") != (self.stopped_because is None):
            raise ValueError("a tick that did not run to the end says why")
        if not skip_digests(info) and self.tick_digest != sealed_digest(AutopilotTick, self, "tick_digest"):
            raise ValueError("tick_digest must commit the exact tick")
        return self

    def render(self) -> str:
        head = (f"**Autopilot tick** ({self.company_ref}, {self.at[:16]}): {self.outcome}" + (f" ({self.stopped_because})" if self.stopped_because else "")
                + f"; did {len(self.did)}, held back {len(self.held)}, {len(self.asks)} for the owner, {len(self.ruled_out)} ruled out, {len(self.waiting)} waiting"
                + (f"; next tick {self.next_tick_at[:16]}" if self.next_tick_at else ""))
        lines = [head]
        for label, rows in (("did", self.did), ("held back", self.held), ("needs the owner", self.asks), ("ruled out", self.ruled_out), ("waiting", self.waiting)):
            lines.extend(f"- {label}: {row.render()}" for row in rows)
        return "\n".join(lines)


# --------------------------------------------------------------------------- #
# The records
# --------------------------------------------------------------------------- #


def _state(console: Any, entity_ref: str, *, key: str, document: Mapping[str, Any], digest: str, version: int, now: str, status: str) -> dict[str, Any]:
    return {"schema": AUTOPILOT_RECORD_SCHEMA, "status": status, "plan_digest": stable_digest({AUTOPILOT_ENGINE: console.bundle.company_ref}), "version": version, "state_digest": digest, "scope": console.bundle.engine_scope(entity_ref), "as_of": timestamp(now, field_name="now"), key: dict(document)}


def _put(console: Any, entity_ref: str, *, key: str, document: Mapping[str, Any], digest: str, now: str, status: str, existing: Mapping[str, Any] | None) -> Mapping[str, Any]:
    version = 1 if existing is None else int(existing["version"]) + 1
    return console.store.put(AUTOPILOT_ENGINE, entity_ref, _state(console, entity_ref, key=key, document=document, digest=digest, version=version, now=now, status=status), expected_version=None if existing is None else int(existing["version"]), expected_state_digest=None if existing is None else str(existing["state_digest"]))


def verify_autopilot_control(value: Any) -> AutopilotControl:
    return value if isinstance(value, AutopilotControl) else AutopilotControl.model_validate(dict(detached(value)))


def verify_autopilot_ledger(value: Any) -> AutopilotLedger:
    return value if isinstance(value, AutopilotLedger) else AutopilotLedger.model_validate(dict(detached(value)))


def verify_autopilot_tick(value: Any) -> AutopilotTick:
    return value if isinstance(value, AutopilotTick) else AutopilotTick.model_validate({key: item for key, item in dict(detached(value)).items() if key not in {"summary", "provider_effect_executed", "ran", "replayed"}})


def load_control(console: Any) -> tuple[AutopilotControl | None, Mapping[str, Any] | None]:
    record = console.store.get(AUTOPILOT_ENGINE, CONTROL_ENTITY)
    if record is None:
        return None, None
    control = verify_autopilot_control(dict(record["state"])["control"])
    _require(control.company_ref == console.bundle.company_ref, "SCOPE_MISMATCH", "the autopilot's switch names another company")
    return control, record


def _load_ledger(console: Any) -> tuple[AutopilotLedger, Mapping[str, Any] | None]:
    record = console.store.get(AUTOPILOT_ENGINE, LEDGER_ENTITY)
    if record is None:
        return seal(AutopilotLedger, {"company_ref": console.bundle.company_ref}, "ledger_digest"), None
    ledger = verify_autopilot_ledger(dict(record["state"])["ledger"])
    _require(ledger.company_ref == console.bundle.company_ref, "SCOPE_MISMATCH", "the autopilot's ledger names another company")
    return ledger, record


def _save_ledger(console: Any, ledger: AutopilotLedger, fields: Mapping[str, Any], *, now: str, existing: Mapping[str, Any] | None) -> tuple[AutopilotLedger, Mapping[str, Any]]:
    updated = seal(AutopilotLedger, {**{key: value for key, value in ledger.to_dict().items() if key != "ledger_digest"}, **dict(fields)}, "ledger_digest")
    if existing is not None and updated.ledger_digest == str(existing["state_digest"]):
        return updated, existing
    stored = _put(console, LEDGER_ENTITY, key="ledger", document=updated.to_dict(), digest=updated.ledger_digest, now=now, status="running" if updated.running_since else "idle", existing=existing)
    return updated, stored


def _change(console: Any, control: AutopilotControl | None, existing: Mapping[str, Any] | None, *, now: str, state: str, by: str, reason: str, owner_ref: str | None = None, on_until: str | None = None, limits: AutopilotLimits | None = None, mandate_digest: str | None = None) -> AutopilotControl:
    """Write one change to the switch; the history keeps the last fifty."""

    at = timestamp(now, field_name="now")
    base = {} if control is None else control.to_dict()
    changes = [*base.get("changes", ()), {"at": at, "state": state, "by": by, "reason": reason[:300]}][-MAX_CHANGES:]
    document = {
        "company_ref": console.bundle.company_ref,
        "owner_ref": owner_ref or base.get("owner_ref"),
        "state": state,
        "since": at,
        "by": by,
        "reason": reason[:300],
        "on_until": on_until if on_until is not None else (base.get("on_until") if state != "off" else None),
        "limits": (limits.to_dict() if limits is not None else base.get("limits")) or AutopilotLimits().to_dict(),
        "mandate_digest": mandate_digest if mandate_digest is not None else base.get("mandate_digest"),
        "changes": changes,
    }
    updated = seal(AutopilotControl, {key: value for key, value in document.items() if value is not None}, "control_digest")
    _put(console, CONTROL_ENTITY, key="control", document=updated.to_dict(), digest=updated.control_digest, now=at, status=state, existing=existing)
    return updated


def _notify(console: Any, *, key: str, title: str, message: str) -> bool:
    """Tell the owner inside the platform once; a console with no notifier (a local run) tells nobody and says so."""

    notifier = getattr(console, "owner_notifier", None)
    project_id = str(console.bundle.scope.get("project_id") or "")
    if notifier is None or not project_id:
        return False
    try:
        notifier(project_id=project_id, kind="owner_action", notification_key=key[:160], title=" ".join(title.split())[:200], message=message[:8000])
    except Exception:  # the platform did not take it; the next change or tick tells the owner again
        return False
    return True


# --------------------------------------------------------------------------- #
# The switch
# --------------------------------------------------------------------------- #


def _mandate_problem(console: Any, control: AutopilotControl, *, now: str) -> str | None:
    from lightbulb.company_operator_surface import current_mandate

    try:
        mandate = current_mandate(console)
    except ValueError as exc:
        return f"the mandate cannot be read ({exc})"[:300]
    if mandate is None:
        return "the bundle holds no mandate; the owner gives one (company_mandate set) and resumes"
    if parsed(now) >= parsed(mandate.valid_until):
        return f"the mandate expired {mandate.valid_until[:10]}; the owner renews it and resumes"
    if mandate.owner_ref != control.owner_ref:
        return f"the mandate now names {mandate.owner_ref}, not {control.owner_ref} who turned the autopilot on; the mandate's owner starts it"
    return None


def _why_not(control: AutopilotControl | None) -> str | None:
    if control is None:
        return "off: the owner has not turned the autopilot on (company_autopilot start)"
    if control.state != "on":
        return f"{control.state} since {control.since[:16]} ({control.by}): {control.reason}"
    return None


def cached_reader(read: Callable[[], Mapping[str, Any]], *, seconds: float = 5.0, clock: Callable[[], float] = time.monotonic) -> Callable[[], Mapping[str, Any]]:
    """Wrap a platform read so that a check at every fence costs one request every few seconds (an error is remembered as long)."""

    state: dict[str, Any] = {}

    def read_cached() -> Mapping[str, Any]:
        moment = clock()
        if "at" in state and moment - state["at"] < seconds:
            if "error" in state:
                raise state["error"]
            return state["view"]
        state.clear()
        state["at"] = moment
        try:
            state["view"] = dict(read())
        except Exception as exc:
            state["error"] = exc
            raise
        return state["view"]

    return read_cached


def platform_stop(console: Any) -> dict[str, Any] | None:
    """The platform's owner stop as this console can read it: ``None`` with no reader, else whether it holds the company and why.

    A platform that cannot be read (an older one, or a blip) does not hold the autopilot here: the
    platform still enforces its own stop where work starts and where effects leave, and the status
    says the stop could not be read.
    """

    reader = getattr(console, "autonomy_reader", None)
    if reader is None:
        return None
    try:
        view = dict(reader())
    except Exception as exc:
        return {"stopped": False, "unreadable": f"{type(exc).__name__}: {exc}"[:300]}
    return {"stopped": view.get("status") == "stopped", "halted_by": view.get("halted_by")}


def _platform_hold(console: Any) -> str | None:
    platform = platform_stop(console)
    if platform is not None and platform.get("stopped"):
        cause = platform.get("halted_by") or "the owner's stop"
        return f"stopped on the platform ({cause}); the owner resumes it there"
    return None


def held_reason(console: Any, *, now: str) -> str | None:
    """``None`` when the autopilot may act now, otherwise why not.  An ended grant switches it off and a mandate that no longer lets it act pauses it, and the owner is told once; nothing here ever turns it on."""

    from lightbulb.company_engine_store import EngineStateConflictError

    at = timestamp(now, field_name="now")
    for _ in range(2):
        control, record = load_control(console)
        why = _why_not(control)
        if why is not None:
            return why
        assert control is not None
        try:
            if parsed(at) >= parsed(str(control.on_until)):
                changed = _change(console, control, record, now=at, state="off", by=AUTOPILOT_AGENT, reason=f"the owner's grant ended {str(control.on_until)[:16]}; the owner starts it again to go on")
                _notify(console, key=f"autopilot-switch:{changed.control_digest[:24]}", title="The autopilot switched itself off", message=f"{changed.reason}. Nothing runs on its own until you turn it on again with company_autopilot start.")
                return f"off: {changed.reason}"
            problem = _mandate_problem(console, control, now=at)
            if problem is not None:
                changed = _change(console, control, record, now=at, state="paused", by=AUTOPILOT_AGENT, reason=problem)
                _notify(console, key=f"autopilot-switch:{changed.control_digest[:24]}", title="The autopilot paused itself", message=f"{problem}. Nothing runs on its own until you resume it with company_autopilot resume.")
                return f"paused: {problem}"
        except EngineStateConflictError:
            continue  # the switch changed under us: read it again
        # the owner's one stop on the platform holds the autopilot too, whichever path runs it
        return _platform_hold(console)
    return "the switch is changing; nothing runs until it settles"


def _limits(current: AutopilotLimits | None, values: Mapping[str, Any]) -> AutopilotLimits:
    raw = {} if current is None else current.to_dict()
    for name in LIMIT_FIELDS:
        if name not in values or values[name] is None:
            continue
        value = values[name]
        if name in ("read_books", "send_digest"):
            if isinstance(value, str) and value.lower() in ("true", "false"):
                value = value.lower() == "true"
            _require(isinstance(value, bool), "LIMIT_INVALID", f"{name} is true or false")
        else:
            _require(not isinstance(value, bool) and str(value).strip().lstrip("-").isdigit(), "LIMIT_INVALID", f"{name} is a whole number")
            value = int(str(value).strip())
        raw[name] = value
    try:
        return AutopilotLimits.model_validate(raw)
    except ValueError as exc:
        raise AutopilotError("LIMIT_INVALID", str(exc).splitlines()[0][:300]) from exc


def start_autopilot(console: Any, *, now: str, owner_ref: str, days: Any = DEFAULT_LEASE_DAYS, reason: str | None = None, **limits: Any) -> dict[str, Any]:
    """The owner turns the autopilot on (or renews it) for a number of days, under the current mandate and the given limits."""

    from lightbulb.company_operator_surface import current_mandate

    at = timestamp(now, field_name="now")
    unknown = set(limits) - set(LIMIT_FIELDS)
    _require(not unknown, "LIMIT_UNKNOWN", f"the limits are {', '.join(LIMIT_FIELDS)}; {', '.join(sorted(unknown))} is not one")
    mandate = current_mandate(console)
    _require(mandate is not None, "MANDATE_REQUIRED", "the autopilot only acts within the owner's mandate; give one first (company_mandate set)")
    assert mandate is not None
    _require(str(owner_ref) == mandate.owner_ref, "OWNER_ONLY", f"only the mandate's owner ({mandate.owner_ref}) turns the autopilot on")
    _require(parsed(at) < parsed(mandate.valid_until), "MANDATE_EXPIRED", f"the mandate expired {mandate.valid_until[:10]}; renew it first")
    _require(not isinstance(days, bool) and str(days).strip().isdigit() and 1 <= int(str(days)) <= MAX_LEASE_DAYS, "DAYS_INVALID", f"the owner's grant lasts 1 to {MAX_LEASE_DAYS} days")
    control, record = load_control(console)
    chosen = _limits(None if control is None else control.limits, limits)
    until = min(_plus(at, days=int(str(days))), mandate.valid_until, key=parsed)
    renewing = control is not None and control.state == "on"
    note = reason or ("the owner renewed the autopilot" if renewing else "the owner turned the autopilot on")
    changed = _change(console, control, record, now=at, state="on", by=mandate.owner_ref, reason=f"{note} until {until[:10]}", owner_ref=mandate.owner_ref, on_until=until, limits=chosen, mandate_digest=mandate.mandate_digest)
    return {**autopilot_status_document(console, now=at), "changed": changed.changes[-1].to_dict()}


def pause_autopilot(console: Any, *, now: str, reason: str, by: str = DEFAULT_BY) -> dict[str, Any]:
    """Anyone may pause the autopilot; nothing runs until the owner resumes it."""

    at = timestamp(now, field_name="now")
    _require(bool(str(reason).strip()), "REASON_REQUIRED", "say why it is paused")
    control, record = load_control(console)
    if control is None or control.state != "on":
        return {**autopilot_status_document(console, now=at), "changed": None, "note": "the autopilot is not on; nothing to pause"}
    changed = _change(console, control, record, now=at, state="paused", by=str(by), reason=str(reason))
    return {**autopilot_status_document(console, now=at), "changed": changed.changes[-1].to_dict()}


def resume_autopilot(console: Any, *, now: str, owner_ref: str, reason: str | None = None) -> dict[str, Any]:
    """The owner resumes a paused autopilot within the grant already given; an ended grant needs start."""

    at = timestamp(now, field_name="now")
    control, record = load_control(console)
    _require(control is not None and control.state == "paused", "NOT_PAUSED", "only a paused autopilot resumes; an autopilot that is off is started")
    assert control is not None
    _require(str(owner_ref) == control.owner_ref, "OWNER_ONLY", f"only the owner who turned it on ({control.owner_ref}) resumes it")
    _require(parsed(at) < parsed(str(control.on_until)), "GRANT_ENDED", f"the owner's grant ended {str(control.on_until)[:10]}; start it again")
    problem = _mandate_problem(console, control, now=at)
    _require(problem is None, "MANDATE_PROBLEM", str(problem))
    changed = _change(console, control, record, now=at, state="on", by=control.owner_ref, reason=reason or "the owner resumed the autopilot")
    return {**autopilot_status_document(console, now=at), "changed": changed.changes[-1].to_dict()}


def stop_autopilot(console: Any, *, now: str, reason: str, by: str = DEFAULT_BY, withdraw: Any = False) -> dict[str, Any]:
    """Anyone may stop the autopilot; with ``withdraw`` every action still waiting to be sent is withdrawn too."""

    from lightbulb.company_act_surface import decline_owner_action_document, persisted_owner_actions

    at = timestamp(now, field_name="now")
    _require(bool(str(reason).strip()), "REASON_REQUIRED", "say why it is stopped")
    _require(isinstance(withdraw, bool), "WITHDRAW_INVALID", "withdraw is true or false")
    control, record = load_control(console)
    changed = None
    if control is not None and control.state != "off":
        changed = _change(console, control, record, now=at, state="off", by=str(by), reason=str(reason))
    withdrawn = []
    if withdraw:
        for action in persisted_owner_actions(console):
            if action.status in ("planned", "awaiting_approval"):
                decline_owner_action_document(console, now=at, action_ref=action.action_ref, reason=f"withdrawn when the autopilot was stopped: {reason}"[:300], owner_ref=str(by))
                withdrawn.append({"action_ref": action.action_ref, "kind": action.action_kind, "subject": action.subject, "was": action.status})
    note = None
    if any(row["was"] == "awaiting_approval" for row in withdrawn):
        note = "the platform may still show approval requests for the withdrawn sends; nothing sends them now, and they can be dismissed there"
    return {**autopilot_status_document(console, now=at), "changed": None if changed is None else changed.changes[-1].to_dict(), "withdrawn": withdrawn, "note": note}


# --------------------------------------------------------------------------- #
# The tick
# --------------------------------------------------------------------------- #


class _Stop(Exception):
    """The owner's switch changed during the tick; nothing more happens in it."""


class _Breaker(Exception):
    """Failures in a row reached the owner's limit; the autopilot pauses itself."""


class _FenceLost(Exception):
    """The host lost its lease; the host's own error is the cause."""


def _not_run(console: Any, *, now: str, why: str, next_tick_at: str | None = None) -> dict[str, Any]:
    return {"schema": AUTOPILOT_TICK_SCHEMA, "company_ref": console.bundle.company_ref, "at": timestamp(now, field_name="now"), "ran": False, "why": why[:300], "next_tick_at": next_tick_at, "summary": f"**Autopilot tick** ({console.bundle.company_ref}): did not run; {why}"[:600], "provider_effect_executed": False}


def _entry(key: str, step: str, subject: str, outcome: str, detail: str | None = None, *, action_ref: str | None = None, money: Any = "0") -> dict[str, Any]:
    return {"key": str(key)[:300], "step": str(step)[:300] or "do", "subject": str(subject)[:300] or "-", "outcome": outcome, "detail": None if not detail else str(detail)[:300], "action_ref": action_ref, "money": str(money)}


def _row_entry(row: Mapping[str, Any], outcome: str, detail: str | None = None) -> dict[str, Any]:
    return _entry(str(row["key"]), str(row["step"]), str(row["subject"]), outcome, detail, money=row.get("money_at_stake") or "0")


def _action_entry(action: Any, outcome: str, detail: str | None = None) -> dict[str, Any]:
    # a ledger posting is its own step: the journal's "do" entries are the chases whose payment the next session checks
    step = "send" if action.action_kind == "send_digest" else "post" if action.action_kind == "post_to_ledger" else "do"
    return _entry(action.key, step, f"{action.action_kind}: {action.subject}", outcome, detail, action_ref=action.action_ref, money=action.money)


def _months_missing(row: Mapping[str, Any], at: str) -> int:
    """How many complete months the books lack: all twelve when none is recorded, else the months since the latest one."""

    if row.get("operation") == "plan" or not str(row.get("key", "")).startswith("books:record:"):
        return BOOKS_MONTHS_WHEN_EMPTY
    ended = parsed(str(row["key"]).rsplit(":", 1)[-1] + "T00:00:00Z")
    now = parsed(at)
    return max(1, min(BOOKS_MONTHS_WHEN_EMPTY, (now.year * 12 + now.month) - (ended.year * 12 + ended.month)))


def _read_books(console: Any, *, now: str, row: Mapping[str, Any], accounts: Mapping[str, str], executor: Any, still_on: Callable[[], None]) -> tuple[dict[str, Any], bool]:
    """Make the backfill reads through the platform and record them; returns the entry and whether anything failed."""

    from lightbulb.company_execution_bridge import execution_receipt_from_connector, provenance_from_execution_receipt
    from lightbulb.company_operator_surface import plan_books_backfill_document, record_books_backfill
    from lightbulb.connector_execution import ConnectorEffect, ConnectorExecutionRequest, ExecutionScope

    plan = plan_books_backfill_document(console, now=now, months=_months_missing(row, now))
    tools = sorted({str(read["tool"]) for read in plan["reads"]})
    missing = [tool for tool in tools if tool not in accounts]
    if executor is None or missing:
        why = "the host has no connector executor" if executor is None else f"the host holds no read account for {', '.join(missing)}"
        return _row_entry(row, "waiting", why), False
    project_id = str(console.bundle.scope.get("project_id") or "")
    scope = ExecutionScope(project_ref=str(console.bundle.scope.get("project_ref") or project_id), project_id=project_id or None, actor_ref=getattr(console.bundle, "actor_ref", None))
    sources = []
    for read in plan["reads"]:
        still_on()
        request = ConnectorExecutionRequest(tool=str(read["tool"]), arguments=dict(read["arguments"]), scope=scope, connector_account_ref=accounts[str(read["tool"])], effect=ConnectorEffect.READ, metadata={"autopilot_tick": now, "window_start": str(read["window_start"])})
        result = executor.execute(request)
        try:
            receipt = execution_receipt_from_connector(result, request)
        except ValueError as exc:
            return _row_entry(row, "failed", f"{read['tool']} for {str(read['window_start'])[:7]}: {exc}"), True
        sources.append({"kind": read["kind"], "provenance": provenance_from_execution_receipt(receipt).to_dict(), "payload": dict(result.output or {})})
    recorded = record_books_backfill(console, now=now, sources=sources, plan={key: value for key, value in plan.items() if key not in {"summary", "provider_effect_executed"}})
    statuses = [str(window.get("status")) for window in recorded.get("windows", ())]
    counts = {status: statuses.count(status) for status in sorted(set(statuses))}
    return _row_entry(row, "recorded", f"{len(sources)} read(s): " + ", ".join(f"{count} {status}" for status, count in counts.items())), False


def _exchange_turns(console: Any, *, now: str) -> list[dict[str, Any]]:
    """The exchanges where it is this company's turn to send a document the tick answers (nothing when the company has no card)."""

    from lightbulb.company_exchange_sourcing import sourced_exchange_refs
    from lightbulb.company_exchange_standing import standing_exchange_refs
    from lightbulb.company_exchange_surface import current_card, exchange_status_document

    card = current_card(console)
    if card is None:
        return []
    # a quote asked for by a sourcing request or a standing order is ordered by that request's decision (the best of
    # its quotes, or within the standing order's ceilings), never on its own
    sourced = sourced_exchange_refs(console) | standing_exchange_refs(console)
    turns = []
    for row in exchange_status_document(console, now=now)["exchanges"]:
        if row["next_kind"] == "purchase_order" and row["exchange_ref"] in sourced:
            continue
        if row["our_turn"] and row["next_kind"] in EXCHANGE_ANSWERS:
            counterparty = row["seller"] if row["buyer"] == card.party_ref else row["buyer"]
            turns.append({"exchange_ref": row["exchange_ref"], "next_kind": row["next_kind"], "counterparty": counterparty, "value": row["value"] or "0"})
    return turns


def _describe_track_record(record: Mapping[str, Any] | None) -> str:
    from lightbulb.company_exchange_surface import describe_track_record

    return describe_track_record(record)


def _welcome_new_customers(console: Any, *, now: str, taken: Mapping[str, Any]) -> list[dict[str, Any]]:
    from lightbulb.company_exchange_surface import welcome_new_customers

    return welcome_new_customers(console, now=now, taken=taken)


def _standing_turns(console: Any) -> list[str]:
    from lightbulb.company_exchange_standing import standing_turns
    from lightbulb.company_exchange_surface import current_card

    return [] if current_card(console) is None else standing_turns(console)


def _advance_standing(console: Any, *, now: str, standing_ref: str) -> dict[str, Any] | None:
    from lightbulb.company_exchange_standing import advance_standing_order

    return advance_standing_order(console, now=now, standing_ref=standing_ref)


def _sourcing_turns(console: Any, *, now: str) -> list[dict[str, Any]]:
    """The sourcing requests with something for the tick: an award when the quotes are in, or what waits for the owner (nothing without a card)."""

    from lightbulb.company_exchange_sourcing import sourcing_turns
    from lightbulb.company_exchange_surface import current_card

    return [] if current_card(console) is None else sourcing_turns(console, now=now)


def _award_sourcing(console: Any, *, now: str, turn: Mapping[str, Any]) -> dict[str, Any]:
    from lightbulb.company_exchange_sourcing import award_sourcing

    return award_sourcing(console, now=now, sourcing_ref=str(turn["sourcing_ref"]))


def _answer_exchange(console: Any, *, now: str, turn: Mapping[str, Any]) -> dict[str, Any]:
    import lightbulb.company_exchange_surface as exchange

    if turn["next_kind"] == "quote" and exchange._load_thread(console, str(turn["exchange_ref"]))[0].last().kind == "counter":
        # the buyer countered: the revised quote is the discount policy's (the owner answers when there is none)
        from lightbulb.company_exchange_negotiation import answer_counter

        return answer_counter(console, now=now, exchange_ref=str(turn["exchange_ref"]))
    return getattr(exchange, EXCHANGE_ANSWERS[str(turn["next_kind"])])(console, now=now, exchange_ref=str(turn["exchange_ref"]))


def run_autopilot_tick(console: Any, *, now: str, connector_account_refs: Mapping[str, str] | None = None, fence: Callable[[], Any] | None = None) -> dict[str, Any]:
    """One pass: nothing unless the owner's switch is on and the interval has passed; then read the books if stale, plan and hand over what is due within the limits, tell the owner what needs them, write the journal, and seal the tick."""

    from lightbulb.company_act_surface import dispatch_owner_actions_document, persisted_owner_actions, plan_owner_actions_document
    from lightbulb.company_engine_store import EngineStateConflictError
    from lightbulb.company_operator_surface import build_operating_step_document, current_mandate, record_operator_journal
    from lightbulb.owner_actions import DISPATCHABLE_STATUSES

    at = timestamp(now, field_name="now")
    tick_ref = f"tick:{at}"
    replay = console.store.get(AUTOPILOT_ENGINE, tick_ref)
    if replay is not None:
        sealed = verify_autopilot_tick(dict(replay["state"])["tick"])
        return {**sealed.to_dict(), "ran": True, "replayed": True, "summary": sealed.render(), "provider_effect_executed": False}
    why = held_reason(console, now=at)
    if why is not None:
        return _not_run(console, now=at, why=why)
    control, _ = load_control(console)
    assert control is not None
    limits = control.limits
    ledger, ledger_record = _load_ledger(console)
    if ledger.last_tick_at is not None and parsed(at) < parsed(_plus(ledger.last_tick_at, hours=limits.tick_every_hours)):
        due = _plus(ledger.last_tick_at, hours=limits.tick_every_hours)
        return _not_run(console, now=at, why=f"not due: the last tick ran {ledger.last_tick_at[:16]} and the owner allows one every {limits.tick_every_hours}h", next_tick_at=due)
    if ledger.running_since is not None and parsed(at) < parsed(_plus(ledger.running_since, minutes=RUNNING_STALE_MINUTES)):
        return _not_run(console, now=at, why=f"busy: the tick started {ledger.running_since[:16]} is still running")
    day = at[:10]
    try:
        ledger, ledger_record = _save_ledger(console, ledger, {"day": day, "actions_today": ledger.actions_today if ledger.day == day else 0, "running_since": at, "running_tick": tick_ref}, now=at, existing=ledger_record)
    except EngineStateConflictError:
        return _not_run(console, now=at, why="busy: another tick claimed this one first")

    from lightbulb.company_hosted_scheduler import OwnerSwitchHeld

    mandate = current_mandate(console)
    accounts = {str(tool): str(ref) for tool, ref in dict(connector_account_refs or {}).items()}
    executor = getattr(console, "connector_executor", None)
    buckets: dict[str, list[dict[str, Any]]] = {"did": [], "held": [], "asks": [], "ruled_out": [], "waiting": []}
    counters = {"actions_today": ledger.actions_today, "failures": ledger.failures_in_a_row}
    # when each person was last messaged, kept for the cooldown (and a day at least, so a cooldown of zero still shows it)
    contacts = {mark.subject: mark.at for mark in ledger.contacts if parsed(at) < parsed(_plus(mark.at, days=max(limits.contact_cooldown_days, 1)))}
    notified: list[str] = []
    outcome, stopped_because, step, effect = "ran", None, None, False

    def breaker() -> None:
        if counters["failures"] >= limits.max_failures_in_a_row:
            raise _Breaker(f"{counters['failures']} failure(s) in a row")

    def still_on() -> None:
        if fence is not None:
            try:
                fence()
            except OwnerSwitchHeld as held:
                raise _Stop(str(held)[:300]) from held
            except Exception as lost:
                raise _FenceLost() from lost
        current, _ = load_control(console)
        if current is None or current.control_digest != control.control_digest:
            raise _Stop("the owner's switch changed during the tick" + ("" if current is None else f": {current.state} ({current.by}), {current.reason}")[:250])
        platform = _platform_hold(console)
        if platform is not None:
            raise _Stop(platform[:300])

    def progress() -> None:
        nonlocal ledger, ledger_record
        ledger, ledger_record = _save_ledger(console, ledger, {"actions_today": counters["actions_today"], "failures_in_a_row": counters["failures"], "contacts": [{"subject": subject, "at": stamp} for subject, stamp in sorted(contacts.items(), key=lambda item: item[1])][-MAX_CONTACTS:]}, now=at, existing=ledger_record)

    try:
        try:
            still_on()
            step = build_operating_step_document(console, now=at)
            read_row = next((row for row in step["queue"] if row["step"] == "read" and row["tool"] == "company_backfill"), None)
            if read_row is not None:
                if not limits.read_books:
                    buckets["waiting"].append(_row_entry(read_row, "waiting", "the owner turned book reads off in the autopilot's limits"))
                else:
                    entry, failed = _read_books(console, now=at, row=read_row, accounts=accounts, executor=executor, still_on=still_on)
                    buckets["did" if entry["outcome"] in ("recorded", "failed") else "waiting"].append(entry)
                    counters["failures"] = counters["failures"] + 1 if failed else (0 if entry["outcome"] == "recorded" else counters["failures"])
                    progress()
                    breaker()
                    if entry["outcome"] == "recorded":
                        step = build_operating_step_document(console, now=at)
            digest_due = False
            for row in step["queue"]:
                if row["step"] == "read":
                    continue
                if row["autonomy"] == "never":
                    buckets["ruled_out"].append(_row_entry(row, "ruled_out", row["mandate_reason"]))
                elif row["tool"] == "company_act" and row.get("action_kind") == "send_digest":
                    if limits.send_digest:
                        digest_due = True
                    else:
                        buckets["waiting"].append(_row_entry(row, "waiting", "the owner turned the digest off in the autopilot's limits"))
                elif row["tool"] == "company_act" and row.get("action_kind") == "chase_overdue":
                    continue  # the act plan below turns every reminder that is due into an action
                elif row["tool"] == "platform.software_factory":
                    buckets["waiting"].append(_row_entry(row, "waiting", "the platform's software factory carries this out under the mandate"))
                else:
                    buckets["asks"].append(_row_entry(row, "asked", row["mandate_reason"] if row["autonomy"] == "ask" else "the autopilot does not carry this out yet; the owner or an operator does it with " + str(row["tool"])))
            still_on()
            plan_owner_actions_document(console, now=at, digest_channel="in_app" if digest_due else None)
            candidates = [action for action in persisted_owner_actions(console) if action.action_kind in DISPATCHED_KINDS and action.status in DISPATCHABLE_STATUSES]
            candidates.sort(key=lambda action: (action.action_kind != "send_digest", -action.money, action.planned_at, action.action_ref))
            waiting_on_platform = {action.subject for action in candidates if action.action_kind in CONTACT_KINDS and action.status == "awaiting_approval"}
            room = min(limits.max_actions_per_tick, max(0, limits.max_actions_per_day - counters["actions_today"]))
            for index, action in enumerate(candidates):
                try:
                    still_on()
                except _Stop:
                    for rest in candidates[index:]:
                        buckets["held"].append(_action_entry(rest, "held", "the owner's switch changed; not sent"))
                    raise
                if room <= 0:
                    buckets["held"].append(_action_entry(action, "held", f"the limit is reached: {limits.max_actions_per_tick} a tick, {limits.max_actions_per_day} a day ({counters['actions_today']} today)"))
                    continue
                if action.action_kind in CONTACT_KINDS and action.status == "planned":
                    last = contacts.get(action.subject)
                    if last is not None and limits.contact_cooldown_days > 0 and parsed(at) < parsed(_plus(last, days=limits.contact_cooldown_days)):
                        buckets["held"].append(_action_entry(action, "held", f"messaged {last[:10]}; one message per person per {limits.contact_cooldown_days} day(s)"))
                        continue
                    if action.subject in waiting_on_platform:
                        buckets["held"].append(_action_entry(action, "held", "another message to them is waiting for the owner's approval"))
                        continue
                before = action.status
                try:
                    touched_rows = dispatch_owner_actions_document(console, now=at, connector_account_refs=accounts, action_refs=[action.action_ref])["touched"]
                    touched = touched_rows[0] if touched_rows else None
                except (_Stop, _FenceLost):
                    raise
                except Exception as exc:  # a platform or store error on one action is that action's failure, not the loop's
                    touched = {"status": "failed", "note": f"{type(exc).__name__}: {exc}"[:300]}
                if touched is None:
                    continue
                if touched.get("skipped"):
                    buckets["waiting"].append(_action_entry(action, "waiting", str(touched["skipped"])))
                    continue
                status = str(touched.get("status"))
                if before == "planned" or status == "done":
                    room -= 1
                    counters["actions_today"] += 1
                effect = effect or (status == "done" and touched.get("execution") == "connector")
                buckets["did"].append(_action_entry(action, status if status in ("done", "awaiting_approval", "blocked", "failed", "reconcile", "declined") else "failed", touched.get("note") or touched.get("error_code") or touched.get("message")))
                if status == "done" and action.action_kind in CONTACT_KINDS:
                    contacts[action.subject] = at
                if status == "awaiting_approval" and action.action_kind in CONTACT_KINDS:
                    waiting_on_platform.add(action.subject)
                if status == "blocked":
                    buckets["asks"].append(_action_entry(action, "asked", f"the platform refused it ({touched.get('note') or touched.get('error_code') or 'blocked'}); the owner decides"))
                counters["failures"] = counters["failures"] + 1 if status in ("failed", "reconcile") else (0 if status in ("done", "awaiting_approval") else counters["failures"])
                progress()
                try:
                    breaker()
                except _Breaker:
                    for rest in candidates[index + 1:]:
                        buckets["held"].append(_action_entry(rest, "held", "the autopilot paused itself after failures in a row"))
                    raise
            # what other companies sent comes in first, so a document that arrived since the last tick is answered in this one
            transport = getattr(console, "exchange_transport", None)
            if callable(getattr(transport, "drain", None)):
                try:
                    taken = transport.drain(console, now=at)
                except (ValueError, LookupError) as exc:
                    buckets["asks"].append(_entry("exchange:inbox", "exchange", "the exchange inbox", "asked", f"the inbox could not be taken in: {exc}"))
                else:
                    # a business whose first request for quote came in is taken on as a customer when the mandate lets the agent, and answered below
                    welcomed = {row["address"]: row for row in _welcome_new_customers(console, now=at, taken=taken)}
                    for row in taken["received"]:
                        if not row["sender_registered"]:
                            took = welcomed.get(str(row.get("from_address")), {})
                            if took.get("outcome") == "registered" and took.get("exchange_ref") == row["exchange_ref"]:
                                effect = True
                                buckets["did"].append(_entry(f"exchange:{row['exchange_ref']}", "exchange", f"{row['kind']} from {row['from_party']}", "done",
                                                             f"took on {took.get('display_name') or row['from_party']} as a new customer under the mandate ({row['from_address']}; {_describe_track_record(took.get('track_record'))})"[:300]))
                            elif took.get("outcome") == "registered":
                                continue
                            else:
                                why = f" (registering it failed: {took.get('code')})" if took.get("outcome") == "failed" else ""
                                buckets["asks"].append(_entry(f"exchange:{row['exchange_ref']}", "exchange", f"{row['kind']} from {row['from_party']}", "asked",
                                                              f"a company not yet registered sent it ({row['from_address']}): register it with company_exchange counterparty before the agent answers"
                                                              f"{why}; the mandate's take_new_customer can let the agent take on businesses that ask for a quote"[:300]))
                    for row in taken["refused"]:
                        buckets["asks"].append(_entry(f"exchange:{row['exchange_ref']}", "exchange", f"{row['kind']} from {row['from_party']}", "asked",
                                                      f"refused on arrival ({row['code']}); the sender was told"))
                    for row in taken["received"]:
                        if row.get("kind") == "remittance":
                            buckets["did"].append(_entry(f"exchange:{row['exchange_ref']}", "exchange", f"remittance from {row['from_party']}", "done",
                                                         "taken in: the customer says the invoice is paid; reminders for it wait while the transfer lands"))
                    for row in taken["received"]:
                        booked = dict(row.get("books") or {})
                        if booked.get("applied"):
                            buckets["did"].append(_entry(f"exchange:{row['exchange_ref']}", "exchange", f"{row['kind']} from {row['from_party']}", "done",
                                                         f"put in the books ({booked['engine'].replace('_', ' ')}: {booked['status']}); paying it needs the owner's approval"))
                        elif booked.get("code"):
                            buckets["asks"].append(_entry(f"exchange:{row['exchange_ref']}", "exchange", f"{row['kind']} from {row['from_party']}", "asked",
                                                          f"taken in, but the books refused it ({booked['code']}): {booked.get('detail') or ''}"[:300]))
                    if taken.get("unsettled"):
                        codes = ", ".join(sorted({str(row.get("code")) for row in taken["unsettled"]}))
                        buckets["held"].append(_entry("exchange:inbox", "exchange", "the exchange inbox", "held",
                                                      f"{len(taken['unsettled'])} left in the inbox for the next pass ({codes})"))
            # the exchanges where it is this company's turn: answer each under the mandate, within what is left of the limits
            for turn in _exchange_turns(console, now=at):
                still_on()
                subject = f"{turn['next_kind']}: {turn['counterparty']}"
                if room <= 0:
                    buckets["held"].append(_entry(turn["exchange_ref"], "exchange", subject, "held", f"the limit is reached: {limits.max_actions_per_tick} a tick, {limits.max_actions_per_day} a day ({counters['actions_today']} today)", money=turn["value"]))
                    continue
                try:
                    view = _answer_exchange(console, now=at, turn=turn)
                except (ValueError, LookupError) as exc:  # the catalog does not cover it, the owner ruled it out, the quote lapsed...
                    buckets["asks"].append(_entry(turn["exchange_ref"], "exchange", subject, "asked", f"the autopilot cannot answer it: {exc}", money=turn["value"]))
                    continue
                room -= 1
                counters["actions_today"] += 1
                document = dict(view.get("document") or {})
                sent = dict(view["delivery"].get(document.get("document_digest"), {})).get("status")
                effect = effect or sent == "sent"
                if sent == "sent":
                    booked = dict(view.get("books") or {})
                    in_books = f"; in the books ({booked['engine'].replace('_', ' ')}: {booked['status']})" if booked.get("applied") else f"; the books refused it ({booked['code']})" if booked.get("code") else ""
                    buckets["did"].append(_entry(turn["exchange_ref"], "exchange", subject, "done", f"sent under the mandate{in_books}", money=document.get("total") or "0"))
                elif sent == "waiting_for_owner":
                    buckets["asks"].append(_entry(turn["exchange_ref"], "exchange", subject, "asked", f"prepared; the mandate asks the owner: company_exchange send with owner_ref ({view['waiting'][0].get('reason', '')})"[:300], money=document.get("total") or "0"))
                else:
                    buckets["waiting"].append(_entry(turn["exchange_ref"], "exchange", subject, "waiting", "prepared; no transport: deliver it by hand, then company_exchange send with delivered_by_hand", money=document.get("total") or "0"))
                progress()
            # sourcing: order from the best quote of each request whose quotes are in, under the mandate; tell the owner what waits for them
            for turn in _sourcing_turns(console, now=at):
                still_on()
                key = f"sourcing:{turn['sourcing_ref']}"
                if turn["do"] != "award":
                    buckets["asks"].append(_entry(key, "sourcing", turn["subject"], "asked", str(turn.get("detail") or "")[:300]))
                    continue
                if room <= 0:
                    buckets["held"].append(_entry(key, "sourcing", turn["subject"], "held", f"the limit is reached: {limits.max_actions_per_tick} a tick, {limits.max_actions_per_day} a day ({counters['actions_today']} today)", money=turn["value"]))
                    continue
                try:
                    view = _award_sourcing(console, now=at, turn=turn)
                except (ValueError, LookupError) as exc:  # the owner ruled it out, the quote lapsed, the platform refused the order...
                    buckets["asks"].append(_entry(key, "sourcing", turn["subject"], "asked", f"the autopilot cannot order it: {exc}"[:300], money=turn["value"]))
                    continue
                room -= 1
                counters["actions_today"] += 1
                chosen = dict(view.get("chosen") or {})
                order = dict(view.get("order") or {})
                document = dict(order.get("document") or {})
                sent = dict(order.get("delivery", {}).get(document.get("document_digest"), {})).get("status")
                effect = effect or sent == "sent"
                won = f"{chosen.get('display_name')} at {chosen.get('total')} {chosen.get('currency')}"
                if sent == "sent":
                    buckets["did"].append(_entry(key, "sourcing", turn["subject"], "done", f"ordered from {won}, the best of {len(view.get('quotes') or []) + len(view.get('ordered') or [])} quote(s), under the mandate"[:300], money=chosen.get("total") or "0"))
                elif sent == "waiting_for_owner":
                    buckets["asks"].append(_entry(key, "sourcing", turn["subject"], "asked", f"the order to {won} is prepared; the mandate asks the owner: company_exchange send with owner_ref"[:300], money=chosen.get("total") or "0"))
                else:
                    buckets["waiting"].append(_entry(key, "sourcing", turn["subject"], "waiting", f"the order to {won} is prepared; no transport: deliver it by hand, then company_exchange send with delivered_by_hand"[:300], money=chosen.get("total") or "0"))
                progress()
            # standing orders: ask for each cycle that falls due and order its quote within the ceilings, under the owner's standing approval
            for standing_ref in _standing_turns(console):
                still_on()
                key = f"standing:{standing_ref}"
                if room <= 0:
                    buckets["held"].append(_entry("standing", "standing", "standing orders", "held", f"the limit is reached: {limits.max_actions_per_tick} a tick, {limits.max_actions_per_day} a day; the standing orders wait for the next tick"))
                    break
                try:
                    step = _advance_standing(console, now=at, standing_ref=standing_ref)
                except (ValueError, LookupError) as exc:
                    buckets["asks"].append(_entry(key, "standing", f"standing order {standing_ref}", "asked", f"the autopilot cannot advance it: {exc}"[:300]))
                    continue
                if step is None or step["step"] == "record":
                    continue
                # a counter-offer is a message to the supplier, like the request: it counts as an action
                subject = f"standing order {standing_ref}, cycle {step['cycle']}"
                if step["step"] == "owner":
                    buckets["asks"].append(_entry(key, "standing", subject, "asked", f"cycle {step['cycle']}: {step['detail']}; the owner decides (company_exchange standing_orders)"[:300], money=step["money"]))
                    continue
                room -= 1
                counters["actions_today"] += 1
                effect = True
                buckets["did"].append(_entry(key, "standing", subject, "done", step["detail"], money=step["money"]))
                progress()
        except _Stop as stop:
            outcome, stopped_because = "stopped", str(stop)[:300] or "the owner's switch changed"
        except _Breaker as tripped:
            outcome, stopped_because = "paused_itself", str(tripped)
        except _FenceLost:
            raise
        except Exception as exc:  # the tick itself broke: record it, count it, and let the breaker decide
            outcome, stopped_because = "failed", f"{type(exc).__name__}: {exc}"[:300]
            counters["failures"] += 1
            if counters["failures"] >= limits.max_failures_in_a_row:
                outcome = "paused_itself"
        if outcome == "paused_itself":
            current, current_record = load_control(console)
            if current is not None and current.control_digest == control.control_digest:
                reason = f"it paused itself after {counters['failures']} failure(s) in a row" + ("" if stopped_because is None or stopped_because.startswith(str(counters["failures"])) else f" (the last: {stopped_because})")
                changed = _change(console, current, current_record, now=at, state="paused", by=AUTOPILOT_AGENT, reason=reason[:300])
                key = f"autopilot-switch:{changed.control_digest[:24]}"
                if _notify(console, key=key, title="The autopilot paused itself", message=f"{changed.reason}. Nothing runs on its own until you resume it with company_autopilot resume."):
                    notified.append(key)
        # what needs the owner, told once while it stays the same
        asks = buckets["asks"]
        asks_digest = stable_digest(sorted(entry["key"] for entry in asks)) if asks else None
        remembered = list(ledger.notified)
        if asks and asks_digest != ledger.asks_digest and outcome != "stopped":
            key = f"autopilot-asks:{str(asks_digest)[:24]}"
            lines = [f"- {entry['subject']}: {entry['detail'] or entry['outcome']}" for entry in asks[:20]]
            if _notify(console, key=key, title=f"{len(asks)} thing(s) need you", message="The autopilot left these for you:\n" + "\n".join(lines)):
                notified.append(key)
            else:
                asks_digest = ledger.asks_digest
        elif not asks:
            asks_digest = None
        else:
            asks_digest = ledger.asks_digest
        on_until = str(control.on_until)
        reminder = f"autopilot-grant:{on_until}"
        if outcome != "stopped" and parsed(on_until) - parsed(at) <= timedelta(days=LEASE_REMINDER_DAYS) and reminder not in remembered:
            if _notify(console, key=reminder, title="The autopilot switches off soon", message=f"Your grant ends {on_until[:16]}. After that nothing runs on its own until you turn it on again with company_autopilot start."):
                notified.append(reminder)
                remembered.append(reminder)
        # the journal the next session starts from
        did_rows = [{"key": entry["key"], "result": f"{entry['outcome']}: {entry['detail'] or entry['subject']}"[:300]} for entry in buckets["did"]]
        promised = [{"check": "customer_paid", "subject": entry["subject"].split(": ", 1)[-1]} for entry in buckets["did"] if entry["step"] == "do" and entry["outcome"] in ("done", "awaiting_approval")]
        handover = (f"autopilot tick {at[:16]}: {outcome}" + (f" ({stopped_because})" if stopped_because else "") + f"; did {len(buckets['did'])}, held back {len(buckets['held'])}, {len(asks)} for the owner, {len(buckets['waiting'])} waiting")
        try:
            record_operator_journal(console, now=at, agent_ref=AUTOPILOT_AGENT, handover=handover, did=did_rows[:100], promised=promised[:100], step_digest=None if step is None else step.get("step_digest"))
        except ValueError:
            pass  # an entry already holds this exact time; the tick record below is the trace
        still_running = outcome in ("ran", "failed")
        next_tick_at = _plus(at, hours=limits.tick_every_hours) if still_running else None
        sealed = seal(AutopilotTick, {"company_ref": console.bundle.company_ref, "at": at, "control_digest": control.control_digest, "mandate_digest": None if mandate is None else mandate.mandate_digest, "step_digest": None if step is None else step.get("step_digest"), "outcome": outcome, "stopped_because": stopped_because, **{name: rows[:MAX_ENTRIES] for name, rows in buckets.items()}, "notified": notified[:10], "actions_today": counters["actions_today"], "failures_in_a_row": counters["failures"], "next_tick_at": next_tick_at}, "tick_digest")
        _put(console, tick_ref, key="tick", document=sealed.to_dict(), digest=sealed.tick_digest, now=at, status=outcome, existing=None)
        line = {"at": at, "outcome": outcome, "did": len(sealed.did), "held": len(sealed.held), "asks": len(sealed.asks), "tick_digest": sealed.tick_digest}
        ledger, ledger_record = _save_ledger(console, ledger, {"actions_today": counters["actions_today"], "failures_in_a_row": counters["failures"], "contacts": [{"subject": subject, "at": stamp} for subject, stamp in sorted(contacts.items(), key=lambda item: item[1])][-MAX_CONTACTS:], "ticks": ledger.ticks + 1, "last_tick_at": at, "running_since": None, "running_tick": None, "asks_digest": asks_digest, "notified": remembered[-MAX_NOTIFIED:], "recent": [*[item.to_dict() for item in ledger.recent], line][-MAX_RECENT:]}, now=at, existing=ledger_record)
        return {**sealed.to_dict(), "ran": True, "summary": sealed.render(), "provider_effect_executed": effect}
    except _FenceLost as lost:
        # the host no longer holds the company: free the tick for whoever does, and hand the host its own error
        try:
            _save_ledger(console, ledger, {"running_since": None, "running_tick": None, "actions_today": counters["actions_today"], "failures_in_a_row": counters["failures"]}, now=at, existing=ledger_record)
        except Exception:
            pass  # the marker goes stale after fifteen minutes anyway
        raise lost.__cause__ from None


# --------------------------------------------------------------------------- #
# What the owner sees
# --------------------------------------------------------------------------- #


def persisted_autopilot_ticks(console: Any) -> list[AutopilotTick]:
    """Every tick recorded for this company, newest first."""

    rows = []
    for record in console.store.list_all(engine=AUTOPILOT_ENGINE):
        if not str(record.get("entity_ref", "")).startswith("tick:"):
            continue
        state = dict(record["state"])
        if state.get("schema") != AUTOPILOT_RECORD_SCHEMA or "tick" not in state:
            continue
        tick = verify_autopilot_tick(state["tick"])
        if tick.company_ref == console.bundle.company_ref:
            rows.append(tick)
    return sorted(rows, key=lambda tick: tick.at, reverse=True)


def list_autopilot_ticks(console: Any, *, now: str, limit: Any = 20) -> dict[str, Any]:
    _require(not isinstance(limit, bool) and str(limit).strip().isdigit() and 1 <= int(str(limit)) <= 200, "LIMIT_INVALID", "limit is 1 to 200")
    ticks = persisted_autopilot_ticks(console)[: int(str(limit))]
    return {"schema": "lightbulb.autopilot_ticks.v1", "company_ref": console.bundle.company_ref, "as_of": timestamp(now, field_name="now"), "ticks": [tick.to_dict() for tick in ticks], "count": len(ticks), "summary": "\n\n".join(tick.render() for tick in ticks) or "no tick has run", "provider_effect_executed": False}


def autopilot_status_document(console: Any, *, now: str) -> dict[str, Any]:
    """Everything about the autopilot in one place: the switch and who set it, the grant, the limits and how much of today is used, the last ticks, what is queued, what waits on the owner, and how to stop it."""

    from lightbulb.company_act_surface import persisted_owner_actions
    from lightbulb.owner_actions import DISPATCHABLE_STATUSES

    at = timestamp(now, field_name="now")
    control, _ = load_control(console)
    ledger, _ = _load_ledger(console)
    state, why = ("off", _why_not(None)) if control is None else (control.state, _why_not(control))
    if control is not None and control.state == "on" and parsed(at) >= parsed(str(control.on_until)):
        state, why = "off", f"off: the owner's grant ended {str(control.on_until)[:16]} (the next tick records it)"
    elif control is not None and control.state == "on":
        problem = _mandate_problem(console, control, now=at)
        if problem is not None:
            state, why = "paused", f"paused: {problem} (the next tick records it)"
    platform = platform_stop(console)
    platform_holds = platform is not None and bool(platform.get("stopped"))
    if platform_holds:
        why = f"stopped on the platform ({platform.get('halted_by') or 'the owner stop'}); the owner resumes it there"
    limits = AutopilotLimits() if control is None else control.limits
    today = ledger.actions_today if ledger.day == at[:10] else 0
    next_tick_at = None
    if state == "on" and not platform_holds:
        next_tick_at = at if ledger.last_tick_at is None else max(at, _plus(ledger.last_tick_at, hours=limits.tick_every_hours), key=parsed)
    queued = [{"action_ref": action.action_ref, "kind": action.action_kind, "subject": action.subject, "status": action.status, "money": str(action.money), "planned_at": action.planned_at} for action in persisted_owner_actions(console) if action.status in DISPATCHABLE_STATUSES]
    last_record = console.store.get(AUTOPILOT_ENGINE, f"tick:{ledger.last_tick_at}") if ledger.last_tick_at else None
    last = None if last_record is None else verify_autopilot_tick(dict(last_record["state"])["tick"])
    days_left = None if control is None or control.on_until is None or state == "off" else max(0, (parsed(str(control.on_until)) - parsed(at)).days)
    lines = [f"**Autopilot** ({console.bundle.company_ref}, {at[:16]}): {state.upper()}" + ("" if why is None else f"; {why}")]
    if control is not None and state != "off":
        lines.append(f"- the owner's grant ({control.owner_ref}) ends {str(control.on_until)[:16]} ({days_left} day(s) left)")
    lines.append(f"- limits: {limits.render()}; {today} of {limits.max_actions_per_day} used today; {ledger.failures_in_a_row} failure(s) in a row")
    if next_tick_at:
        lines.append(f"- next tick {next_tick_at[:16]}")
    lines.extend(f"- tick {item.at[:16]}: {item.outcome}, did {item.did}, held back {item.held}, {item.asks} for the owner" for item in reversed(ledger.recent[-5:]))
    lines.extend(f"- queued: {row['kind']} {row['subject']} ({row['status']})" for row in queued[:10])
    if last is not None:
        lines.extend(f"- needs you: {entry.subject}: {entry.detail or entry.outcome}" for entry in last.asks[:10])
    if platform_holds:
        lines.append(f"- the platform's owner stop holds the company ({platform.get('halted_by')}): nothing runs until the owner resumes it there")
    elif platform is not None and platform.get("unreadable"):
        lines.append(f"- the platform's owner stop could not be read ({platform['unreadable'][:120]}); the platform still enforces it where work starts")
    lines.append("- to stop everything it does: company_autopilot stop (payload reason; withdraw true also withdraws what is queued)")
    return {
        "schema": AUTOPILOT_STATUS_SCHEMA,
        "company_ref": console.bundle.company_ref,
        "as_of": at,
        "state": state,
        "why": why,
        "control": None if control is None else control.to_dict(),
        "limits": limits.to_dict(),
        "on_until": None if control is None or state == "off" else control.on_until,
        "days_left": days_left,
        "next_tick_at": next_tick_at,
        "actions_today": today,
        "failures_in_a_row": ledger.failures_in_a_row,
        "ticks": ledger.ticks,
        "recent": [item.to_dict() for item in ledger.recent],
        "queued": queued,
        "waiting_on_owner": [] if last is None else [entry.to_dict() for entry in last.asks],
        "platform": platform,
        "how_to_stop": "company_autopilot stop with a reason stops every tick at its next step; withdraw true also withdraws every action still queued. Anyone may stop or pause it; only the mandate's owner starts or resumes it.",
        "summary": "\n".join(lines),
        "provider_effect_executed": False,
    }


@dataclass
class HostedAutopilot:
    """The owner's switch and one autopilot pass, as the hosted worker runs them: while the switch is off the worker does nothing but look at it again every ``poll_seconds``.

    The worker holds the bundle it was started with, and its cadence is
    pinned to that bundle's digest, so that bundle is never touched.  The owner
    sets the mandate on the project's stored bundle (``company_mandate set``),
    so the autopilot works through a console of its own over the stored bundle
    (the same store, executor and notifier), re-read at most once a minute; a
    project with no stored bundle has only the worker's.
    """

    console: Any
    connector_account_refs: Mapping[str, str] = field(default_factory=dict)
    poll_seconds: int = 900
    _view: Any = field(default=None, init=False, repr=False)
    _view_read_at: str | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        _require(not isinstance(self.poll_seconds, bool) and 60 <= int(self.poll_seconds) <= 3600, "POLL_INVALID", "the worker looks at the switch every 60 to 3600 seconds while it is off")
        self.connector_account_refs = {str(tool): str(ref) for tool, ref in dict(self.connector_account_refs).items()}

    def current(self, *, now: str) -> Any:
        """The console the autopilot works through: the stored bundle's when the project holds one for this company, else the worker's."""

        from lightbulb.company_bootstrap import load_company_bundle
        from lightbulb.company_console import CompanyConsole

        at = timestamp(now, field_name="now")
        if self._view_read_at is not None and parsed(at) < parsed(_plus(self._view_read_at, seconds=60)):
            return self._view or self.console
        self._view_read_at = at
        try:
            stored = load_company_bundle(self.console.store, project_id=self.console.bundle.scope.get("project_id"))
        except LookupError:
            self._view = None
            return self.console
        if stored.get("company_ref") != self.console.bundle.company_ref:
            self._view = None
            return self.console
        if self._view is None or self._view.bundle.bundle_digest != stored.get("bundle_digest"):
            self._view = CompanyConsole.from_document(stored, self.console.store, self.console.clock, approval_requester=getattr(self.console, "approval_requester", None), connector_executor=getattr(self.console, "connector_executor", None), owner_notifier=getattr(self.console, "owner_notifier", None), autonomy_reader=getattr(self.console, "autonomy_reader", None))
            self._view.exchange_transport = getattr(self.console, "exchange_transport", None)  # type: ignore[attr-defined]
        return self._view

    def held(self, *, now: str) -> str | None:
        return held_reason(self.current(now=now), now=now)

    def tick(self, *, now: str, fence: Callable[[], Any] | None = None) -> dict[str, Any]:
        return run_autopilot_tick(self.current(now=now), now=now, connector_account_refs=self.connector_account_refs, fence=fence)

    def status(self, *, now: str) -> dict[str, Any]:
        return autopilot_status_document(self.current(now=now), now=now)


__all__ = [
    "AUTOPILOT_AGENT",
    "AUTOPILOT_CONTROL_SCHEMA",
    "AUTOPILOT_ENGINE",
    "AUTOPILOT_LEDGER_SCHEMA",
    "AUTOPILOT_MANIFEST",
    "AUTOPILOT_STATUS_SCHEMA",
    "AUTOPILOT_TICK_SCHEMA",
    "AutopilotControl",
    "AutopilotError",
    "AutopilotLedger",
    "AutopilotLimits",
    "AutopilotTick",
    "ControlChange",
    "HostedAutopilot",
    "TickEntry",
    "autopilot_status_document",
    "held_reason",
    "list_autopilot_ticks",
    "load_control",
    "pause_autopilot",
    "persisted_autopilot_ticks",
    "resume_autopilot",
    "run_autopilot_tick",
    "start_autopilot",
    "stop_autopilot",
    "verify_autopilot_control",
    "verify_autopilot_ledger",
    "verify_autopilot_tick",
]
