"""The board cadence chain: one replay-fenced lifecycle per board meeting, from the call to tracked resolutions.

``company_brief.board_pack`` rolls the month up into a sealed pack.  Nothing
held the meeting it went to: who was called, whether the pack went out in
time, who attended and whether that was a quorum, what was resolved and by
what vote, whose minutes recorded it, and whether the actions the board
asked for were done.  ``BOARD_CADENCE_LIFECYCLE`` does:

    called -> pack_issued -> held -> minuted -> (track_actions)* -> closed   (terminal)
    called | pack_issued -> cancelled                                         (terminal, with a reason)

* ``call_receipt`` names the meeting, its time, and the agenda; decision
  items are the only ones a resolution may attach to.
* ``pack_receipt`` binds the sealed board pack (and optionally the sealed
  cash forecast) and must be issued the plan's lead time before the meeting.
* ``attendance_receipt`` lists who was present; the voting directors present
  must meet the plan's quorum.  Resolutions are recorded with their votes and
  ``carried`` is computed, never typed; a director who declared an interest
  in the item is refused as a voter on it.
* ``minutes_receipt`` is the secretary's record, approved by the chair,
  inside the plan's window, with the actions the board assigned.
* ``track_actions`` closes actions with evidence; the meeting closes when
  every action is done or explicitly carried forward.

``resolution_register`` and ``overdue_actions`` are what the operating
system consumes; ``signals.board_action_overdue`` names the actions the
board is still waiting on.  Nothing here sends a notice or persists anything.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import timedelta
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    BoundedText,
    CurrencyCode,
    LifecycleSpec,
    OpaqueRef,
    Sha256Digest,
    ShortText,
    StrictModel,
    detached,
    parsed,
    require,
    seal,
    sealed_digest,
    skip_digests,
    stable_digest,
    timestamp,
    unique,
)

BOARD_CADENCE_KIND = "board_cadence_chain"
BOARD_CADENCE_GOLDEN_LOOP = "governance.board_cycle_to_tracked_resolutions@0.1.0"
BOARD_CADENCE_PLAN_SCHEMA = "lightbulb.board_cadence_plan.v1"
MAX_BOARD_TRANSITIONS = 200
DirectorRole = Literal["chair", "director", "secretary", "observer"]
AgendaKind = Literal["decision", "report", "noting"]

BOARD_STATUSES: tuple[str, ...] = ("called", "pack_issued", "held", "minuted", "closed", "cancelled")
TERMINAL_BOARD_STATUSES: frozenset[str] = frozenset({"closed", "cancelled"})
BOARD_EVENTS: tuple[str, ...] = ("call_meeting", "issue_pack", "hold_meeting", "record_minutes", "track_actions", "close", "cancel")
_BOARD_TABLE: dict[tuple[str, str], str] = {
    ("new", "call_meeting"): "called",
    ("called", "issue_pack"): "pack_issued",
    ("pack_issued", "hold_meeting"): "held",
    ("held", "record_minutes"): "minuted",
    ("minuted", "track_actions"): "minuted",
    ("minuted", "close"): "closed",
    ("called", "cancel"): "cancelled",
    ("pack_issued", "cancel"): "cancelled",
}


class BoardCadenceError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise BoardCadenceError(code, message)


# --------------------------------------------------------------------------- #
# Plan
# --------------------------------------------------------------------------- #


class Director(StrictModel):
    director_ref: OpaqueRef
    role: DirectorRole = "director"
    voting: bool = True


class BoardCadencePlan(StrictModel):
    """What the chain enforces: who sits on the board, the quorum, how far ahead the pack goes out, and how quickly minutes follow."""

    schema_id: str = Field(default=BOARD_CADENCE_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    directors: tuple[Director, ...] = Field(min_length=1, max_length=30)
    quorum: int = Field(ge=1, le=30)
    pack_lead_days: int = Field(default=5, ge=0, le=60)
    minutes_days: int = Field(default=14, ge=1, le=90)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("directors", mode="before")
    @classmethod
    def _sequences(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "BoardCadencePlan":
        unique([item.director_ref for item in self.directors], label="directors")
        voting = sum(1 for item in self.directors if item.voting)
        if self.quorum > voting:
            raise ValueError(f"the quorum {self.quorum} exceeds the {voting} voting director(s)")
        if sum(1 for item in self.directors if item.role == "chair") != 1:
            raise ValueError("a board names exactly one chair")
        if sum(1 for item in self.directors if item.role == "secretary") != 1:
            raise ValueError("a board names exactly one secretary")
        if not skip_digests(info) and self.plan_digest != sealed_digest(BoardCadencePlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self

    def director(self, director_ref: str) -> Director | None:
        return next((item for item in self.directors if item.director_ref == director_ref), None)

    @property
    def chair_ref(self) -> str:
        return next(item.director_ref for item in self.directors if item.role == "chair")

    @property
    def secretary_ref(self) -> str:
        return next(item.director_ref for item in self.directors if item.role == "secretary")


def compile_board_cadence_chain(company_ref: str, *, currency: str, directors: Sequence[Mapping[str, Any]], quorum: int, overrides: Mapping[str, Any] | None = None) -> BoardCadencePlan:
    raw: dict[str, Any] = {"company_ref": company_ref, "currency": str(currency).upper(), "directors": [dict(detached(item)) for item in directors], "quorum": quorum, **dict(overrides or {})}
    return seal(BoardCadencePlan, raw, "plan_digest")


# --------------------------------------------------------------------------- #
# Receipts, ledger, lifecycle
# --------------------------------------------------------------------------- #


class AgendaItem(StrictModel):
    item_ref: OpaqueRef
    title: ShortText
    kind: AgendaKind = "report"


class Resolution(StrictModel):
    resolution_ref: OpaqueRef
    item_ref: OpaqueRef
    text: BoundedText
    votes_for: int = Field(ge=0, le=30)
    votes_against: int = Field(ge=0, le=30)
    abstained: int = Field(ge=0, le=30)
    interested_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=30)
    carried: bool = False

    @field_validator("interested_refs", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value


class ActionItem(StrictModel):
    action_ref: OpaqueRef
    resolution_ref: OpaqueRef | None = None
    owner_ref: OpaqueRef
    title: ShortText
    due_at: str
    completed_at: str | None = None
    evidence_sha256: Sha256Digest | None = None
    carried_forward_to: OpaqueRef | None = None

    @field_validator("due_at")
    @classmethod
    def _due(cls, value: str) -> str:
        return timestamp(value, field_name="due_at")


class BoardReceipt(StrictModel):
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    meeting_ref: OpaqueRef | None = None
    scheduled_at: str | None = None
    called_by: OpaqueRef | None = None
    agenda: tuple[AgendaItem, ...] = Field(default_factory=tuple, max_length=40)
    board_pack: dict[str, Any] | None = None
    forecast_digest: Sha256Digest | None = None
    issued_at: str | None = None
    held_at: str | None = None
    present_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=30)
    resolutions: tuple[Resolution, ...] = Field(default_factory=tuple, max_length=40)
    minutes_sha256: Sha256Digest | None = None
    recorded_by: OpaqueRef | None = None
    approved_by: OpaqueRef | None = None
    recorded_at: str | None = None
    actions: tuple[ActionItem, ...] = Field(default_factory=tuple, max_length=60)
    completed: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=60)
    carried_forward: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=60)
    detail: BoundedText | None = None

    @field_validator("evidence_refs", "agenda", "present_refs", "resolutions", "actions", "completed", "carried_forward", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("scheduled_at", "issued_at", "held_at", "recorded_at")
    @classmethod
    def _stamps(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))


class BoardLedger(StrictModel):
    meeting_ref: str | None = None
    scheduled_at: str | None = None
    called_by: str | None = None
    called_at: str | None = None
    agenda: tuple[AgendaItem, ...] = Field(default_factory=tuple, max_length=40)
    pack_digest: str | None = None
    pack_month: str | None = None
    forecast_digest: str | None = None
    pack_issued_at: str | None = None
    held_at: str | None = None
    present_refs: tuple[str, ...] = Field(default_factory=tuple, max_length=30)
    voting_present: int = 0
    quorum_met: bool = False
    resolutions: tuple[Resolution, ...] = Field(default_factory=tuple, max_length=40)
    carried: int = 0
    minutes_sha256: str | None = None
    recorded_by: str | None = None
    approved_by: str | None = None
    minuted_at: str | None = None
    actions: tuple[ActionItem, ...] = Field(default_factory=tuple, max_length=60)
    actions_open: int = 0
    closed_at: str | None = None
    cancel_reason: str | None = None
    outcome: Literal["open", "closed", "cancelled"] = "open"

    @field_validator("agenda", "present_refs", "resolutions", "actions", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value


class BoardEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    notice_sent: Literal[False] = False
    filing_made: Literal[False] = False
    provider_read: Literal[False] = False


def _iso(value: Any) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _apply_board(plan: BoardCadencePlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event, at = command.receipt, command.event, command.occurred_at
    if event == "call_meeting":
        require(r.meeting_ref is not None and r.scheduled_at is not None and r.called_by is not None and len(r.agenda) > 0, "CALL_MISSING", "a call names the meeting, its time, who called it, and the agenda")
        require(plan.director(str(r.called_by)) is not None, "CALLER_NOT_ON_BOARD", f"{r.called_by} is not on the board")
        unique([item.item_ref for item in r.agenda], label="agenda items")
        require(parsed(str(r.scheduled_at)) >= parsed(at) + timedelta(days=plan.pack_lead_days), "CALLED_TOO_LATE", f"a meeting is called at least {plan.pack_lead_days} day(s) ahead so the pack can go out in time")
        data.update({"meeting_ref": r.meeting_ref, "scheduled_at": r.scheduled_at, "called_by": r.called_by, "called_at": at, "agenda": [item.to_dict() for item in r.agenda]})
    elif event == "issue_pack":
        require(r.board_pack is not None and r.issued_at is not None, "PACK_MISSING", "the pack is the sealed board pack and the time it was issued")
        from lightbulb.company_brief import BoardPack

        try:
            pack = BoardPack.model_validate(dict(r.board_pack or {}))
        except (ValueError, TypeError) as exc:
            require(False, "PACK_NOT_SEALED", f"the board pack must validate as sealed: {exc}"[:300])
            raise AssertionError from exc
        require(pack.company_ref == plan.company_ref, "PACK_SCOPE_MISMATCH", "the pack belongs to another company")
        require(parsed(pack.prepared_at) <= parsed(str(r.issued_at)) <= parsed(at), "PACK_TIME_INVALID", "the pack is issued after it is prepared and before the recording")
        require(parsed(str(r.issued_at)) + timedelta(days=plan.pack_lead_days) <= parsed(str(data["scheduled_at"])), "PACK_ISSUED_LATE", f"the pack goes out {plan.pack_lead_days} day(s) before the meeting", "manual_reconciliation")
        data.update({"pack_digest": pack.pack_digest, "pack_month": pack.month, "forecast_digest": r.forecast_digest, "pack_issued_at": r.issued_at})
    elif event == "hold_meeting":
        require(r.held_at is not None and len(r.present_refs) > 0, "ATTENDANCE_MISSING", "holding a meeting names when and who was present")
        unique(list(r.present_refs), label="attendees")
        for ref in r.present_refs:
            require(plan.director(str(ref)) is not None, "ATTENDEE_NOT_ON_BOARD", f"{ref} is not on the board")
        require(parsed(str(data["pack_issued_at"])) <= parsed(str(r.held_at)) <= parsed(at), "HELD_TIME_INVALID", "the meeting follows the pack and precedes the recording")
        voting_present = sum(1 for ref in r.present_refs if plan.director(str(ref)) is not None and plan.director(str(ref)).voting)  # type: ignore[union-attr]
        require(voting_present >= plan.quorum, "QUORUM_NOT_MET", f"{voting_present} voting director(s) present; the quorum is {plan.quorum}", "manual_reconciliation")
        agenda = {str(item["item_ref"]): str(item["kind"]) for item in data.get("agenda", ())}
        unique([item.resolution_ref for item in r.resolutions], label="resolutions")
        resolutions = []
        for item in r.resolutions:
            require(agenda.get(str(item.item_ref)) == "decision", "RESOLUTION_NOT_ON_AGENDA", f"{item.resolution_ref} attaches to {item.item_ref}, which is not a decision item on the agenda")
            eligible = voting_present - sum(1 for ref in item.interested_refs if ref in r.present_refs)
            require(item.votes_for + item.votes_against + item.abstained <= eligible, "VOTES_EXCEED_ELIGIBLE", f"{item.resolution_ref} records more votes than eligible directors present")
            resolutions.append({**item.to_dict(), "carried": item.votes_for > item.votes_against and item.votes_for > 0})
        data.update({"held_at": r.held_at, "present_refs": list(r.present_refs), "voting_present": voting_present, "quorum_met": True, "resolutions": resolutions, "carried": sum(1 for item in resolutions if item["carried"])})
    elif event == "record_minutes":
        require(r.minutes_sha256 is not None and r.recorded_by is not None and r.approved_by is not None and r.recorded_at is not None, "MINUTES_MISSING", "minutes carry their digest, who recorded them, who approved them, and when")
        require(str(r.recorded_by) == plan.secretary_ref, "MINUTES_NOT_BY_SECRETARY", f"minutes are recorded by the secretary {plan.secretary_ref}")
        require(str(r.approved_by) == plan.chair_ref and str(r.approved_by) != str(r.recorded_by), "MINUTES_NOT_APPROVED_BY_CHAIR", f"minutes are approved by the chair {plan.chair_ref}, who is not the recorder")
        require(parsed(str(data["held_at"])) <= parsed(str(r.recorded_at)) <= parsed(at), "MINUTES_TIME_INVALID", "minutes follow the meeting")
        require(parsed(str(r.recorded_at)) <= parsed(str(data["held_at"])) + timedelta(days=plan.minutes_days), "MINUTES_LATE", f"minutes are recorded within {plan.minutes_days} day(s) of the meeting", "manual_reconciliation")
        unique([item.action_ref for item in r.actions], label="actions")
        carried = {str(item["resolution_ref"]) for item in data.get("resolutions", ()) if item["carried"]}
        for item in r.actions:
            require(item.resolution_ref is None or str(item.resolution_ref) in carried, "ACTION_WITHOUT_RESOLUTION", f"{item.action_ref} cites {item.resolution_ref}, which was not carried")
            require(parsed(item.due_at) > parsed(str(data["held_at"])), "ACTION_DUE_IN_PAST", f"{item.action_ref} is due before the meeting that raised it")
        data.update({"minutes_sha256": r.minutes_sha256, "recorded_by": r.recorded_by, "approved_by": r.approved_by, "minuted_at": r.recorded_at, "actions": [item.to_dict() for item in r.actions], "actions_open": len(r.actions)})
    elif event == "track_actions":
        require(len(r.completed) + len(r.carried_forward) > 0, "NOTHING_TRACKED", "tracking names the actions completed or carried forward")
        actions = [dict(item) for item in data.get("actions", ())]
        by_ref = {str(item["action_ref"]): item for item in actions}
        for done in r.completed:
            ref = str(done.get("action_ref"))
            require(ref in by_ref, "ACTION_UNKNOWN", f"{ref} is not an action of this meeting")
            require(by_ref[ref].get("completed_at") is None and by_ref[ref].get("carried_forward_to") is None, "ACTION_ALREADY_CLOSED", f"{ref} is already closed")
            require(bool(done.get("evidence_sha256")) and bool(done.get("completed_at")), "ACTION_EVIDENCE_MISSING", f"{ref} closes with evidence and a completion time")
            completed_at = timestamp(str(done["completed_at"]), field_name="completed_at")
            require(parsed(str(data["held_at"])) <= parsed(completed_at) <= parsed(at), "ACTION_TIME_INVALID", f"{ref} completes after the meeting and before the recording")
            by_ref[ref].update({"completed_at": completed_at, "evidence_sha256": str(done["evidence_sha256"])})
        for carried in r.carried_forward:
            ref = str(carried.get("action_ref"))
            require(ref in by_ref, "ACTION_UNKNOWN", f"{ref} is not an action of this meeting")
            require(by_ref[ref].get("completed_at") is None and by_ref[ref].get("carried_forward_to") is None, "ACTION_ALREADY_CLOSED", f"{ref} is already closed")
            require(bool(carried.get("meeting_ref")), "CARRY_FORWARD_TARGET_MISSING", f"{ref} is carried forward to a named meeting")
            by_ref[ref].update({"carried_forward_to": str(carried["meeting_ref"])})
        data.update({"actions": actions, "actions_open": sum(1 for item in actions if item.get("completed_at") is None and item.get("carried_forward_to") is None)})
    elif event == "close":
        require(int(data.get("actions_open", 0)) == 0, "ACTIONS_OPEN", f"{data.get('actions_open')} action(s) are neither done nor carried forward")
        data.update({"closed_at": at, "outcome": "closed"})
    elif event == "cancel":
        data.update({"cancel_reason": str(command.reason)[:300], "outcome": "cancelled"})
    return next_status, data


BOARD_CADENCE_LIFECYCLE = LifecycleSpec(entity="board_meeting", schema_prefix=BOARD_CADENCE_KIND, statuses=BOARD_STATUSES, terminal=TERMINAL_BOARD_STATUSES, events=BOARD_EVENTS, table=_BOARD_TABLE, opening_event="call_meeting", reason_events=("cancel",), apply=_apply_board, ledger_model=BoardLedger, receipt_model=BoardReceipt, effect_boundary_model=BoardEffectBoundary, plan_model=BoardCadencePlan, max_transitions=MAX_BOARD_TRANSITIONS)
BoardMeetingState = BOARD_CADENCE_LIFECYCLE.State


def open_board_meeting(plan: BoardCadencePlan | Mapping[str, Any], scope: Mapping[str, Any], *, receipt: Mapping[str, Any], opened_at: str, actor_ref: str) -> Any:
    return BOARD_CADENCE_LIFECYCLE.open(plan, scope, opened_at=opened_at, actor_ref=actor_ref, receipt=receipt)


def advance_board_meeting(plan: BoardCadencePlan | Mapping[str, Any], state: Any, command: Any) -> Any:
    return BOARD_CADENCE_LIFECYCLE.advance(plan, state, command)


# --------------------------------------------------------------------------- #
# Receipts
# --------------------------------------------------------------------------- #


def call_receipt(*, meeting_ref: str, scheduled_at: str, called_by: str, agenda: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    return {"meeting_ref": meeting_ref, "scheduled_at": timestamp(scheduled_at, field_name="scheduled_at"), "called_by": called_by, "agenda": [dict(detached(item)) for item in agenda], "evidence_refs": [f"meeting:{meeting_ref}"]}


def pack_receipt(board_pack: Any, *, issued_at: str, forecast: Mapping[str, Any] | Any | None = None) -> dict[str, Any]:
    """The sealed board pack (``company_brief.board_pack``) and, when the board saw it, the sealed cash forecast."""

    from lightbulb.company_brief import BoardPack

    pack = board_pack if isinstance(board_pack, BoardPack) else BoardPack.model_validate(dict(detached(board_pack)))
    receipt: dict[str, Any] = {"board_pack": pack.to_dict(), "issued_at": timestamp(issued_at, field_name="issued_at"), "evidence_refs": [f"board_pack:{pack.month}:{pack.pack_digest[:16]}"]}
    if forecast is not None:
        digest = str(dict(detached(forecast)).get("forecast_digest") or "")
        _require(len(digest) == 64, "FORECAST_NOT_SEALED", "a forecast carries its forecast_digest")
        receipt["forecast_digest"] = digest
        receipt["evidence_refs"].append(f"forecast:{digest[:16]}")
    return receipt


def attendance_receipt(*, held_at: str, present_refs: Sequence[str], resolutions: Sequence[Mapping[str, Any]] = ()) -> dict[str, Any]:
    return {"held_at": timestamp(held_at, field_name="held_at"), "present_refs": list(present_refs), "resolutions": [dict(detached(item)) for item in resolutions], "evidence_refs": [f"attendance:{stable_digest(sorted(present_refs))[:16]}"]}


def minutes_receipt(*, minutes_sha256: str, recorded_by: str, approved_by: str, recorded_at: str, actions: Sequence[Mapping[str, Any]] = ()) -> dict[str, Any]:
    return {"minutes_sha256": minutes_sha256, "recorded_by": recorded_by, "approved_by": approved_by, "recorded_at": timestamp(recorded_at, field_name="recorded_at"), "actions": [dict(detached(item)) for item in actions], "evidence_refs": [f"minutes:{minutes_sha256[:16]}"]}


def tracking_receipt(*, completed: Sequence[Mapping[str, Any]] = (), carried_forward: Sequence[Mapping[str, Any]] = ()) -> dict[str, Any]:
    return {"completed": [dict(detached(item)) for item in completed], "carried_forward": [dict(detached(item)) for item in carried_forward], "evidence_refs": [f"tracking:{stable_digest([list(completed), list(carried_forward)])[:16]}"]}


# --------------------------------------------------------------------------- #
# What the chain hands to the other engines
# --------------------------------------------------------------------------- #


def resolution_register(states: Sequence[Any]) -> list[dict[str, Any]]:
    """Every resolution across the meetings, carried or not, with its meeting and vote."""

    rows = []
    for state in states:
        for item in state.ledger.resolutions:
            rows.append({"meeting_ref": state.ledger.meeting_ref, "held_at": state.ledger.held_at, "resolution_ref": item.resolution_ref, "item_ref": item.item_ref, "text": item.text, "votes_for": item.votes_for, "votes_against": item.votes_against, "abstained": item.abstained, "carried": item.carried, "source_digest": state.state_digest})
    rows.sort(key=lambda row: (str(row["held_at"]), str(row["resolution_ref"])))
    return rows


def overdue_actions(state: Any, *, source_plan: Any, now: str) -> list[dict[str, Any]]:
    _plan, bound = BOARD_CADENCE_LIFECYCLE.bind(source_plan, state)
    stamp = parsed(timestamp(now, field_name="now"))
    rows = []
    for item in bound.ledger.actions:
        if item.completed_at is None and item.carried_forward_to is None and parsed(item.due_at) < stamp:
            rows.append({"action_ref": item.action_ref, "owner_ref": item.owner_ref, "title": item.title, "due_at": item.due_at, "days_overdue": (stamp - parsed(item.due_at)).days, "resolution_ref": item.resolution_ref})
    rows.sort(key=lambda row: (str(row["due_at"]), str(row["action_ref"])))
    return rows


def board_action_overdue_signal(state: Any, *, source_plan: Any, now: str) -> dict[str, Any] | None:
    """``signals.board_action_overdue`` when a minuted meeting still has actions past due."""

    _plan, bound = BOARD_CADENCE_LIFECYCLE.bind(source_plan, state)
    rows = overdue_actions(bound, source_plan=source_plan, now=now)
    if bound.status != "minuted" or not rows:
        return None
    return {"name": "signals.board_action_overdue", "producer": BOARD_CADENCE_KIND, "emitted_at": timestamp(now, field_name="now"), "payload": {"meeting_ref": bound.ledger.meeting_ref, "overdue_count": len(rows), "action_refs": [row["action_ref"] for row in rows], "owner_refs": sorted({str(row["owner_ref"]) for row in rows}), "oldest_due_at": rows[0]["due_at"], "source_digest": bound.state_digest}}


def governance_summary(states: Sequence[Any], *, now: str | None = None) -> dict[str, Any]:
    counts = {status: sum(1 for state in states if state.status == status) for status in BOARD_STATUSES}
    held = [state for state in states if state.ledger.held_at is not None]
    return {"meetings": len(states), "by_status": counts, "resolutions": sum(len(state.ledger.resolutions) for state in held), "carried": sum(state.ledger.carried for state in held), "actions_open": sum(state.ledger.actions_open for state in states if state.status == "minuted"), "last_held_at": max((str(state.ledger.held_at) for state in held), default=None), "quorum_failures": 0, "unminuted": [state.scope.entity_ref for state in states if state.status == "held"]}


BOARD_CADENCE_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": BOARD_CADENCE_KIND,
    "golden_loop": BOARD_CADENCE_GOLDEN_LOOP,
    "stages": ["call_meeting", "issue_pack", "hold_meeting", "record_minutes", "track_actions"],
    "statuses": list(BOARD_STATUSES),
    "events": list(BOARD_EVENTS),
    "hops": {"call_meeting": "the meeting, its time, who called it, the agenda; called far enough ahead for the pack", "issue_pack": "the sealed board pack (and forecast) issued the lead time before the meeting", "hold_meeting": "attendance meeting the quorum; resolutions on decision items with computed outcomes", "record_minutes": "the secretary's minutes approved by the chair inside the window, with the actions", "track_actions": "actions closed with evidence or carried forward to a named meeting"},
    "required_connectors": ["lightbulb.sdk_engine_state"],
    "hard_rules": [
        "the pack the board saw is the sealed board pack, named by digest",
        "no quorum, no meeting; a resolution is carried by the votes recorded, never by assertion",
        "minutes are the secretary's and the chair's, never one person's",
        "a meeting closes only when every action is done or carried forward",
    ],
}

__all__ = ["BOARD_CADENCE_GOLDEN_LOOP", "BOARD_CADENCE_KIND", "BOARD_CADENCE_LIFECYCLE", "BOARD_CADENCE_MANIFEST", "BOARD_EVENTS", "BOARD_STATUSES", "TERMINAL_BOARD_STATUSES", "ActionItem", "AgendaItem", "BoardCadenceError", "BoardCadencePlan", "BoardEffectBoundary", "BoardLedger", "BoardMeetingState", "BoardReceipt", "Director", "Resolution", "advance_board_meeting", "attendance_receipt", "board_action_overdue_signal", "call_receipt", "compile_board_cadence_chain", "governance_summary", "minutes_receipt", "open_board_meeting", "overdue_actions", "pack_receipt", "resolution_register", "tracking_receipt"]
