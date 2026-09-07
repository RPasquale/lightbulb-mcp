"""The front door's one page: where the launch actually is, who it is waiting on, and what the kill-or-scale decision would cost.

``launch_plan`` runs the critical path; this module reads it back to a person.
Nothing here is typed by a caller:

* :func:`launch_board` binds the persisted ``company_launch`` state to its plan
  and classifies every step of the critical path against the transition history,
  the approval inbox, and the ledger - done (with the transition that did it and
  the evidence it carried), waiting on a named human, waiting on a named
  platform read or write, awaiting a named ``sdk_launch_gate`` task, blocked on
  paper or a licence an earlier step has not produced, next, or later.  It adds
  the countdown to the fixed kill-or-scale date, the spend to date against the
  pinned ceiling summed from persisted ``company_operating_system`` periods, the
  attention list, and the single next action - which names the verb, the receipt
  builder, and the event, so the operator supplies rather than guesses.  It
  accepts ``state=None`` so the front door can render the board of a launch that
  has not started.
* :func:`brief_launch_decision` is the evidence the ``kill_or_scale_decided``
  gate asks for: the observed returns of the periods since the company went
  live, a **synthetic** forecast of scaling (and of extending, when an extension
  is on the table), the arithmetic of killing, a ranking, and the observed
  return at which scaling stops beating killing.  It is labelled synthetic, it
  executes nothing, and its ``brief_digest`` is what
  ``launch_plan.decision_attestation`` seals into the decision.

What it hands on: a sealed :class:`LaunchBoard` (with ``render_board``), a
sealed :class:`LaunchDecisionBrief` (with ``render``) that satisfies the launch
engine's ``BRIEF_MISSING`` guard, and - through
``company_evals.record_from_launch_brief`` - a scoreable record of what the
director decided against what the brief recommended.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_decisions import _observed_returns
from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    BoundedText,
    CurrencyCode,
    OpaqueRef,
    Sha256Digest,
    ShortText,
    StrictModel,
    add_days,
    decimal_value,
    detached,
    parsed,
    seal,
    sealed_digest,
    skip_digests,
    stable_digest,
    timestamp,
)
from lightbulb.company_operating_system import PERIOD_LIFECYCLE, CompanyOperatingPlan
from lightbulb.company_simulator import MAX_PERIODS, build_scenario, simulate_company, standard_scenario
from lightbulb.launch_plan import (
    LAUNCH_GATE_APPROVAL_TYPE,
    LAUNCH_GOLDEN_LOOP,
    LAUNCH_KIND,
    LAUNCH_LIFECYCLE,
    TERMINAL_LAUNCH_STATUSES,
    LaunchLedger,
    LaunchPlan,
    StepKind,
)

BOARD_SCHEMA = "lightbulb.company_launch_board.v1"
LAUNCH_DECISION_BRIEF_SCHEMA = "lightbulb.launch_decision_brief.v1"
BOARD_ENGINE = "launch_board"
NOT_STARTED = "not_started"
MIN_BOARD_ROWS, MAX_BOARD_ROWS = 10, 16
MAX_NEEDS_YOU = 20
SENSITIVITY_STEPS = 20
SUPPLY_VERB = "launch_supply"
GATE_VERB = "company_launch_gate_request"
# ``sign_paper`` and ``grant_licence`` are the only steps that produce the ref they block on; every
# other blocking requirement was produced by an earlier step, which is what makes a row blocked.
_SELF_PRODUCING_EVENTS: frozenset[str] = frozenset({"sign_paper", "grant_licence"})

RowStatus = Literal["done", "waiting_on_human", "waiting_on_platform", "awaiting_approval", "next", "later", "blocked"]
LaunchOption = Literal["scale", "kill", "extend"]
LaunchRecommendation = Literal["scale", "kill", "extend", "no_forecast"]
_NEXT_ACTION_ORDER: tuple[str, ...] = ("awaiting_approval", "waiting_on_human", "waiting_on_platform", "blocked", "next")


class LaunchBoardError(ValueError):
    """The board or the brief was asked to read something that does not belong to this launch; carries a code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise LaunchBoardError(code, message)


def _parse(model: Any, document: Any, code: str, what: str) -> Any:
    """Parse a document that claims to be a named sealed artifact, refusing anything of another schema."""

    try:
        return model.model_validate(_document(document))
    except (ValueError, TypeError) as exc:
        raise LaunchBoardError(code, f"{what}: {exc}") from exc


def _document(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        to_dict = getattr(value, "to_dict", None)
        if callable(to_dict):
            value = to_dict()
    try:
        return dict(detached(value))
    except (TypeError, ValueError) as exc:
        raise LaunchBoardError("DOCUMENT_INVALID", f"a supplied document is neither a mapping nor a sealed model: {exc}") from exc


def _money(value: Any, *, field_name: str, allow_negative: bool = False) -> Decimal:
    return decimal_value(value, field_name=field_name, allow_negative=allow_negative)


def _days(from_at: str, to_at: str) -> int:
    return (parsed(to_at) - parsed(from_at)).days


# --------------------------------------------------------------------------- #
# The board
# --------------------------------------------------------------------------- #


class BoardRow(StrictModel):
    """One step of the critical path as the operator sees it: what it is waiting on and what supplies it."""

    step_ref: OpaqueRef
    event: ShortText
    title: ShortText
    kind: StepKind
    gate_kind: ShortText | None = None
    human_role: ShortText | None = None
    status: RowStatus
    waiting_on: BoundedText | None = None
    evidence_ref: OpaqueRef | None = None
    done_at: str | None = None
    target_day: int = Field(ge=0, le=365)
    due_at: str
    days_late: int | None = Field(default=None, ge=1)
    next_action: BoundedText

    @field_validator("due_at")
    @classmethod
    def _due(cls, value: str) -> str:
        return timestamp(value, field_name="due_at")

    @field_validator("done_at")
    @classmethod
    def _done(cls, value: str | None) -> str | None:
        return None if value is None else timestamp(value, field_name="done_at")


class LaunchCountdown(StrictModel):
    """Where the launch stands against the two dates the plan fixed: the first-dollar target and the kill-or-scale date."""

    planned_at: str
    now: str
    days_since_planned: int
    time_to_first_dollar_target_days: int = Field(ge=1, le=365)
    first_dollar_day_forecast: int | None = Field(default=None, ge=0, le=730)
    kill_or_scale_at: str
    days_to_kill_or_scale: int
    first_dollar_at: str | None = None
    days_to_first_dollar: int | None = None
    ahead_or_behind_days: int | None = None

    @field_validator("planned_at", "now", "kill_or_scale_at")
    @classmethod
    def _stamps(cls, value: str, info: ValidationInfo) -> str:
        return timestamp(value, field_name=str(info.field_name))


class LaunchSpend(StrictModel):
    """Spend since the company went live, summed off the persisted operating periods, against the ceiling the plan pinned."""

    spend_to_date: Decimal
    ceiling: Decimal
    remaining: Decimal
    breached: bool = False
    periods_counted: int = Field(ge=0)
    source: Literal["persisted_periods", "none"] = "none"

    @field_validator("spend_to_date", "ceiling", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _money(value, field_name=str(info.field_name))

    @field_validator("remaining", mode="before")
    @classmethod
    def _signed(cls, value: Any) -> Decimal:
        return _money(value, field_name="remaining", allow_negative=True)


class LaunchBoard(StrictModel):
    """Every launch step, done or waiting, with the countdown, the spend, and the one next action; sealed."""

    schema_id: str = Field(default=BOARD_SCHEMA, alias="schema")
    company_name: ShortText
    company_ref: OpaqueRef | None = None
    currency: CurrencyCode
    launch_ref: OpaqueRef
    rendered_at: str
    status: ShortText
    rows: tuple[BoardRow, ...] = Field(min_length=MIN_BOARD_ROWS, max_length=MAX_BOARD_ROWS)
    countdown: LaunchCountdown
    spend: LaunchSpend
    needs_you: tuple[BoundedText, ...] = Field(default=(), max_length=MAX_NEEDS_YOU)
    next_action: BoundedText
    approvals_waiting: tuple[OpaqueRef, ...] = Field(default=(), max_length=MAX_BOARD_ROWS)
    blockers: tuple[ShortText, ...] = Field(default=(), max_length=MAX_NEEDS_YOU)
    source_digests: dict[str, str] = Field(default_factory=dict)
    board_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("rendered_at")
    @classmethod
    def _when(cls, value: str) -> str:
        return timestamp(value, field_name="rendered_at")

    @field_validator("rows", "needs_you", "approvals_waiting", "blockers", mode="before")
    @classmethod
    def _sequences(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> LaunchBoard:
        if not skip_digests(info) and self.board_digest != sealed_digest(LaunchBoard, self, "board_digest"):
            raise ValueError("board_digest must commit the exact board")
        return self

    def row(self, step_ref: str) -> BoardRow | None:
        return next((item for item in self.rows if item.step_ref == step_ref), None)

    @property
    def started(self) -> bool:
        return self.status != NOT_STARTED


def render_board(board: LaunchBoard) -> str:
    """The board as markdown: the headline, what needs a person, the one next action, the table, the dates, the money."""

    window = board.countdown.days_since_planned + board.countdown.days_to_kill_or_scale
    lines = [
        f"# {board.company_name} — launch board",
        "",
        f"{board.company_name}: {board.status}, day {board.countdown.days_since_planned} of {window}; first dollar due day {board.countdown.time_to_first_dollar_target_days}; spend {board.spend.spend_to_date} of {board.spend.ceiling} {board.currency}",
        "",
    ]
    if board.needs_you:
        lines.append("## Needs you")
        lines.extend(f"- {item}" for item in board.needs_you)
        lines.append("")
    lines.extend(["## Next", f"- {board.next_action}", "", "## Board", "| step | kind | status | owner | waiting on | due | done |", "| --- | --- | --- | --- | --- | --- | --- |"])
    for row in board.rows:
        owner = row.human_role or ("platform" if row.kind in ("platform_read", "platform_write") else "sdk")
        late = f" (+{row.days_late}d)" if row.days_late else ""
        lines.append(f"| {row.step_ref} | {row.kind} | {row.status}{late} | {owner} | {row.waiting_on or '—'} | day {row.target_day} | {row.done_at[:10] if row.done_at else '—'} |")
    countdown = board.countdown
    lines.extend([
        "",
        "## Countdown",
        f"- planned {countdown.planned_at[:10]}; day {countdown.days_since_planned} as of {countdown.now[:10]}",
        f"- kill-or-scale {countdown.kill_or_scale_at[:10]}: {countdown.days_to_kill_or_scale} day(s) away",
        "- first dollar: " + (f"recorded {countdown.first_dollar_at[:10]} on day {countdown.days_to_first_dollar}" if countdown.first_dollar_at else f"target day {countdown.time_to_first_dollar_target_days}, forecast day {countdown.first_dollar_day_forecast}"),
    ])
    if countdown.ahead_or_behind_days is not None:
        lines.append(f"- {abs(countdown.ahead_or_behind_days)} day(s) " + ("ahead of" if countdown.ahead_or_behind_days > 0 else "behind") + " the first-dollar target")
    lines.extend([
        "",
        "## Spend",
        f"- {board.spend.spend_to_date} of {board.spend.ceiling} {board.currency} across {board.spend.periods_counted} persisted period(s) ({board.spend.source})",
        f"- remaining {board.spend.remaining}" + ("; the ceiling is breached" if board.spend.breached else ""),
        "",
        "evidence: " + ", ".join(f"{key} {value[:16]}" for key, value in sorted(board.source_digests.items())),
    ])
    return "\n".join(lines).rstrip() + "\n"


def _bind(plan: LaunchPlan | Mapping[str, Any], state: Any) -> tuple[LaunchPlan, Any]:
    parsed_plan = plan if isinstance(plan, LaunchPlan) else _parse(LaunchPlan, plan, "LAUNCH_PLAN_INVALID", "the supplied document is not a sealed launch plan")
    if state is None:
        return parsed_plan, None
    try:
        return LAUNCH_LIFECYCLE.bind(parsed_plan, state)
    except LaunchBoardError:
        raise
    except (ValueError, TypeError) as exc:
        raise LaunchBoardError("LAUNCH_STATE_MISMATCH", f"the supplied state is not a company_launch state of this plan: {exc}") from exc


def _pending_index(launch_ref: str, pending_tasks: Sequence[Mapping[str, Any]], pending_requests: Mapping[str, Any] | None) -> dict[str, tuple[str, str | None]]:
    """Approval rows for this launch, by event: the platform inbox first, then whatever the runtime is still holding."""

    rows: dict[str, tuple[str, str | None]] = {}
    for task in pending_tasks:
        raw = _document(task)
        if str(raw.get("approvalType") or raw.get("approval_type") or "") != LAUNCH_GATE_APPROVAL_TYPE:
            continue
        context = dict(raw.get("contextData") or raw.get("context_data") or raw.get("context") or {})
        if str(context.get("entity_ref") or "") != launch_ref:
            continue
        event, task_id = str(context.get("event") or ""), str(raw.get("id") or raw.get("task_id") or raw.get("approvalRef") or raw.get("approval_ref") or "")
        if event and task_id:
            rows.setdefault(event, (task_id, None if context.get("gate_kind") is None else str(context["gate_kind"])))
    for key, request in dict(pending_requests or {}).items():
        raw = _document(request)
        if str(raw.get("entity_ref") or "") != launch_ref:
            continue
        event = str(raw.get("event") or "")
        if event:
            rows.setdefault(event, (str(key), None if raw.get("gate_kind") is None else str(raw["gate_kind"])))
    return rows


def _match(step: Any, pool: list[Any]) -> int | None:
    """The transition that did this step: the one naming its paper or licence, otherwise the next one of that event."""

    for index, transition in enumerate(pool):
        receipt = transition.command.receipt
        marker = receipt.paper_ref or receipt.licence_ref
        if step.blocking_requirements and marker is not None:
            if marker in step.blocking_requirements:
                return index
            continue
        return index
    return None


def _done_transitions(plan: LaunchPlan, state: Any) -> dict[int, Any]:
    history: dict[str, list[Any]] = {}
    if state is not None:
        for transition in state.transition_history:
            history.setdefault(transition.command.event, []).append(transition)
    done: dict[int, Any] = {}
    for index, step in enumerate(plan.steps):
        pool = history.get(step.event) or []
        picked = _match(step, pool)
        if picked is not None:
            done[index] = pool.pop(picked)
    return done


def _next_action(step: Any) -> str:
    verb = GATE_VERB if step.kind == "human_gate" else SUPPLY_VERB
    return f"{step.verb} -> supply {step.produces} via {verb} {step.event}"


def _rows(plan: LaunchPlan, state: Any, ledger: LaunchLedger, *, planned_at: str, days_since_planned: int, pending: Mapping[str, tuple[str, str | None]]) -> list[dict[str, Any]]:
    done = _done_transitions(plan, state)
    status = state.status if state is not None else "new"
    remaining = [index for index in range(len(plan.steps)) if index not in done]
    # A scaled, killed or abandoned launch is not waiting on anybody: no legal event remains, so nothing
    # is next, nothing is blocked, and the board must not tell an operator to go form a dead company.
    terminal = status in TERMINAL_LAUNCH_STATUSES
    next_index = None if terminal else next((index for index in remaining if (status, plan.steps[index].event) in LAUNCH_LIFECYCLE.table), remaining[0] if remaining else None)
    produced_by: dict[str, int] = {}
    for index, step in enumerate(plan.steps):
        if step.event in _SELF_PRODUCING_EVENTS and len(step.blocking_requirements) == 1:
            produced_by.setdefault(step.blocking_requirements[0], index)
    held = {*ledger.paper_done, *ledger.licences_granted}

    rows: list[dict[str, Any]] = []
    for index, step in enumerate(plan.steps):
        row: dict[str, Any] = {
            "step_ref": step.step_ref,
            "event": step.event,
            "title": step.title,
            "kind": step.kind,
            "gate_kind": step.gate_kind,
            "human_role": step.human_role,
            "target_day": step.target_day,
            "due_at": add_days(planned_at, step.target_day),
            "next_action": _next_action(step),
        }
        transition = done.get(index)
        if transition is not None:
            receipt = transition.command.receipt
            rows.append({**row, "status": "done", "done_at": transition.command.occurred_at, "evidence_ref": receipt.evidence_refs[0] if receipt.evidence_refs else receipt.gate_task_ref, "next_action": "done; nothing further"})
            continue
        # An ``sdk_launch_gate`` task parks the command the engine is actually holding, so it belongs to
        # the step that is legally next and to no other; and a task whose ``gate_kind`` contradicts the
        # gate this plan sealed for that step is not this step's approval, whatever it claims to be.
        approval = pending.get(step.event) if index == next_index and step.gate_kind is not None else None
        if approval is not None and approval[1] is not None and approval[1] != step.gate_kind:
            approval = None
        missing = [ref for ref in step.blocking_requirements if ref not in held and produced_by.get(ref) is not None and produced_by[ref] < index]
        if approval is not None:
            row.update({"status": "awaiting_approval", "waiting_on": f"approval task {approval[0]} ({approval[1] or step.gate_kind})"})
        elif index == next_index:
            if step.kind == "human_gate":
                row.update({"status": "waiting_on_human", "waiting_on": f"{step.human_role}: {step.verb}"})
            elif step.kind in ("platform_read", "platform_write"):
                row.update({"status": "waiting_on_platform", "waiting_on": step.verb})
            else:
                row["status"] = "next"
        elif state is not None and not terminal and missing:
            row.update({"status": "blocked", "waiting_on": ", ".join(missing)[:4000]})
        else:
            row["status"] = "later"
        late = days_since_planned - step.target_day
        rows.append({**row, "days_late": late if late > 0 else None})
    return rows


def _period_ledgers(periods: Sequence[Mapping[str, Any] | Any], *, operating_plan_digest: str, live_at: str | None) -> tuple[list[dict[str, Any]], list[str]]:
    counted: list[dict[str, Any]] = []
    digests: list[str] = []
    for record in periods:
        raw = _document(record)
        document = dict(raw.get("state") or raw)
        # The spend on this board is summed off persisted ``company_operating_system`` states, never off a
        # number a caller typed: a record that does not name the operating plan this launch pinned is
        # refused rather than added, exactly as ``brief_launch_decision`` refuses it.
        _require(
            str(document.get("plan_digest") or raw.get("plan_digest") or "") == operating_plan_digest,
            "PERIOD_PLAN_MISMATCH",
            "a supplied period does not name the operating plan this launch pinned; only that plan's persisted periods are this launch's spend",
        )
        digests.append(str(document.get("state_digest") or stable_digest(document)))
        period = dict(document.get("ledger") or {})
        start = period.get("period_start")
        if live_at is not None and (start is None or parsed(timestamp(str(start), field_name="period_start")) < parsed(live_at)):
            continue
        counted.append(period)
    return counted, digests


def _spend(plan: LaunchPlan, ledger: LaunchLedger, periods: Sequence[Mapping[str, Any] | Any]) -> tuple[dict[str, Any], list[str]]:
    counted, digests = _period_ledgers(periods, operating_plan_digest=plan.operating_plan_digest, live_at=ledger.live_at)
    total = sum((_money(row.get("total_spend", "0"), field_name="total_spend") for row in counted), Decimal("0"))
    first_dollar = ledger.first_dollar_at is not None
    ceiling = plan.targets.max_spend_before_first_dollar
    if first_dollar:
        # Past the first dollar the cap is no longer "spend before you earn"; it is the operating budget
        # the persisted periods themselves carry, so the board still compares against a sealed number.
        budgets = [_money(row["budget_total"], field_name="budget_total") for row in counted if row.get("budget_total")]
        ceiling = budgets[-1] if budgets else ceiling
    breached = bool(ledger.spend_ceiling_breached) or (not first_dollar and total > ceiling)
    return {"spend_to_date": str(total), "ceiling": str(ceiling), "remaining": str(ceiling - total), "breached": breached, "periods_counted": len(counted), "source": "persisted_periods" if periods else "none"}, digests


def _countdown(plan: LaunchPlan, ledger: LaunchLedger, *, planned_at: str, now_at: str) -> dict[str, Any]:
    kill_at = ledger.kill_or_scale_at or add_days(planned_at, plan.targets.kill_or_scale_days)
    days_since = _days(planned_at, now_at)
    target = plan.targets.time_to_first_dollar_days
    if ledger.first_dollar_at is not None:
        drift = target - _days(planned_at, ledger.first_dollar_at)
    elif days_since > target:
        drift = target - days_since
    else:
        drift = None
    return {
        "planned_at": planned_at,
        "now": now_at,
        "days_since_planned": days_since,
        "time_to_first_dollar_target_days": target,
        "first_dollar_day_forecast": plan.first_dollar_day_forecast,
        "kill_or_scale_at": kill_at,
        "days_to_kill_or_scale": _days(now_at, kill_at),
        "first_dollar_at": ledger.first_dollar_at,
        "days_to_first_dollar": ledger.days_to_first_dollar,
        "ahead_or_behind_days": drift,
    }


def launch_board(
    plan: LaunchPlan | Mapping[str, Any],
    state: Any = None,
    *,
    now: str,
    launch_ref: str | None = None,
    periods: Sequence[Mapping[str, Any] | Any] = (),
    pending_tasks: Sequence[Mapping[str, Any]] = (),
    pending_requests: Mapping[str, Any] | None = None,
    blueprint_blockers: Sequence[str] = (),
) -> LaunchBoard:
    """The whole critical path, classified from the persisted state, the inbox and the periods; nothing is typed."""

    parsed_plan, bound = _bind(plan, state)
    now_at = timestamp(now, field_name="now")
    ledger = bound.ledger if bound is not None else LaunchLedger()
    if bound is not None:
        entity_ref = str(bound.scope.entity_ref)
        _require(launch_ref is None or launch_ref == entity_ref, "LAUNCH_REF_MISMATCH", f"the persisted state is {entity_ref}, not {launch_ref}")
    else:
        # A launch that has not opened has no scope to read the ref off; the plan's own digest names it
        # until ``start_launch`` does, and an operator may pass the ref the inbox is filed under.
        entity_ref = launch_ref or f"launch:{parsed_plan.plan_digest[:24]}"
    planned_at = ledger.planned_at or parsed_plan.planned_at
    countdown = _countdown(parsed_plan, ledger, planned_at=planned_at, now_at=now_at)
    pending = _pending_index(entity_ref, pending_tasks, pending_requests)
    rows = _rows(parsed_plan, bound, ledger, planned_at=planned_at, days_since_planned=countdown["days_since_planned"], pending=pending)
    spend, period_digests = _spend(parsed_plan, ledger, periods)
    status = bound.status if bound is not None else NOT_STARTED

    needs: list[str] = [f"{row['title']}: {row['waiting_on']}"[:4000] for row in rows if row["status"] in ("waiting_on_human", "awaiting_approval")]
    if spend["breached"]:
        needs.append(f"spend ceiling breached: {spend['spend_to_date']} of {spend['ceiling']} {parsed_plan.currency}")
    if countdown["days_to_kill_or_scale"] <= 0 and status not in TERMINAL_LAUNCH_STATUSES and status != NOT_STARTED:
        needs.append("kill-or-scale date passed; decide")
    if countdown["ahead_or_behind_days"] is not None and countdown["ahead_or_behind_days"] < 0:
        needs.append(f"first dollar is {abs(countdown['ahead_or_behind_days'])} day(s) late")
    needs.extend(str(item)[:4000] for item in blueprint_blockers)

    chosen = next((row for wanted in _NEXT_ACTION_ORDER for row in rows if row["status"] == wanted), None)
    # ``blockers`` is ShortText; a blueprint blocker or a long requirement list is trimmed, never a crash.
    blockers = [*(str(item)[:300] for item in blueprint_blockers), *(f"{row['step_ref']} waits on {row['waiting_on']}"[:300] for row in rows if row["status"] == "blocked")]
    digests = {
        "plan": parsed_plan.plan_digest,
        "state": bound.state_digest if bound is not None else "none",
        "periods": stable_digest(period_digests),
        "inbox": stable_digest(sorted(f"{event}:{task[0]}" for event, task in pending.items())),
    }
    return seal(LaunchBoard, {
        "company_name": parsed_plan.company_name,
        "company_ref": ledger.formed_company_ref,
        "currency": parsed_plan.currency,
        "launch_ref": entity_ref,
        "rendered_at": now_at,
        "status": status,
        "rows": rows,
        "countdown": countdown,
        "spend": spend,
        "needs_you": needs[:MAX_NEEDS_YOU],
        "next_action": chosen["next_action"] if chosen is not None else f"nothing is waiting; the launch is {status}",
        "approvals_waiting": [pending[row["event"]][0] for row in rows if row["status"] == "awaiting_approval"],
        "blockers": blockers[:MAX_NEEDS_YOU],
        "source_digests": digests,
    }, "board_digest")


# --------------------------------------------------------------------------- #
# The kill-or-scale decision brief
# --------------------------------------------------------------------------- #


class LaunchOptionForecast(StrictModel):
    """One option at the kill-or-scale date: simulated over the observed returns, or the arithmetic of stopping."""

    option: LaunchOption
    label: BoundedText
    plan_digest: Sha256Digest
    periods: int = Field(ge=1, le=MAX_PERIODS)
    total_revenue: Decimal
    total_gross_profit: Decimal
    final_cash: Decimal
    min_cash: Decimal
    halted_at_period: int | None = Field(default=None, ge=1, le=MAX_PERIODS)
    halt_reason: ShortText | None = None
    result_digest: Sha256Digest | None = None
    arithmetic: bool = False

    @field_validator("total_revenue", "total_gross_profit", "final_cash", "min_cash", mode="before")
    @classmethod
    def _signed(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _money(value, field_name=str(info.field_name), allow_negative=True)

    @model_validator(mode="after")
    def _guard(self) -> LaunchOptionForecast:
        if self.arithmetic != (self.result_digest is None):
            raise ValueError("a simulated option names its result digest and an arithmetic one does not")
        return self


class LaunchDecisionBrief(StrictModel):
    """What scaling, killing, or extending would do, from the periods since the company went live; synthetic and sealed."""

    schema_id: str = Field(default=LAUNCH_DECISION_BRIEF_SCHEMA, alias="schema")
    launch_ref: OpaqueRef
    decided_from_state_digest: Sha256Digest
    operating_plan_digest: Sha256Digest
    launch_plan_digest: Sha256Digest
    horizon_periods: int = Field(ge=1, le=MAX_PERIODS)
    observed_returns: dict[str, Decimal] = Field(default_factory=dict)
    forecasts: tuple[LaunchOptionForecast, ...] = Field(min_length=1, max_length=3)
    first_dollar_recorded: bool = False
    days_to_first_dollar: int | None = None
    spend_before_first_dollar: Decimal
    recommendation: LaunchRecommendation
    rationale: tuple[BoundedText, ...] = Field(min_length=1, max_length=8)
    sensitivity: tuple[dict[str, str], ...] = Field(default=(), max_length=8)
    memory_state_digest: Sha256Digest | None = None
    synthetic: Literal[True] = True
    executes_nothing: Literal[True] = True
    brief_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("observed_returns", mode="before")
    @classmethod
    def _returns(cls, value: Any) -> dict[str, Decimal]:
        return {str(key): _money(item, field_name=f"observed_returns.{key}", allow_negative=True) for key, item in dict(value or {}).items()}

    @field_validator("spend_before_first_dollar", mode="before")
    @classmethod
    def _spent(cls, value: Any) -> Decimal:
        return _money(value, field_name="spend_before_first_dollar")

    @field_validator("forecasts", "rationale", "sensitivity", mode="before")
    @classmethod
    def _sequences(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> LaunchDecisionBrief:
        if not skip_digests(info) and self.brief_digest != sealed_digest(LaunchDecisionBrief, self, "brief_digest"):
            raise ValueError("brief_digest must commit the exact brief")
        return self

    def forecast(self, option: str) -> LaunchOptionForecast | None:
        return next((item for item in self.forecasts if item.option == option), None)

    def render(self) -> str:
        lines = [f"**kill or scale** on `{self.launch_ref}`: recommend **{self.recommendation}** (synthetic; executes nothing)"]
        for item in self.forecasts:
            halt = f", halts period {item.halted_at_period} ({item.halt_reason})" if item.halted_at_period else ""
            lines.append(f"- {item.option}: {item.label}; revenue {item.total_revenue}, gross profit {item.total_gross_profit}, final cash {item.final_cash}{halt}" + (" [arithmetic]" if item.arithmetic else ""))
        lines.extend(f"- {reason}" for reason in self.rationale)
        lines.extend(f"- sensitivity: {item['note']}" for item in self.sensitivity)
        return "\n".join(lines)


def _bind_periods(operating_plan: CompanyOperatingPlan, periods: Sequence[Mapping[str, Any] | Any], *, live_at: str | None) -> list[Any]:
    """Persisted operating periods since the company went live, bound to the plan that produced them."""

    out: list[Any] = []
    for record in periods:
        raw = _document(record)
        document = dict(raw.get("state") or raw)
        _require(str(document.get("plan_digest") or "") == operating_plan.plan_digest, "PERIOD_PLAN_MISMATCH", "a supplied period belongs to a different operating plan than the one this launch pinned")
        start = dict(document.get("ledger") or {}).get("period_start")
        if live_at is not None and (start is None or parsed(timestamp(str(start), field_name="period_start")) < parsed(live_at)):
            continue
        out.append(PERIOD_LIFECYCLE.State.model_validate(document, context={PERIOD_LIFECYCLE.plan_context_key: operating_plan}))
    return out


def _assumptions(returns: Mapping[str, Decimal], memory_assumptions: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """The observed return band (+/-10%), widened or narrowed by whatever the operating memory learned."""

    rows: dict[str, dict[str, Any]] = {}
    for engine, value in returns.items():
        rows[engine] = {"engine": engine, "return_on_spend_min": str(max(Decimal("0"), value * Decimal("0.9"))), "return_on_spend_max": str(max(Decimal("0"), value * Decimal("1.1"))), "utilisation_min_percent": "85", "utilisation_max_percent": "100"}
    for item in memory_assumptions:
        engine = str(item["engine"])
        rows[engine] = {**rows.get(engine, {"engine": engine}), **{key: value for key, value in item.items() if key != "engine"}}
    return list(rows.values())


def _scale_scenario(returns: Mapping[str, Decimal], memory_assumptions: Sequence[Mapping[str, Any]], *, periods: int, start_at: str, starting_cash: Any) -> Any:
    base = standard_scenario("steady_state").to_dict()
    base.pop("scenario_digest", None)
    # The standard scenario carries a generic fixed cost this company never declared, and the operating
    # plan's own budget is already the spend the simulator models; the wind-down cost of stopping is
    # priced once, in the kill option, from the same sealed budget.
    return build_scenario({**base, "name": "launch_decision_forecast", "periods": periods, "start_at": start_at, "starting_cash": str(starting_cash), "fixed_costs_per_period": "0", "assumptions": _assumptions(returns, memory_assumptions), "replan_each_period": False, "approvals_granted": True})


def _simulated(option: str, label: str, operating_plan: CompanyOperatingPlan, scenario: Any) -> tuple[Any, dict[str, Any]]:
    result = simulate_company(operating_plan, scenario)
    return result, {"option": option, "label": label, "plan_digest": operating_plan.plan_digest, "periods": result.periods_run, "total_revenue": str(result.total_revenue), "total_gross_profit": str(result.total_gross_profit), "final_cash": str(result.final_cash), "min_cash": str(result.min_cash), "halted_at_period": result.halted_at_period, "halt_reason": result.halt_reason, "result_digest": result.result_digest, "arithmetic": False}


def _kill_forecast(operating_plan: CompanyOperatingPlan, *, cash_on_hand: Decimal) -> dict[str, Any]:
    """Killing is arithmetic, not a simulation: one last period of the sealed operating budget, no revenue, then nothing."""

    fixed = operating_plan.blueprint.operating_budget_per_period
    remaining = cash_on_hand - fixed
    return {"option": "kill", "label": "stop spending; hand to wind-down", "plan_digest": operating_plan.plan_digest, "periods": 1, "total_revenue": "0", "total_gross_profit": str(-fixed), "final_cash": str(remaining), "min_cash": str(remaining), "halted_at_period": None, "halt_reason": None, "result_digest": None, "arithmetic": True}


def _rank(rows: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    return sorted(rows, key=lambda item: (item.get("halted_at_period") is not None, -Decimal(str(item["total_gross_profit"])), -Decimal(str(item["final_cash"]))))


def _sensitivity(returns: Mapping[str, Decimal], memory_assumptions: Sequence[Mapping[str, Any]], operating_plan: CompanyOperatingPlan, kill_profit: Decimal, *, periods: int, start_at: str, starting_cash: Any) -> list[dict[str, str]]:
    """The observed return at which scaling stops beating killing, searched downwards in tenths."""

    out: list[dict[str, str]] = []
    for engine, observed in sorted(returns.items()):
        flip: Decimal | None = None
        for step in range(1, SENSITIVITY_STEPS + 1):
            factor = Decimal(1) - Decimal(step) * Decimal("0.1")
            if factor <= 0:
                break
            probe = {**returns, engine: (observed * factor).quantize(Decimal("0.01"))}
            result = simulate_company(operating_plan, _scale_scenario(probe, memory_assumptions, periods=periods, start_at=start_at, starting_cash=starting_cash))
            if result.halted_at_period is not None or result.total_gross_profit <= kill_profit:
                flip = probe[engine]
                break
        row = {"engine": engine, "observed_return_on_spend": str(observed), "direction": "lower" if flip is not None else "none"}
        if flip is not None:
            row["flip_at_return_on_spend"] = str(flip)
        row["note"] = f"{engine} observed return {observed}; " + (f"scaling stops beating killing at {flip}" if flip is not None else "scaling still beats killing across the whole searched band")
        out.append(row)
    return out[:8]


def brief_launch_decision(
    plan: LaunchPlan | Mapping[str, Any],
    state: Any,
    *,
    operating_plan: CompanyOperatingPlan | Mapping[str, Any],
    periods: Sequence[Mapping[str, Any] | Any] = (),
    now: str,
    cash_on_hand: Any,
    extend_days: int | None = None,
    memory_state: Any = None,
) -> LaunchDecisionBrief:
    """The evidence the kill-or-scale gate asks for: scale, kill, and (when offered) extend, ranked; synthetic throughout."""

    parsed_plan, bound = _bind(plan, state)
    _require(bound is not None, "LAUNCH_NOT_STARTED", "a kill-or-scale brief is taken against a persisted launch state; there is nothing to decide yet")
    parsed_operating = operating_plan if isinstance(operating_plan, CompanyOperatingPlan) else _parse(CompanyOperatingPlan, operating_plan, "OPERATING_PLAN_INVALID", "the supplied document is not a sealed company operating plan")
    _require(parsed_operating.plan_digest == parsed_plan.operating_plan_digest, "OPERATING_PLAN_MISMATCH", "the supplied operating plan is not the one this launch plan compiled and pinned")
    _require(extend_days is None or 1 <= int(extend_days) <= 365, "EXTEND_DAYS_INVALID", "an extension runs between 1 and 365 days")
    stamp = timestamp(now, field_name="now")
    ledger = bound.ledger
    cash = _money(cash_on_hand, field_name="cash_on_hand")
    bound_periods = _bind_periods(parsed_operating, periods, live_at=ledger.live_at)
    returns = _observed_returns(parsed_operating, bound_periods)
    observed_revenue = sum((item.ledger.total_revenue for item in bound_periods), Decimal("0"))
    period_days = parsed_operating.blueprint.period_days
    horizon = max(1, min(MAX_PERIODS, math.ceil(parsed_plan.targets.time_to_first_dollar_days / period_days)))
    kill_at = ledger.kill_or_scale_at or add_days(ledger.planned_at or parsed_plan.planned_at, parsed_plan.targets.kill_or_scale_days)
    days_to_decision = _days(stamp, kill_at)

    memory_assumptions: list[Mapping[str, Any]] = []
    memory_digest = None
    if memory_state is not None:
        from lightbulb.company_operating_memory import priors_to_assumptions

        memory_assumptions = priors_to_assumptions(memory_state, engines=list(parsed_operating.blueprint.engine_kinds))
        memory_digest = memory_state.state_digest

    base = {
        "launch_ref": str(bound.scope.entity_ref),
        "decided_from_state_digest": bound.state_digest,
        "operating_plan_digest": parsed_operating.plan_digest,
        "launch_plan_digest": parsed_plan.plan_digest,
        "horizon_periods": horizon,
        "observed_returns": {key: str(value) for key, value in returns.items()},
        "first_dollar_recorded": ledger.first_dollar_at is not None,
        "days_to_first_dollar": ledger.days_to_first_dollar,
        "spend_before_first_dollar": str(ledger.spend_before_first_dollar),
        "memory_state_digest": memory_digest,
    }
    kill = _kill_forecast(parsed_operating, cash_on_hand=cash)

    if ledger.first_dollar_at is None and observed_revenue == 0 and days_to_decision <= 0:
        return seal(LaunchDecisionBrief, {**base, "forecasts": [kill], "recommendation": "kill", "rationale": ["no revenue recorded by the kill-or-scale date", f"the kill-or-scale date was {kill_at}; {abs(days_to_decision)} day(s) have passed with nothing settled", "killing costs one more period of the operating budget and stops; the decision is a person's, bound in Spring"], "sensitivity": []}, "brief_digest")
    if not returns and not memory_assumptions:
        return seal(LaunchDecisionBrief, {**base, "forecasts": [kill], "recommendation": "no_forecast", "rationale": ["no period since going live has recorded spend and revenue, and no memory priors exist; there is nothing to forecast scaling from", "only the arithmetic of killing is shown; decide on the plan's own limits"], "sensitivity": []}, "brief_digest")

    scenario = _scale_scenario(returns, memory_assumptions, periods=horizon, start_at=stamp, starting_cash=cash)
    _, scale = _simulated("scale", "keep operating at the current plan", parsed_operating, scenario)
    forecasts: list[dict[str, Any]] = [scale, kill]
    if extend_days is not None:
        extended = max(1, min(MAX_PERIODS, horizon + math.ceil(int(extend_days) / period_days)))
        _, extend = _simulated("extend", f"push the decision out {int(extend_days)} day(s) and keep operating", parsed_operating, _scale_scenario(returns, memory_assumptions, periods=extended, start_at=stamp, starting_cash=cash))
        forecasts.append(extend)

    ranked = _rank(forecasts)
    recommendation = str(ranked[0]["option"])
    rationale = [
        f"{recommendation} yields gross profit {ranked[0]['total_gross_profit']} over {ranked[0]['periods']} period(s) versus {ranked[1]['total_gross_profit']} for {ranked[1]['option']}",
        f"{'a first dollar settled on day ' + str(ledger.days_to_first_dollar) if ledger.first_dollar_at is not None else 'no first dollar has settled'}; {abs(days_to_decision)} day(s) " + ("remain before" if days_to_decision > 0 else "past") + " the kill-or-scale date",
        "the forecast uses the returns observed in the periods since the company went live (+/-10%) and any memory priors; it is synthetic and executes nothing",
    ]
    if any(item.get("halted_at_period") is not None for item in forecasts):
        rationale.append("halt risk: " + ", ".join(f"{item['option']} halts at period {item['halted_at_period']}" for item in forecasts if item.get("halted_at_period") is not None))
    sensitivity = _sensitivity(returns, memory_assumptions, parsed_operating, _money(kill["total_gross_profit"], field_name="total_gross_profit", allow_negative=True), periods=horizon, start_at=stamp, starting_cash=cash)
    return seal(LaunchDecisionBrief, {**base, "forecasts": forecasts, "recommendation": recommendation, "rationale": rationale[:8], "sensitivity": sensitivity}, "brief_digest")


LAUNCH_BOARD_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": BOARD_ENGINE,
    "golden_loop": LAUNCH_GOLDEN_LOOP,
    "stages": ["bind_state", "classify_rows", "count_down", "sum_spend", "derive_attention", "seal", "render"],
    "row_statuses": ["done", "waiting_on_human", "waiting_on_platform", "awaiting_approval", "next", "later", "blocked"],
    "documents": {
        BOARD_SCHEMA: "every launch step, the countdown, the spend, the attention list and the one next action",
        LAUNCH_DECISION_BRIEF_SCHEMA: "the synthetic scale / kill / extend brief the kill_or_scale_decided gate decides against",
    },
    "consumes": [f"{LAUNCH_KIND} state (lightbulb.sdk_engine_state)", "company_operating_system period records", "list_pending_approvals rows of type sdk_launch_gate", "EngineRuntime.pending launch gate requests"],
    "required_connectors": ["lightbulb.sdk_engine_state", "lightbulb.approvals"],
    "hard_rules": [
        "every row is derived from the persisted launch state, the plan and the inbox; nothing is typed",
        "the next action names the verb, the receipt builder and the event; the operator supplies, the SDK never fabricates",
        "the kill-or-scale brief is synthetic and says so; the decision is a person's, bound in Spring",
    ],
}

__all__ = [
    "BOARD_SCHEMA",
    "GATE_VERB",
    "LAUNCH_BOARD_MANIFEST",
    "LAUNCH_DECISION_BRIEF_SCHEMA",
    "MAX_BOARD_ROWS",
    "MIN_BOARD_ROWS",
    "NOT_STARTED",
    "SUPPLY_VERB",
    "BoardRow",
    "LaunchBoard",
    "LaunchBoardError",
    "LaunchCountdown",
    "LaunchDecisionBrief",
    "LaunchOptionForecast",
    "LaunchSpend",
    "RowStatus",
    "brief_launch_decision",
    "launch_board",
    "render_board",
]
