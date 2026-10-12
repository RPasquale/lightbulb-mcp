"""The act half of the owner loop: every effect the SDK plans becomes one durable action that is sent once, through the platform, and recorded with its receipt.

The chase plan drafts reminders, the owner digest has a delivery brief, and
an accepted "hire" becomes the hiring chain's opening receipt; until now
each stopped at a draft.  An ``OwnerAction`` turns one of them into a record
with a stable reference (a reminder rung for a customer, a digest, a
hand-off), so the same effect can never be planned or sent twice, and with
the platform's answer at every attempt:

* a message (a reminder, the digest) goes through Governed Connector
  Execution: the first dispatch asks the platform, which opens the owner's
  approval and answers ``pending_approval`` with its reference; the next
  dispatch carries that reference, the platform checks and spends the
  approval, sends once under the action's idempotency key, and returns the
  receipt with its provenance;
* a hire opens the hiring chain from the drafted receipt; the owner's
  accepted decision is the authority, and the chain's own guards still
  apply;
* a contract hand-off cannot open until an agreement names a contractor,
  so it is recorded blocked with that next step;
* the owner's digest can also go to the owner inside the platform, as an
  in-app notification to the person the agent works for: nothing leaves
  the platform and no recipient can be named.

The mandate is asked again at every dispatch, so an action the owner has
since ruled ``never`` stops; an action sent under ``act`` is also written
to the month's mandate log.  Recipients stay opaque references the platform
resolves; no address passes through here.  Nothing in this module performs
I/O: the surface calls the executor and hands its result back.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, OpaqueRef, Sha256Digest, ShortText, StrictModel, decimal_value, detached, seal, sealed_digest, skip_digests, stable_digest, timestamp

OWNER_ACTION_SCHEMA = "lightbulb.owner_action.v1"
OWNER_ACTIONS_MANIFEST: dict[str, Any] = {"engine": "owner_action", "kind": "effect_record", "reads": ("collections_loop", "owner_digest", "sourcing_hand_offs", "owner_mandate"), "writes": ("owner_action", "mandate_log")}
ActionStatus = Literal["planned", "awaiting_approval", "done", "blocked", "failed", "reconcile", "declined"]
Source = Literal["chase_plan", "owner_digest", "sourcing_hand_offs", "exchange_books"]
Execution = Literal["connector", "engine", "notification", "none"]
OPEN_STATUSES: frozenset[str] = frozenset({"planned", "awaiting_approval"})
# an uncertain send is asked again with the same idempotency key: the platform's journal replays its
# recorded outcome (sent, failed, or still ambiguous) and never dispatches a second time
DISPATCHABLE_STATUSES: frozenset[str] = OPEN_STATUSES | {"reconcile"}
FINAL_STATUSES: frozenset[str] = frozenset({"done", "declined"})
MAX_ATTEMPTS = 50
_ADDRESS_MARKERS = ("@", "://", "mailto:")


class OwnerActionError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise OwnerActionError(code, message)


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


def action_ref_for(company_ref: str, source: str, key: str) -> str:
    """The stable reference of one logical effect: the same reminder rung, digest or hand-off always maps to the same action."""

    return "act-" + hashlib.sha256(f"{company_ref}|{source}|{key}".encode("utf-8")).hexdigest()[:24]


class ActionAttempt(StrictModel):
    at: str
    outcome: ShortText
    autonomy: Literal["act", "ask", "never"] | None = None
    approval_ref: ShortText | None = None
    error_code: ShortText | None = None
    message: ShortText | None = None


class OwnerAction(StrictModel):
    schema_id: str = Field(default=OWNER_ACTION_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    action_ref: OpaqueRef
    key: ShortText
    source: Source
    source_digest: Sha256Digest
    action_kind: ShortText
    subject: ShortText
    money: Decimal
    autonomy: Literal["act", "ask", "never"]
    authority: ShortText
    execution: Execution
    tool: ShortText | None = None
    arguments: dict[str, Any] = Field(default_factory=dict)
    engine_command: dict[str, Any] | None = None
    idempotency_key: ShortText
    planned_at: str
    request_digest: Sha256Digest
    status: ActionStatus
    approval_ref: ShortText | None = None
    receipt: dict[str, Any] | None = None
    attempts: tuple[ActionAttempt, ...] = Field(default_factory=tuple, max_length=MAX_ATTEMPTS)
    note: ShortText | None = None
    updated_at: str
    action_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("attempts", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("money", mode="before")
    @classmethod
    def _numbers(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="money")

    @field_validator("planned_at", "updated_at")
    @classmethod
    def _stamps(cls, value: str, info: ValidationInfo) -> str:
        return timestamp(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "OwnerAction":
        if self.action_ref != action_ref_for(self.company_ref, self.source, self.key):
            raise ValueError("action_ref is derived from the company, the source and the key")
        if self.idempotency_key != f"owner-action:{self.action_ref}":
            raise ValueError("the idempotency key is the action's own reference, so a retry can never send twice")
        if self.request_digest != request_digest(self):
            raise ValueError("request_digest must commit what the action does; it never changes after planning")
        if (self.execution == "connector") != (self.tool is not None):
            raise ValueError("a connector action names its tool and nothing else does")
        if (self.execution == "engine") != (self.engine_command is not None):
            raise ValueError("an engine action carries its command and nothing else does")
        if _carries_address(self.arguments):
            raise ValueError("recipients are opaque references the platform resolves, never addresses")
        if self.status == "done" and self.receipt is None:
            raise ValueError("a done action carries the receipt of what was done")
        if self.status == "awaiting_approval" and self.approval_ref is None:
            raise ValueError("an action awaiting approval names the approval")
        if not skip_digests(info) and self.action_digest != sealed_digest(OwnerAction, self, "action_digest"):
            raise ValueError("action_digest must commit the exact action")
        return self

    def render(self) -> str:
        where = self.tool or (self.engine_command or {}).get("verb") or "no execution"
        return f"{self.action_kind} {self.subject} via {where}: {self.status}" + (f" (approval {self.approval_ref})" if self.status == "awaiting_approval" else "") + (f"; {self.note}" if self.note else "")


_REQUEST_FIELDS = ("company_ref", "action_ref", "key", "source", "source_digest", "action_kind", "subject", "money", "execution", "tool", "arguments", "engine_command", "idempotency_key", "planned_at")


def request_digest(action: OwnerAction | Mapping[str, Any]) -> str:
    """What the action does, fixed at planning: the attempts, status and receipt move; this never does."""

    values = action.to_dict() if isinstance(action, OwnerAction) else dict(detached(action))
    return stable_digest({name: values.get(name) for name in _REQUEST_FIELDS})


def _carries_address(value: Any, key: str = "") -> bool:
    if isinstance(value, Mapping):
        return any(_carries_address(item, str(name)) for name, item in value.items())
    if isinstance(value, (list, tuple)):
        return any(_carries_address(item, key) for item in value)
    return key in {"recipient_ref", "to", "channel", "recipient"} and isinstance(value, str) and any(marker in value.lower() for marker in _ADDRESS_MARKERS)


def plan_action(*, company_ref: str, source: str, key: str, source_digest: str, action_kind: str, subject: str, money: Any = "0", autonomy: str, authority: str, execution: str, tool: str | None = None, arguments: Mapping[str, Any] | None = None, engine_command: Mapping[str, Any] | None = None, now: str, status: str = "planned", note: str | None = None) -> OwnerAction:
    at = timestamp(now, field_name="now")
    ref = action_ref_for(company_ref, source, key)
    fields: dict[str, Any] = {"company_ref": company_ref, "action_ref": ref, "key": key[:300], "source": source, "source_digest": source_digest, "action_kind": action_kind, "subject": str(subject)[:300], "money": str(decimal_value(money, field_name="money")), "execution": execution, "tool": tool, "arguments": dict(detached(arguments or {})), "engine_command": None if engine_command is None else dict(detached(engine_command)), "idempotency_key": f"owner-action:{ref}", "planned_at": at}
    fields["request_digest"] = request_digest(fields)
    return seal(OwnerAction, {**fields, "autonomy": autonomy, "authority": authority[:300], "status": status, "note": None if note is None else note[:300], "updated_at": at, "attempts": []}, "action_digest")


def actions_from_chase_plan(plan: Mapping[str, Any] | Any, *, now: str) -> list[OwnerAction]:
    """One action per reminder due now; the key is the customer and the rung, so a rung is sent at most once however often the plan is rebuilt."""

    from lightbulb.collections_loop import verify_chase_plan

    parsed = verify_chase_plan(plan)
    actions = []
    for draft in parsed.drafts:
        if draft.status != "due" or draft.delivery is None or draft.autonomy is None:
            continue
        delivery = dict(draft.delivery)
        arguments = {"recipient_ref": delivery["recipient_ref"], "subject": delivery["subject"], "text": delivery["text"], "channel": draft.channel}
        actions.append(plan_action(company_ref=parsed.company_ref, source="chase_plan", key=f"chase:{draft.customer_ref}:rung:{draft.rung}", source_digest=parsed.plan_digest, action_kind="chase_overdue", subject=draft.customer_ref, money=draft.overdue, autonomy=draft.autonomy, authority=draft.mandate_reason or "the chase plan", execution="connector", tool=str(delivery["capability"]), arguments=arguments, now=now))
    return actions


def action_from_digest(digest: Mapping[str, Any] | Any, *, channel: str, recipient_ref: str, now: str, autonomy: str = "ask", authority: str = "the owner approves each digest send") -> OwnerAction:
    """The week's digest as one send: the key is the digest's own digest, so the same week's digest goes out once."""

    from lightbulb.owner_digest import delivery_brief, verify_owner_digest

    parsed = verify_owner_digest(digest)
    brief = delivery_brief(parsed, channel=channel, recipient_ref=recipient_ref)
    arguments = {"recipient_ref": brief["recipient_ref"], "subject": brief["subject"], "text": brief["text"], "channel": channel}
    return plan_action(company_ref=parsed.company_ref, source="owner_digest", key=f"digest:{parsed.digest_digest}", source_digest=parsed.digest_digest, action_kind="send_digest", subject=recipient_ref, autonomy=autonomy, authority=authority, execution="connector", tool=str(brief["capability"]), arguments=arguments, now=now)


def action_from_digest_in_app(digest: Mapping[str, Any] | Any, *, now: str, autonomy: str = "act", authority: str = "delivered to the owner inside the platform; nothing leaves it") -> OwnerAction:
    """The week's digest as an in-app notification to the owner the agent works for; keyed like any digest send, so it arrives once."""

    from lightbulb.owner_digest import verify_owner_digest

    parsed = verify_owner_digest(digest)
    arguments = {"recipient_ref": "self", "subject": parsed.subject, "text": parsed.render_text(), "channel": "in_app"}
    return plan_action(company_ref=parsed.company_ref, source="owner_digest", key=f"digest:{parsed.digest_digest}:in_app", source_digest=parsed.digest_digest, action_kind="send_digest", subject="owner:self", autonomy=autonomy, authority=authority, execution="notification", arguments=arguments, now=now)


def action_from_ledger_posting(posting: Mapping[str, Any], *, company_ref: str, now: str, autonomy: str, authority: str) -> OwnerAction:
    """An exchange invoice posted to the ledger as one governed write: the key is the exchange and the side, so the same invoice is posted at most once however often it is planned."""

    raw = dict(detached(posting))
    _require(raw.get("schema") == "lightbulb.exchange_ledger_posting.v1", "POSTING_SCHEMA_MISMATCH", "expected an exchange ledger posting")
    subject = f"{'bill from' if raw['side'] == 'payable' else 'invoice to'} {raw['counterparty']} ({raw['exchange_ref']})"
    return plan_action(company_ref=company_ref, source="exchange_books", key=f"ledger:{raw['side']}:{raw['exchange_ref']}", source_digest=str(raw["invoice_digest"]), action_kind="post_to_ledger",
                       subject=subject, money=raw["total"], autonomy=autonomy, authority=authority, execution="connector", tool=str(raw["tool"]), arguments=dict(raw["arguments"]), now=now)


def apply_notification_result(action: OwnerAction, *, now: str, receipt: Mapping[str, Any] | None = None, error: BaseException | None = None) -> OwnerAction:
    """The platform delivered the notification (its receipt is kept), or did not (a failure the next dispatch retries)."""

    _require(action.execution == "notification", "NOT_A_NOTIFICATION", "only an in-app notification takes this result")
    _require((receipt is None) != (error is None), "RESULT_AMBIGUOUS", "a notification attempt either delivered or raised")
    if error is not None:
        return _advance(action, now=now, status="planned", attempt={"outcome": "not delivered; the next dispatch tries again", "error_code": type(error).__name__, "message": str(error)[:300]})
    kept = {key: value for key, value in dict(detached(receipt)).items() if key in {"delivered", "channel", "recipient", "notification_key", "delivered_at", "kind"}}
    return _advance(action, now=now, status="done", attempt={"outcome": "delivered in the platform"}, receipt=kept)


def actions_from_hand_offs(hand_offs: Mapping[str, Any] | Any, *, now: str) -> list[OwnerAction]:
    """A drafted hire opens the hiring chain on the owner's accepted decision; a contract waits blocked on an agreement with a named contractor; a blocked draft stays blocked with the chain's reason."""

    from lightbulb.sourcing_hand_offs import verify_sourcing_hand_offs

    parsed = verify_sourcing_hand_offs(hand_offs)
    actions = []
    for draft in parsed.drafts:
        authority = f"the owner accepted {draft.route} for {draft.subject}" + (f" ({draft.owner_ref})" if draft.owner_ref else "")
        base = {"company_ref": parsed.company_ref, "source": "sourcing_hand_offs", "key": f"hand_off:{draft.key}", "source_digest": parsed.hand_offs_digest, "subject": draft.subject, "authority": authority, "now": now}
        if draft.chain == "hiring_chain" and draft.status == "drafted" and draft.receipt is not None:
            # engine entity refs admit no spaces; the requisition is named after the action's stable reference
            command = {"verb": "hiring", "operation": "open", "entity_ref": f"requisition:{action_ref_for(parsed.company_ref, 'sourcing_hand_offs', f'hand_off:{draft.key}')}", "payload": {"receipt": dict(draft.receipt)}}
            actions.append(plan_action(**base, action_kind="open_requisition", autonomy="act", execution="engine", engine_command=command))
        else:
            actions.append(plan_action(**base, action_kind="open_requisition" if draft.chain == "hiring_chain" else "engage_contractor", autonomy="ask", execution="none", status="blocked", note=draft.next_step))
    return actions


def _advance(action: OwnerAction, *, now: str, status: str, attempt: Mapping[str, Any], approval_ref: str | None = None, receipt: Mapping[str, Any] | None = None, autonomy: str | None = None, note: str | None = None) -> OwnerAction:
    _require(action.status not in FINAL_STATUSES, "ACTION_FINAL", f"the action is already {action.status}")
    _require(len(action.attempts) < MAX_ATTEMPTS, "TOO_MANY_ATTEMPTS", "the action has been tried too often; a person looks at it")
    at = timestamp(now, field_name="now")
    values = action.to_dict()
    values.update({"status": status, "updated_at": at, "attempts": [*[row.to_dict() for row in action.attempts], {key: value for key, value in {"at": at, **dict(attempt)}.items() if value is not None}]})
    if approval_ref is not None:
        values["approval_ref"] = approval_ref
    if receipt is not None:
        values["receipt"] = dict(detached(receipt))
    if autonomy is not None:
        values["autonomy"] = autonomy
    if note is not None:
        values["note"] = note[:300]
    return seal(OwnerAction, values, "action_digest")


def refuse_under_mandate(action: OwnerAction, *, now: str, reason: str) -> OwnerAction:
    """The mandate now says never: the action stops before anything is asked or sent."""

    return _advance(action, now=now, status="blocked", attempt={"outcome": "refused by the mandate", "autonomy": "never", "message": reason[:300]}, autonomy="never", note=reason)


def connector_request(action: OwnerAction, *, project_id: str, project_ref: str, connector_account_ref: str, actor_ref: str | None = None) -> Any:
    """The governed write the platform executes: the action's own idempotency key, the approval once there is one, and the owner-action reference as metadata."""

    from lightbulb.connector_execution import ConnectorEffect, ConnectorExecutionRequest, ExecutionScope

    _require(action.execution == "connector" and action.tool is not None, "NOT_A_CONNECTOR_ACTION", "only a message goes through the connector path")
    _require(action.status in DISPATCHABLE_STATUSES, "ACTION_NOT_OPEN", f"the action is {action.status}")
    return ConnectorExecutionRequest(tool=action.tool, arguments=dict(action.arguments), scope=ExecutionScope(project_ref=project_ref, project_id=project_id, actor_ref=actor_ref), connector_account_ref=connector_account_ref, effect=ConnectorEffect.WRITE, approval_required=action.autonomy != "act", approval_ref=action.approval_ref, idempotency_key=action.idempotency_key, metadata={"owner_action_ref": action.action_ref, "action_kind": action.action_kind, "request_digest": action.request_digest})


def apply_connector_result(action: OwnerAction, result: Any, *, now: str, autonomy: str | None = None) -> OwnerAction:
    """The platform's answer, recorded: completed is done with its receipt, pending is awaiting that approval, an ambiguous failure goes to reconciliation, anything else is blocked or failed with the platform's code."""

    raw = result.model_dump(mode="json") if hasattr(result, "model_dump") else dict(detached(result))
    status = str(raw.get("status"))
    common = {"autonomy": autonomy, "error_code": raw.get("error_code"), "message": (raw.get("message") or "")[:300] or None}
    if status == "completed":
        output = dict(raw.get("output") or {})
        provenance = dict(raw.get("provenance") or {})
        provider_ref = next((str(output[name]) for name in ("id", "message_id", "ts", "messageId") if output.get(name)), None)
        receipt = {"tool": action.tool, "provider_ref": provider_ref, "thread_ref": output.get("threadId") or output.get("thread_ts"), "approval_ref": action.approval_ref, "request_digest": provenance.get("request_digest"), "journal_ref": provenance.get("journal_ref") or provenance.get("execution_ref"), "replayed": bool(dict(raw.get("output") or {}).get("replayed", False))}
        return _advance(action, now=now, status="done", attempt={**common, "outcome": "sent", "approval_ref": action.approval_ref}, receipt={key: value for key, value in receipt.items() if value not in (None, "")}, autonomy=autonomy)
    if status == "pending_approval":
        approval_ref = raw.get("approval_ref") or action.approval_ref
        _require(bool(approval_ref), "APPROVAL_REF_MISSING", "the platform asked for approval without naming it")
        return _advance(action, now=now, status="awaiting_approval", attempt={**common, "outcome": "awaiting the owner's approval", "approval_ref": approval_ref}, approval_ref=str(approval_ref), autonomy=autonomy)
    if status == "failed" and (raw.get("error_code") == "GOVERNED_EXECUTION_AMBIGUOUS" or raw.get("unverified_recovery_journal_locator")):
        return _advance(action, now=now, status="reconcile", attempt={**common, "outcome": "the platform cannot say whether it was sent"}, autonomy=autonomy, note="the send may have happened; dispatching again asks the platform's journal for the recorded outcome and never sends twice")
    if status == "preview":
        return _advance(action, now=now, status=action.status, attempt={**common, "outcome": "previewed only"}, autonomy=autonomy)
    final = "failed" if status == "failed" and raw.get("retryable") else "blocked" if status in {"blocked", "failed"} else "failed"
    return _advance(action, now=now, status=final, attempt={**common, "outcome": f"not sent ({status})"}, autonomy=autonomy, note=f"{raw.get('error_code') or status}: {(raw.get('message') or '')[:200]}")


def apply_engine_result(action: OwnerAction, *, now: str, record: Mapping[str, Any] | None = None, error: BaseException | None = None) -> OwnerAction:
    """The chain opened (its entity and state digest are the receipt), or refused with its own reason."""

    _require((record is None) != (error is None), "RESULT_AMBIGUOUS", "an engine attempt either opened the chain or raised")
    if error is not None:
        return _advance(action, now=now, status="blocked", attempt={"outcome": "the chain refused it", "error_code": type(error).__name__, "message": str(error)[:300]}, note=str(error)[:300])
    state = dict((record or {}).get("state") or {})
    receipt = {"engine": (record or {}).get("engine"), "entity_ref": (record or {}).get("entity_ref"), "state_digest": state.get("state_digest"), "status": state.get("status")}
    return _advance(action, now=now, status="done", attempt={"outcome": "opened"}, receipt={key: value for key, value in receipt.items() if value is not None})


def decline_action(action: OwnerAction, *, now: str, reason: str, owner_ref: str | None = None) -> OwnerAction:
    """The owner says no: the action is closed and never planned again."""

    _require(bool(reason.strip()), "REASON_REQUIRED", "a declined action says why")
    return _advance(action, now=now, status="declined", attempt={"outcome": "declined by the owner" + (f" ({owner_ref})" if owner_ref else ""), "message": reason[:300]}, note=reason)


def verify_owner_action(value: Any) -> OwnerAction:
    return value if isinstance(value, OwnerAction) else OwnerAction.model_validate({key: item for key, item in dict(detached(value)).items() if key not in {"summary", "provider_effect_executed", "version"}})


__all__ = ["action_from_ledger_posting", "action_from_digest_in_app", "apply_notification_result", "DISPATCHABLE_STATUSES", "FINAL_STATUSES", "OPEN_STATUSES", "OWNER_ACTIONS_MANIFEST", "OWNER_ACTION_SCHEMA", "ActionAttempt", "OwnerAction", "OwnerActionError", "action_from_digest", "action_ref_for", "actions_from_chase_plan", "actions_from_hand_offs", "apply_connector_result", "apply_engine_result", "connector_request", "decline_action", "plan_action", "refuse_under_mandate", "request_digest", "verify_owner_action"]
