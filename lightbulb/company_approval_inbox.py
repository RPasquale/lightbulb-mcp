"""Operator approval inbox: engine approvals rendered for a person, and resumed for the engine.

The platform's approval queue lists every pending decision.  For company
engine transitions that is not enough: the operator needs to see which
engine wants which transition on which entity, why the engine stopped
(the rejection code and the engine's own instructions), what approving or
rejecting does, and whether the binding is still current or the entity has
moved on since the request.  After a decision the engine should resume by
itself: bind the approved task to the exact request and re-issue the
command through the runtime.

:func:`build_inbox` renders the platform tasks into a sealed
:class:`ApprovalInbox` from the tasks, the persisted engine states, and the
requests the runtimes still hold.  :class:`InboxOperator` wraps a client and
a cadence runner: refresh, approve or reject through the platform, and
resume the engine on approval.  Nothing here decides; people decide.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import Field, ValidationInfo, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, BoundedText, OpaqueRef, Sha256Digest, ShortText, StrictModel, detached, parsed, seal, sealed_digest, skip_digests, timestamp
from lightbulb.company_execution_bridge import ENGINE_APPROVAL_TYPE, EngineApprovalRequest, bind_approval

INBOX_SCHEMA = "lightbulb.company_approval_inbox.v1"
DECISION_PLAN_SCHEMA = "lightbulb.company_approval_decision_plan.v1"
Freshness = Literal["current", "stale", "unknown"]
Decision = Literal["approve", "reject"]
_BINDING_KEYS = ("engine", "entity_ref", "event", "transition_ref", "idempotency_key", "request_digest", "expected_version", "expected_state_digest", "plan_digest", "actor_ref", "approval_request_digest")
_EVENT_EFFECTS: Mapping[str, str] = {
    "replan": "moves budget between engine envelopes for the next period",
    "launch": "lets the platform publish the campaign under its envelope",
    "touch": "lets the platform send the outreach touch on this channel",
    "start_canary": "lets the platform deploy the release to the canary",
    "approve": "records the approval on the entity",
    "dispatch": "lets the platform dispatch the engine's worker",
    "submit_resolution": "issues the remedy inside the ceiling",
}


class EngineTransitionBinding(StrictModel):
    engine: ShortText
    entity_ref: OpaqueRef
    event: ShortText
    transition_ref: OpaqueRef
    idempotency_key: OpaqueRef
    request_digest: Sha256Digest
    expected_version: int = Field(ge=0)
    expected_state_digest: Sha256Digest
    plan_digest: Sha256Digest
    actor_ref: OpaqueRef
    approval_request_digest: Sha256Digest
    rejection_code: ShortText | None = None


class InboxItem(StrictModel):
    task_id: OpaqueRef
    status: ShortText
    approval_type: ShortText
    summary: BoundedText
    description: BoundedText | None = None
    risk_level: ShortText | None = None
    created_at: str | None = None
    expires_at: str | None = None
    engine_binding: EngineTransitionBinding | None = None
    freshness: Freshness = "unknown"
    current_status: ShortText | None = None
    current_version: int | None = Field(default=None, ge=0)
    engine_instructions: BoundedText | None = None
    rendered: BoundedText
    on_approve: BoundedText
    on_reject: BoundedText
    resumable: bool = False


class ApprovalInbox(StrictModel):
    schema_id: str = Field(default=INBOX_SCHEMA, alias="schema")
    rendered_at: str
    items: tuple[InboxItem, ...] = Field(default_factory=tuple, max_length=200)
    engine_items: int = Field(ge=0)
    stale_items: int = Field(ge=0)
    expiring_soon: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=200)
    inbox_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> ApprovalInbox:
        ids = [item.task_id for item in self.items]
        if len(ids) != len(set(ids)):
            raise ValueError("task ids must be unique")
        if not skip_digests(info) and self.inbox_digest != sealed_digest(ApprovalInbox, self, "inbox_digest"):
            raise ValueError("inbox_digest must commit the exact inbox")
        return self


def _binding(task: Mapping[str, Any]) -> EngineTransitionBinding | None:
    if str(task.get("approvalType", "")) != ENGINE_APPROVAL_TYPE:
        return None
    context = dict(task.get("contextData") or task.get("context") or {})
    proposed = dict(task.get("proposedAction") or {}) if isinstance(task.get("proposedAction"), Mapping) else {}
    source = {**proposed, **{key: context[key] for key in _BINDING_KEYS if key in context}}
    if any(key not in source for key in _BINDING_KEYS):
        return None
    try:
        return EngineTransitionBinding.model_validate({**{key: source[key] for key in _BINDING_KEYS}, "rejection_code": context.get("rejection_code")})
    except ValueError:
        return None


def _stamp(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    if text.endswith("Z"):
        return text
    if "T" in text:
        return text.split(".")[0] + "Z"
    return None


def render_item(task: Mapping[str, Any], *, states: Mapping[str, Sequence[Mapping[str, Any]]] | None = None, pending_requests: Mapping[str, EngineApprovalRequest] | None = None, now: str) -> InboxItem:
    raw = dict(detached(task))
    task_id = str(raw.get("id") or "")
    if not task_id:
        raise ValueError("APPROVAL_TASK_INVALID: the task carries no id")
    status = str(raw.get("status") or "PENDING").upper()
    approval_type = str(raw.get("approvalType") or "unknown")
    summary = str(raw.get("summary") or raw.get("title") or "Approval")[:2000]
    description = raw.get("description")
    binding = _binding(raw)
    risk = raw.get("riskLevel")
    risk_text = None if risk is None else str(risk)
    if binding is None:
        return InboxItem(task_id=task_id, status=status, approval_type=approval_type, summary=summary, description=str(description)[:2000] if description else None, risk_level=risk_text, created_at=_stamp(raw.get("createdAt")), expires_at=_stamp(raw.get("expiresAt")), rendered=f"{approval_type}: {summary}", on_approve="Approves the platform task; no company engine resumes from it.", on_reject="Rejects the platform task.")
    freshness: Freshness = "unknown"
    current_status = current_version = None
    for record in (states or {}).get(binding.engine, ()):
        row = dict(detached(record))
        if str(row.get("entity_ref")) == binding.entity_ref:
            current_version = int(row.get("version", 0))
            current_status = str(row.get("status"))
            freshness = "current" if current_version == binding.expected_version and str(row.get("state_digest")) == binding.expected_state_digest else "stale"
            break
    request = (pending_requests or {}).get(binding.transition_ref)
    instructions = None
    if request is not None:
        instructions = f"{request.rejection_code}: {request.description}"
    effect = _EVENT_EFFECTS.get(binding.event, f"applies the {binding.event} transition")
    rendered = (f"{binding.engine} wants to {binding.event} {binding.entity_ref} (version {binding.expected_version}" + (f", now {current_status} v{current_version}" if current_version is not None else "") + f"). Stopped on {binding.rejection_code or 'APPROVAL_REQUIRED'}. " + ("The binding is current." if freshness == "current" else "The entity moved on since the request; approving will not resume it, ask for a fresh request." if freshness == "stale" else "State not loaded; freshness unknown."))
    return InboxItem(task_id=task_id, status=status, approval_type=approval_type, summary=summary, description=str(description)[:2000] if description else None, risk_level=risk_text, created_at=_stamp(raw.get("createdAt")), expires_at=_stamp(raw.get("expiresAt")), engine_binding=binding, freshness=freshness, current_status=current_status, current_version=current_version, engine_instructions=instructions, rendered=rendered, on_approve=f"Approving {effect}; the engine re-issues the exact command with the bound approval and persists the new state.", on_reject="Rejecting leaves the entity where it is; the engine raises the same work item again only if the operator asks.", resumable=freshness == "current" and request is not None and status == "PENDING")


def build_inbox(tasks: Sequence[Mapping[str, Any]], *, states: Mapping[str, Sequence[Mapping[str, Any]]] | None = None, pending_requests: Mapping[str, EngineApprovalRequest] | None = None, now: str, expiring_within_hours: int = 24) -> ApprovalInbox:
    now = timestamp(now, field_name="now")
    items = [render_item(task, states=states, pending_requests=pending_requests, now=now) for task in tasks]
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    items.sort(key=lambda item: (0 if item.engine_binding is not None else 1, order.get(str(item.risk_level).lower(), 2) if not str(item.risk_level).isdigit() else max(0, 10 - int(str(item.risk_level))), item.expires_at or "9999", item.task_id))
    horizon = parsed(now).timestamp() + expiring_within_hours * 3600
    expiring = tuple(item.task_id for item in items if item.expires_at and parsed(item.expires_at).timestamp() <= horizon and item.status == "PENDING")
    return seal(ApprovalInbox, {"rendered_at": now, "items": tuple(items), "engine_items": sum(1 for item in items if item.engine_binding is not None), "stale_items": sum(1 for item in items if item.freshness == "stale"), "expiring_soon": expiring}, "inbox_digest")


class DecisionPlan(StrictModel):
    schema_id: str = Field(default=DECISION_PLAN_SCHEMA, alias="schema")
    task_id: OpaqueRef
    decision: Decision
    client_method: Literal["LightbulbClient.approve_task", "LightbulbClient.reject_task"]
    comments: BoundedText
    resumes: bool
    engine: ShortText | None = None
    entity_ref: OpaqueRef | None = None
    transition_ref: OpaqueRef | None = None
    warning: BoundedText | None = None


def plan_decision(item: InboxItem | Mapping[str, Any], decision: Decision, *, comments: str) -> DecisionPlan:
    parsed_item = item if isinstance(item, InboxItem) else InboxItem.model_validate(dict(detached(item)))
    if parsed_item.status != "PENDING":
        raise ValueError(f"APPROVAL_NOT_PENDING: task {parsed_item.task_id} is {parsed_item.status}")
    binding = parsed_item.engine_binding
    warning = None
    if binding is not None and parsed_item.freshness == "stale":
        warning = "the entity moved on since this request; the engine will not resume from this approval"
    return DecisionPlan(task_id=parsed_item.task_id, decision=decision, client_method="LightbulbClient.approve_task" if decision == "approve" else "LightbulbClient.reject_task", comments=comments.strip() or f"{decision} via operator inbox", resumes=decision == "approve" and parsed_item.resumable, engine=binding.engine if binding else None, entity_ref=binding.entity_ref if binding else None, transition_ref=binding.transition_ref if binding else None, warning=warning)


@dataclass
class InboxOperator:
    """Refresh the inbox from the platform, decide through it, and resume engines on approval."""

    client: Any
    runner: Any
    clock: Any
    inbox: ApprovalInbox | None = None
    resumed: list[Any] = field(default_factory=list)

    def _pending(self) -> dict[str, EngineApprovalRequest]:
        merged: dict[str, EngineApprovalRequest] = {}
        for runtime in self.runner.runtimes.values():
            merged.update(runtime.pending)
        return merged

    def _resume_auto_accepted(self) -> None:
        """Resume the transitions the platform already accepted under a standing rule.

        ``advance_and_persist`` discards the requester's return and the platform
        queue lists only ``PENDING`` tasks, so an auto-accepted transition never
        appears in the inbox and would stay parked.  The task the runtime kept is
        re-read before it is believed, and a decision that does not bind leaves
        the request pending for a person.
        """

        for runtime in self.runner.runtimes.values():
            for transition_ref in list(runtime.pending):
                task = dict(detached(getattr(runtime, "requested", {}).get(transition_ref) or {}))
                context = dict(task.get("contextData") or task.get("context") or {})
                if str(task.get("status") or "").upper() != "APPROVED" or not bool(context.get("auto_accepted")):
                    continue
                task_id = str(task.get("id") or "")
                decided = dict(self.client.get_approval(task_id)) if task_id else task
                try:
                    bind_approval(decided, runtime.pending[transition_ref])
                    self.resumed.append(runtime.resume_pending(transition_ref, decided, occurred_at=self.clock()))
                except (LookupError, ValueError):
                    continue

    def refresh(self) -> ApprovalInbox:
        self._resume_auto_accepted()
        tasks = list(self.client.list_pending_approvals() or [])
        self.inbox = build_inbox(tasks, states=self.runner.states(), pending_requests=self._pending(), now=self.clock())
        return self.inbox

    def item(self, task_id: str) -> InboxItem:
        inbox = self.inbox or self.refresh()
        match = next((item for item in inbox.items if item.task_id == task_id), None)
        if match is None:
            raise LookupError(f"task {task_id} is not in the inbox")
        return match

    def decide(self, task_id: str, decision: Decision, *, comments: str = "", authorization_proof: Any = None) -> tuple[DecisionPlan, Mapping[str, Any], Any]:
        plan = plan_decision(self.item(task_id), decision, comments=comments)
        task = self.client.approve_task(task_id, comments=plan.comments) if decision == "approve" else self.client.reject_task(task_id, comments=plan.comments)
        outcome = None
        if plan.resumes and plan.transition_ref is not None:
            decided = self.client.get_approval(task_id)
            for runtime in self.runner.runtimes.values():
                if plan.transition_ref in runtime.pending:
                    request = runtime.pending[plan.transition_ref]
                    bind_approval(decided, request)
                    outcome = runtime.resume_pending(plan.transition_ref, decided, occurred_at=self.clock(), authorization_proof=authorization_proof)
                    self.resumed.append(outcome)
                    break
        self.inbox = None
        return plan, task, outcome


__all__ = ["DECISION_PLAN_SCHEMA", "INBOX_SCHEMA", "ApprovalInbox", "DecisionPlan", "EngineTransitionBinding", "InboxItem", "InboxOperator", "build_inbox", "plan_decision", "render_item"]
