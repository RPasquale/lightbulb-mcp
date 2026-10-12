"""The console side of the act loop: plan the owner's actions from the sealed documents, dispatch them through the platform, and keep one record per action.

``plan`` turns what is due (the reminders in the chase plan, the week's
digest when the owner names where it goes, the hand-offs the owner accepted)
into ``owner_action`` records; a record that already exists is left alone,
so rebuilding the plan never queues the same send twice.  ``dispatch`` takes
the open actions, asks the mandate again, and hands each to the platform: a
message to the console's connector executor (Governed Connector Execution,
which asks the owner and sends once), a hire to the hiring chain.  The
answer is written back to the record, and a send the agent made under the
mandate's ``act`` is logged in the month's mandate log.  ``decline`` closes
an action for good; ``list`` shows them all.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from lightbulb.company_engine_core import stable_digest, timestamp

OWNER_ACTION_ENGINE = "owner_action"
OWNER_ACTION_RECORD_SCHEMA = "lightbulb.owner_action_record.v1"


def _entity(action_ref: str) -> str:
    return f"action:{action_ref}"


def _load(console: Any, action_ref: str) -> tuple[Any, dict[str, Any]] | None:
    from lightbulb.owner_actions import verify_owner_action

    record = console.store.get(OWNER_ACTION_ENGINE, _entity(action_ref))
    if record is None:
        return None
    return verify_owner_action(dict(record["state"])["action"]), record


def _save(console: Any, action: Any, *, now: str, existing: Mapping[str, Any] | None) -> dict[str, Any]:
    entity_ref = _entity(action.action_ref)
    version = 1 if existing is None else int(existing["version"]) + 1
    state = {"schema": OWNER_ACTION_RECORD_SCHEMA, "status": action.status, "plan_digest": stable_digest({"owner_action": console.bundle.company_ref}), "version": version, "state_digest": action.action_digest, "scope": console.bundle.engine_scope(entity_ref), "as_of": timestamp(now, field_name="now"), "action": action.to_dict()}
    console.store.put(OWNER_ACTION_ENGINE, entity_ref, state, expected_version=None if existing is None else int(existing["version"]), expected_state_digest=None if existing is None else str(existing["state_digest"]))
    return {**action.to_dict(), "entity_ref": entity_ref, "version": version}


def persisted_owner_actions(console: Any) -> list[Any]:
    """Every action recorded for this company, oldest plan first."""

    from lightbulb.owner_actions import verify_owner_action

    actions = [verify_owner_action(dict(record["state"])["action"]) for record in console.store.list(engine=OWNER_ACTION_ENGINE, limit=500)]
    return sorted((action for action in actions if action.company_ref == console.bundle.company_ref), key=lambda action: (action.planned_at, action.action_ref))


def _inventory(console: Any, *, now: str, touched: Sequence[Mapping[str, Any]] = (), label: str) -> dict[str, Any]:
    actions = persisted_owner_actions(console)
    counts: dict[str, int] = {}
    for action in actions:
        counts[action.status] = counts.get(action.status, 0) + 1
    lines = [f"**Owner actions** ({console.bundle.company_ref}, {timestamp(now, field_name='now')[:10]}): {label}; " + (", ".join(f"{count} {status}" for status, count in sorted(counts.items())) or "none recorded")]
    lines.extend(f"- {action.render()}" for action in actions if action.status not in {"done", "declined"})
    return {"schema": "lightbulb.owner_action_inventory.v1", "company_ref": console.bundle.company_ref, "as_of": timestamp(now, field_name="now"), "counts": counts, "actions": [action.to_dict() for action in actions], "touched": list(touched), "summary": "\n".join(lines), "provider_effect_executed": any(row.get("status") == "done" and row.get("execution") == "connector" for row in touched)}


def list_owner_actions_document(console: Any, *, now: str) -> dict[str, Any]:
    return _inventory(console, now=now, label="as recorded")


def plan_owner_actions_document(console: Any, *, now: str, digest_channel: str | None = None, digest_recipient_ref: str | None = None, hand_offs: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Record an action for every reminder due now, for the week's digest when its channel and recipient are given, and for each hand-off in a supplied sealed hand-offs document; existing actions are kept as they are."""

    from lightbulb.company_operator_surface import build_chase_plan_document
    from lightbulb.owner_actions import action_from_digest, action_from_digest_in_app, actions_from_chase_plan, actions_from_hand_offs

    at = timestamp(now, field_name="now")
    candidates = list(actions_from_chase_plan({key: value for key, value in build_chase_plan_document(console, now=at).items() if key not in {"summary", "provider_effect_executed", "held_for_remittance"}}, now=at))
    if digest_channel == "in_app":
        from lightbulb.company_operator_surface import build_owner_digest_document, check_mandate

        if digest_recipient_ref is not None:
            raise ValueError("an in-app digest goes to the owner the agent works for; it takes no digest_recipient_ref")
        digest = build_owner_digest_document(console, now=at)
        decision = check_mandate(console, now=at, action_kind="send_digest", subject="owner:self")
        autonomy = "never" if decision["autonomy"] == "never" else "act"
        candidates.append(action_from_digest_in_app({key: value for key, value in digest.items() if key not in {"summary", "provider_effect_executed", "documents_built", "text", "delivery", "gaps"}}, now=at, autonomy=autonomy))
    elif (digest_channel is None) != (digest_recipient_ref is None):
        raise ValueError("the digest needs digest_channel in_app, or email or slack with digest_recipient_ref, or neither")
    elif digest_channel is not None:
        from lightbulb.company_operator_surface import build_owner_digest_document, check_mandate

        digest = build_owner_digest_document(console, now=at)
        decision = check_mandate(console, now=at, action_kind="send_digest", subject=str(digest_recipient_ref))
        candidates.append(action_from_digest({key: value for key, value in digest.items() if key not in {"summary", "provider_effect_executed", "documents_built", "text", "delivery", "gaps"}}, channel=str(digest_channel), recipient_ref=str(digest_recipient_ref), now=at, autonomy=str(decision["autonomy"]), authority=str(decision["reason"])))
    if hand_offs is not None:
        if dict(hand_offs).get("company_ref") != console.bundle.company_ref:
            raise ValueError("SCOPE_MISMATCH: the hand-offs name another company")
        candidates.extend(actions_from_hand_offs(hand_offs, now=at))
    touched = []
    for action in candidates:
        if _load(console, action.action_ref) is not None:
            continue
        touched.append(_save(console, action, now=at, existing=None))
    return _inventory(console, now=at, touched=touched, label=f"{len(touched)} new action(s) planned")


def record_owner_actions(console: Any, actions: Sequence[Any], *, now: str) -> list[dict[str, Any]]:
    """Keep one record per action planned elsewhere (an exchange's ledger posting): a new action is recorded, one already recorded is left as it is."""

    at = timestamp(now, field_name="now")
    kept = []
    for action in actions:
        loaded = _load(console, action.action_ref)
        kept.append({**loaded[0].to_dict(), "entity_ref": _entity(action.action_ref), "recorded": False} if loaded is not None else {**_save(console, action, now=at, existing=None), "recorded": True})
    return kept


def _mandate_decision(console: Any, action: Any, *, now: str) -> dict[str, Any] | None:
    from lightbulb.company_operator_surface import check_mandate

    if action.source == "sourcing_hand_offs":
        return None  # the owner's accepted decision is the authority for a hand-off
    return check_mandate(console, now=now, action_kind=action.action_kind, money=action.money, subject=action.subject)


def dispatch_owner_actions_document(console: Any, *, now: str, connector_account_refs: Mapping[str, str] | None = None, action_refs: Sequence[str] | None = None) -> dict[str, Any]:
    """Hand every open action (or the ones named) to the platform and record its answer; ``connector_account_refs`` maps each tool to the project's exact account reference."""

    from lightbulb.company_operator_surface import check_mandate_log, record_mandate_action
    from lightbulb.owner_actions import DISPATCHABLE_STATUSES, MAX_ATTEMPTS, OPEN_STATUSES, apply_connector_result, apply_engine_result, apply_notification_result, connector_request, refuse_under_mandate

    at = timestamp(now, field_name="now")
    wanted = None if action_refs is None else {str(ref) for ref in action_refs}
    accounts = {str(tool): str(ref) for tool, ref in dict(connector_account_refs or {}).items()}
    project_id = str(console.bundle.scope.get("project_id") or "")
    executor = getattr(console, "connector_executor", None)
    touched = []
    for action in persisted_owner_actions(console):
        if action.status not in DISPATCHABLE_STATUSES or (wanted is not None and action.action_ref not in wanted):
            continue
        if action.status not in OPEN_STATUSES and action.execution != "connector":
            continue
        # Check before any effect, including reconciliation. Otherwise the provider can
        # succeed after the bounded attempt history can no longer retain its receipt.
        if len(action.attempts) >= MAX_ATTEMPTS:
            touched.append({**action.to_dict(), "skipped": "attempt limit reached; a person must reconcile the action"})
            continue
        loaded = _load(console, action.action_ref)
        assert loaded is not None
        _, existing = loaded
        decision = _mandate_decision(console, action, now=at)
        autonomy = None if decision is None else str(decision["autonomy"])
        if autonomy == "never" and action.status != "reconcile":
            touched.append(_save(console, refuse_under_mandate(action, now=at, reason=str(decision["reason"])), now=at, existing=existing))
            continue
        if action.execution == "engine":
            command = dict(action.engine_command or {})
            try:
                opened = console.chain(str(command["verb"]), operation=str(command["operation"]), entity_ref=str(command["entity_ref"]), payload=dict(command.get("payload") or {}), now=at)
                updated = apply_engine_result(action, now=at, record={"engine": opened.get("engine"), "entity_ref": opened.get("entity_ref"), "state": opened.get("state")})
            except (ValueError, LookupError) as exc:
                updated = apply_engine_result(action, now=at, error=exc)
            touched.append(_save(console, updated, now=at, existing=existing))
            continue
        if action.execution == "notification":
            notifier = getattr(console, "owner_notifier", None)
            if notifier is None or not project_id:
                touched.append({**action.to_dict(), "skipped": "the console has no owner notifier (a hosted console supplies one)" if notifier is None else "the bundle's scope has no project_id"})
                continue
            try:
                title = " ".join(str(action.arguments.get("subject") or "Your week").split())[:200]
                delivered = notifier(project_id=project_id, kind="owner_digest", notification_key=action.idempotency_key, title=title, message=str(action.arguments.get("text") or "")[:8000])
                updated = apply_notification_result(action, now=at, receipt=delivered)
            except Exception as exc:  # the platform did not deliver it; the action stays open for the next dispatch
                updated = apply_notification_result(action, now=at, error=exc)
            touched.append(_save(console, updated, now=at, existing=existing))
            continue
        if action.execution != "connector":
            continue
        account = accounts.get(str(action.tool))
        if executor is None or not project_id or account is None:
            missing = "the console has no connector executor (a hosted console supplies one)" if executor is None else "the bundle's scope has no project_id" if not project_id else f"no connector account reference was given for {action.tool}"
            touched.append({**action.to_dict(), "skipped": missing})
            continue
        if autonomy == "act" and decision is not None and decision.get("decision_digest"):
            try:
                # the month's log must be able to take the entry before the provider is called: an effect with no record breaks the envelope
                check_mandate_log(console, now=at, decision=decision)
            except (ValueError, LookupError) as exc:
                touched.append({**action.to_dict(), "skipped": f"the month's mandate log cannot record it: {exc}"[:300]})
                continue
        request = connector_request(action, project_id=project_id, project_ref=str(console.bundle.scope.get("project_ref") or project_id), connector_account_ref=account, actor_ref=getattr(console.bundle, "actor_ref", None))
        updated = apply_connector_result(action, executor.execute(request), now=at, autonomy=autonomy)
        saved = _save(console, updated, now=at, existing=existing)
        if updated.status == "done" and autonomy == "act" and decision is not None and decision.get("decision_digest"):
            logged = record_mandate_action(console, now=at, decision=decision, tool=action.tool, effect_ref=str((updated.receipt or {}).get("provider_ref") or action.action_ref), note=_log_note(action))
            saved["mandate_log"] = {"entity_ref": logged["entity_ref"], "version": logged["version"]}
        touched.append(saved)
    return _inventory(console, now=at, touched=touched, label=f"{len(touched)} action(s) dispatched")


def _log_note(action: Any) -> str:
    if action.action_kind == "chase_overdue":
        return f"rung:{action.key.rsplit(':', 1)[-1]} {action.action_ref}"
    return action.action_ref


def decline_owner_action_document(console: Any, *, now: str, action_ref: str, reason: str, owner_ref: str | None = None) -> dict[str, Any]:
    from lightbulb.owner_actions import decline_action

    at = timestamp(now, field_name="now")
    loaded = _load(console, str(action_ref))
    if loaded is None:
        raise LookupError(f"no owner action {action_ref}")
    action, existing = loaded
    saved = _save(console, decline_action(action, now=at, reason=str(reason), owner_ref=owner_ref), now=at, existing=existing)
    return _inventory(console, now=at, touched=[saved], label="1 action declined")


def sent_chases(console: Any) -> list[dict[str, Any]]:
    """Every reminder the act loop has sent (with or without the owner's approval), in the chase history's shape."""

    rows = []
    for action in persisted_owner_actions(console):
        if action.action_kind == "chase_overdue" and action.status == "done":
            rung = action.key.rsplit(":", 1)[-1]
            rows.append({"customer_ref": action.subject, "rung": int(rung) if rung.isdigit() else None, "at": action.updated_at, "money": str(action.money), "action_ref": action.action_ref})
    return rows


__all__ = ["OWNER_ACTION_ENGINE", "decline_owner_action_document", "dispatch_owner_actions_document", "list_owner_actions_document", "persisted_owner_actions", "plan_owner_actions_document", "sent_chases"]
