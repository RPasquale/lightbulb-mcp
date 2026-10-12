"""Advice cases that persist: the case lifecycle run through the platform's engine-state store, with the adviser's approval as a platform decision.

An advice case is state the business must keep: who the client is (as a commitment), what was
found, what was shortlisted, what was recommended, who approved it and under which authority,
what was presented and implemented, and when it is reviewed. This module runs the case lifecycle
through the same durable runtime every other engine uses: every transition is replay-fenced by
version and digest, every state is sealed, and the licensed adviser's approval is a platform
approval task decided by a different person from the one who asked, bound to the exact
recommendation before the case moves on. Nothing here advises; the lifecycle refuses what the
plan does not allow.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any

from lightbulb.company_engine_core import detached, parsed, timestamp
from lightbulb.company_engine_store import EngineAdvanceOutcome, EngineRuntime, EngineStateStore, HostedEngineStateStore
from lightbulb.company_execution_bridge import EngineApprovalRequest
from lightbulb.finance_advice_engine import ADVICE_CASE_LIFECYCLE, AdvicePlan, Authority, advance_advice_case, approval_receipt, open_advice_case

FINANCE_ADVICE_ENGINE = "finance_advice_engine"
DEFAULT_CASE_RISK_LEVEL = 7


def advice_case_runtime(plan: AdvicePlan, store: EngineStateStore, *, approval_requester: Callable[[EngineApprovalRequest], Mapping[str, Any]] | None = None, approval_reader: Callable[[str], Mapping[str, Any]] | None = None, risk_level: int = DEFAULT_CASE_RISK_LEVEL) -> EngineRuntime:
    """The durable runtime for one plan's advice cases."""

    return EngineRuntime(spec=ADVICE_CASE_LIFECYCLE, engine=FINANCE_ADVICE_ENGINE, plan=plan, store=store, advance=advance_advice_case, approval_requester=approval_requester, approval_reader=approval_reader, risk_level=risk_level)


def hosted_advice_case_runtime(client: Any, plan: AdvicePlan, *, project_id: str, company_id: str | None = None, approval_requester: Callable[[EngineApprovalRequest], Mapping[str, Any]] | None = None, risk_level: int = DEFAULT_CASE_RISK_LEVEL) -> EngineRuntime:
    """Compatibility adapter for reading advice through the generic engine store.

    Production advice writes must use the governed finance/advice actions. The
    public generic state API refuses writes and migrations for this engine;
    workers use their scoped internal case store with authoritative validation.
    """

    store = HostedEngineStateStore(client, project_id=project_id, company_id=company_id)
    reader = getattr(client, "get_approval", None)
    return advice_case_runtime(plan, store, approval_requester=approval_requester, approval_reader=reader, risk_level=risk_level)


def open_case(runtime: EngineRuntime, *, entity_ref: str, scope: Mapping[str, Any], receipt: Mapping[str, Any], opened_at: str, actor_ref: str, engagement: Mapping[str, Any] | None = None, predecessor_case_ref: str | None = None) -> Any:
    """Open a case under the runtime's plan and persist version 1."""
    receipt = dict(receipt)
    if engagement is not None:
        receipt.setdefault("engagement_digest", dict(detached(engagement)).get("engagement_digest"))
    if predecessor_case_ref is not None:
        receipt.setdefault("predecessor_case_ref", predecessor_case_ref)

    state = open_advice_case(runtime.plan, {**dict(scope), "entity_ref": entity_ref}, receipt=receipt, opened_at=opened_at, actor_ref=actor_ref)
    runtime.open(entity_ref, state)
    return state


def advance_case(runtime: EngineRuntime, entity_ref: str, *, event: str, receipt: Mapping[str, Any] | None, occurred_at: str, actor_ref: str, reason: str | None = None, summary: str | None = None) -> EngineAdvanceOutcome:
    """One transition against the persisted case; a refused transition is returned, never raised, and an approval gate opens a request."""

    state = runtime.load(entity_ref)
    command = runtime.command(state, event=event, transition_ref=f"{event}:{entity_ref}:{state.version}", idempotency_key=f"{event}:{entity_ref}:{state.version}", occurred_at=occurred_at, actor_ref=actor_ref, receipt=receipt, reason=reason)
    return runtime.advance_and_persist(entity_ref, command, summary=summary or f"Advice case {entity_ref}: {event}", description=f"{FINANCE_ADVICE_ENGINE} asks for {event} on {entity_ref}")


VERIFICATION_MAX_AGE_DAYS = 35


def _digest_of(payload: Mapping[str, Any] | Any, *names: str) -> str | None:
    raw = dict(detached(payload))
    for name in names:
        value = raw.get(name)
        if value:
            return str(value)
    return None


def request_adviser_approval(runtime: EngineRuntime, entity_ref: str, *, adviser_ref: str, authority: Authority | Mapping[str, Any], approved_at: str, recommendation_digest: str, actor_ref: str, occurred_at: str, checklist: Mapping[str, Any] | None = None, verification: Mapping[str, Any] | None = None) -> EngineAdvanceOutcome:
    """Ask the platform for the licensed adviser's approval of the exact recommendation; the case waits until a different person decides.

    When the compliance checklist and the licence verification are offered they are checked before the platform
    is asked: an incomplete checklist, a checklist for another recommendation, a refused or stale verification, or a
    verification of another commitment refuses here, by code, and no approval task is opened.
    """

    a = authority if isinstance(authority, Authority) else Authority.model_validate(dict(detached(authority)))
    checklist_digest = None
    verification_digest = None
    if checklist is not None:
        raw = dict(detached(checklist))
        missing = list(raw.get("missing") or ())
        if not missing and raw.get("missing_count"):
            missing = [f"{raw['missing_count']} item(s)"]
        if missing:
            raise ValueError("CHECKLIST_INCOMPLETE: the compliance checklist still lacks " + ", ".join(str(item) for item in missing))
        if raw.get("recommendation_digest") not in (None, recommendation_digest):
            raise ValueError("CHECKLIST_MISMATCH: the checklist was evaluated for a different recommendation")
        checklist_digest = _digest_of(raw, "checklist_digest", "digest")
    if verification is not None:
        raw = dict(detached(verification))
        if raw.get("verdict") != "verified":
            raise ValueError("AUTHORITY_UNVERIFIED: the licence verification did not verify the authority (" + ", ".join(str(item) for item in raw.get("findings") or ()) + ")")
        if raw.get("authority_ref_sha256") != a.authority_ref_sha256:
            raise ValueError("COMMITMENT_MISMATCH: the verification names a different authority commitment")
        verified_at = raw.get("verified_at")
        if verified_at and (parsed(timestamp(approved_at, field_name="approved_at")) - parsed(str(verified_at))).days > VERIFICATION_MAX_AGE_DAYS:
            raise ValueError(f"VERIFICATION_STALE: the licence was verified more than {VERIFICATION_MAX_AGE_DAYS} days before the approval")
        verification_digest = _digest_of(raw, "verification_digest", "digest")
    receipt = approval_receipt(approval_ref=None, adviser_ref=adviser_ref, authority=a, approved_at=approved_at, recommendation_digest=recommendation_digest, checklist_digest=checklist_digest, verification_digest=verification_digest)
    return advance_case(runtime, entity_ref, event="approve", receipt=receipt, occurred_at=occurred_at, actor_ref=actor_ref, summary=f"Adviser approval for advice case {entity_ref}")


def present_case(runtime: EngineRuntime, entity_ref: str, *, document: Mapping[str, Any], acknowledgement: Mapping[str, Any], explanation: Mapping[str, Any] | None = None, occurred_at: str, actor_ref: str) -> EngineAdvanceOutcome:
    """Present the approved document to the client: the document must be the approved record and the acknowledgement must name that document."""

    doc = dict(detached(document))
    ack = dict(detached(acknowledgement))
    if not doc.get("complete", False):
        raise ValueError("DOCUMENT_DRAFT: a draft document is not presented; the adviser approves first")
    if ack.get("document_digest") != doc.get("document_digest"):
        raise ValueError("ACKNOWLEDGEMENT_MISMATCH: the acknowledgement names a different document")
    explanation_digest = _digest_of(explanation, "explanation_digest", "document_digest") if explanation is not None else None
    if explanation is not None and dict(detached(explanation)).get("record_digest") not in (None, doc.get("record_digest")):
        raise ValueError("EXPLANATION_NOT_FOR_THIS_RECORD: the explanation was written for a different record")
    receipt = {"statement_digest": doc.get("record_digest"), "client_acknowledgement_ref": ack.get("acknowledgement_ref") or ack.get("acknowledged_by_ref") or ack.get("client_ref"), "document_digest": doc.get("document_digest"), "explanation_digest": explanation_digest, "evidence_refs": [f"document:{str(doc.get('document_digest'))[:16]}"]}
    return advance_case(runtime, entity_ref, event="present", receipt=receipt, occurred_at=occurred_at, actor_ref=actor_ref, summary=f"Advice presented for case {entity_ref}")


def implement_case(runtime: EngineRuntime, entity_ref: str, *, pack: Mapping[str, Any], outcome: Mapping[str, Any], reconciliation: Mapping[str, Any] | None = None, differences_acknowledged_ref: str | None = None, occurred_at: str, actor_ref: str) -> EngineAdvanceOutcome:
    """Implement the recommended product: the application pack names the product, the provider's outcome is recorded, and differing terms need the adviser's acknowledgement."""

    p = dict(detached(pack))
    o = dict(detached(outcome))
    r = dict(detached(reconciliation)) if reconciliation is not None else {}
    receipt = {"implementation_ref": _digest_of(p, "pack_ref", "application_ref", "pack_digest", "application_digest"), "product_ref": p.get("product_ref"), "outcome_digest": _digest_of(o, "outcome_digest", "digest"), "reconciliation_digest": _digest_of(r, "reconciliation_digest", "digest"), "reconciliation_verdict": r.get("verdict"), "differences_acknowledged_ref": differences_acknowledged_ref, "evidence_refs": [f"outcome:{str(o.get('outcome') or o.get('kind') or 'stated')}"]}
    return advance_case(runtime, entity_ref, event="implement", receipt=receipt, occurred_at=occurred_at, actor_ref=actor_ref, summary=f"Advice implemented for case {entity_ref}")


def review_case(runtime: EngineRuntime, entity_ref: str, *, assessment: Mapping[str, Any], outcome_note: str | None = None, successor_case_ref: str | None = None, occurred_at: str, actor_ref: str) -> EngineAdvanceOutcome:
    """Close the case with its review assessment; a re-advice names the successor case that carries the client forward."""

    a = dict(detached(assessment))
    outcome = str(a.get("outcome") or a.get("verdict") or "reviewed")
    if outcome_note:
        outcome = f"{outcome}: {outcome_note}"
    receipt = {"review_outcome": outcome[:200], "review_digest": _digest_of(a, "review_digest", "assessment_digest", "digest"), "successor_case_ref": successor_case_ref, "evidence_refs": [f"review:{str(a.get('reviewed_at') or a.get('as_of') or occurred_at)[:10]}"]}
    return advance_case(runtime, entity_ref, event="review", receipt=receipt, occurred_at=occurred_at, actor_ref=actor_ref, summary=f"Advice reviewed for case {entity_ref}")


def open_successor_case(runtime: EngineRuntime, *, predecessor_ref: str, entity_ref: str, scope: Mapping[str, Any], state_now: Mapping[str, Any], opened_at: str, actor_ref: str, engagement: Mapping[str, Any] | None = None) -> Any:
    """Open the case that carries a reviewed client forward: same client commitment, the current state's vertical and objective, linked to its predecessor."""

    st = dict(detached(state_now))
    # A retry after the successor was persisted must reuse that case, never reopen it with a new time.
    if runtime.store.get(runtime.engine, entity_ref) is not None:
        existing = runtime.load(entity_ref)
        existing_scope = dict(detached(existing.scope))
        if (existing.ledger.predecessor_case_ref != predecessor_ref or existing.ledger.client_ref != st.get("client_ref")
                or existing.ledger.vertical_id != st.get("vertical_id")
                or any(existing_scope.get(key) != value for key, value in scope.items())):
            raise ValueError("SUCCESSOR_SCOPE_MISMATCH: the retained successor belongs to another case or scope")
        return existing
    receipt = {"client_ref": st.get("client_ref"), "vertical_id": st.get("vertical_id"), "objective": st.get("objective"), "evidence_refs": [f"predecessor:{predecessor_ref}"]}
    return open_case(runtime, entity_ref=entity_ref, scope=scope, receipt=receipt, opened_at=opened_at, actor_ref=actor_ref, engagement=engagement, predecessor_case_ref=predecessor_ref)


def resume_with_adviser_approval(runtime: EngineRuntime, entity_ref: str, task: Mapping[str, Any], *, occurred_at: str) -> EngineAdvanceOutcome:
    """Bind the platform's approved task to the pending approve command and move the case to adviser_approved."""

    pending = [ref for ref, request in runtime.pending.items() if request.entity_ref == entity_ref and request.event == "approve"]
    if not pending:
        raise LookupError(f"no pending adviser approval for advice case {entity_ref}")
    command = runtime.pending_commands[pending[-1]]
    return runtime.resume_with_approval(entity_ref, command, task, occurred_at=occurred_at)


def apply_fact_change(runtime: EngineRuntime, entity_ref: str, *, event_ref: str, changed_fields: Sequence[str] = (), changed_product_refs: Sequence[str] = (), occurred_at: str, actor_ref: str) -> EngineAdvanceOutcome:
    """A published fact change reaches one open case: back to its fact find, or flagged for the adviser when advice was already approved or presented."""

    return advance_case(runtime, entity_ref, event="facts_changed", receipt={"event_ref": event_ref, "changed_fields": list(changed_fields), "changed_product_refs": list(changed_product_refs)}, occurred_at=occurred_at, actor_ref=actor_ref, summary=f"facts changed: {event_ref}")


def apply_client_revision(runtime: EngineRuntime, entity_ref: str, state: Mapping[str, Any], *, occurred_at: str, actor_ref: str) -> EngineAdvanceOutcome:
    """Bind an actual same-client SDK revision before any existing approval can continue."""
    from lightbulb.finance_advice_engine import ClientState
    revision = ClientState.model_validate(dict(detached(state)))
    current = runtime.load(entity_ref)
    if (current.ledger.client_ref != revision.client_ref or current.ledger.vertical_id != revision.vertical_id
            or current.ledger.personal_data_sha256 not in (None, revision.personal_data_sha256)):
        raise ValueError("REVISION_CLIENT_MISMATCH: revised facts must belong to this case's client")
    return advance_case(runtime, entity_ref, event="facts_changed", receipt={
        "event_ref": f"client-facts:{revision.state_digest}", "state_digest": revision.state_digest,
        "client_ref": revision.client_ref, "changed_fields": ["client_state"]}, occurred_at=occurred_at,
        actor_ref=actor_ref, summary="Review revised client facts")


def open_cases(runtime: EngineRuntime, *, vertical_id: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
    """The cases this runtime's store holds that are not terminal, as summaries; optionally one vertical."""

    out: list[dict[str, Any]] = []
    for record in runtime.store.list(engine=FINANCE_ADVICE_ENGINE, limit=limit):
        status = str(record.get("status") or "")
        if status in ("reviewed", "declined", "withdrawn"):
            continue
        entity_ref = str(record.get("entity_ref") or "")
        if not entity_ref:
            continue
        summary = case_summary(runtime, entity_ref)
        if vertical_id is None or summary.get("vertical_id") == vertical_id:
            out.append(summary)
    return out


def case_summary(runtime: EngineRuntime, entity_ref: str) -> dict[str, Any]:
    from lightbulb.finance_advice_engine import advice_case_summary

    return advice_case_summary(runtime.load(entity_ref))


FINANCE_ADVICE_CASES_MANIFEST: dict[str, Any] = {
    "kind": "lightbulb.finance_advice_cases.v1",
    "engine": FINANCE_ADVICE_ENGINE,
    "store": "sdk_engine_states (Spring) through HostedEngineStateStore; InMemoryEngineStateStore for tests",
    "hard_rules": [
        "every transition is replay-fenced by the persisted version and state digest",
        "the adviser's approval is a platform approval task bound to the exact recommendation; the decider is never the acting actor",
        "the case never moves to adviser_approved without a bound approval reference on the receipt",
        "nothing here advises; the lifecycle refuses what the plan does not allow",
    ],
}

__all__ = [
    "VERIFICATION_MAX_AGE_DAYS",
    "implement_case",
    "open_successor_case",
    "present_case",
    "review_case",
    "DEFAULT_CASE_RISK_LEVEL",
    "FINANCE_ADVICE_CASES_MANIFEST",
    "FINANCE_ADVICE_ENGINE",
    "advance_case",
    "advice_case_runtime",
    "case_summary",
    "open_cases",
    "apply_fact_change",
    "hosted_advice_case_runtime",
    "open_case",
    "request_adviser_approval",
    "resume_with_adviser_approval",
]
