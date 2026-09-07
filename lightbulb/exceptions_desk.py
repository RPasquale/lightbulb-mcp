"""The exceptions desk: one lifecycle for everything the engines refuse, with evidence-driven resolution and an SLA per kind.

Refusals are the product, but they landed in five places: a revenue or
payables case in ``reconciliation_required``, an observer disposition of
``NON_UNIQUE`` / ``NON_EXHAUSTIVE`` / ``NOT_FOUND``, an ambiguous write
receipt, a tick action rejected with a fence code, a cash cover that fell
short.  ``open_exceptions`` collects them into exception cases:

    opened -> triaged -> evidence_requested -> resolved   (terminal)
    opened | triaged | evidence_requested -> escalated     (terminal)
    opened | triaged | evidence_requested -> expired       (terminal, SLA elapsed)

Each kind has a resolution path (which read or receipt resolves it) and an
SLA in hours.  ``resolution_receipt`` accepts only the evidence the path
names: a unique observation for a non-unique one, an exhaustive read for a
non-exhaustive one, a reconciliation receipt for an ambiguous write, a
covered cash cover for a shortfall, the engine's own accepting transition
for a rejected action.  ``desk_summary`` is what the operator sees: open
exceptions by kind, the ones past SLA, and the evidence each is waiting on.
Nothing here executes a read or a write.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import timedelta
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    BoundedText,
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
)

EXCEPTIONS_KIND = "exception_case"
EXCEPTIONS_GOLDEN_LOOP = "company.blueprint_to_governed_operating_cadence@0.1.0"
DESK_PLAN_SCHEMA = "lightbulb.exceptions_desk_plan.v1"
MAX_EXCEPTION_TRANSITIONS = 12

ExceptionKind = Literal["ambiguous_write", "non_unique_observation", "non_exhaustive_observation", "not_found_observation", "chain_reconciliation", "tick_rejection", "stale_read", "cash_shortfall", "overdue_obligation", "wind_down_blocked"]
EXCEPTION_KINDS: tuple[str, ...] = ("ambiguous_write", "non_unique_observation", "non_exhaustive_observation", "not_found_observation", "chain_reconciliation", "tick_rejection", "stale_read", "cash_shortfall", "overdue_obligation", "wind_down_blocked")
EXCEPTION_STATUSES: tuple[str, ...] = ("opened", "triaged", "evidence_requested", "resolved", "escalated", "expired")
TERMINAL_EXCEPTION_STATUSES: frozenset[str] = frozenset({"resolved", "escalated", "expired"})
EXCEPTION_EVENTS: tuple[str, ...] = ("open", "triage", "request_evidence", "resolve", "escalate", "expire")
_EXCEPTION_TABLE: dict[tuple[str, str], str] = {
    ("new", "open"): "opened",
    ("opened", "triage"): "triaged",
    ("triaged", "request_evidence"): "evidence_requested",
    ("opened", "resolve"): "resolved",
    ("triaged", "resolve"): "resolved",
    ("evidence_requested", "resolve"): "resolved",
    **{(status, "escalate"): "escalated" for status in ("opened", "triaged", "evidence_requested")},
    **{(status, "expire"): "expired" for status in ("opened", "triaged", "evidence_requested")},
}

# What resolves each kind, and the default SLA.
RESOLUTION_PATHS: dict[str, dict[str, Any]] = {
    "ambiguous_write": {"resolves_with": "reconciliation_receipt", "read": "the exact effect observer for the write's correlation", "sla_hours": 24, "severity": "high"},
    "non_unique_observation": {"resolves_with": "observation", "read": "the same observer after the duplicate provider document is voided or the correlation corrected", "sla_hours": 48, "severity": "high"},
    "non_exhaustive_observation": {"resolves_with": "observation", "read": "the same observer with the bound raised in a reviewed catalog change, or the document split", "sla_hours": 72, "severity": "medium"},
    "not_found_observation": {"resolves_with": "observation", "read": "the same observer after the write is confirmed applied, or a cancel of the case", "sla_hours": 48, "severity": "medium"},
    "chain_reconciliation": {"resolves_with": "chain_transition", "read": "the chain's own accepting transition after the underlying exception resolves", "sla_hours": 96, "severity": "high"},
    "tick_rejection": {"resolves_with": "engine_transition", "read": "the engine's accepting transition with a corrected receipt", "sla_hours": 24, "severity": "medium"},
    "stale_read": {"resolves_with": "observation", "read": "a fresh read completed after the state's last transition", "sla_hours": 12, "severity": "low"},
    "cash_shortfall": {"resolves_with": "cash_cover", "read": "a covered treasury cash cover after inflows arrive or the outflow is rescheduled", "sla_hours": 120, "severity": "high"},
    "overdue_obligation": {"resolves_with": "obligation_transition", "read": "the obligation lodged or paid", "sla_hours": 48, "severity": "high"},
    "wind_down_blocked": {"resolves_with": "engine_transition", "read": "the wind-down hop's accepting transition, once the chain that owns that money reaches its own terminal state", "sla_hours": 168, "severity": "high"},
}
Severity = Literal["low", "medium", "high"]


class ExceptionsDeskPlan(StrictModel):
    schema_id: str = Field(default=DESK_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    sla_hours: dict[str, int] = Field(default_factory=dict)
    escalate_to: ShortText = "founder"
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("sla_hours", mode="before")
    @classmethod
    def _slas(cls, value: Any) -> dict[str, int]:
        out = {str(key): int(item) for key, item in dict(value or {}).items()}
        for key, hours in out.items():
            if key not in RESOLUTION_PATHS or hours < 1 or hours > 2000:
                raise ValueError(f"sla_hours.{key} must name an exception kind with 1..2000 hours")
        return out

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> ExceptionsDeskPlan:
        if not skip_digests(info) and self.plan_digest != sealed_digest(ExceptionsDeskPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self

    def sla_for(self, kind: str) -> int:
        return self.sla_hours.get(kind, int(RESOLUTION_PATHS[kind]["sla_hours"]))


def compile_exceptions_desk(company_ref: str, *, overrides: Mapping[str, Any] | None = None) -> ExceptionsDeskPlan:
    return seal(ExceptionsDeskPlan, {"company_ref": company_ref, **dict(overrides or {})}, "plan_digest")


class ExceptionReceipt(StrictModel):
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    kind: ExceptionKind | None = None
    source_engine: ShortText | None = None
    source_ref: OpaqueRef | None = None
    source_digest: Sha256Digest | None = None
    code: ShortText | None = None
    detail: BoundedText | None = None
    severity: Severity | None = None
    owner_ref: OpaqueRef | None = None
    requested_read: BoundedText | None = None
    resolves_with: ShortText | None = None
    resolution_digest: Sha256Digest | None = None
    resolution_ref: OpaqueRef | None = None
    resolved_status: ShortText | None = None
    escalated_to: ShortText | None = None

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value


class ExceptionLedger(StrictModel):
    kind: str | None = None
    source_engine: str | None = None
    source_ref: str | None = None
    source_digest: str | None = None
    code: str | None = None
    detail: str | None = None
    severity: str | None = None
    opened_at: str | None = None
    sla_deadline: str | None = None
    owner_ref: str | None = None
    triaged_at: str | None = None
    requested_read: str | None = None
    evidence_requested_at: str | None = None
    resolution_digest: str | None = None
    resolution_ref: str | None = None
    resolved_at: str | None = None
    hours_to_resolve: int | None = None
    within_sla: bool | None = None
    escalated_to: str | None = None
    escalation_reason: str | None = None
    expiry_reason: str | None = None
    outcome: Literal["open", "resolved", "escalated", "expired"] = "open"


class ExceptionEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    provider_read: Literal[False] = False
    message_sent: Literal[False] = False


def _apply_exception(plan: ExceptionsDeskPlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event, at = command.receipt, command.event, command.occurred_at
    if event == "open":
        require(r.kind is not None and r.source_engine is not None and r.source_ref is not None and r.source_digest is not None and r.code is not None, "EXCEPTION_MISSING", "an exception names its kind, the source engine, the source reference, the source digest, and the code")
        path = RESOLUTION_PATHS[r.kind]
        deadline = (parsed(at) + timedelta(hours=plan.sla_for(r.kind))).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        data.update({"kind": r.kind, "source_engine": r.source_engine, "source_ref": r.source_ref, "source_digest": r.source_digest, "code": r.code, "detail": r.detail, "severity": r.severity or path["severity"], "opened_at": at, "sla_deadline": deadline})
    elif event == "triage":
        require(r.owner_ref is not None, "OWNER_MISSING", "triage names the owner")
        data.update({"owner_ref": r.owner_ref, "triaged_at": at, "severity": r.severity or data.get("severity")})
    elif event == "request_evidence":
        path = RESOLUTION_PATHS[str(data["kind"])]
        data.update({"requested_read": r.requested_read or path["read"], "evidence_requested_at": at})
    elif event == "resolve":
        path = RESOLUTION_PATHS[str(data["kind"])]
        require(r.resolves_with == path["resolves_with"], "RESOLUTION_KIND_MISMATCH", f"a {data['kind']} exception resolves with {path['resolves_with']}, not {r.resolves_with}", "correct_input")
        require(r.resolution_digest is not None and r.resolution_ref is not None, "RESOLUTION_MISSING", "a resolution carries the evidence digest and reference")
        require(r.resolution_digest != data.get("source_digest"), "RESOLUTION_IS_THE_SOURCE", "the evidence that opened the exception cannot resolve it")
        hours = int((parsed(at) - parsed(str(data["opened_at"]))).total_seconds() // 3600)
        data.update({"resolution_digest": r.resolution_digest, "resolution_ref": r.resolution_ref, "resolved_at": at, "hours_to_resolve": hours, "within_sla": parsed(at) <= parsed(str(data["sla_deadline"])), "outcome": "resolved"})
    elif event == "escalate":
        data.update({"escalated_to": r.escalated_to or plan.escalate_to, "escalation_reason": str(command.reason)[:300], "outcome": "escalated"})
    elif event == "expire":
        require(parsed(at) > parsed(str(data["sla_deadline"])), "SLA_NOT_ELAPSED", "the SLA has not elapsed; resolve or escalate instead")
        data.update({"expiry_reason": str(command.reason)[:300], "outcome": "expired"})
    return next_status, data


EXCEPTIONS_LIFECYCLE = LifecycleSpec(entity="exception_case", schema_prefix=EXCEPTIONS_KIND, statuses=EXCEPTION_STATUSES, terminal=TERMINAL_EXCEPTION_STATUSES, events=EXCEPTION_EVENTS, table=_EXCEPTION_TABLE, opening_event="open", reason_events=("escalate", "expire"), apply=_apply_exception, ledger_model=ExceptionLedger, receipt_model=ExceptionReceipt, effect_boundary_model=ExceptionEffectBoundary, plan_model=ExceptionsDeskPlan, max_transitions=MAX_EXCEPTION_TRANSITIONS)
ExceptionCaseState = EXCEPTIONS_LIFECYCLE.State


def open_exception(plan: ExceptionsDeskPlan | Mapping[str, Any], scope: Mapping[str, Any], *, receipt: Mapping[str, Any], opened_at: str, actor_ref: str) -> Any:
    return EXCEPTIONS_LIFECYCLE.open(plan, scope, opened_at=opened_at, actor_ref=actor_ref, receipt=receipt)


def advance_exception(plan: ExceptionsDeskPlan | Mapping[str, Any], state: Any, command: Any) -> Any:
    return EXCEPTIONS_LIFECYCLE.advance(plan, state, command)


# --------------------------------------------------------------------------- #
# Collecting exceptions from what the engines refused
# --------------------------------------------------------------------------- #


class ExceptionsDeskError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def exception_ref(kind: str, source_ref: str, source_digest: str) -> str:
    return f"exc:{kind}:{stable_digest({'source_ref': source_ref, 'source_digest': source_digest})[:16]}"


def _opening(kind: str, *, source_engine: str, source_ref: str, source_digest: str, code: str, detail: str, evidence_refs: Sequence[str] = ()) -> dict[str, Any]:
    return {"kind": kind, "source_engine": source_engine, "source_ref": source_ref, "source_digest": source_digest, "code": code, "detail": detail[:900], "evidence_refs": list(evidence_refs)[:50]}


def exceptions_from_tick(tick_result: Mapping[str, Any] | Any) -> list[dict[str, Any]]:
    """Opening receipts for every rejected action in a cadence tick result (fence codes the operator must resolve)."""

    raw = dict(detached(tick_result))
    out: list[dict[str, Any]] = []
    for item in raw.get("applied") or []:
        action = dict(detached(item))
        if action.get("outcome") != "rejected":
            continue
        code = str(action.get("rejection_code") or "REJECTED")
        kind = "stale_read" if code in ("STALE_STATE", "NON_CHRONOLOGICAL_TRANSITION") else "tick_rejection"
        out.append(_opening(kind, source_engine=str(action["engine"]), source_ref=f"{action['engine']}:{action['entity_ref']}:{action['action_id']}", source_digest=str(raw.get("result_digest") or stable_digest(action)), code=code, detail=str(action.get("detail") or f"{action['event']} rejected with {code}"), evidence_refs=[f"tick:{str(raw.get('result_digest') or '')[:16]}"]))
    return out


def exception_from_observation(observation: Mapping[str, Any] | Any, *, source_engine: str, source_ref: str) -> dict[str, Any] | None:
    """An opening receipt when an observer's disposition is not the applied one; ``None`` when the observation is clean."""

    raw = dict(detached(observation))
    disposition = str(raw.get("disposition") or "").upper()
    kind = {"NON_UNIQUE": "non_unique_observation", "NON_EXHAUSTIVE": "non_exhaustive_observation", "NOT_FOUND": "not_found_observation"}.get(disposition)
    if kind is None:
        return None
    digest = str(raw.get("evidence_sha256") or stable_digest(raw))
    return _opening(kind, source_engine=source_engine, source_ref=source_ref, source_digest=digest, code=disposition, detail=f"{raw.get('schema', 'observation')} returned {disposition}", evidence_refs=[f"observation:{digest[:16]}"])


def exception_from_write(write_receipt: Mapping[str, Any] | Any, *, source_engine: str, source_ref: str) -> dict[str, Any] | None:
    raw = dict(detached(write_receipt))
    state = str(raw.get("state") or raw.get("status") or "")
    if "ambiguous" not in state.lower():
        return None
    digest = str(raw.get("receipt_digest") or stable_digest(raw))
    return _opening("ambiguous_write", source_engine=source_engine, source_ref=source_ref, source_digest=digest, code=state.upper()[:60], detail=f"write journal {raw.get('write_journal_ref')} ended {state}; observe the exact effect before any redispatch", evidence_refs=[f"journal:{raw.get('write_journal_ref')}"])


def exception_from_chain(case_state: Any, *, engine: str) -> dict[str, Any] | None:
    if case_state.status != "reconciliation_required":
        return None
    reason = str(getattr(case_state.ledger, "reconciliation_reason", "") or "reconciliation required")
    return _opening("chain_reconciliation", source_engine=engine, source_ref=f"{engine}:{case_state.scope.entity_ref}", source_digest=case_state.state_digest, code="RECONCILIATION_REQUIRED", detail=reason, evidence_refs=[f"{engine}:{case_state.scope.entity_ref}:{case_state.state_digest[:16]}"])


def exception_from_cover(cover: Mapping[str, Any] | Any, *, source_ref: str) -> dict[str, Any] | None:
    raw = dict(detached(cover))
    if raw.get("schema") != "lightbulb.company_cash_cover.v1" or bool(raw.get("covered")):
        return None
    return _opening("cash_shortfall", source_engine="company_treasury", source_ref=source_ref, source_digest=str(raw["cover_digest"]), code="CASH_NOT_COVERED", detail=str(raw.get("detail") or "shortfall"), evidence_refs=[f"cover:{str(raw['cover_digest'])[:16]}"])


def exception_from_obligation(obligation_state: Any) -> dict[str, Any] | None:
    if obligation_state.status != "overdue":
        return None
    ledger = obligation_state.ledger
    return _opening("overdue_obligation", source_engine="compliance_obligation", source_ref=f"compliance_obligation:{obligation_state.scope.entity_ref}", source_digest=obligation_state.state_digest, code="OBLIGATION_OVERDUE", detail=f"{ledger.kind} due {ledger.due_at} is {ledger.days_late} day(s) late", evidence_refs=[f"obligation:{obligation_state.scope.entity_ref}"])


def resolution_receipt(kind: str, evidence: Mapping[str, Any] | Any, *, resolution_ref: str | None = None) -> dict[str, Any]:
    """The ``resolve`` receipt from the evidence the kind's path names; anything else is refused."""

    if kind not in RESOLUTION_PATHS:
        raise ExceptionsDeskError("EXCEPTION_KIND_UNKNOWN", f"{kind} is not an exception kind")
    path = RESOLUTION_PATHS[kind]
    raw = dict(detached(evidence)) if isinstance(evidence, Mapping) else {}
    resolves_with = str(path["resolves_with"])
    if resolves_with == "observation":
        disposition = str(raw.get("disposition") or "").upper()
        if kind == "non_exhaustive_observation" and not bool(raw.get("exhaustive_read")):
            raise ExceptionsDeskError("RESOLUTION_NOT_EXHAUSTIVE", "the observation is still not exhaustive")
        if kind == "non_unique_observation" and (raw.get("unique_match") is False or disposition == "NON_UNIQUE"):
            raise ExceptionsDeskError("RESOLUTION_NOT_UNIQUE", "the observation is still not unique")
        if disposition not in ("APPLIED", "SETTLED"):
            raise ExceptionsDeskError("RESOLUTION_NOT_APPLIED", f"the observation is {disposition or 'missing'}; only APPLIED or SETTLED resolves a {kind}")
        digest, ref = str(raw.get("evidence_sha256") or stable_digest(raw)), resolution_ref or f"observation:{str(raw.get('evidence_sha256') or stable_digest(raw))[:16]}"
    elif resolves_with == "reconciliation_receipt":
        if str(raw.get("disposition") or "").upper() not in ("APPLIED", "NOT_APPLIED"):
            raise ExceptionsDeskError("RECONCILIATION_UNDECIDED", "a reconciliation receipt carries an APPLIED or NOT_APPLIED disposition")
        digest, ref = str(raw.get("receipt_sha256") or raw.get("reconciliation_receipt_sha256") or stable_digest(raw)), resolution_ref or f"reconciliation:{raw.get('journal_id') or raw.get('journal_ref')}"
    elif resolves_with == "cash_cover":
        if raw.get("schema") != "lightbulb.company_cash_cover.v1" or not bool(raw.get("covered")):
            raise ExceptionsDeskError("RESOLUTION_NOT_COVERED", "only a covered cash cover resolves a shortfall")
        digest, ref = str(raw["cover_digest"]), resolution_ref or f"cover:{str(raw['cover_digest'])[:16]}"
    else:  # engine_transition | chain_transition | obligation_transition: the accepting transition's state
        state = evidence
        status = getattr(state, "status", None) or raw.get("status")
        digest = getattr(state, "state_digest", None) or raw.get("state_digest")
        if not status or not digest:
            raise ExceptionsDeskError("RESOLUTION_STATE_MISSING", "the accepting transition's state (status and state_digest) resolves this exception")
        if str(status) in ("reconciliation_required", "overdue"):
            raise ExceptionsDeskError("RESOLUTION_STATE_UNCHANGED", f"the state is still {status}")
        ref = resolution_ref or f"state:{str(digest)[:16]}"
        return {"resolves_with": resolves_with, "resolution_digest": str(digest), "resolution_ref": ref, "resolved_status": str(status), "evidence_refs": [ref]}
    return {"resolves_with": resolves_with, "resolution_digest": digest, "resolution_ref": ref, "evidence_refs": [ref]}


def desk_summary(plan: ExceptionsDeskPlan | Mapping[str, Any], states: Sequence[Any], *, now: str) -> dict[str, Any]:
    parsed_plan = ExceptionsDeskPlan.model_validate(detached(plan))
    stamp = parsed(timestamp(now, field_name="now"))
    open_cases = [state for state in states if state.status not in TERMINAL_EXCEPTION_STATUSES]
    past_sla = [state for state in open_cases if parsed(str(state.ledger.sla_deadline)) < stamp]
    by_kind = {kind: sum(1 for state in open_cases if state.ledger.kind == kind) for kind in EXCEPTION_KINDS if any(state.ledger.kind == kind for state in open_cases)}
    resolved = [state for state in states if state.status == "resolved"]
    within = sum(1 for state in resolved if state.ledger.within_sla)
    rows = [{"case_ref": str(state.scope.entity_ref), "kind": state.ledger.kind, "status": state.status, "severity": state.ledger.severity, "code": state.ledger.code, "source_ref": state.ledger.source_ref, "sla_deadline": state.ledger.sla_deadline, "past_sla": parsed(str(state.ledger.sla_deadline)) < stamp, "waiting_on": state.ledger.requested_read or RESOLUTION_PATHS[str(state.ledger.kind)]["read"], "owner_ref": state.ledger.owner_ref} for state in sorted(open_cases, key=lambda item: (str(item.ledger.sla_deadline), str(item.scope.entity_ref)))]
    return {"company_ref": parsed_plan.company_ref, "as_of": now, "open": len(open_cases), "past_sla": len(past_sla), "by_kind": by_kind, "resolved": len(resolved), "resolved_within_sla": within, "escalated": sum(1 for state in states if state.status == "escalated"), "expired": sum(1 for state in states if state.status == "expired"), "cases": rows, "summary_digest": stable_digest(rows)}


EXCEPTIONS_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": EXCEPTIONS_KIND,
    "golden_loop": EXCEPTIONS_GOLDEN_LOOP,
    "stages": ["open", "triage", "request_evidence", "resolve"],
    "statuses": list(EXCEPTION_STATUSES),
    "events": list(EXCEPTION_EVENTS),
    "kinds": {kind: dict(path) for kind, path in RESOLUTION_PATHS.items()},
    "required_connectors": ["lightbulb.sdk_engine_state"],
    "hard_rules": [
        "an exception is opened from what an engine, observer, write receipt, cover, or obligation actually returned; nothing is typed",
        "each kind resolves only with the evidence its path names, and never with the evidence that opened it",
        "an exception past its SLA can expire or escalate, never quietly close",
    ],
}

__all__ = ["EXCEPTION_EVENTS", "EXCEPTION_KINDS", "EXCEPTION_STATUSES", "EXCEPTIONS_GOLDEN_LOOP", "EXCEPTIONS_KIND", "EXCEPTIONS_LIFECYCLE", "EXCEPTIONS_MANIFEST", "RESOLUTION_PATHS", "ExceptionCaseState", "ExceptionsDeskError", "ExceptionsDeskPlan", "advance_exception", "compile_exceptions_desk", "desk_summary", "exception_from_chain", "exception_from_cover", "exception_from_obligation", "exception_from_observation", "exception_from_write", "exception_ref", "exceptions_from_tick", "open_exception", "resolution_receipt"]
