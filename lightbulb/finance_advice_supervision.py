"""The supervisor's evidence file and append-only complaint chronology.

The SDK records document commitments and deterministic follow-up dates. It neither sends a
response nor declares legal compliance, resolves a complaint, or approves the adviser's work.
Spring owns scoped custody, actor permissions and any consequential action.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import date, timedelta
from typing import Any, Literal

from pydantic import Field, ValidationInfo, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, OpaqueRef, Sha256Digest, detached, parsed, seal, sealed_digest, skip_digests, timestamp
from lightbulb.finance_advice_identity import AdviceIdentityModel as StrictModel
from lightbulb.finance_advice_compliance import ComplianceChecklist
from lightbulb.finance_advice_record import RecordOfAdviceEvidence

COMPLAINT_SCHEMA = "lightbulb.finance_advice_complaint_file.v1"
COMPLAINT_EVENT_SCHEMA = "lightbulb.finance_advice_complaint_event.v1"
SUPERVISION_SCHEMA = "lightbulb.finance_advice_supervision_file.v1"
ComplaintRegime = Literal["au_standard", "au_super_trustee", "au_specialist", "ca_investment", "ca_banking", "ca_other"]
ComplaintEventKind = Literal["received", "acknowledged", "response_issued", "escalated", "resolved", "reopened"]

# These are reference dates for human follow-up, not autonomous legal determinations.
# The operator must establish that the selected regime applies to the actual respondent.
COMPLAINT_RULES = {
    "au_standard": {"jurisdiction": "AU", "response_days": 30, "source_url": "https://download.asic.gov.au/media/3olo5aq5/rg271-published-2-september-2021.pdf", "effective_from": "2021-10-05", "reviewed_at": "2026-09-07", "basis": "RG 271 standard complaints; special credit, death-benefit and other exceptions require specialist assessment."},
    "au_super_trustee": {"jurisdiction": "AU", "response_days": 45, "source_url": "https://download.asic.gov.au/media/3olo5aq5/rg271-published-2-september-2021.pdf", "effective_from": "2021-10-05", "reviewed_at": "2026-09-07", "basis": "Superannuation trustee complaints excluding death-benefit distributions; not every complaint about super advice is a trustee complaint."},
    "ca_investment": {"jurisdiction": "CA", "response_days": 90, "quebec_response_days": 60, "escalation_days_after_response": 180, "source_url": "https://www.ciro.ca/office-investor/how-make-complaint/seeking-financial-compensation", "effective_from": "2025-07-01", "reviewed_at": "2026-09-07", "basis": "CIRO investment firms: Quebec ordinarily 60 days, other provinces 90; extensions and eligibility require review. OBSI referral is generally within 180 days of the firm's response."},
    "ca_banking": {"jurisdiction": "CA", "response_days": 56, "escalation_days_after_response": 180, "source_url": "https://www.obsi.ca/en/for-firms/what-to-expect-for-firms/", "effective_from": "2024-11-01", "reviewed_at": "2026-09-07", "basis": "Banks and federal credit unions: 56 days before OBSI escalation; provincial credit unions and other respondents require their own regime assessment."},
}


class AdviceSupervisionError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


class ComplaintEvent(StrictModel):
    schema_id: Literal["lightbulb.finance_advice_complaint_event.v1"] = COMPLAINT_EVENT_SCHEMA
    complaint_ref: OpaqueRef
    case_ref: OpaqueRef
    event_ref: OpaqueRef
    sequence: int = Field(ge=1, le=200)
    kind: ComplaintEventKind
    actor_ref: OpaqueRef
    occurred_at: str
    evidence_sha256: Sha256Digest
    previous_event_digest: Sha256Digest = GENESIS_DIGEST
    event_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _seal(self, info: ValidationInfo) -> ComplaintEvent:
        timestamp(self.occurred_at, field_name="occurred_at")
        if not skip_digests(info) and self.event_digest != sealed_digest(ComplaintEvent, self, "event_digest"):
            raise ValueError("event_digest does not match the complaint event")
        return self


def _event_chain(events: Sequence[ComplaintEvent], complaint_ref: str, case_ref: str) -> str:
    previous, last_at, state = GENESIS_DIGEST, None, "open"
    seen = set()
    for index, event in enumerate(events, 1):
        if event.case_ref != case_ref or event.complaint_ref != complaint_ref or event.sequence != index or event.previous_event_digest != previous:
            raise ValueError("complaint events must form one contiguous chain in the exact case")
        if event.event_ref in seen or (last_at is not None and parsed(event.occurred_at) < last_at):
            raise ValueError("complaint event identities are unique and event times cannot go backwards")
        if (index == 1) != (event.kind == "received"):
            raise ValueError("the first and only received event opens the complaint")
        if state == "resolved" and event.kind != "reopened":
            raise ValueError("a resolved complaint must be reopened before another event")
        if event.kind == "reopened" and state != "resolved":
            raise ValueError("only a resolved complaint can be reopened")
        state = "resolved" if event.kind == "resolved" else ("open" if event.kind == "reopened" else state)
        seen.add(event.event_ref)
        previous, last_at = event.event_digest, parsed(event.occurred_at)
    return state


class ComplaintFile(StrictModel):
    schema_id: Literal["lightbulb.finance_advice_complaint_file.v1"] = COMPLAINT_SCHEMA
    complaint_ref: OpaqueRef
    case_ref: OpaqueRef
    record_digest: Sha256Digest
    jurisdiction: Literal["AU", "CA"]
    regime: ComplaintRegime
    region: str | None = None
    status: Literal["open", "resolved"]
    category: Literal["advice", "fees", "service", "privacy", "implementation", "other"]
    events: tuple[ComplaintEvent, ...] = Field(min_length=1, max_length=200)
    complaint_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _seal(self, info: ValidationInfo) -> ComplaintFile:
        if not self.regime.startswith(self.jurisdiction.lower() + "_"):
            raise ValueError("the complaint regime must match the jurisdiction")
        if self.status != _event_chain(self.events, self.complaint_ref, self.case_ref):
            raise ValueError("complaint status must match its event history")
        if not skip_digests(info) and self.complaint_digest != sealed_digest(ComplaintFile, self, "complaint_digest"):
            raise ValueError("complaint_digest does not match the complaint file")
        return self


def open_complaint(*, complaint_ref: str, case_ref: str, record: RecordOfAdviceEvidence | Mapping[str, Any], regime: ComplaintRegime, category: str, actor_ref: str, received_at: str, evidence_sha256: str, event_ref: str, region: str | None = None) -> ComplaintFile:
    r = RecordOfAdviceEvidence.model_validate(dict(detached(record)))
    stamp = timestamp(received_at, field_name="received_at")
    if parsed(stamp) < parsed(r.prepared_at):
        raise AdviceSupervisionError("COMPLAINT_BEFORE_RECORD", "the complaint cannot precede the record it cites")
    event = seal(ComplaintEvent, {"complaint_ref": complaint_ref, "case_ref": case_ref, "event_ref": event_ref, "sequence": 1, "kind": "received", "actor_ref": actor_ref, "occurred_at": stamp, "evidence_sha256": evidence_sha256}, "event_digest")
    return seal(ComplaintFile, {"complaint_ref": complaint_ref, "case_ref": case_ref, "record_digest": r.record_digest, "jurisdiction": r.jurisdiction, "regime": regime, "region": region.upper() if region else None, "category": category, "status": "open", "events": [event]}, "complaint_digest")


def append_complaint_event(complaint: ComplaintFile | Mapping[str, Any], *, event_ref: str, kind: ComplaintEventKind, actor_ref: str, occurred_at: str, evidence_sha256: str) -> ComplaintFile:
    c = ComplaintFile.model_validate(dict(detached(complaint)))
    stamp = timestamp(occurred_at, field_name="occurred_at")
    existing = next((event for event in c.events if event.event_ref == event_ref), None)
    if existing:
        if (existing.kind, existing.actor_ref, existing.occurred_at, existing.evidence_sha256) != (kind, actor_ref, stamp, evidence_sha256):
            raise AdviceSupervisionError("COMPLAINT_EVENT_REPLAY_CONFLICT", "the event reference was already used for different evidence")
        return c
    event = seal(ComplaintEvent, {"complaint_ref": c.complaint_ref, "case_ref": c.case_ref, "event_ref": event_ref, "sequence": len(c.events) + 1, "kind": kind, "actor_ref": actor_ref, "occurred_at": stamp, "evidence_sha256": evidence_sha256, "previous_event_digest": c.events[-1].event_digest}, "event_digest")
    raw = c.to_dict()
    raw.update(events=[*c.events, event], status="resolved" if kind == "resolved" else ("open" if kind == "reopened" else c.status))
    raw.pop("complaint_digest")
    return seal(ComplaintFile, raw, "complaint_digest")


def complaint_follow_up(complaint: ComplaintFile | Mapping[str, Any], *, as_of: str) -> dict[str, Any]:
    c = ComplaintFile.model_validate(dict(detached(complaint)))
    stamp = timestamp(as_of, field_name="as_of")
    if parsed(stamp) < parsed(c.events[-1].occurred_at):
        raise AdviceSupervisionError("COMPLAINT_FUTURE_EVENT", "the chronology includes an event after this assessment")
    rule = COMPLAINT_RULES.get(c.regime)
    days = rule["response_days"] if rule else None
    if c.regime == "ca_investment":
        days = None if c.region is None else (rule["quebec_response_days"] if c.region == "QC" else days)
    if rule and c.events[0].occurred_at[:10] < rule["effective_from"]:
        days = None
    received = date.fromisoformat(c.events[0].occurred_at[:10])
    due = received + timedelta(days=days) if days is not None else None
    response = next((event for event in c.events if event.kind == "response_issued"), None)
    escalation = date.fromisoformat(response.occurred_at[:10]) + timedelta(days=rule["escalation_days_after_response"]) if response and rule and rule.get("escalation_days_after_response") else None
    return {"complaint_ref": c.complaint_ref, "complaint_digest": c.complaint_digest, "status": c.status, "response_due_on": due.isoformat() if due else None, "response_recorded": response is not None, "response_overdue": bool(due and response is None and date.fromisoformat(stamp[:10]) > due), "response_was_late": bool(due and response and response.occurred_at[:10] > due.isoformat()), "external_referral_due_on": escalation.isoformat() if escalation else None, "rule": {**rule, "confirmed": False} if rule else None, "needs_regime_review": days is None, "basis": "Calendar follow-up only, not a legal deadline determination. The day of receipt is excluded. Exceptions, extensions, reopened complaints and local date boundaries require a human review; the original deadline is never reset."}


class SupervisionItem(StrictModel):
    key: str
    status: Literal["evidenced", "missing", "human_review"]
    evidence: tuple[str, ...] = ()
    action: str


class SupervisionFile(StrictModel):
    schema_id: Literal["lightbulb.finance_advice_supervision_file.v1"] = SUPERVISION_SCHEMA
    case_ref: OpaqueRef
    jurisdiction: Literal["AU", "CA"]
    stage: str
    record_digest: Sha256Digest
    checklist_digest: Sha256Digest
    items: tuple[SupervisionItem, ...]
    complaints: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=100)
    status: Literal["requires_attention", "ready_for_supervisor"]
    disclaimer: str = "Evidence for a human supervisor; no regulatory determination, supervisor approval or complaint resolution is issued by the SDK."
    as_of: str
    supervision_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _seal(self, info: ValidationInfo) -> SupervisionFile:
        expected = "requires_attention" if any(item.status == "missing" for item in self.items) else "ready_for_supervisor"
        if self.status != expected:
            raise ValueError("supervision status must agree with the evidence items")
        if not skip_digests(info) and self.supervision_digest != sealed_digest(SupervisionFile, self, "supervision_digest"):
            raise ValueError("supervision_digest does not match the supervision file")
        return self


def supervision_file(*, case_ref: str, record: RecordOfAdviceEvidence | Mapping[str, Any], checklist: ComplianceChecklist | Mapping[str, Any], stage: str, complaints: Sequence[ComplaintFile | Mapping[str, Any]] = (), as_of: str) -> SupervisionFile:
    r = RecordOfAdviceEvidence.model_validate(dict(detached(record)))
    c = ComplianceChecklist.model_validate(dict(detached(checklist)))
    stamp = timestamp(as_of, field_name="as_of")
    if (r.plan_digest, r.state_digest, r.recommendation_digest) != (c.plan_digest, c.state_digest, c.recommendation_digest):
        raise AdviceSupervisionError("SUPERVISION_EVIDENCE_MISMATCH", "the record and checklist must describe the same plan, state and recommendation")
    if c.record_digest != r.record_digest and r.approval.get("checklist_digest") != c.checklist_digest:
        raise AdviceSupervisionError("SUPERVISION_RECORD_MISMATCH", "a superseding approved record must name the original checklist")
    if parsed(stamp) < max(parsed(r.prepared_at), parsed(c.as_of)):
        raise AdviceSupervisionError("SUPERVISION_FUTURE_EVIDENCE", "the assessment cannot precede the evidence")
    items = [SupervisionItem(key="checklist:" + item.key, status="missing" if item.status == "missing" else ("human_review" if item.status == "adviser_confirms" else "evidenced"), evidence=(c.checklist_digest, *item.evidence), action=item.adviser_action or item.basis) for item in c.items]
    items.append(SupervisionItem(key="licensed_adviser_approval", status="evidenced" if r.approval else "missing", evidence=(r.record_digest,), action="Confirm the platform's licensed-human approval and separation of duties for this recommendation before presentation."))
    for kind in ("tax", "retirement"):
        view = r.strategy.get(kind)
        if view:
            problems = list(view.get("missing") or ())
            if kind == "retirement":
                problems.extend(item["scheme"] + " exceeds disclosed contribution room" for item in view.get("contribution_checks") or () if item.get("status") == "exceeds_disclosed_room")
            items.append(SupervisionItem(key=kind + "_assumptions", status="missing" if problems else "human_review", evidence=(view[kind + "_digest"],), action="; ".join(problems) if problems else "Confirm the scenario assumptions, rule dates, limitations and individual eligibility; this illustration is not a tax or retirement determination."))
    follow_ups = []
    seen = set()
    for raw in complaints:
        complaint = ComplaintFile.model_validate(dict(detached(raw)))
        if complaint.case_ref != case_ref or complaint.jurisdiction != r.jurisdiction or complaint.record_digest not in {r.record_digest, c.record_digest}:
            raise AdviceSupervisionError("COMPLAINT_CASE_MISMATCH", "complaint evidence must belong to this case and its retained record")
        if complaint.complaint_ref in seen:
            raise AdviceSupervisionError("COMPLAINT_DUPLICATE", "provide one latest chronology for each complaint")
        seen.add(complaint.complaint_ref)
        follow = complaint_follow_up(complaint, as_of=stamp)
        follow_ups.append(follow)
        items.append(SupervisionItem(key="complaint:" + complaint.complaint_ref, status="missing" if complaint.status == "open" or follow["needs_regime_review"] else "human_review", evidence=(complaint.complaint_digest,), action="Review the complaint chronology, response evidence and external escalation rights; never treat recorded resolution as an SDK decision."))
    return seal(SupervisionFile, {"case_ref": case_ref, "jurisdiction": r.jurisdiction, "stage": stage, "record_digest": r.record_digest, "checklist_digest": c.checklist_digest, "items": items, "complaints": follow_ups, "status": "requires_attention" if any(item.status == "missing" for item in items) else "ready_for_supervisor", "as_of": stamp}, "supervision_digest")


SUPERVISION_MANIFEST = {"schemas": {"supervision": SUPERVISION_SCHEMA, "complaint": COMPLAINT_SCHEMA, "event": COMPLAINT_EVENT_SCHEMA}, "authority": "SDK evidence preview; Spring owns scoped custody, human permissions, approvals and communications", "privacy": "opaque references and source-document commitments; no complaint narrative or client identity", "complaints": "append-only digest chain, exact retries idempotent, changed retries refused, original follow-up date retained"}

__all__ = ["AdviceSupervisionError", "COMPLAINT_EVENT_SCHEMA", "COMPLAINT_RULES", "COMPLAINT_SCHEMA", "SUPERVISION_MANIFEST", "SUPERVISION_SCHEMA", "ComplaintEvent", "ComplaintFile", "SupervisionFile", "SupervisionItem", "append_complaint_event", "complaint_follow_up", "open_complaint", "supervision_file"]
