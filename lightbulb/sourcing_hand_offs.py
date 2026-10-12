"""Sourcing hand-offs: the owner accepted "hire" or "contract", so draft the paperwork the hiring and contractor chains open from.

The labour sourcing document ranks the routes to close each skills gap and
the weekly review raises the chosen route as an action.  Once the owner
accepts it (through the review's decisions ledger), the next step used to be
retyping the same facts into a hiring requisition or a contractor brief.
``draft_sourcing_hand_offs`` does that step without doing anything else:

* an accepted ``hire`` (or an accepted requisition) becomes the hiring
  chain's own opening receipt, built by ``hiring_chain.headcount_receipt``
  from the role, heads and banded rate the sourcing document chose, with the
  decision's owner as requester;
* an accepted ``contract`` becomes a brief for the contractor chain: the
  skill and level, the rate ceiling and unit, the monthly cap and the end
  date, and the step the chain still needs (an agreement in force with a
  named contractor) before an engagement can open.

Nothing is opened, persisted or sent.  A decision that is deferred,
declined or not yet made produces no draft and is listed as waiting.  A
hire the hiring plan cannot fund yet (no band, or a budget envelope
required and not supplied) is drafted as blocked with the chain's own
reason, so the owner sees what to fix before opening it.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, OpaqueRef, Sha256Digest, ShortText, StrictModel, detached, seal, sealed_digest, skip_digests, timestamp

SOURCING_HAND_OFFS_SCHEMA = "lightbulb.sourcing_hand_offs.v1"
SOURCING_HAND_OFFS_MANIFEST: dict[str, Any] = {"engine": "sourcing_hand_offs", "kind": "intelligence_document", "reads": ("labour_sourcing", "review_decisions"), "writes": ()}
DraftStatus = Literal["drafted", "blocked"]
_PRESENTATION = frozenset({"summary", "provider_effect_executed", "documents_built", "version"})
_DONE = {"accept": "accepted", "defer": "deferred", "decline": "declined"}


class SourcingHandOffError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise SourcingHandOffError(code, message)


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


class HandOffDraft(StrictModel):
    key: ShortText
    route: Literal["hire", "contract", "requisition"]
    chain: Literal["hiring_chain", "contractor_chain"]
    status: DraftStatus
    subject: ShortText
    owner_ref: OpaqueRef | None = None
    due_at: str | None = None
    receipt: dict[str, Any] | None = None
    brief: dict[str, Any] | None = None
    next_step: ShortText


class SourcingHandOffs(StrictModel):
    schema_id: str = Field(default=SOURCING_HAND_OFFS_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    as_of: str
    sourcing_digest: Sha256Digest
    drafts: tuple[HandOffDraft, ...] = Field(default_factory=tuple, max_length=500)
    waiting: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=500)
    verdict: ShortText
    hand_offs_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("drafts", "waiting", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "SourcingHandOffs":
        if any((draft.receipt is None) == (draft.brief is None) and draft.status == "drafted" for draft in self.drafts):
            raise ValueError("a drafted hand-off carries a receipt or a brief, not both")
        if not skip_digests(info) and self.hand_offs_digest != sealed_digest(SourcingHandOffs, self, "hand_offs_digest"):
            raise ValueError("hand_offs_digest must commit the exact drafts")
        return self

    def render(self) -> str:
        lines = [f"**Sourcing hand-offs** ({self.company_ref}, {self.as_of[:10]}): {self.verdict}"]
        lines.extend(f"- {draft.route} {draft.subject}: {draft.status}; {draft.next_step}" for draft in self.drafts)
        return "\n".join(lines)


def _decisions(ledgers: Sequence[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    """The latest decision per action key across the supplied ledgers (each re-verified against its seal)."""

    from lightbulb.review_decisions import verify_review_decisions

    latest: dict[str, dict[str, Any]] = {}
    for raw in ledgers:
        ledger = verify_review_decisions({key: value for key, value in dict(detached(raw)).items() if key not in _PRESENTATION})
        for row in ledger.actions:
            item = row.to_dict()
            if item.get("decision") is None:
                continue
            current = latest.get(row.key)
            if current is None or str(item.get("decided_at") or "") >= str(current.get("decided_at") or ""):
                latest[row.key] = item
    return latest


def draft_sourcing_hand_offs(sourcing: Mapping[str, Any] | Any, *, decisions: Sequence[Mapping[str, Any]], as_of: str, hiring_plan: Mapping[str, Any] | None = None, budget_envelope: Mapping[str, Any] | None = None) -> SourcingHandOffs:
    """The hiring receipts and contractor briefs for every sourcing route the owner accepted; everything else is listed as waiting."""

    from lightbulb.labour_sourcing import verify_labour_sourcing
    from lightbulb.review_decisions import action_key

    doc = verify_labour_sourcing({key: value for key, value in dict(detached(sourcing)).items() if key not in _PRESENTATION})
    decided = _decisions(decisions)
    drafts: list[dict[str, Any]] = []
    waiting: list[str] = []

    def hire(key: str, subject: str, route: str, decision: dict[str, Any], request: Mapping[str, Any]) -> None:
        row = {"key": key, "route": route, "chain": "hiring_chain", "subject": subject, "owner_ref": decision.get("owner_ref"), "due_at": decision.get("due_at")}
        if hiring_plan is None:
            drafts.append({**row, "status": "blocked", "next_step": "add a hiring plan with a pay band for the role to the bundle, then draft again"})
            return
        from lightbulb.hiring_chain import headcount_receipt

        try:
            receipt = headcount_receipt(hiring_plan, role_ref=str(request["role_ref"]), headcount=int(request.get("headcount", 1)), pay_rate=request["pay_rate"], pay_rate_uom=str(request["pay_rate_uom"]), requester_ref=str(decision.get("owner_ref") or "owner"), envelope=budget_envelope)
        except ValueError as exc:
            drafts.append({**row, "status": "blocked", "next_step": f"the hiring chain refuses it as it stands: {str(exc)[:220]}"})
            return
        drafts.append({**row, "status": "drafted", "receipt": receipt, "next_step": "open it with company_hiring open, passing this receipt"})

    for action in doc.actions:
        if action.chosen not in ("hire", "contract"):
            continue
        subject = f"{action.job_ref} / {action.skill_ref}"
        key = action_key("labour_sourcing", f"source_{action.chosen}", subject)
        decision = decided.get(key)
        if decision is None or decision["decision"] != "accept":
            waiting.append(f"{action.chosen} {subject}: " + ("no decision yet" if decision is None else _DONE.get(str(decision["decision"]), str(decision["decision"]))))
            continue
        if action.chosen == "hire":
            hire(key, subject, "hire", decision, action.request)
            continue
        brief = {"skill_ref": action.skill_ref, "minimum_level": action.minimum_level, "hours": str(action.hours), "rate_ceiling": action.request.get("rate"), "rate_uom": action.request.get("rate_uom"), "monthly_cap": action.request.get("monthly_cap"), "engagement_end": action.request.get("engagement_end"), "job_ref": action.job_ref, "starts_at": action.starts_at}
        drafts.append({"key": key, "route": "contract", "chain": "contractor_chain", "status": "drafted", "subject": subject, "owner_ref": decision.get("owner_ref"), "due_at": decision.get("due_at"), "brief": brief, "next_step": f"agree terms with a contractor at no more than {brief['rate_ceiling']}/{brief['rate_uom']}, add them to the contractor plan's programs, then open the engagement with company_contractors"})
    for item in doc.requisitions:
        key = action_key("labour_sourcing", "open_requisition", item.role_ref)
        decision = decided.get(key)
        if decision is None or decision["decision"] != "accept":
            waiting.append(f"requisition {item.role_ref}: " + ("no decision yet" if decision is None else _DONE.get(str(decision["decision"]), str(decision["decision"]))))
            continue
        hire(key, item.role_ref, "requisition", decision, {"role_ref": item.role_ref, "headcount": item.headcount, "pay_rate": str(item.pay_rate), "pay_rate_uom": item.pay_rate_uom})
    ready = sum(1 for row in drafts if row["status"] == "drafted")
    blocked = len(drafts) - ready
    verdict = f"{ready} hand-off(s) ready to open" + (f", {blocked} blocked" if blocked else "") + f"; {len(waiting)} route(s) waiting on a decision"
    return seal(SourcingHandOffs, {"company_ref": doc.company_ref, "as_of": timestamp(as_of, field_name="as_of"), "sourcing_digest": doc.sourcing_digest, "drafts": [{key: value for key, value in row.items() if value is not None} for row in drafts], "waiting": [item[:300] for item in waiting], "verdict": verdict[:300]}, "hand_offs_digest")


def verify_sourcing_hand_offs(value: Any) -> SourcingHandOffs:
    return value if isinstance(value, SourcingHandOffs) else SourcingHandOffs.model_validate({key: item for key, item in dict(detached(value)).items() if key not in _PRESENTATION})


__all__ = ["SOURCING_HAND_OFFS_MANIFEST", "SOURCING_HAND_OFFS_SCHEMA", "HandOffDraft", "SourcingHandOffError", "SourcingHandOffs", "draft_sourcing_hand_offs", "verify_sourcing_hand_offs"]
