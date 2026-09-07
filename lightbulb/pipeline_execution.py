"""Pipeline engine closed loop: platform results into prospect receipts, and the next touch as an exact request.

The prospect lifecycle already has every event an outbound motion needs;
what it lacked was the glue between the platform's results and its receipts:

* ``reply_receipt`` turns a ``communication.classify_reply`` output (or the
  ``crm_classify_reply`` agent output) into the ``reply`` receipt through an
  explicit intent-to-disposition table; an intent the table does not name is
  refused, never guessed, and low-confidence or review-flagged
  classifications are refused until a person confirms.
* ``enrichment_receipt`` turns a ``crm_enrich_contact`` result plus a named
  suppression check into the ``enrich`` receipt (``no_contact_found`` and
  ``rejected`` yield nothing).
* ``meeting_receipt`` turns a ``crm_book_meeting`` result into the
  ``book_meeting`` receipt only when the platform reports ``booked``.
* ``ConsentRegistry`` is a compatibility/simulation policy for plans that
  explicitly disable ``require_permission_register``; it does not prove
  eligible outreach. New plans require replayed register eligibility.
  ``touch_receipt`` binds the platform's write execution receipt (approval
  carried) to the ``touch`` event through the existing execution bridge.
* ``plan_next_touch`` reads the prospect state and its sequence plan and
  returns the exact ``ConnectorExecutionRequest`` the platform must execute
  for the next step (Gmail today), with the idempotency key derived from the
  prospect, sequence, and step so a retry can never send twice.

Nothing here sends, books, or enriches; the platform executes the request
behind approval and the receipt comes back through ``touch_receipt``.
The host supplies the complete current scoped prospect inventory for channel
caps and atomically persists/reserves sends in one shared store. Independent
stores or incomplete inventories cannot establish a company-wide send cap.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import timedelta
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    BoundedText,
    OpaqueRef,
    Sha256Digest,
    ShortText,
    StrictModel,
    detached,
    parsed,
    seal,
    sealed_digest,
    skip_digests,
    stable_digest,
    timestamp,
    unique,
)
from lightbulb.company_execution_bridge import BoundExecution, ExecutionReceipt, bind_execution
from lightbulb.pipeline_engine_loop import CONSENT_CHANNELS, PipelineEngineLoopPlan, SequencePlan

CONSENT_REGISTRY_SCHEMA = "lightbulb.pipeline_consent_registry.v1"
TOUCH_REQUEST_SCHEMA = "lightbulb.pipeline_touch_request.v1"
Disposition = Literal["positive", "objection", "not_now", "negative", "out_of_office", "wrong_person"]

# Explicit table: classifier intents that map to a reply disposition. Anything
# else is refused so a new label can never silently become a lost deal.
INTENT_DISPOSITIONS: Mapping[str, Disposition] = {
    "interested": "positive",
    "positive": "positive",
    "meeting_request": "positive",
    "meeting_intent": "positive",
    "book_meeting": "positive",
    "question": "objection",
    "objection": "objection",
    "pricing_objection": "objection",
    "timing": "not_now",
    "not_now": "not_now",
    "later": "not_now",
    "follow_up_later": "not_now",
    "not_interested": "negative",
    "negative": "negative",
    "unsubscribe": "negative",
    "opt_out": "negative",
    "out_of_office": "out_of_office",
    "auto_reply": "out_of_office",
    "wrong_person": "wrong_person",
    "referral": "wrong_person",
    "left_company": "wrong_person",
}
MIN_CONFIDENCE = 0.6


class PipelineExecutionError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise PipelineExecutionError(code, message)


# --------------------------------------------------------------------------- #
# Results -> receipts
# --------------------------------------------------------------------------- #


def reply_receipt(classification: Mapping[str, Any], *, reply_ref: str, min_confidence: float = MIN_CONFIDENCE, human_confirmed: bool = False) -> dict[str, Any]:
    """The ``reply`` receipt from a classifier output; refuses unknown intents, low confidence, or unreviewed flags."""

    raw = dict(detached(classification))
    intent = str(raw.get("intent") or raw.get("classification") or "").strip().lower()
    _require(bool(intent), "REPLY_INTENT_MISSING", "the classification names an intent")
    disposition = INTENT_DISPOSITIONS.get(intent)
    _require(disposition is not None, "REPLY_INTENT_UNMAPPED", f"intent {intent!r} has no disposition in INTENT_DISPOSITIONS; add it deliberately")
    confidence = raw.get("confidence")
    if confidence is not None and not human_confirmed:
        _require(float(confidence) >= min_confidence, "REPLY_CONFIDENCE_LOW", f"confidence {confidence} is below {min_confidence}; a person confirms the disposition")
    if bool(raw.get("needs_human_review")) and not human_confirmed:
        raise PipelineExecutionError("REPLY_NEEDS_REVIEW", "the classifier asked for human review; confirm before recording the reply")
    engagement_ref = str(raw.get("classification_ref") or raw.get("route_event") or f"classified:{stable_digest({'reply': reply_ref, 'intent': intent})[:16]}")
    return {"reply_ref": reply_ref, "disposition": disposition, "engagement_ref": engagement_ref, "evidence_refs": [f"classification:{reply_ref}"]}


def enrichment_receipt(result: Mapping[str, Any], *, suppression_check_ref: str, trace_ref: str | None = None) -> dict[str, Any]:
    """The ``enrich`` receipt from a ``crm_enrich_contact`` result; only an enriched contact yields one."""

    raw = dict(detached(result))
    status = str(raw.get("status") or "").lower()
    _require(status == "enriched", "ENRICHMENT_NOT_FOUND", f"enrichment status is {status or 'missing'}; nothing to record")
    contact = raw.get("contact") if isinstance(raw.get("contact"), Mapping) else {}
    ref = str(contact.get("id") or raw.get("enrichment_ref") or "")
    _require(bool(ref), "ENRICHMENT_REF_MISSING", "the enriched contact names its provider id")
    _require(bool(suppression_check_ref.strip()), "SUPPRESSION_CHECK_MISSING", "an enrichment names the suppression check that cleared it")
    evidence = [f"enrichment:{ref}"] + ([f"trace:{trace_ref}"] if trace_ref else [])
    return {"enrichment_ref": f"enrichment:{ref}", "suppression_check_ref": suppression_check_ref, "evidence_refs": evidence}


def meeting_receipt(result: Mapping[str, Any]) -> dict[str, Any]:
    """The ``book_meeting`` receipt from a ``crm_book_meeting`` result; only ``booked`` counts."""

    raw = dict(detached(result))
    status = str(raw.get("status") or "").lower()
    _require(status in ("booked", "rescheduled"), "MEETING_NOT_BOOKED", f"booking status is {status or 'missing'}")
    event = raw.get("event") if isinstance(raw.get("event"), Mapping) else {}
    ref = str(event.get("id") or "")
    start = str(event.get("start") or "")
    _require(bool(ref) and bool(start), "MEETING_EVENT_MISSING", "the booked event names its id and start")
    provider = str(raw.get("provider") or event.get("provider") or "calendar")
    return {"meeting_ref": f"{provider}:{ref}", "meeting_at": timestamp(start if start.endswith("Z") or "+" in start[10:] else start + "Z", field_name="meeting_at"), "evidence_refs": [f"calendar:{ref}"]}


# --------------------------------------------------------------------------- #
# Consent
# --------------------------------------------------------------------------- #


class ConsentEntry(StrictModel):
    prospect_ref: OpaqueRef
    channel: Literal["voice", "sms", "email", "linkedin"]
    consent_ref: OpaqueRef
    source: ShortText
    granted_at: str
    expires_at: str | None = None

    @field_validator("granted_at", "expires_at")
    @classmethod
    def _stamps(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))


class ConsentRegistry(StrictModel):
    """Sealed, dated consents; the only source a voice or SMS touch may cite."""

    schema_id: str = Field(default=CONSENT_REGISTRY_SCHEMA, alias="schema")
    entries: tuple[ConsentEntry, ...] = Field(default_factory=tuple, max_length=5000)
    registry_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("entries", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> ConsentRegistry:
        unique([item.consent_ref for item in self.entries], label="consent refs")
        if not skip_digests(info) and self.registry_digest != sealed_digest(ConsentRegistry, self, "registry_digest"):
            raise ValueError("registry_digest must commit the exact registry")
        return self

    def consent_for(self, prospect_ref: str, channel: str, *, at: str) -> ConsentEntry | None:
        when = parsed(timestamp(at, field_name="at"))
        for entry in self.entries:
            if entry.prospect_ref == prospect_ref and entry.channel == channel and parsed(entry.granted_at) <= when and (entry.expires_at is None or parsed(entry.expires_at) > when):
                return entry
        return None


def consent_registry(entries: Sequence[Mapping[str, Any]]) -> ConsentRegistry:
    return seal(ConsentRegistry, {"entries": [dict(detached(item)) for item in entries]}, "registry_digest")


# --------------------------------------------------------------------------- #
# Next touch as an exact request
# --------------------------------------------------------------------------- #

_CHANNEL_TOOLS: Mapping[str, str] = {"email": "gmail.send_email", "linkedin": "linkedin.send_message", "sms": "twilio.send_sms_turn", "voice": "twilio.place_call_turn"}


class TouchRequest(StrictModel):
    """The exact platform write for one sequence step, with the fields the ``touch`` receipt will carry."""

    schema_id: str = Field(default=TOUCH_REQUEST_SCHEMA, alias="schema")
    prospect_ref: OpaqueRef
    sequence_ref: OpaqueRef
    step: int = Field(ge=1, le=20)
    channel: Literal["email", "linkedin", "voice", "sms"]
    intent: Literal["introduce", "value", "proof", "ask", "breakup"]
    tool: ShortText
    not_before: str
    subject: ShortText | None = None
    body: BoundedText
    claim_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=20)
    consent_ref: OpaqueRef | None = None
    requires_approval: bool
    idempotency_key: OpaqueRef
    arguments: dict[str, Any]
    eligibility_receipt: dict[str, Any] | None = None
    suppression_digest: Sha256Digest | None = None
    request_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("claim_refs", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> TouchRequest:
        if self.channel in CONSENT_CHANNELS and self.consent_ref is None:
            raise ValueError(f"a {self.channel} touch cites a consent")
        if self.channel == "email" and not self.subject:
            raise ValueError("an email touch has a subject")
        if not skip_digests(info) and self.request_digest != sealed_digest(TouchRequest, self, "request_digest"):
            raise ValueError("request_digest must commit the exact request")
        return self

    def receipt_fields(self) -> dict[str, Any]:
        fields: dict[str, Any] = {"step": self.step, "channel": self.channel, "intent": self.intent, "body": self.body, "claim_refs": list(self.claim_refs)}
        if self.subject:
            fields["subject"] = self.subject
        if self.consent_ref:
            fields["consent_ref"] = self.consent_ref
        if self.eligibility_receipt:
            fields.update(eligibility_receipt=self.eligibility_receipt, suppression_digest=self.suppression_digest)
        return fields


def plan_next_touch(plan: PipelineEngineLoopPlan | Mapping[str, Any], state: Any, sequence: SequencePlan | Mapping[str, Any], *, now: str, to_address: str, body: str, subject: str | None = None, claim_refs: Sequence[str] = (), consents: ConsentRegistry | None = None, thread_ref: str | None = None, eligibility_receipt: Any = None, suppression_digest: str | None = None, endpoint_digest: str | None = None, channel_sources: Sequence[Mapping[str, Any]] | None = None) -> TouchRequest:
    """The next step's exact request from the prospect state and its sequence plan; refuses when it is too soon, exhausted, or unconsented."""

    from lightbulb.pipeline_engine_loop import PROSPECT_LIFECYCLE
    parsed_plan, state = PROSPECT_LIFECYCLE.bind(plan, state)
    seq = sequence if isinstance(sequence, SequencePlan) else SequencePlan.model_validate(dict(detached(sequence)))
    ledger = state.ledger
    _require(str(getattr(ledger, "sequence_ref", "") or "") == seq.sequence_ref, "SEQUENCE_MISMATCH", "the sequence plan must be the one the prospect is sequenced on")
    next_step = int(getattr(ledger, "next_step", 1) or 1)
    _require(next_step <= len(seq.touches), "SEQUENCE_EXHAUSTED", f"all {len(seq.touches)} touches were sent")
    touch = seq.touches[next_step - 1]
    _require(touch.step == next_step, "SEQUENCE_PLAN_INCONSISTENT", "the sequence plan steps must be contiguous from 1")
    stamp = timestamp(now, field_name="now")
    _require(parsed(stamp) >= parsed(touch.not_before), "TOUCH_NOT_DUE", f"step {touch.step} is not due before {touch.not_before}")
    policy = next((item for item in parsed_plan.blueprint.channels if item.channel == touch.channel), None)
    _require(policy is not None, "CHANNEL_NOT_ENABLED", f"{touch.channel} is not an enabled channel in this blueprint")
    assert policy is not None
    _require(channel_sources is not None or not parsed_plan.blueprint.require_permission_register, "CHANNEL_USAGE_MISSING", "protected outreach requires the host's complete scoped channel inventory with retained plans")
    candidates = {str(state.scope.entity_ref): state}
    for source in channel_sources or ():
        _, prior = PROSPECT_LIFECYCLE.bind(source["source_plan"], source["state"])
        _require(all(getattr(prior.scope, key) == getattr(state.scope, key) for key in ("tenant_ref", "company_ref", "project_ref", "project_id", "currency")), "SCOPE_MISMATCH", "channel usage must share the active company execution scope")
        ref = str(prior.scope.entity_ref)
        _require(ref not in candidates or candidates[ref].state_digest == prior.state_digest, "CHANNEL_USAGE_CONFLICT", "one current state per prospect in the scoped inventory")
        candidates[ref] = prior
    day_key = f"{touch.channel}:{stamp[:10]}"
    sent = sum(item.ledger.sends_by_day.get(day_key, 0) for item in candidates.values())
    _require(sent < policy.daily_cap, "DAILY_CAP_EXCEEDED", "the channel's daily cap covers all prospects in this company")
    last_touch_at = getattr(ledger, "last_touch_at", None)
    if last_touch_at:
        gap = timedelta(hours=int(policy.min_hours_between_touches))
        _require(parsed(stamp) >= parsed(str(last_touch_at)) + gap, "TOUCH_TOO_SOON", f"policy requires {gap} between touches")
    consent_ref = None
    permission_fields = {}
    if parsed_plan.blueprint.require_permission_register or eligibility_receipt is not None:
        from lightbulb.permission_register import verify_eligibility
        _require(endpoint_digest is not None, "SEND_WITHOUT_ELIGIBILITY", "the host must bind the destination to its keyed endpoint digest")
        proof = verify_eligibility(eligibility_receipt, suppression_digest=suppression_digest, channel=touch.channel, at=stamp, endpoints=[endpoint_digest], company_ref=parsed_plan.blueprint.permission_company_ref, expected_scope=state.scope)
        consent_ref = f"eligibility:{proof.eligibility_digest[:24]}"
        permission_fields = {"eligibility_receipt": proof.to_dict(), "suppression_digest": proof.suppression_digest}
    elif touch.channel in CONSENT_CHANNELS:
        _require(consents is not None, "CONSENT_REGISTRY_REQUIRED", f"a {touch.channel} touch needs the consent registry")
        assert consents is not None
        entry = consents.consent_for(seq.prospect_ref, touch.channel, at=stamp)
        _require(entry is not None, "CONSENT_MISSING", f"no current {touch.channel} consent for {seq.prospect_ref}")
        assert entry is not None
        consent_ref = entry.consent_ref
    tool = _CHANNEL_TOOLS[touch.channel]
    key = f"touch:{seq.prospect_ref}:{seq.sequence_ref}:{touch.step}"
    if touch.channel == "email":
        _require(bool(subject and subject.strip()), "SUBJECT_REQUIRED", "an email touch has a subject")
        arguments: dict[str, Any] = {"to": to_address, "subject": subject, "body": body}
        if thread_ref:
            arguments["thread_id"] = thread_ref
    elif touch.channel == "sms":
        arguments = {"to": to_address, "body": body, "consent_ref": consent_ref}
    elif touch.channel == "voice":
        arguments = {"to": to_address, "script": body, "consent_ref": consent_ref}
    else:
        arguments = {"profile": to_address, "message": body}
    if permission_fields:
        arguments["permission"] = {"eligibility_digest": proof.eligibility_digest, "suppression_digest": proof.suppression_digest, "endpoint_digest": endpoint_digest}
    return seal(TouchRequest, {"prospect_ref": seq.prospect_ref, "sequence_ref": seq.sequence_ref, "step": touch.step, "channel": touch.channel, "intent": touch.intent, "tool": tool, "not_before": touch.not_before, "subject": subject, "body": body, "claim_refs": list(claim_refs), "consent_ref": consent_ref, "requires_approval": bool(getattr(policy, "requires_approval", True)) or touch.requires_approval, "idempotency_key": key, "arguments": arguments, **permission_fields}, "request_digest")


def connector_request(touch: TouchRequest, *, scope: Mapping[str, Any], connector_account_ref: str, approval_ref: str | None = None) -> dict[str, Any]:
    """The ``ConnectorExecutionRequest`` document for the platform: a write behind approval with the derived idempotency key."""

    return {"schema": "lightbulb.connector_execution_request.v1", "tool": touch.tool, "arguments": dict(touch.arguments), "scope": dict(scope), "connector_account_ref": connector_account_ref, "effect": "write", "approval_required": True, "approval_ref": approval_ref, "preview_only": approval_ref is None, "idempotency_key": touch.idempotency_key, "metadata": {"prospect_ref": touch.prospect_ref, "sequence_ref": touch.sequence_ref, "step": touch.step, "touch_request_digest": touch.request_digest}}


def touch_receipt(touch: TouchRequest, execution: ExecutionReceipt | Mapping[str, Any], *, request: Any = None) -> BoundExecution:
    """Bind the platform's write execution receipt to the ``touch`` event; the tool must be the one the request named."""

    receipt = execution if isinstance(execution, ExecutionReceipt) else ExecutionReceipt.model_validate(dict(detached(execution)))
    _require(receipt.tool == touch.tool, "TOUCH_TOOL_MISMATCH", f"the request named {touch.tool}; the execution ran {receipt.tool}")
    _require(request is not None or touch.eligibility_receipt is None, "EXECUTION_REQUEST_MISSING", "a protected touch retains its exact approved connector request")
    if request is not None:
        from lightbulb._execution_gates import exact_request
        exact_request(request, receipt, tool=touch.tool, arguments=touch.arguments, idempotency_key=touch.idempotency_key)
    return bind_execution(receipt, engine="pipeline_engine", event="touch", fields=touch.receipt_fields())


PIPELINE_EXECUTION_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "pipeline_execution",
    "golden_loop": "revenue.icp_to_qualified_pipeline@0.1.0",
    "stages": ["enrich_from_result", "plan_touch", "execute_behind_approval", "bind_touch", "classify_reply", "book_meeting"],
    "channel_tools": dict(_CHANNEL_TOOLS),
    "intent_dispositions": dict(INTENT_DISPOSITIONS),
    "required_connectors": ["gmail", "hubspot", "calendar", "lightbulb.domain_agents"],
    "hard_rules": [
        "a reply disposition comes from the explicit intent table; unknown intents, low confidence, and review flags are refused until a person confirms",
        "voice and SMS touches cite a dated consent from the sealed registry",
        "the next touch is an exact request with an idempotency key derived from prospect, sequence, and step",
        "a touch is recorded only from the platform's write execution receipt with its approval",
    ],
}

__all__ = [
    "CONSENT_REGISTRY_SCHEMA",
    "INTENT_DISPOSITIONS",
    "PIPELINE_EXECUTION_MANIFEST",
    "TOUCH_REQUEST_SCHEMA",
    "ConsentEntry",
    "ConsentRegistry",
    "PipelineExecutionError",
    "TouchRequest",
    "connector_request",
    "consent_registry",
    "enrichment_receipt",
    "meeting_receipt",
    "plan_next_touch",
    "reply_receipt",
    "touch_receipt",
]
