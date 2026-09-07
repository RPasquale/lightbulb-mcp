"""Local presence: a claimed listing and its reviews as two replay-fenced lifecycles.

A local-services company is found on Maps and Search before anywhere else, and
today nothing in the SDK can prove its listing is verified, notice that someone
edited it outside the loop, or answer a review without a human approving the
words.  The platform's four Business Profile reads (``gbp.list_locations``,
``gbp.get_voice_of_merchant_state``, ``gbp.get_location_performance``,
``gbp.get_location``) and, when the legacy host is confirmed, the review reads
and the governed reply write, are the only inputs.  Nothing here calls a
provider: every receipt is built from a sealed observation with provenance or
from a bound ``ExecutionReceipt`` of the approved reply.

``LISTING_LIFECYCLE``::

    unclaimed -> claim_requested -> verification_pending -> verified
              -> published -> (observe_profile loops) -> suspended <-> published
    verification_pending -> unclaimed          (a failed verification)
    published | verified -> retired            (terminal)

``REVIEW_LIFECYCLE``::

    received -> triaged -> response_drafted -> response_approved -> responded -> closed
    any of the open statuses -> escalated -> closed

The guards that matter to a real local operator: a profile observed after
publication whose digest differs from the published one is ``PROFILE_DRIFT``
(someone edited the listing outside the loop) and goes to reconciliation; a
public reply is a governed write behind approval, never automatic; a reply
that offers anything in exchange for a review is refused, because that gets
listings suspended; and the PII and incentive matchers are heuristics, so a
pass is not clearance.  Local performance is platform-reported: it witnesses
touches and never carries revenue.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
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
    timestamp,
)
from lightbulb.company_execution_bridge import ExecutionReceipt, ObservationProvenance

LOCAL_PRESENCE_KIND = "local_presence_engine"
LOCAL_PRESENCE_GOLDEN_LOOP = "growth.local_presence_to_booked_demand@0.1.0"
LOCAL_PRESENCE_PLAN_SCHEMA = "lightbulb.local_presence_plan.v1"
MAX_LISTING_TRANSITIONS = 400
MAX_REVIEW_TRANSITIONS = 12

LOCATION_PAGE_SCHEMA = "lightbulb.gbp_location_page.v1"
LOCATION_SCHEMA = "lightbulb.gbp_location.v1"
VOICE_SCHEMA = "lightbulb.gbp_voice_of_merchant.v1"
PERFORMANCE_SCHEMA = "lightbulb.gbp_location_performance_observation.v1"
REVIEW_PAGE_SCHEMA = "lightbulb.gbp_review_page.v1"
REPLY_TOOL = "gbp.reply_to_review"

LOCATION_TOOLS = frozenset({"gbp.list_locations", "gbp.get_location"})
VERIFICATION_TOOL = "gbp.get_voice_of_merchant_state"
PERFORMANCE_TOOL = "gbp.get_location_performance"
REVIEW_TOOL = "gbp.list_reviews"

StarRating = Literal["ONE", "TWO", "THREE", "FOUR", "FIVE", "STAR_RATING_UNKNOWN"]
VerificationMethod = Literal["POSTCARD", "PHONE_CALL", "EMAIL", "AUTO", "VIDEO", "ADDRESS"]
VerificationState = Literal["PENDING", "COMPLETED", "FAILED"]
TriageClass = Literal["service_failure", "praise", "question", "spam", "other"]

_STARS: dict[str, int] = {"ONE": 1, "TWO": 2, "THREE": 3, "FOUR": 4, "FIVE": 5}
_REMEDY_WORDS = ("gift card", "giftcard", "discount", "refund", "voucher", "free ", "credit", "cash back", "cashback")
_REVIEW_WORDS = ("review", "rating", "stars", "star rating", "feedback", "edit", "change", "update", "remove")
_PII_PATTERNS = (
    re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"),
    re.compile(r"(?:\+?\d[\d\s().-]{7,}\d)"),
    re.compile(r"\b(?:order|booking|invoice|job|ticket|ref(?:erence)?)\s*(?:no\.?|number|#)?\s*[:#]?\s*[A-Z0-9][A-Z0-9-]{3,}\b", re.IGNORECASE),
)


# --------------------------------------------------------------------------- #
# Plan
# --------------------------------------------------------------------------- #


class LocalPresencePlan(StrictModel):
    """What the loop enforces for one listing: who must approve, when to escalate, what a reply may never say."""

    schema_id: str = Field(default=LOCAL_PRESENCE_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    location_commitment: Sha256Digest
    escalate_at_or_below: int = Field(default=2, ge=1, le=5)
    response_sla_hours: int = Field(default=48, ge=1, le=720)
    require_approval_for_response: Literal[True] = True
    prohibited_response_terms: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=50)
    require_case_for_escalation: bool = True
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> LocalPresencePlan:
        if not skip_digests(info) and self.plan_digest != sealed_digest(LocalPresencePlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self


def compile_local_presence_plan(company_ref: str, *, location_commitment: str, overrides: Mapping[str, Any] | None = None) -> LocalPresencePlan:
    return seal(LocalPresencePlan, {"company_ref": company_ref, "location_commitment": location_commitment, **dict(overrides or {})}, "plan_digest")


# --------------------------------------------------------------------------- #
# Listing lifecycle
# --------------------------------------------------------------------------- #

LISTING_STATUSES: tuple[str, ...] = ("unclaimed", "claim_requested", "verification_pending", "verified", "published", "suspended", "retired")
TERMINAL_LISTING_STATUSES: frozenset[str] = frozenset({"retired"})
LISTING_EVENTS: tuple[str, ...] = ("request_claim", "submit_verification", "observe_verification", "publish_profile", "observe_profile", "suspend", "restore", "retire")
_LISTING_TABLE: dict[tuple[str, str], str] = {
    ("new", "request_claim"): "claim_requested",
    ("claim_requested", "submit_verification"): "verification_pending",
    ("verification_pending", "observe_verification"): "verified",
    ("verified", "publish_profile"): "published",
    ("published", "observe_profile"): "published",
    ("published", "suspend"): "suspended",
    ("suspended", "restore"): "published",
    ("published", "retire"): "retired",
    ("verified", "retire"): "retired",
}


class ListingReceipt(StrictModel):
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    location_commitment: Sha256Digest | None = None
    gate_status_digest: Sha256Digest | None = None
    gate_satisfied_at: str | None = None
    gate_evidence_ref: OpaqueRef | None = None
    gate_observed_by_tool: ShortText | None = None
    verification_ref: OpaqueRef | None = None
    verification_method: VerificationMethod | None = None
    verification_state: VerificationState | None = None
    profile_digest: Sha256Digest | None = None
    approval_ref: OpaqueRef | None = None
    observation_ref: OpaqueRef | None = None
    observed_through: str | None = None
    impressions_maps: int | None = Field(default=None, ge=0)
    impressions_search: int | None = Field(default=None, ge=0)
    call_clicks: int | None = Field(default=None, ge=0)
    website_clicks: int | None = Field(default=None, ge=0)
    direction_requests: int | None = Field(default=None, ge=0)
    bookings: int | None = Field(default=None, ge=0)
    conversations: int | None = Field(default=None, ge=0)
    suspend_reason: ShortText | None = None

    @field_validator("gate_satisfied_at", "observed_through")
    @classmethod
    def _stamps(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))


class ListingLedger(StrictModel):
    location_commitment: str | None = None
    gate_status_digest: str | None = None
    claim_requested_at: str | None = None
    verification_ref: str | None = None
    verification_method: str | None = None
    verification_state: str | None = None
    verified_at: str | None = None
    published_profile_digest: str | None = None
    approval_ref: str | None = None
    published_at: str | None = None
    observation_ref: str | None = None
    observed_through: str | None = None
    impressions_maps: int = 0
    impressions_search: int = 0
    call_clicks: int = 0
    website_clicks: int = 0
    direction_requests: int = 0
    bookings: int = 0
    conversations: int = 0
    performance_observations: int = 0
    suspend_reason: str | None = None
    retire_reason: str | None = None
    verification_failures: int = 0
    outcome: Literal["open", "retired"] = "open"


class ListingEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    listing_claimed: Literal[False] = False
    verification_performed: Literal[False] = False
    profile_written: Literal[False] = False
    message_sent: Literal[False] = False
    provider_read: Literal[False] = False


def _apply_listing(plan: LocalPresencePlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event, at = command.receipt, command.event, command.occurred_at
    if event == "request_claim":
        require(r.location_commitment is not None, "LOCATION_UNCOMMITTED", "a claim names the listing by its commitment, never its id")
        require(r.location_commitment == plan.location_commitment, "LOCATION_NOT_PLANNED", "the listing is not the one this plan binds")
        data.update({"location_commitment": r.location_commitment, "claim_requested_at": at})
    elif event == "submit_verification":
        require(r.verification_ref is not None and r.verification_method is not None, "VERIFICATION_MISSING", "a submitted verification names its reference and method")
        data.update({"verification_ref": r.verification_ref, "verification_method": r.verification_method, "verification_state": "PENDING"})
    elif event == "observe_verification":
        require(r.verification_state is not None and r.observation_ref is not None, "VERIFICATION_NOT_COMPLETED", "an observed verification carries the read's state and observation ref", "await_approval")
        if r.verification_state == "FAILED":
            data.update({"verification_state": "FAILED", "verification_failures": int(data.get("verification_failures", 0)) + 1, "observation_ref": r.observation_ref})
            return "unclaimed", data
        require(r.verification_state == "COMPLETED", "VERIFICATION_NOT_COMPLETED", f"verification is {r.verification_state}, not COMPLETED", "await_approval")
        data.update({"verification_state": "COMPLETED", "verified_at": at, "observation_ref": r.observation_ref})
    elif event == "publish_profile":
        require(r.gate_status_digest is not None and r.gate_satisfied_at is not None and r.gate_evidence_ref is not None, "GATE_UNSATISFIED", "every access gate must be satisfied with evidence before a profile write is planned", "await_approval")
        require(r.gate_observed_by_tool is not None, "GATE_UNOBSERVED", "an operator asserted a gate no read witnessed", "await_approval")
        require(r.approval_ref is not None, "PROFILE_WRITE_WITHOUT_APPROVAL", "a profile write is a governed write behind approval", "await_approval")
        require(r.profile_digest is not None, "PROFILE_DIGEST_MISSING", "the published profile is committed by its digest")
        data.update({"gate_status_digest": r.gate_status_digest, "approval_ref": r.approval_ref, "published_profile_digest": r.profile_digest, "published_at": at})
    elif event == "observe_profile":
        require(r.observation_ref is not None and r.observed_through is not None, "OBSERVATION_MISSING", "a profile observation names its ref and the time it covers")
        previous = data.get("observed_through")
        require(previous is None or parsed(r.observed_through) > parsed(str(previous)), "OBSERVATION_NOT_NEWER", "the observation does not advance observed_through")
        if r.profile_digest is not None:
            require(r.profile_digest == data.get("published_profile_digest"), "PROFILE_DRIFT", "the listing observed differs from the profile published through the loop: someone edited it outside", "manual_reconciliation")
        counters = {k: getattr(r, k) for k in ("impressions_maps", "impressions_search", "call_clicks", "website_clicks", "direction_requests", "bookings", "conversations") if getattr(r, k) is not None}
        for key, value in counters.items():
            data[key] = int(data.get(key, 0)) + int(value)
        data.update({"observation_ref": r.observation_ref, "observed_through": r.observed_through, "performance_observations": int(data.get("performance_observations", 0)) + (1 if counters else 0)})
    elif event == "suspend":
        require(command.reason is not None and str(command.reason).strip() != "", "SUSPENSION_UNEXPLAINED", "a suspension carries the provider's stated reason")
        data.update({"suspend_reason": str(command.reason)[:300]})
    elif event == "restore":
        require(r.observation_ref is not None, "OBSERVATION_MISSING", "a restore is witnessed by a read of the live listing")
        data.update({"suspend_reason": None, "observation_ref": r.observation_ref})
    elif event == "retire":
        data.update({"retire_reason": str(command.reason)[:300], "outcome": "retired"})
    return next_status, data


LISTING_LIFECYCLE = LifecycleSpec(entity="gbp_listing", schema_prefix="gbp_listing", statuses=LISTING_STATUSES, terminal=TERMINAL_LISTING_STATUSES, events=LISTING_EVENTS, table=_LISTING_TABLE, opening_event="request_claim", reason_events=("suspend", "retire"), apply=_apply_listing, ledger_model=ListingLedger, receipt_model=ListingReceipt, effect_boundary_model=ListingEffectBoundary, plan_model=LocalPresencePlan, max_transitions=MAX_LISTING_TRANSITIONS)
ListingState = LISTING_LIFECYCLE.State


def open_listing(plan: LocalPresencePlan | Mapping[str, Any], scope: Mapping[str, Any], *, receipt: Mapping[str, Any], opened_at: str, actor_ref: str) -> Any:
    return LISTING_LIFECYCLE.open(plan, scope, opened_at=opened_at, actor_ref=actor_ref, receipt=receipt)


def advance_listing(plan: LocalPresencePlan | Mapping[str, Any], state: Any, command: Any) -> Any:
    return LISTING_LIFECYCLE.advance(plan, state, command)


# --------------------------------------------------------------------------- #
# Review lifecycle
# --------------------------------------------------------------------------- #

REVIEW_STATUSES: tuple[str, ...] = ("received", "triaged", "response_drafted", "response_approved", "responded", "escalated", "closed")
TERMINAL_REVIEW_STATUSES: frozenset[str] = frozenset({"closed"})
REVIEW_EVENTS: tuple[str, ...] = ("receive", "triage", "draft_response", "approve_response", "publish_response", "escalate", "close")
_REVIEW_TABLE: dict[tuple[str, str], str] = {
    ("new", "receive"): "received",
    ("received", "triage"): "triaged",
    ("triaged", "draft_response"): "response_drafted",
    ("response_drafted", "draft_response"): "response_drafted",
    ("response_drafted", "approve_response"): "response_approved",
    ("response_approved", "publish_response"): "responded",
    ("responded", "close"): "closed",
    ("escalated", "close"): "closed",
    ("triaged", "close"): "closed",
    **{(status, "escalate"): "escalated" for status in ("received", "triaged", "response_drafted", "response_approved", "responded")},
}


class ReviewReceipt(StrictModel):
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    review_commitment: Sha256Digest | None = None
    location_commitment: Sha256Digest | None = None
    star_rating: StarRating | None = None
    comment_digest: Sha256Digest | None = None
    comment_length: int | None = Field(default=None, ge=0)
    has_reply: bool | None = None
    received_at: str | None = None
    observation_ref: OpaqueRef | None = None
    triage_class: TriageClass | None = None
    case_ref: OpaqueRef | None = None
    response_body: BoundedText | None = None
    reviewer_display_name: ShortText | None = None
    response_digest: Sha256Digest | None = None
    approval_ref: OpaqueRef | None = None
    approved_at: str | None = None
    publish_execution_digest: Sha256Digest | None = None
    reply_update_time: str | None = None
    customer_commitment: Sha256Digest | None = None

    @field_validator("received_at", "approved_at", "reply_update_time")
    @classmethod
    def _stamps(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))


class ReviewLedger(StrictModel):
    review_commitment: str | None = None
    location_commitment: str | None = None
    star_rating: str | None = None
    stars: int | None = None
    comment_digest: str | None = None
    comment_length: int = 0
    received_at: str | None = None
    sla_due_at: str | None = None
    sla_breached: bool = False
    triage_class: str | None = None
    case_ref: str | None = None
    response_digest: str | None = None
    drafted_at: str | None = None
    draft_count: int = 0
    approval_ref: str | None = None
    approved_at: str | None = None
    responded_at: str | None = None
    publish_execution_digest: str | None = None
    escalation_reason: str | None = None
    close_reason: str | None = None
    outcome: Literal["open", "responded", "escalated", "closed"] = "open"


class ReviewEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    reply_published: Literal[False] = False
    message_sent: Literal[False] = False
    provider_read: Literal[False] = False


def incentive_offered(text: str) -> bool:
    """A bounded heuristic: a remedy word and a review word in the same reply. A pass is not clearance."""

    lowered = f" {text.lower()} "
    return any(word in lowered for word in _REMEDY_WORDS) and any(word in lowered for word in _REVIEW_WORDS)


def pii_in_response(text: str, reviewer_display_name: str | None = None) -> bool:
    """A bounded heuristic: e-mail, phone, order/booking references, or the reviewer's supplied name."""

    if reviewer_display_name and reviewer_display_name.strip() and reviewer_display_name.strip().lower() in text.lower():
        return True
    return any(pattern.search(text) for pattern in _PII_PATTERNS)


def _hours_between(start: str | None, end: str) -> float:
    if start is None:
        return 0.0
    return (parsed(end) - parsed(start)).total_seconds() / 3600.0


def _apply_review(plan: LocalPresencePlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event, at = command.receipt, command.event, command.occurred_at
    if event == "receive":
        require(r.review_commitment is not None and r.star_rating is not None and r.comment_digest is not None and r.received_at is not None and r.observation_ref is not None, "REVIEW_MISSING", "a received review carries its commitment, rating, comment digest, time, and observation ref")
        require(r.location_commitment == plan.location_commitment, "LOCATION_NOT_PLANNED", "the review belongs to a listing this plan does not bind")
        require(not bool(r.has_reply), "REVIEW_ALREADY_ANSWERED", "the review already carries a reply; it is not open work")
        stars = _STARS.get(str(r.star_rating))
        due = parsed(r.received_at).timestamp() + plan.response_sla_hours * 3600
        from datetime import datetime, timezone

        sla_due_at = datetime.fromtimestamp(due, tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        data.update({"review_commitment": r.review_commitment, "location_commitment": r.location_commitment, "star_rating": r.star_rating, "stars": stars, "comment_digest": r.comment_digest, "comment_length": int(r.comment_length or 0), "received_at": r.received_at, "sla_due_at": sla_due_at})
    elif event == "triage":
        require(r.triage_class is not None, "TRIAGE_MISSING", "a triage names its class")
        stars = data.get("stars")
        if stars is not None and int(stars) <= plan.escalate_at_or_below:
            require(r.triage_class in ("service_failure", "spam", "other"), "LOW_RATING_NOT_TRIAGED", f"a {stars}-star review must be triaged as a service failure, spam, or other")
        data.update({"triage_class": r.triage_class})
    elif event == "draft_response":
        require(r.response_body is not None and r.response_digest is not None, "RESPONSE_MISSING", "a draft carries its body and digest")
        body = str(r.response_body)
        require(not incentive_offered(body), "INCENTIVE_OFFERED", "a reply that offers anything in exchange for a review gets the listing suspended", "manual_reconciliation")
        require(not pii_in_response(body, r.reviewer_display_name), "PII_IN_RESPONSE", "a public reply must not carry personal or transaction details")
        lowered = body.lower()
        require(not any(term.lower() in lowered for term in plan.prohibited_response_terms), "PROHIBITED_TERM", "the reply uses a term the plan prohibits")
        data.update({"response_digest": r.response_digest, "drafted_at": at, "draft_count": int(data.get("draft_count", 0)) + 1, "approval_ref": None, "approved_at": None})
    elif event == "approve_response":
        require(r.approval_ref is not None and r.approved_at is not None and r.response_digest is not None, "RESPONSE_NOT_APPROVED", "a public reply is approved by a person before it is planned", "await_approval")
        require(r.response_digest == data.get("response_digest"), "RESPONSE_STALE", "the approval covers a different draft than the current one", "await_approval")
        require(parsed(r.approved_at) >= parsed(str(data.get("drafted_at"))), "RESPONSE_STALE", "the approval predates the last draft", "await_approval")
        data.update({"approval_ref": r.approval_ref, "approved_at": r.approved_at})
    elif event == "publish_response":
        require(data.get("approval_ref") is not None, "RESPONSE_NOT_APPROVED", "a reply cannot be published without an approval", "await_approval")
        require(r.publish_execution_digest is not None and r.reply_update_time is not None and r.response_digest is not None, "PUBLICATION_MISSING", "a published reply is proven by its execution receipt and the provider's reply time")
        require(r.response_digest == data.get("response_digest"), "RESPONSE_STALE", "the published reply is not the approved draft", "manual_reconciliation")
        breached = _hours_between(data.get("received_at"), r.reply_update_time) > plan.response_sla_hours
        data.update({"publish_execution_digest": r.publish_execution_digest, "responded_at": r.reply_update_time, "sla_breached": breached, "outcome": "responded"})
    elif event == "escalate":
        if plan.require_case_for_escalation:
            require(r.case_ref is not None, "ESCALATION_UNROUTED", "an escalation opens a delivery case", "await_approval")
        data.update({"case_ref": r.case_ref, "escalation_reason": str(command.reason)[:300], "outcome": "escalated"})
    elif event == "close":
        data.update({"close_reason": str(command.reason)[:300], "outcome": "closed"})
    return next_status, data


REVIEW_LIFECYCLE = LifecycleSpec(entity="gbp_review", schema_prefix="gbp_review", statuses=REVIEW_STATUSES, terminal=TERMINAL_REVIEW_STATUSES, events=REVIEW_EVENTS, table=_REVIEW_TABLE, opening_event="receive", reason_events=("escalate", "close"), apply=_apply_review, ledger_model=ReviewLedger, receipt_model=ReviewReceipt, effect_boundary_model=ReviewEffectBoundary, plan_model=LocalPresencePlan, max_transitions=MAX_REVIEW_TRANSITIONS)
ReviewState = REVIEW_LIFECYCLE.State


def open_review(plan: LocalPresencePlan | Mapping[str, Any], scope: Mapping[str, Any], *, receipt: Mapping[str, Any], opened_at: str, actor_ref: str) -> Any:
    return REVIEW_LIFECYCLE.open(plan, scope, opened_at=opened_at, actor_ref=actor_ref, receipt=receipt)


def advance_review(plan: LocalPresencePlan | Mapping[str, Any], state: Any, command: Any) -> Any:
    return REVIEW_LIFECYCLE.advance(plan, state, command)


# --------------------------------------------------------------------------- #
# Receipts from the platform's sealed artifacts
# --------------------------------------------------------------------------- #


class LocalPresenceError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise LocalPresenceError(code, message)


def _provenance(provenance: Mapping[str, Any] | Any, *, tools: frozenset[str] | set[str]) -> ObservationProvenance:
    try:
        sealed = ObservationProvenance.model_validate(detached(provenance))
    except Exception as invalid:  # noqa: BLE001 - surfaced as a coded refusal
        raise LocalPresenceError("PROVENANCE_INVALID", str(invalid)) from invalid
    _require(sealed.source_tool in tools, "PROVENANCE_TOOL_MISMATCH", f"expected one of {sorted(tools)}, got {sealed.source_tool}")
    return sealed


def location_receipt(provenance: Mapping[str, Any] | Any, payload: Mapping[str, Any] | Any, *, location_commitment: str | None = None) -> dict[str, Any]:
    """The claim receipt from ``gbp.get_location`` (one listing) or ``gbp.list_locations`` (pick by commitment)."""

    sealed = _provenance(provenance, tools=LOCATION_TOOLS)
    observed = dict(detached(payload))
    schema = observed.get("schema")
    if schema == LOCATION_SCHEMA:
        commitment = str(observed["location_name_sha256"])
        profile_digest = str(observed["profile_digest"])
    elif schema == LOCATION_PAGE_SCHEMA:
        _require(location_commitment is not None, "LOCATION_UNCOMMITTED", "pick the listing from a page by its commitment")
        rows = [row for row in observed.get("locations", []) if str(row.get("location_name_sha256")) == location_commitment]
        _require(len(rows) == 1, "LOCATION_NOT_IN_PAGE", "the listing is not in the observed page")
        commitment = str(location_commitment)
        profile_digest = None
    else:
        raise LocalPresenceError("LOCATION_SCHEMA_MISMATCH", f"expected a Business Profile location artifact, got {schema}")
    _require(location_commitment is None or commitment == location_commitment, "LOCATION_NOT_PLANNED", "the observed listing is not the planned one")
    return {"location_commitment": commitment, "profile_digest": profile_digest, "observation_ref": str(sealed.observation_ref), "observed_through": str(observed.get("observed_at") or sealed.completed_at), "evidence_refs": [f"observation:{sealed.observation_ref}", f"provenance:{sealed.provenance_digest[:24]}"]}


def verification_receipt(provenance: Mapping[str, Any] | Any, payload: Mapping[str, Any] | Any) -> dict[str, Any]:
    """From ``gbp.get_voice_of_merchant_state``: no API verifies a listing, this only reports the state."""

    sealed = _provenance(provenance, tools={VERIFICATION_TOOL})
    observed = dict(detached(payload))
    _require(observed.get("schema") == VOICE_SCHEMA, "VERIFICATION_SCHEMA_MISMATCH", f"expected {VOICE_SCHEMA}")
    if bool(observed.get("has_voice_of_merchant")):
        state: VerificationState = "COMPLETED"
    elif bool(observed.get("waiting_for_voice_of_merchant")) or observed.get("resolution_state") == "verify":
        state = "PENDING"
    else:
        state = "FAILED"
    return {"location_commitment": str(observed["location_name_sha256"]), "verification_state": state, "observation_ref": str(sealed.observation_ref), "evidence_refs": [f"observation:{sealed.observation_ref}"]}


def performance_receipt(provenance: Mapping[str, Any] | Any, payload: Mapping[str, Any] | Any) -> dict[str, Any]:
    """From ``gbp.get_location_performance``: platform-reported touches, never revenue."""

    sealed = _provenance(provenance, tools={PERFORMANCE_TOOL})
    observed = dict(detached(payload))
    _require(observed.get("schema") == PERFORMANCE_SCHEMA, "PERFORMANCE_SCHEMA_MISMATCH", f"expected {PERFORMANCE_SCHEMA}")
    totals = dict(observed.get("totals") or {})
    _require(bool(observed.get("exhaustive_read", False)), "PERFORMANCE_NOT_EXHAUSTIVE", "a truncated performance read is not an observation")
    metric = {"impressions_maps": int(totals.get("BUSINESS_IMPRESSIONS_DESKTOP_MAPS", 0)) + int(totals.get("BUSINESS_IMPRESSIONS_MOBILE_MAPS", 0)), "impressions_search": int(totals.get("BUSINESS_IMPRESSIONS_DESKTOP_SEARCH", 0)) + int(totals.get("BUSINESS_IMPRESSIONS_MOBILE_SEARCH", 0)), "call_clicks": int(totals.get("CALL_CLICKS", 0)), "website_clicks": int(totals.get("WEBSITE_CLICKS", 0)), "direction_requests": int(totals.get("BUSINESS_DIRECTION_REQUESTS", 0)), "bookings": int(totals.get("BUSINESS_BOOKINGS", 0)), "conversations": int(totals.get("BUSINESS_CONVERSATIONS", 0))}
    return {"location_commitment": str(observed["location_name_sha256"]), "observation_ref": str(sealed.observation_ref), "observed_through": f"{observed['window_end']}T23:59:59Z", **metric, "evidence_refs": [f"observation:{sealed.observation_ref}", f"evidence:{str(observed['evidence_sha256'])[:24]}"]}


def review_receipt(provenance: Mapping[str, Any] | Any, review_row: Mapping[str, Any], *, location_commitment: str) -> dict[str, Any]:
    """One row of a ``gbp.list_reviews`` page. The reviewer's name and the prose never enter the SDK."""

    sealed = _provenance(provenance, tools={REVIEW_TOOL})
    row = dict(review_row)
    rating = str(row.get("star_rating", ""))
    star: StarRating = rating if rating in _STARS else "STAR_RATING_UNKNOWN"  # type: ignore[assignment]
    return {"review_commitment": str(row["review_id_sha256"]), "location_commitment": location_commitment, "star_rating": star, "comment_digest": str(row["comment_sha256"]), "comment_length": int(row.get("comment_length", 0)), "has_reply": bool(row.get("has_reply", False)), "received_at": str(row["create_time"]), "observation_ref": str(sealed.observation_ref), "evidence_refs": [f"observation:{sealed.observation_ref}", f"review:{str(row['review_id_sha256'])[:24]}"]}


def response_publish_receipt(execution: Mapping[str, Any] | Any, *, response_digest: str, reply_update_time: str) -> dict[str, Any]:
    """From the bound ``ExecutionReceipt`` of the approved ``gbp.reply_to_review`` write."""

    try:
        sealed = ExecutionReceipt.model_validate(detached(execution))
    except Exception as invalid:  # noqa: BLE001
        raise LocalPresenceError("EXECUTION_INVALID", str(invalid)) from invalid
    _require(sealed.tool == REPLY_TOOL and sealed.effect == "write", "EXECUTION_TOOL_MISMATCH", f"expected an approved {REPLY_TOOL} write, got {sealed.tool}/{sealed.effect}")
    _require(sealed.approval_ref is not None, "RESPONSE_NOT_APPROVED", "the reply write carried no approval")
    return {"publish_execution_digest": sealed.execution_digest, "response_digest": response_digest, "reply_update_time": reply_update_time, "approval_ref": sealed.approval_ref, "evidence_refs": [f"journal:{sealed.journal_ref}", f"execution:{sealed.execution_digest[:24]}"]}


# --------------------------------------------------------------------------- #
# Cross-engine outputs
# --------------------------------------------------------------------------- #


def reputation_signal(review_state: Any, *, emitted_at: str) -> dict[str, Any]:
    """A ``reputation_risk`` company signal for the operating system and service delivery."""

    ledger = review_state.ledger
    return {"name": "reputation_risk", "producer": "growth_engine", "emitted_at": timestamp(emitted_at, field_name="emitted_at"), "payload": {"location_ref": str(ledger.location_commitment), "star_rating": str(ledger.star_rating), "triage_class": str(ledger.triage_class or "untriaged"), "sla_due_at": str(ledger.sla_due_at), "review_ref": str(ledger.review_commitment)}}


def service_case_receipt(review_state: Any) -> dict[str, Any]:
    """What service delivery opens a case from: commitments only, never prose."""

    ledger = review_state.ledger
    _require(ledger.triage_class == "service_failure", "NOT_A_SERVICE_FAILURE", "only a service failure opens a delivery case")
    return {"review_commitment": str(ledger.review_commitment), "comment_digest": str(ledger.comment_digest), "star_rating": str(ledger.star_rating), "location_commitment": str(ledger.location_commitment), "received_at": str(ledger.received_at), "evidence_refs": [f"review:{str(ledger.review_commitment)[:24]}"]}


def retention_flag(review_state: Any, customer_commitment: str | None) -> dict[str, Any]:
    """A retention-chain at-risk receipt when the reviewer is a known customer; unmatched is reported, never guessed."""

    ledger = review_state.ledger
    if customer_commitment is None:
        return {"disposition": "CUSTOMER_UNMATCHED", "review_commitment": str(ledger.review_commitment)}
    return {"disposition": "AT_RISK", "customer_commitment": customer_commitment, "risk_reason": f"{ledger.star_rating} star review", "review_commitment": str(ledger.review_commitment), "evidence_refs": [f"review:{str(ledger.review_commitment)[:24]}"]}


def local_touch_claims(performance_observation: Mapping[str, Any] | Any, *, location_commitment: str) -> list[dict[str, Any]]:
    """Demand witnesses for the attribution ledger: platform-reported touches that must be joined host-side to a settled booking or reported unmatched."""

    observed = dict(detached(performance_observation))
    _require(observed.get("schema") == PERFORMANCE_SCHEMA, "PERFORMANCE_SCHEMA_MISMATCH", f"expected {PERFORMANCE_SCHEMA}")
    _require(str(observed.get("location_name_sha256")) == location_commitment, "LOCATION_NOT_PLANNED", "the performance observation is for another listing")
    claims: list[dict[str, Any]] = []
    for row in observed.get("daily", []):
        metric = str(row.get("metric"))
        if metric not in ("CALL_CLICKS", "BUSINESS_BOOKINGS", "BUSINESS_DIRECTION_REQUESTS"):
            continue
        count = int(row.get("value", 0))
        if count <= 0:
            continue
        claims.append({"channel": "local_presence", "basis": "platform_reported", "claim_source": PERFORMANCE_TOOL, "location_commitment": location_commitment, "metric": metric, "count": count, "occurred_on": str(row.get("date")), "evidence_sha256": str(observed.get("evidence_sha256")), "matched": False})
    return claims


def listing_summary(listing_state: Any) -> dict[str, Any]:
    ledger = listing_state.ledger
    return {"status": listing_state.status, "verification_state": ledger.verification_state, "published": ledger.published_at is not None, "observed_through": ledger.observed_through, "touches": {"call_clicks": ledger.call_clicks, "bookings": ledger.bookings, "direction_requests": ledger.direction_requests, "website_clicks": ledger.website_clicks}, "impressions": {"maps": ledger.impressions_maps, "search": ledger.impressions_search}, "suspended": ledger.suspend_reason is not None}


LOCAL_PRESENCE_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": LOCAL_PRESENCE_KIND,
    "golden_loop": LOCAL_PRESENCE_GOLDEN_LOOP,
    "stages": ("claim", "verify", "publish", "observe", "answer", "escalate"),
    "statuses": {"listing": LISTING_STATUSES, "review": REVIEW_STATUSES},
    "events": {"listing": LISTING_EVENTS, "review": REVIEW_EVENTS},
    "hops": ("location_receipt", "verification_receipt", "performance_receipt", "review_receipt", "response_publish_receipt"),
    "required_connectors": ("google_business_profile",),
    "provider_endpoints": (
        {"tool": "gbp.list_locations", "host": "mybusinessbusinessinformation.googleapis.com/v1", "confidence": "verified-shape"},
        {"tool": "gbp.get_voice_of_merchant_state", "host": "mybusinessverifications.googleapis.com/v1", "confidence": "verified-shape"},
        {"tool": "gbp.get_location_performance", "host": "businessprofileperformance.googleapis.com/v1", "confidence": "verified-shape"},
        {"tool": "gbp.get_location", "host": "mybusinessbusinessinformation.googleapis.com/v1", "confidence": "verified-shape"},
        {"tool": "gbp.list_reviews", "host": "mybusiness.googleapis.com/v4", "confidence": "unverified-legacy-host"},
        {"tool": "gbp.reply_to_review", "host": "mybusiness.googleapis.com/v4", "confidence": "unverified-legacy-host"},
    ),
    "human_gates": ("the listing is claimed and verified by the owner; the API only reports the state", "the Business Profile API access request is approved by Google", "every public reply is approved by a person"),
    "hard_rules": (
        "no write is planned until every gate is satisfied AND observed by a read",
        "a public reply is a governed write behind approval, never automatic",
        "a reply offering anything in exchange for a review is refused",
        "an edited listing observed off-plan is a reconciliation exception",
        "local performance is platform-reported: it witnesses touches and never carries revenue",
        "the PII and incentive matchers are heuristics; a pass is not clearance",
    ),
}

__all__ = [
    "LOCAL_PRESENCE_KIND", "LOCAL_PRESENCE_GOLDEN_LOOP", "LOCAL_PRESENCE_MANIFEST", "LOCAL_PRESENCE_PLAN_SCHEMA",
    "LISTING_LIFECYCLE", "REVIEW_LIFECYCLE", "LISTING_STATUSES", "REVIEW_STATUSES", "LISTING_EVENTS", "REVIEW_EVENTS",
    "LocalPresencePlan", "LocalPresenceError", "ListingReceipt", "ListingLedger", "ListingEffectBoundary", "ListingState",
    "ReviewReceipt", "ReviewLedger", "ReviewEffectBoundary", "ReviewState",
    "compile_local_presence_plan", "open_listing", "advance_listing", "open_review", "advance_review",
    "location_receipt", "verification_receipt", "performance_receipt", "review_receipt", "response_publish_receipt",
    "reputation_signal", "service_case_receipt", "retention_flag", "local_touch_claims", "listing_summary",
    "incentive_offered", "pii_in_response",
]
