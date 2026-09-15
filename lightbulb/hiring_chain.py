"""The hiring chain: one replay-fenced lifecycle per requisition, from a funded headcount need to an accepted offer.

The employment chain begins at ``offered`` and nothing produced the offer:
a requisition was never funded against the budget envelope, never
authorised, and candidates were interviewed nowhere the platform could
replay.  ``HIRING_LIFECYCLE`` is that missing front half:

    requested -> approved -> sourcing -> interviewing -> offer_extended
                                                  -> offer_accepted     (terminal)
    offer_extended -> interviewing            (declined offer; the pool remains)
    requested | approved -> cancelled         (terminal, with a reason)
    sourcing | interviewing | offer_extended -> withdrawn  (terminal, with a reason)

Every hop consumes a sealed artifact and nothing is asserted by the caller:

* ``headcount_receipt`` opens the requisition from the role's pay band and a
  ``CashBudgetEnvelope``: the annualised commitment of the requested heads
  must fit inside the envelope's affordable incremental monthly burn.
* ``approve`` consumes an :class:`~lightbulb.authority_matrix.AuthorizationProof`
  of category ``people_change`` for the exact commitment; the approver is
  never the requester.
* ``applications_receipt`` consumes a host-lane ATS applications read; each
  application becomes an opaque ``candidate:`` commitment derived from the
  application id, and a person never enters the engine.
* ``interview_receipt`` consumes a scorecard digest with its interviewer,
  score and recommendation.
* ``offer_receipt`` extends an offer inside the band to a candidate with the
  plan's minimum interviews and a ``hire`` recommendation.
* ``acceptance_receipt`` consumes the ATS application row in ``hired`` /
  ``offer_accepted`` and the signed envelope whose document digest is the
  offer's.

``employment_offer_receipt`` turns an accepted requisition into the
employment chain's opening receipt (``employment_chain.offer_receipt`` from
the retained application read and offer terms), so a person is employed
only through a requisition that was funded and authorised.  Nothing here
reads a provider, writes to one, or persists anything.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    MONEY_QUANTUM,
    BoundedText,
    CurrencyCode,
    LifecycleSpec,
    OpaqueRef,
    Sha256Digest,
    ShortText,
    StrictModel,
    decimal_value,
    detached,
    parsed,
    require,
    seal,
    sealed_digest,
    skip_digests,
    stable_digest,
    timestamp,
)

HIRING_KIND = "hiring_chain"
HIRING_GOLDEN_LOOP = "people.headcount_need_to_accepted_offer@0.1.0"
HIRING_PLAN_SCHEMA = "lightbulb.hiring_chain_plan.v1"
SCORECARD_SCHEMA = "lightbulb.hiring_scorecard.v1"
MAX_HIRING_TRANSITIONS = 60
APPLICATIONS_TOOLS: frozenset[str] = frozenset({"greenhouse.list_applications", "ats.list_applications", "host.ats_applications", "hr_live_recruiting_applications"})
APPLICATION_TOOLS: frozenset[str] = frozenset({"ats.get_application", "greenhouse.get_application"})
ENVELOPE_TOOLS: frozenset[str] = frozenset({"signing.get_envelope"})
BUDGET_ENVELOPE_SCHEMA = "lightbulb.cash_budget_envelope.v1"
_TWELVE = Decimal("12")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_IDENTITY_MARKERS: tuple[str, ...] = (
    "displayname", "fullname", "firstname", "lastname", "givenname", "familyname", "middlename", "preferredname", "legalname",
    "candidatename", "personname", "surname", "email", "phone", "mobile", "address", "dateofbirth", "birthdate", "linkedin",
    "resume", "cv", "coverletter", "personaldetails",
)

HIRING_STATUSES: tuple[str, ...] = ("requested", "approved", "sourcing", "interviewing", "offer_extended", "offer_accepted", "withdrawn", "cancelled")
TERMINAL_HIRING_STATUSES: frozenset[str] = frozenset({"offer_accepted", "withdrawn", "cancelled"})
HIRING_EVENTS: tuple[str, ...] = ("request", "approve", "source", "interview", "extend_offer", "accept_offer", "decline_offer", "withdraw", "cancel")
_HIRING_TABLE: dict[tuple[str, str], str] = {
    ("new", "request"): "requested",
    ("requested", "approve"): "approved",
    ("requested", "cancel"): "cancelled",
    ("approved", "cancel"): "cancelled",
    ("approved", "source"): "sourcing",
    ("sourcing", "source"): "sourcing",
    ("sourcing", "interview"): "interviewing",
    ("interviewing", "interview"): "interviewing",
    ("interviewing", "source"): "interviewing",
    ("interviewing", "extend_offer"): "offer_extended",
    ("offer_extended", "accept_offer"): "offer_accepted",
    ("offer_extended", "decline_offer"): "interviewing",
    **{(status, "withdraw"): "withdrawn" for status in ("sourcing", "interviewing", "offer_extended")},
}
Recommendation = Literal["hire", "no_hire", "hold"]
PayRateUom = Literal["hour", "year"]


class HiringChainError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise HiringChainError(code, message)


def _normalized(key: str) -> str:
    return str(key).lower().replace("_", "").replace("-", "")


def _reject_identity(payload: Any, *, path: str = "receipt") -> Any:
    """Refuse a payload that still carries a person; only hashed commitments cross this boundary."""

    if isinstance(payload, str):
        _require(not _EMAIL.search(payload), "IDENTITY_IN_RECEIPT", f"{path} carries an email address; a person never crosses this boundary")
        return payload
    if isinstance(payload, Mapping):
        for key, item in payload.items():
            normal = _normalized(key)
            _require(not any(marker in normal for marker in _IDENTITY_MARKERS), "IDENTITY_IN_RECEIPT", f"{path}.{key} names a person; only hashed commitments cross this boundary")
            _reject_identity(item, path=f"{path}.{key}")
        return payload
    if isinstance(payload, (list, tuple)):
        for index, item in enumerate(payload):
            _reject_identity(item, path=f"{path}[{index}]")
    return payload


def candidate_ref(application_id: str) -> str:
    """The opaque commitment to one application; the person behind it never enters the engine."""

    return f"candidate:{stable_digest({'application_id': str(application_id)})[:24]}"


# --------------------------------------------------------------------------- #
# Plan
# --------------------------------------------------------------------------- #


class PayBand(StrictModel):
    role_ref: OpaqueRef
    pay_rate_uom: PayRateUom
    min_amount: Decimal
    max_amount: Decimal

    @field_validator("min_amount", "max_amount", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _ordered(self) -> "PayBand":
        if self.min_amount <= 0 or self.max_amount < self.min_amount:
            raise ValueError("a pay band runs from a positive minimum to a maximum at or above it")
        return self


class HiringChainPlan(StrictModel):
    """What the chain enforces: the bands, the hours a year that annualise hourly pay, the interview floor, and the windows."""

    schema_id: str = Field(default=HIRING_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    jurisdiction: str = Field(min_length=2, max_length=2)
    pay_bands: tuple[PayBand, ...] = Field(min_length=1, max_length=60)
    hours_per_year: int = Field(default=1976, ge=1, le=4000)
    min_interviews_before_offer: int = Field(default=1, ge=0, le=12)
    require_hire_recommendation: bool = True
    require_budget_cover: bool = True
    offer_validity_days: int = Field(default=14, ge=1, le=90)
    max_days_requisition_to_offer: int = Field(default=120, ge=1, le=730)
    people_plan_digest: Sha256Digest | None = None
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("jurisdiction")
    @classmethod
    def _jurisdiction(cls, value: str) -> str:
        return value.upper()

    @field_validator("pay_bands", mode="before")
    @classmethod
    def _bands(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "HiringChainPlan":
        refs = [band.role_ref for band in self.pay_bands]
        if len(refs) != len(set(refs)):
            raise ValueError("pay band role refs must be unique")
        if not skip_digests(info) and self.plan_digest != sealed_digest(HiringChainPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self

    def band(self, role_ref: str) -> PayBand | None:
        return next((band for band in self.pay_bands if band.role_ref == role_ref), None)

    def annualised(self, amount: Decimal, uom: str) -> Decimal:
        yearly = amount * self.hours_per_year if uom == "hour" else amount
        return Decimal(yearly).quantize(MONEY_QUANTUM)


def compile_hiring_chain(company_ref: str, *, currency: str, jurisdiction: str, pay_bands: Sequence[Mapping[str, Any]], people_plan: Any = None, overrides: Mapping[str, Any] | None = None) -> HiringChainPlan:
    """Bands come from the operator; the people plan, when given, is retained by digest."""

    raw: dict[str, Any] = {"company_ref": company_ref, "currency": str(currency).upper(), "jurisdiction": jurisdiction, "pay_bands": [dict(detached(item)) for item in pay_bands], **dict(overrides or {})}
    if people_plan is not None:
        raw["people_plan_digest"] = str(dict(detached(people_plan)).get("plan_digest") or stable_digest(detached(people_plan)))
    return seal(HiringChainPlan, raw, "plan_digest")


# --------------------------------------------------------------------------- #
# Receipts, ledger, lifecycle
# --------------------------------------------------------------------------- #


class OfferRecord(StrictModel):
    offer_ref: OpaqueRef
    candidate_ref: OpaqueRef
    amount: Decimal
    pay_rate_uom: PayRateUom
    document_sha256: Sha256Digest
    extended_at: str
    expires_at: str
    status: Literal["open", "accepted", "declined"] = "open"

    @field_validator("amount", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="amount")


class HiringReceipt(StrictModel):
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    role_ref: OpaqueRef | None = None
    headcount: int | None = Field(default=None, ge=1, le=200)
    pay_rate: Decimal | None = None
    pay_rate_uom: PayRateUom | None = None
    period_ref: OpaqueRef | None = None
    requester_ref: OpaqueRef | None = None
    envelope_source: dict[str, Any] | None = None
    envelope_digest: Sha256Digest | None = None
    authorization_proof: dict[str, Any] | None = None
    candidate_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=500)
    applications_provenance: dict[str, Any] | None = None
    applications_digest: Sha256Digest | None = None
    candidate_ref: OpaqueRef | None = None
    interviewer_ref: OpaqueRef | None = None
    stage: ShortText | None = None
    score: int | None = Field(default=None, ge=0, le=100)
    recommendation: Recommendation | None = None
    scorecard_sha256: Sha256Digest | None = None
    offer_ref: OpaqueRef | None = None
    amount: Decimal | None = None
    document_sha256: Sha256Digest | None = None
    expires_at: str | None = None
    accepted_at: str | None = None
    application_source: dict[str, Any] | None = None
    application_ref: OpaqueRef | None = None
    ats_status: ShortText | None = None
    envelope_status: ShortText | None = None
    envelope_document_sha256: Sha256Digest | None = None
    detail: BoundedText | None = None

    @field_validator("evidence_refs", "candidate_refs", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("pay_rate", "amount", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))

    @field_validator("expires_at", "accepted_at")
    @classmethod
    def _stamps(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _no_identity(self) -> "HiringReceipt":
        _reject_identity(self.application_source or {}, path="application_source")
        _reject_identity(self.envelope_source or {}, path="envelope_source")
        return self


class HiringLedger(StrictModel):
    role_ref: str | None = None
    headcount: int = Field(default=0, ge=0)
    filled: int = Field(default=0, ge=0)
    pay_rate: Decimal = Field(default=Decimal("0"), validate_default=True)
    pay_rate_uom: str | None = None
    commitment_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    monthly_burn_added: Decimal = Field(default=Decimal("0"), validate_default=True)
    period_ref: str | None = None
    envelope_digest: str | None = None
    requester_ref: str | None = None
    requested_at: str | None = None
    approved_at: str | None = None
    approval_ref: str | None = None
    approver_ref: str | None = None
    candidate_refs: tuple[str, ...] = Field(default_factory=tuple, max_length=2000)
    applications_digests: tuple[str, ...] = Field(default_factory=tuple, max_length=200)
    interviews: dict[str, int] = Field(default_factory=dict)
    recommendations: dict[str, str] = Field(default_factory=dict)
    offers: tuple[OfferRecord, ...] = Field(default_factory=tuple, max_length=60)
    open_offer_ref: str | None = None
    accepted_offer_refs: tuple[str, ...] = Field(default_factory=tuple, max_length=200)
    accepted_commitment: Decimal = Field(default=Decimal("0"), validate_default=True)
    accepted_sources: dict[str, dict[str, Any]] = Field(default_factory=dict)
    first_offer_at: str | None = None
    last_accepted_at: str | None = None
    withdraw_reason: str | None = None
    cancel_reason: str | None = None
    outcome: Literal["open", "filled", "withdrawn", "cancelled"] = "open"

    @field_validator("candidate_refs", "applications_digests", "accepted_offer_refs", "offers", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("pay_rate", "commitment_amount", "monthly_burn_added", "accepted_commitment", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @property
    def open_positions(self) -> int:
        return max(0, self.headcount - self.filled)


class HiringEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    offer_sent: Literal[False] = False
    employee_created: Literal[False] = False
    provider_read: Literal[False] = False


def _days(start: str | None, end: str) -> int:
    return 0 if start is None else (parsed(end) - parsed(start)).days


def _envelope_cover(plan: HiringChainPlan, envelope: Mapping[str, Any], monthly: Decimal) -> None:
    require(str(envelope.get("schema")) == BUDGET_ENVELOPE_SCHEMA, "ENVELOPE_NOT_SEALED", f"the budget envelope names itself {BUDGET_ENVELOPE_SCHEMA}")
    require(str(envelope.get("currency", "")).upper() == plan.currency, "ENVELOPE_CURRENCY_MISMATCH", f"the envelope is in {envelope.get('currency')}; the chain runs in {plan.currency}")
    status = str(envelope.get("status", "unknown"))
    require(status not in ("unknown", "danger"), "ENVELOPE_NOT_SPENDABLE", f"the runway envelope is {status}; no headcount is funded from it", "await_approval")
    affordable = envelope.get("affordable_incremental_monthly_burn")
    require(affordable is not None, "ENVELOPE_NOT_SPENDABLE", "the envelope states no affordable incremental monthly burn")
    require(decimal_value(affordable, field_name="affordable_incremental_monthly_burn") >= monthly, "HEADCOUNT_UNFUNDED", f"the request adds {monthly} {plan.currency} a month; the envelope affords {affordable}", "await_approval")


def _apply_hiring(plan: HiringChainPlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event, at = command.receipt, command.event, command.occurred_at
    if event == "request":
        require(r.role_ref is not None and r.headcount is not None and r.pay_rate is not None and r.pay_rate_uom is not None and r.requester_ref is not None, "REQUISITION_MISSING", "a requisition names the role, the headcount, the pay rate and its unit, and the requester")
        band = plan.band(str(r.role_ref))
        require(band is not None, "ROLE_UNBANDED", f"{r.role_ref} has no pay band in this plan")
        assert band is not None and r.pay_rate is not None and r.headcount is not None
        require(band.pay_rate_uom == r.pay_rate_uom, "PAY_UNIT_MISMATCH", f"{r.role_ref} is banded per {band.pay_rate_uom}, not per {r.pay_rate_uom}")
        require(band.min_amount <= r.pay_rate <= band.max_amount, "PAY_OUTSIDE_BAND", f"{r.pay_rate} is outside the {band.min_amount}-{band.max_amount} band for {r.role_ref}")
        commitment = (plan.annualised(r.pay_rate, str(r.pay_rate_uom)) * r.headcount).quantize(MONEY_QUANTUM)
        monthly = (commitment / _TWELVE).quantize(MONEY_QUANTUM)
        if plan.require_budget_cover:
            require(r.envelope_source is not None and r.envelope_digest == stable_digest(r.envelope_source), "ENVELOPE_NOT_SEALED", "a funded requisition retains the exact budget envelope it was checked against")
            _envelope_cover(plan, r.envelope_source or {}, monthly)
        data.update({"role_ref": r.role_ref, "headcount": r.headcount, "pay_rate": str(r.pay_rate), "pay_rate_uom": r.pay_rate_uom, "commitment_amount": str(commitment), "monthly_burn_added": str(monthly), "period_ref": r.period_ref, "envelope_digest": r.envelope_digest, "requester_ref": r.requester_ref, "requested_at": at})
    elif event == "approve":
        require(r.authorization_proof is not None, "REQUISITION_NOT_AUTHORIZED", f"opening {data['headcount']} position(s) commits {data['commitment_amount']} {plan.currency} a year of people_change authority; a human decides it", "await_approval")
        from lightbulb.authority_matrix import require_authorization_proof
        proof = require_authorization_proof(r.authorization_proof, category="people_change", amount=Decimal(str(data["commitment_amount"])), currency=plan.currency, command=command, plan_digest=plan.plan_digest, company_ref=plan.company_ref)
        require(proof.engine == HIRING_KIND, "APPROVAL_TRANSITION_MISMATCH", "the proof authorizes another engine")
        require(proof.approver_ref != data.get("requester_ref"), "SEGREGATION_VIOLATED", "the requester cannot approve their own requisition")
        data.update({"approved_at": at, "approval_ref": proof.approval_task_id, "approver_ref": proof.approver_ref})
    elif event == "source":
        require(r.applications_provenance is not None and r.applications_digest is not None and bool(r.candidate_refs), "APPLICATIONS_MISSING", "sourcing carries the ATS read provenance, its digest, and at least one candidate commitment")
        require(str(dict(r.applications_provenance or {}).get("output_digest")) == r.applications_digest, "APPLICATIONS_NOT_BOUND", "the provenance does not seal these applications")
        require(all(item.startswith("candidate:") and len(item) == 34 for item in r.candidate_refs), "CANDIDATE_REF_INVALID", "candidates are opaque commitments derived from application ids")
        require(r.applications_digest not in data.get("applications_digests", ()), "APPLICATIONS_ALREADY_SOURCED", "this applications read was already consumed")
        pool = list(dict.fromkeys([*data.get("candidate_refs", ()), *r.candidate_refs]))
        data.update({"candidate_refs": pool, "applications_digests": [*data.get("applications_digests", ()), r.applications_digest]})
    elif event == "interview":
        require(r.candidate_ref is not None and r.interviewer_ref is not None and r.scorecard_sha256 is not None and r.score is not None and r.recommendation is not None, "SCORECARD_MISSING", "an interview carries the candidate, the interviewer, the scorecard digest, the score, and the recommendation")
        require(r.candidate_ref in data.get("candidate_refs", ()), "CANDIDATE_UNKNOWN", f"{r.candidate_ref} is not in this requisition's pool")
        interviews = dict(data.get("interviews", {}))
        interviews[str(r.candidate_ref)] = int(interviews.get(str(r.candidate_ref), 0)) + 1
        recommendations = dict(data.get("recommendations", {}))
        recommendations[str(r.candidate_ref)] = str(r.recommendation)
        data.update({"interviews": interviews, "recommendations": recommendations})
    elif event == "extend_offer":
        require(r.candidate_ref is not None and r.offer_ref is not None and r.amount is not None and r.pay_rate_uom is not None and r.document_sha256 is not None and r.expires_at is not None, "OFFER_MISSING", "an offer names the candidate, the offer, the amount and its unit, the document digest, and the expiry")
        require(r.candidate_ref in data.get("candidate_refs", ()), "CANDIDATE_UNKNOWN", f"{r.candidate_ref} is not in this requisition's pool")
        require(int(dict(data.get("interviews", {})).get(str(r.candidate_ref), 0)) >= plan.min_interviews_before_offer, "INTERVIEWS_INSUFFICIENT", f"{r.candidate_ref} has fewer than {plan.min_interviews_before_offer} interview(s)")
        require(not plan.require_hire_recommendation or dict(data.get("recommendations", {})).get(str(r.candidate_ref)) == "hire", "NO_HIRE_RECOMMENDATION", f"the last scorecard for {r.candidate_ref} does not recommend hire")
        band = plan.band(str(data["role_ref"]))
        assert band is not None and r.amount is not None
        require(band.pay_rate_uom == r.pay_rate_uom and band.min_amount <= r.amount <= band.max_amount, "PAY_OUTSIDE_BAND", f"{r.amount} per {r.pay_rate_uom} is outside the band for {data['role_ref']}")
        require(plan.annualised(r.amount, str(r.pay_rate_uom)) <= plan.annualised(Decimal(str(data["pay_rate"])), str(data["pay_rate_uom"])), "OFFER_EXCEEDS_REQUISITION", "the offer exceeds the rate the requisition was funded at")
        require(r.offer_ref not in {str(dict(item).get("offer_ref")) for item in data.get("offers", ())}, "OFFER_DUPLICATE", f"offer {r.offer_ref} was already extended")
        require(data.get("open_offer_ref") is None, "OFFER_ALREADY_OPEN", f"offer {data.get('open_offer_ref')} is still open; a declined or expired offer is recorded first")
        require(int(data.get("filled", 0)) < int(data["headcount"]), "REQUISITION_FILLED", "every position on this requisition is filled")
        require(parsed(r.expires_at) > parsed(at) and (parsed(r.expires_at) - parsed(at)).days <= plan.offer_validity_days, "OFFER_EXPIRY_INVALID", f"an offer expires after it is extended and within {plan.offer_validity_days} days")
        require(_days(data.get("requested_at"), at) <= plan.max_days_requisition_to_offer, "REQUISITION_STALE", f"more than {plan.max_days_requisition_to_offer} days passed since the requisition; refund the envelope or re-approve", "manual_reconciliation")
        offer = OfferRecord(offer_ref=r.offer_ref, candidate_ref=r.candidate_ref, amount=r.amount, pay_rate_uom=r.pay_rate_uom, document_sha256=r.document_sha256, extended_at=at, expires_at=r.expires_at).to_dict()
        data.update({"offers": [*[dict(item) for item in data.get("offers", ())], offer], "open_offer_ref": r.offer_ref, "first_offer_at": data.get("first_offer_at") or at})
    elif event in ("accept_offer", "decline_offer"):
        offers = [dict(item) for item in data.get("offers", ())]
        current = next((item for item in offers if item["offer_ref"] == data.get("open_offer_ref")), None)
        require(current is not None and r.offer_ref == current["offer_ref"], "OFFER_NOT_OPEN", f"{r.offer_ref} is not the open offer on this requisition")
        assert current is not None
        if event == "decline_offer":
            current["status"] = "declined"
            data.update({"offers": offers, "open_offer_ref": None})
            return next_status, data
        require(r.accepted_at is not None and r.envelope_status is not None and r.envelope_document_sha256 is not None and r.application_source is not None and r.application_ref is not None and r.ats_status is not None, "ACCEPTANCE_MISSING", "an acceptance carries the time, the signed envelope, the application read, and the ATS status")
        assert r.accepted_at is not None
        require(parsed(current["extended_at"]) <= parsed(r.accepted_at) <= parsed(current["expires_at"]), "OFFER_EXPIRED", f"the offer expired at {current['expires_at']}")
        require(str(r.envelope_status) == "completed" and r.envelope_document_sha256 == current["document_sha256"], "OFFER_UNSIGNED", "acceptance needs the completed signing envelope of the exact offer document")
        require(str(r.ats_status) in ("hired", "offer_accepted"), "APPLICATION_NOT_ACCEPTED", f"the application is {r.ats_status}")
        source = dict(r.application_source or {})
        row = dict(source.get("row") or {})
        require(candidate_ref(str(row.get("id", ""))) == current["candidate_ref"], "CANDIDATE_MISMATCH", "the accepted application is not the offered candidate")
        current["status"] = "accepted"
        filled = int(data.get("filled", 0)) + 1
        accepted_sources = dict(data.get("accepted_sources", {}))
        accepted_sources[str(current["offer_ref"])] = {"application_source": source, "offer": dict(current)}
        data.update({"offers": offers, "open_offer_ref": None, "filled": filled, "accepted_offer_refs": [*data.get("accepted_offer_refs", ()), current["offer_ref"]], "accepted_commitment": str((Decimal(str(data["accepted_commitment"])) + plan.annualised(Decimal(str(current["amount"])), str(current["pay_rate_uom"]))).quantize(MONEY_QUANTUM)), "accepted_sources": accepted_sources, "last_accepted_at": r.accepted_at})
        if filled < int(data["headcount"]):
            return "interviewing", data
        data["outcome"] = "filled"
    elif event == "withdraw":
        data.update({"withdraw_reason": str(command.reason)[:300], "outcome": "withdrawn"})
    elif event == "cancel":
        data.update({"cancel_reason": str(command.reason)[:300], "outcome": "cancelled"})
    return next_status, data


HIRING_LIFECYCLE = LifecycleSpec(entity="requisition", schema_prefix=HIRING_KIND, statuses=HIRING_STATUSES, terminal=TERMINAL_HIRING_STATUSES, events=HIRING_EVENTS, table=_HIRING_TABLE, opening_event="request", reason_events=("decline_offer", "withdraw", "cancel"), apply=_apply_hiring, ledger_model=HiringLedger, receipt_model=HiringReceipt, effect_boundary_model=HiringEffectBoundary, plan_model=HiringChainPlan, max_transitions=MAX_HIRING_TRANSITIONS)
RequisitionState = HIRING_LIFECYCLE.State


def open_requisition(plan: HiringChainPlan | Mapping[str, Any], scope: Mapping[str, Any], *, receipt: Mapping[str, Any], opened_at: str, actor_ref: str) -> Any:
    return HIRING_LIFECYCLE.open(plan, scope, opened_at=opened_at, actor_ref=actor_ref, receipt=receipt)


def advance_requisition(plan: HiringChainPlan | Mapping[str, Any], state: Any, command: Any) -> Any:
    return HIRING_LIFECYCLE.advance(plan, state, command)


# --------------------------------------------------------------------------- #
# Receipts from the hops' sealed artifacts
# --------------------------------------------------------------------------- #


def _provenance(provenance: Mapping[str, Any] | Any, *, tools: frozenset[str], lanes: tuple[str, ...], code: str) -> dict[str, Any]:
    raw = dict(detached(provenance))
    _require(str(raw.get("source_tool", "")) in tools, code, f"expected a read from {sorted(tools)}, got {raw.get('source_tool')!r}")
    _require(str(raw.get("lane", "")) in lanes, code, f"a {raw.get('source_tool')} read arrives on {lanes}, not {raw.get('lane')!r}")
    for key in ("observation_ref", "provenance_digest", "output_digest", "completed_at"):
        _require(bool(raw.get(key)), code, f"the provenance lacks {key}")
    return raw


def headcount_receipt(plan: HiringChainPlan | Mapping[str, Any], *, role_ref: str, headcount: int, pay_rate: Any, pay_rate_uom: str, requester_ref: str, envelope: Mapping[str, Any] | Any | None = None, period_ref: str | None = None) -> dict[str, Any]:
    """The opening receipt: a banded role, the heads, the funded rate, and the sealed budget envelope it must fit."""

    parsed_plan = HiringChainPlan.model_validate(detached(plan))
    band = parsed_plan.band(role_ref)
    _require(band is not None, "ROLE_UNBANDED", f"{role_ref} has no pay band in this plan")
    rate = decimal_value(pay_rate, field_name="pay_rate")
    receipt: dict[str, Any] = {"role_ref": role_ref, "headcount": int(headcount), "pay_rate": str(rate), "pay_rate_uom": pay_rate_uom, "requester_ref": requester_ref, "period_ref": period_ref, "evidence_refs": [f"role:{role_ref}"]}
    if envelope is not None:
        raw = dict(detached(envelope))
        _require(str(raw.get("schema")) == BUDGET_ENVELOPE_SCHEMA, "ENVELOPE_NOT_SEALED", f"the budget envelope names itself {BUDGET_ENVELOPE_SCHEMA}")
        digest = stable_digest(raw)
        receipt.update({"envelope_source": raw, "envelope_digest": digest, "evidence_refs": [*receipt["evidence_refs"], f"envelope:{str(raw.get('envelope_ref') or digest[:16])}"]})
    else:
        _require(not parsed_plan.require_budget_cover, "ENVELOPE_NOT_SEALED", "this plan funds headcount only against a sealed budget envelope")
    return receipt


def approval_receipt(proof: Mapping[str, Any] | Any) -> dict[str, Any]:
    """From the platform's authorization proof; the proof is retained whole and re-verified against the consuming command."""

    from lightbulb.authority_matrix import authorization_evidence

    evidence = authorization_evidence(proof)
    return {"authorization_proof": evidence["authorization_proof"], "evidence_refs": list(evidence["evidence_refs"])}


def applications_receipt(provenance: Mapping[str, Any] | Any, applications: Sequence[Mapping[str, Any]] | Mapping[str, Any]) -> dict[str, Any]:
    """From a host-lane ATS applications read: one opaque candidate commitment per application id; identity is refused."""

    prov = _provenance(provenance, tools=APPLICATIONS_TOOLS, lanes=("host_read",), code="APPLICATIONS_NOT_BOUND")
    raw = detached(applications)
    rows = list(raw.get("applications") or raw.get("data") or []) if isinstance(raw, Mapping) else list(raw)
    _reject_identity(rows, path="applications")
    _require(str(prov["output_digest"]) == stable_digest(raw), "APPLICATIONS_NOT_BOUND", "the provenance does not seal these exact applications")
    ids = [str(dict(row).get("id") or "") for row in rows]
    _require(bool(ids) and all(ids), "APPLICATIONS_INCOMPLETE", "every application row names its id")
    refs = list(dict.fromkeys(candidate_ref(item) for item in ids))
    return {"applications_provenance": prov, "applications_digest": str(prov["output_digest"]), "candidate_refs": refs, "evidence_refs": [f"applications:{prov['observation_ref']}"]}


def interview_receipt(scorecard: Mapping[str, Any] | Any) -> dict[str, Any]:
    """From a self-naming scorecard: candidate commitment, interviewer, stage, score, recommendation, and the scorecard's digest."""

    raw = _reject_identity(dict(detached(scorecard)), path="scorecard")
    _require(str(raw.get("schema")) == SCORECARD_SCHEMA, "SCORECARD_SCHEMA_MISMATCH", f"a scorecard names itself {SCORECARD_SCHEMA}")
    for key in ("candidate_ref", "interviewer_ref", "stage", "score", "recommendation", "scorecard_sha256"):
        _require(raw.get(key) is not None, "SCORECARD_INCOMPLETE", f"the scorecard lacks {key}")
    _require(str(raw["recommendation"]) in ("hire", "no_hire", "hold"), "SCORECARD_INCOMPLETE", "recommendation is hire, no_hire, or hold")
    return {"candidate_ref": str(raw["candidate_ref"]), "interviewer_ref": str(raw["interviewer_ref"]), "stage": str(raw["stage"]), "score": int(raw["score"]), "recommendation": str(raw["recommendation"]), "scorecard_sha256": str(raw["scorecard_sha256"]), "evidence_refs": [f"scorecard:{str(raw['scorecard_sha256'])[:16]}"]}


def offer_receipt(*, candidate_ref: str, offer_ref: str, amount: Any, pay_rate_uom: str, document_sha256: str, expires_at: str) -> dict[str, Any]:
    """An offer as the operator extends it; the band, the interviews and the recommendation are checked by the guard."""

    return {"candidate_ref": candidate_ref, "offer_ref": offer_ref, "amount": str(decimal_value(amount, field_name="amount")), "pay_rate_uom": pay_rate_uom, "document_sha256": document_sha256, "expires_at": timestamp(expires_at, field_name="expires_at"), "evidence_refs": [f"offer:{offer_ref}"]}


def acceptance_receipt(provenance: Mapping[str, Any] | Any, application_row: Mapping[str, Any] | Any, *, offer_ref: str, accepted_at: str, envelope_row: Mapping[str, Any] | Any) -> dict[str, Any]:
    """From the ATS application row (``hired`` / ``offer_accepted``) and the completed signing envelope of the offer document."""

    prov = _provenance(provenance, tools=APPLICATION_TOOLS, lanes=("host_read",), code="APPLICATION_NOT_BOUND")
    row = _reject_identity(dict(detached(application_row)), path="application_row")
    _require(str(prov["output_digest"]) == stable_digest(row), "APPLICATION_NOT_BOUND", "the provenance does not seal this exact application row")
    _require(bool(row.get("id")) and bool(row.get("status")), "APPLICATION_INCOMPLETE", "an application row names its id and status")
    envelope = dict(detached(envelope_row))
    documents = [dict(item) for item in envelope.get("documents") or []]
    _require(len(documents) == 1 and bool(documents[0].get("document_sha256")), "OFFER_UNSIGNED", "the signing envelope carries exactly one document digest")
    return {"offer_ref": offer_ref, "accepted_at": timestamp(accepted_at, field_name="accepted_at"), "envelope_status": str(envelope.get("status", "")), "envelope_document_sha256": str(documents[0]["document_sha256"]), "application_source": {"provenance": prov, "row": row}, "application_ref": f"ats:application:{row['id']}", "ats_status": str(row["status"]), "evidence_refs": [f"application:{prov['observation_ref']}", f"envelope:{str(envelope.get('envelope_id_sha256') or stable_digest(envelope))[:16]}"]}


def employment_offer_receipt(state: Any, *, source_plan: Any, offer_ref: str | None = None) -> dict[str, Any]:
    """Replay an accepted requisition and hand the employment chain its opening receipt from the retained sources."""

    from lightbulb.employment_chain import OFFER_TERMS_SCHEMA
    from lightbulb.employment_chain import offer_receipt as employment_offer

    try:
        plan, source = HIRING_LIFECYCLE.bind(source_plan, state)
    except (ValueError, TypeError, KeyError) as exc:
        raise HiringChainError("HIRING_SOURCE_INVALID", "retain the original requisition state and its sealed plan") from exc
    _require(plan.schema_id == HIRING_PLAN_SCHEMA, "HIRING_SOURCE_INVALID", "the source must use the hiring plan schema")
    _require(bool(source.ledger.accepted_offer_refs), "OFFER_NOT_ACCEPTED", f"the requisition is {source.status} with no accepted offer")
    ref = offer_ref or source.ledger.accepted_offer_refs[-1]
    _require(ref in source.ledger.accepted_offer_refs, "OFFER_NOT_ACCEPTED", f"{ref} was not accepted on this requisition")
    retained = source.ledger.accepted_sources[ref]
    offer = dict(retained["offer"])
    application = dict(retained["application_source"])
    terms = {"schema": OFFER_TERMS_SCHEMA, "offer_ref": offer["offer_ref"], "amount": str(offer["amount"]), "pay_rate_uom": offer["pay_rate_uom"], "document_sha256": offer["document_sha256"]}
    receipt = employment_offer(application["provenance"], application["row"], offer_terms=terms)
    receipt["evidence_refs"] = [*receipt["evidence_refs"], f"requisition:{source.scope.entity_ref}:{source.state_digest[:16]}"]
    return receipt


def hiring_summary(states: Sequence[Any]) -> dict[str, Any]:
    """Open positions, filled positions, committed annual pay, and the median-free averages the operator asks for."""

    counts = {status: sum(1 for state in states if state.status == status) for status in HIRING_STATUSES}
    open_positions = sum(state.ledger.open_positions for state in states if state.status not in TERMINAL_HIRING_STATUSES)
    filled = sum(state.ledger.filled for state in states)
    offers = [offer for state in states for offer in state.ledger.offers]
    accepted = sum(1 for offer in offers if offer.status == "accepted")
    declined = sum(1 for offer in offers if offer.status == "declined")
    to_offer = [(parsed(state.ledger.first_offer_at) - parsed(state.ledger.requested_at)).days for state in states if state.ledger.first_offer_at and state.ledger.requested_at]
    committed = sum((state.ledger.accepted_commitment for state in states), Decimal("0")).quantize(MONEY_QUANTUM)
    funded = sum((state.ledger.commitment_amount for state in states if state.status not in TERMINAL_HIRING_STATUSES), Decimal("0")).quantize(MONEY_QUANTUM)
    return {"requisitions": len(states), "by_status": counts, "open_positions": open_positions, "filled_positions": filled, "offers_extended": len(offers), "offers_accepted": accepted, "offers_declined": declined, "acceptance_rate_percent": None if not (accepted + declined) else str((Decimal(accepted) / Decimal(accepted + declined) * 100).quantize(Decimal("0.01"))), "average_days_to_first_offer": None if not to_offer else str((Decimal(sum(to_offer)) / Decimal(len(to_offer))).quantize(Decimal("0.1"))), "accepted_annual_commitment": str(committed), "open_annual_commitment": str(funded)}


HIRING_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": HIRING_KIND,
    "golden_loop": HIRING_GOLDEN_LOOP,
    "stages": ["request", "approve", "source", "interview", "extend_offer", "accept_or_decline"],
    "statuses": list(HIRING_STATUSES),
    "events": list(HIRING_EVENTS),
    "hops": {"request": "pay band + sealed cash budget envelope", "approve": "people_change authorization proof for the exact annual commitment", "source": "host-lane ATS applications read", "interview": "self-naming scorecard digest", "extend_offer": "operator offer inside the band after the interview floor", "accept_offer": "ATS application row hired/offer_accepted + completed signing envelope of the offer document"},
    "required_connectors": ["greenhouse", "signing", "lightbulb.sdk_engine_state"],
    "hard_rules": [
        "a requisition is funded only when its added monthly burn fits the sealed budget envelope",
        "the approver of a requisition is never its requester; the proof is re-verified against the consuming command",
        "a person never enters the engine: candidates are digests of application ids and identity keys are refused",
        "an offer needs the plan's interview floor and a hire recommendation, and cannot exceed the funded rate",
        "the employment chain opens only from employment_offer_receipt of an accepted requisition",
    ],
}

__all__ = ["APPLICATIONS_TOOLS", "APPLICATION_TOOLS", "BUDGET_ENVELOPE_SCHEMA", "HIRING_EVENTS", "HIRING_GOLDEN_LOOP", "HIRING_KIND", "HIRING_LIFECYCLE", "HIRING_MANIFEST", "HIRING_STATUSES", "SCORECARD_SCHEMA", "TERMINAL_HIRING_STATUSES", "HiringChainError", "HiringChainPlan", "HiringLedger", "HiringReceipt", "OfferRecord", "PayBand", "RequisitionState", "acceptance_receipt", "advance_requisition", "applications_receipt", "approval_receipt", "candidate_ref", "compile_hiring_chain", "employment_offer_receipt", "headcount_receipt", "hiring_summary", "interview_receipt", "offer_receipt", "open_requisition"]
