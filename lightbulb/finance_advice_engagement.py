"""Engagement: what the client was given and agreed to before advice, the risk profile, the acknowledgement and the fee arrangement.

A regulator reads the engagement file first: which guide, notice or disclosure the client was
given before any advice, through which channel and when; the client's consent to the advice
process and to the collection of their information; for investments, a risk profile the client
can check because it is a fixed table of questions with a fixed score; the client's acknowledgement
of exactly which document (by digest) they received; and the fee arrangement with its anniversary,
because an ongoing fee needs renewed consent. This module writes that file down as sealed objects.

The SDK never holds a disclosure document's text, only its digest and the operator's title and
version. Identities are opaque refs and commitments; consent carries no signature, contact or
identity data. Channels are recorded, not used: nothing here sends anything to anyone. The
engagement gaps are what stops a case from opening; the presentation receipt binds the lifecycle's
``present`` event to the approved document and to an acknowledgement of that exact digest. Nothing
here recommends or advises.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import date, datetime, timedelta, timezone
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, CurrencyCode, OpaqueRef, Sha256Digest, ShortText, add_days, detached, parsed, seal, sealed_digest, skip_digests, timestamp
from lightbulb.finance_advice_identity import AdviceIdentityModel as StrictModel
from lightbulb.finance_advice_document import AdviceDocument

ENGAGEMENT_SCHEMA = "lightbulb.finance_advice_engagement_pack.v1"
ACKNOWLEDGEMENT_SCHEMA = "lightbulb.finance_advice_acknowledgement.v1"
FEE_ARRANGEMENT_SCHEMA = "lightbulb.finance_advice_fee_arrangement.v1"
RISK_PROFILE_SCHEMA = "lightbulb.finance_advice_risk_profile.v1"
DISCLOSURE_DOCUMENT_SCHEMA = "lightbulb.finance_advice_disclosure_document.v1"
FEE_CONSENT_RENEWAL_DAYS = 365
FORBIDDEN_CONSENT_KEYS = frozenset({"name", "email", "phone", "signature", "signature_image", "ip_address", "address", "date_of_birth"})
CA_MORTGAGE_BROKER_VERTICALS = frozenset({"CA-05"})

DisclosureKind = Literal["financial_services_guide", "credit_guide", "privacy_collection_notice", "engagement_letter", "fee_arrangement", "relationship_disclosure", "conflicts_disclosure", "complaints_information", "product_disclosure_statement", "key_facts_sheet"]
Channel = Literal["in_person", "email", "portal", "post", "phone_recorded", "video"]
ConsentScope = Literal["advice_process", "data_collection", "ongoing_service", "electronic_delivery", "data_retention"]
FeeKind = Literal["one_off", "ongoing"]
FeePeriod = Literal["once", "monthly", "annual"]

# which disclosures the client is given before advice, per jurisdiction and product family; a table, not an interpretation
REQUIRED_DISCLOSURES: dict[tuple[str, str], tuple[DisclosureKind, ...]] = {
    ("AU", "credit"): ("credit_guide", "privacy_collection_notice", "complaints_information"),
    ("AU", "deposits"): ("financial_services_guide", "privacy_collection_notice", "complaints_information"),
    ("AU", "insurance"): ("financial_services_guide", "privacy_collection_notice", "complaints_information"),
    ("AU", "investments"): ("financial_services_guide", "privacy_collection_notice", "complaints_information"),
    ("CA", "credit"): ("relationship_disclosure", "privacy_collection_notice", "complaints_information"),
    ("CA", "deposits"): ("relationship_disclosure", "conflicts_disclosure", "privacy_collection_notice", "complaints_information"),
    ("CA", "insurance"): ("relationship_disclosure", "conflicts_disclosure", "privacy_collection_notice", "complaints_information"),
    ("CA", "investments"): ("relationship_disclosure", "conflicts_disclosure", "privacy_collection_notice", "complaints_information"),
}
# disclosures owed at presentation, checked by the review's disclosures_current rather than by the engagement gate
PRESENTATION_STAGE_DISCLOSURES: dict[tuple[str, str], tuple[DisclosureKind, ...]] = {
    ("AU", "insurance"): ("product_disclosure_statement",),
    ("AU", "investments"): ("product_disclosure_statement",),
}
_ONGOING_FEE_FAMILIES = frozenset({"deposits", "insurance", "investments"})

# the fixed risk-profile table: seven questions, each answered 1..5, summed; the client can check every step
RISK_QUESTIONS: tuple[dict[str, Any], ...] = (
    {"key": "horizon", "question": "How long before you expect to need most of this money?", "options": {1: "under 2 years", 2: "2 to 4 years", 3: "5 to 7 years", 4: "8 to 12 years", 5: "more than 12 years"}},
    {"key": "loss_reaction", "question": "If the value of your investments fell by a fifth in one year, what would you do?", "options": {1: "sell everything", 2: "sell some", 3: "hold and wait", 4: "hold and consider adding", 5: "add more"}},
    {"key": "income_stability", "question": "How stable is the income you rely on?", "options": {1: "not stable; it could stop at any time", 2: "variable from month to month", 3: "mostly stable", 4: "stable with some growth", 5: "very stable and growing"}},
    {"key": "experience", "question": "Which investments have you held before?", "options": {1: "none, or deposits only", 2: "deposits and a managed fund", 3: "managed funds and some shares", 4: "shares, funds and property", 5: "shares, funds, property and other markets"}},
    {"key": "objective", "question": "What matters more to you: keeping what you have, or growing it?", "options": {1: "keeping every dollar", 2: "keeping most of it with a little growth", 3: "a balance of both", 4: "growth, accepting some falls", 5: "the highest growth over the long run"}},
    {"key": "reserve", "question": "How many months of expenses could you cover from savings without selling investments?", "options": {1: "under 1 month", 2: "1 to 3 months", 3: "3 to 6 months", 4: "6 to 12 months", 5: "more than 12 months"}},
    {"key": "volatility_tolerance", "question": "For an investment of 100,000, which range of one-year outcomes would you accept?", "options": {1: "down 2,000 to up 6,000", 2: "down 8,000 to up 14,000", 3: "down 15,000 to up 22,000", 4: "down 25,000 to up 33,000", 5: "down 35,000 to up 45,000"}},
)
RISK_ANSWER_MIN = 1
RISK_ANSWER_MAX = 5
# sum thresholds in ascending order; the band is the last threshold the score reaches; every band string is a key finance_advice_engine._RISK_PROFILE_MAX reads
RISK_BANDS: tuple[tuple[int, str], ...] = ((7, "conservative"), (13, "moderately conservative"), (19, "balanced"), (25, "growth"), (31, "high_growth"))
_RISK_KEYS: tuple[str, ...] = tuple(str(item["key"]) for item in RISK_QUESTIONS)
_RISK_SCORE_MIN = len(RISK_QUESTIONS) * RISK_ANSWER_MIN
_RISK_SCORE_MAX = len(RISK_QUESTIONS) * RISK_ANSWER_MAX
_CENTS = Decimal("0.01")
_ZERO = Decimal("0.00")
_MAX_AMOUNT = Decimal("1000000000000")
_MAX_WINDOW_DAYS = 36500


class AdviceEngagementError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise AdviceEngagementError(code, message)


def _tuple(value: Any) -> Any:
    return tuple(value) if isinstance(value, list) else value


def _money(value: Any, *, field_name: str) -> Decimal:
    if value is None or isinstance(value, (bool, float)):
        raise ValueError(f"{field_name} must be a decimal string, integer or Decimal")
    try:
        result = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"{field_name} must be a decimal") from exc
    if not result.is_finite() or result < 0 or result > _MAX_AMOUNT:
        raise ValueError(f"{field_name} must be a finite non-negative bounded amount")
    quantised = result.quantize(_CENTS, rounding=ROUND_HALF_UP)
    return _ZERO if quantised == 0 else quantised  # a signed zero serialises as 0.00, never -0.00


def _stamp_or_date(value: str, *, field_name: str) -> str:
    """An operator document date: a UTC timestamp, or a plain ISO date."""
    if isinstance(value, str) and "T" not in value:
        try:
            return date.fromisoformat(value).isoformat()
        except ValueError as exc:
            raise ValueError(f"{field_name} must be an ISO date or a UTC timestamp") from exc
    return timestamp(value, field_name=field_name)


def _moment(value: str, *, end_of_day: bool = False) -> datetime:
    """A stored date or timestamp as a UTC instant; a plain date is its midnight, or the next midnight when it closes a window."""
    if "T" in value:
        return parsed(value)
    day = datetime.combine(date.fromisoformat(value), datetime.min.time(), tzinfo=timezone.utc)
    return day + timedelta(days=1) if end_of_day else day


def _band_for(score: int) -> str:
    band = RISK_BANDS[0][1]
    for threshold, name in RISK_BANDS:
        if score >= threshold:
            band = name
    return band


def _refuse_identity(value: Any, *, what: str) -> Any:
    if isinstance(value, Mapping):
        bad = sorted(str(key) for key in value if str(key).lower() in FORBIDDEN_CONSENT_KEYS)
        if bad:
            raise ValueError(f"CONSENT_CARRIES_IDENTITY: {what} carries no identity, contact or signature data; identities are commitments: {', '.join(bad)}")
    return value


def _as_dict(value: Any) -> dict[str, Any]:
    return dict(detached(value))


def _late_events(prepared_at: str, *, given: Sequence[GivenDisclosure], consent: ConsentRecord, risk_profile: RiskProfile | None) -> list[str]:
    """What the pack would record as having happened after it was prepared; an engagement file never records its own future."""
    prepared = parsed(prepared_at)
    late = [f"{item.kind} given at {item.given_at}" for item in given if parsed(item.given_at) > prepared]
    if parsed(consent.consented_at) > prepared:
        late.append(f"consent given at {consent.consented_at}")
    if risk_profile is not None and parsed(risk_profile.answered_at) > prepared:
        late.append(f"risk profile answered at {risk_profile.answered_at}")
    return late


# --------------------------------------------------------------------------- #
# Disclosures given before advice
# --------------------------------------------------------------------------- #


class DisclosureDocument(StrictModel):
    """An operator document the client is given, known to the SDK only by its digest, title and version."""

    schema_id: str = Field(default=DISCLOSURE_DOCUMENT_SCHEMA, alias="schema")
    kind: DisclosureKind
    jurisdiction: Literal["AU", "CA"]
    title: ShortText
    version: ShortText
    document_digest: Sha256Digest
    issued_by_ref: OpaqueRef
    effective_from: str
    expires_at: str | None = None

    @field_validator("effective_from")
    @classmethod
    def _from(cls, value: str) -> str:
        return _stamp_or_date(value, field_name="effective_from")

    @field_validator("expires_at")
    @classmethod
    def _to(cls, value: str | None) -> str | None:
        return None if value is None else _stamp_or_date(value, field_name="expires_at")

    @model_validator(mode="after")
    def _window(self) -> DisclosureDocument:
        if self.expires_at is not None and _moment(self.expires_at, end_of_day=True) <= _moment(self.effective_from):
            raise ValueError("DOCUMENT_WINDOW_INVERTED: a document expires after it takes effect")
        return self


class GivenDisclosure(StrictModel):
    """One disclosure given to the client: which kind, which document digest, when, through which channel."""

    kind: DisclosureKind
    document_digest: Sha256Digest
    given_at: str
    channel: Channel
    acknowledgement_digest: Sha256Digest | None = None

    @field_validator("given_at")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="given_at")


class ConsentRecord(StrictModel):
    """What the client consented to, when and how; never who they are or how they signed."""

    scope: tuple[ConsentScope, ...] = Field(min_length=1)
    consented_at: str
    channel: Channel
    withdrawn_at: str | None = None
    statement: ShortText

    @model_validator(mode="before")
    @classmethod
    def _no_identity(cls, value: Any) -> Any:
        return _refuse_identity(value, what="a consent record")

    @field_validator("scope", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _tuple(value)

    @field_validator("consented_at")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="consented_at")

    @field_validator("withdrawn_at")
    @classmethod
    def _withdrawn(cls, value: str | None) -> str | None:
        return None if value is None else timestamp(value, field_name="withdrawn_at")

    @model_validator(mode="after")
    def _order(self) -> ConsentRecord:
        if self.withdrawn_at is not None and parsed(self.withdrawn_at) < parsed(self.consented_at):
            raise ValueError("CONSENT_WITHDRAWN_BEFORE_GIVEN: consent cannot be withdrawn before it was given")
        return self

    @property
    def active(self) -> bool:
        return self.withdrawn_at is None


def required_disclosures(jurisdiction: str, family: str, *, ongoing_fee: bool = False, vertical_id: str | None = None) -> tuple[DisclosureKind, ...]:
    """The disclosure kinds owed before advice for one jurisdiction and family; a family the table does not know owes nothing here."""
    kinds: list[DisclosureKind] = list(REQUIRED_DISCLOSURES.get((jurisdiction, family), ()))
    if ongoing_fee and jurisdiction == "AU" and family in _ONGOING_FEE_FAMILIES:
        kinds.append("fee_arrangement")
    if jurisdiction == "CA" and family == "credit" and vertical_id in CA_MORTGAGE_BROKER_VERTICALS:
        kinds.append("key_facts_sheet")
    return tuple(dict.fromkeys(kinds))


def _required_for(jurisdiction: str, family: str, verticals: Sequence[str], *, ongoing_fee: bool) -> tuple[DisclosureKind, ...]:
    """The table's union over the verticals, in table order, each kind once."""
    kinds: list[DisclosureKind] = []
    for vertical_id in verticals:
        kinds.extend(required_disclosures(jurisdiction, family, ongoing_fee=ongoing_fee, vertical_id=vertical_id))
    return tuple(dict.fromkeys(kinds))


def disclosure_document(kind: DisclosureKind, *, jurisdiction: str, title: str, version: str, document_digest: str, issued_by_ref: str, effective_from: str, expires_at: str | None = None) -> DisclosureDocument:
    """Register an operator document by digest; the SDK never holds its text."""
    return DisclosureDocument.model_validate({"kind": kind, "jurisdiction": jurisdiction, "title": title, "version": version, "document_digest": document_digest, "issued_by_ref": issued_by_ref, "effective_from": effective_from, "expires_at": expires_at})


def given_disclosure(document: DisclosureDocument | Mapping[str, Any], *, given_at: str, channel: Channel, acknowledgement: Acknowledgement | Mapping[str, Any] | None = None) -> GivenDisclosure:
    """Record that one registered document was given within the version's effective window; an acknowledgement, when present, must be of that document's digest and no earlier than the giving."""
    d = document if isinstance(document, DisclosureDocument) else DisclosureDocument.model_validate(_as_dict(document))
    ack = None if acknowledgement is None else acknowledgement if isinstance(acknowledgement, Acknowledgement) else Acknowledgement.model_validate(_as_dict(acknowledgement))
    at = timestamp(given_at, field_name="given_at")
    _require(parsed(at) >= _moment(d.effective_from), "DOCUMENT_NOT_EFFECTIVE", f"the {d.kind} version {d.version} takes effect at {d.effective_from}, after it was given at {at}")
    _require(d.expires_at is None or parsed(at) < _moment(d.expires_at, end_of_day=True), "DOCUMENT_EXPIRED", f"the {d.kind} version {d.version} expired at {d.expires_at}, before it was given at {at}")
    if ack is not None:
        _require(ack.document_digest == d.document_digest, "ACKNOWLEDGEMENT_MISMATCH", "the acknowledgement is of a different document digest")
        _require(parsed(ack.acknowledged_at) >= parsed(at), "ACKNOWLEDGEMENT_BEFORE_GIVEN", f"the document was given at {at}, after it was acknowledged at {ack.acknowledged_at}")
    return GivenDisclosure.model_validate({"kind": d.kind, "document_digest": d.document_digest, "given_at": at, "channel": channel, "acknowledgement_digest": ack.acknowledgement_digest if ack is not None else None})


# --------------------------------------------------------------------------- #
# The risk profile: a fixed, checkable table
# --------------------------------------------------------------------------- #


class RiskProfile(StrictModel):
    """The client's answers to the fixed table, their sum, and the band the engine reads."""

    schema_id: str = Field(default=RISK_PROFILE_SCHEMA, alias="schema")
    answers: dict[str, int]
    score: int = Field(ge=len(RISK_QUESTIONS) * RISK_ANSWER_MIN, le=len(RISK_QUESTIONS) * RISK_ANSWER_MAX)
    band: str
    answered_at: str
    profile_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("answered_at")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="answered_at")

    @model_validator(mode="after")
    def _seal(self, info: ValidationInfo) -> RiskProfile:
        if tuple(self.answers) != _RISK_KEYS:
            raise ValueError("RISK_ANSWERS_NOT_THE_TABLE: a profile answers exactly the fixed table's questions in its order")
        if any(isinstance(value, bool) or not RISK_ANSWER_MIN <= value <= RISK_ANSWER_MAX for value in self.answers.values()):
            raise ValueError(f"RISK_ANSWER_OUT_OF_RANGE: every answer is {RISK_ANSWER_MIN}..{RISK_ANSWER_MAX}")
        if self.score != sum(self.answers.values()):
            raise ValueError("RISK_SCORE_MISMATCH: the score is the sum of the answers")
        if self.band != _band_for(self.score):
            raise ValueError(f"RISK_BAND_MISMATCH: a score of {self.score} is the band {_band_for(self.score)}")
        if not skip_digests(info) and self.profile_digest != sealed_digest(RiskProfile, self, "profile_digest"):
            raise ValueError("profile_digest does not match the risk profile")
        return self


def risk_profile_questions() -> tuple[dict[str, Any], ...]:
    """The fixed table, copied so a caller cannot change it."""
    return tuple({"key": item["key"], "question": item["question"], "options": dict(item["options"]), "min": RISK_ANSWER_MIN, "max": RISK_ANSWER_MAX} for item in RISK_QUESTIONS)


def risk_band(score: int) -> str:
    """The band a summed score falls in; the last threshold the score reaches."""
    _require(isinstance(score, int) and not isinstance(score, bool) and _RISK_SCORE_MIN <= score <= _RISK_SCORE_MAX, "RISK_SCORE_OUT_OF_RANGE", f"a score sums {len(RISK_QUESTIONS)} answers of {RISK_ANSWER_MIN}..{RISK_ANSWER_MAX}")
    return _band_for(score)


def risk_profile(answers: Mapping[str, int], *, answered_at: str) -> RiskProfile:
    """Score the client's answers against the fixed table; every question answered, every answer in range."""
    unknown = sorted(str(key) for key in answers if str(key) not in _RISK_KEYS)
    _require(not unknown, "RISK_QUESTION_UNKNOWN", "the table has no question: " + ", ".join(unknown))
    missing = [key for key in _RISK_KEYS if key not in answers]
    _require(not missing, "RISK_ANSWER_MISSING", "every question is answered; missing: " + ", ".join(missing))
    scored: dict[str, int] = {}
    for key in _RISK_KEYS:
        value = answers[key]
        _require(isinstance(value, int) and not isinstance(value, bool) and RISK_ANSWER_MIN <= value <= RISK_ANSWER_MAX, "RISK_ANSWER_OUT_OF_RANGE", f"{key} is answered {RISK_ANSWER_MIN}..{RISK_ANSWER_MAX}, not {value!r}")
        scored[key] = value
    score = sum(scored.values())
    return seal(RiskProfile, {"answers": scored, "score": score, "band": risk_band(score), "answered_at": timestamp(answered_at, field_name="answered_at")}, "profile_digest")


# --------------------------------------------------------------------------- #
# Fee arrangements and their renewal
# --------------------------------------------------------------------------- #


class FeeArrangement(StrictModel):
    """What the client pays the adviser, for which services, from when; an ongoing fee carries its anniversary and renewal date."""

    schema_id: str = Field(default=FEE_ARRANGEMENT_SCHEMA, alias="schema")
    arrangement_ref: OpaqueRef
    kind: FeeKind
    amount: Decimal
    currency: CurrencyCode
    period: FeePeriod
    services: tuple[ShortText, ...] = Field(min_length=1)
    start_at: str
    anniversary_at: str | None = None
    renewal_due_at: str | None = None
    consent: ConsentRecord | None = None
    arrangement_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("amount", mode="before")
    @classmethod
    def _amount(cls, value: Any) -> Decimal:
        return _money(value, field_name="amount")

    @field_validator("services", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _tuple(value)

    @field_validator("start_at")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="start_at")

    @field_validator("anniversary_at", "renewal_due_at")
    @classmethod
    def _stamps(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _seal(self, info: ValidationInfo) -> FeeArrangement:
        if self.kind == "ongoing":
            if self.period == "once":
                raise ValueError("FEE_PERIOD_MISMATCH: an ongoing fee is monthly or annual, not once")
            if self.renewal_due_at is None or self.anniversary_at is None:
                raise ValueError("FEE_RENEWAL_UNSTATED: an ongoing fee carries its anniversary and renewal date")
            anniversary = add_days(self.start_at, FEE_CONSENT_RENEWAL_DAYS)
            if self.anniversary_at != anniversary:
                raise ValueError(f"FEE_ANNIVERSARY_MISMATCH: the anniversary is the start plus {FEE_CONSENT_RENEWAL_DAYS} days, {anniversary}")
            if parsed(self.renewal_due_at) > parsed(anniversary) or parsed(self.renewal_due_at) <= parsed(self.start_at):
                raise ValueError("FEE_RENEWAL_OUT_OF_WINDOW: renewal falls after the start and no later than the anniversary")
            if self.consent is not None and "ongoing_service" not in self.consent.scope:
                raise ValueError("FEE_CONSENT_SCOPE: the consent attached to an ongoing fee covers ongoing_service")
        else:
            if self.period != "once":
                raise ValueError("FEE_PERIOD_MISMATCH: a one-off fee is paid once")
            if self.renewal_due_at is not None or self.anniversary_at is not None:
                raise ValueError("FEE_RENEWAL_NOT_APPLICABLE: a one-off fee has no anniversary or renewal")
        if not skip_digests(info) and self.arrangement_digest != sealed_digest(FeeArrangement, self, "arrangement_digest"):
            raise ValueError("arrangement_digest does not match the fee arrangement")
        return self


def fee_arrangement(arrangement_ref: str, *, kind: FeeKind, amount: Decimal | str, currency: str, period: FeePeriod, services: Sequence[str], start_at: str, consent: ConsentRecord | Mapping[str, Any] | None = None) -> FeeArrangement:
    """Seal a fee arrangement; an ongoing one gets its anniversary and renewal date from the start plus the renewal period."""
    start = timestamp(start_at, field_name="start_at")
    anniversary = add_days(start, FEE_CONSENT_RENEWAL_DAYS) if kind == "ongoing" else None
    return seal(FeeArrangement, {"arrangement_ref": arrangement_ref, "kind": kind, "amount": amount, "currency": currency, "period": period, "services": list(services), "start_at": start, "anniversary_at": anniversary, "renewal_due_at": anniversary, "consent": _as_dict(consent) if consent is not None else None}, "arrangement_digest")


def fee_renewals_due(arrangements: Sequence[FeeArrangement | Mapping[str, Any]], *, as_of: str, within_days: int = 60) -> tuple[FeeArrangement, ...]:
    """The ongoing arrangements whose renewal falls on or before ``as_of`` plus the window, overdue ones included, earliest first."""
    _require(isinstance(within_days, int) and not isinstance(within_days, bool) and 0 <= within_days <= _MAX_WINDOW_DAYS, "WINDOW_OUT_OF_RANGE", f"the window is a whole number of days from as_of, 0..{_MAX_WINDOW_DAYS}")
    horizon = parsed(add_days(timestamp(as_of, field_name="as_of"), within_days))
    due: list[FeeArrangement] = []
    for item in arrangements:
        arrangement = item if isinstance(item, FeeArrangement) else FeeArrangement.model_validate(_as_dict(item))
        if arrangement.kind != "ongoing" or arrangement.renewal_due_at is None:
            continue
        if parsed(arrangement.renewal_due_at) <= horizon:
            due.append(arrangement)
    return tuple(sorted(due, key=lambda item: (item.renewal_due_at or "", item.arrangement_ref)))


# --------------------------------------------------------------------------- #
# The engagement pack and its gaps
# --------------------------------------------------------------------------- #


class EngagementPack(StrictModel):
    """The engagement file: disclosures given, consent, fee arrangement, risk profile, the scope, what is still missing."""

    schema_id: str = Field(default=ENGAGEMENT_SCHEMA, alias="schema")
    client_ref: OpaqueRef
    personal_data_sha256: Sha256Digest
    jurisdiction: Literal["AU", "CA"]
    family: str = Field(min_length=1)
    verticals: tuple[str, ...] = Field(min_length=1)
    objectives: dict[str, ShortText] = Field(default_factory=dict)
    given: tuple[GivenDisclosure, ...] = Field(default_factory=tuple)
    consent: ConsentRecord
    fee_arrangement: FeeArrangement | None = None
    risk_profile: RiskProfile | None = None
    scope_exclusions: tuple[ShortText, ...] = Field(default_factory=tuple)
    required: tuple[DisclosureKind, ...] = Field(default_factory=tuple)
    missing: tuple[DisclosureKind, ...] = Field(default_factory=tuple)
    complete: bool = False
    prepared_at: str
    engagement_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="before")
    @classmethod
    def _no_identity(cls, value: Any) -> Any:
        return _refuse_identity(value, what="an engagement pack")

    @field_validator("verticals", "given", "scope_exclusions", "required", "missing", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _tuple(value)

    @field_validator("prepared_at")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="prepared_at")

    @model_validator(mode="after")
    def _seal(self, info: ValidationInfo) -> EngagementPack:
        if (self.jurisdiction, self.family) not in REQUIRED_DISCLOSURES:
            raise ValueError(f"FAMILY_UNKNOWN: the disclosure table has no row for {self.jurisdiction}/{self.family}")
        if len(set(self.verticals)) != len(self.verticals):
            raise ValueError("VERTICALS_DUPLICATE: an engagement names each vertical once")
        stray = sorted(key for key in self.objectives if key not in self.verticals)
        if stray:
            raise ValueError("OBJECTIVE_VERTICAL_UNKNOWN: objectives are keyed by the engagement's verticals, not " + ", ".join(stray))
        late = _late_events(self.prepared_at, given=self.given, consent=self.consent, risk_profile=self.risk_profile)
        if late:
            raise ValueError(f"ENGAGEMENT_EVENT_AFTER_PREPARED: a pack prepared at {self.prepared_at} records nothing that happened later: " + "; ".join(late))
        required = _required_for(self.jurisdiction, self.family, self.verticals, ongoing_fee=self.fee_arrangement is not None and self.fee_arrangement.kind == "ongoing")
        missing = tuple(kind for kind in required if kind not in self.given_kinds())
        if self.required != required or self.missing != missing or self.complete != (not missing):
            raise ValueError("ENGAGEMENT_DERIVED_MISMATCH: required, missing and complete follow from the table, the verticals, the fee and what was given")
        if not skip_digests(info) and self.engagement_digest != sealed_digest(EngagementPack, self, "engagement_digest"):
            raise ValueError("engagement_digest does not match the engagement pack")
        return self

    def given_kinds(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(item.kind for item in self.given))


def engagement_pack(client_ref: str, *, personal_data_sha256: str, jurisdiction: str, family: str, verticals: Sequence[str], objectives: Mapping[str, str], given: Sequence[GivenDisclosure | Mapping[str, Any]], consent: ConsentRecord | Mapping[str, Any], fee_arrangement: FeeArrangement | Mapping[str, Any] | None = None, risk_profile: RiskProfile | Mapping[str, Any] | None = None, scope_exclusions: Sequence[str] = (), prepared_at: str) -> EngagementPack:
    """Seal the engagement file; ``required`` is the table's union over the verticals, ``missing`` what was not given; nothing in it happened after ``prepared_at``."""
    _require(len(verticals) > 0, "VERTICALS_UNSTATED", "an engagement names at least one vertical")
    _require(len(set(verticals)) == len(verticals), "VERTICALS_DUPLICATE", "an engagement names each vertical once")
    _require((jurisdiction, family) in REQUIRED_DISCLOSURES, "FAMILY_UNKNOWN", f"the disclosure table has no row for {jurisdiction}/{family}; an engagement never owes nothing by accident")
    stray = sorted(str(key) for key in objectives if str(key) not in verticals)
    _require(not stray, "OBJECTIVE_VERTICAL_UNKNOWN", "objectives are keyed by the engagement's verticals, not " + ", ".join(stray))
    fee = fee_arrangement if isinstance(fee_arrangement, FeeArrangement) or fee_arrangement is None else FeeArrangement.model_validate(_as_dict(fee_arrangement))
    required_unique = _required_for(jurisdiction, family, verticals, ongoing_fee=fee is not None and fee.kind == "ongoing")
    items = [item if isinstance(item, GivenDisclosure) else GivenDisclosure.model_validate(_as_dict(item)) for item in given]
    agreed = consent if isinstance(consent, ConsentRecord) else ConsentRecord.model_validate(_as_dict(consent))
    profile = risk_profile if isinstance(risk_profile, RiskProfile) or risk_profile is None else RiskProfile.model_validate(_as_dict(risk_profile))
    at = timestamp(prepared_at, field_name="prepared_at")
    late = _late_events(at, given=items, consent=agreed, risk_profile=profile)
    _require(not late, "ENGAGEMENT_EVENT_AFTER_PREPARED", f"a pack prepared at {at} records nothing that happened later: " + "; ".join(late))
    given_kinds = {item.kind for item in items}
    missing = tuple(kind for kind in required_unique if kind not in given_kinds)
    return seal(EngagementPack, {
        "client_ref": client_ref,
        "personal_data_sha256": personal_data_sha256,
        "jurisdiction": jurisdiction,
        "family": family,
        "verticals": list(verticals),
        "objectives": {str(key): value for key, value in objectives.items()},
        "given": [item.to_dict() for item in items],
        "consent": agreed.to_dict(),
        "fee_arrangement": fee.to_dict() if fee is not None else None,
        "risk_profile": profile.to_dict() if profile is not None else None,
        "scope_exclusions": list(scope_exclusions),
        "required": list(required_unique),
        "missing": list(missing),
        "complete": not missing,
        "prepared_at": at,
    }, "engagement_digest")


def engagement_gaps(pack: EngagementPack | Mapping[str, Any], *, vertical_id: str | None = None) -> tuple[str, ...]:
    """What stops a case from opening on this engagement; an empty tuple means nothing does."""
    p = pack if isinstance(pack, EngagementPack) else EngagementPack.model_validate(_as_dict(pack))
    gaps: list[str] = [f"disclosure not given: {kind}" for kind in p.missing]
    if "advice_process" not in p.consent.scope:
        gaps.append("consent to the advice process not recorded")
    if p.consent.withdrawn_at is not None:
        gaps.append(f"consent withdrawn at {p.consent.withdrawn_at}")
    ongoing_consented = "ongoing_service" in p.consent.scope
    if ongoing_consented and (p.fee_arrangement is None or p.fee_arrangement.kind != "ongoing"):
        gaps.append("ongoing service consented but no ongoing fee arrangement stated")
    if p.fee_arrangement is not None and p.fee_arrangement.kind == "ongoing" and not ongoing_consented:
        gaps.append("an ongoing fee arrangement is stated without consent to ongoing service")
    if p.fee_arrangement is not None and p.fee_arrangement.consent is not None and p.fee_arrangement.consent.withdrawn_at is not None:
        gaps.append(f"consent to the fee arrangement withdrawn at {p.fee_arrangement.consent.withdrawn_at}")
    if vertical_id is not None and vertical_id not in p.verticals:
        gaps.append(f"vertical {vertical_id} is not in the engagement's scope")
    wanted = (vertical_id,) if vertical_id is not None else p.verticals
    for item in wanted:
        if item not in p.objectives:
            gaps.append(f"objective not stated for {item}")
    if p.family == "investments" and p.risk_profile is None:
        gaps.append("risk profile not recorded for investments")
    return tuple(gaps)


def engagement_receipt(pack: EngagementPack | Mapping[str, Any]) -> dict[str, Any]:
    """What the lifecycle's open receipt carries from the engagement: its digest and the evidence ref; refuses on any gap."""
    p = pack if isinstance(pack, EngagementPack) else EngagementPack.model_validate(_as_dict(pack))
    gaps = engagement_gaps(p)
    _require(not gaps, "ENGAGEMENT_INCOMPLETE", "; ".join(gaps))
    return {"engagement_digest": p.engagement_digest, "evidence_refs": [f"engagement:{p.engagement_digest}"]}


# --------------------------------------------------------------------------- #
# The client's acknowledgement and the presentation receipt
# --------------------------------------------------------------------------- #


class Acknowledgement(StrictModel):
    """The client acknowledged receipt of exactly one document, by digest; the client is a commitment."""

    schema_id: str = Field(default=ACKNOWLEDGEMENT_SCHEMA, alias="schema")
    client_ref: OpaqueRef
    personal_data_sha256: Sha256Digest
    document_digest: Sha256Digest
    document_kind: str = Field(min_length=1)
    acknowledged_at: str
    channel: Channel
    warnings_acknowledged: tuple[ShortText, ...] = Field(default_factory=tuple)
    statement: ShortText = "The client acknowledged receipt of the document with this digest"
    acknowledgement_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="before")
    @classmethod
    def _no_identity(cls, value: Any) -> Any:
        return _refuse_identity(value, what="an acknowledgement")

    @field_validator("warnings_acknowledged", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _tuple(value)

    @field_validator("acknowledged_at")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="acknowledged_at")

    @model_validator(mode="after")
    def _seal(self, info: ValidationInfo) -> Acknowledgement:
        if not skip_digests(info) and self.acknowledgement_digest != sealed_digest(Acknowledgement, self, "acknowledgement_digest"):
            raise ValueError("acknowledgement_digest does not match the acknowledgement")
        return self


def _document_identity(document: Any) -> tuple[str, str]:
    d = _refuse_identity(_as_dict(document), what="a document")
    digest = d.get("document_digest")
    _require(isinstance(digest, str) and len(digest) == 64, "DOCUMENT_DIGEST_MISSING", "a document is acknowledged by its digest")
    kind = d.get("kind") or d.get("document_kind")
    _require(isinstance(kind, str) and bool(kind), "DOCUMENT_KIND_MISSING", "a document names its kind")
    return str(digest), str(kind)


def acknowledge(document: Any, *, client_ref: str, personal_data_sha256: str, acknowledged_at: str, channel: Channel, warnings_acknowledged: Sequence[str] = ()) -> Acknowledgement:
    """Seal the client's acknowledgement of one document (an advice document or a disclosure document) by its digest."""
    digest, kind = _document_identity(document)
    return seal(Acknowledgement, {"client_ref": client_ref, "personal_data_sha256": personal_data_sha256, "document_digest": digest, "document_kind": kind, "acknowledged_at": timestamp(acknowledged_at, field_name="acknowledged_at"), "channel": channel, "warnings_acknowledged": list(warnings_acknowledged)}, "acknowledgement_digest")


def presentation_receipt(document: Any, acknowledgement: Acknowledgement | Mapping[str, Any], *, explanation_digest: str | None = None) -> dict[str, Any]:
    """The lifecycle's present receipt: the approved document's record digest and the acknowledgement of that exact document.

    A draft document (its watermark says it is not advice) is refused; so is an acknowledgement of
    any other digest. The SDK sends nothing: the acknowledgement was recorded by the operator.
    """
    d = _as_dict(document)
    a = acknowledgement if isinstance(acknowledgement, Acknowledgement) else Acknowledgement.model_validate(_as_dict(acknowledgement))
    digest, kind = _document_identity(d)
    _require(kind == "record_of_advice_evidence", "PRESENT_KIND_REFUSED", f"presentation cites the record of advice document, not a {kind}")
    rendered = document if isinstance(document, AdviceDocument) else AdviceDocument.model_validate(d)  # the seal proves the completeness flag was not edited
    _require(rendered.complete is True, "PRESENT_DRAFT_REFUSED", "the document is draft evidence, not advice; the adviser's approval comes first")
    record_digest = rendered.record_digest
    _require(isinstance(record_digest, str) and len(record_digest) == 64, "RECORD_DIGEST_MISSING", "the document carries the record digest it renders")
    _require(a.document_digest == digest, "ACKNOWLEDGEMENT_MISMATCH", f"the acknowledgement is of document {a.document_digest[:16]}, not {digest[:16]}")
    _require(parsed(a.acknowledged_at) >= parsed(rendered.prepared_at), "ACKNOWLEDGEMENT_BEFORE_DOCUMENT", f"the document was prepared at {rendered.prepared_at}, after the acknowledgement at {a.acknowledged_at}")
    if explanation_digest is not None:
        _require(isinstance(explanation_digest, str) and len(explanation_digest) == 64, "EXPLANATION_DIGEST_INVALID", "an explanation is cited by its sha256 digest")
    refs = [f"document:{digest}", f"ack:{a.acknowledgement_digest}"] + ([f"explanation:{explanation_digest}"] if explanation_digest else [])
    return {"statement_digest": record_digest, "document_digest": digest, "client_acknowledgement_ref": f"ack:{a.acknowledgement_digest}", "explanation_digest": explanation_digest, "evidence_refs": refs}


ENGAGEMENT_MANIFEST: dict[str, Any] = {
    "schemas": {"engagement_pack": ENGAGEMENT_SCHEMA, "acknowledgement": ACKNOWLEDGEMENT_SCHEMA, "fee_arrangement": FEE_ARRANGEMENT_SCHEMA, "risk_profile": RISK_PROFILE_SCHEMA, "disclosure_document": DISCLOSURE_DOCUMENT_SCHEMA},
    "required_disclosures": {f"{jurisdiction}/{family}": list(kinds) for (jurisdiction, family), kinds in REQUIRED_DISCLOSURES.items()},
    "conditional_disclosures": {"fee_arrangement": "AU deposits, insurance and investments when the fee is ongoing", "key_facts_sheet": "CA credit on " + ", ".join(sorted(CA_MORTGAGE_BROKER_VERTICALS))},
    "presentation_stage_disclosures": {f"{jurisdiction}/{family}": list(kinds) for (jurisdiction, family), kinds in PRESENTATION_STAGE_DISCLOSURES.items()},
    "gaps": ["disclosure not given", "consent to the advice process not recorded", "consent withdrawn", "ongoing service without an ongoing fee arrangement", "ongoing fee without consent to ongoing service", "consent to the fee arrangement withdrawn", "objective not stated for a vertical", "risk profile not recorded for investments"],
    "risk_profile": {"questions": [item["key"] for item in RISK_QUESTIONS], "answer_range": [RISK_ANSWER_MIN, RISK_ANSWER_MAX], "bands": [{"from_score": threshold, "band": name} for threshold, name in RISK_BANDS], "read_by": "finance_advice_engine._RISK_PROFILE_MAX through ClientState.facts['risk_profile']"},
    "fee_renewal_days": FEE_CONSENT_RENEWAL_DAYS,
    "forbidden_keys": sorted(FORBIDDEN_CONSENT_KEYS),
    "refusals": ["VERTICALS_UNSTATED", "VERTICALS_DUPLICATE", "FAMILY_UNKNOWN", "OBJECTIVE_VERTICAL_UNKNOWN", "ENGAGEMENT_INCOMPLETE", "ENGAGEMENT_DERIVED_MISMATCH", "ENGAGEMENT_EVENT_AFTER_PREPARED", "CONSENT_CARRIES_IDENTITY", "CONSENT_WITHDRAWN_BEFORE_GIVEN", "DOCUMENT_WINDOW_INVERTED", "DOCUMENT_NOT_EFFECTIVE", "DOCUMENT_EXPIRED", "DOCUMENT_DIGEST_MISSING", "DOCUMENT_KIND_MISSING", "ACKNOWLEDGEMENT_MISMATCH", "ACKNOWLEDGEMENT_BEFORE_GIVEN", "ACKNOWLEDGEMENT_BEFORE_DOCUMENT", "RISK_QUESTION_UNKNOWN", "RISK_ANSWER_MISSING", "RISK_ANSWER_OUT_OF_RANGE", "RISK_ANSWERS_NOT_THE_TABLE", "RISK_SCORE_OUT_OF_RANGE", "RISK_SCORE_MISMATCH", "RISK_BAND_MISMATCH", "FEE_PERIOD_MISMATCH", "FEE_RENEWAL_UNSTATED", "FEE_RENEWAL_NOT_APPLICABLE", "FEE_ANNIVERSARY_MISMATCH", "FEE_RENEWAL_OUT_OF_WINDOW", "FEE_CONSENT_SCOPE", "WINDOW_OUT_OF_RANGE", "PRESENT_KIND_REFUSED", "PRESENT_DRAFT_REFUSED", "RECORD_DIGEST_MISSING", "EXPLANATION_DIGEST_INVALID"],
    "presentation": "cites the approved record document only and an acknowledgement of that exact digest; a draft is refused",
    "not_claimed": "the engagement file records what was given and agreed; the SDK holds no document text, sends nothing to the client and advises nothing",
}

__all__ = [
    "ACKNOWLEDGEMENT_SCHEMA",
    "CA_MORTGAGE_BROKER_VERTICALS",
    "DISCLOSURE_DOCUMENT_SCHEMA",
    "ENGAGEMENT_MANIFEST",
    "ENGAGEMENT_SCHEMA",
    "FEE_ARRANGEMENT_SCHEMA",
    "FEE_CONSENT_RENEWAL_DAYS",
    "FORBIDDEN_CONSENT_KEYS",
    "PRESENTATION_STAGE_DISCLOSURES",
    "REQUIRED_DISCLOSURES",
    "RISK_ANSWER_MAX",
    "RISK_ANSWER_MIN",
    "RISK_BANDS",
    "RISK_PROFILE_SCHEMA",
    "RISK_QUESTIONS",
    "Acknowledgement",
    "AdviceEngagementError",
    "Channel",
    "ConsentRecord",
    "ConsentScope",
    "DisclosureDocument",
    "DisclosureKind",
    "EngagementPack",
    "FeeArrangement",
    "GivenDisclosure",
    "RiskProfile",
    "acknowledge",
    "disclosure_document",
    "engagement_gaps",
    "engagement_pack",
    "engagement_receipt",
    "fee_arrangement",
    "fee_renewals_due",
    "given_disclosure",
    "presentation_receipt",
    "required_disclosures",
    "risk_band",
    "risk_profile",
    "risk_profile_questions",
]
