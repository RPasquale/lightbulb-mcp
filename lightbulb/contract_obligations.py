"""Deterministic contract-obligation domain models and mechanics.

This module turns one exact approved agreement version into typed, digest-bound
obligation artifacts: clause-cited obligation candidates are normalized into a
register candidate, a reviewed register is compiled into a bounded dated
schedule, retained evidence is evaluated against exact fulfillment criteria,
one obligation instance advances through an immutable, replay-fenced transition
history, and a portfolio of instances is assessed effect-dark.

It never decides that a clause is legally binding, declares breach, waives an
obligation, contacts a counterparty, pays money, authenticates an actor,
approves anything, persists anything, or invokes a connector.  Spring remains
authoritative for identity, RBAC, the obligation register of record, review and
approval, evidence custody, persistence, schedules, and every external effect.
The legal/commercial agent interprets clauses and proposes; this module only
validates, schedules, evaluates, and proposes typed candidates.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from datetime import date, datetime, time, timedelta, timezone
from decimal import Decimal, InvalidOperation
from typing import Annotated, Any, Literal
from uuid import UUID
from functools import lru_cache
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError, available_timezones

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationInfo,
    field_validator,
    model_validator,
)

from lightbulb.primitive_runtime import (
    PrimitiveEvidenceClassification,
    PrimitiveEvidenceRef,
    PrimitiveEvidenceVerificationGrade,
)


CONTRACT_OBLIGATION_GOLDEN_LOOP = (
    "legal.approved_contract_obligation_to_verified_fulfillment@0.1.0"
)
CONTRACT_OBLIGATION_SCOPE_SCHEMA = "lightbulb.contract_obligation_scope.v1"
AGREEMENT_VERSION_SCHEMA = "lightbulb.contract_agreement_version.v1"
CLAUSE_LOCATOR_SCHEMA = "lightbulb.contract_clause_locator.v1"
OBLIGATION_DEFINITION_SCHEMA = "lightbulb.contract_obligation_definition.v1"
OBLIGATION_CANDIDATE_SCHEMA = "lightbulb.contract_obligation_candidate.v1"
OBLIGATION_REGISTER_SCHEMA = "lightbulb.contract_obligation_register.v1"
OBLIGATION_SCHEDULE_SCHEMA = "lightbulb.contract_obligation_schedule.v1"
OBLIGATION_INSTANCE_SCHEMA = "lightbulb.contract_obligation_instance.v1"
OBLIGATION_EVIDENCE_SCHEMA = "lightbulb.contract_obligation_evidence_envelope.v1"
OBLIGATION_EVALUATION_SCHEMA = "lightbulb.contract_obligation_fulfillment_evaluation.v1"
OBLIGATION_COMMAND_SCHEMA = "lightbulb.contract_obligation_transition_command.v1"
OBLIGATION_SNAPSHOT_SCHEMA = "lightbulb.contract_obligation_instance_snapshot.v1"
OBLIGATION_RECEIPT_SCHEMA = "lightbulb.contract_obligation_transition_receipt.v1"
OBLIGATION_TRANSITION_RESULT_SCHEMA = "lightbulb.contract_obligation_transition_result.v1"
OBLIGATION_PORTFOLIO_SCHEMA = "lightbulb.contract_obligation_portfolio_assessment.v1"

GENESIS_STATE_DIGEST = "0" * 64
MAX_OBLIGATION_TRANSITIONS = 8
MAX_SCHEDULE_HORIZON_DAYS = 731
MAX_INSTANCES_PER_OBLIGATION = 400
MAX_SCHEDULE_INSTANCES = 5000
MAX_REGISTER_DEFINITIONS = 500
MAX_PORTFOLIO_INSTANCES = 2000
MAX_EVIDENCE_PER_COMMAND = 40

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}$"
_TIMEZONE_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_+\-/]{0,63}$")
_LOCAL_TIME_PATTERN = re.compile(r"^([01][0-9]|2[0-3]):[0-5][0-9]$")
_DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_CURRENCY_PATTERN = r"^[A-Z]{3}$"

# Model-supplied payloads may never carry raw credentials or tenant authority.
_SECRET_LIKE_KEYS = (
    "secret",
    "password",
    "passwd",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "credential",
    "private_key",
    "client_secret",
    "tenant_id",
    "company_id",
    "user_id",
)
_SECRET_LIKE_VALUE_PATTERNS = (
    re.compile(r"^(sk|rk|pk)_(live|test)_[A-Za-z0-9]{8,}"),
    re.compile(r"^AKIA[0-9A-Z]{16}$"),
    re.compile(r"^(xox[abprs]-|ghp_|gho_|github_pat_|glpat-)[A-Za-z0-9_-]{8,}"),
    re.compile(r"^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"^(Bearer|Basic) [A-Za-z0-9._~+/=-]{8,}$", re.IGNORECASE),
)


def _reject_secret_like_text(value: str, *, label: str) -> None:
    for pattern in _SECRET_LIKE_VALUE_PATTERNS:
        if pattern.search(value):
            raise ValueError(f"{label} must not carry credential-like material")


def _reject_secret_like_payload(value: Any, *, path: str = "input") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            key_text = str(key)
            lowered = key_text.lower()
            if any(marker in lowered for marker in _SECRET_LIKE_KEYS):
                raise ValueError(
                    f"{path}.{key_text} is a credential-like or authority-like field "
                    "and is never accepted"
                )
            _reject_secret_like_payload(item, path=f"{path}.{key_text}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _reject_secret_like_payload(item, path=f"{path}[{index}]")
    elif isinstance(value, str):
        _reject_secret_like_text(value, label=path)


def _visible_ref(value: str) -> str:
    if value != value.strip() or any(ord(character) < 33 for character in value):
        raise ValueError("references must contain visible non-whitespace characters")
    _reject_secret_like_text(value, label="reference")
    return value


OpaqueRef = Annotated[
    str,
    StringConstraints(pattern=_REF_PATTERN),
    AfterValidator(_visible_ref),
]
Sha256Digest = Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)]
CurrencyCode = Annotated[str, StringConstraints(pattern=_CURRENCY_PATTERN)]
BoundedText = Annotated[str, StringConstraints(min_length=1, max_length=500)]
ShortText = Annotated[str, StringConstraints(min_length=1, max_length=200)]

ObligationKind = Literal[
    "monetary",
    "service",
    "notice",
    "reporting",
    "compliance",
    "delivery",
    "acceptance",
    "restriction",
]
ObligationDirection = Literal["owed_by_company", "owed_to_company"]
Materiality = Literal["low", "medium", "high", "critical"]
DueRuleKind = Literal["fixed_date", "relative_to_agreement", "recurring"]
RelativeAnchor = Literal["agreement_effective_at", "agreement_expires_at"]
RecurrenceFrequency = Literal["daily", "weekly", "monthly", "quarterly", "annually"]
CalendarRoll = Literal["none", "following", "preceding", "modified_following"]
ActivationKind = Literal["unconditional", "on_event", "on_dependency_fulfilled"]
CriterionMeasure = Literal["presence", "quantity"]
EvidenceAssertion = Literal["satisfied", "not_satisfied"]
FulfillmentVerdict = Literal[
    "verified",
    "incomplete",
    "conflicting",
    "stale",
    "indeterminate",
]
CriterionFindingStatus = Literal[
    "satisfied",
    "partial",
    "missing",
    "stale",
    "conflicting",
    "not_satisfied",
    "indeterminate",
]
EvidenceExclusionReason = Literal[
    "cross_obligation_evidence",
    "unknown_criterion",
    "observed_before_period",
    "observed_after_as_of",
    "stale_beyond_freshness",
    "grade_below_minimum",
]
ObligationInstanceStatus = Literal[
    "scheduled",
    "evidence_pending",
    "fulfilled_verified",
    "exception_open",
    "superseded",
    "escalated_unresolved",
    "authoritative_change_required",
]
TransitionKind = Literal[
    "open_evidence_window",
    "record_fulfillment",
    "open_exception",
    "cure_exception",
    "supersede",
    "escalate",
    "require_authoritative_change",
]
ExceptionCode = Literal[
    "partial_fulfillment",
    "evidence_unavailable",
    "counterparty_delay",
    "internal_delay",
    "disputed_scope",
    "force_majeure_claimed",
]
EscalationReason = Literal[
    "overdue_beyond_policy",
    "exception_cure_missed",
    "dependency_unresolved",
    "repeated_exception",
]
AuthoritativeChangeReason = Literal[
    "waiver_requested",
    "amendment_required",
    "scope_dispute",
    "counterparty_breach_alleged",
    "evidence_custody_failure",
    "no_successor_registered",
]
CandidateRejectionCode = Literal[
    "clause_not_found",
    "clause_digest_mismatch",
    "duplicate_obligation_ref",
    "duplicate_definition",
    "dependency_unresolved",
    "dependency_cycle",
    "supersession_target_unknown",
    "supersession_conflict",
    "supersession_requires_amendment",
    "obligation_ref_collides_with_prior",
]
RecoveryDisposition = Literal[
    "not_required",
    "do_not_replay",
    "refresh_snapshot",
    "correct_input",
    "manual_reconciliation",
]

TERMINAL_INSTANCE_STATUSES: frozenset[str] = frozenset(
    {
        "fulfilled_verified",
        "superseded",
        "escalated_unresolved",
        "authoritative_change_required",
    }
)
_TRANSITIONS: dict[str, dict[str, str]] = {
    "scheduled": {
        "open_evidence_window": "evidence_pending",
        "record_fulfillment": "fulfilled_verified",
        "open_exception": "exception_open",
        "supersede": "superseded",
        "escalate": "escalated_unresolved",
        "require_authoritative_change": "authoritative_change_required",
    },
    "evidence_pending": {
        "record_fulfillment": "fulfilled_verified",
        "open_exception": "exception_open",
        "supersede": "superseded",
        "escalate": "escalated_unresolved",
        "require_authoritative_change": "authoritative_change_required",
    },
    "exception_open": {
        "cure_exception": "evidence_pending",
        "supersede": "superseded",
        "escalate": "escalated_unresolved",
        "require_authoritative_change": "authoritative_change_required",
    },
}
_GRADE_RANK = {
    PrimitiveEvidenceVerificationGrade.UNVERIFIED: 0,
    PrimitiveEvidenceVerificationGrade.ASSERTED: 1,
    PrimitiveEvidenceVerificationGrade.ATTESTED: 2,
    PrimitiveEvidenceVerificationGrade.VERIFIED: 3,
}
_GRADE_BY_NAME = {grade.value: grade for grade in PrimitiveEvidenceVerificationGrade}


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        revalidate_instances="always",
        serialize_by_alias=True,
        strict=True,
    )

    @model_validator(mode="before")
    @classmethod
    def _portable_payload(cls, value: Any) -> Any:
        if isinstance(value, BaseModel):
            value = value.model_dump(mode="json", by_alias=True, exclude_none=True)
        if not isinstance(value, Mapping):
            return value
        _reject_secret_like_payload(value)
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            normalized[str(key)] = tuple(item) if isinstance(item, list) else item
        return normalized

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def _detached_validation_payload(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", by_alias=True, exclude_none=True)
    if isinstance(value, Mapping):
        return {key: _detached_validation_payload(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_detached_validation_payload(item) for item in value]
    return value


def _timestamp(value: str, *, field_name: str) -> str:
    if value != value.strip():
        raise ValueError(f"{field_name} must not contain surrounding whitespace")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field_name} must be valid ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field_name} must include a UTC offset")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parsed_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _iso_date(value: str, *, field_name: str) -> str:
    if not _DATE_PATTERN.fullmatch(value):
        raise ValueError(f"{field_name} must be an ISO calendar date (YYYY-MM-DD)")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be a real calendar date") from exc
    return parsed.isoformat()


def _parsed_date(value: str) -> date:
    return date.fromisoformat(value)


def _format_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


@lru_cache(maxsize=1)
def _canonical_timezones() -> frozenset[str]:
    return frozenset(available_timezones())


def _timezone_name(value: str) -> str:
    if not _TIMEZONE_PATTERN.fullmatch(value):
        raise ValueError("timezone must be an IANA zone name")
    # Case-insensitive filesystems resolve "utc" or "america/new_york"; only the
    # canonical spelling is portable across hosts, so require it explicitly.
    if value not in _canonical_timezones():
        raise ValueError(f"timezone {value!r} is not a canonical IANA zone name")
    try:
        ZoneInfo(value)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValueError(f"timezone {value!r} is not available in the zone database") from exc
    return value


def _local_time(value: str) -> str:
    if not _LOCAL_TIME_PATTERN.fullmatch(value):
        raise ValueError("local times must use HH:MM in 24-hour form")
    return value


def _decimal(value: Any, *, field_name: str) -> Decimal:
    if isinstance(value, bool) or isinstance(value, float):
        raise ValueError(f"{field_name} must be a decimal string or integer")
    if isinstance(value, Decimal):
        parsed = value
    elif isinstance(value, int):
        parsed = Decimal(value)
    elif isinstance(value, str):
        if value != value.strip() or not value:
            raise ValueError(f"{field_name} must be a canonical decimal string")
        try:
            parsed = Decimal(value)
        except InvalidOperation as exc:
            raise ValueError(f"{field_name} must be a canonical decimal string") from exc
    else:
        raise ValueError(f"{field_name} must be a decimal string or integer")
    if not parsed.is_finite():
        raise ValueError(f"{field_name} must be finite")
    if parsed.as_tuple().exponent < -6:
        raise ValueError(f"{field_name} supports at most six decimal places")
    return parsed


def _stable_digest(value: Any) -> str:
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _unique(values: Sequence[str], *, label: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must be unique")


def _sorted_unique_tuple(value: Any, *, label: str) -> Any:
    if not isinstance(value, (tuple, list)):
        return value
    items = tuple(value)
    _unique(list(items), label=label)
    return tuple(sorted(items))


def _canonical_uuid(value: Any) -> UUID:
    if isinstance(value, UUID):
        return value
    if not isinstance(value, str) or value != value.strip():
        raise ValueError("project_id must be a canonical UUID")
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise ValueError("project_id must be a canonical UUID") from exc
    if str(parsed) != value:
        raise ValueError("project_id must be a canonical UUID")
    return parsed


def _digest_without(payload: Mapping[str, Any], *fields: str) -> str:
    reduced = {key: value for key, value in payload.items() if key not in fields}
    return _stable_digest(reduced)


# --------------------------------------------------------------------------- #
# Scope, agreement, clause
# --------------------------------------------------------------------------- #


class ContractObligationScope(_StrictModel):
    """Exact portable identity fence; Spring authenticates every value."""

    schema_id: Literal["lightbulb.contract_obligation_scope.v1"] = Field(
        default=CONTRACT_OBLIGATION_SCOPE_SCHEMA, alias="schema"
    )
    tenant_ref: OpaqueRef
    company_ref: OpaqueRef
    project_ref: OpaqueRef
    project_id: UUID
    agreement_ref: OpaqueRef
    evidence_custody_ref: OpaqueRef
    authorized_evidence_issuer_refs: tuple[OpaqueRef, ...] = Field(
        min_length=1, max_length=100
    )

    @field_validator("project_id", mode="before")
    @classmethod
    def _project_id(cls, value: Any) -> UUID:
        return _canonical_uuid(value)

    @field_validator("authorized_evidence_issuer_refs", mode="before")
    @classmethod
    def _issuers(cls, value: Any) -> Any:
        return _sorted_unique_tuple(value, label="authorized evidence issuers")


def contract_obligation_scope_digest(
    scope: ContractObligationScope | Mapping[str, Any],
) -> str:
    parsed = ContractObligationScope.model_validate(_detached_validation_payload(scope))
    return _stable_digest(parsed.to_dict())


class AgreementVersionRef(_StrictModel):
    """One exact approved agreement version; approval is Spring's assertion."""

    schema_id: Literal["lightbulb.contract_agreement_version.v1"] = Field(
        default=AGREEMENT_VERSION_SCHEMA, alias="schema"
    )
    agreement_ref: OpaqueRef
    version: int = Field(ge=1, le=10_000)
    agreement_digest: Sha256Digest
    approval_evidence_ref: OpaqueRef
    approved_at: str
    effective_at: str
    expires_at: str | None = None
    supersedes_version: int | None = Field(default=None, ge=1, le=10_000)

    @field_validator("approved_at", "effective_at", "expires_at")
    @classmethod
    def _timestamps(cls, value: str | None, info: ValidationInfo) -> str | None:
        if value is None:
            return None
        return _timestamp(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _version_is_coherent(self) -> "AgreementVersionRef":
        if self.supersedes_version is not None and self.supersedes_version >= self.version:
            raise ValueError("an amendment must supersede a strictly earlier version")
        if self.expires_at is not None and _parsed_timestamp(
            self.expires_at
        ) <= _parsed_timestamp(self.effective_at):
            raise ValueError("agreement expiry must follow its effective time")
        return self


class ClauseLocator(_StrictModel):
    """Where an obligation lives inside the retained agreement artifact."""

    schema_id: Literal["lightbulb.contract_clause_locator.v1"] = Field(
        default=CLAUSE_LOCATOR_SCHEMA, alias="schema"
    )
    clause_ref: OpaqueRef
    heading: ShortText | None = None
    clause_text_digest: Sha256Digest
    source_evidence_ref: OpaqueRef
    page: int | None = Field(default=None, ge=1, le=100_000)
    paragraph: int | None = Field(default=None, ge=1, le=100_000)


# --------------------------------------------------------------------------- #
# Obligation definition building blocks
# --------------------------------------------------------------------------- #


class BusinessCalendarPolicy(_StrictModel):
    weekend_days: tuple[int, ...] = Field(default=(5, 6), max_length=6)
    holidays: tuple[str, ...] = Field(default_factory=tuple, max_length=400)
    roll: CalendarRoll = "none"

    @field_validator("weekend_days", mode="before")
    @classmethod
    def _weekend(cls, value: Any) -> Any:
        if isinstance(value, (list, tuple)):
            items = tuple(value)
            for item in items:
                if isinstance(item, bool) or not isinstance(item, int) or not 0 <= item <= 6:
                    raise ValueError("weekend_days must contain weekday numbers 0-6")
            _unique([str(item) for item in items], label="weekend days")
            return tuple(sorted(items))
        return value

    @field_validator("holidays", mode="before")
    @classmethod
    def _holidays(cls, value: Any) -> Any:
        if isinstance(value, (list, tuple)):
            items = tuple(_iso_date(str(item), field_name="holidays") for item in value)
            _unique(list(items), label="holidays")
            return tuple(sorted(items))
        return value


class RecurrenceRule(_StrictModel):
    frequency: RecurrenceFrequency
    interval: int = Field(default=1, ge=1, le=12)
    start_date: str
    end_date: str | None = None
    day_of_month: int | None = Field(default=None, ge=1, le=31)
    count_limit: int | None = Field(default=None, ge=1, le=MAX_INSTANCES_PER_OBLIGATION)

    @field_validator("start_date", "end_date")
    @classmethod
    def _dates(cls, value: str | None, info: ValidationInfo) -> str | None:
        if value is None:
            return None
        return _iso_date(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _recurrence_is_bounded(self) -> "RecurrenceRule":
        if self.end_date is not None and _parsed_date(self.end_date) < _parsed_date(
            self.start_date
        ):
            raise ValueError("recurrence end_date cannot precede start_date")
        if self.day_of_month is not None and self.frequency in {"daily", "weekly"}:
            raise ValueError("day_of_month applies only to monthly or longer recurrence")
        return self


class DueRule(_StrictModel):
    """Versioned due-date semantics with explicit timezone and calendar rules."""

    rule_version: int = Field(ge=1, le=10_000)
    kind: DueRuleKind
    timezone: str
    due_local_time: str = "17:00"
    calendar: BusinessCalendarPolicy = Field(default_factory=BusinessCalendarPolicy)
    fixed_date: str | None = None
    anchor: RelativeAnchor | None = None
    offset_days: int | None = Field(default=None, ge=-3650, le=3650)
    recurrence: RecurrenceRule | None = None

    @field_validator("timezone")
    @classmethod
    def _zone(cls, value: str) -> str:
        return _timezone_name(value)

    @field_validator("due_local_time")
    @classmethod
    def _time(cls, value: str) -> str:
        return _local_time(value)

    @field_validator("fixed_date")
    @classmethod
    def _fixed(cls, value: str | None) -> str | None:
        return None if value is None else _iso_date(value, field_name="fixed_date")

    @model_validator(mode="after")
    def _shape_matches_kind(self) -> "DueRule":
        if self.kind == "fixed_date":
            if self.fixed_date is None or self.anchor is not None or (
                self.offset_days is not None or self.recurrence is not None
            ):
                raise ValueError("fixed_date rules carry only fixed_date")
        elif self.kind == "relative_to_agreement":
            if self.anchor is None or self.offset_days is None or (
                self.fixed_date is not None or self.recurrence is not None
            ):
                raise ValueError("relative rules carry exactly anchor and offset_days")
        else:
            if self.recurrence is None or self.fixed_date is not None or (
                self.anchor is not None or self.offset_days is not None
            ):
                raise ValueError("recurring rules carry exactly a recurrence")
        return self


class ActivationCondition(_StrictModel):
    kind: ActivationKind = "unconditional"
    event_ref: OpaqueRef | None = None
    dependency_obligation_ref: OpaqueRef | None = None

    @model_validator(mode="after")
    def _condition_is_exact(self) -> "ActivationCondition":
        if self.kind == "unconditional" and (
            self.event_ref is not None or self.dependency_obligation_ref is not None
        ):
            raise ValueError("unconditional activation carries no condition references")
        if self.kind == "on_event" and (
            self.event_ref is None or self.dependency_obligation_ref is not None
        ):
            raise ValueError("on_event activation requires exactly event_ref")
        if self.kind == "on_dependency_fulfilled" and (
            self.dependency_obligation_ref is None or self.event_ref is not None
        ):
            raise ValueError(
                "on_dependency_fulfilled activation requires exactly "
                "dependency_obligation_ref"
            )
        return self


class FulfillmentCriterion(_StrictModel):
    criterion_ref: OpaqueRef
    description: BoundedText
    evidence_kind: ShortText
    minimum_verification_grade: PrimitiveEvidenceVerificationGrade = (
        PrimitiveEvidenceVerificationGrade.ATTESTED
    )
    required: bool = True
    measure: CriterionMeasure = "presence"
    target_quantity: Decimal | None = None
    unit: ShortText | None = None

    @field_validator("minimum_verification_grade", mode="before")
    @classmethod
    def _grade(cls, value: Any) -> Any:
        if isinstance(value, str) and value in _GRADE_BY_NAME:
            return _GRADE_BY_NAME[value]
        return value

    @field_validator("target_quantity", mode="before")
    @classmethod
    def _quantity(cls, value: Any) -> Any:
        return None if value is None else _decimal(value, field_name="target_quantity")

    @model_validator(mode="after")
    def _measure_is_exact(self) -> "FulfillmentCriterion":
        if self.measure == "quantity":
            if self.target_quantity is None or self.target_quantity <= 0 or self.unit is None:
                raise ValueError("quantity criteria require a positive target and unit")
        elif self.target_quantity is not None or self.unit is not None:
            raise ValueError("presence criteria carry no quantity target")
        return self


class EscalationPolicy(_StrictModel):
    escalate_after_overdue_days: int = Field(ge=0, le=365)
    escalate_to_role_ref: OpaqueRef
    max_exception_days: int = Field(ge=1, le=365)


class MonetaryTerms(_StrictModel):
    amount: Decimal
    currency: CurrencyCode

    @field_validator("amount", mode="before")
    @classmethod
    def _amount(cls, value: Any) -> Any:
        parsed = _decimal(value, field_name="amount")
        if parsed <= 0:
            raise ValueError("monetary amount must be positive")
        return parsed


class ObligationSource(_StrictModel):
    candidate_ref: OpaqueRef
    proposed_by_ref: OpaqueRef
    proposal_evidence_ref: OpaqueRef


class _ObligationShape(_StrictModel):
    obligation_ref: OpaqueRef
    kind: ObligationKind
    direction: ObligationDirection
    title: ShortText
    criteria: tuple[FulfillmentCriterion, ...] = Field(min_length=1, max_length=40)
    responsible_party_ref: OpaqueRef
    counterparty_ref: OpaqueRef
    due_rule: DueRule
    activation: ActivationCondition = Field(default_factory=ActivationCondition)
    dependencies: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=20)
    notice_lead_days: int | None = Field(default=None, ge=0, le=730)
    evidence_lead_days: int = Field(default=0, ge=0, le=365)
    evidence_freshness_days: int = Field(default=365, ge=1, le=3650)
    materiality: Materiality = "medium"
    escalation_policy: EscalationPolicy
    monetary: MonetaryTerms | None = None
    supersedes_obligation_ref: OpaqueRef | None = None

    @field_validator("dependencies", mode="before")
    @classmethod
    def _dependencies(cls, value: Any) -> Any:
        return _sorted_unique_tuple(value, label="dependencies")

    @model_validator(mode="after")
    def _shape_is_exact(self) -> "_ObligationShape":
        _unique([item.criterion_ref for item in self.criteria], label="criterion refs")
        if not any(item.required for item in self.criteria):
            raise ValueError("at least one fulfillment criterion must be required")
        if (self.kind == "monetary") != (self.monetary is not None):
            raise ValueError("monetary terms are required exactly for monetary obligations")
        if self.kind == "notice" and self.notice_lead_days is None:
            raise ValueError("notice obligations require notice_lead_days")
        if self.obligation_ref in self.dependencies:
            raise ValueError("an obligation cannot depend on itself")
        if (
            self.activation.kind == "on_dependency_fulfilled"
            and self.activation.dependency_obligation_ref not in self.dependencies
        ):
            raise ValueError(
                "dependency-activated obligations must list the activating dependency"
            )
        if self.supersedes_obligation_ref == self.obligation_ref:
            raise ValueError("an obligation cannot supersede itself")
        return self


class ObligationCandidate(_ObligationShape):
    """Agent-proposed, clause-cited obligation awaiting normalization."""

    schema_id: Literal["lightbulb.contract_obligation_candidate.v1"] = Field(
        default=OBLIGATION_CANDIDATE_SCHEMA, alias="schema"
    )
    candidate_ref: OpaqueRef
    clause_ref: OpaqueRef
    clause_text_digest: Sha256Digest
    proposed_by_ref: OpaqueRef
    proposal_evidence_ref: OpaqueRef


class ObligationDefinition(_ObligationShape):
    """Normalized obligation bound to an exact agreement version and clause."""

    schema_id: Literal["lightbulb.contract_obligation_definition.v1"] = Field(
        default=OBLIGATION_DEFINITION_SCHEMA, alias="schema"
    )
    agreement: AgreementVersionRef
    clause: ClauseLocator
    source: ObligationSource
    definition_digest: Sha256Digest = GENESIS_STATE_DIGEST

    @model_validator(mode="after")
    def _digest_is_exact(self, info: ValidationInfo) -> "ObligationDefinition":
        if (info.context or {}).get("skip_obligation_digests"):
            return self
        if self.definition_digest != obligation_definition_digest(self):
            raise ValueError("definition_digest must commit the exact definition")
        return self


def obligation_definition_digest(
    definition: ObligationDefinition | Mapping[str, Any],
) -> str:
    raw = dict(_detached_validation_payload(definition))
    raw.setdefault("definition_digest", GENESIS_STATE_DIGEST)
    parsed = ObligationDefinition.model_validate(
        raw, context={"skip_obligation_digests": True}
    )
    return _digest_without(parsed.to_dict(), "definition_digest")


def seal_obligation_definition(definition: Mapping[str, Any]) -> dict[str, Any]:
    raw = dict(_detached_validation_payload(definition))
    raw["definition_digest"] = obligation_definition_digest(raw)
    return ObligationDefinition.model_validate(raw).to_dict()


# --------------------------------------------------------------------------- #
# Register normalization
# --------------------------------------------------------------------------- #


class CandidateRejection(_StrictModel):
    candidate_ref: OpaqueRef
    obligation_ref: OpaqueRef
    code: CandidateRejectionCode
    message: BoundedText


class SupersessionLink(_StrictModel):
    obligation_ref: OpaqueRef
    supersedes_obligation_ref: OpaqueRef
    prior_definition_digest: Sha256Digest
    prior_agreement_version: int = Field(ge=1, le=10_000)


class CarriedObligation(_StrictModel):
    """A prior-version obligation retained by reference, never rewritten."""

    obligation_ref: OpaqueRef
    definition_digest: Sha256Digest
    agreement_version: int = Field(ge=1, le=10_000)


class ObligationRegister(_StrictModel):
    schema_id: Literal["lightbulb.contract_obligation_register.v1"] = Field(
        default=OBLIGATION_REGISTER_SCHEMA, alias="schema"
    )
    scope: ContractObligationScope
    agreement: AgreementVersionRef
    definitions: tuple[ObligationDefinition, ...] = Field(
        default_factory=tuple, max_length=MAX_REGISTER_DEFINITIONS
    )
    rejections: tuple[CandidateRejection, ...] = Field(
        default_factory=tuple, max_length=MAX_REGISTER_DEFINITIONS
    )
    supersessions: tuple[SupersessionLink, ...] = Field(
        default_factory=tuple, max_length=MAX_REGISTER_DEFINITIONS
    )
    carried_forward: tuple[CarriedObligation, ...] = Field(
        default_factory=tuple, max_length=MAX_REGISTER_DEFINITIONS
    )
    prior_register_digest: Sha256Digest | None = None
    register_digest: Sha256Digest = GENESIS_STATE_DIGEST

    @model_validator(mode="after")
    def _register_is_exact(self, info: ValidationInfo) -> "ObligationRegister":
        refs = [item.obligation_ref for item in self.definitions]
        _unique(refs, label="register obligation refs")
        if refs != sorted(refs):
            raise ValueError("register definitions must be sorted by obligation_ref")
        for definition in self.definitions:
            if definition.agreement != self.agreement:
                raise ValueError("every definition must bind the register agreement")
            if self.scope.agreement_ref != definition.agreement.agreement_ref:
                raise ValueError("definition agreement must match scope agreement")
        if self.scope.agreement_ref != self.agreement.agreement_ref:
            raise ValueError("register agreement must match scope agreement")
        rejection_keys = [item.candidate_ref for item in self.rejections]
        if rejection_keys != sorted(rejection_keys):
            raise ValueError("register rejections must be sorted by candidate_ref")
        supersession_keys = [item.obligation_ref for item in self.supersessions]
        _unique(supersession_keys, label="supersession obligation refs")
        _unique(
            [item.supersedes_obligation_ref for item in self.supersessions],
            label="superseded prior obligations",
        )
        if supersession_keys != sorted(supersession_keys):
            raise ValueError("supersessions must be sorted by obligation_ref")
        carried_keys = [item.obligation_ref for item in self.carried_forward]
        _unique(carried_keys, label="carried-forward obligations")
        if carried_keys != sorted(carried_keys):
            raise ValueError("carried-forward obligations must be sorted")
        if set(carried_keys) & set(refs):
            raise ValueError("carried-forward obligations cannot be redefined")
        if (self.agreement.supersedes_version is None) != (
            self.prior_register_digest is None
        ):
            raise ValueError("amendment registers carry exactly one prior register digest")
        if self.agreement.supersedes_version is None and (
            self.supersessions or self.carried_forward
        ):
            raise ValueError("only amendment registers carry supersession lineage")
        if (info.context or {}).get("skip_obligation_digests"):
            return self
        if self.register_digest != obligation_register_digest(self):
            raise ValueError("register_digest must commit the exact register")
        return self


def obligation_register_digest(
    register: ObligationRegister | Mapping[str, Any],
) -> str:
    raw = dict(_detached_validation_payload(register))
    raw.setdefault("register_digest", GENESIS_STATE_DIGEST)
    parsed = ObligationRegister.model_validate(
        raw, context={"skip_obligation_digests": True}
    )
    return _digest_without(parsed.to_dict(), "register_digest")


class ContractObligationNormalizationInput(_StrictModel):
    scope: ContractObligationScope
    agreement: AgreementVersionRef
    clause_index: tuple[ClauseLocator, ...] = Field(min_length=1, max_length=2000)
    candidates: tuple[ObligationCandidate, ...] = Field(
        min_length=1, max_length=MAX_REGISTER_DEFINITIONS
    )
    prior_register: ObligationRegister | None = None
    requested_by_ref: OpaqueRef

    @model_validator(mode="after")
    def _input_is_exact(self) -> "ContractObligationNormalizationInput":
        if self.scope.agreement_ref != self.agreement.agreement_ref:
            raise ValueError("agreement must match the scoped agreement reference")
        _unique([item.clause_ref for item in self.clause_index], label="clause refs")
        _unique([item.candidate_ref for item in self.candidates], label="candidate refs")
        if self.prior_register is not None:
            prior = self.prior_register
            if prior.scope != self.scope:
                raise ValueError("prior register must share the exact scope")
            if self.agreement.supersedes_version != prior.agreement.version:
                raise ValueError(
                    "amendment must supersede exactly the prior register version"
                )
            if self.agreement.version <= prior.agreement.version:
                raise ValueError("amendment version must advance the agreement version")
        elif self.agreement.supersedes_version is not None:
            raise ValueError("amendment normalization requires the prior register")
        return self


def _dependency_cycles(edges: Mapping[str, Sequence[str]]) -> set[str]:
    """Return every node participating in a dependency cycle (deterministic)."""

    state: dict[str, int] = {}
    in_cycle: set[str] = set()
    stack: list[str] = []

    def visit(node: str) -> None:
        state[node] = 1
        stack.append(node)
        for target in sorted(edges.get(node, ())):
            if target not in edges:
                continue
            if state.get(target) == 1:
                in_cycle.update(stack[stack.index(target):])
            elif state.get(target) is None:
                visit(target)
        stack.pop()
        state[node] = 2

    for node in sorted(edges):
        if state.get(node) is None:
            visit(node)
    return in_cycle


def normalize_contract_obligation_candidates(
    inputs: ContractObligationNormalizationInput | Mapping[str, Any],
) -> ObligationRegister:
    """Validate clause-cited candidates into one deterministic register candidate.

    Legal meaning is never decided here: a rejected candidate is structurally
    unsupported, and an accepted candidate is only structurally coherent.
    """

    parsed = ContractObligationNormalizationInput.model_validate(
        _detached_validation_payload(inputs)
    )
    clause_by_ref = {item.clause_ref: item for item in parsed.clause_index}
    prior = parsed.prior_register
    prior_definitions = (
        {item.obligation_ref: item for item in prior.definitions} if prior else {}
    )
    prior_carried = {item.obligation_ref: item for item in prior.carried_forward} if prior else {}
    rejections: dict[str, CandidateRejection] = {}

    def reject(candidate: ObligationCandidate, code: CandidateRejectionCode, message: str) -> None:
        rejections.setdefault(
            candidate.candidate_ref,
            CandidateRejection(
                candidate_ref=candidate.candidate_ref,
                obligation_ref=candidate.obligation_ref,
                code=code,
                message=message,
            ),
        )

    ordered = sorted(parsed.candidates, key=lambda item: item.candidate_ref)
    ref_counts: dict[str, int] = {}
    for candidate in ordered:
        ref_counts[candidate.obligation_ref] = ref_counts.get(candidate.obligation_ref, 0) + 1
    for candidate in ordered:
        if ref_counts[candidate.obligation_ref] > 1:
            reject(
                candidate,
                "duplicate_obligation_ref",
                "more than one candidate claims this obligation reference",
            )
            continue
        if candidate.obligation_ref in prior_definitions or (
            candidate.obligation_ref in prior_carried
        ):
            reject(
                candidate,
                "obligation_ref_collides_with_prior",
                "obligation reference already exists in the prior register",
            )
            continue
        clause = clause_by_ref.get(candidate.clause_ref)
        if clause is None:
            reject(candidate, "clause_not_found", "clause reference is not in the index")
            continue
        if clause.clause_text_digest != candidate.clause_text_digest:
            reject(
                candidate,
                "clause_digest_mismatch",
                "candidate cites a clause digest that differs from the retained clause",
            )
            continue
        if candidate.supersedes_obligation_ref is not None:
            if prior is None:
                reject(
                    candidate,
                    "supersession_requires_amendment",
                    "supersession is only valid while normalizing an amendment",
                )
                continue
            if candidate.supersedes_obligation_ref not in prior_definitions and (
                candidate.supersedes_obligation_ref not in prior_carried
            ):
                reject(
                    candidate,
                    "supersession_target_unknown",
                    "superseded obligation is not in the prior register",
                )
                continue

    surviving = [item for item in ordered if item.candidate_ref not in rejections]

    supersession_targets: dict[str, list[ObligationCandidate]] = {}
    for candidate in surviving:
        if candidate.supersedes_obligation_ref is not None:
            supersession_targets.setdefault(candidate.supersedes_obligation_ref, []).append(
                candidate
            )
    for target, claimants in supersession_targets.items():
        if len(claimants) > 1:
            for candidate in claimants:
                reject(
                    candidate,
                    "supersession_conflict",
                    f"more than one candidate supersedes prior obligation {target}",
                )
    surviving = [item for item in surviving if item.candidate_ref not in rejections]

    definition_keys: dict[str, str] = {}
    for candidate in surviving:
        key = _stable_digest(
            {
                "clause_ref": candidate.clause_ref,
                "kind": candidate.kind,
                "direction": candidate.direction,
                "due_rule": candidate.due_rule.to_dict(),
                "responsible_party_ref": candidate.responsible_party_ref,
                "counterparty_ref": candidate.counterparty_ref,
            }
        )
        if key in definition_keys:
            reject(
                candidate,
                "duplicate_definition",
                f"structurally identical to candidate {definition_keys[key]}",
            )
        else:
            definition_keys[key] = candidate.candidate_ref
    surviving = [item for item in surviving if item.candidate_ref not in rejections]

    known_refs = {item.obligation_ref for item in surviving}
    superseded_prior = {
        item.supersedes_obligation_ref
        for item in surviving
        if item.supersedes_obligation_ref is not None
    }
    available_prior = (set(prior_definitions) | set(prior_carried)) - superseded_prior
    edges = {
        item.obligation_ref: [dep for dep in item.dependencies if dep in known_refs]
        for item in surviving
    }
    cyclic = _dependency_cycles(edges)
    for candidate in surviving:
        if candidate.obligation_ref in cyclic:
            reject(candidate, "dependency_cycle", "candidate participates in a dependency cycle")
            continue
        unresolved = [
            dep
            for dep in candidate.dependencies
            if dep not in known_refs and dep not in available_prior
        ]
        if unresolved:
            reject(
                candidate,
                "dependency_unresolved",
                f"dependencies are not registered: {', '.join(unresolved)}",
            )
    # Dependencies on rejected candidates are unresolved as well; settle to a fixpoint.
    while True:
        surviving = [item for item in surviving if item.candidate_ref not in rejections]
        accepted_refs = {item.obligation_ref for item in surviving}
        newly_rejected = False
        for candidate in surviving:
            unresolved = [
                dep
                for dep in candidate.dependencies
                if dep not in accepted_refs and dep not in available_prior
            ]
            if unresolved:
                reject(
                    candidate,
                    "dependency_unresolved",
                    f"dependencies are not registered: {', '.join(unresolved)}",
                )
                newly_rejected = True
        if not newly_rejected:
            break

    definitions: list[dict[str, Any]] = []
    supersessions: list[SupersessionLink] = []
    for candidate in surviving:
        clause = clause_by_ref[candidate.clause_ref]
        payload = candidate.to_dict()
        for key in (
            "schema",
            "candidate_ref",
            "clause_ref",
            "clause_text_digest",
            "proposed_by_ref",
            "proposal_evidence_ref",
        ):
            payload.pop(key, None)
        payload["agreement"] = parsed.agreement.to_dict()
        payload["clause"] = clause.to_dict()
        payload["source"] = ObligationSource(
            candidate_ref=candidate.candidate_ref,
            proposed_by_ref=candidate.proposed_by_ref,
            proposal_evidence_ref=candidate.proposal_evidence_ref,
        ).to_dict()
        definitions.append(seal_obligation_definition(payload))
        if candidate.supersedes_obligation_ref is not None and prior is not None:
            target = candidate.supersedes_obligation_ref
            if target in prior_definitions:
                prior_digest = prior_definitions[target].definition_digest
                prior_version = prior.agreement.version
            else:
                prior_digest = prior_carried[target].definition_digest
                prior_version = prior_carried[target].agreement_version
            supersessions.append(
                SupersessionLink(
                    obligation_ref=candidate.obligation_ref,
                    supersedes_obligation_ref=target,
                    prior_definition_digest=prior_digest,
                    prior_agreement_version=prior_version,
                )
            )

    carried: list[CarriedObligation] = []
    if prior is not None:
        for item in prior.definitions:
            if item.obligation_ref not in superseded_prior:
                carried.append(
                    CarriedObligation(
                        obligation_ref=item.obligation_ref,
                        definition_digest=item.definition_digest,
                        agreement_version=prior.agreement.version,
                    )
                )
        for item in prior.carried_forward:
            if item.obligation_ref not in superseded_prior:
                carried.append(item)

    register = {
        "scope": parsed.scope.to_dict(),
        "agreement": parsed.agreement.to_dict(),
        "definitions": sorted(definitions, key=lambda item: item["obligation_ref"]),
        "rejections": [
            rejections[key].to_dict() for key in sorted(rejections)
        ],
        "supersessions": [
            item.to_dict()
            for item in sorted(supersessions, key=lambda item: item.obligation_ref)
        ],
        "carried_forward": [
            item.to_dict() for item in sorted(carried, key=lambda item: item.obligation_ref)
        ],
        "prior_register_digest": prior.register_digest if prior is not None else None,
    }
    register["register_digest"] = obligation_register_digest(register)
    return ObligationRegister.model_validate(register)


# --------------------------------------------------------------------------- #
# Schedule compilation
# --------------------------------------------------------------------------- #


def _add_months(value: date, months: int, *, day_of_month: int | None) -> date:
    month_index = value.month - 1 + months
    year = value.year + month_index // 12
    month = month_index % 12 + 1
    wanted = day_of_month if day_of_month is not None else value.day
    last_day = (date(year + (month // 12), month % 12 + 1, 1) - timedelta(days=1)).day
    return date(year, month, min(wanted, last_day))


def _roll_business_day(value: date, calendar: BusinessCalendarPolicy) -> date:
    holidays = {_parsed_date(item) for item in calendar.holidays}

    def is_business_day(candidate: date) -> bool:
        return candidate.weekday() not in calendar.weekend_days and candidate not in holidays

    if calendar.roll == "none" or is_business_day(value):
        return value
    if calendar.roll == "preceding":
        step = -1
    else:
        step = 1
    rolled = value
    for _ in range(0, 60):
        rolled = rolled + timedelta(days=step)
        if is_business_day(rolled):
            break
    else:
        raise ValueError("business calendar has no business day within sixty days")
    if calendar.roll == "modified_following" and rolled.month != value.month:
        rolled = value
        for _ in range(0, 60):
            rolled = rolled - timedelta(days=1)
            if is_business_day(rolled):
                break
        else:
            raise ValueError("business calendar has no business day within sixty days")
    return rolled


def _local_due(value: date, rule: DueRule) -> tuple[str, datetime]:
    hours, minutes = (int(part) for part in rule.due_local_time.split(":"))
    local = datetime.combine(value, time(hours, minutes), tzinfo=ZoneInfo(rule.timezone))
    # Non-existent local wall times (DST gaps) resolve with fold=0, which is the
    # deterministic pre-transition offset; ambiguous times (DST overlaps) resolve
    # to the first occurrence.  Both are stable across replays.
    return local.isoformat(), local.astimezone(timezone.utc)


def _occurrence_dates(
    recurrence: RecurrenceRule,
    *,
    horizon_to: date,
    series_end: date | None,
) -> list[tuple[int, date, date]]:
    """Return (occurrence_index, period_start, due_date) for the whole series
    up to the horizon end, capped by the series end, count_limit, and the
    per-obligation bound."""

    start = _parsed_date(recurrence.start_date)
    end = _parsed_date(recurrence.end_date) if recurrence.end_date else None
    if series_end is not None and (end is None or series_end < end):
        end = series_end
    # One occurrence past the per-obligation bound is generated on purpose so a
    # truncated expansion can report where the next expansion must resume.
    limit = (
        recurrence.count_limit
        if recurrence.count_limit is not None
        else MAX_INSTANCES_PER_OBLIGATION + 1
    )
    results: list[tuple[int, date, date]] = []
    index = 1
    current = start
    period_start = start
    while current <= horizon_to and index <= limit and index <= MAX_INSTANCES_PER_OBLIGATION + 1:
        if end is not None and current > end:
            break
        results.append((index, period_start, current))
        period_start = current
        if recurrence.frequency == "daily":
            current = current + timedelta(days=recurrence.interval)
        elif recurrence.frequency == "weekly":
            current = current + timedelta(days=7 * recurrence.interval)
        elif recurrence.frequency == "monthly":
            current = _add_months(
                start, recurrence.interval * index, day_of_month=recurrence.day_of_month
            )
        elif recurrence.frequency == "quarterly":
            current = _add_months(
                start, 3 * recurrence.interval * index, day_of_month=recurrence.day_of_month
            )
        else:
            current = _add_months(
                start, 12 * recurrence.interval * index, day_of_month=recurrence.day_of_month
            )
        index += 1
    return results


class ScheduleHorizon(_StrictModel):
    from_date: str
    to_date: str

    @field_validator("from_date", "to_date")
    @classmethod
    def _dates(cls, value: str, info: ValidationInfo) -> str:
        return _iso_date(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _horizon_is_bounded(self) -> "ScheduleHorizon":
        span = (_parsed_date(self.to_date) - _parsed_date(self.from_date)).days
        if span < 0:
            raise ValueError("horizon to_date cannot precede from_date")
        if span > MAX_SCHEDULE_HORIZON_DAYS:
            raise ValueError(
                f"schedule horizon is bounded to {MAX_SCHEDULE_HORIZON_DAYS} days"
            )
        return self


class ActivationEvent(_StrictModel):
    event_ref: OpaqueRef
    occurred_at: str
    evidence_ref: OpaqueRef

    @field_validator("occurred_at")
    @classmethod
    def _occurred(cls, value: str) -> str:
        return _timestamp(value, field_name="occurred_at")


class DependencyState(_StrictModel):
    obligation_ref: OpaqueRef
    fulfilled_instance_ref: OpaqueRef
    fulfilled_state_digest: Sha256Digest
    fulfilled_at: str

    @field_validator("fulfilled_at")
    @classmethod
    def _fulfilled(cls, value: str) -> str:
        return _timestamp(value, field_name="fulfilled_at")


class RegisterReviewAttestation(_StrictModel):
    """Structural proof that Spring recorded a review of the exact register."""

    reviewed_by_ref: OpaqueRef
    review_evidence: PrimitiveEvidenceRef

    @field_validator("review_evidence", mode="before")
    @classmethod
    def _revalidated(cls, value: Any) -> Any:
        return _detached_validation_payload(value)


class ObligationInstance(_StrictModel):
    schema_id: Literal["lightbulb.contract_obligation_instance.v1"] = Field(
        default=OBLIGATION_INSTANCE_SCHEMA, alias="schema"
    )
    instance_ref: OpaqueRef
    obligation_ref: OpaqueRef
    definition_digest: Sha256Digest
    agreement_version: int = Field(ge=1, le=10_000)
    due_rule_version: int = Field(ge=1, le=10_000)
    occurrence_index: int = Field(ge=1, le=MAX_INSTANCES_PER_OBLIGATION + 1)
    period_start_at: str
    due_local: str
    due_at: str
    evidence_due_at: str
    evidence_window_opens_at: str
    notice_window_opens_at: str | None = None
    blocked_by: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=20)
    activated_by_event_ref: OpaqueRef | None = None

    @field_validator(
        "period_start_at",
        "due_at",
        "evidence_due_at",
        "evidence_window_opens_at",
        "notice_window_opens_at",
    )
    @classmethod
    def _timestamps(cls, value: str | None, info: ValidationInfo) -> str | None:
        if value is None:
            return None
        return _timestamp(value, field_name=str(info.field_name))

    @field_validator("due_local")
    @classmethod
    def _local(cls, value: str) -> str:
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError as exc:
            raise ValueError("due_local must be an ISO-8601 local timestamp") from exc
        if parsed.tzinfo is None:
            raise ValueError("due_local must carry its local UTC offset")
        return value

    @field_validator("blocked_by", mode="before")
    @classmethod
    def _blocked(cls, value: Any) -> Any:
        return _sorted_unique_tuple(value, label="blocked_by")

    @model_validator(mode="after")
    def _instance_is_coherent(self) -> "ObligationInstance":
        due = _parsed_timestamp(self.due_at)
        if _parsed_timestamp(self.due_local) != due:
            raise ValueError("due_local and due_at must denote the same instant")
        if _parsed_timestamp(self.evidence_due_at) > due:
            raise ValueError("evidence_due_at cannot follow due_at")
        if _parsed_timestamp(self.evidence_window_opens_at) > _parsed_timestamp(
            self.evidence_due_at
        ):
            raise ValueError("evidence window cannot open after evidence is due")
        if _parsed_timestamp(self.period_start_at) > due:
            raise ValueError("period_start_at cannot follow due_at")
        if self.notice_window_opens_at is not None and _parsed_timestamp(
            self.notice_window_opens_at
        ) > due:
            raise ValueError("notice window cannot open after due_at")
        if self.instance_ref != f"{self.obligation_ref}:occ-{self.occurrence_index:04d}":
            raise ValueError("instance_ref must be the canonical obligation occurrence key")
        return self


class DeferredObligation(_StrictModel):
    obligation_ref: OpaqueRef
    definition_digest: Sha256Digest
    reason: Literal[
        "awaiting_event",
        "awaiting_dependency",
        "outside_horizon",
        "anchor_unavailable",
    ]
    detail: BoundedText


class ScheduleTruncation(_StrictModel):
    obligation_ref: OpaqueRef
    expanded_count: int = Field(ge=0, le=MAX_SCHEDULE_INSTANCES)
    next_expansion_from: str

    @field_validator("next_expansion_from")
    @classmethod
    def _date(cls, value: str) -> str:
        return _iso_date(value, field_name="next_expansion_from")


class ObligationSchedule(_StrictModel):
    schema_id: Literal["lightbulb.contract_obligation_schedule.v1"] = Field(
        default=OBLIGATION_SCHEDULE_SCHEMA, alias="schema"
    )
    scope: ContractObligationScope
    register_digest: Sha256Digest
    agreement_version: int = Field(ge=1, le=10_000)
    horizon: ScheduleHorizon
    as_of: str
    instances: tuple[ObligationInstance, ...] = Field(
        default_factory=tuple, max_length=MAX_SCHEDULE_INSTANCES
    )
    deferred: tuple[DeferredObligation, ...] = Field(
        default_factory=tuple, max_length=MAX_REGISTER_DEFINITIONS
    )
    truncations: tuple[ScheduleTruncation, ...] = Field(
        default_factory=tuple, max_length=MAX_REGISTER_DEFINITIONS
    )
    schedule_digest: Sha256Digest = GENESIS_STATE_DIGEST

    @field_validator("as_of")
    @classmethod
    def _as_of(cls, value: str) -> str:
        return _timestamp(value, field_name="as_of")

    @model_validator(mode="after")
    def _schedule_is_exact(self, info: ValidationInfo) -> "ObligationSchedule":
        keys = [
            (item.due_at, item.obligation_ref, item.occurrence_index)
            for item in self.instances
        ]
        if keys != sorted(keys):
            raise ValueError("schedule instances must be ordered by due time then key")
        _unique([item.instance_ref for item in self.instances], label="instance refs")
        if (info.context or {}).get("skip_obligation_digests"):
            return self
        if self.schedule_digest != obligation_schedule_digest(self):
            raise ValueError("schedule_digest must commit the exact schedule")
        return self


def obligation_schedule_digest(
    schedule: ObligationSchedule | Mapping[str, Any],
) -> str:
    raw = dict(_detached_validation_payload(schedule))
    raw.setdefault("schedule_digest", GENESIS_STATE_DIGEST)
    parsed = ObligationSchedule.model_validate(
        raw, context={"skip_obligation_digests": True}
    )
    return _digest_without(parsed.to_dict(), "schedule_digest")


class ContractObligationScheduleInput(_StrictModel):
    scope: ContractObligationScope
    obligation_register: ObligationRegister
    review: RegisterReviewAttestation
    horizon: ScheduleHorizon
    as_of: str
    activation_events: tuple[ActivationEvent, ...] = Field(
        default_factory=tuple, max_length=500
    )
    dependency_states: tuple[DependencyState, ...] = Field(
        default_factory=tuple, max_length=MAX_REGISTER_DEFINITIONS
    )
    requested_by_ref: OpaqueRef

    @field_validator("as_of")
    @classmethod
    def _as_of(cls, value: str) -> str:
        return _timestamp(value, field_name="as_of")

    @model_validator(mode="after")
    def _input_is_exact(self) -> "ContractObligationScheduleInput":
        if self.obligation_register.scope != self.scope:
            raise ValueError("register scope must exactly match schedule scope")
        if not self.obligation_register.definitions:
            raise ValueError("a schedule requires at least one registered definition")
        review = self.review.review_evidence
        if review.subject_ref != self.obligation_register.register_digest:
            raise ValueError("register review evidence must bind the exact register digest")
        if review.issuer_ref not in self.scope.authorized_evidence_issuer_refs:
            raise ValueError("register review issuer is not authorized by scope")
        if _GRADE_RANK[review.verification_grade] < _GRADE_RANK[
            PrimitiveEvidenceVerificationGrade.ATTESTED
        ]:
            raise ValueError("register review evidence must be at least attested")
        if review.kind != "obligation_register_review":
            raise ValueError("register review evidence must be an obligation register review")
        if _parsed_timestamp(review.observed_at) > _parsed_timestamp(self.as_of):
            raise ValueError("register review cannot be observed after as_of")
        _unique([item.event_ref for item in self.activation_events], label="activation events")
        _unique(
            [item.obligation_ref for item in self.dependency_states],
            label="dependency states",
        )
        return self


def _anchor_date(definition: ObligationDefinition, rule: DueRule) -> date | None:
    if rule.anchor == "agreement_effective_at":
        anchor = definition.agreement.effective_at
    else:
        anchor = definition.agreement.expires_at
        if anchor is None:
            return None
    local = _parsed_timestamp(anchor).astimezone(ZoneInfo(rule.timezone))
    return local.date() + timedelta(days=rule.offset_days or 0)


def compile_contract_obligation_schedule(
    inputs: ContractObligationScheduleInput | Mapping[str, Any],
) -> ObligationSchedule:
    """Expand a reviewed register into bounded, dated obligation instances."""

    parsed = ContractObligationScheduleInput.model_validate(
        _detached_validation_payload(inputs)
    )
    register = parsed.obligation_register
    events = {item.event_ref: item for item in parsed.activation_events}
    dependency_states = {item.obligation_ref: item for item in parsed.dependency_states}
    horizon_from = _parsed_date(parsed.horizon.from_date)
    horizon_to = _parsed_date(parsed.horizon.to_date)
    instances: list[ObligationInstance] = []
    deferred: list[DeferredObligation] = []
    truncations: list[ScheduleTruncation] = []
    total = 0

    for definition in register.definitions:
        rule = definition.due_rule
        activated_by: str | None = None
        if definition.activation.kind == "on_event":
            event = events.get(str(definition.activation.event_ref))
            if event is None:
                deferred.append(
                    DeferredObligation(
                        obligation_ref=definition.obligation_ref,
                        definition_digest=definition.definition_digest,
                        reason="awaiting_event",
                        detail=f"activation event {definition.activation.event_ref} not observed",
                    )
                )
                continue
            activated_by = event.event_ref
        elif definition.activation.kind == "on_dependency_fulfilled":
            if str(definition.activation.dependency_obligation_ref) not in dependency_states:
                deferred.append(
                    DeferredObligation(
                        obligation_ref=definition.obligation_ref,
                        definition_digest=definition.definition_digest,
                        reason="awaiting_dependency",
                        detail=(
                            "activating dependency "
                            f"{definition.activation.dependency_obligation_ref} is not fulfilled"
                        ),
                    )
                )
                continue
        blocked_by = tuple(
            sorted(dep for dep in definition.dependencies if dep not in dependency_states)
        )
        occurrences: list[tuple[int, date, date]]
        if rule.kind == "fixed_date":
            due_date = _parsed_date(str(rule.fixed_date))
            period_start = _parsed_timestamp(definition.agreement.effective_at)
            occurrences = [(1, period_start.astimezone(ZoneInfo(rule.timezone)).date(), due_date)]
        elif rule.kind == "relative_to_agreement":
            anchor = _anchor_date(definition, rule)
            if anchor is None:
                deferred.append(
                    DeferredObligation(
                        obligation_ref=definition.obligation_ref,
                        definition_digest=definition.definition_digest,
                        reason="anchor_unavailable",
                        detail="agreement has no expiry to anchor the due rule",
                    )
                )
                continue
            period_start = _parsed_timestamp(definition.agreement.effective_at)
            occurrences = [(1, period_start.astimezone(ZoneInfo(rule.timezone)).date(), anchor)]
        else:
            # An open-ended recurrence cannot outlive its agreement version.
            expiry = definition.agreement.expires_at
            occurrences = _occurrence_dates(
                rule.recurrence,  # type: ignore[arg-type]
                horizon_to=horizon_to,
                series_end=(
                    _parsed_timestamp(expiry).astimezone(ZoneInfo(rule.timezone)).date()
                    if expiry is not None
                    else None
                ),
            )
        in_horizon = [
            item for item in occurrences if horizon_from <= item[2] <= horizon_to
        ]
        if not in_horizon:
            deferred.append(
                DeferredObligation(
                    obligation_ref=definition.obligation_ref,
                    definition_digest=definition.definition_digest,
                    reason="outside_horizon",
                    detail="no occurrence falls inside the requested horizon",
                )
            )
            continue
        truncated_at: date | None = None
        if len(in_horizon) > MAX_INSTANCES_PER_OBLIGATION:
            truncated_at = in_horizon[MAX_INSTANCES_PER_OBLIGATION][2]
            in_horizon = in_horizon[:MAX_INSTANCES_PER_OBLIGATION]
        if total + len(in_horizon) > MAX_SCHEDULE_INSTANCES:
            keep = max(0, MAX_SCHEDULE_INSTANCES - total)
            if keep < len(in_horizon):
                truncated_at = in_horizon[keep][2] if keep < len(in_horizon) else truncated_at
            in_horizon = in_horizon[:keep]
        for index, period_start_date, raw_due in in_horizon:
            rolled = _roll_business_day(raw_due, rule.calendar)
            due_local, due_utc = _local_due(rolled, rule)
            if index == 1:
                # The first occurrence covers everything since the agreement became
                # effective; later occurrences cover the gap since the prior due date.
                period_start_at = _parsed_timestamp(definition.agreement.effective_at)
            else:
                period_start_at = datetime.combine(
                    period_start_date, time(0, 0), tzinfo=ZoneInfo(rule.timezone)
                ).astimezone(timezone.utc)
            if period_start_at > due_utc:
                period_start_at = due_utc
            evidence_due = due_utc - timedelta(days=definition.evidence_lead_days)
            if evidence_due < period_start_at:
                evidence_due = period_start_at
            notice_opens = (
                due_utc - timedelta(days=definition.notice_lead_days)
                if definition.notice_lead_days is not None
                else None
            )
            instances.append(
                ObligationInstance(
                    instance_ref=f"{definition.obligation_ref}:occ-{index:04d}",
                    obligation_ref=definition.obligation_ref,
                    definition_digest=definition.definition_digest,
                    agreement_version=definition.agreement.version,
                    due_rule_version=rule.rule_version,
                    occurrence_index=index,
                    period_start_at=_format_utc(period_start_at),
                    due_local=due_local,
                    due_at=_format_utc(due_utc),
                    evidence_due_at=_format_utc(evidence_due),
                    evidence_window_opens_at=_format_utc(period_start_at),
                    notice_window_opens_at=(
                        _format_utc(notice_opens) if notice_opens is not None else None
                    ),
                    blocked_by=blocked_by,
                    activated_by_event_ref=activated_by,
                )
            )
            total += 1
        if truncated_at is not None:
            truncations.append(
                ScheduleTruncation(
                    obligation_ref=definition.obligation_ref,
                    expanded_count=len(in_horizon),
                    next_expansion_from=truncated_at.isoformat(),
                )
            )

    instances.sort(key=lambda item: (item.due_at, item.obligation_ref, item.occurrence_index))
    schedule = {
        "scope": parsed.scope.to_dict(),
        "register_digest": register.register_digest,
        "agreement_version": register.agreement.version,
        "horizon": parsed.horizon.to_dict(),
        "as_of": parsed.as_of,
        "instances": [item.to_dict() for item in instances],
        "deferred": [
            item.to_dict() for item in sorted(deferred, key=lambda item: item.obligation_ref)
        ],
        "truncations": [
            item.to_dict()
            for item in sorted(truncations, key=lambda item: item.obligation_ref)
        ],
    }
    schedule["schedule_digest"] = obligation_schedule_digest(schedule)
    return ObligationSchedule.model_validate(schedule)


# --------------------------------------------------------------------------- #
# Evidence and fulfillment evaluation
# --------------------------------------------------------------------------- #


class ObligationEvidenceEnvelope(_StrictModel):
    schema_id: Literal["lightbulb.contract_obligation_evidence_envelope.v1"] = Field(
        default=OBLIGATION_EVIDENCE_SCHEMA, alias="schema"
    )
    use_ref: OpaqueRef
    custody_ref: OpaqueRef
    criterion_ref: OpaqueRef | None = None
    assertion: EvidenceAssertion = "satisfied"
    quantity: Decimal | None = None
    reference: PrimitiveEvidenceRef

    @field_validator("reference", mode="before")
    @classmethod
    def _revalidated(cls, value: Any) -> Any:
        return _detached_validation_payload(value)

    @field_validator("quantity", mode="before")
    @classmethod
    def _quantity(cls, value: Any) -> Any:
        if value is None:
            return None
        parsed = _decimal(value, field_name="quantity")
        if parsed < 0:
            raise ValueError("evidence quantity cannot be negative")
        return parsed


class CriterionFinding(_StrictModel):
    criterion_ref: OpaqueRef
    required: bool
    status: CriterionFindingStatus
    satisfied_quantity: Decimal | None = None
    target_quantity: Decimal | None = None
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=40)
    detail: BoundedText

    @field_validator("satisfied_quantity", "target_quantity", mode="before")
    @classmethod
    def _quantities(cls, value: Any, info: ValidationInfo) -> Any:
        return None if value is None else _decimal(value, field_name=str(info.field_name))

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _refs(cls, value: Any) -> Any:
        return _sorted_unique_tuple(value, label="finding evidence refs")


class EvidenceExclusion(_StrictModel):
    use_ref: OpaqueRef
    evidence_ref: OpaqueRef
    reason: EvidenceExclusionReason
    detail: BoundedText


class ObligationFulfillmentEvaluation(_StrictModel):
    schema_id: Literal[
        "lightbulb.contract_obligation_fulfillment_evaluation.v1"
    ] = Field(default=OBLIGATION_EVALUATION_SCHEMA, alias="schema")
    scope: ContractObligationScope
    instance_ref: OpaqueRef
    obligation_ref: OpaqueRef
    definition_digest: Sha256Digest
    as_of: str
    verdict: FulfillmentVerdict
    fulfillment_ratio: Decimal
    findings: tuple[CriterionFinding, ...] = Field(min_length=1, max_length=40)
    exclusions: tuple[EvidenceExclusion, ...] = Field(
        default_factory=tuple, max_length=MAX_EVIDENCE_PER_COMMAND
    )
    evidence_digest: Sha256Digest
    evaluation_digest: Sha256Digest = GENESIS_STATE_DIGEST

    @field_validator("as_of")
    @classmethod
    def _as_of(cls, value: str) -> str:
        return _timestamp(value, field_name="as_of")

    @field_validator("fulfillment_ratio", mode="before")
    @classmethod
    def _ratio(cls, value: Any) -> Any:
        parsed = _decimal(value, field_name="fulfillment_ratio")
        if not 0 <= parsed <= 1:
            raise ValueError("fulfillment_ratio must lie within [0, 1]")
        return parsed

    @model_validator(mode="after")
    def _evaluation_is_exact(self, info: ValidationInfo) -> "ObligationFulfillmentEvaluation":
        keys = [item.criterion_ref for item in self.findings]
        _unique(keys, label="finding criteria")
        if keys != sorted(keys):
            raise ValueError("findings must be sorted by criterion_ref")
        if self.verdict == "verified" and self.fulfillment_ratio != 1:
            raise ValueError("a verified evaluation must be fully fulfilled")
        if (info.context or {}).get("skip_obligation_digests"):
            return self
        if self.evaluation_digest != obligation_evaluation_digest(self):
            raise ValueError("evaluation_digest must commit the exact evaluation")
        return self


def obligation_evaluation_digest(
    evaluation: ObligationFulfillmentEvaluation | Mapping[str, Any],
) -> str:
    raw = dict(_detached_validation_payload(evaluation))
    raw.setdefault("evaluation_digest", GENESIS_STATE_DIGEST)
    parsed = ObligationFulfillmentEvaluation.model_validate(
        raw, context={"skip_obligation_digests": True}
    )
    return _digest_without(parsed.to_dict(), "evaluation_digest")


def obligation_evidence_digest(
    evidence: Sequence[ObligationEvidenceEnvelope],
) -> str:
    return _stable_digest(
        [item.to_dict() for item in sorted(evidence, key=lambda item: item.use_ref)]
    )


class ContractObligationEvaluationInput(_StrictModel):
    scope: ContractObligationScope
    definition: ObligationDefinition
    instance: ObligationInstance
    evidence: tuple[ObligationEvidenceEnvelope, ...] = Field(
        default_factory=tuple, max_length=MAX_EVIDENCE_PER_COMMAND
    )
    as_of: str
    requested_by_ref: OpaqueRef

    @field_validator("as_of")
    @classmethod
    def _as_of(cls, value: str) -> str:
        return _timestamp(value, field_name="as_of")

    @model_validator(mode="after")
    def _input_is_exact(self) -> "ContractObligationEvaluationInput":
        if self.definition.agreement.agreement_ref != self.scope.agreement_ref:
            raise ValueError("definition must bind the scoped agreement")
        if self.instance.obligation_ref != self.definition.obligation_ref or (
            self.instance.definition_digest != self.definition.definition_digest
        ):
            raise ValueError("instance must bind the exact definition digest")
        if self.instance.due_rule_version != self.definition.due_rule.rule_version:
            raise ValueError("instance due-rule version must match the definition")
        _validate_evidence_envelopes(self.evidence, scope=self.scope)
        return self


def _validate_evidence_envelopes(
    evidence: Sequence[ObligationEvidenceEnvelope],
    *,
    scope: ContractObligationScope,
) -> None:
    _unique([item.use_ref for item in evidence], label="evidence use refs")
    _unique(
        [item.reference.evidence_ref for item in evidence],
        label="portable evidence references",
    )
    for envelope in evidence:
        if envelope.custody_ref != scope.evidence_custody_ref:
            raise ValueError("evidence custody must exactly match the scoped custody")
        if envelope.reference.issuer_ref not in scope.authorized_evidence_issuer_refs:
            raise ValueError("evidence issuer is not authorized by scope")
        if envelope.reference.classification == PrimitiveEvidenceClassification.PUBLIC:
            raise ValueError("obligation evidence cannot use public classification")


def evaluate_contract_obligation_fulfillment(
    inputs: ContractObligationEvaluationInput | Mapping[str, Any],
) -> ObligationFulfillmentEvaluation:
    """Compare retained evidence against exact criteria; never decide breach."""

    parsed = ContractObligationEvaluationInput.model_validate(
        _detached_validation_payload(inputs)
    )
    definition = parsed.definition
    instance = parsed.instance
    as_of = _parsed_timestamp(parsed.as_of)
    period_start = _parsed_timestamp(instance.period_start_at)
    freshness = timedelta(days=definition.evidence_freshness_days)
    criteria = {item.criterion_ref: item for item in definition.criteria}
    usable: dict[str, list[ObligationEvidenceEnvelope]] = {ref: [] for ref in criteria}
    stale_by_criterion: dict[str, list[ObligationEvidenceEnvelope]] = {ref: [] for ref in criteria}
    exclusions: list[EvidenceExclusion] = []

    def exclude(envelope: ObligationEvidenceEnvelope, reason: EvidenceExclusionReason, detail: str) -> None:
        exclusions.append(
            EvidenceExclusion(
                use_ref=envelope.use_ref,
                evidence_ref=envelope.reference.evidence_ref,
                reason=reason,
                detail=detail,
            )
        )

    for envelope in sorted(parsed.evidence, key=lambda item: item.use_ref):
        reference = envelope.reference
        if reference.subject_ref != instance.instance_ref:
            exclude(
                envelope,
                "cross_obligation_evidence",
                f"evidence subject {reference.subject_ref} is not this instance",
            )
            continue
        if envelope.criterion_ref is None or envelope.criterion_ref not in criteria:
            exclude(envelope, "unknown_criterion", "evidence does not cite a defined criterion")
            continue
        observed = _parsed_timestamp(reference.observed_at)
        if observed > as_of:
            exclude(envelope, "observed_after_as_of", "evidence was observed after as_of")
            continue
        criterion = criteria[envelope.criterion_ref]
        if _GRADE_RANK[reference.verification_grade] < _GRADE_RANK[
            criterion.minimum_verification_grade
        ]:
            exclude(
                envelope,
                "grade_below_minimum",
                f"grade {reference.verification_grade.value} is below the criterion minimum",
            )
            continue
        if observed < period_start:
            stale_by_criterion[envelope.criterion_ref].append(envelope)
            exclude(
                envelope,
                "observed_before_period",
                "evidence predates this obligation period",
            )
            continue
        if as_of - observed > freshness:
            stale_by_criterion[envelope.criterion_ref].append(envelope)
            exclude(
                envelope,
                "stale_beyond_freshness",
                f"evidence is older than {definition.evidence_freshness_days} days",
            )
            continue
        usable[envelope.criterion_ref].append(envelope)

    findings: list[CriterionFinding] = []
    any_conflict = False
    any_stale_only = False
    any_usable = False
    required_total = Decimal(0)
    required_satisfied = Decimal(0)
    for criterion_ref in sorted(criteria):
        criterion = criteria[criterion_ref]
        items = usable[criterion_ref]
        refs = tuple(sorted(item.reference.evidence_ref for item in items))
        target = criterion.target_quantity
        if items:
            any_usable = True
        assertions = {item.assertion for item in items}
        if criterion.required:
            required_total += 1
        if not items:
            if stale_by_criterion[criterion_ref]:
                status: CriterionFindingStatus = "stale"
                detail = "only stale or out-of-period evidence was supplied"
                if criterion.required:
                    any_stale_only = True
            else:
                status = "missing"
                detail = "no usable evidence cites this criterion"
            findings.append(
                CriterionFinding(
                    criterion_ref=criterion_ref,
                    required=criterion.required,
                    status=status,
                    target_quantity=target,
                    evidence_refs=refs,
                    detail=detail,
                )
            )
            continue
        if len(assertions) > 1:
            any_conflict = True
            findings.append(
                CriterionFinding(
                    criterion_ref=criterion_ref,
                    required=criterion.required,
                    status="conflicting",
                    target_quantity=target,
                    evidence_refs=refs,
                    detail="retained evidence both asserts and denies satisfaction",
                )
            )
            continue
        if "not_satisfied" in assertions:
            findings.append(
                CriterionFinding(
                    criterion_ref=criterion_ref,
                    required=criterion.required,
                    status="not_satisfied",
                    target_quantity=target,
                    evidence_refs=refs,
                    detail="retained evidence denies satisfaction",
                )
            )
            continue
        if criterion.measure == "quantity":
            quantities = [item.quantity for item in items if item.quantity is not None]
            if len(quantities) != len(items):
                findings.append(
                    CriterionFinding(
                        criterion_ref=criterion_ref,
                        required=criterion.required,
                        status="indeterminate",
                        target_quantity=target,
                        evidence_refs=refs,
                        detail="quantity criterion evidence must carry quantities",
                    )
                )
                continue
            issuers = {item.reference.issuer_ref for item in items}
            if len(issuers) > 1 and len({str(q) for q in quantities}) > 1:
                any_conflict = True
                findings.append(
                    CriterionFinding(
                        criterion_ref=criterion_ref,
                        required=criterion.required,
                        status="conflicting",
                        target_quantity=target,
                        evidence_refs=refs,
                        detail="independent issuers report different quantities",
                    )
                )
                continue
            satisfied = max(quantities) if len(issuers) > 1 else sum(quantities, Decimal(0))
            assert target is not None
            if satisfied >= target:
                if criterion.required:
                    required_satisfied += 1
                findings.append(
                    CriterionFinding(
                        criterion_ref=criterion_ref,
                        required=criterion.required,
                        status="satisfied",
                        satisfied_quantity=satisfied,
                        target_quantity=target,
                        evidence_refs=refs,
                        detail="retained evidence meets the quantity target",
                    )
                )
            else:
                ratio = satisfied / target
                if criterion.required:
                    required_satisfied += ratio
                findings.append(
                    CriterionFinding(
                        criterion_ref=criterion_ref,
                        required=criterion.required,
                        status="partial",
                        satisfied_quantity=satisfied,
                        target_quantity=target,
                        evidence_refs=refs,
                        detail="retained evidence covers only part of the quantity target",
                    )
                )
            continue
        if criterion.required:
            required_satisfied += 1
        findings.append(
            CriterionFinding(
                criterion_ref=criterion_ref,
                required=criterion.required,
                status="satisfied",
                target_quantity=target,
                evidence_refs=refs,
                detail="retained evidence asserts satisfaction at or above the minimum grade",
            )
        )

    required_findings = [item for item in findings if item.required]
    if any_conflict:
        verdict: FulfillmentVerdict = "conflicting"
    elif any_stale_only:
        verdict = "stale"
    elif not any_usable:
        verdict = "indeterminate"
    elif all(item.status == "satisfied" for item in required_findings):
        verdict = "verified"
    else:
        verdict = "incomplete"
    ratio_value = (
        (required_satisfied / required_total) if required_total else Decimal(0)
    ).quantize(Decimal("0.000001"))
    if verdict == "verified":
        ratio_value = Decimal(1)
    evaluation = {
        "scope": parsed.scope.to_dict(),
        "instance_ref": instance.instance_ref,
        "obligation_ref": instance.obligation_ref,
        "definition_digest": definition.definition_digest,
        "as_of": parsed.as_of,
        "verdict": verdict,
        "fulfillment_ratio": str(ratio_value),
        "findings": [item.to_dict() for item in findings],
        "exclusions": [item.to_dict() for item in exclusions],
        "evidence_digest": obligation_evidence_digest(parsed.evidence),
    }
    evaluation["evaluation_digest"] = obligation_evaluation_digest(evaluation)
    return ObligationFulfillmentEvaluation.model_validate(evaluation)


# --------------------------------------------------------------------------- #
# Transition proposals
# --------------------------------------------------------------------------- #


class DependencyAttestation(_StrictModel):
    obligation_ref: OpaqueRef
    fulfilled_instance_ref: OpaqueRef
    fulfilled_state_digest: Sha256Digest


class OpenEvidenceWindowPackage(_StrictModel):
    kind: Literal["open_evidence_window"] = "open_evidence_window"
    note: BoundedText | None = None


class RecordFulfillmentPackage(_StrictModel):
    kind: Literal["record_fulfillment"] = "record_fulfillment"
    evaluation: ObligationFulfillmentEvaluation
    dependency_attestations: tuple[DependencyAttestation, ...] = Field(
        default_factory=tuple, max_length=20
    )

    @field_validator("dependency_attestations", mode="before")
    @classmethod
    def _attestations(cls, value: Any) -> Any:
        if isinstance(value, (list, tuple)):
            items = tuple(value)
            return tuple(
                sorted(
                    items,
                    key=lambda item: str(
                        item.get("obligation_ref") if isinstance(item, Mapping) else item.obligation_ref
                    ),
                )
            )
        return value


class OpenExceptionPackage(_StrictModel):
    kind: Literal["open_exception"] = "open_exception"
    exception_code: ExceptionCode
    opened_by_ref: OpaqueRef
    owner_role_ref: OpaqueRef
    cure_by: str
    note: BoundedText | None = None

    @field_validator("cure_by")
    @classmethod
    def _cure(cls, value: str) -> str:
        return _timestamp(value, field_name="cure_by")


class CureExceptionPackage(_StrictModel):
    kind: Literal["cure_exception"] = "cure_exception"
    cure_evidence_ref: OpaqueRef
    cured_by_ref: OpaqueRef


class SupersedePackage(_StrictModel):
    kind: Literal["supersede"] = "supersede"
    superseding_agreement: AgreementVersionRef
    successor_obligation_ref: OpaqueRef
    successor_definition_digest: Sha256Digest
    supersession_evidence_ref: OpaqueRef


class EscalatePackage(_StrictModel):
    kind: Literal["escalate"] = "escalate"
    reason: EscalationReason
    escalate_to_role_ref: OpaqueRef
    note: BoundedText | None = None


class RequireAuthoritativeChangePackage(_StrictModel):
    kind: Literal["require_authoritative_change"] = "require_authoritative_change"
    reason: AuthoritativeChangeReason
    requested_change_ref: OpaqueRef
    note: BoundedText | None = None


TransitionPackage = Annotated[
    OpenEvidenceWindowPackage
    | RecordFulfillmentPackage
    | OpenExceptionPackage
    | CureExceptionPackage
    | SupersedePackage
    | EscalatePackage
    | RequireAuthoritativeChangePackage,
    Field(discriminator="kind"),
]


class ContractObligationTransitionCommand(_StrictModel):
    schema_id: Literal["lightbulb.contract_obligation_transition_command.v1"] = Field(
        default=OBLIGATION_COMMAND_SCHEMA, alias="schema"
    )
    kind: TransitionKind
    scope: ContractObligationScope
    instance_ref: OpaqueRef
    obligation_ref: OpaqueRef
    definition_digest: Sha256Digest
    transition_ref: OpaqueRef
    idempotency_key: OpaqueRef
    expected_version: int = Field(ge=0, le=MAX_OBLIGATION_TRANSITIONS)
    expected_state_digest: Sha256Digest
    occurred_at: str
    host_outcome_report: Literal[
        "reported_certain", "reported_in_doubt", "unreported"
    ] = "reported_certain"
    requested_by_ref: OpaqueRef
    evidence: tuple[ObligationEvidenceEnvelope, ...] = Field(
        default_factory=tuple, max_length=MAX_EVIDENCE_PER_COMMAND
    )
    package: TransitionPackage
    request_digest: Sha256Digest = GENESIS_STATE_DIGEST

    @field_validator("occurred_at")
    @classmethod
    def _occurred(cls, value: str) -> str:
        return _timestamp(value, field_name="occurred_at")

    @model_validator(mode="after")
    def _command_is_exact(self, info: ValidationInfo) -> "ContractObligationTransitionCommand":
        if self.kind != self.package.kind:
            raise ValueError("command kind must exactly match its tagged package")
        _validate_evidence_envelopes(self.evidence, scope=self.scope)
        for envelope in self.evidence:
            if envelope.reference.subject_ref != self.instance_ref:
                raise ValueError("command evidence must bind the exact instance reference")
            if _parsed_timestamp(envelope.reference.observed_at) > _parsed_timestamp(
                self.occurred_at
            ):
                raise ValueError("evidence cannot be observed after the transition")
        if isinstance(self.package, RecordFulfillmentPackage):
            evaluation = self.package.evaluation
            if (
                evaluation.scope != self.scope
                or evaluation.instance_ref != self.instance_ref
                or evaluation.obligation_ref != self.obligation_ref
                or evaluation.definition_digest != self.definition_digest
            ):
                raise ValueError("fulfillment evaluation must bind the exact instance")
            if evaluation.evidence_digest != obligation_evidence_digest(self.evidence):
                raise ValueError("command evidence must equal the evaluated evidence set")
            if _parsed_timestamp(evaluation.as_of) > _parsed_timestamp(self.occurred_at):
                raise ValueError("evaluation cannot be later than the transition")
            _unique(
                [item.obligation_ref for item in self.package.dependency_attestations],
                label="dependency attestations",
            )
        elif isinstance(self.package, CureExceptionPackage):
            if self.package.cure_evidence_ref not in {
                item.reference.evidence_ref for item in self.evidence
            }:
                raise ValueError("cure evidence must be retained in the command evidence")
        elif isinstance(self.package, SupersedePackage):
            if self.package.supersession_evidence_ref not in {
                item.reference.evidence_ref for item in self.evidence
            }:
                raise ValueError("supersession evidence must be retained in the command")
            if self.package.superseding_agreement.agreement_ref != self.scope.agreement_ref:
                raise ValueError("superseding agreement must share the scoped agreement")
            if self.package.successor_obligation_ref == self.obligation_ref:
                raise ValueError("a successor obligation must carry a new reference")
        elif isinstance(self.package, OpenExceptionPackage):
            if _parsed_timestamp(self.package.cure_by) <= _parsed_timestamp(self.occurred_at):
                raise ValueError("exception cure_by must follow the transition time")
        if (info.context or {}).get("skip_obligation_digests"):
            return self
        if self.request_digest != contract_obligation_command_digest(self):
            raise ValueError("request_digest must commit the exact normalized command")
        return self


def _normalized_command_payload(
    command: ContractObligationTransitionCommand | Mapping[str, Any],
) -> dict[str, Any]:
    raw = dict(_detached_validation_payload(command))
    raw.setdefault("request_digest", GENESIS_STATE_DIGEST)
    parsed = ContractObligationTransitionCommand.model_validate(
        raw, context={"skip_obligation_digests": True}
    )
    return parsed.to_dict()


def contract_obligation_command_digest(
    command: ContractObligationTransitionCommand | Mapping[str, Any],
) -> str:
    return _digest_without(_normalized_command_payload(command), "request_digest")


def seal_contract_obligation_command(command: Mapping[str, Any]) -> dict[str, Any]:
    payload = _normalized_command_payload(command)
    payload["request_digest"] = contract_obligation_command_digest(payload)
    return ContractObligationTransitionCommand.model_validate(payload).to_dict()


class ContractObligationTransitionCandidate(_StrictModel):
    to_version: int = Field(ge=1, le=MAX_OBLIGATION_TRANSITIONS)
    prior_state_digest: Sha256Digest
    to_status: ObligationInstanceStatus
    evidence_digest: Sha256Digest
    transition_digest: Sha256Digest
    command: ContractObligationTransitionCommand

    @model_validator(mode="after")
    def _candidate_is_self_proving(self) -> "ContractObligationTransitionCandidate":
        if self.command.expected_version != self.to_version - 1:
            raise ValueError("candidate version must match command revision fence")
        if self.command.expected_state_digest != self.prior_state_digest:
            raise ValueError("candidate prior digest must match command state fence")
        if self.evidence_digest != obligation_evidence_digest(self.command.evidence):
            raise ValueError("candidate evidence digest is invalid")
        if self.transition_digest != _transition_digest(
            to_version=self.to_version,
            prior_state_digest=self.prior_state_digest,
            to_status=self.to_status,
            command=self.command,
        ):
            raise ValueError("transition digest must commit the exact candidate")
        return self


def _transition_digest(
    *,
    to_version: int,
    prior_state_digest: str,
    to_status: str,
    command: ContractObligationTransitionCommand,
) -> str:
    return _stable_digest(
        {
            "to_version": to_version,
            "prior_state_digest": prior_state_digest,
            "to_status": to_status,
            "request_digest": command.request_digest,
            "transition_ref": command.transition_ref,
            "idempotency_key": command.idempotency_key,
            "kind": command.kind,
        }
    )


def _state_digest(
    scope: ContractObligationScope,
    instance: ObligationInstance,
    history: Sequence[ContractObligationTransitionCandidate],
) -> str:
    return _stable_digest(
        {
            "scope": scope.to_dict(),
            "instance": instance.to_dict(),
            "transitions": [item.transition_digest for item in history],
        }
    )


def genesis_instance_state_digest(
    scope: ContractObligationScope | Mapping[str, Any],
    instance: ObligationInstance | Mapping[str, Any],
) -> str:
    parsed_scope = ContractObligationScope.model_validate(_detached_validation_payload(scope))
    parsed_instance = ObligationInstance.model_validate(_detached_validation_payload(instance))
    return _state_digest(parsed_scope, parsed_instance, ())


class OpenException(_StrictModel):
    exception_code: ExceptionCode
    opened_by_ref: OpaqueRef
    owner_role_ref: OpaqueRef
    opened_at: str
    cure_by: str
    occurrences: int = Field(ge=1, le=MAX_OBLIGATION_TRANSITIONS)


class ContractObligationInstanceSnapshot(_StrictModel):
    schema_id: Literal["lightbulb.contract_obligation_instance_snapshot.v1"] = Field(
        default=OBLIGATION_SNAPSHOT_SCHEMA, alias="schema"
    )
    scope: ContractObligationScope
    instance: ObligationInstance
    status: ObligationInstanceStatus
    version: int = Field(ge=1, le=MAX_OBLIGATION_TRANSITIONS)
    transition_history: tuple[ContractObligationTransitionCandidate, ...] = Field(
        min_length=1, max_length=MAX_OBLIGATION_TRANSITIONS
    )
    open_exception: OpenException | None = None
    exception_count: int = Field(ge=0, le=MAX_OBLIGATION_TRANSITIONS)
    state_digest: Sha256Digest

    @model_validator(mode="after")
    def _snapshot_is_exact(self) -> "ContractObligationInstanceSnapshot":
        history = self.transition_history
        if self.version != len(history):
            raise ValueError("snapshot version must equal transition count")
        if [item.to_version for item in history] != list(range(1, self.version + 1)):
            raise ValueError("transition candidate versions must be contiguous")
        _validate_history_uniqueness(history)
        prefix: tuple[ContractObligationTransitionCandidate, ...] = ()
        status: str = "scheduled"
        derived_exception: OpenException | None = None
        exception_count = 0
        for index, candidate in enumerate(history):
            command = candidate.command
            if command.scope != self.scope:
                raise ValueError("every retained transition must match snapshot scope")
            if (
                command.instance_ref != self.instance.instance_ref
                or command.obligation_ref != self.instance.obligation_ref
                or command.definition_digest != self.instance.definition_digest
            ):
                raise ValueError("every retained transition must bind the snapshot instance")
            if candidate.prior_state_digest != _state_digest(self.scope, self.instance, prefix):
                raise ValueError("historical transition has a discontinuous state digest")
            next_status = _TRANSITIONS.get(status, {}).get(command.kind)
            if next_status is None or next_status != candidate.to_status:
                raise ValueError(f"historical transition {index + 1} is not a legal move")
            if index > 0 and _parsed_timestamp(command.occurred_at) < _parsed_timestamp(
                history[index - 1].command.occurred_at
            ):
                raise ValueError("historical transitions must be chronological")
            if isinstance(command.package, OpenExceptionPackage):
                exception_count += 1
                derived_exception = OpenException(
                    exception_code=command.package.exception_code,
                    opened_by_ref=command.package.opened_by_ref,
                    owner_role_ref=command.package.owner_role_ref,
                    opened_at=command.occurred_at,
                    cure_by=command.package.cure_by,
                    occurrences=exception_count,
                )
            elif next_status != "exception_open":
                derived_exception = None
            status = next_status
            prefix = (*prefix, candidate)
        if self.status != status:
            raise ValueError("snapshot status must be derived from its transition history")
        if self.open_exception != derived_exception:
            raise ValueError("snapshot open_exception must be derived from history")
        if self.exception_count != exception_count:
            raise ValueError("snapshot exception_count must be derived from history")
        if self.state_digest != _state_digest(self.scope, self.instance, history):
            raise ValueError("state_digest must commit the exact instance snapshot")
        return self


def _validate_history_uniqueness(
    history: Sequence[ContractObligationTransitionCandidate],
) -> None:
    commands = [item.command for item in history]
    for field_name in ("transition_ref", "idempotency_key", "request_digest"):
        _unique(
            [str(getattr(command, field_name)) for command in commands],
            label=f"historical {field_name} values",
        )
    envelopes = [envelope for command in commands for envelope in command.evidence]
    _unique([item.use_ref for item in envelopes], label="historical evidence use refs")
    _unique(
        [item.reference.evidence_ref for item in envelopes],
        label="historical portable evidence references",
    )


class ContractObligationTransitionInput(_StrictModel):
    scope: ContractObligationScope
    definition: ObligationDefinition
    instance: ObligationInstance
    command: ContractObligationTransitionCommand
    current_snapshot: ContractObligationInstanceSnapshot | None = None

    @model_validator(mode="after")
    def _input_is_exact(self) -> "ContractObligationTransitionInput":
        if self.command.scope != self.scope:
            raise ValueError("command scope must exactly match transition input scope")
        if self.definition.agreement.agreement_ref != self.scope.agreement_ref:
            raise ValueError("definition must bind the scoped agreement")
        if (
            self.instance.obligation_ref != self.definition.obligation_ref
            or self.instance.definition_digest != self.definition.definition_digest
            or self.instance.due_rule_version != self.definition.due_rule.rule_version
        ):
            raise ValueError("instance must bind the exact definition")
        if (
            self.command.instance_ref != self.instance.instance_ref
            or self.command.obligation_ref != self.instance.obligation_ref
            or self.command.definition_digest != self.instance.definition_digest
        ):
            raise ValueError("command must bind the exact instance")
        if self.current_snapshot is not None and (
            self.current_snapshot.scope != self.scope
            or self.current_snapshot.instance != self.instance
        ):
            raise ValueError("snapshot must bind the exact scope and instance")
        return self


class ContractObligationRecovery(_StrictModel):
    disposition: RecoveryDisposition
    automatic_retry_allowed: Literal[False] = False
    instructions: BoundedText | None = None

    @model_validator(mode="after")
    def _recovery_is_bounded(self) -> "ContractObligationRecovery":
        if (self.disposition == "not_required") != (self.instructions is None):
            raise ValueError("recovery instructions must match recovery disposition")
        return self


class ContractObligationEffectBoundary(_StrictModel):
    sdk_candidate_only: Literal[True] = True
    legal_determination_made: Literal[False] = False
    binding_status_asserted: Literal[False] = False
    breach_declared: Literal[False] = False
    obligation_waived: Literal[False] = False
    counterparty_contacted: Literal[False] = False
    payment_executed: Literal[False] = False
    model_supplied_scope_accepted: Literal[False] = False
    persistence_written: Literal[False] = False
    approval_recorded: Literal[False] = False
    connector_effect_executed: Literal[False] = False


class ContractObligationTransitionReceipt(_StrictModel):
    schema_id: Literal["lightbulb.contract_obligation_transition_receipt.v1"] = Field(
        default=OBLIGATION_RECEIPT_SCHEMA, alias="schema"
    )
    transition_ref: OpaqueRef
    idempotency_key: OpaqueRef
    request_digest: Sha256Digest
    command_kind: TransitionKind
    status: Literal["candidate_materialized", "rejected", "in_doubt"]
    from_version: int = Field(ge=0, le=MAX_OBLIGATION_TRANSITIONS)
    to_version: int = Field(ge=0, le=MAX_OBLIGATION_TRANSITIONS)
    from_status: ObligationInstanceStatus
    to_status: ObligationInstanceStatus
    from_state_digest: Sha256Digest
    to_state_digest: Sha256Digest
    evidence_digest: Sha256Digest
    rejection_code: str | None = Field(default=None, min_length=1, max_length=120)
    recovery: ContractObligationRecovery
    effect_boundary: ContractObligationEffectBoundary = Field(
        default_factory=ContractObligationEffectBoundary
    )

    @model_validator(mode="after")
    def _receipt_is_coherent(self) -> "ContractObligationTransitionReceipt":
        if self.status == "candidate_materialized":
            if self.to_version != self.from_version + 1:
                raise ValueError("materialized candidate must advance exactly one version")
            if self.to_state_digest == self.from_state_digest:
                raise ValueError("materialized candidate must advance the state digest")
            if self.rejection_code is not None or self.recovery.disposition != "not_required":
                raise ValueError("materialized candidate cannot carry rejection recovery")
        else:
            if self.to_version != self.from_version or self.to_status != self.from_status:
                raise ValueError("rejected or in-doubt transition cannot advance")
            if self.to_state_digest != self.from_state_digest:
                raise ValueError("rejected or in-doubt transition cannot change state")
            if self.rejection_code is None or self.recovery.disposition == "not_required":
                raise ValueError("rejected transition requires a code and recovery route")
        if self.status == "in_doubt" and self.recovery.disposition != "manual_reconciliation":
            raise ValueError("in-doubt transition requires manual reconciliation")
        return self


class ContractObligationTransitionResult(_StrictModel):
    schema_id: Literal["lightbulb.contract_obligation_transition_result.v1"] = Field(
        default=OBLIGATION_TRANSITION_RESULT_SCHEMA, alias="schema"
    )
    candidate_validated: bool
    snapshot: ContractObligationInstanceSnapshot | None = None
    transition_receipt: ContractObligationTransitionReceipt
    effect_boundary: ContractObligationEffectBoundary = Field(
        default_factory=ContractObligationEffectBoundary
    )

    @model_validator(mode="after")
    def _result_is_coherent(self) -> "ContractObligationTransitionResult":
        receipt = self.transition_receipt
        if self.candidate_validated != (receipt.status == "candidate_materialized"):
            raise ValueError("candidate flag must match transition receipt")
        if self.candidate_validated and self.snapshot is None:
            raise ValueError("validated candidate requires a resulting snapshot")
        if self.snapshot is not None and (
            self.snapshot.version != receipt.to_version
            or self.snapshot.state_digest != receipt.to_state_digest
            or self.snapshot.status != receipt.to_status
        ):
            raise ValueError("result snapshot must match transition receipt")
        if self.candidate_validated and self.snapshot is not None:
            latest = self.snapshot.transition_history[-1]
            command = latest.command
            if (
                receipt.transition_ref != command.transition_ref
                or receipt.idempotency_key != command.idempotency_key
                or receipt.request_digest != command.request_digest
                or receipt.command_kind != command.kind
                or receipt.from_version != latest.to_version - 1
                or receipt.from_state_digest != latest.prior_state_digest
                or receipt.evidence_digest != latest.evidence_digest
            ):
                raise ValueError("candidate receipt must bind the exact retained transition")
        return self


class _TransitionRejected(ValueError):
    def __init__(
        self,
        code: str,
        instructions: str,
        recovery: RecoveryDisposition,
        *,
        in_doubt: bool = False,
    ) -> None:
        super().__init__(instructions)
        self.code = code
        self.instructions = instructions
        self.recovery = recovery
        self.in_doubt = in_doubt


def _check_history_conflicts(
    command: ContractObligationTransitionCommand,
    history: Sequence[ContractObligationTransitionCandidate],
) -> None:
    for candidate in history:
        prior = candidate.command
        if prior.request_digest == command.request_digest:
            raise _TransitionRejected(
                "TRANSITION_ALREADY_APPLIED",
                "This exact transition is already retained; do not replay it.",
                "do_not_replay",
            )
        if prior.transition_ref == command.transition_ref or (
            prior.idempotency_key == command.idempotency_key
        ):
            raise _TransitionRejected(
                "IDEMPOTENCY_CONFLICT",
                "A different transition already used this reference or idempotency key.",
                "manual_reconciliation",
            )
    retained_evidence = {
        envelope.reference.evidence_ref
        for candidate in history
        for envelope in candidate.command.evidence
    }
    retained_uses = {
        envelope.use_ref for candidate in history for envelope in candidate.command.evidence
    }
    for envelope in command.evidence:
        if envelope.reference.evidence_ref in retained_evidence or (
            envelope.use_ref in retained_uses
        ):
            raise _TransitionRejected(
                "EVIDENCE_ALREADY_CONSUMED",
                "Evidence references are single-use within one instance history.",
                "correct_input",
            )


def _validate_transition_semantics(
    inputs: ContractObligationTransitionInput,
    status: str,
    snapshot: ContractObligationInstanceSnapshot | None,
) -> str:
    command = inputs.command
    instance = inputs.instance
    definition = inputs.definition
    occurred = _parsed_timestamp(command.occurred_at)
    if status in TERMINAL_INSTANCE_STATUSES:
        raise _TransitionRejected(
            "INSTANCE_TERMINAL",
            f"Instance is already {status}; a new instance requires Spring re-baselining.",
            "do_not_replay",
        )
    next_status = _TRANSITIONS[status].get(command.kind)
    if next_status is None:
        raise _TransitionRejected(
            "ILLEGAL_TRANSITION",
            f"{command.kind} is not allowed from {status}.",
            "correct_input",
        )
    if snapshot is not None and occurred < _parsed_timestamp(
        snapshot.transition_history[-1].command.occurred_at
    ):
        raise _TransitionRejected(
            "NON_CHRONOLOGICAL_TRANSITION",
            "Transition time precedes the last retained transition.",
            "correct_input",
        )
    if occurred < _parsed_timestamp(instance.period_start_at):
        raise _TransitionRejected(
            "BEFORE_PERIOD_START",
            "Transition precedes the obligation period start.",
            "correct_input",
        )
    package = command.package
    if isinstance(package, OpenEvidenceWindowPackage):
        if occurred < _parsed_timestamp(instance.evidence_window_opens_at):
            raise _TransitionRejected(
                "EVIDENCE_WINDOW_NOT_OPEN",
                "The evidence window has not opened for this instance.",
                "correct_input",
            )
    elif isinstance(package, RecordFulfillmentPackage):
        recomputed = evaluate_contract_obligation_fulfillment(
            {
                "scope": inputs.scope.to_dict(),
                "definition": definition.to_dict(),
                "instance": instance.to_dict(),
                "evidence": [item.to_dict() for item in command.evidence],
                "as_of": package.evaluation.as_of,
                "requested_by_ref": command.requested_by_ref,
            }
        )
        if recomputed.evaluation_digest != package.evaluation.evaluation_digest:
            raise _TransitionRejected(
                "EVALUATION_FORGED",
                "Supplied evaluation does not match a fresh deterministic evaluation.",
                "correct_input",
            )
        if recomputed.verdict != "verified":
            raise _TransitionRejected(
                "FULFILLMENT_NOT_VERIFIED",
                f"Evaluation verdict is {recomputed.verdict}; open an exception or "
                "supply complete, fresh, consistent evidence.",
                "correct_input",
            )
        attested = {
            item.obligation_ref: item for item in package.dependency_attestations
        }
        missing = [dep for dep in instance.blocked_by if dep not in attested]
        if missing:
            raise _TransitionRejected(
                "DEPENDENCY_UNRESOLVED",
                f"Blocking dependencies lack fulfillment attestations: {', '.join(missing)}.",
                "correct_input",
            )
        extra = [ref for ref in attested if ref not in instance.blocked_by]
        if extra:
            raise _TransitionRejected(
                "DEPENDENCY_ATTESTATION_UNEXPECTED",
                "Attestations reference obligations that do not block this instance.",
                "correct_input",
            )
    elif isinstance(package, OpenExceptionPackage):
        max_cure = occurred + timedelta(days=definition.escalation_policy.max_exception_days)
        if _parsed_timestamp(package.cure_by) > max_cure:
            raise _TransitionRejected(
                "EXCEPTION_CURE_EXCEEDS_POLICY",
                "Exception cure_by exceeds the definition's maximum exception window.",
                "correct_input",
            )
        if package.opened_by_ref == package.owner_role_ref:
            raise _TransitionRejected(
                "EXCEPTION_OWNER_NOT_SEPARATE",
                "Exception opener and owning role must be structurally distinct.",
                "correct_input",
            )
    elif isinstance(package, CureExceptionPackage):
        assert snapshot is not None and snapshot.open_exception is not None
        if occurred > _parsed_timestamp(snapshot.open_exception.cure_by):
            raise _TransitionRejected(
                "EXCEPTION_CURE_MISSED",
                "Cure arrived after cure_by; escalate or request authoritative change.",
                "correct_input",
            )
    elif isinstance(package, SupersedePackage):
        if package.superseding_agreement.version <= instance.agreement_version:
            raise _TransitionRejected(
                "SUPERSESSION_VERSION_NOT_ADVANCED",
                "Superseding agreement must be a later version than the instance agreement.",
                "correct_input",
            )
        if package.superseding_agreement.supersedes_version is None:
            raise _TransitionRejected(
                "SUPERSESSION_REQUIRES_AMENDMENT",
                "Superseding agreement must declare the version it supersedes.",
                "correct_input",
            )
        if occurred < _parsed_timestamp(package.superseding_agreement.approved_at):
            raise _TransitionRejected(
                "SUPERSESSION_BEFORE_APPROVAL",
                "Supersession cannot precede approval of the amending version.",
                "correct_input",
            )
    elif isinstance(package, EscalatePackage):
        policy = definition.escalation_policy
        overdue_at = _parsed_timestamp(instance.due_at) + timedelta(
            days=policy.escalate_after_overdue_days
        )
        cure_missed = (
            snapshot is not None
            and snapshot.open_exception is not None
            and occurred > _parsed_timestamp(snapshot.open_exception.cure_by)
        )
        repeated = snapshot is not None and snapshot.exception_count >= 2
        blocked = bool(instance.blocked_by)
        justified = {
            "overdue_beyond_policy": occurred >= overdue_at,
            "exception_cure_missed": cure_missed,
            "repeated_exception": repeated,
            "dependency_unresolved": blocked and occurred >= _parsed_timestamp(instance.due_at),
        }[package.reason]
        if not justified:
            raise _TransitionRejected(
                "ESCALATION_NOT_JUSTIFIED",
                f"Escalation reason {package.reason} is not supported by the instance state.",
                "correct_input",
            )
        if package.escalate_to_role_ref != policy.escalate_to_role_ref:
            raise _TransitionRejected(
                "ESCALATION_ROLE_MISMATCH",
                "Escalation must target the role fixed by the definition's policy.",
                "correct_input",
            )
    return next_status


def materialize_contract_obligation_transition(
    inputs: ContractObligationTransitionInput | Mapping[str, Any],
) -> ContractObligationTransitionResult:
    """Materialize exactly one bounded, SDK-only obligation transition candidate."""

    parsed = ContractObligationTransitionInput.model_validate(
        _detached_validation_payload(inputs)
    )
    snapshot = parsed.current_snapshot
    command = parsed.command
    history = snapshot.transition_history if snapshot is not None else ()
    from_version = snapshot.version if snapshot is not None else 0
    from_status: str = snapshot.status if snapshot is not None else "scheduled"
    from_digest = (
        snapshot.state_digest
        if snapshot is not None
        else _state_digest(parsed.scope, parsed.instance, ())
    )
    evidence_digest = obligation_evidence_digest(command.evidence)

    def rejected(exc: _TransitionRejected) -> ContractObligationTransitionResult:
        receipt = ContractObligationTransitionReceipt(
            transition_ref=command.transition_ref,
            idempotency_key=command.idempotency_key,
            request_digest=command.request_digest,
            command_kind=command.kind,
            status="in_doubt" if exc.in_doubt else "rejected",
            from_version=from_version,
            to_version=from_version,
            from_status=from_status,  # type: ignore[arg-type]
            to_status=from_status,  # type: ignore[arg-type]
            from_state_digest=from_digest,
            to_state_digest=from_digest,
            evidence_digest=evidence_digest,
            rejection_code=exc.code,
            recovery=ContractObligationRecovery(
                disposition=exc.recovery, instructions=exc.instructions
            ),
        )
        return ContractObligationTransitionResult(
            candidate_validated=False, snapshot=None, transition_receipt=receipt
        )

    try:
        if command.host_outcome_report != "reported_certain":
            raise _TransitionRejected(
                "OUTCOME_IN_DOUBT",
                "Host reported an uncertain outcome; reconcile in Spring before replay.",
                "manual_reconciliation",
                in_doubt=True,
            )
        # Exact replays and reference reuse are reported before the revision
        # fence so a duplicate delivery is told "do not replay" rather than
        # "refresh and try again".
        _check_history_conflicts(command, history)
        if command.expected_version != from_version or (
            command.expected_state_digest != from_digest
        ):
            raise _TransitionRejected(
                "STALE_SNAPSHOT",
                "Command revision or state fence does not match the current snapshot.",
                "refresh_snapshot",
            )
        if from_version >= MAX_OBLIGATION_TRANSITIONS:
            raise _TransitionRejected(
                "TRANSITION_BOUND_REACHED",
                "This instance reached its bounded transition count; Spring must re-baseline.",
                "manual_reconciliation",
            )
        next_status = _validate_transition_semantics(parsed, from_status, snapshot)
    except _TransitionRejected as exc:
        return rejected(exc)

    candidate = ContractObligationTransitionCandidate(
        to_version=from_version + 1,
        prior_state_digest=from_digest,
        to_status=next_status,  # type: ignore[arg-type]
        evidence_digest=evidence_digest,
        transition_digest=_transition_digest(
            to_version=from_version + 1,
            prior_state_digest=from_digest,
            to_status=next_status,
            command=command,
        ),
        command=command,
    )
    new_history = (*history, candidate)
    exception_count = snapshot.exception_count if snapshot is not None else 0
    open_exception = snapshot.open_exception if snapshot is not None else None
    if isinstance(command.package, OpenExceptionPackage):
        exception_count += 1
        open_exception = OpenException(
            exception_code=command.package.exception_code,
            opened_by_ref=command.package.opened_by_ref,
            owner_role_ref=command.package.owner_role_ref,
            opened_at=command.occurred_at,
            cure_by=command.package.cure_by,
            occurrences=exception_count,
        )
    elif next_status != "exception_open":
        open_exception = None
    resulting = ContractObligationInstanceSnapshot(
        scope=parsed.scope,
        instance=parsed.instance,
        status=next_status,  # type: ignore[arg-type]
        version=from_version + 1,
        transition_history=new_history,
        open_exception=open_exception,
        exception_count=exception_count,
        state_digest=_state_digest(parsed.scope, parsed.instance, new_history),
    )
    receipt = ContractObligationTransitionReceipt(
        transition_ref=command.transition_ref,
        idempotency_key=command.idempotency_key,
        request_digest=command.request_digest,
        command_kind=command.kind,
        status="candidate_materialized",
        from_version=from_version,
        to_version=resulting.version,
        from_status=from_status,  # type: ignore[arg-type]
        to_status=resulting.status,
        from_state_digest=from_digest,
        to_state_digest=resulting.state_digest,
        evidence_digest=evidence_digest,
        recovery=ContractObligationRecovery(disposition="not_required"),
    )
    return ContractObligationTransitionResult(
        candidate_validated=True, snapshot=resulting, transition_receipt=receipt
    )


# --------------------------------------------------------------------------- #
# Portfolio assessment
# --------------------------------------------------------------------------- #


class PortfolioInstanceView(_StrictModel):
    instance_ref: OpaqueRef
    obligation_ref: OpaqueRef
    status: ObligationInstanceStatus
    kind: ObligationKind
    direction: ObligationDirection
    materiality: Materiality
    due_at: str
    evidence_due_at: str
    days_overdue: int = Field(ge=0, le=100_000)
    monetary: MonetaryTerms | None = None
    blocked_by: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=20)


class DependencyConflict(_StrictModel):
    instance_ref: OpaqueRef
    depends_on_obligation_ref: OpaqueRef
    detail: BoundedText


class EscalationCandidate(_StrictModel):
    instance_ref: OpaqueRef
    reason: EscalationReason
    escalate_to_role_ref: OpaqueRef
    detail: BoundedText


class MaterialExposure(_StrictModel):
    currency: CurrencyCode
    direction: ObligationDirection
    amount: Decimal
    instance_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=MAX_PORTFOLIO_INSTANCES)

    @field_validator("amount", mode="before")
    @classmethod
    def _amount(cls, value: Any) -> Any:
        return _decimal(value, field_name="amount")


class ContractObligationPortfolioAssessment(_StrictModel):
    schema_id: Literal[
        "lightbulb.contract_obligation_portfolio_assessment.v1"
    ] = Field(default=OBLIGATION_PORTFOLIO_SCHEMA, alias="schema")
    scope: ContractObligationScope
    as_of: str
    upcoming_window_days: int = Field(ge=1, le=365)
    status_counts: dict[str, int]
    upcoming: tuple[PortfolioInstanceView, ...] = Field(
        default_factory=tuple, max_length=MAX_PORTFOLIO_INSTANCES
    )
    overdue: tuple[PortfolioInstanceView, ...] = Field(
        default_factory=tuple, max_length=MAX_PORTFOLIO_INSTANCES
    )
    evidence_overdue: tuple[PortfolioInstanceView, ...] = Field(
        default_factory=tuple, max_length=MAX_PORTFOLIO_INSTANCES
    )
    exceptions_past_cure: tuple[PortfolioInstanceView, ...] = Field(
        default_factory=tuple, max_length=MAX_PORTFOLIO_INSTANCES
    )
    dependency_conflicts: tuple[DependencyConflict, ...] = Field(
        default_factory=tuple, max_length=MAX_PORTFOLIO_INSTANCES
    )
    escalation_candidates: tuple[EscalationCandidate, ...] = Field(
        default_factory=tuple, max_length=MAX_PORTFOLIO_INSTANCES
    )
    material_exposure: tuple[MaterialExposure, ...] = Field(
        default_factory=tuple, max_length=200
    )
    effect_boundary: ContractObligationEffectBoundary = Field(
        default_factory=ContractObligationEffectBoundary
    )
    assessment_digest: Sha256Digest = GENESIS_STATE_DIGEST

    @field_validator("as_of")
    @classmethod
    def _as_of(cls, value: str) -> str:
        return _timestamp(value, field_name="as_of")

    @field_validator("status_counts", mode="before")
    @classmethod
    def _counts(cls, value: Any) -> Any:
        if isinstance(value, Mapping):
            return {str(key): value[key] for key in sorted(value)}
        return value

    @model_validator(mode="after")
    def _assessment_is_exact(self, info: ValidationInfo) -> "ContractObligationPortfolioAssessment":
        for key, count in self.status_counts.items():
            if key not in _TRANSITIONS and key not in TERMINAL_INSTANCE_STATUSES:
                raise ValueError("status_counts may only contain instance statuses")
            if isinstance(count, bool) or count < 0:
                raise ValueError("status counts must be non-negative integers")
        if (info.context or {}).get("skip_obligation_digests"):
            return self
        if self.assessment_digest != obligation_portfolio_digest(self):
            raise ValueError("assessment_digest must commit the exact assessment")
        return self


def obligation_portfolio_digest(
    assessment: ContractObligationPortfolioAssessment | Mapping[str, Any],
) -> str:
    raw = dict(_detached_validation_payload(assessment))
    raw.setdefault("assessment_digest", GENESIS_STATE_DIGEST)
    parsed = ContractObligationPortfolioAssessment.model_validate(
        raw, context={"skip_obligation_digests": True}
    )
    return _digest_without(parsed.to_dict(), "assessment_digest")


class ContractObligationPortfolioInput(_StrictModel):
    scope: ContractObligationScope
    as_of: str
    upcoming_window_days: int = Field(default=30, ge=1, le=365)
    definitions: tuple[ObligationDefinition, ...] = Field(
        min_length=1, max_length=MAX_REGISTER_DEFINITIONS
    )
    snapshots: tuple[ContractObligationInstanceSnapshot, ...] = Field(
        default_factory=tuple, max_length=MAX_PORTFOLIO_INSTANCES
    )
    unstarted_instances: tuple[ObligationInstance, ...] = Field(
        default_factory=tuple, max_length=MAX_PORTFOLIO_INSTANCES
    )
    requested_by_ref: OpaqueRef

    @field_validator("as_of")
    @classmethod
    def _as_of(cls, value: str) -> str:
        return _timestamp(value, field_name="as_of")

    @model_validator(mode="after")
    def _input_is_exact(self) -> "ContractObligationPortfolioInput":
        digests = {item.definition_digest: item for item in self.definitions}
        _unique(list(digests), label="definition digests")
        for definition in self.definitions:
            if definition.agreement.agreement_ref != self.scope.agreement_ref:
                raise ValueError("every definition must bind the scoped agreement")
        refs = [item.instance.instance_ref for item in self.snapshots] + [
            item.instance_ref for item in self.unstarted_instances
        ]
        _unique(refs, label="portfolio instance refs")
        for snapshot in self.snapshots:
            if snapshot.scope != self.scope:
                raise ValueError("every snapshot must share the exact scope")
            if snapshot.instance.definition_digest not in digests:
                raise ValueError("every snapshot instance must cite a supplied definition")
        for instance in self.unstarted_instances:
            if instance.definition_digest not in digests:
                raise ValueError("every instance must cite a supplied definition")
        if not refs:
            raise ValueError("portfolio assessment requires at least one instance")
        return self


def assess_contract_obligation_portfolio(
    inputs: ContractObligationPortfolioInput | Mapping[str, Any],
) -> ContractObligationPortfolioAssessment:
    """Produce an effect-dark portfolio view; no transition is proposed here."""

    parsed = ContractObligationPortfolioInput.model_validate(
        _detached_validation_payload(inputs)
    )
    as_of = _parsed_timestamp(parsed.as_of)
    window_end = as_of + timedelta(days=parsed.upcoming_window_days)
    definitions = {item.definition_digest: item for item in parsed.definitions}
    rows: list[tuple[ObligationInstance, str, ContractObligationInstanceSnapshot | None]] = [
        (item.instance, item.status, item) for item in parsed.snapshots
    ] + [(item, "scheduled", None) for item in parsed.unstarted_instances]
    rows.sort(key=lambda row: (row[0].due_at, row[0].instance_ref))
    fulfilled_obligations = {
        row[0].obligation_ref for row in rows if row[1] == "fulfilled_verified"
    }
    status_counts: dict[str, int] = {}
    upcoming: list[PortfolioInstanceView] = []
    overdue: list[PortfolioInstanceView] = []
    evidence_overdue: list[PortfolioInstanceView] = []
    past_cure: list[PortfolioInstanceView] = []
    conflicts: list[DependencyConflict] = []
    escalations: list[EscalationCandidate] = []
    exposure: dict[tuple[str, str], tuple[Decimal, list[str]]] = {}

    for instance, status, snapshot in rows:
        definition = definitions[instance.definition_digest]
        status_counts[status] = status_counts.get(status, 0) + 1
        due = _parsed_timestamp(instance.due_at)
        days_overdue = max(0, (as_of - due).days) if as_of > due else 0
        view = PortfolioInstanceView(
            instance_ref=instance.instance_ref,
            obligation_ref=instance.obligation_ref,
            status=status,  # type: ignore[arg-type]
            kind=definition.kind,
            direction=definition.direction,
            materiality=definition.materiality,
            due_at=instance.due_at,
            evidence_due_at=instance.evidence_due_at,
            days_overdue=days_overdue,
            monetary=definition.monetary,
            blocked_by=instance.blocked_by,
        )
        if status in TERMINAL_INSTANCE_STATUSES:
            continue
        if as_of < due <= window_end:
            upcoming.append(view)
        if as_of > due:
            overdue.append(view)
        if status in {"scheduled", "evidence_pending"} and as_of > _parsed_timestamp(
            instance.evidence_due_at
        ):
            evidence_overdue.append(view)
        if (
            snapshot is not None
            and snapshot.open_exception is not None
            and as_of > _parsed_timestamp(snapshot.open_exception.cure_by)
        ):
            past_cure.append(view)
            escalations.append(
                EscalationCandidate(
                    instance_ref=instance.instance_ref,
                    reason="exception_cure_missed",
                    escalate_to_role_ref=definition.escalation_policy.escalate_to_role_ref,
                    detail="open exception passed its cure_by without cure",
                )
            )
        policy_overdue_at = due + timedelta(
            days=definition.escalation_policy.escalate_after_overdue_days
        )
        if as_of >= policy_overdue_at and as_of > due:
            escalations.append(
                EscalationCandidate(
                    instance_ref=instance.instance_ref,
                    reason="overdue_beyond_policy",
                    escalate_to_role_ref=definition.escalation_policy.escalate_to_role_ref,
                    detail=f"overdue {days_overdue} days against a policy of "
                    f"{definition.escalation_policy.escalate_after_overdue_days}",
                )
            )
        for dependency in instance.blocked_by:
            if dependency in fulfilled_obligations:
                continue
            dependency_rows = [
                row for row in rows if row[0].obligation_ref == dependency
            ]
            if not dependency_rows:
                conflicts.append(
                    DependencyConflict(
                        instance_ref=instance.instance_ref,
                        depends_on_obligation_ref=dependency,
                        detail="blocking dependency has no instance in the portfolio",
                    )
                )
                continue
            latest_dependency_due = max(
                _parsed_timestamp(row[0].due_at) for row in dependency_rows
            )
            if latest_dependency_due > due:
                conflicts.append(
                    DependencyConflict(
                        instance_ref=instance.instance_ref,
                        depends_on_obligation_ref=dependency,
                        detail="dependency is due after the dependent obligation",
                    )
                )
            elif as_of > due:
                conflicts.append(
                    DependencyConflict(
                        instance_ref=instance.instance_ref,
                        depends_on_obligation_ref=dependency,
                        detail="dependent obligation is overdue while its dependency is unfulfilled",
                    )
                )
        if definition.monetary is not None and (as_of > due or status == "exception_open"):
            key = (definition.monetary.currency, definition.direction)
            amount, refs = exposure.get(key, (Decimal(0), []))
            exposure[key] = (amount + definition.monetary.amount, [*refs, instance.instance_ref])

    assessment = {
        "scope": parsed.scope.to_dict(),
        "as_of": parsed.as_of,
        "upcoming_window_days": parsed.upcoming_window_days,
        "status_counts": status_counts,
        "upcoming": [item.to_dict() for item in upcoming],
        "overdue": [item.to_dict() for item in overdue],
        "evidence_overdue": [item.to_dict() for item in evidence_overdue],
        "exceptions_past_cure": [item.to_dict() for item in past_cure],
        "dependency_conflicts": [
            item.to_dict()
            for item in sorted(
                conflicts, key=lambda item: (item.instance_ref, item.depends_on_obligation_ref)
            )
        ],
        "escalation_candidates": [
            item.to_dict()
            for item in sorted(escalations, key=lambda item: (item.instance_ref, item.reason))
        ],
        "material_exposure": [
            MaterialExposure(
                currency=currency,
                direction=direction,  # type: ignore[arg-type]
                amount=amount,
                instance_refs=tuple(sorted(refs)),
            ).to_dict()
            for (currency, direction), (amount, refs) in sorted(exposure.items())
        ],
    }
    assessment["assessment_digest"] = obligation_portfolio_digest(assessment)
    return ContractObligationPortfolioAssessment.model_validate(assessment)


__all__ = [
    "AGREEMENT_VERSION_SCHEMA",
    "CLAUSE_LOCATOR_SCHEMA",
    "CONTRACT_OBLIGATION_GOLDEN_LOOP",
    "CONTRACT_OBLIGATION_SCOPE_SCHEMA",
    "GENESIS_STATE_DIGEST",
    "MAX_INSTANCES_PER_OBLIGATION",
    "MAX_OBLIGATION_TRANSITIONS",
    "MAX_SCHEDULE_HORIZON_DAYS",
    "MAX_SCHEDULE_INSTANCES",
    "OBLIGATION_CANDIDATE_SCHEMA",
    "OBLIGATION_COMMAND_SCHEMA",
    "OBLIGATION_DEFINITION_SCHEMA",
    "OBLIGATION_EVALUATION_SCHEMA",
    "OBLIGATION_EVIDENCE_SCHEMA",
    "OBLIGATION_INSTANCE_SCHEMA",
    "OBLIGATION_PORTFOLIO_SCHEMA",
    "OBLIGATION_RECEIPT_SCHEMA",
    "OBLIGATION_REGISTER_SCHEMA",
    "OBLIGATION_SCHEDULE_SCHEMA",
    "OBLIGATION_SNAPSHOT_SCHEMA",
    "OBLIGATION_TRANSITION_RESULT_SCHEMA",
    "TERMINAL_INSTANCE_STATUSES",
    "ActivationCondition",
    "ActivationEvent",
    "AgreementVersionRef",
    "BusinessCalendarPolicy",
    "CandidateRejection",
    "CarriedObligation",
    "ClauseLocator",
    "ContractObligationEffectBoundary",
    "ContractObligationEvaluationInput",
    "ContractObligationInstanceSnapshot",
    "ContractObligationNormalizationInput",
    "ContractObligationPortfolioAssessment",
    "ContractObligationPortfolioInput",
    "ContractObligationRecovery",
    "ContractObligationScheduleInput",
    "ContractObligationScope",
    "ContractObligationTransitionCandidate",
    "ContractObligationTransitionCommand",
    "ContractObligationTransitionInput",
    "ContractObligationTransitionReceipt",
    "ContractObligationTransitionResult",
    "CriterionFinding",
    "DependencyAttestation",
    "DependencyConflict",
    "DependencyState",
    "DeferredObligation",
    "DueRule",
    "EscalatePackage",
    "EscalationCandidate",
    "EscalationPolicy",
    "EvidenceExclusion",
    "FulfillmentCriterion",
    "MaterialExposure",
    "MonetaryTerms",
    "ObligationCandidate",
    "ObligationDefinition",
    "ObligationEvidenceEnvelope",
    "ObligationFulfillmentEvaluation",
    "ObligationInstance",
    "ObligationRegister",
    "ObligationSchedule",
    "ObligationSource",
    "OpenException",
    "OpenExceptionPackage",
    "OpenEvidenceWindowPackage",
    "CureExceptionPackage",
    "PortfolioInstanceView",
    "RecordFulfillmentPackage",
    "RecurrenceRule",
    "RegisterReviewAttestation",
    "RequireAuthoritativeChangePackage",
    "ScheduleHorizon",
    "ScheduleTruncation",
    "SupersedePackage",
    "SupersessionLink",
    "assess_contract_obligation_portfolio",
    "compile_contract_obligation_schedule",
    "contract_obligation_command_digest",
    "contract_obligation_scope_digest",
    "evaluate_contract_obligation_fulfillment",
    "genesis_instance_state_digest",
    "materialize_contract_obligation_transition",
    "normalize_contract_obligation_candidates",
    "obligation_definition_digest",
    "obligation_evaluation_digest",
    "obligation_evidence_digest",
    "obligation_portfolio_digest",
    "obligation_register_digest",
    "obligation_schedule_digest",
    "seal_contract_obligation_command",
    "seal_obligation_definition",
]
