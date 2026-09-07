"""The employment chain: one replay-fenced lifecycle per human employee, from an accepted offer to a proven offboarding.

Every other people pack proved a fragment.  ``people_operations_lifecycle``
proved the offboarding commands, the Spring ``hr_onboarding`` /
``hr_offboarding`` workflows proved the checklists, the round-7 Xero payroll
observers proved the pay, and ``obligation_paper`` proved the licences.  None
of them proved that *this* person was hired under an authority decision, put
on a roster, had that roster's hours approved by somebody else, was paid what
a posted pay run says, and left with every access system revoked.
``EMPLOYMENT_LIFECYCLE`` links them into one case per worker:

    offered -> hired -> onboarded -> rostered -> time_recorded -> paid
            -> (roster | record_time | start_leave | end_leave)*
            -> offboarding -> offboarded                       (terminal)
    offered | hired      -> withdrawn                          (terminal)
    hired .. offboarding -> reconciliation_required            (terminal)

Every hop consumes the sealed artifact of the pack that produced it and
nothing else: a host-lane ATS application row plus a self-naming offer-terms
input (``offer``), an ``AuthorizationProof`` of category ``people_change`` for
the annualised cost of the commitment plus a ``xero.observe_headcount`` row
and current ``obligation_paper`` standing items (``hire``), the Spring
``hr_onboarding`` response with its APPROVED ApprovalTask (``onboard``), a
published roster read (``roster``), a ``xero.observe_timesheets`` row approved
by somebody other than the worker (``record_time``), a paid payroll-run state
with the worker's share of a ``xero.observe_payrun`` observation
(``record_pay``), a ``xero.observe_leave`` row (``start_leave`` /
``end_leave``), the ``hr_offboarding`` response with its task and a second
``people_change`` proof (``initiate_offboarding``), and access-revocation
evidence shaped like
``people_operations_lifecycle.VerifyAccessRevocationCommand``
(``complete_offboarding``).

A name never enters the engine.  Every provider identifier crosses the
boundary as a sha256 already, and :func:`_reject_identity` refuses any receipt
payload that still carries a person in it.  The chain never computes wages:
gross and net are read off the worker's row of a posted pay run.

What it hands to other engines: :func:`capacity_expectation` for the
per-period ``people_engine``, :func:`timesheet_expectation` for
``payroll_run_chain``, :func:`headcount_receipt` for ``wind_down_chain``,
:func:`right_to_work_item` for ``obligation_paper``, rostered states for
``job_chain.assign``, capacity/capability signals, and exceptions-desk
openings through ``authority_exception``.  Nothing here reads a provider,
writes to one, or persists anything.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationError, ValidationInfo, field_validator, model_validator

from lightbulb.ai_operator import AuthorizationProof, authority_exception, money
from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    EngineScope,
    BoundedText,
    CurrencyCode,
    LifecycleSpec,
    OpaqueRef,
    Rejected,
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

EMPLOYMENT_KIND = "employment_chain"
EMPLOYMENT_GOLDEN_LOOP = "people.offer_to_offboarded_with_proven_pay@0.1.0"
EMPLOYMENT_PLAN_SCHEMA = "lightbulb.employment_plan.v1"
CAPACITY_EXPECTATION_SCHEMA = "lightbulb.people_capacity_expectation.v1"
TIMESHEET_EXPECTATION_SCHEMA = "lightbulb.people_timesheet_expectation.v1"
HEADCOUNT_PROOF_SCHEMA = "lightbulb.people_headcount_proof.v1"
OFFER_TERMS_SCHEMA = "lightbulb.employment_offer_terms.v1"
ROSTER_SCHEMA = "lightbulb.roster.v1"
ROSTER_SHEET_SCHEMA = "lightbulb.people_roster_sheet.v1"
STANDING_ITEM_SCHEMA = "lightbulb.obligation_paper_standing_item.v1"
MAX_EMPLOYMENT_TRANSITIONS = 96
_HUNDRED = Decimal("100")
_DAYS_PER_YEAR = 365

#: The reads this chain consumes, by hop.
APPLICATION_TOOLS: frozenset[str] = frozenset({"ats.get_application", "greenhouse.get_application"})
ENVELOPE_TOOLS: frozenset[str] = frozenset({"signing.get_envelope"})
ROSTER_TOOLS: frozenset[str] = frozenset({"host.roster", "scheduling.get_roster"})
HEADCOUNT_TOOL = "xero.observe_headcount"
TIMESHEET_TOOL = "xero.observe_timesheets"
LEAVE_TOOL = "xero.observe_leave"
PAYRUN_TOOL = "xero.observe_payrun"

EMPLOYMENT_STATUSES: tuple[str, ...] = ("offered", "hired", "onboarded", "rostered", "time_recorded", "paid", "on_leave", "offboarding", "offboarded", "withdrawn", "reconciliation_required")
TERMINAL_EMPLOYMENT_STATUSES: frozenset[str] = frozenset({"offboarded", "withdrawn", "reconciliation_required"})
EMPLOYMENT_EVENTS: tuple[str, ...] = ("offer", "hire", "onboard", "roster", "record_time", "record_pay", "start_leave", "end_leave", "initiate_offboarding", "complete_offboarding", "withdraw", "require_reconciliation")
_EMPLOYMENT_TABLE: dict[tuple[str, str], str] = {
    ("new", "offer"): "offered",
    ("offered", "hire"): "hired",
    ("hired", "onboard"): "onboarded",
    **{(status, "roster"): "rostered" for status in ("onboarded", "rostered", "paid")},
    **{(status, "record_time"): "time_recorded" for status in ("rostered", "time_recorded", "paid")},
    ("time_recorded", "record_pay"): "paid",
    ("offboarding", "record_pay"): "offboarding",
    **{(status, "start_leave"): "on_leave" for status in ("rostered", "paid")},
    ("on_leave", "end_leave"): "rostered",
    **{(status, "initiate_offboarding"): "offboarding" for status in ("onboarded", "rostered", "time_recorded", "paid", "on_leave")},
    ("offboarding", "complete_offboarding"): "offboarded",
    **{(status, "withdraw"): "withdrawn" for status in ("offered", "hired")},
    **{(status, "require_reconciliation"): "reconciliation_required" for status in ("hired", "onboarded", "rostered", "time_recorded", "paid", "on_leave", "offboarding")},
}


class EmploymentChainError(ValueError):
    """A receipt builder refusing an artifact that does not line up; carries the code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code, self.message = code, message


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise EmploymentChainError(code, message)


# --------------------------------------------------------------------------- #
# ROUND5_SHIM
#
# Round 5 lands ``lightbulb/authority_matrix.py`` (require_authorization_proof
# L685, authorization_evidence L696), ``lightbulb/obligation_paper.py``
# (verify_paper_current L740, STANDING_STATUSES L38) and
# ``lightbulb/payroll_run_chain.py`` (_reject_identity L471, _worker_ref L497,
# TIMESHEET_TOOLS L92 / RUN_TOOLS L91, timesheet_receipt, PAY_RUN_STATUSES
# L106).  None of them is in this tree yet, so the exact sealed shapes this
# module consumes live here with round 5's field names and rejection codes.
# When round 5 lands, delete this block and import the real names instead;
# nothing below it changes.
# --------------------------------------------------------------------------- #

AUTHORIZATION_FACTS_SCHEMA = "lightbulb.company_authorization_proof_facts.v1"
PAPER_FACTS_SCHEMA = "lightbulb.obligation_paper_facts.v1"
PAY_RUN_FACTS_SCHEMA = "lightbulb.payroll_run_facts.v1"
PAPER_KINDS: tuple[str, ...] = ("right_to_work", "police_check", "technician_certification")
STANDING_STATUSES: tuple[str, ...] = ("drafted", "issued", "current", "expiring", "lapsed", "replaced", "withdrawn")
CURRENT_PAPER_STATUSES: frozenset[str] = frozenset({"current", "renewal_due"})
PAY_RUN_STATUSES: frozenset[str] = frozenset({"paid", "liabilities_reserved", "reconciled"})
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
#: Key markers, normalized (lowercased, ``_``/``-`` stripped), that name a
#: person rather than a commitment to one.  ``payroll_run_chain._reject_identity``.
_IDENTITY_MARKERS: tuple[str, ...] = (
    "displayname", "fullname", "firstname", "lastname", "givenname", "familyname", "middlename", "preferredname",
    "legalname", "employeename", "workername", "candidatename", "personname", "surname", "email", "phone", "mobile",
    "address", "dateofbirth", "birthdate", "tfn", "taxfilenumber", "bankaccount", "bsb", "accountnumber",
    "employeeprofile", "personaldetails", "nextofkin",
)


def _normalized(key: str) -> str:
    return str(key).lower().replace("_", "").replace("-", "")


def _reject_identity(payload: Any, *, path: str = "receipt") -> Any:
    """Refuse a payload that still carries a person; ``payroll_run_chain._reject_identity``."""

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


def payroll_worker_ref(employee_id_sha256: str) -> str:
    """``payroll_run_chain._worker_ref``: the payroll commitment to one employee, and never the employee."""

    value = str(employee_id_sha256)
    _require(bool(_HEX64.match(value)), "EMPLOYEE_ID_NOT_HASHED", "an employee reaches the SDK only as a 64-hex sha256")
    return f"worker:{value[:24]}"


def _maybe_worker_ref(value: Any) -> str | None:
    """The same commitment inside a guard, where an unhashed id is a rejection rather than a raise."""

    text = str(value or "")
    return f"worker:{text[:24]}" if _HEX64.match(text) else None


# Compatibility export for callers; the receipt now retains the full central proof.
AuthorizationFacts = AuthorizationProof


def authorization_evidence(proof: AuthorizationProof | Mapping[str, Any]) -> dict[str, Any]:
    from lightbulb.authority_matrix import authorization_evidence as central_evidence
    evidence = central_evidence(proof)
    return {"authorization_proof": evidence["authorization_proof"], "evidence_refs": evidence["evidence_refs"]}


def require_authorization_proof(facts: Any, *, engine: str = EMPLOYMENT_KIND, **kwargs: Any) -> AuthorizationProof:
    from lightbulb.authority_matrix import require_authorization_proof as central_require
    proof = central_require(facts, **kwargs)
    require(proof.engine == engine, "APPROVAL_TRANSITION_MISMATCH", "the proof authorizes another engine")
    return proof


class PaperFacts(StrictModel):
    """One ``obligation_paper`` STANDING item proved current for a holder."""

    schema_id: Literal["lightbulb.obligation_paper_facts.v1"] = Field(default=PAPER_FACTS_SCHEMA, alias="schema")
    kind: ShortText
    holder_ref: OpaqueRef
    status: ShortText
    verified_at: str
    current_until: str | None = None
    state_digest: Sha256Digest
    plan_digest: Sha256Digest
    source_state: dict[str, Any]
    source_plan: dict[str, Any]

    @field_validator("verified_at", "current_until")
    @classmethod
    def _stamps(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))


def verify_paper_current(paper_state: Mapping[str, Any] | Any, *, source_plan: Any = None, company_ref: str | None = None, currency: str | None = None, at: str, kind: str, holder_ref: str) -> PaperFacts:
    """``obligation_paper.verify_paper_current``: this holder's paper of this kind is current at ``at``."""

    from lightbulb.obligation_paper import verify_paper_current as verify_current, ObligationPaperPlan
    plan = ObligationPaperPlan.model_validate(detached(source_plan))
    proven = verify_current(paper_state, source_plan=plan, company_ref=company_ref or plan.company_ref,
        currency=currency or plan.currency, at=at, kind=kind, holder_ref=holder_ref)
    return PaperFacts(kind=kind, holder_ref=holder_ref, status=proven.status,
        verified_at=proven.transition_history[-1].command.occurred_at,
        current_until=proven.ledger.period_end, state_digest=proven.state_digest,
        plan_digest=plan.plan_digest, source_state=proven.to_dict(), source_plan=plan.to_dict())



class PayRunFacts(StrictModel):
    """The facts of a paid ``payroll_run_chain`` state; ``people_engine.LabourSource``'s ``state`` half."""

    schema_id: Literal["lightbulb.payroll_run_facts.v1"] = Field(default=PAY_RUN_FACTS_SCHEMA, alias="schema")
    status: ShortText
    state_digest: Sha256Digest
    plan_digest: Sha256Digest
    pay_run_ref: OpaqueRef
    period_start: str
    period_end: str
    paid_at: str
    worker_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=500)

    @field_validator("worker_refs", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("period_start", "period_end", "paid_at")
    @classmethod
    def _stamps(cls, value: str, info: ValidationInfo) -> str:
        return timestamp(value, field_name=str(info.field_name))


def timesheet_page_totals(page: Mapping[str, Any] | Any, *, worker_refs: Sequence[str] = (), statuses: Sequence[str] = ("APPROVED",)) -> dict[str, Any]:
    """``payroll_run_chain.timesheet_receipt``'s totals over one ``xero.observe_timesheets`` page."""

    raw = dict(detached(page))
    _require(str(raw.get("schema")) == "lightbulb.xero_timesheet_page.v1", "TIMESHEET_PAGE_SCHEMA_MISMATCH", "expected a xero timesheet page")
    wanted = frozenset(worker_refs)
    allowed = frozenset(statuses)
    rows = [row for row in (raw.get("timesheets") or []) if str(row.get("status", "")).upper() in allowed]
    selected = [row for row in rows if not wanted or payroll_worker_ref(str(row["employee_id_sha256"])) in wanted]
    total = sum((decimal_value(row.get("hours"), field_name="hours") for row in selected), Decimal("0.00"))
    refs = sorted({payroll_worker_ref(str(row["employee_id_sha256"])) for row in selected})
    return {"worker_refs": refs, "total_hours": str(total), "row_count": len(selected), "period_start": str(raw.get("period_start")), "period_end": str(raw.get("period_end"))}


# --------------------------------------------------------------------------- #
# end ROUND5_SHIM
# --------------------------------------------------------------------------- #


def _plan_digest(value: Any) -> str | None:
    if value is None:
        return None
    raw = detached(value)
    if isinstance(raw, Mapping):
        return None if raw.get("plan_digest") is None else str(raw["plan_digest"])
    return None


def _at(value: Any, *, field_name: str) -> str:
    """A provider date (``2026-10-05``) or stamp, as the ISO-8601 Z the engine keeps."""

    text = str(value)
    return timestamp(text if text.endswith("Z") else f"{text}T00:00:00Z", field_name=field_name)


class EmploymentPlan(StrictModel):
    """What the chain enforces about one company's employment: the pay cycle, the paper, the ceilings on hours and notice."""

    schema_id: str = Field(default=EMPLOYMENT_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    jurisdiction: Literal["AU", "CA", "NZ", "UK", "US"]
    pay_frequency_days: int = Field(default=14, ge=7, le=31)
    max_hours_per_period: Decimal = Field(default=Decimal("80.00"), validate_default=True)
    required_paper_kinds: tuple[Literal["right_to_work", "police_check", "technician_certification"], ...] = ("right_to_work",)
    require_signed_contract: bool = True
    probation_days: int = Field(default=90, ge=0, le=365)
    max_days_offer_to_hire: int = Field(default=60, ge=1, le=180)
    max_days_hire_to_onboard: int = Field(default=30, ge=1, le=90)
    timesheet_overrun_tolerance: Decimal = Field(default=Decimal("1.25"), validate_default=True)
    leave_balance_floor_hours: Decimal = Field(default=Decimal("0.00"), validate_default=True)
    min_notice_days: int = Field(default=28, ge=0, le=90)
    payroll_plan_digest: Sha256Digest | None = None
    obligation_paper_plan_digest: Sha256Digest | None = None
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("max_hours_per_period", "leave_balance_floor_hours", mode="before")
    @classmethod
    def _hours(cls, value: Any, info: ValidationInfo) -> Decimal:
        result = decimal_value(value, field_name=str(info.field_name))
        if result > Decimal("744"):
            raise ValueError(f"{info.field_name} must be at most 744 hours")
        return result

    @field_validator("timesheet_overrun_tolerance", mode="before")
    @classmethod
    def _tolerance(cls, value: Any) -> Decimal:
        result = decimal_value(value, field_name="timesheet_overrun_tolerance")
        if result < Decimal("1") or result > Decimal("2"):
            raise ValueError("timesheet_overrun_tolerance must be between 1 and 2")
        return result

    @field_validator("required_paper_kinds", mode="before")
    @classmethod
    def _kinds(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> EmploymentPlan:
        if len(set(self.required_paper_kinds)) != len(self.required_paper_kinds):
            raise ValueError("required_paper_kinds must be unique")
        if not skip_digests(info) and self.plan_digest != sealed_digest(EmploymentPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self

    @property
    def periods_per_year(self) -> int:
        return _DAYS_PER_YEAR // self.pay_frequency_days


def compile_employment_chain(company_ref: str, *, currency: str, jurisdiction: str, payroll_plan: Any = None, obligation_paper_plan: Any = None, overrides: Mapping[str, Any] | None = None) -> EmploymentPlan:
    payload = {
        "company_ref": company_ref,
        "currency": str(currency).upper(),
        "jurisdiction": str(jurisdiction).upper(),
        "payroll_plan_digest": _plan_digest(payroll_plan),
        "obligation_paper_plan_digest": _plan_digest(obligation_paper_plan),
        **dict(overrides or {}),
    }
    return seal(EmploymentPlan, {key: value for key, value in payload.items() if value is not None}, "plan_digest")


class EmploymentReceipt(StrictModel):
    entity_scope: EngineScope | None = None
    """What one hop proves, always derived from the sealed artifact of the pack that produced it."""

    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    # offer
    worker_ref: OpaqueRef | None = None
    application_ref: OpaqueRef | None = None
    ats_status: ShortText | None = None
    offer_amount: Decimal | None = None
    pay_rate_uom: Literal["hour", "year"] | None = None
    application_provenance: dict[str, Any] | None = None
    offer_terms: dict[str, Any] | None = None
    # contract + hire
    contract_document_sha256: Sha256Digest | None = None
    contract_envelope_status: ShortText | None = None
    contract_signed_at: str | None = None
    #: The sealed :class:`AuthorizationFacts`.  Named ``authorization_proof`` and not
    #: ``authorization_proof`` because ``reject_secret_like_payload`` refuses any
    #: key containing ``authorization`` at the boundary, whatever it holds.
    authorization_proof: dict[str, Any] | None = None
    paper_sources: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=12)
    headcount_source: dict[str, Any] | None = None
    payroll_worker_ref: OpaqueRef | None = None
    start_date: str | None = None
    # onboarding / offboarding workflows
    hr_workflow_source: dict[str, Any] | None = None
    hr_task: dict[str, Any] | None = None
    # roster
    roster_source: dict[str, Any] | None = None
    period_start: str | None = None
    period_end: str | None = None
    shift_count: int | None = Field(default=None, ge=0, le=400)
    rostered_hours: Decimal | None = None
    # timesheet
    timesheet_source: dict[str, Any] | None = None
    timesheet_hours: Decimal | None = None
    timesheet_status: ShortText | None = None
    approver_ref: OpaqueRef | None = None
    # pay
    pay_run_source: dict[str, Any] | None = None
    payrun_observation: dict[str, Any] | None = None
    pay_run_ref: OpaqueRef | None = None
    gross: Decimal | None = None
    net: Decimal | None = None
    paid_at: str | None = None
    # leave
    leave_source: dict[str, Any] | None = None
    leave_type_ref: OpaqueRef | None = None
    leave_start: str | None = None
    leave_end: str | None = None
    leave_hours: Decimal | None = None
    leave_balance_hours: Decimal | None = None
    # offboarding
    access_systems_expected: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=40)
    access_revocations: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=40)
    last_working_at: str | None = None
    detail: BoundedText | None = None

    @field_validator("evidence_refs", "paper_sources", "access_systems_expected", "access_revocations", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("offer_amount", "rostered_hours", "timesheet_hours", "gross", "net", "leave_hours", "leave_balance_hours", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))

    @field_validator("contract_signed_at", "start_date", "period_start", "period_end", "paid_at", "leave_start", "leave_end", "last_working_at")
    @classmethod
    def _stamps(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _no_person(self) -> EmploymentReceipt:
        """The manifest's first hard rule, at the boundary and not only in the builders.

        ``reject_secret_like_payload`` refuses credentials and identifiers; a
        person's *name* is not one of its markers, so the receipt scans itself
        as well -- a hand-built receipt cannot smuggle in what every builder
        already strips.
        """

        _reject_identity(self.to_dict(), path="receipt")
        return self


class EmploymentLedger(StrictModel):
    entity_scope: EngineScope | None = None
    """Derived state only: every number here came off a receipt that came off a sealed artifact."""

    worker_ref: str | None = None
    application_ref: str | None = None
    offered_at: str | None = None
    offer_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    pay_rate_uom: str | None = None
    commitment_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    hired_at: str | None = None
    hire_proof_digest: str | None = None
    payroll_worker_ref: str | None = None
    employee_ref: str | None = None
    start_date: str | None = None
    paper_verified_kinds: tuple[str, ...] = ()
    checklist_ref: str | None = None
    onboarded_at: str | None = None
    current_period_start: str | None = None
    current_period_end: str | None = None
    rostered_hours: Decimal = Field(default=Decimal("0"), validate_default=True)
    roster_periods: int = 0
    timesheet_hours_period: Decimal = Field(default=Decimal("0"), validate_default=True)
    timesheet_hours_total: Decimal = Field(default=Decimal("0"), validate_default=True)
    pay_run_refs: tuple[str, ...] = ()
    gross_paid_total: Decimal = Field(default=Decimal("0"), validate_default=True)
    net_paid_total: Decimal = Field(default=Decimal("0"), validate_default=True)
    last_paid_at: str | None = None
    leave_open: bool = False
    leave_hours_total: Decimal = Field(default=Decimal("0"), validate_default=True)
    leave_balance_hours: Decimal = Field(default=Decimal("0"), validate_default=True)
    offboarding_case_ref: str | None = None
    offboarding_initiated_at: str | None = None
    last_working_at: str | None = None
    access_systems_expected: tuple[str, ...] = ()
    access_systems_revoked: tuple[str, ...] = ()
    final_pay_run_ref: str | None = None
    offboarded_at: str | None = None
    days_offer_to_hire: int | None = None
    withdraw_reason: str | None = None
    reconciliation_reason: str | None = None
    outcome: Literal["open", "offboarded", "withdrawn", "reconciliation_required"] = "open"

    @field_validator("paper_verified_kinds", "pay_run_refs", "access_systems_expected", "access_systems_revoked", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("offer_amount", "commitment_amount", "rostered_hours", "timesheet_hours_period", "timesheet_hours_total", "gross_paid_total", "net_paid_total", "leave_hours_total", "leave_balance_hours", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))


class EmploymentEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    employee_created: Literal[False] = False
    payroll_posted: Literal[False] = False
    timesheet_approved_in_provider: Literal[False] = False
    message_sent: Literal[False] = False
    access_revoked: Literal[False] = False
    provider_read: Literal[False] = False


# --------------------------------------------------------------------------- #
# Guards
# --------------------------------------------------------------------------- #


def _days(start: str | None, end: str) -> int:
    return 0 if not start else (parsed(end) - parsed(start)).days


def _amount(data: Mapping[str, Any], key: str) -> Decimal:
    return decimal_value(data.get(key, "0"), field_name=key)


def _source(value: Mapping[str, Any] | None, key: str) -> dict[str, Any]:
    return dict((value or {}).get(key) or {})


def _tool(source: Mapping[str, Any] | None) -> str:
    return str(_source(source, "provenance").get("source_tool", ""))


def _observed(value: Any, *, field_name: str, code: str, detail: str) -> Decimal:
    """A quantity read straight off a sealed provider row, or a rejection naming the row that could not be read."""

    try:
        return decimal_value(value, field_name=field_name)
    except ValueError as exc:
        raise Rejected(code, f"{detail}: {exc}", "manual_reconciliation") from exc


def _minor(value: Any, *, field_name: str, code: str, detail: str) -> Decimal:
    """Money read off a sealed provider row in minor units; never a number the caller chose."""

    try:
        return (Decimal(int(value)) / _HUNDRED).quantize(Decimal("0.01"))
    except (TypeError, ValueError, ArithmeticError) as exc:
        raise Rejected(code, f"{detail} ({field_name}): {exc}", "manual_reconciliation") from exc


def _moment(value: Any, *, field_name: str, code: str) -> Any:
    """An instant read off an unvalidated sealed projection; an unreadable one is a rejection, never a traceback."""

    try:
        return parsed(timestamp(str(value), field_name=field_name))
    except ValueError as exc:
        raise Rejected(code, f"{field_name} is not an ISO-8601 Z instant: {exc}", "manual_reconciliation") from exc


def _same_window(row: Mapping[str, Any], start: str | None, end: str | None, *, start_key: str = "start_date", end_key: str = "end_date") -> bool:
    """Whether a receipt's declared window is the window the sealed row itself carries."""

    observed = (row.get(start_key), row.get(end_key))
    return all(observed) and (_at(observed[0], field_name="period_start"), _at(observed[1], field_name="period_end")) == (start, end)


def _commitment(plan: EmploymentPlan, amount: Decimal, uom: str) -> Decimal:
    if uom == "year":
        return amount
    return (amount * plan.max_hours_per_period * Decimal(plan.periods_per_year)).quantize(Decimal("0.01"))


def _apply_employment(plan: EmploymentPlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event, at = command.receipt, command.event, command.occurred_at
    if event == "offer":
        require(r.entity_scope is not None and command.expected_state_digest == EMPLOYMENT_LIFECYCLE.state_digest(plan.plan_digest, r.entity_scope, ()),
                "EMPLOYEE_SCOPE_MISMATCH", "employment must retain the actual authenticated entity scope")
        data["entity_scope"] = r.entity_scope.to_dict()
        require(all(item is not None for item in (r.application_ref, r.worker_ref, r.offer_amount, r.pay_rate_uom, r.application_provenance, r.offer_terms)), "OFFER_MISSING", "an offer names the application, the worker commitment, the amount, its unit, the read it came from, and the offer terms")
        require(r.offer_amount is not None and r.offer_amount > 0, "OFFER_AMOUNT_INVALID", "an offer is worth something")
        require(str(r.ats_status) in ("hired", "offer_accepted"), "APPLICATION_NOT_HIRED", f"the application is {r.ats_status}; an offer is only opened once the candidate accepted")
        # the case's identity is a digest of the application it came from, so a
        # caller cannot name a worker the application never carried.
        require(r.worker_ref == employment_worker_ref(str(r.application_ref)), "OFFER_WORKER_REF_INVALID", f"{r.worker_ref} is not the commitment derived from {r.application_ref}")
        assert r.offer_amount is not None and r.pay_rate_uom is not None
        data.update({"worker_ref": r.worker_ref, "application_ref": r.application_ref, "offered_at": at, "offer_amount": str(r.offer_amount), "pay_rate_uom": r.pay_rate_uom, "commitment_amount": str(_commitment(plan, r.offer_amount, r.pay_rate_uom))})
    elif event == "hire":
        require(r.authorization_proof is not None, "HIRE_NOT_AUTHORIZED", f"hiring commits {_amount(data, 'commitment_amount')} {plan.currency} of people_change authority; a human decides it", "await_approval")
        facts = require_authorization_proof(r.authorization_proof, category="people_change", amount=_amount(data, "commitment_amount"), currency=plan.currency, command=command, plan_digest=plan.plan_digest, company_ref=plan.company_ref, entity_ref=str(data.get("worker_ref") or ""))
        require(_days(data.get("offered_at"), at) <= plan.max_days_offer_to_hire, "HIRE_TOO_LATE", f"the hire landed more than {plan.max_days_offer_to_hire} days after the offer", "manual_reconciliation")
        require(not plan.require_signed_contract or str(r.contract_envelope_status) == "completed", "CONTRACT_UNSIGNED", f"the employment contract envelope is {r.contract_envelope_status}; a signed contract precedes a hire")
        row = _source(r.headcount_source, "row")
        require(_tool(r.headcount_source) == HEADCOUNT_TOOL and str(row.get("status")) == "ACTIVE" and bool(row.get("start_date")) and r.payroll_worker_ref is not None and _maybe_worker_ref(row.get("employee_id_sha256")) == r.payroll_worker_ref, "PAYROLL_EMPLOYEE_MISSING", "a hire needs an ACTIVE Xero payroll employee, with a start date, whose hashed id is this worker")
        from lightbulb.obligation_paper import verify_paper_current as verify_current
        papers = {str(item.get("kind")): item for item in r.paper_sources}
        for kind in plan.required_paper_kinds:
            paper = papers.get(kind)
            require(paper is not None, "PAPER_NOT_CURRENT", f"{kind} is not proved current for {r.payroll_worker_ref}")
            try:
                source = verify_current(paper.get("source_state"), source_plan=paper.get("source_plan"),
                    company_ref=plan.company_ref, currency=plan.currency, at=at, kind=kind,
                    holder_ref=str(r.payroll_worker_ref), expected_scope=data["entity_scope"])
            except (ValueError, TypeError) as exc:
                raise Rejected("PAPER_NOT_CURRENT", "employment requires replayable current paper in its own scope", "manual_reconciliation") from exc
            require(plan.obligation_paper_plan_digest is None or source.plan_digest == plan.obligation_paper_plan_digest,
                    "PAPER_PLAN_MISMATCH", "paper belongs to another adopted plan")
        # only the kinds this guard actually re-checked are claimed as verified;
        # an extra paper the receipt carries proves nothing the plan asked for.
        data.update({"hired_at": at, "hire_proof_digest": facts.proof_digest, "payroll_worker_ref": r.payroll_worker_ref, "start_date": _at(row["start_date"], field_name="start_date"), "paper_verified_kinds": sorted(set(plan.required_paper_kinds)), "days_offer_to_hire": _days(data.get("offered_at"), at)})
    elif event == "onboard":
        workflow = dict(r.hr_workflow_source or {})
        task = dict(r.hr_task or {})
        require(str(workflow.get("workflow")) == "hr_onboarding" and bool(workflow.get("success")) and bool(workflow.get("employee_ref_sha256")) and bool(workflow.get("checklist_id")) and bool(workflow.get("decision_id")), "ONBOARDING_MISSING", "an onboarding names its persisted workflow, the hashed employee, the checklist, and the decision it waited on")
        require(str(task.get("status")) == "APPROVED" and str(task.get("id")) == str(workflow.get("decision_id")) and bool(task.get("decided_by_ref")) and bool(task.get("decided_at")), "ONBOARDING_NOT_APPROVED", "the onboarding's own ApprovalTask must be APPROVED, attributed, and the decision the workflow named")
        require(_days(data.get("hired_at"), at) <= plan.max_days_hire_to_onboard, "ONBOARD_TOO_LATE", f"onboarding landed more than {plan.max_days_hire_to_onboard} days after the hire", "manual_reconciliation")
        linked = str(workflow.get("payroll_employee_ref_sha256") or "")
        require(bool(linked) and _maybe_worker_ref(linked) == str(data.get("payroll_worker_ref")), "PAYROLL_LINK_MISSING", "the HR profile is not linked to the payroll employee this chain hired")
        data.update({"employee_ref": f"hr-profile:{str(workflow['employee_ref_sha256'])[:32]}", "checklist_ref": str(workflow["checklist_id"]), "onboarded_at": at})
    elif event == "roster":
        payload = _source(r.roster_source, "payload")
        provenance = _source(r.roster_source, "provenance")
        require(_tool(r.roster_source) in ROSTER_TOOLS and str(provenance.get("lane")) in ("host_read", "governed_read") and str(provenance.get("output_digest")) == stable_digest(payload) and str(payload.get("schema")) in (ROSTER_SCHEMA, ROSTER_SHEET_SCHEMA) and str(payload.get("status")) == "published" and r.period_start is not None and r.period_end is not None and r.rostered_hours is not None, "ROSTER_MISSING", "a roster is a published roster read whose provenance seals the exact payload, with its window and hours")
        shifts = [shift for shift in (payload.get("shifts") or []) if str(shift.get("worker_ref")) == str(data.get("payroll_worker_ref"))]
        require(bool(shifts), "ROSTER_WORKER_ABSENT", "the published roster carries no shift for this worker")
        # the hours and the window are recomputed from the payload the provenance
        # sealed; the receipt's own numbers are only ever a claim about it.
        observed_hours = sum((_observed(shift.get("hours"), field_name="hours", code="ROSTER_HOURS_MISMATCH", detail="a shift on the sealed roster carries no readable hours") for shift in shifts), Decimal("0.00"))
        require(r.rostered_hours == observed_hours, "ROSTER_HOURS_MISMATCH", f"the receipt claims {r.rostered_hours}h; the sealed roster carries {observed_hours}h for this worker", "manual_reconciliation")
        require(_same_window(payload, r.period_start, r.period_end, start_key="period_start", end_key="period_end"), "ROSTER_WINDOW_INVALID", f"the declared window {r.period_start}..{r.period_end} is not the published roster's own window")
        require((parsed(r.period_end) - parsed(r.period_start)).days + 1 == plan.pay_frequency_days, "ROSTER_WINDOW_INVALID", f"a roster window is exactly one {plan.pay_frequency_days}-day pay period, first day to last day inclusive")
        require(r.rostered_hours <= plan.max_hours_per_period, "ROSTER_HOURS_EXCEEDED", f"{r.rostered_hours}h exceeds the {plan.max_hours_per_period}h period ceiling; a human decides the overtime", "await_approval")
        require(not bool(data.get("leave_open")), "ROSTER_WHILE_ON_LEAVE", "this worker is on recorded leave; end the leave before rostering", "manual_reconciliation")
        data.update({"current_period_start": r.period_start, "current_period_end": r.period_end, "rostered_hours": str(r.rostered_hours), "roster_periods": int(data.get("roster_periods") or 0) + 1, "timesheet_hours_period": "0"})
    elif event == "record_time":
        row = _source(r.timesheet_source, "row")
        require(_tool(r.timesheet_source) == TIMESHEET_TOOL and r.timesheet_hours is not None and r.approver_ref is not None and bool(row), "TIMESHEET_MISSING", "recorded time is a xero.observe_timesheets row with its hours and the provider approver")
        require(str(row.get("status")) == "APPROVED", "TIMESHEET_NOT_APPROVED", f"the timesheet is {row.get('status')}; only an approved timesheet records time")
        require(_maybe_worker_ref(row.get("employee_id_sha256")) == str(data.get("payroll_worker_ref")), "TIMESHEET_WORKER_MISMATCH", "the timesheet row belongs to a different worker")
        require(r.period_start == data.get("current_period_start") and r.period_end == data.get("current_period_end"), "TIMESHEET_OUTSIDE_PERIOD", f"the timesheet covers {r.period_start}..{r.period_end}, not the rostered period {data.get('current_period_start')}..{data.get('current_period_end')}")
        ceiling = (_amount(data, "rostered_hours") * plan.timesheet_overrun_tolerance).quantize(Decimal("0.01"))
        require(r.timesheet_hours <= ceiling, "TIMESHEET_OVER_ROSTER", f"{r.timesheet_hours}h exceeds the rostered {data.get('rostered_hours')}h by more than the {plan.timesheet_overrun_tolerance}x tolerance", "manual_reconciliation")
        # the hours and the window come off the approved row itself, never off
        # the receipt's claim about it.
        observed_hours = _observed(row.get("hours"), field_name="hours", code="TIMESHEET_HOURS_MISMATCH", detail="the approved timesheet row carries no readable hours")
        require(r.timesheet_hours == observed_hours, "TIMESHEET_HOURS_MISMATCH", f"the receipt claims {r.timesheet_hours}h; the approved timesheet row carries {observed_hours}h", "manual_reconciliation")
        require(_same_window(row, r.period_start, r.period_end), "TIMESHEET_OUTSIDE_PERIOD", f"the declared window {r.period_start}..{r.period_end} is not the approved timesheet row's own window")
        require(str(r.approver_ref) not in (str(data.get("worker_ref")), str(data.get("payroll_worker_ref"))), "APPROVER_IS_WORKER", "a worker never approves their own timesheet; the approval happens in the provider, by someone else", "manual_reconciliation")
        data.update({"timesheet_hours_period": str(r.timesheet_hours), "timesheet_hours_total": str(_amount(data, "timesheet_hours_total") + r.timesheet_hours)})
    elif event == "record_pay":
        from lightbulb.payroll_run_chain import verify_paid_pay_run
        source = dict(r.pay_run_source or {})
        try:
            proven = verify_paid_pay_run(source.get("state"), source_plan=source.get("plan"),
                company_ref=plan.company_ref, currency=plan.currency, expected_scope=data["entity_scope"], at=at)
            expected = pay_receipt(proven, source_plan=source["plan"], worker_ref=str(data.get("payroll_worker_ref")),
                payrun_observation=source.get("observation"))
        except (ValueError, TypeError) as exc:
            raise Rejected("PAY_RUN_MISSING", "pay requires the full scoped paid payroll run and its exact worker observation", "manual_reconciliation") from exc
        require(all(detached(getattr(r, key)) == detached(expected[key]) for key in ("pay_run_ref", "paid_at", "payrun_observation"))
                and r.gross == Decimal(expected["gross"]) and r.net == Decimal(expected["net"]),
                "WORKER_SHARE_MISMATCH", "pay amounts must be reproduced from the paid source")
        run = proven.ledger.to_dict()
        run_plan = source["plan"]
        require(plan.payroll_plan_digest is None or proven.plan_digest == plan.payroll_plan_digest,
                "PAYROLL_PLAN_MISMATCH", "the paid run belongs to another payroll plan")
        require(str(r.pay_run_ref) not in tuple(data.get("pay_run_refs") or ()), "PAY_RUN_ALREADY_RECORDED", f"pay run {r.pay_run_ref} is already recorded against this employee", "do_not_replay")
        period_end = str(run.get("period_end") or "")
        require(bool(period_end), "PAY_RUN_BEFORE_TIME", "the pay run state names no period end", "manual_reconciliation")
        run_end = _moment(period_end, field_name="period_end", code="PAY_RUN_BEFORE_TIME")
        require(data.get("current_period_end") is None or run_end >= parsed(str(data["current_period_end"])), "PAY_RUN_BEFORE_TIME", "the pay run closes before the period whose time was recorded", "manual_reconciliation")
        observation = dict(r.payrun_observation or {})
        share = dict(observation.get("worker") or {})
        require(bool(share) and _maybe_worker_ref(share.get("employee_id_sha256")) == str(data.get("payroll_worker_ref")) and r.gross is not None and r.net is not None, "WORKER_SHARE_MISSING", "the pay run observation carries no row for this worker; gross and net are never computed here")
        require(str(observation.get("currency", "")).upper() == str(plan.currency).upper(), "PAY_CURRENCY_MISMATCH", f"the pay run pays in {observation.get('currency')}; this employment plan is {plan.currency}", "manual_reconciliation")
        # gross and net are the posted run's own minor units, never a number a
        # caller put on the receipt beside them.
        observed_gross = _minor(share.get("wages_minor"), field_name="wages_minor", code="WORKER_SHARE_MISMATCH", detail="the worker's row of the posted run carries no readable wages")
        observed_net = _minor(share.get("net_pay_minor"), field_name="net_pay_minor", code="WORKER_SHARE_MISMATCH", detail="the worker's row of the posted run carries no readable net pay")
        require((r.gross, r.net) == (observed_gross, observed_net), "WORKER_SHARE_MISMATCH", f"the receipt claims {r.gross}/{r.net}; the posted run pays this worker {observed_gross}/{observed_net}", "manual_reconciliation")
        if status == "offboarding":
            require(data.get("last_working_at") is not None and run_end >= parsed(str(data["last_working_at"])), "FINAL_PAY_PERIOD_MISMATCH", "the final pay run must cover the last working day", "manual_reconciliation")
            data["final_pay_run_ref"] = str(r.pay_run_ref)
        data.update({"pay_run_refs": [*tuple(data.get("pay_run_refs") or ()), str(r.pay_run_ref)], "gross_paid_total": str(_amount(data, "gross_paid_total") + r.gross), "net_paid_total": str(_amount(data, "net_paid_total") + r.net), "last_paid_at": r.paid_at})
    elif event == "start_leave":
        row = _source(r.leave_source, "row")
        require(_tool(r.leave_source) == LEAVE_TOOL and _maybe_worker_ref(row.get("employee_id_sha256")) == str(data.get("payroll_worker_ref")) and r.leave_start is not None and r.leave_end is not None and r.leave_hours is not None, "LEAVE_MISSING", "leave is a xero.observe_leave row for this worker, with its window and units")
        observed_units = _observed(row.get("units"), field_name="units", code="LEAVE_UNITS_MISMATCH", detail="the observed leave row carries no readable units")
        require(r.leave_hours == observed_units, "LEAVE_UNITS_MISMATCH", f"the receipt claims {r.leave_hours}h of leave; the observed row carries {observed_units}h", "manual_reconciliation")
        require(_same_window(row, r.leave_start, r.leave_end), "LEAVE_MISSING", f"the declared leave window {r.leave_start}..{r.leave_end} is not the observed row's own window")
        require(not bool(data.get("leave_open")), "LEAVE_ALREADY_OPEN", "this worker already has leave open; end it before opening another", "manual_reconciliation")
        balance = r.leave_balance_hours if r.leave_balance_hours is not None else _amount(data, "leave_balance_hours")
        require(balance - r.leave_hours >= plan.leave_balance_floor_hours, "LEAVE_BALANCE_INSUFFICIENT", f"{r.leave_hours}h of leave takes the balance below the {plan.leave_balance_floor_hours}h floor; a human decides", "await_approval")
        data.update({"leave_open": True, "leave_hours_total": str(_amount(data, "leave_hours_total") + r.leave_hours), "leave_balance_hours": str(balance - r.leave_hours)})
    elif event == "end_leave":
        require(bool(data.get("leave_open")), "LEAVE_NOT_OPEN", "no leave is open for this worker", "manual_reconciliation")
        require(r.leave_start is not None and r.leave_end is not None and parsed(r.leave_end) >= parsed(r.leave_start), "LEAVE_END_BEFORE_START", "leave cannot end before it started")
        data.update({"leave_open": False})
    elif event == "initiate_offboarding":
        workflow = dict(r.hr_workflow_source or {})
        task = dict(r.hr_task or {})
        require(str(workflow.get("workflow")) == "hr_offboarding" and bool(workflow.get("case_id")) and bool(workflow.get("decision_id")) and bool(workflow.get("last_working_day")) and str(workflow.get("employee_ref_sha256") or "")[:32] == str(data.get("employee_ref") or "")[len("hr-profile:"):], "OFFBOARDING_MISSING", "an offboarding names its case, its decision, the last working day, and the same hashed employee this chain onboarded")
        require(str(task.get("status")) == "APPROVED" and str(task.get("id")) == str(workflow.get("decision_id")) and bool(task.get("decided_by_ref")) and bool(task.get("decided_at")), "OFFBOARDING_NOT_APPROVED", "the offboarding's own ApprovalTask must be APPROVED, attributed, and the decision the workflow named")
        require(r.authorization_proof is not None, "OFFBOARDING_NOT_AUTHORIZED", "a termination is a people_change decision a human makes; it is never auto-accepted", "await_approval")
        require_authorization_proof(r.authorization_proof, category="people_change", amount=Decimal("0.00"), currency=plan.currency, command=command, plan_digest=plan.plan_digest, company_ref=plan.company_ref, entity_ref=str(data.get("worker_ref") or ""))
        require(r.last_working_at is not None and _days(at, r.last_working_at) >= plan.min_notice_days, "NOTICE_TOO_SHORT", f"the last working day is less than the {plan.min_notice_days}-day notice floor away; a human decides the shortfall", "await_approval")
        require(len(r.access_systems_expected) > 0, "ACCESS_SYSTEMS_MISSING", "an offboarding names the access systems that must be revoked before it can close")
        data.update({"offboarding_case_ref": f"hr-case:{workflow['case_id']}", "offboarding_initiated_at": at, "last_working_at": r.last_working_at, "access_systems_expected": sorted(set(r.access_systems_expected))})
    elif event == "complete_offboarding":
        require(data.get("final_pay_run_ref") is not None, "FINAL_PAY_MISSING", "an offboarding closes only after the final pay run covering the last working day is recorded", "manual_reconciliation")
        last_working = str(data.get("last_working_at"))
        revoked: set[str] = set()
        for item in r.access_revocations:
            digest = str(item.get("claimed_provider_effect_receipt_digest", ""))
            when = item.get("revoked_at")
            if _HEX64.match(digest) and when is not None and parsed(timestamp(str(when), field_name="revoked_at")) >= parsed(last_working):
                revoked.add(str(item.get("system_ref")))
        expected = set(tuple(data.get("access_systems_expected") or ()))
        require(expected.issubset(revoked), "ACCESS_NOT_REVOKED", f"access is still live on {sorted(expected - revoked)}; every expected system needs a verified revocation on or after the last working day", "manual_reconciliation")
        require(parsed(at) >= parsed(last_working), "OFFBOARDED_BEFORE_LAST_DAY", "an employee is not offboarded before their last working day")
        data.update({"access_systems_revoked": sorted(revoked), "offboarded_at": at, "outcome": "offboarded"})
    elif event == "withdraw":
        data.update({"withdraw_reason": str(command.reason)[:300], "outcome": "withdrawn"})
    elif event == "require_reconciliation":
        data.update({"reconciliation_reason": str(command.reason)[:300], "outcome": "reconciliation_required"})
    return next_status, data


EMPLOYMENT_LIFECYCLE = LifecycleSpec(
    entity="employee",
    schema_prefix="employment",
    statuses=EMPLOYMENT_STATUSES,
    terminal=TERMINAL_EMPLOYMENT_STATUSES,
    events=EMPLOYMENT_EVENTS,
    table=_EMPLOYMENT_TABLE,
    opening_event="offer",
    reason_events=("withdraw", "require_reconciliation"),
    apply=_apply_employment,
    ledger_model=EmploymentLedger,
    receipt_model=EmploymentReceipt,
    effect_boundary_model=EmploymentEffectBoundary,
    plan_model=EmploymentPlan,
    max_transitions=MAX_EMPLOYMENT_TRANSITIONS,
)
EmployeeState = EMPLOYMENT_LIFECYCLE.State


def open_employee(plan: EmploymentPlan | Mapping[str, Any], scope: Mapping[str, Any], *, receipt: Mapping[str, Any], opened_at: str, actor_ref: str) -> Any:
    """Open the case; the scope entity is the worker commitment the offer receipt named, so a proof can be fenced on it."""

    entity_ref = str(dict(detached(scope)).get("entity_ref", ""))
    worker_ref = str(dict(detached(receipt)).get("worker_ref", ""))
    _require(entity_ref == worker_ref, "EMPLOYEE_SCOPE_MISMATCH", f"the case is scoped to {entity_ref!r}; the offer names {worker_ref!r}")
    return EMPLOYMENT_LIFECYCLE.open(plan, scope, opened_at=opened_at, actor_ref=actor_ref, receipt={**detached(receipt), "entity_scope": detached(scope)})


def advance_employee(plan: EmploymentPlan | Mapping[str, Any], state: Any, command: Any) -> Any:
    return EMPLOYMENT_LIFECYCLE.advance(plan, state, command)


# --------------------------------------------------------------------------- #
# Receipts from the hops' sealed artifacts
# --------------------------------------------------------------------------- #


def _provenance(provenance: Mapping[str, Any] | Any, *, tools: frozenset[str] | set[str], lanes: tuple[str, ...], code: str) -> dict[str, Any]:
    raw = dict(detached(provenance))
    _require(str(raw.get("source_tool", "")) in tools, code, f"expected a read from {sorted(tools)}, got {raw.get('source_tool')!r}")
    _require(str(raw.get("lane", "")) in lanes, code, f"a {raw.get('source_tool')} read arrives on {lanes}, not {raw.get('lane')!r}")
    for key in ("observation_ref", "provenance_digest", "output_digest", "completed_at"):
        _require(bool(raw.get(key)), code, f"the provenance lacks {key}")
    return raw


def employment_worker_ref(application_ref: str) -> str:
    """The chain's own commitment to one applicant: ``emp:`` plus a digest of the application reference."""

    return f"emp:{stable_digest({'application': str(application_ref)})[:32]}"


def offer_receipt(provenance: Mapping[str, Any] | Any, application_row: Mapping[str, Any] | Any, *, offer_terms: Mapping[str, Any] | Any) -> dict[str, Any]:
    """From a host-lane ATS application row plus the self-naming offer-terms input a human signed off."""

    prov = _provenance(provenance, tools=APPLICATION_TOOLS, lanes=("host_read",), code="APPLICATION_NOT_BOUND")
    row = _reject_identity(dict(detached(application_row)), path="application_row")
    _require(str(prov["output_digest"]) == stable_digest(row), "APPLICATION_NOT_BOUND", "the provenance does not seal this exact application row")
    _require(bool(row.get("id")) and bool(row.get("status")), "APPLICATION_INCOMPLETE", "an application row names its id and status")
    terms = _reject_identity(dict(detached(offer_terms)), path="offer_terms")
    _require(str(terms.get("schema")) == OFFER_TERMS_SCHEMA, "OFFER_TERMS_SCHEMA_MISMATCH", f"offer terms name themselves {OFFER_TERMS_SCHEMA}")
    for key in ("offer_ref", "amount", "pay_rate_uom", "document_sha256"):
        _require(terms.get(key) is not None, "OFFER_TERMS_INCOMPLETE", f"the offer terms lack {key}")
    _require(str(terms["pay_rate_uom"]) in ("hour", "year"), "OFFER_TERMS_INCOMPLETE", "pay_rate_uom is 'hour' or 'year'")
    application_ref = f"ats:application:{row['id']}"
    stage = dict(row.get("current_stage") or {})
    return {
        "worker_ref": employment_worker_ref(application_ref),
        "application_ref": application_ref,
        "ats_status": str(row["status"]),
        "offer_amount": str(decimal_value(terms["amount"], field_name="amount")),
        "pay_rate_uom": str(terms["pay_rate_uom"]),
        "application_provenance": prov,
        "offer_terms": {"schema": OFFER_TERMS_SCHEMA, "operator_supplied": True, "offer_ref": str(terms["offer_ref"]), "amount": str(decimal_value(terms["amount"], field_name="amount")), "pay_rate_uom": str(terms["pay_rate_uom"]), "document_sha256": str(terms["document_sha256"]), "stage": str(stage.get("name") or "")},
        "evidence_refs": [f"application:{prov['observation_ref']}", f"offer:{terms['offer_ref']}"],
    }


def contract_receipt(envelope_row: Mapping[str, Any] | Any) -> dict[str, Any]:
    """From a host-lane DocuSign ``signing.get_envelope`` row; the status travels through so the guard, not the builder, refuses an unsigned contract."""

    row = _reject_identity(dict(detached(envelope_row)), path="envelope_row")
    _require(bool(row.get("status")) and bool(row.get("envelope_id_sha256") or row.get("envelope_ref")), "ENVELOPE_INCOMPLETE", "an envelope row names its status and its hashed envelope")
    documents = list(row.get("documents") or [])
    _require(len(documents) >= 1, "ENVELOPE_INCOMPLETE", "an employment contract envelope carries at least one document")
    digest = str(documents[0].get("document_sha256", ""))
    _require(bool(_HEX64.match(digest)), "ENVELOPE_INCOMPLETE", "the envelope's document is not a sha256")
    completed = row.get("completed_at") or row.get("status_changed_at")
    return {"contract_envelope_status": str(row["status"]), "contract_document_sha256": digest, "contract_signed_at": None if completed is None else _at(completed, field_name="contract_signed_at"), "evidence_refs": [f"envelope:{str(row.get('envelope_id_sha256') or row.get('envelope_ref'))[:24]}"]}


def hire_receipt(
    proof: AuthorizationProof | Mapping[str, Any] | None,
    *,
    headcount_provenance: Mapping[str, Any] | Any,
    headcount_page: Mapping[str, Any] | Any,
    worker_ref: str,
    paper_states: Sequence[Any] = (),
    paper_plan: Any = None,
    contract: Mapping[str, Any] | None = None,
    at: str | None = None,
) -> dict[str, Any]:
    """From the people_change proof, the worker's ``xero.observe_headcount`` row, and their current standing paper.

    ``worker_ref`` is the *payroll* commitment (``worker:<employee_id_sha256[:24]>``):
    it selects the headcount row and holds the paper.  ``proof`` is ``None``
    while the hire is still being *asked for*: the receipt is then the body of
    the approval request, and the guard refuses it with ``HIRE_NOT_AUTHORIZED``
    until the approver's decision comes back as a sealed proof.
    """

    evidence = authorization_evidence(proof) if proof is not None else {"evidence_refs": []}
    prov = _provenance(headcount_provenance, tools=frozenset({HEADCOUNT_TOOL}), lanes=("governed_read", "observation_read_receipt"), code="HEADCOUNT_NOT_BOUND")
    page = _reject_identity(dict(detached(headcount_page)), path="headcount_page")
    _require(str(page.get("schema")) == "lightbulb.xero_headcount_page.v1", "HEADCOUNT_SCHEMA_MISMATCH", "expected a xero headcount page")
    _require(str(prov["output_digest"]) == stable_digest(page), "HEADCOUNT_NOT_BOUND", "the provenance does not seal this exact headcount page")
    rows = [row for row in (page.get("employees") or []) if payroll_worker_ref(str(row.get("employee_id_sha256", ""))) == worker_ref]
    _require(len(rows) == 1, "HEADCOUNT_ROW_MISSING", f"the headcount page carries {len(rows)} rows for {worker_ref}; exactly one is required")
    stamp = at or _at(page["observed_at"], field_name="observed_at")
    papers = [verify_paper_current(state, source_plan=paper_plan, at=stamp, kind=str(dict(detached(state)).get("ledger", {}).get("kind")), holder_ref=worker_ref).to_dict() for state in paper_states]
    receipt: dict[str, Any] = {
        **evidence,
        "payroll_worker_ref": worker_ref,
        "headcount_source": {"provenance": prov, "row": rows[0]},
        "paper_sources": papers,
        "start_date": _at(rows[0]["start_date"], field_name="start_date"),
        "evidence_refs": [*evidence["evidence_refs"], f"headcount:{prov['observation_ref']}", *[f"paper:{item['kind']}:{item['state_digest'][:16]}" for item in papers]],
    }
    if contract is not None:
        contract_facts = dict(detached(contract))
        receipt.update({key: contract_facts[key] for key in ("contract_envelope_status", "contract_document_sha256", "contract_signed_at") if key in contract_facts})
        receipt["evidence_refs"] = [*receipt["evidence_refs"], *list(contract_facts.get("evidence_refs") or [])]
    return receipt


_WORKFLOW_KEYS: tuple[str, ...] = ("workflow", "success", "employee_ref_sha256", "payroll_employee_ref_sha256", "checklist_id", "checklist_status", "task_count", "decision_id", "case_id", "last_working_day")


def _hr_receipt(hr_response: Mapping[str, Any] | Any, task: Mapping[str, Any] | Any, *, workflow: str) -> dict[str, Any]:
    raw = dict(detached(hr_response))
    _require(str(raw.get("workflow")) == workflow, "HR_WORKFLOW_MISMATCH", f"expected an {workflow} response, got {raw.get('workflow')!r}")
    _require(str(raw.get("status", "persisted")) not in ("not_persisted", "error"), "HR_WORKFLOW_NOT_PERSISTED", f"the {workflow} response is {raw.get('status')}; only a persisted workflow is evidence")
    _require(bool(raw.get("employee_ref_sha256")), "HR_EMPLOYEE_REF_MISSING", f"the {workflow} response carries no hashed employee reference")
    # ``employee_profile`` is dropped whole; whatever the response still carries
    # after that is scanned before anything is kept.
    _reject_identity({key: item for key, item in raw.items() if key != "employee_profile"}, path="hr_response")
    reduced = {key: raw[key] for key in _WORKFLOW_KEYS if raw.get(key) is not None}
    raw_task = dict(detached(task))
    _require(str(raw_task.get("status", "")).upper() == "APPROVED", "TASK_NOT_APPROVED", f"the {workflow} approval task is {raw_task.get('status')}, not APPROVED")
    decided_by = raw_task.get("decidedByRef") or raw_task.get("decided_by_ref") or raw_task.get("decidedBy") or raw_task.get("decided_by")
    decided_at = raw_task.get("decidedAt") or raw_task.get("decided_at")
    _require(bool(raw_task.get("id")) and bool(decided_by) and bool(decided_at), "TASK_NOT_APPROVED", "an approved task names its id, who decided it, and when")
    normalized = {"id": str(raw_task["id"]), "status": "APPROVED", "decided_by_ref": str(decided_by), "decided_at": _at(decided_at, field_name="decided_at")}
    _reject_identity(normalized, path="hr_task")
    return {"hr_workflow_source": reduced, "hr_task": normalized, "evidence_refs": [f"{workflow}:{reduced.get('checklist_id') or reduced.get('case_id')}", f"task:{normalized['id']}"]}


def onboarding_receipt(hr_response: Mapping[str, Any] | Any, task: Mapping[str, Any] | Any) -> dict[str, Any]:
    """From the Spring ``hr_onboarding`` response and its APPROVED ApprovalTask; ``employee_profile`` is dropped whole."""

    return _hr_receipt(hr_response, task, workflow="hr_onboarding")


def offboarding_receipt(hr_response: Mapping[str, Any] | Any, task: Mapping[str, Any] | Any, *, access_systems: Sequence[str] = (), authorization: Mapping[str, Any] | AuthorizationProof | None = None) -> dict[str, Any]:
    """From the Spring ``hr_offboarding`` response, its APPROVED task, the operator-held access-system list, and the people_change proof."""

    receipt = _hr_receipt(hr_response, task, workflow="hr_offboarding")
    workflow = receipt["hr_workflow_source"]
    _require(bool(workflow.get("last_working_day")) and bool(workflow.get("case_id")), "OFFBOARDING_INCOMPLETE", "an offboarding response names its case and the last working day")
    receipt["last_working_at"] = _at(workflow["last_working_day"], field_name="last_working_at")
    receipt["access_systems_expected"] = sorted({str(item) for item in access_systems})
    if authorization is not None:
        evidence = authorization_evidence(authorization)
        receipt["authorization_proof"] = evidence["authorization_proof"]
        receipt["evidence_refs"] = [*receipt["evidence_refs"], *evidence["evidence_refs"]]
    return receipt


def roster_receipt(provenance: Mapping[str, Any] | Any, roster_payload: Mapping[str, Any] | Any, *, worker_ref: str) -> dict[str, Any]:
    """From a published ``host.roster`` read, or the self-naming operator roster sheet that stands in for one."""

    prov = _provenance(provenance, tools=ROSTER_TOOLS, lanes=("host_read", "governed_read"), code="ROSTER_NOT_BOUND")
    payload = _reject_identity(dict(detached(roster_payload)), path="roster_payload")
    _require(str(payload.get("schema")) in (ROSTER_SCHEMA, ROSTER_SHEET_SCHEMA), "ROSTER_SCHEMA_MISMATCH", f"expected {ROSTER_SCHEMA} or {ROSTER_SHEET_SCHEMA}, got {payload.get('schema')!r}")
    _require(str(payload.get("status")) == "published", "ROSTER_NOT_PUBLISHED", f"the roster is {payload.get('status')}; only a published roster is evidence")
    _require(str(prov["output_digest"]) == stable_digest(payload), "ROSTER_NOT_BOUND", "the provenance does not seal this exact roster payload")
    for key in ("roster_ref", "period_start", "period_end"):
        _require(bool(payload.get(key)), "ROSTER_INCOMPLETE", f"the roster lacks {key}")
    shifts = [shift for shift in (payload.get("shifts") or []) if str(shift.get("worker_ref")) == worker_ref]
    _require(len(shifts) >= 1, "ROSTER_WORKER_ABSENT", f"the roster carries no shift for {worker_ref}")
    hours = sum((decimal_value(shift.get("hours"), field_name="hours") for shift in shifts), Decimal("0.00"))
    return {
        "roster_source": {"provenance": prov, "payload": payload},
        "period_start": _at(payload["period_start"], field_name="period_start"),
        "period_end": _at(payload["period_end"], field_name="period_end"),
        "shift_count": len(shifts),
        "rostered_hours": str(hours),
        "evidence_refs": [f"roster:{payload['roster_ref']}", f"read:{prov['observation_ref']}"],
    }


def timesheet_receipt(provenance: Mapping[str, Any] | Any, page: Mapping[str, Any] | Any, *, worker_ref: str, approver_ref: str) -> dict[str, Any]:
    """From the worker's row of a ``xero.observe_timesheets`` page; ``approver_ref`` is who approved it in the provider."""

    prov = _provenance(provenance, tools=frozenset({TIMESHEET_TOOL}), lanes=("governed_read", "observation_read_receipt"), code="TIMESHEET_NOT_BOUND")
    raw = _reject_identity(dict(detached(page)), path="timesheet_page")
    _require(str(raw.get("schema")) == "lightbulb.xero_timesheet_page.v1", "TIMESHEET_PAGE_SCHEMA_MISMATCH", "expected a xero timesheet page")
    _require(str(prov["output_digest"]) == stable_digest(raw), "TIMESHEET_NOT_BOUND", "the provenance does not seal this exact timesheet page")
    rows = [row for row in (raw.get("timesheets") or []) if payroll_worker_ref(str(row.get("employee_id_sha256", ""))) == worker_ref]
    _require(len(rows) == 1, "TIMESHEET_ROW_MISSING", f"the timesheet page carries {len(rows)} rows for {worker_ref}; exactly one is required")
    row = rows[0]
    totals = timesheet_page_totals(raw, worker_refs=(worker_ref,))
    return {
        "timesheet_source": {"provenance": prov, "row": row, "totals": totals},
        "timesheet_hours": str(decimal_value(row["hours"], field_name="hours")),
        "timesheet_status": str(row["status"]),
        "period_start": _at(row["start_date"], field_name="period_start"),
        "period_end": _at(row["end_date"], field_name="period_end"),
        "approver_ref": str(approver_ref),
        "evidence_refs": [f"timesheet:{str(row['timesheet_id_sha256'])[:24]}", f"read:{prov['observation_ref']}"],
    }


def pay_receipt(run_state: Mapping[str, Any] | Any, *, source_plan: Any, worker_ref: str, payrun_observation: Mapping[str, Any] | Any) -> dict[str, Any]:
    """From a paid ``payroll_run_chain`` state plus the worker's row of the ``xero.observe_payrun`` observation.

    Gross and net are read off the worker's row in minor units; the chain never
    computes a wage.
    """

    from lightbulb.payroll_run_chain import verify_paid_pay_run
    proven = verify_paid_pay_run(run_state, source_plan=source_plan)
    raw_state = _reject_identity(proven.to_dict(), path="pay_run_state")
    ledger = dict(raw_state.get("ledger") or {})
    _require(str(raw_state.get("status", "")) in PAY_RUN_STATUSES, "PAY_RUN_NOT_PAID", f"the payroll run is {raw_state.get('status')}; only a posted run proves pay")
    observation = _reject_identity(dict(detached(payrun_observation)), path="payrun_observation")
    _require(str(observation.get("schema")) == "lightbulb.xero_payrun_observation.v1", "PAYRUN_OBSERVATION_SCHEMA_MISMATCH", "expected a xero pay run observation")
    _require(str(observation.get("pay_run_status")) == "POSTED" and str(observation.get("disposition")) == "POSTED", "PAYRUN_NOT_POSTED", f"the pay run is {observation.get('pay_run_status')}, not POSTED")
    workers = [row for row in (observation.get("workers") or []) if payroll_worker_ref(str(row.get("employee_id_sha256", ""))) == worker_ref]
    _require(len(workers) == 1, "WORKER_SHARE_MISSING", f"the pay run observation carries {len(workers)} rows for {worker_ref}; exactly one is required")
    cost_reads = [entry.command.receipt.source_payload for entry in proven.transition_history
                  if entry.command.event == "cost_run"]
    _require(bool(cost_reads) and stable_digest(detached(cost_reads[-1])) == stable_digest(observation),
        "PAY_RUN_CORRELATION_MISMATCH", "worker shares must come from the exact governed cost read retained by the paid run")
    _require(worker_ref in proven.ledger.worker_refs, "PAY_RUN_WORKER_ABSENT", "the paid run must include this worker")
    share = workers[0]
    pay_run_ref = f"payrun:{str(observation['pay_run_id_sha256'])[:16]}"
    # one receipt binds one run: the posted state and the observation must be
    # the same pay run, or the gross and net below belong to a different one.
    ledger_ref = str(ledger.get("run_ref") or "")
    _require(not ledger_ref or ledger_ref == pay_run_ref, "PAY_RUN_CORRELATION_MISMATCH", f"the paid run state proves {ledger_ref}; the observation is {pay_run_ref}")
    for key in ("period_start", "period_end"):
        if ledger.get(key):
            _require(_at(ledger[key], field_name=key) == _at(observation[key], field_name=key), "PAY_RUN_CORRELATION_MISMATCH", f"the paid run state's {key} is not the observation's {key}")
    facts = PayRunFacts(
        status=str(raw_state["status"]),
        state_digest=str(raw_state["state_digest"]),
        plan_digest=str(raw_state["plan_digest"]),
        pay_run_ref=pay_run_ref,
        period_start=_at(observation["period_start"], field_name="period_start"),
        period_end=_at(observation["period_end"], field_name="period_end"),
        paid_at=_at(observation["payment_date"], field_name="paid_at"),
        worker_refs=tuple(str(item) for item in (ledger.get("worker_refs") or ())),
    )
    return {
        "pay_run_source": {"state": raw_state, "plan": detached(source_plan), "observation": observation},
        "payrun_observation": {"schema": observation["schema"], "pay_run_id_sha256": observation["pay_run_id_sha256"], "currency": observation["currency"], "evidence_sha256": observation["evidence_sha256"], "worker": share},
        "pay_run_ref": pay_run_ref,
        "gross": str((Decimal(int(share["wages_minor"])) / _HUNDRED).quantize(Decimal("0.01"))),
        "net": str((Decimal(int(share["net_pay_minor"])) / _HUNDRED).quantize(Decimal("0.01"))),
        "paid_at": facts.paid_at,
        "evidence_refs": [pay_run_ref, f"payrun_evidence:{str(observation['evidence_sha256'])[:24]}", f"run_state:{facts.state_digest[:16]}"],
    }


def leave_receipt(provenance: Mapping[str, Any] | Any, page: Mapping[str, Any] | Any, *, worker_ref: str, balance_hours: Any = None) -> dict[str, Any]:
    """From the worker's row of a ``xero.observe_leave`` page; the balance is an operator input until ``host.leave_balances`` exists."""

    prov = _provenance(provenance, tools=frozenset({LEAVE_TOOL}), lanes=("governed_read", "observation_read_receipt"), code="LEAVE_NOT_BOUND")
    raw = _reject_identity(dict(detached(page)), path="leave_page")
    _require(str(raw.get("schema")) == "lightbulb.xero_leave_page.v1", "LEAVE_PAGE_SCHEMA_MISMATCH", "expected a xero leave page")
    _require(str(prov["output_digest"]) == stable_digest(raw), "LEAVE_NOT_BOUND", "the provenance does not seal this exact leave page")
    rows = [row for row in (raw.get("leave") or []) if payroll_worker_ref(str(row.get("employee_id_sha256", ""))) == worker_ref]
    _require(len(rows) == 1, "LEAVE_ROW_MISSING", f"the leave page carries {len(rows)} rows for {worker_ref}; exactly one is required")
    row = rows[0]
    receipt: dict[str, Any] = {
        "leave_source": {"provenance": prov, "row": row},
        "leave_type_ref": f"leave-type:{str(row['leave_type_id_sha256'])[:24]}",
        "leave_start": _at(row["start_date"], field_name="leave_start"),
        "leave_end": _at(row["end_date"], field_name="leave_end"),
        "leave_hours": str(decimal_value(row["units"], field_name="units")),
        "evidence_refs": [f"leave:{str(row['leave_application_id_sha256'])[:24]}", f"read:{prov['observation_ref']}"],
    }
    if balance_hours is not None:
        receipt["leave_balance_hours"] = str(decimal_value(balance_hours, field_name="leave_balance_hours"))
    return receipt


def access_revocation_receipt(revocations: Sequence[Mapping[str, Any] | Any]) -> dict[str, Any]:
    """From operator-held revocation evidence shaped like ``people_operations_lifecycle.VerifyAccessRevocationCommand``."""

    items: list[dict[str, Any]] = []
    for entry in revocations:
        raw = _reject_identity(dict(detached(entry)), path="revocation")
        for key in ("system_ref", "account_ref", "revocation_verification_ref", "claimed_provider_effect_receipt_digest", "revoked_at"):
            _require(bool(raw.get(key)), "REVOCATION_INCOMPLETE", f"a revocation lacks {key}")
        _require(bool(_HEX64.match(str(raw["claimed_provider_effect_receipt_digest"]))), "REVOCATION_UNPROVEN", "a revocation names the 64-hex provider effect receipt it claims")
        items.append({key: (str(raw[key]) if key != "revoked_at" else _at(raw[key], field_name="revoked_at")) for key in ("system_ref", "account_ref", "revocation_verification_ref", "claimed_provider_effect_receipt_digest", "revoked_at")})
    _require(len(items) >= 1, "REVOCATION_INCOMPLETE", "an access revocation receipt carries at least one system")
    return {"access_revocations": items, "evidence_refs": [f"revocation:{item['revocation_verification_ref']}" for item in items][:50]}


# --------------------------------------------------------------------------- #
# What the chain hands to the other engines
# --------------------------------------------------------------------------- #


def _bound(state: Any, plan: EmploymentPlan | Mapping[str, Any] | None = None) -> Any:
    parsed_state = state if isinstance(state, EmployeeState) else EmployeeState.model_validate(detached(state))
    if plan is not None:
        parsed_plan = EmploymentPlan.model_validate(detached(plan))
        _require(parsed_state.plan_digest == parsed_plan.plan_digest, "EMPLOYEE_PLAN_MISMATCH", "the employee belongs to a different employment plan")
    return parsed_state


def capacity_expectation(states: Sequence[Any], *, plan: EmploymentPlan | Mapping[str, Any], period_start: str, period_end: str) -> dict[str, Any]:
    """What ``people_engine`` should see for the period: the hours this chain rostered, per worker."""

    start, end = timestamp(period_start, field_name="period_start"), timestamp(period_end, field_name="period_end")
    workers = []
    for state in states:
        parsed_state = _bound(state, plan)
        ledger = parsed_state.ledger
        if parsed_state.status in ("rostered", "time_recorded", "paid", "on_leave", "offboarding") and ledger.current_period_start == start and ledger.current_period_end == end:
            workers.append({"worker_ref": str(ledger.payroll_worker_ref), "available_hours": str(ledger.rostered_hours)})
    workers.sort(key=lambda item: item["worker_ref"])
    payload = {"schema": CAPACITY_EXPECTATION_SCHEMA, "period_start": start, "period_end": end, "workers": workers}
    return {**payload, "expected_digest": stable_digest(payload)}


def timesheet_expectation(states: Sequence[Any], *, plan: EmploymentPlan | Mapping[str, Any], period_start: str, period_end: str) -> dict[str, Any]:
    """What ``payroll_run_chain`` should read back for the period: the workers and the approved hours the chain recorded."""

    start, end = timestamp(period_start, field_name="period_start"), timestamp(period_end, field_name="period_end")
    refs: list[str] = []
    total = Decimal("0.00")
    for state in states:
        ledger = _bound(state, plan).ledger
        if ledger.current_period_start == start and ledger.current_period_end == end and ledger.timesheet_hours_period > 0:
            refs.append(str(ledger.payroll_worker_ref))
            total += ledger.timesheet_hours_period
    payload = {"schema": TIMESHEET_EXPECTATION_SCHEMA, "period_start": start, "period_end": end, "worker_refs": sorted(refs), "total_hours": str(total)}
    return {**payload, "expected_digest": stable_digest(payload)}


def headcount_receipt(states: Sequence[Any], *, plan: EmploymentPlan | Mapping[str, Any]) -> dict[str, Any]:
    """What ``wind_down_chain.run_final_pay`` needs: who is still employed, who is proven gone, and when the last one left."""

    active: list[str] = []
    gone: list[str] = []
    last: str | None = None
    digests: list[str] = []
    for state in states:
        parsed_state = _bound(state, plan)
        ledger = parsed_state.ledger
        ref = str(ledger.payroll_worker_ref or ledger.worker_ref)
        digests.append(parsed_state.state_digest)
        if parsed_state.status == "offboarded":
            gone.append(ref)
            if ledger.last_working_at is not None and (last is None or parsed(ledger.last_working_at) > parsed(last)):
                last = ledger.last_working_at
        elif parsed_state.status not in ("withdrawn", "reconciliation_required"):
            active.append(ref)
    payload = {"schema": HEADCOUNT_PROOF_SCHEMA, "active_worker_refs": sorted(active), "offboarded_worker_refs": sorted(gone), "all_offboarded": not active and bool(gone), "last_working_at": last}
    return {**payload, "states_digest": stable_digest(sorted(digests))}


def right_to_work_item(state: Any) -> dict[str, Any]:
    """The ``obligation_paper`` STANDING record receipt this employee's right-to-work paper opens as."""

    parsed_state = _bound(state)
    ledger = parsed_state.ledger
    _require(ledger.payroll_worker_ref is not None, "EMPLOYEE_NOT_HIRED", f"{parsed_state.scope.entity_ref} is {parsed_state.status}; standing paper is held from the hire onward")
    return {
        "schema": STANDING_ITEM_SCHEMA,
        "record": "standing",
        "kind": "right_to_work",
        "holder_ref": str(ledger.payroll_worker_ref),
        "subject_ref": str(ledger.worker_ref),
        "jurisdiction_scoped": True,
        "verified_at": str(ledger.hired_at),
        "source_engine": EMPLOYMENT_KIND,
        "source_state_digest": parsed_state.state_digest,
        "evidence_refs": [f"employee:{parsed_state.scope.entity_ref}", f"state:{parsed_state.state_digest[:24]}"],
    }


def capacity_signal(states: Sequence[Any], *, period_ref: str, hours_required: Any, emitted_at: str) -> dict[str, Any]:
    """``signals.capacity_shortfall``: the hours the roster covers against the hours the period needs."""

    required = decimal_value(hours_required, field_name="hours_required")
    available = sum((_bound(state).ledger.rostered_hours for state in states), Decimal("0.00"))
    shortfall = required - available
    return {
        "name": "signals.capacity_shortfall",
        "producer": EMPLOYMENT_KIND,
        "emitted_at": timestamp(emitted_at, field_name="emitted_at"),
        "payload": {"period_ref": str(period_ref), "hours_required": str(required), "available_hours": str(available), "shortfall_hours": str(shortfall if shortfall > 0 else Decimal("0.00")), "worker_count": len(list(states))},
    }


def capability_lapsed_signal(states: Sequence[Any], standing_states: Sequence[Any], *, emitted_at: str) -> dict[str, Any] | None:
    """``signals.capability_lapsed``: the standing paper a rostered worker no longer holds, or ``None`` when every paper is current."""

    holders = {str(_bound(state).ledger.payroll_worker_ref) for state in states if _bound(state).status not in ("offboarded", "withdrawn", "reconciliation_required")}
    lapsed = []
    for paper in standing_states:
        raw = dict(detached(paper))
        ledger = dict(raw.get("ledger") or {})
        if str(ledger.get("holder_ref")) in holders and str(raw.get("status")) not in CURRENT_PAPER_STATUSES:
            lapsed.append((str(ledger.get("holder_ref")), str(ledger.get("kind"))))
    if not lapsed:
        return None
    return {
        "name": "signals.capability_lapsed",
        "producer": EMPLOYMENT_KIND,
        "emitted_at": timestamp(emitted_at, field_name="emitted_at"),
        "payload": {"lapsed_count": len(lapsed), "kinds": ",".join(sorted({kind for _, kind in lapsed}))[:280], "worker_refs": ",".join(sorted({holder for holder, _ in lapsed}))[:280]},
    }


def _hours(value: Decimal) -> str:
    return f"{value:.0f}" if value == value.to_integral_value() else f"{value:.2f}"


def _day(stamp: str | None) -> str:
    if not stamp:
        return "?"
    when = parsed(stamp)
    return f"{when.day} {when.strftime('%b')}"


def narrate_employee(state: Any, *, currency: str | None = None) -> str:
    """One line an operator reads: who was hired under which proof, and what the chain has proved since."""

    parsed_state = _bound(state)
    ledger = parsed_state.ledger
    unit = currency or parsed_state.scope.currency
    parts = [f"{parsed_state.scope.entity_ref}"]
    if ledger.hired_at:
        parts.append(f"hired {_day(ledger.hired_at)} (people_change proof {str(ledger.hire_proof_digest)[:4]}…)")
    else:
        parts.append(f"offered {_day(ledger.offered_at)} ({money(ledger.commitment_amount, unit)} commitment)")
    if ledger.onboarded_at:
        parts.append("onboarded")
    if ledger.rostered_hours > 0:
        parts.append(f"rostered {_hours(ledger.rostered_hours)}h")
    if ledger.timesheet_hours_period > 0:
        parts.append(f"TS approved {_hours(ledger.timesheet_hours_period)}h")
    if ledger.pay_run_refs:
        parts.append(f"paid in run {ledger.pay_run_refs[-1][:11]}… net {money(ledger.net_paid_total, unit)}")
    if ledger.leave_open:
        parts.append(f"on leave ({_hours(ledger.leave_hours_total)}h taken)")
    if ledger.offboarding_initiated_at and not ledger.offboarded_at:
        parts.append(f"offboarding, last day {_day(ledger.last_working_at)}")
    if ledger.offboarded_at:
        parts.append(f"offboarded {_day(ledger.offboarded_at)}, {len(ledger.access_systems_revoked)} systems revoked")
    return f"{parts[0]}: {', '.join(parts[1:])}"


def employee_summary(state: Any) -> dict[str, Any]:
    parsed_state = _bound(state)
    ledger = parsed_state.ledger
    return {
        "employee_ref": str(parsed_state.scope.entity_ref),
        "status": parsed_state.status,
        "worker_ref": ledger.worker_ref,
        "payroll_worker_ref": ledger.payroll_worker_ref,
        "commitment_amount": str(ledger.commitment_amount),
        "rostered_hours": str(ledger.rostered_hours),
        "timesheet_hours_total": str(ledger.timesheet_hours_total),
        "gross_paid_total": str(ledger.gross_paid_total),
        "net_paid_total": str(ledger.net_paid_total),
        "pay_run_refs": list(ledger.pay_run_refs),
        "final_pay_run_ref": ledger.final_pay_run_ref,
        "outcome": ledger.outcome,
        "state_digest": parsed_state.state_digest,
    }


def employment_exception(error: Exception, *, source_ref: str, category: str | None = "people_change") -> dict[str, Any]:
    """An exceptions-desk opening receipt for a refused hop, through ``authority_matrix.authority_exception``."""

    return authority_exception(error, source_engine=EMPLOYMENT_KIND, source_ref=source_ref, category=category)


EMPLOYMENT_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": EMPLOYMENT_KIND,
    "golden_loop": EMPLOYMENT_GOLDEN_LOOP,
    "stages": ["offer", "hire", "onboard", "roster", "record_time", "record_pay", "initiate_offboarding", "complete_offboarding"],
    "statuses": list(EMPLOYMENT_STATUSES),
    "events": list(EMPLOYMENT_EVENTS),
    "hops": {
        "offer": "host-lane ats.get_application / greenhouse.get_application row + a self-naming lightbulb.employment_offer_terms.v1 input",
        "hire": "authority_matrix people_change AuthorizationProof for the annualised commitment + xero.observe_headcount ACTIVE row + current obligation_paper standing items (+ docusign signing.get_envelope)",
        "onboard": "Spring hr_onboarding response (employee_ref_sha256, payroll_employee_ref_sha256, checklist) + its APPROVED ApprovalTask",
        "roster": "host.roster / scheduling.get_roster published roster sealed by its provenance",
        "record_time": "xero.observe_timesheets APPROVED row for the worker, approved in the provider by someone else",
        "record_pay": "paid payroll_run_chain state + the worker's row of a POSTED xero.observe_payrun observation",
        "start_leave": "xero.observe_leave row for the worker (balance operator-held until host.leave_balances exists)",
        "end_leave": "the same xero.observe_leave row, closed",
        "initiate_offboarding": "Spring hr_offboarding response + its APPROVED ApprovalTask + a second people_change AuthorizationProof",
        "complete_offboarding": "the final pay run plus people_operations_lifecycle-shaped access revocation evidence per expected system",
        "withdraw": "an operator reason; no artifact is claimed",
        "require_reconciliation": "an operator reason; the case leaves the automated path",
    },
    "required_connectors": ["xero", "greenhouse", "docusign", "lightbulb.internal_hr", "lightbulb.sdk_engine_state"],
    "missing_reads": ["host.roster", "host.leave_balances"],
    "hard_rules": [
        "a person is never named: every provider id is hashed before it crosses the boundary",
        "hiring is a people_change commitment: it consumes an authority proof for the annualised cost, never a typed approval",
        "pay is only what a posted payroll run proves; the chain never computes wages",
        "timesheets are approved by someone other than the worker, in the provider, never by the SDK",
        "offboarding closes only after the final run covers the last working day and every access system is revoked",
    ],
}

__all__ = [
    "APPLICATION_TOOLS",
    "AUTHORIZATION_FACTS_SCHEMA",
    "CAPACITY_EXPECTATION_SCHEMA",
    "CURRENT_PAPER_STATUSES",
    "EMPLOYMENT_EVENTS",
    "EMPLOYMENT_GOLDEN_LOOP",
    "EMPLOYMENT_KIND",
    "EMPLOYMENT_LIFECYCLE",
    "EMPLOYMENT_MANIFEST",
    "EMPLOYMENT_PLAN_SCHEMA",
    "EMPLOYMENT_STATUSES",
    "ENVELOPE_TOOLS",
    "HEADCOUNT_PROOF_SCHEMA",
    "HEADCOUNT_TOOL",
    "LEAVE_TOOL",
    "MAX_EMPLOYMENT_TRANSITIONS",
    "OFFER_TERMS_SCHEMA",
    "PAPER_FACTS_SCHEMA",
    "PAPER_KINDS",
    "PAY_RUN_FACTS_SCHEMA",
    "PAY_RUN_STATUSES",
    "PAYRUN_TOOL",
    "ROSTER_SCHEMA",
    "ROSTER_SHEET_SCHEMA",
    "ROSTER_TOOLS",
    "STANDING_ITEM_SCHEMA",
    "STANDING_STATUSES",
    "TERMINAL_EMPLOYMENT_STATUSES",
    "TIMESHEET_EXPECTATION_SCHEMA",
    "TIMESHEET_TOOL",
    "AuthorizationFacts",
    "EmployeeState",
    "EmploymentChainError",
    "EmploymentEffectBoundary",
    "EmploymentLedger",
    "EmploymentPlan",
    "EmploymentReceipt",
    "PaperFacts",
    "PayRunFacts",
    "access_revocation_receipt",
    "advance_employee",
    "authorization_evidence",
    "capability_lapsed_signal",
    "capacity_expectation",
    "capacity_signal",
    "compile_employment_chain",
    "contract_receipt",
    "employee_summary",
    "employment_exception",
    "employment_worker_ref",
    "headcount_receipt",
    "hire_receipt",
    "leave_receipt",
    "narrate_employee",
    "offboarding_receipt",
    "offer_receipt",
    "onboarding_receipt",
    "open_employee",
    "pay_receipt",
    "payroll_worker_ref",
    "require_authorization_proof",
    "right_to_work_item",
    "roster_receipt",
    "timesheet_expectation",
    "timesheet_page_totals",
    "timesheet_receipt",
    "verify_paper_current",
]
