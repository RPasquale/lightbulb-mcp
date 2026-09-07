"""The job chain: one replay-fenced lifecycle per job, from a lead to the first dollar settled.

For a plumber, a cleaner, a clinic or a consulting firm the revenue engine is
not a contract -- it is the job.  ``revenue_chain`` is contract-shaped and
consumes QuickBooks/Stripe observers; ``services_firm`` attributes all revenue
to pipeline and growth spend and no period ever receives a job's cash.
``JOB_LIFECYCLE`` links the hops a services business actually runs:

    lead_received -> quoted -> accepted -> booked -> assigned -> done
                  -> invoiced -> paid -> reconciled            (terminal)
    lead_received .. assigned -> cancelled                     (terminal)
    booked .. paid            -> reconciliation_required       (terminal)

Every hop consumes the sealed artifact of the pack that produced it and
nothing else: a ``pipeline_engine`` handed-off prospect, a ``service_delivery``
case, a ``square.observe_bookings`` row or a self-naming operator lead
(``receive_lead``); an ``xero.create_quote`` :class:`ExecutionReceipt` plus the
``xero.observe_quote`` observation that carries its correlation, or the
self-naming ``quote_input`` the Square rail needs because Square has no quotes
API (``quote``); the customer's own acceptance -- an ACCEPTED quote
observation, a classified inbound thread, or a signed quote
(``accept``); a ``square.observe_bookings`` row (``book``); a rostered
``employment_chain`` state, a ``company_workforce`` dispatch receipt, or an
``engagement_engine`` state (``assign``); a later booking row that has elapsed
plus a human's sign-off (``complete``); the ``square.create_invoice`` +
``square.publish_invoice`` or ``xero.create_invoice`` execution receipts
(``invoice``); a ``square.observe_invoice_payment`` PAID observation or a row
of the governed ``xero.list_payments`` page (``apply_payment``); and a closed
``finance_close`` period that reconciled receivables (``reconcile``).

Authority, never a string: the quote and the invoice are gated on an
``AuthorizationProof`` of category ``job_quote`` / ``job_invoice`` (and
``pricing`` when the discount exceeds the plan's threshold) minted by
``ai_operator.authorize`` from a bound platform decision.  A discount, a
booking, a completion or a payment the provider never showed cannot advance
the job.

What it hands to other engines: :func:`period_evidence_receipt` (the
``record_evidence`` receipt whose revenue is *paid job cash*, not quoted
value), :func:`chain_revenue_receipt` and :func:`job_cost_sources` for the
cost register, :func:`receivable_receipt` for ``collections_chain``,
:func:`job_flows` for ``company_treasury``, :func:`first_dollar_signal`, and
:func:`narrate_job` for ``company_brief``.  Nothing here creates a quote, a
booking or an invoice, reads a provider, or persists anything: it binds the
receipts the platform produced.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from decimal import Decimal
from typing import Annotated, Any, Literal

from pydantic import Field, StringConstraints, ValidationInfo, field_validator, model_validator

from lightbulb.ai_operator import AuthorizationProof, authority_exception, money
from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    MONEY_QUANTUM,
    BoundedText,
    CurrencyCode,
    EngineScope,
    LifecycleSpec,
    OpaqueRef,
    Rejected,
    Sha256Digest,
    ShortText,
    StrictModel,
    add_days,
    decimal_value,
    detached,
    parsed,
    pct,
    require,
    seal,
    sealed_digest,
    skip_digests,
    stable_digest,
    timestamp,
)
from lightbulb.company_execution_bridge import ExecutionReceipt, ObservationProvenance
from lightbulb.company_treasury import ScheduledFlow

# ROUND5_SHIM (re-used, not re-declared)
#
# ``authority_matrix.require_authorization_proof`` (L685) and
# ``authority_matrix.authorization_evidence`` (L696) are not in this tree yet;
# ``employment_chain`` already carries them verbatim in its own ROUND5_SHIM
# block with round 5's field names and rejection codes, so the two round-7
# chains fence authority through exactly the same code instead of two copies
# that could drift.  When round 5 lands, both modules import the real names.
from lightbulb.employment_chain import (
    AuthorizationFacts,
    authorization_evidence,
    require_authorization_proof,
)
from lightbulb.pipeline_engine_loop import PROSPECT_LIFECYCLE, PipelineEngineLoopPlan
from lightbulb.service_delivery_engine import CASE_LIFECYCLE, ServiceDeliveryLoopPlan

JOB_CHAIN_KIND = "job_chain"
JOB_GOLDEN_LOOP = "services.lead_to_cash_per_job@0.1.0"
JOB_PLAN_SCHEMA = "lightbulb.job_chain_plan.v1"
JOB_LEAD_INTAKE_SCHEMA = "lightbulb.job_lead_intake.v1"
JOB_QUOTE_INPUT_SCHEMA = "lightbulb.job_quote_input.v1"
JOB_ACCEPTANCE_SCHEMA = "lightbulb.job_acceptance.v1"
JOB_COMPLETION_SIGNOFF_SCHEMA = "lightbulb.job_completion_signoff.v1"
BOOKING_PAGE_SCHEMA = "lightbulb.square_booking_page.v1"
QUOTE_OBSERVATION_SCHEMA = "lightbulb.xero_quote_observation.v1"
SQUARE_PAYMENT_OBSERVATION_SCHEMA = "lightbulb.square_invoice_payment_observation.v1"
MAX_JOB_TRANSITIONS = 24
_HUNDRED = Decimal("100")

#: The writes this chain binds and the reads it consumes, by rail.
QUOTE_WRITE_TOOLS: Mapping[str, str] = {"xero": "xero.create_quote"}
INVOICE_WRITE_TOOLS: Mapping[str, str] = {"square": "square.create_invoice", "xero": "xero.create_invoice"}
PUBLISH_TOOL = "square.publish_invoice"
BOOKING_TOOL = "square.observe_bookings"
QUOTE_OBSERVATION_TOOL = "xero.observe_quote"
SQUARE_PAYMENT_TOOL = "square.observe_invoice_payment"
XERO_PAYMENTS_TOOL = "xero.list_payments"
ACCEPTANCE_THREAD_TOOLS: frozenset[str] = frozenset({"gmail.get_thread", "microsoft.get_conversation"})
_READ_LANES: tuple[str, ...] = ("governed_read", "observation_read_receipt", "host_read")

OPEN_BOOKING_STATUSES: frozenset[str] = frozenset({"PENDING", "ACCEPTED"})
CANCELLED_BOOKING_STATUSES: frozenset[str] = frozenset({"CANCELLED_BY_BUYER", "CANCELLED_BY_SELLER", "CANCELLED", "DECLINED", "NO_SHOW"})
LIVE_QUOTE_STATUSES: frozenset[str] = frozenset({"SENT", "ACCEPTED"})
ROSTERED_STATUSES: frozenset[str] = frozenset({"rostered", "time_recorded", "paid"})
ENGAGEMENT_STATUSES: frozenset[str] = frozenset({"staffed", "delivering"})

JOB_STATUSES: tuple[str, ...] = ("lead_received", "quoted", "accepted", "booked", "assigned", "done", "invoiced", "paid", "reconciled", "cancelled", "reconciliation_required")
TERMINAL_JOB_STATUSES: frozenset[str] = frozenset({"reconciled", "cancelled", "reconciliation_required"})
JOB_EVENTS: tuple[str, ...] = ("receive_lead", "quote", "accept", "book", "assign", "complete", "invoice", "apply_payment", "reconcile", "cancel", "require_reconciliation")
_JOB_TABLE: dict[tuple[str, str], str] = {
    ("new", "receive_lead"): "lead_received",
    ("lead_received", "quote"): "quoted",
    ("quoted", "quote"): "quoted",
    ("quoted", "accept"): "accepted",
    ("accepted", "book"): "booked",
    ("booked", "assign"): "assigned",
    ("assigned", "complete"): "done",
    ("booked", "complete"): "done",
    ("done", "invoice"): "invoiced",
    ("invoiced", "apply_payment"): "paid",
    ("paid", "reconcile"): "reconciled",
    **{(status, "cancel"): "cancelled" for status in ("lead_received", "quoted", "accepted", "booked", "assigned")},
    **{(status, "require_reconciliation"): "reconciliation_required" for status in ("booked", "assigned", "done", "invoiced", "paid")},
}

Correlation = Annotated[str, StringConstraints(pattern=r"^LB-JOB-[0-9A-F]{18}$")]
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class JobChainError(ValueError):
    """A receipt builder refusing an artifact that does not line up; carries the code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code, self.message = code, message


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise JobChainError(code, message)


#: A key that names a customer or a technician rather than a commitment to one.
#: The same list ``payroll_run_chain._reject_identity`` (L471) fences payroll
#: with and ``employment_chain`` carries for the people side; a job row names a
#: customer only as ``customer_id_sha256`` and a technician only as a worker ref.
_IDENTITY_MARKERS: tuple[str, ...] = (
    "displayname", "fullname", "firstname", "lastname", "givenname", "familyname", "middlename", "preferredname",
    "legalname", "customername", "contactname", "employeename", "workername", "technicianname", "personname",
    "surname", "email", "phone", "mobile", "address", "dateofbirth", "birthdate", "tfn", "taxfilenumber",
    "bankaccount", "bsb", "accountnumber", "customerprofile", "personaldetails",
)
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


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
            # Canonical agreement notice custody uses an opaque address_ref;
            # its value still passes the email guard and full agreement replay.
            _require(item is None or isinstance(item, bool) or key in ("address_ref", "notice_address_ref") or not any(marker in normal for marker in _IDENTITY_MARKERS), "IDENTITY_IN_RECEIPT", f"{path}.{key} names a person; only hashed commitments cross this boundary")
            _reject_identity(item, path=f"{path}.{key}")
        return payload
    if isinstance(payload, (list, tuple)):
        for index, item in enumerate(payload):
            _reject_identity(item, path=f"{path}[{index}]")
    return payload


def _sha256_utf8(value: str) -> str:
    """``CanonicalConnectorJson.sha256Utf8``: the digest the platform stamps a correlation with."""

    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def job_correlation(job_ref: str, *, kind: Literal["quote", "invoice"]) -> str:
    """The ``LB-JOB-`` correlation one job's writes carry: 12 hex of the job, 6 of the write kind."""

    token = stable_digest({"job": str(job_ref)})[:12]
    suffix = stable_digest({"kind": str(kind)})[:6]
    return f"LB-JOB-{(token + suffix).upper()}"


def _job_token(correlation: str | None) -> str:
    return str(correlation or "")[7:19]


# --------------------------------------------------------------------------- #
# ROUND5_SHIM
#
# ``engagement_engine`` (verify_engagement), ``wip_billing`` (verify_wip),
# ``collections_chain`` (open_receivable) and ``company_cost_centres``
# (REVENUE_STATE_SCHEMAS L106 / SETTLED_REVENUE_STATUSES L107 /
# chain_revenue_receipt) land with round 5.  The exact sealed shapes this
# module consumes and produces live here with round 5's field names; delete
# this block and import the real names when round 5 lands.  Note that round
# 5's SETTLED_REVENUE_STATUSES carries no ``paid`` -- registering this chain
# needs that companion edit, which is why the shim spells the statuses out.
# --------------------------------------------------------------------------- #

ENGAGEMENT_FACTS_SCHEMA = "lightbulb.engagement_engine_facts.v1"
WIP_FACTS_SCHEMA = "lightbulb.wip_billing_facts.v1"
COST_SOURCE_SCHEMA = "lightbulb.company_cost_centre_source.v1"
REVENUE_SOURCE_SCHEMA = "lightbulb.company_cost_centre_revenue_source.v1"
RECEIVABLE_INTAKE_SCHEMA = "lightbulb.collections_receivable_intake.v1"
#: ``company_cost_centres.REVENUE_STATE_SCHEMAS`` once this chain is registered.
REVENUE_STATE_SCHEMAS: tuple[str, ...] = ("lightbulb.revenue_chain_state.v1", "lightbulb.job_chain_state.v1")
#: ``company_cost_centres.SETTLED_REVENUE_STATUSES`` plus this chain's own settled statuses.
SETTLED_REVENUE_STATUSES: frozenset[str] = frozenset({"cash_settled", "receivable_cleared", "paid", "reconciled"})


class EngagementFacts(StrictModel):
    """``engagement_engine.verify_engagement``: the engagement a consulting job is staffed under."""

    schema_id: Literal["lightbulb.engagement_engine_facts.v1"] = Field(default=ENGAGEMENT_FACTS_SCHEMA, alias="schema")
    engagement_ref: OpaqueRef
    status: ShortText
    state_digest: Sha256Digest
    plan_digest: Sha256Digest
    source_state: dict[str, Any]
    source_plan: dict[str, Any]


def verify_engagement(engagement_state: Mapping[str, Any] | Any, *, source_plan: Any = None) -> EngagementFacts:
    """``engagement_engine.verify_engagement``: a staffed or delivering engagement, or a refusal."""

    from lightbulb.engagement_engine import verify_engagement as replay
    try:
        source = replay(engagement_state, source_plan=source_plan)
    except (ValueError, TypeError) as exc:
        raise JobChainError("ENGAGEMENT_STATE_INVALID", "retain the complete canonical engagement and plan") from exc
    _require(source.status in ENGAGEMENT_STATUSES, "ENGAGEMENT_NOT_STAFFED", "the engagement must be staffed or delivering")
    return EngagementFacts(engagement_ref=source.scope.entity_ref, status=source.status,
        state_digest=source.state_digest, plan_digest=source.plan_digest,
        source_state=source.to_dict(), source_plan=detached(source_plan))



class WipFacts(StrictModel):
    """``wip_billing.verify_wip``: the work-in-progress balance a consulting invoice draws down."""

    schema_id: Literal["lightbulb.wip_billing_facts.v1"] = Field(default=WIP_FACTS_SCHEMA, alias="schema")
    wip_ref: OpaqueRef
    status: ShortText
    state_digest: Sha256Digest
    plan_digest: Sha256Digest
    source_state: dict[str, Any]
    source_plan: dict[str, Any]


def verify_wip(wip_state: Mapping[str, Any] | Any, *, source_plan: Any = None) -> WipFacts:
    """``wip_billing.verify_wip``: the WIP state's own status travels through so the guard refuses, not the builder."""

    from lightbulb.wip_billing import verify_wip as replay
    try:
        source = replay(wip_state, source_plan=source_plan)
    except (ValueError, TypeError) as exc:
        raise JobChainError("WIP_STATE_INVALID", "retain the complete canonical WIP state and plan") from exc
    return WipFacts(wip_ref=source.scope.entity_ref, status=source.status,
        state_digest=source.state_digest, plan_digest=source.plan_digest,
        source_state=source.to_dict(), source_plan=detached(source_plan))



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
    """A provider date (``2026-10-19``) or stamp, as the ISO-8601 Z the engine keeps."""

    text = str(value)
    return timestamp(text if text.endswith("Z") else f"{text}T00:00:00Z", field_name=field_name)


class JobChainPlan(StrictModel):
    """What the chain enforces: the rail, how long each hop may take, and the authority the quote and the invoice need."""

    schema_id: str = Field(default=JOB_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    rail: Literal["square", "xero"] = "square"
    profile: Literal["local_services", "consulting"] = "local_services"
    quote_validity_days: int = Field(default=30, ge=1, le=180)
    invoice_tolerance_percent: Decimal = Field(default=Decimal("5.00"), validate_default=True)
    deposit_percent: Decimal = Field(default=Decimal("0"), validate_default=True)
    max_days_accept_to_book: int = Field(default=60, ge=1, le=365)
    max_days_book_to_complete: int = Field(default=90, ge=1, le=365)
    max_days_done_to_invoice: int = Field(default=7, ge=1, le=180)
    max_days_invoice_to_payment: int = Field(default=30, ge=1, le=365)
    require_assignment: bool = True
    require_quote_authority: bool = True
    pricing_authority_threshold_percent: Decimal = Field(default=Decimal("10"), validate_default=True)
    min_completion_evidence: int = Field(default=1, ge=0, le=20)
    #: The cost-register centre this job's materials, labour and revenue land on.
    #: Optional because ``compile_job_chain`` does not mint one; the producers
    #: that need it refuse without it rather than inventing a centre.
    centre_ref: OpaqueRef | None = None
    employment_plan_digest: Sha256Digest | None = None
    engagement_plan_digest: Sha256Digest | None = None
    wip_plan_digest: Sha256Digest | None = None
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("invoice_tolerance_percent", mode="before")
    @classmethod
    def _tolerance(cls, value: Any) -> Decimal:
        result = decimal_value(value, field_name="invoice_tolerance_percent")
        if result > Decimal("50"):
            raise ValueError("invoice_tolerance_percent must be at most 50")
        return result

    @field_validator("deposit_percent", "pricing_authority_threshold_percent", mode="before")
    @classmethod
    def _percent(cls, value: Any, info: ValidationInfo) -> Decimal:
        result = decimal_value(value, field_name=str(info.field_name))
        if result > _HUNDRED:
            raise ValueError(f"{info.field_name} must be between 0 and 100")
        return result

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> JobChainPlan:
        if not skip_digests(info) and self.plan_digest != sealed_digest(JobChainPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self

    def deposit_on(self, quote_total: Decimal) -> Decimal:
        return pct(quote_total, self.deposit_percent)


def compile_job_chain(company_ref: str, *, currency: str, rail: str = "square", profile: str = "local_services", employment_plan: Any = None, engagement_plan: Any = None, wip_plan: Any = None, overrides: Mapping[str, Any] | None = None) -> JobChainPlan:
    payload = {
        "company_ref": company_ref,
        "currency": str(currency).upper(),
        "rail": str(rail),
        "profile": str(profile),
        "employment_plan_digest": _plan_digest(employment_plan),
        "engagement_plan_digest": _plan_digest(engagement_plan),
        "wip_plan_digest": _plan_digest(wip_plan),
        **dict(overrides or {}),
    }
    return seal(JobChainPlan, {key: value for key, value in payload.items() if value is not None}, "plan_digest")


class JobReceipt(StrictModel):
    entity_scope: EngineScope | None = None
    """What one hop proves, always derived from the sealed artifact of the pack that produced it."""

    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    #: The job this receipt opens, stamped from the scope by :func:`open_job`.
    #: An :class:`AuthorizationFacts` names the entity its decision was made
    #: for, and without this the proof for one job's ``quote:1`` would
    #: authorize every other job's ``quote:1`` under the same plan.
    job_ref: OpaqueRef | None = None
    # lead
    lead_ref: OpaqueRef | None = None
    lead_source: Literal["pipeline_engine", "service_delivery", "booking_observation", "operator_input"] | None = None
    lead_digest: Sha256Digest | None = None
    customer_ref: OpaqueRef | None = None
    # quote
    quote_ref: OpaqueRef | None = None
    quote_correlation: Correlation | None = None
    quote_total: Decimal | None = None
    list_total: Decimal | None = None
    discount_percent: Decimal | None = None
    quote_status: ShortText | None = None
    quote_expiry: str | None = None
    quote_execution_digest: Sha256Digest | None = None
    quote_observation: dict[str, Any] | None = None
    #: The sealed :class:`AuthorizationFacts`.  Named ``authorization_proof`` and
    #: not ``authorization_proof`` because ``reject_secret_like_payload``
    #: refuses any key containing ``authorization`` at the boundary.
    authorization_proof: dict[str, Any] | None = None
    pricing_authorization_proof: dict[str, Any] | None = None
    # acceptance
    acceptance_digest: Sha256Digest | None = None
    #: The quote the acceptance names, carried through so the guard -- not the
    #: builder -- refuses an acceptance that belongs to another job's quote.
    acceptance_correlation_sha256: Sha256Digest | None = None
    accepted_at: str | None = None
    # booking
    booking_ref: OpaqueRef | None = None
    booking_row: dict[str, Any] | None = None
    booking_observation_digest: Sha256Digest | None = None
    start_at: str | None = None
    duration_minutes: int | None = Field(default=None, ge=1, le=10080)
    location_ref: OpaqueRef | None = None
    # assignment
    assignee_ref: OpaqueRef | None = None
    assignment_kind: Literal["worker", "agent"] | None = None
    employment_sources: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=12)
    engagement_source: dict[str, Any] | None = None
    dispatch_receipt: dict[str, Any] | None = None
    # completion
    completion_row: dict[str, Any] | None = None
    completion_signoff: dict[str, Any] | None = None
    completed_at: str | None = None
    completion_evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=20)
    # invoice
    invoice_ref: OpaqueRef | None = None
    invoice_correlation: Correlation | None = None
    invoice_total: Decimal | None = None
    invoice_execution_digest: Sha256Digest | None = None
    publish_execution_digest: Sha256Digest | None = None
    issued_at: str | None = None
    wip_source: dict[str, Any] | None = None
    # payment
    payment_observation: dict[str, Any] | None = None
    paid_amount: Decimal | None = None
    paid_at: str | None = None
    # clearance
    close_ref: OpaqueRef | None = None
    close_state_digest: Sha256Digest | None = None
    reconciliation_ref: OpaqueRef | None = None
    period_end: str | None = None
    approval_ref: OpaqueRef | None = None
    detail: BoundedText | None = None

    @model_validator(mode="before")
    @classmethod
    def _no_person(cls, value: Any) -> Any:
        """A provider row reaches the ledger hashed or not at all -- including the rows nested in it."""

        return _reject_identity(value) if isinstance(value, Mapping) else value

    @field_validator("evidence_refs", "employment_sources", "completion_evidence_refs", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("quote_total", "list_total", "discount_percent", "invoice_total", "paid_amount", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))

    @field_validator("quote_expiry", "accepted_at", "start_at", "completed_at", "issued_at", "paid_at", "period_end")
    @classmethod
    def _stamps(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))


class JobLedger(StrictModel):
    entity_scope: EngineScope | None = None
    engagement_ref: OpaqueRef | None = None
    """Derived state only: every number here came off a receipt that came off a sealed artifact."""

    job_ref: str | None = None
    lead_ref: str | None = None
    lead_source: str | None = None
    customer_ref: str | None = None
    received_at: str | None = None
    quote_ref: str | None = None
    quote_correlation: str | None = None
    quote_total: Decimal = Field(default=Decimal("0"), validate_default=True)
    list_total: Decimal = Field(default=Decimal("0"), validate_default=True)
    discount_percent: Decimal = Field(default=Decimal("0"), validate_default=True)
    quote_expiry: str | None = None
    quoted_at: str | None = None
    accepted_at: str | None = None
    booking_ref: str | None = None
    booking_id_sha256: str | None = None
    start_at: str | None = None
    duration_minutes: int | None = None
    assignee_ref: str | None = None
    assignment_kind: str | None = None
    completed_at: str | None = None
    invoice_ref: str | None = None
    invoice_correlation: str | None = None
    invoice_total: Decimal = Field(default=Decimal("0"), validate_default=True)
    issued_at: str | None = None
    paid_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    paid_at: str | None = None
    close_ref: str | None = None
    days_lead_to_cash: int | None = None
    cancel_reason: str | None = None
    reconciliation_reason: str | None = None
    outcome: Literal["open", "cleared", "cancelled", "reconciliation_required"] = "open"

    @field_validator("quote_total", "list_total", "discount_percent", "invoice_total", "paid_amount", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))


class JobEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    quote_created: Literal[False] = False
    booking_created: Literal[False] = False
    invoice_created: Literal[False] = False
    invoice_published: Literal[False] = False
    payment_collected: Literal[False] = False
    message_sent: Literal[False] = False
    provider_read: Literal[False] = False
    persistence_written: Literal[False] = False


# --------------------------------------------------------------------------- #
# Guards
# --------------------------------------------------------------------------- #


def _days(start: str | None, end: str) -> int:
    return 0 if not start else (parsed(end) - parsed(start)).days


def _amount(data: Mapping[str, Any], key: str) -> Decimal:
    return decimal_value(data.get(key, "0"), field_name=key)


def _within(value: Decimal, reference: Decimal, tolerance_percent: Decimal) -> bool:
    if reference <= 0:
        return value == reference
    return (value - reference).copy_abs() <= (reference * tolerance_percent / _HUNDRED).quantize(MONEY_QUANTUM)


def _minor(value: Any, *, field_name: str, code: str) -> Decimal:
    """Money read off a sealed provider row in minor units; never a number the caller chose."""

    try:
        return (Decimal(int(value)) / _HUNDRED).quantize(MONEY_QUANTUM)
    except (TypeError, ValueError, ArithmeticError) as exc:
        raise Rejected(code, f"{field_name} is not readable minor units: {exc}", "manual_reconciliation") from exc


def _moment(value: Any, *, field_name: str, code: str) -> Any:
    """An instant read off an unvalidated sealed projection; an unreadable one is a rejection, never a traceback."""

    try:
        return parsed(_at(value, field_name=field_name))
    except ValueError as exc:
        raise Rejected(code, f"{field_name} is not an ISO-8601 instant: {exc}", "manual_reconciliation") from exc


def _proof(r: Any, key: str) -> Mapping[str, Any] | None:
    value = getattr(r, key, None)
    return None if value is None else dict(value)


def _entity(data: Mapping[str, Any]) -> str | None:
    """The job an ``AuthorizationProof`` must have been decided for; ``None`` only for a job opened without :func:`open_job`."""

    ref = str(data.get("job_ref") or "")
    return ref or None


def _job_source_scope(source, source_plan, job_plan, ledger, at):
    source_plan = detached(source_plan)
    _require(source_plan.get("company_ref") == job_plan.company_ref and source.scope.currency == job_plan.currency,
        "SOURCE_SCOPE_MISMATCH", "source belongs to another company or currency")
    expected = detached(ledger["entity_scope"])
    _require(all(getattr(source.scope, key) == expected.get(key) for key in ("tenant_ref", "company_ref", "project_ref", "project_id", "currency")),
        "SOURCE_SCOPE_MISMATCH", "source belongs to another authenticated scope")
    _require(all(parsed(entry.command.occurred_at) <= parsed(at) for entry in source.transition_history),
        "SOURCE_FROM_FUTURE", "source history must precede its consumption")


def _apply_job(plan: JobChainPlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event, at = command.receipt, command.event, command.occurred_at
    if event == "receive_lead":
        require(r.entity_scope is not None and command.expected_state_digest == JOB_LIFECYCLE.state_digest(plan.plan_digest, r.entity_scope, ()),
            "SOURCE_SCOPE_MISMATCH", "job opening must retain its actual authenticated scope")
        data["entity_scope"] = r.entity_scope.to_dict()
        require(r.lead_ref is not None and r.lead_source is not None and r.customer_ref is not None, "LEAD_MISSING", "a lead names its reference, where it came from, and the customer commitment it is for")
        data.update({"lead_ref": r.lead_ref, "lead_source": r.lead_source, "customer_ref": r.customer_ref, "received_at": at})
        if r.job_ref is not None:
            data.update({"job_ref": r.job_ref})
    elif event == "quote":
        require(r.quote_ref is not None and r.quote_correlation is not None and r.quote_total is not None and r.quote_expiry is not None, "QUOTE_MISSING", "a quote names its provider record, its LB-JOB correlation, its total, and when it expires")
        require(r.quote_total > 0, "QUOTE_MISSING", "a quote is worth something")
        job = _entity(data)
        if plan.require_quote_authority:
            require(r.authorization_proof is not None, "QUOTE_NOT_AUTHORIZED", f"quoting {r.quote_total} {plan.currency} is a job_quote decision; a human (or their standing ceiling) makes it", "await_approval")
            require_authorization_proof(r.authorization_proof, category="job_quote", amount=r.quote_total, currency=plan.currency, command=command, plan_digest=plan.plan_digest, company_ref=plan.company_ref, engine=JOB_CHAIN_KIND, entity_ref=job)
        # the discount the receipt declares is the caller's arithmetic; when the
        # receipt also carries the list price the guard derives it and takes the
        # larger, so an understated discount cannot walk past the threshold.
        declared = r.discount_percent if r.discount_percent is not None else Decimal("0.00")
        derived = Decimal("0.00") if r.list_total is None else _discount(r.quote_total, r.list_total)
        discount = max(declared, derived)
        if discount > plan.pricing_authority_threshold_percent:
            require(r.pricing_authorization_proof is not None, "PRICING_NOT_AUTHORIZED", f"a {discount}% discount exceeds the {plan.pricing_authority_threshold_percent}% pricing threshold; a human decides it", "await_approval")
            require_authorization_proof(r.pricing_authorization_proof, proof_field="pricing_authorization_proof", category="pricing", amount=r.quote_total, currency=plan.currency, command=command, plan_digest=plan.plan_digest, company_ref=plan.company_ref, engine=JOB_CHAIN_KIND, entity_ref=job)
        require(job is None or _job_token(r.quote_correlation) == _job_token(job_correlation(job, kind="quote")), "QUOTE_CORRELATION_MISMATCH", f"{r.quote_correlation} is not this job's quote correlation", "manual_reconciliation")
        require(parsed(str(r.quote_expiry)) <= parsed(add_days(at, plan.quote_validity_days)), "QUOTE_VALIDITY_EXCEEDED", f"the quote is offered until {r.quote_expiry}; this plan holds a price for {plan.quote_validity_days} days", "correct_input")
        observation = dict(r.quote_observation or {})
        # only a provider observation is held to the provider's own facts; the
        # square rail's self-naming operator document proves the paper, not a
        # Xero quote that never existed.
        if str(observation.get("schema")) == QUOTE_OBSERVATION_SCHEMA:
            require(str(observation.get("status", "")).upper() in LIVE_QUOTE_STATUSES, "QUOTE_NOT_SENT", f"the observed quote is {observation.get('status')}; only a SENT or ACCEPTED quote is a quote")
            require(str(observation.get("quote_correlation_sha256", "")) == _sha256_utf8(str(r.quote_correlation)), "QUOTE_CORRELATION_MISMATCH", "the observed quote does not carry this job's correlation", "manual_reconciliation")
            require(str(observation.get("currency", "")).upper() == plan.currency, "QUOTE_CURRENCY_MISMATCH", f"the quote is in {observation.get('currency')}; this plan is {plan.currency}")
            observed_total = _minor(observation.get("total_minor"), field_name="total_minor", code="QUOTE_TOTAL_MISMATCH")
            require(observed_total == r.quote_total, "QUOTE_TOTAL_MISMATCH", f"the receipt claims {r.quote_total}; the observed quote is {observed_total}", "manual_reconciliation")
        require(_days(data.get("received_at"), at) >= 0, "QUOTE_MISSING", "a quote cannot precede the lead")
        data.update({"quote_ref": r.quote_ref, "quote_correlation": r.quote_correlation, "quote_total": str(r.quote_total), "list_total": str(r.list_total if r.list_total is not None else r.quote_total), "discount_percent": str(discount), "quote_expiry": r.quote_expiry, "quoted_at": at})
    elif event == "accept":
        require(r.acceptance_digest is not None and r.accepted_at is not None, "ACCEPTANCE_MISSING", "an acceptance is the customer's own act, proved by the artifact that observed it")
        # whichever artifact observed it, an acceptance that names a quote names
        # *this* job's quote; a thread the platform classified names none and is
        # fenced only by the classification it arrived with.
        require(r.acceptance_correlation_sha256 is None or r.acceptance_correlation_sha256 == _sha256_utf8(str(data.get("quote_correlation"))), "ACCEPTANCE_QUOTE_MISMATCH", "the accepted quote carries another job's correlation", "manual_reconciliation")
        require(r.quote_ref is None or str(r.quote_ref) == str(data.get("quote_ref")), "ACCEPTANCE_QUOTE_MISMATCH", f"the acceptance signs {r.quote_ref}; this job quoted {data.get('quote_ref')}", "manual_reconciliation")
        require(parsed(r.accepted_at) <= parsed(str(data.get("quote_expiry"))), "QUOTE_EXPIRED", f"the quote expired at {data.get('quote_expiry')}; re-quote before accepting", "correct_input")
        data.update({"accepted_at": r.accepted_at})
    elif event == "book":
        row = dict(r.booking_row or {})
        require(r.booking_ref is not None and r.start_at is not None and r.duration_minutes is not None and bool(row), "BOOKING_MISSING", "a booking is a square.observe_bookings row with its start and duration")
        require(str(row.get("status", "")).upper() in OPEN_BOOKING_STATUSES, "BOOKING_NOT_ACCEPTED", f"the booking is {row.get('status')}; only a pending or accepted booking books a job")
        require(parsed(r.start_at) > parsed(at), "BOOKING_IN_PAST", "a booking that already started cannot be booked")
        require(_days(data.get("accepted_at"), at) <= plan.max_days_accept_to_book, "BOOKING_TOO_LATE", f"the booking landed more than {plan.max_days_accept_to_book} days after acceptance", "manual_reconciliation")
        if str(data.get("lead_source")) == "booking_observation":
            require(str(row.get("customer_id_sha256") or "") == str(data.get("customer_ref")), "CUSTOMER_MISMATCH", "the booking belongs to a different customer than the lead it came from", "manual_reconciliation")
        data.update({"booking_ref": r.booking_ref, "booking_id_sha256": str(row.get("booking_id_sha256") or ""), "start_at": r.start_at, "duration_minutes": r.duration_minutes})
    elif event == "assign":
        require(r.assignee_ref is not None and r.assignment_kind is not None, "ASSIGNMENT_MISSING", "an assignment names who is doing the job and whether they are a worker or an agent")
        if r.assignment_kind == "worker":
            sources = [dict(item) for item in r.employment_sources]
            require(bool(sources), "ASSIGNMENT_MISSING", "a worker assignment carries the rostered employment_chain state it stands on")
            source = sources[0]
            try:
                from lightbulb.employment_chain import EMPLOYMENT_LIFECYCLE
                source_plan, proven = EMPLOYMENT_LIFECYCLE.bind(source.get("plan"), source.get("state"))
                _job_source_scope(proven, source_plan, plan, data, at)
            except (ValueError, TypeError) as exc:
                raise Rejected("EMPLOYEE_STATE_INVALID", "assignment requires the complete rostered employee in this scope", "manual_reconciliation") from exc
            worker = {**proven.ledger.to_dict(), "status": proven.status}
            require(plan.employment_plan_digest is None or str(dict(source.get("plan") or {}).get("plan_digest")) == plan.employment_plan_digest, "EMPLOYMENT_PLAN_MISMATCH", "the employee belongs to a different employment plan", "manual_reconciliation")
            require(str(worker.get("status", "")) in ROSTERED_STATUSES and str(worker.get("payroll_worker_ref") or "") == str(r.assignee_ref), "ASSIGNEE_NOT_ROSTERED", f"{r.assignee_ref} is {worker.get('status')!r}; a job is assigned to a rostered worker")
            start, end = worker.get("current_period_start"), worker.get("current_period_end")
            covers = bool(start) and bool(end) and _moment(start, field_name="current_period_start", code="ASSIGNEE_NOT_ROSTERED") <= parsed(str(data.get("start_at"))) <= _moment(end, field_name="current_period_end", code="ASSIGNEE_NOT_ROSTERED")
            require(covers, "ASSIGNEE_NOT_ROSTERED", f"the roster covers {start}..{end}; the job starts {data.get('start_at')}")
            require(not bool(worker.get("leave_open")), "ASSIGNEE_ON_LEAVE", f"{r.assignee_ref} is on recorded leave; assign somebody else", "manual_reconciliation")
        else:
            dispatch = dict(r.dispatch_receipt or {})
            require(bool(dispatch) and bool(dispatch.get("dispatch_ref")), "ASSIGNMENT_MISSING", "an agent assignment carries the workforce dispatch receipt the platform issued")
            require(bool(dispatch.get("approval_ref")), "DISPATCH_NOT_AUTHORIZED", "an agent that performs the job's writes carries the approval reference of its dispatch", "await_approval")
        if plan.profile == "consulting":
            engagement = dict(r.engagement_source or {})
            try:
                from lightbulb.engagement_engine import verify_engagement as replay
                proven = replay(engagement.get("source_state"), source_plan=engagement.get("source_plan"),
                    company_ref=plan.company_ref, currency=plan.currency, expected_scope=data["entity_scope"])
                _job_source_scope(proven, engagement["source_plan"], plan, data, at)
            except (ValueError, TypeError) as exc:
                raise Rejected("ENGAGEMENT_MISSING", "consulting requires the complete staffed engagement in this scope", "manual_reconciliation") from exc
            require(proven.status in ENGAGEMENT_STATUSES, "ENGAGEMENT_MISSING", "engagement must be staffed or delivering")
            require(plan.engagement_plan_digest is None or proven.plan_digest == plan.engagement_plan_digest, "ENGAGEMENT_PLAN_MISMATCH", "engagement must use the adopted plan")
            require(proven.ledger.customer_ref == data.get("customer_ref"), "ENGAGEMENT_CUSTOMER_MISMATCH", "the engagement must serve the job customer")
            data["engagement_ref"] = proven.scope.entity_ref

        data.update({"assignee_ref": r.assignee_ref, "assignment_kind": r.assignment_kind})
    elif event == "complete":
        require(not (status == "booked" and plan.require_assignment), "ASSIGNMENT_REQUIRED", "this plan requires a job to be assigned before it can be completed")
        row = dict(r.completion_row or {})
        signoff = dict(r.completion_signoff or {})
        require(bool(row) and bool(signoff) and r.completed_at is not None, "COMPLETION_MISSING", "a completion is a later booking row plus a human's sign-off")
        # the sign-off names a booking the caller chose; the booking this job was
        # booked on is the one the ledger holds, and only that row completes it.
        booked_on = str(data.get("booking_id_sha256") or "")
        require(not booked_on or str(row.get("booking_id_sha256") or "") == booked_on, "COMPLETION_BOOKING_MISMATCH", "the completion row is a different booking than the one this job was booked on", "manual_reconciliation")
        require(str(row.get("status", "")).upper() not in CANCELLED_BOOKING_STATUSES, "BOOKING_CANCELLED", f"the booking is {row.get('status')}; cancel the job rather than completing it")
        require(parsed(r.completed_at) >= parsed(str(data.get("start_at"))), "COMPLETED_BEFORE_START", "a job cannot be done before it started")
        elapsed_at = _moment(row.get("start_at"), field_name="start_at", code="COMPLETION_NOT_ELAPSED")
        duration = int(row.get("duration_minutes") or data.get("duration_minutes") or 0)
        observed = _moment(row.get("observed_at"), field_name="observed_at", code="COMPLETION_NOT_ELAPSED")
        require((observed - elapsed_at).total_seconds() >= duration * 60, "COMPLETION_NOT_ELAPSED", f"the booking has not elapsed at {row.get('observed_at')}; a job is done when the provider shows it ran")
        require(len(r.completion_evidence_refs) >= plan.min_completion_evidence, "COMPLETION_EVIDENCE_SHORT", f"the sign-off carries {len(r.completion_evidence_refs)} evidence refs; this plan needs {plan.min_completion_evidence}")
        require(_days(data.get("start_at"), at) <= plan.max_days_book_to_complete, "COMPLETION_TOO_LATE", f"the job completed more than {plan.max_days_book_to_complete} days after it was booked", "manual_reconciliation")
        data.update({"completed_at": r.completed_at})
    elif event == "invoice":
        require(r.invoice_ref is not None and r.invoice_correlation is not None and r.invoice_total is not None and r.issued_at is not None, "INVOICE_MISSING", "an invoice names its provider record, its correlation, its total, and when it issued")
        require(r.authorization_proof is not None, "INVOICE_NOT_AUTHORIZED", f"invoicing {r.invoice_total} {plan.currency} is a job_invoice decision; a human (or their standing ceiling) makes it", "await_approval")
        require_authorization_proof(r.authorization_proof, category="job_invoice", amount=r.invoice_total, currency=plan.currency, command=command, plan_digest=plan.plan_digest, company_ref=plan.company_ref, engine=JOB_CHAIN_KIND, entity_ref=_entity(data))
        quoted = _amount(data, "quote_total")
        expected = (quoted - plan.deposit_on(quoted)).quantize(MONEY_QUANTUM)
        require(_within(r.invoice_total, expected, plan.invoice_tolerance_percent), "INVOICE_NOT_QUOTED_VALUE", f"invoice total {r.invoice_total} differs from the quoted value less deposit {expected} by more than {plan.invoice_tolerance_percent}%", "manual_reconciliation")
        require(_job_token(r.invoice_correlation) == _job_token(data.get("quote_correlation")), "INVOICE_CORRELATION_MISMATCH", "the invoice correlation belongs to a different job than the quote", "manual_reconciliation")
        require(plan.rail != "square" or r.publish_execution_digest is not None, "INVOICE_NOT_PUBLISHED", "a Square invoice is only owed once it is published; bind the square.publish_invoice execution")
        if plan.profile == "consulting":
            wip = dict(r.wip_source or {})
            try:
                from lightbulb.wip_billing import verify_wip as replay
                proven = replay(wip.get("source_state"), source_plan=wip.get("source_plan"))
                _job_source_scope(proven, wip["source_plan"], plan, data, at)
            except (ValueError, TypeError) as exc:
                raise Rejected("WIP_NOT_INVOICED", "consulting requires the complete invoiced WIP in this scope", "manual_reconciliation") from exc
            require(proven.status == "invoiced", "WIP_NOT_INVOICED", "WIP must prove observed invoice issuance")
            require(plan.wip_plan_digest is None or proven.plan_digest == plan.wip_plan_digest, "WIP_PLAN_MISMATCH", "WIP must use the adopted plan")
            require(proven.ledger.engagement_ref == data.get("engagement_ref") and proven.ledger.customer_ref == data.get("customer_ref")
                and proven.ledger.invoice_total == r.invoice_total and proven.ledger.invoice_ref == r.invoice_ref,
                "WIP_INVOICE_MISMATCH", "the WIP must prove this engagement, customer and exact invoice")

        require(_days(data.get("completed_at"), at) <= plan.max_days_done_to_invoice, "INVOICE_TOO_LATE", f"the invoice issued more than {plan.max_days_done_to_invoice} days after the job was done", "manual_reconciliation")
        data.update({"invoice_ref": r.invoice_ref, "invoice_correlation": r.invoice_correlation, "invoice_total": str(r.invoice_total), "issued_at": r.issued_at})
    elif event == "apply_payment":
        require(r.paid_amount is not None and r.paid_at is not None and r.invoice_correlation is not None, "PAYMENT_MISSING", "a payment names its amount, when it landed, and the invoice correlation it settles")
        require(str(r.invoice_correlation) == str(data.get("invoice_correlation")), "PAYMENT_CORRELATION_MISMATCH", "the payment does not carry this invoice's correlation", "manual_reconciliation")
        observation = dict(r.payment_observation or {})
        # a payment whose observation never named a currency is not proof that
        # this plan's currency landed, so the check is never opt-in.
        require(bool(observation.get("currency")), "PAYMENT_CURRENCY_MISMATCH", "the payment observation does not name the currency it settled in", "manual_reconciliation")
        require(str(observation["currency"]).upper() == plan.currency, "PAYMENT_CURRENCY_MISMATCH", f"the payment is in {observation.get('currency')}; this plan is {plan.currency}")
        require(r.paid_amount == _amount(data, "invoice_total"), "PAYMENT_NOT_FULL", f"paid {r.paid_amount} does not settle the invoice total {data.get('invoice_total')}", "manual_reconciliation")
        require(parsed(r.paid_at) >= parsed(str(data.get("issued_at"))), "PAYMENT_BEFORE_INVOICE", "a payment cannot precede the invoice it settles", "manual_reconciliation")
        require(_days(data.get("issued_at"), at) <= plan.max_days_invoice_to_payment, "PAYMENT_TOO_LATE", f"payment landed more than {plan.max_days_invoice_to_payment} days after the invoice", "manual_reconciliation")
        data.update({"paid_amount": str(r.paid_amount), "paid_at": r.paid_at, "days_lead_to_cash": _days(data.get("received_at"), r.paid_at)})
    elif event == "reconcile":
        require(r.close_ref is not None and r.close_state_digest is not None and r.reconciliation_ref is not None and r.period_end is not None, "CLEARANCE_MISSING", "a clearance names the close, its state digest, the receivables reconciliation, and the period end")
        require(parsed(r.period_end) >= parsed(str(data.get("paid_at"))), "CLOSE_BEFORE_PAYMENT", "the close must cover the date the job's cash landed", "manual_reconciliation")
        data.update({"close_ref": r.close_ref, "outcome": "cleared"})
    elif event == "cancel":
        data.update({"cancel_reason": str(command.reason)[:300], "outcome": "cancelled"})
    elif event == "require_reconciliation":
        data.update({"reconciliation_reason": str(command.reason)[:300], "outcome": "reconciliation_required"})
    return next_status, data


JOB_LIFECYCLE = LifecycleSpec(
    entity="job",
    schema_prefix=JOB_CHAIN_KIND,
    statuses=JOB_STATUSES,
    terminal=TERMINAL_JOB_STATUSES,
    events=JOB_EVENTS,
    table=_JOB_TABLE,
    opening_event="receive_lead",
    reason_events=("cancel", "require_reconciliation"),
    apply=_apply_job,
    ledger_model=JobLedger,
    receipt_model=JobReceipt,
    effect_boundary_model=JobEffectBoundary,
    plan_model=JobChainPlan,
    max_transitions=MAX_JOB_TRANSITIONS,
)
JobState = JOB_LIFECYCLE.State


def open_job(plan: JobChainPlan | Mapping[str, Any], scope: Mapping[str, Any], *, receipt: Mapping[str, Any], opened_at: str, actor_ref: str) -> Any:
    """Open the job; the scope currency is the plan's, so every amount the ledger holds is one currency."""

    parsed_plan = JobChainPlan.model_validate(detached(plan))
    raw_scope = dict(detached(scope))
    currency = str(raw_scope.get("currency", ""))
    _require(currency == parsed_plan.currency, "JOB_CURRENCY_MISMATCH", f"the job is scoped to {currency!r}; the plan quotes and invoices in {parsed_plan.currency}")
    # the opening receipt carries the job the scope names, so every later
    # authority proof is fenced to *this* job and not merely to a transition
    # reference two jobs could share.
    entity_ref = raw_scope.get("entity_ref")
    opening = {**dict(detached(receipt)), "entity_scope": raw_scope}
    if entity_ref is not None:
        opening["job_ref"] = str(entity_ref)
    return JOB_LIFECYCLE.open(parsed_plan, scope, opened_at=opened_at, actor_ref=actor_ref, receipt=opening)


def advance_job(plan: JobChainPlan | Mapping[str, Any], state: Any, command: Any) -> Any:
    return JOB_LIFECYCLE.advance(plan, state, command)


# --------------------------------------------------------------------------- #
# Receipts from the hops' sealed artifacts
# --------------------------------------------------------------------------- #


def _provenance(provenance: Mapping[str, Any] | Any, *, tools: frozenset[str] | set[str], code: str) -> dict[str, Any]:
    raw = dict(detached(provenance))
    _require(str(raw.get("source_tool", "")) in tools, code, f"expected a read from {sorted(tools)}, got {raw.get('source_tool')!r}")
    _require(str(raw.get("lane", "")) in _READ_LANES, code, f"a {raw.get('source_tool')} read arrives on {_READ_LANES}, not {raw.get('lane')!r}")
    for key in ("observation_ref", "provenance_digest", "output_digest", "completed_at"):
        _require(bool(raw.get(key)), code, f"the provenance lacks {key}")
    return raw


def _execution(receipt: ExecutionReceipt | Mapping[str, Any], *, tool: str, code: str) -> ExecutionReceipt:
    parsed_receipt = receipt if isinstance(receipt, ExecutionReceipt) else ExecutionReceipt.model_validate(dict(detached(receipt)))
    _require(parsed_receipt.tool == tool, code, f"expected a {tool} execution receipt, got {parsed_receipt.tool}")
    _require(parsed_receipt.effect == "write", code, f"{tool} is a write; the receipt proves a {parsed_receipt.effect}")
    _require(parsed_receipt.approval_ref is not None, code, f"a {tool} write carries the approval it was authorized by")
    return parsed_receipt


def _record_ref(receipt: ExecutionReceipt, output: Mapping[str, Any] | None, *, code: str) -> str | None:
    """The provider record the write created, bound by the output digest the receipt sealed."""

    if output is None:
        return None
    raw = dict(detached(output))
    _require(stable_digest(raw) == receipt.output_digest, code, "the connector output is not the output this execution receipt sealed")
    ref = raw.get("provider_record_ref") or raw.get("providerRecordRef")
    _require(bool(ref), code, "the connector output carries no provider_record_ref")
    return str(ref)


def lead_receipt(prospect_state: Mapping[str, Any] | Any, pipeline_plan: PipelineEngineLoopPlan | Mapping[str, Any]) -> dict[str, Any]:
    """The opening receipt from a handed-off ``pipeline_engine`` prospect."""

    _, state = PROSPECT_LIFECYCLE.bind(pipeline_plan, prospect_state)
    _require(state.status == "handed_off" and state.ledger.deal_ref is not None, "PROSPECT_NOT_HANDED_OFF", f"prospect {state.scope.entity_ref} is {state.status}")
    return {
        "lead_ref": f"lead:{state.scope.entity_ref}",
        "lead_source": "pipeline_engine",
        "lead_digest": state.state_digest,
        "customer_ref": str(state.ledger.deal_ref),
        "evidence_refs": [f"prospect:{state.scope.entity_ref}", f"state:{state.state_digest[:24]}"],
    }


def case_lead_receipt(case_state: Mapping[str, Any] | Any, service_delivery_plan: ServiceDeliveryLoopPlan | Mapping[str, Any]) -> dict[str, Any]:
    """The opening receipt from a ``service_delivery`` case: aftercare that turned into billable work."""

    # A closed case is a perfectly good lead -- aftercare that turned into
    # billable work is the whole point -- so the only thing to refuse is a case
    # whose customer never made it across ``CaseLedger.customer_ref`` (declared
    # optional there), which would otherwise post the string "None".
    _, state = CASE_LIFECYCLE.bind(service_delivery_plan, case_state)
    _require(state.ledger.customer_ref is not None, "CASE_CUSTOMER_MISSING", f"case {state.scope.entity_ref} names no customer")
    return {
        "lead_ref": f"lead:case:{state.scope.entity_ref}",
        "lead_source": "service_delivery",
        "lead_digest": state.state_digest,
        "customer_ref": str(state.ledger.customer_ref),
        "evidence_refs": [f"case:{state.scope.entity_ref}", f"state:{state.state_digest[:24]}"],
    }


def booking_page_rows(page: Mapping[str, Any] | Any) -> tuple[list[dict[str, Any]], str]:
    """The rows of a ``square.observe_bookings`` page and the instant the page was observed."""

    raw = dict(detached(page))
    _require(str(raw.get("schema")) == BOOKING_PAGE_SCHEMA, "BOOKING_PAGE_SCHEMA_MISMATCH", f"expected a {BOOKING_PAGE_SCHEMA}")
    _require(bool(raw.get("observed_at")), "BOOKING_PAGE_INCOMPLETE", "a bookings page names when it was observed")
    rows = [dict(item) for item in (raw.get("bookings") or [])]
    _require(bool(rows), "BOOKING_ROW_MISSING", "the bookings page carries no bookings")
    return rows, _at(raw["observed_at"], field_name="observed_at")


def booking_ref_of(row: Mapping[str, Any]) -> str:
    digest = str(dict(row).get("booking_id_sha256", ""))
    _require(bool(_HEX64.match(digest)), "BOOKING_ID_NOT_HASHED", "a booking reaches the SDK only as a 64-hex sha256")
    return f"booking:{digest[:24]}"


def _select_booking(source: Mapping[str, Any] | Any, booking_ref: str | None) -> tuple[dict[str, Any], str | None]:
    raw = _reject_identity(dict(detached(source)), path="booking")
    if str(raw.get("schema")) == BOOKING_PAGE_SCHEMA:
        rows, observed_at = booking_page_rows(raw)
        if booking_ref is not None:
            rows = [row for row in rows if booking_ref_of(row) == booking_ref]
        _require(len(rows) == 1, "BOOKING_ROW_MISSING", f"the bookings page carries {len(rows)} rows for {booking_ref or 'this job'}; exactly one is required")
        return rows[0], observed_at
    _require(bool(raw.get("booking_id_sha256")), "BOOKING_ROW_MISSING", "expected a bookings page or one of its rows")
    return raw, None


def booking_lead_receipt(booking_page_row: Mapping[str, Any] | Any, *, booking_ref: str | None = None) -> dict[str, Any]:
    """The opening receipt for a walk-in: the customer booked before anybody quoted them."""

    row, _ = _select_booking(booking_page_row, booking_ref)
    customer = str(row.get("customer_id_sha256") or "")
    _require(bool(_HEX64.match(customer)), "BOOKING_CUSTOMER_MISSING", "a booking-sourced lead needs the booking's hashed customer")
    ref = booking_ref_of(row)
    return {
        "lead_ref": f"lead:{ref}",
        "lead_source": "booking_observation",
        "lead_digest": stable_digest(row),
        "customer_ref": customer,
        "evidence_refs": [ref],
    }


def lead_input(*, lead_ref: str, customer_ref: str, requested_service: str) -> dict[str, Any]:
    """A lead an operator typed -- the phone rang.  It names itself as operator-supplied; nothing pretends it was observed."""

    payload = {"schema": JOB_LEAD_INTAKE_SCHEMA, "operator_supplied": True, "lead_ref": str(lead_ref), "customer_ref": str(customer_ref), "requested_service": str(requested_service)[:300]}
    return {
        "lead_ref": str(lead_ref),
        "lead_source": "operator_input",
        "lead_digest": stable_digest(payload),
        "customer_ref": str(customer_ref),
        "evidence_refs": [f"intake:{stable_digest(payload)[:24]}"],
    }


def _authority(proof: AuthorizationProof | Mapping[str, Any] | None, *, key: str) -> dict[str, Any]:
    if proof is None:
        return {"evidence_refs": []}
    evidence = authorization_evidence(proof)
    return {key: evidence["authorization_proof"], "evidence_refs": list(evidence["evidence_refs"])}


def quote_receipt(
    execution_receipt: ExecutionReceipt | Mapping[str, Any],
    quote_observation: Mapping[str, Any] | Any,
    *,
    correlation: str,
    output: Mapping[str, Any] | None = None,
    authorization_proof: AuthorizationProof | Mapping[str, Any] | None = None,
    pricing_proof: AuthorizationProof | Mapping[str, Any] | None = None,
    list_total: Any = None,
) -> dict[str, Any]:
    """From the ``xero.create_quote`` write receipt plus the ``xero.observe_quote`` observation that carries its correlation.

    The execution receipt seals its connector output as a digest and not as a
    body, so ``output`` (the connector result's own output, checked against
    that digest) supplies the ``provider_record_ref``; without it the quote
    reference is the observation's hashed quote id, which is equally sealed.
    """

    write = _execution(execution_receipt, tool=QUOTE_WRITE_TOOLS["xero"], code="QUOTE_WRITE_INVALID")
    observed = dict(detached(quote_observation))
    _require(str(observed.get("schema")) == QUOTE_OBSERVATION_SCHEMA, "QUOTE_OBSERVATION_SCHEMA_MISMATCH", f"expected a {QUOTE_OBSERVATION_SCHEMA}")
    _require(str(observed.get("disposition")) == "FOUND", "QUOTE_NOT_FOUND", f"the quote observation is {observed.get('disposition')}")
    _require(str(observed.get("status", "")).upper() in LIVE_QUOTE_STATUSES, "QUOTE_NOT_SENT", f"the observed quote is {observed.get('status')}")
    _require(str(observed.get("quote_correlation_sha256", "")) == _sha256_utf8(correlation), "QUOTE_CORRELATION_MISMATCH", "the observed quote does not carry this correlation")
    total = (Decimal(int(observed["total_minor"])) / _HUNDRED).quantize(MONEY_QUANTUM)
    record_ref = _record_ref(write, output, code="QUOTE_WRITE_INVALID") or f"quote:{str(observed['quote_id_sha256'])[:24]}"
    evidence = _authority(authorization_proof, key="authorization_proof")
    pricing = _authority(pricing_proof, key="pricing_authorization_proof")
    return {
        **{key: value for key, value in evidence.items() if key != "evidence_refs"},
        **{key: value for key, value in pricing.items() if key != "evidence_refs"},
        "quote_ref": record_ref,
        "quote_correlation": correlation,
        "quote_total": str(total),
        "list_total": None if list_total is None else str(decimal_value(list_total, field_name="list_total")),
        "discount_percent": None if list_total is None else str(_discount(total, decimal_value(list_total, field_name="list_total"))),
        "quote_status": str(observed["status"]),
        "quote_expiry": _at(observed["expiry_date"], field_name="quote_expiry"),
        "quote_execution_digest": write.execution_digest,
        "quote_observation": {key: observed[key] for key in ("schema", "status", "currency", "total_minor", "quote_correlation_sha256", "quote_id_sha256", "evidence_sha256", "observed_at", "expiry_date") if key in observed},
        "evidence_refs": [f"quote:{write.journal_ref}", f"observation:{str(observed['evidence_sha256'])[:24]}", *evidence["evidence_refs"], *pricing["evidence_refs"]],
    }


def _discount(quote_total: Decimal, list_total: Decimal) -> Decimal:
    if list_total <= 0:
        return Decimal("0.00")
    return (((list_total - quote_total) * _HUNDRED) / list_total).quantize(MONEY_QUANTUM)


def quote_input(
    *,
    quote_ref: str,
    quote_total: Any,
    expiry: str,
    document_sha256: str,
    correlation: str,
    authorization_proof: AuthorizationProof | Mapping[str, Any] | None = None,
    pricing_proof: AuthorizationProof | Mapping[str, Any] | None = None,
    list_total: Any = None,
) -> dict[str, Any]:
    """The Square rail's quote: Square has no quotes API, so the quote is an operator-supplied document that names itself.

    The authority is not waived: the job still needs a ``job_quote`` proof
    before it may be quoted, and the document digest is what a later dispute
    is argued from.
    """

    _require(bool(_HEX64.match(str(document_sha256))), "QUOTE_DOCUMENT_UNHASHED", "the quote document is named by its 64-hex sha256")
    total = decimal_value(quote_total, field_name="quote_total")
    listed = None if list_total is None else decimal_value(list_total, field_name="list_total")
    payload = {"schema": JOB_QUOTE_INPUT_SCHEMA, "operator_supplied": True, "quote_ref": str(quote_ref), "quote_total": str(total), "expiry": _at(expiry, field_name="quote_expiry"), "document_sha256": str(document_sha256), "quote_correlation": str(correlation)}
    evidence = _authority(authorization_proof, key="authorization_proof")
    pricing = _authority(pricing_proof, key="pricing_authorization_proof")
    return {
        **{key: value for key, value in evidence.items() if key != "evidence_refs"},
        **{key: value for key, value in pricing.items() if key != "evidence_refs"},
        "quote_ref": str(quote_ref),
        "quote_correlation": str(correlation),
        "quote_total": str(total),
        "list_total": None if listed is None else str(listed),
        "discount_percent": None if listed is None else str(_discount(total, listed)),
        "quote_status": "OPERATOR_DOCUMENT",
        "quote_expiry": payload["expiry"],
        "quote_observation": payload,
        "evidence_refs": [f"quote_document:{str(document_sha256)[:24]}", *evidence["evidence_refs"], *pricing["evidence_refs"]],
    }


def acceptance_input(*, quote_ref: str, accepted_at: str, document_sha256: str, signed_by_ref: str) -> dict[str, Any]:
    """The customer signed the quote: a self-naming operator input carrying the signed document's digest."""

    _require(bool(_HEX64.match(str(document_sha256))), "ACCEPTANCE_DOCUMENT_UNHASHED", "the signed quote is named by its 64-hex sha256")
    return {"schema": JOB_ACCEPTANCE_SCHEMA, "operator_supplied": True, "quote_ref": str(quote_ref), "accepted_at": timestamp(accepted_at, field_name="accepted_at"), "document_sha256": str(document_sha256), "signed_by_ref": str(signed_by_ref)}


def accept_receipt(source: Mapping[str, Any] | Any) -> dict[str, Any]:
    """The customer's acceptance, from whichever artifact observed it.

    An ACCEPTED ``xero.observe_quote`` observation, an inbound thread the
    platform classified ``accepted`` (the ``EngineObservation`` that
    ``company_execution_bridge.gmail_thread_to_pipeline_event`` seals), or the
    self-naming :func:`acceptance_input` carrying the signed quote's digest.
    Acceptance is never assumed from silence.
    """

    raw = dict(detached(source))
    schema = str(raw.get("schema", ""))
    if schema == QUOTE_OBSERVATION_SCHEMA:
        _require(str(raw.get("disposition")) == "FOUND", "QUOTE_NOT_FOUND", f"the quote observation is {raw.get('disposition')}; a quote nobody found accepted nothing")
        _require(str(raw.get("status", "")).upper() == "ACCEPTED", "ACCEPTANCE_MISSING", f"the observed quote is {raw.get('status')}, not ACCEPTED")
        when = raw.get("updated_at") or raw.get("observed_at")
        return {"acceptance_digest": str(raw["evidence_sha256"]), "acceptance_correlation_sha256": str(raw["quote_correlation_sha256"]), "accepted_at": _at(when, field_name="accepted_at"), "evidence_refs": [f"quote_observation:{str(raw['evidence_sha256'])[:24]}"]}
    if schema == JOB_ACCEPTANCE_SCHEMA:
        return {"acceptance_digest": stable_digest(raw), "quote_ref": str(raw["quote_ref"]), "accepted_at": timestamp(str(raw["accepted_at"]), field_name="accepted_at"), "evidence_refs": [f"acceptance:{str(raw['document_sha256'])[:24]}"]}
    if schema == "lightbulb.engine_observation.v1":
        _require(str(raw.get("source_tool")) in ACCEPTANCE_THREAD_TOOLS, "ACCEPTANCE_SOURCE_MISMATCH", f"a thread acceptance comes from {sorted(ACCEPTANCE_THREAD_TOOLS)}, not {raw.get('source_tool')!r}")
        fields = dict(raw.get("receipt_fields") or {})
        _require(str(fields.get("disposition")) == "accepted", "ACCEPTANCE_MISSING", f"the thread was classified {fields.get('disposition')!r}, not 'accepted'")
        _require(bool(fields.get("engagement_ref")), "ACCEPTANCE_UNCLASSIFIED", "a classified reply names the classification reference it was decided by")
        return {"acceptance_digest": str(raw["observation_digest"]), "accepted_at": timestamp(str(raw["observed_through"]), field_name="accepted_at"), "evidence_refs": [f"thread:{str(fields['reply_ref'])[:60]}", f"classification:{str(fields['engagement_ref'])[:60]}"]}
    raise JobChainError("ACCEPTANCE_SCHEMA_MISMATCH", f"an acceptance is a quote observation, a classified thread observation, or a signed quote input; got {schema!r}")


def book_receipt(booking_page_row: Mapping[str, Any] | Any, *, booking_ref: str | None = None) -> dict[str, Any]:
    """From a ``square.observe_bookings`` row: the provider showed the booking, so the job is booked."""

    row, _ = _select_booking(booking_page_row, booking_ref)
    for key in ("status", "start_at", "duration_minutes"):
        _require(row.get(key) is not None, "BOOKING_INCOMPLETE", f"the booking row lacks {key}")
    ref = booking_ref_of(row)
    return {
        "booking_ref": ref,
        "booking_row": row,
        "booking_observation_digest": stable_digest(row),
        "start_at": _at(row["start_at"], field_name="start_at"),
        "duration_minutes": int(row["duration_minutes"]),
        "location_ref": None if not row.get("location_id_sha256") else f"location:{str(row['location_id_sha256'])[:24]}",
        "evidence_refs": [ref, f"booking_row:{stable_digest(row)[:24]}"],
    }


def assign_receipt(employee_state: Mapping[str, Any] | Any, *, employment_plan: Any = None) -> dict[str, Any]:
    """From a rostered ``employment_chain`` state: only the derived facts the guard re-checks cross over."""

    from lightbulb.employment_chain import EMPLOYMENT_LIFECYCLE
    try:
        _, source = EMPLOYMENT_LIFECYCLE.bind(employment_plan, employee_state)
    except (ValueError, TypeError) as exc:
        raise JobChainError("EMPLOYEE_STATE_INVALID", "assignment retains the complete employment state and plan") from exc
    raw, ledger = source.to_dict(), source.ledger.to_dict()
    worker = str(ledger.get("payroll_worker_ref") or "")
    _require(bool(worker), "EMPLOYEE_NOT_HIRED", f"the employee is {raw.get('status')!r}; a job is assigned to a hired worker")
    facts = {key: ledger.get(key) for key in ("payroll_worker_ref", "worker_ref", "current_period_start", "current_period_end", "leave_open") if ledger.get(key) is not None}
    facts.update({"status": str(raw.get("status")), "state_digest": str(raw["state_digest"])})
    return {
        "assignee_ref": worker,
        "assignment_kind": "worker",
        "employment_sources": [{"state": raw, "plan": detached(employment_plan)}],
        "evidence_refs": [f"employee:{worker}", f"state:{str(raw['state_digest'])[:24]}"],
    }


def assign_dispatch_receipt(dispatch_receipt: Mapping[str, Any] | Any) -> dict[str, Any]:
    """From a ``company_workforce`` dispatch receipt: an agent does the job, under the approval its dispatch carried."""

    raw = dict(detached(dispatch_receipt))
    for key in ("worker_ref", "dispatch_ref"):
        _require(bool(raw.get(key)), "DISPATCH_INCOMPLETE", f"the dispatch receipt lacks {key}")
    kept = {key: raw[key] for key in ("worker_ref", "dispatch_ref", "period_ref", "action", "approval_ref", "evidence_ref") if raw.get(key) is not None}
    return {"assignee_ref": str(raw["worker_ref"]), "assignment_kind": "agent", "dispatch_receipt": kept, "approval_ref": raw.get("approval_ref"), "evidence_refs": [str(raw["dispatch_ref"])[:200]]}


def assign_engagement_receipt(engagement_state: Mapping[str, Any] | Any, *, engagement_plan: Any = None) -> dict[str, Any]:
    """From an ``engagement_engine`` state; a consulting job is only assigned under a staffed engagement."""

    facts = verify_engagement(engagement_state, source_plan=engagement_plan)
    return {"engagement_source": facts.to_dict(), "evidence_refs": [f"engagement:{facts.engagement_ref}", f"state:{facts.state_digest[:24]}"]}


def completion_signoff(*, booking_ref: str, completed_at: str, signed_by_ref: str, evidence_sha256s: Sequence[str]) -> dict[str, Any]:
    """A human attests the job is done: the self-naming sign-off, with the photo/report digests it stands on."""

    digests = [str(item) for item in evidence_sha256s]
    for digest in digests:
        _require(bool(_HEX64.match(digest)), "SIGNOFF_EVIDENCE_UNHASHED", "sign-off evidence is named by its 64-hex sha256")
    return {"schema": JOB_COMPLETION_SIGNOFF_SCHEMA, "operator_supplied": True, "booking_ref": str(booking_ref), "completed_at": timestamp(completed_at, field_name="completed_at"), "signed_by_ref": str(signed_by_ref), "evidence_sha256s": digests}


def complete_receipt(booking_page_row: Mapping[str, Any] | Any, signoff: Mapping[str, Any] | Any, *, booking_ref: str | None = None) -> dict[str, Any]:
    """From a later ``square.observe_bookings`` row for the same booking plus the human sign-off that closed it out."""

    raw_signoff = dict(detached(signoff))
    _require(str(raw_signoff.get("schema")) == JOB_COMPLETION_SIGNOFF_SCHEMA, "SIGNOFF_SCHEMA_MISMATCH", f"a completion sign-off names itself {JOB_COMPLETION_SIGNOFF_SCHEMA}")
    for key in ("booking_ref", "completed_at", "signed_by_ref"):
        _require(bool(raw_signoff.get(key)), "SIGNOFF_INCOMPLETE", f"the sign-off lacks {key}")
    row, observed_at = _select_booking(booking_page_row, booking_ref or str(raw_signoff["booking_ref"]))
    _require(booking_ref_of(row) == str(raw_signoff["booking_ref"]), "SIGNOFF_BOOKING_MISMATCH", "the sign-off names a different booking than the row it came with")
    when = observed_at or row.get("observed_at")
    _require(bool(when), "COMPLETION_ROW_UNOBSERVED", "the completion row must come from an observed bookings page")
    return {
        "completion_row": {**row, "observed_at": _at(when, field_name="observed_at")},
        "completion_signoff": raw_signoff,
        "completed_at": timestamp(str(raw_signoff["completed_at"]), field_name="completed_at"),
        "completion_evidence_refs": [f"signoff_evidence:{digest[:24]}" for digest in (raw_signoff.get("evidence_sha256s") or [])],
        "evidence_refs": [f"completion:{stable_digest(row)[:24]}", f"signoff:{stable_digest(raw_signoff)[:24]}"],
    }


def job_invoice_request(state: Any, *, plan: JobChainPlan | Mapping[str, Any], due_date: str, order_ref: str | None = None, location_ref: str | None = None, connector_account_ref: str | None = None) -> tuple[Any, ...]:
    """The closed connector bodies the platform would execute to invoice this job.  Preview only; nothing is sent.

    Square invoices are drawn on an existing Order -- the one the technician
    creates at the point of sale -- so ``order_ref`` is required on that rail
    and its absence is a named platform gap, not a body the SDK may invent.
    The amount is the quoted value less the plan's deposit; it is never a
    number the caller passes in.
    """

    from lightbulb.connector_execution import ConnectorEffect, ConnectorExecutionRequest, ExecutionScope

    parsed_plan = JobChainPlan.model_validate(detached(plan))
    parsed_state = _bound(state, parsed_plan)
    ledger = parsed_state.ledger
    _require(ledger.quote_total > 0, "INVOICE_REQUEST_UNQUOTED", "a job is invoiced for its quoted value; quote it first")
    _require(ledger.customer_ref is not None, "INVOICE_REQUEST_UNADDRESSED", "a job is invoiced to the customer its lead named")
    amount = (ledger.quote_total - parsed_plan.deposit_on(ledger.quote_total)).quantize(MONEY_QUANTUM)
    correlation = job_correlation(str(parsed_state.scope.entity_ref), kind="invoice")
    scope = ExecutionScope(tenant_ref=parsed_state.scope.tenant_ref, company_ref=parsed_state.scope.company_ref, project_ref=parsed_state.scope.project_ref, project_id=parsed_state.scope.project_id)
    if parsed_plan.rail == "square":
        _require(order_ref is not None, "SQUARE_ORDER_MISSING", "Square invoices are drawn on an existing Order the technician creates at the POS; no Order, no invoice")
        _require(location_ref is not None, "SQUARE_LOCATION_MISSING", "a Square invoice names the location its Order belongs to")
        create = ConnectorExecutionRequest(
            tool=INVOICE_WRITE_TOOLS["square"],
            arguments={
                "location_id": str(location_ref),
                "order_id": str(order_ref),
                "primary_recipient": {"customer_id": str(ledger.customer_ref)},
                "invoice_number": correlation,
                "payment_requests": [{"request_type": "BALANCE", "due_date": str(due_date)}],
                "delivery_method": "EMAIL",
            },
            scope=scope,
            connector_account_ref=connector_account_ref,
            effect=ConnectorEffect.WRITE,
            approval_required=True,
            preview_only=True,
            idempotency_key=f"{correlation}:create",
        )
        # the invoice id is the create's own output; the publish body is closed
        # around this job's correlation and carries nothing else.
        publish = ConnectorExecutionRequest(
            tool=PUBLISH_TOOL,
            arguments={"invoice_id": None, "correlation_ref": correlation},
            scope=scope,
            connector_account_ref=connector_account_ref,
            effect=ConnectorEffect.WRITE,
            approval_required=True,
            preview_only=True,
            idempotency_key=f"{correlation}:publish",
        )
        return (create, publish)
    create = ConnectorExecutionRequest(
        tool=INVOICE_WRITE_TOOLS["xero"],
        arguments={"customer_id": str(ledger.customer_ref), "amount": str(amount), "currency": parsed_plan.currency, "due_date": str(due_date), "reference": correlation, "line_items": [{"description": f"Job {parsed_state.scope.entity_ref}", "quantity": 1, "unit_amount": str(amount)}]},
        scope=scope,
        connector_account_ref=connector_account_ref,
        effect=ConnectorEffect.WRITE,
        approval_required=True,
        preview_only=True,
        idempotency_key=f"{correlation}:create",
    )
    return (create,)


def invoice_receipt(
    execution_receipt: ExecutionReceipt | Mapping[str, Any],
    *,
    invoice_total: Any,
    correlation: str,
    authorization_proof: AuthorizationProof | Mapping[str, Any] | None = None,
    output: Mapping[str, Any] | None = None,
    publish_receipt: ExecutionReceipt | Mapping[str, Any] | None = None,
    wip_state: Mapping[str, Any] | Any = None,
    wip_plan: Any = None,
) -> dict[str, Any]:
    """From the ``square.create_invoice`` (+ ``square.publish_invoice``) or ``xero.create_invoice`` write receipts."""

    parsed_receipt = execution_receipt if isinstance(execution_receipt, ExecutionReceipt) else ExecutionReceipt.model_validate(dict(detached(execution_receipt)))
    tool = parsed_receipt.tool
    _require(tool in set(INVOICE_WRITE_TOOLS.values()), "INVOICE_WRITE_INVALID", f"expected one of {sorted(set(INVOICE_WRITE_TOOLS.values()))}, got {tool}")
    write = _execution(parsed_receipt, tool=tool, code="INVOICE_WRITE_INVALID")
    publish = None
    if publish_receipt is not None:
        publish = _execution(publish_receipt, tool=PUBLISH_TOOL, code="INVOICE_PUBLISH_INVALID")
    record_ref = _record_ref(write, output, code="INVOICE_WRITE_INVALID") or f"invoice:{write.journal_ref}"
    evidence = _authority(authorization_proof, key="authorization_proof")
    receipt: dict[str, Any] = {
        **{key: value for key, value in evidence.items() if key != "evidence_refs"},
        "invoice_ref": record_ref,
        "invoice_correlation": str(correlation),
        "invoice_total": str(decimal_value(invoice_total, field_name="invoice_total")),
        "invoice_execution_digest": write.execution_digest,
        "publish_execution_digest": None if publish is None else publish.execution_digest,
        "issued_at": write.completed_at,
        "evidence_refs": [f"invoice:{write.journal_ref}", *([f"publish:{publish.journal_ref}"] if publish is not None else []), *evidence["evidence_refs"]],
    }
    if wip_state is not None:
        facts = verify_wip(wip_state, source_plan=wip_plan)
        receipt["wip_source"] = facts.to_dict()
        receipt["evidence_refs"] = [*receipt["evidence_refs"], f"wip:{facts.wip_ref}"]
    return receipt


def payment_receipt(source: Mapping[str, Any] | Any, *, correlation: str, invoice_ref: str | None = None, provenance: ObservationProvenance | Mapping[str, Any] | None = None, currency: str | None = None) -> dict[str, Any]:
    """From the ``square.observe_invoice_payment`` PAID observation, or a row of the governed ``xero.list_payments`` page."""

    raw = dict(detached(source))
    if str(raw.get("schema")) == SQUARE_PAYMENT_OBSERVATION_SCHEMA:
        _require(str(raw.get("disposition")) == "PAID" and str(raw.get("invoice_status")) == "PAID", "PAYMENT_NOT_PAID", f"the invoice observation is {raw.get('disposition')}")
        _require(str(raw.get("invoice_correlation_sha256", "")) == _sha256_utf8(correlation), "PAYMENT_CORRELATION_MISMATCH", "the payment observation does not carry this invoice's correlation")
        _require(int(raw.get("amount_due_minor", 0)) == 0, "INVOICE_BALANCE_OPEN", "the invoice still carries a balance")
        amount = (Decimal(int(raw["amount_paid_minor"])) / _HUNDRED).quantize(MONEY_QUANTUM)
        return {
            "invoice_correlation": str(correlation),
            "paid_amount": str(amount),
            "paid_at": _at(raw["paid_at"], field_name="paid_at"),
            "payment_observation": {key: raw[key] for key in ("schema", "disposition", "invoice_status", "currency", "amount_paid_minor", "amount_due_minor", "invoice_correlation_sha256", "invoice_id_sha256", "evidence_sha256", "paid_at") if key in raw},
            "evidence_refs": [f"payment:{str(raw['evidence_sha256'])[:24]}"],
        }
    if raw.get("Payments") is not None or raw.get("payments") is not None:
        prov = _provenance(provenance, tools=frozenset({XERO_PAYMENTS_TOOL}), code="PAYMENT_NOT_BOUND")
        _require(str(prov["output_digest"]) == stable_digest(raw), "PAYMENT_NOT_BOUND", "the provenance does not seal this exact payments page")
        _require(invoice_ref is not None, "PAYMENT_INVOICE_UNNAMED", "name the invoice whose payment is being bound")
        rows = [dict(item) for item in (raw.get("Payments") or raw.get("payments") or [])]
        matched = [row for row in rows if str(dict(row.get("Invoice") or {}).get("InvoiceID") or row.get("InvoiceID") or "") == str(invoice_ref)]
        _require(len(matched) == 1, "PAYMENT_ROW_MISSING", f"the payments page carries {len(matched)} rows for {invoice_ref}; exactly one is required")
        row = matched[0]
        _require(str(row.get("Status", "")).upper() == "AUTHORISED", "PAYMENT_NOT_PAID", f"the payment is {row.get('Status')}, not AUTHORISED")
        if currency is not None:
            code = str(row.get("CurrencyCode") or dict(row.get("Invoice") or {}).get("CurrencyCode") or currency).upper()
            _require(code == str(currency).upper(), "PAYMENT_CURRENCY_MISMATCH", f"the payment is in {code}, not {currency}")
        amount = decimal_value(str(row.get("Amount", "0")), field_name="Amount")
        return {
            "invoice_correlation": str(correlation),
            "paid_amount": str(amount),
            "paid_at": _at(row["Date"], field_name="paid_at"),
            "payment_observation": {"schema": "lightbulb.xero_payment_row.v1", "currency": None if currency is None else str(currency).upper(), "payment_id": str(row.get("PaymentID") or ""), "invoice_ref": str(invoice_ref), "status": str(row["Status"]), "amount": str(amount), "observation_ref": str(prov["observation_ref"])},
            "evidence_refs": [f"payment:{str(row.get('PaymentID') or stable_digest(row))[:24]}", f"read:{prov['observation_ref']}"],
        }
    raise JobChainError("PAYMENT_OBSERVATION_SCHEMA_MISMATCH", f"a payment is a Square invoice payment observation or a governed xero.list_payments page; got {raw.get('schema')!r}")


def clearance_receipt(close_state: Any, *, reconciliation_ref: str | None = None) -> dict[str, Any]:
    """From a closed finance period whose receivables reconciliation is retained."""

    _require(close_state.status == "closed", "CLOSE_NOT_CLOSED", f"the close is {close_state.status}")
    ledger = close_state.ledger
    reconciled = list(getattr(ledger, "reconciled_accounts", ()) or ())
    _require("accounts_receivable" in reconciled, "RECEIVABLES_NOT_RECONCILED", "the close did not reconcile accounts receivable")
    ref = reconciliation_ref or next((str(getattr(item, "reconciliation_ref", "")) for item in getattr(ledger, "reconciliations", ()) or () if getattr(item, "account_kind", None) == "accounts_receivable"), None) or f"close:{close_state.scope.entity_ref}:accounts_receivable"
    return {"close_ref": str(close_state.scope.entity_ref), "close_state_digest": close_state.state_digest, "reconciliation_ref": ref, "period_end": str(ledger.period_end), "evidence_refs": [f"close:{close_state.scope.entity_ref}", f"state:{close_state.state_digest[:24]}"]}


# --------------------------------------------------------------------------- #
# What the chain hands to the other engines
# --------------------------------------------------------------------------- #


def _bound(state: Any, plan: JobChainPlan | Mapping[str, Any] | None = None) -> Any:
    parsed_state = state if isinstance(state, JobState) else JobState.model_validate(detached(state))
    if plan is not None:
        parsed_plan = JobChainPlan.model_validate(detached(plan))
        _require(parsed_state.plan_digest == parsed_plan.plan_digest, "JOB_PLAN_MISMATCH", "the job belongs to a different job_chain plan")
    return parsed_state


def _paid(state: Any) -> Any:
    parsed_state = _bound(state)
    _require(parsed_state.status in ("paid", "reconciled"), "JOB_NOT_PAID", f"the job is {parsed_state.status}; only settled job cash is revenue")
    return parsed_state


def period_evidence_receipt(job_state: Any, *, plan: JobChainPlan | Mapping[str, Any] | None = None, engine: str | None = None, evidence_ref: str | None = None) -> dict[str, Any]:
    """The operating system's ``record_evidence`` receipt: the period's service revenue is the job's *paid* cash.

    The engine the evidence lands on follows the plan's profile -- a local
    services job is ``service_delivery`` revenue, a consulting job is
    ``engagement_engine`` revenue -- and defaults to ``service_delivery`` when
    the plan is not supplied.

    COMPANION EDIT: ``company_operating_system.EngineKind`` (L64) names five
    engines and ``engagement_engine`` is not one of them, so a consulting
    profile's receipt is refused by ``PeriodReceipt`` until registering this
    chain adds it.  Pass ``engine="service_delivery"`` in the meantime; the
    gap is pinned by a test rather than left to a period that will not close.
    """

    parsed_state = _paid(job_state)
    profile = "local_services" if plan is None else JobChainPlan.model_validate(detached(plan)).profile
    return {
        "engine": engine or ("service_delivery" if profile == "local_services" else "engagement_engine"),
        "evidence_ref": evidence_ref or f"job:{parsed_state.scope.entity_ref}:{parsed_state.state_digest[:16]}",
        "spend": "0",
        "revenue": str(parsed_state.ledger.paid_amount),
        "signals": [],
    }


def job_cost_sources(job_state: Any, payable_states: Sequence[Any] = (), *, plan: JobChainPlan | Mapping[str, Any] | None = None, centre_ref: str | None = None) -> list[dict[str, Any]]:
    """The cost-register sources this job puts on its centre: the materials and subcontractors its payables paid."""

    parsed_state = _bound(job_state, plan)
    centre = _centre(centre_ref, plan)
    sources: list[dict[str, Any]] = []
    for item in payable_states:
        raw = dict(detached(item))
        ledger = dict(raw.get("ledger") or {})
        ref = ledger.get("bill_ref") or ledger.get("payable_ref") or dict(raw.get("scope") or {}).get("entity_ref")
        amount = ledger.get("paid_amount") or ledger.get("approved_amount") or ledger.get("bill_total") or "0"
        _require(bool(ref), "PAYABLE_STATE_INVALID", "a payable source names its bill")
        sources.append({
            "schema": COST_SOURCE_SCHEMA,
            "centre_ref": centre,
            "kind": "subcontractor" if str(ledger.get("category") or "") == "subcontractor" else "materials",
            "source_engine": "payables_chain",
            "source_ref": str(ref),
            "source_state_digest": str(raw.get("state_digest") or ""),
            "job_ref": str(parsed_state.scope.entity_ref),
            "amount": str(decimal_value(amount, field_name="amount")),
            "currency": str(parsed_state.scope.currency),
        })
    return sources


def _centre(centre_ref: str | None, plan: JobChainPlan | Mapping[str, Any] | None) -> str:
    """The cost centre the register posts to; the plan owns it, and neither the SDK nor the caller invents one."""

    ref = centre_ref or (None if plan is None else JobChainPlan.model_validate(detached(plan)).centre_ref)
    _require(ref is not None, "CENTRE_REF_MISSING", "the cost register needs the centre this job posts to; set centre_ref on the plan")
    return str(ref)


def chain_revenue_receipt(job_state: Any, *, plan: JobChainPlan | Mapping[str, Any] | None = None, centre_ref: str | None = None) -> dict[str, Any]:
    """``company_cost_centres.chain_revenue_receipt`` for a paid job: proven cash, on the job's centre."""

    parsed_state = _paid(job_state)
    _require(parsed_state.schema_id in REVENUE_STATE_SCHEMAS, "REVENUE_STATE_SCHEMA_MISMATCH", f"{parsed_state.schema_id} is not a registered revenue state schema")
    _require(parsed_state.status in SETTLED_REVENUE_STATUSES, "REVENUE_NOT_SETTLED", f"{parsed_state.status} is not a settled revenue status")
    ledger = parsed_state.ledger
    return {
        "schema": REVENUE_SOURCE_SCHEMA,
        "centre_ref": _centre(centre_ref, plan),
        "source_engine": JOB_CHAIN_KIND,
        "source_ref": str(parsed_state.scope.entity_ref),
        "source_state_digest": parsed_state.state_digest,
        "status": parsed_state.status,
        "amount": str(ledger.paid_amount),
        "currency": str(parsed_state.scope.currency),
        "settled_at": ledger.paid_at,
        "evidence_refs": [f"job:{parsed_state.scope.entity_ref}", f"invoice:{ledger.invoice_ref}"],
    }


def receivable_receipt(job_state: Any, *, at: str, terms_days: int = 0) -> dict[str, Any]:
    """``collections_chain.open_receivable`` for a job that was invoiced and is now past due."""

    parsed_state = _bound(job_state)
    ledger = parsed_state.ledger
    _require(parsed_state.status == "invoiced", "JOB_NOT_INVOICED", f"the job is {parsed_state.status}; only an unpaid invoiced job is a receivable")
    due_at = _due_at(ledger, terms_days)
    now = timestamp(at, field_name="at")
    _require(parsed(now) > parsed(due_at), "RECEIVABLE_NOT_DUE", f"the invoice is due at {due_at}; nothing is overdue yet")
    return {
        "schema": RECEIVABLE_INTAKE_SCHEMA,
        "receivable_ref": f"receivable:{ledger.invoice_ref}",
        "customer_ref": str(ledger.customer_ref),
        "invoice_ref": str(ledger.invoice_ref),
        "invoice_correlation": str(ledger.invoice_correlation),
        "amount": str(ledger.invoice_total),
        "currency": str(parsed_state.scope.currency),
        "issued_at": str(ledger.issued_at),
        "due_at": due_at,
        "days_overdue": (parsed(now) - parsed(due_at)).days,
        "source_engine": JOB_CHAIN_KIND,
        "source_state_digest": parsed_state.state_digest,
        "evidence_refs": [f"job:{parsed_state.scope.entity_ref}", f"invoice:{ledger.invoice_ref}"],
    }


def _due_at(ledger: Any, terms_days: int) -> str:
    return add_days(str(ledger.issued_at), int(terms_days))


def job_flows(state: Any, *, terms_days: int = 0) -> tuple[ScheduledFlow, ...]:
    """The treasury flow an invoiced-but-unpaid job contributes: one receivable, due when the invoice is due."""

    parsed_state = _bound(state)
    ledger = parsed_state.ledger
    if parsed_state.status != "invoiced" or ledger.invoice_ref is None:
        return ()
    return (ScheduledFlow(kind="receivable", ref=f"receivable:{ledger.invoice_ref}", due_at=_due_at(ledger, terms_days), amount=str(ledger.invoice_total), source=JOB_CHAIN_KIND),)


def first_dollar_signal(state: Any, *, source_plan: Any, emitted_at: str) -> dict[str, Any]:
    """A replayed job settlement is an economic signal; marketing attribution is separate."""
    plan, source = JOB_LIFECYCLE.bind(source_plan, state)
    _require(source.status in {"paid", "reconciled"}, "JOB_NOT_PAID", "only settled job cash is revenue")
    at = timestamp(emitted_at, field_name="emitted_at")
    _require(parsed(source.transition_history[-1].command.occurred_at) <= parsed(at), "SOURCE_FROM_FUTURE", "settlement must already be observed")
    from lightbulb.company_operating_system import CompanySignal
    return CompanySignal(name="signals.job_settled", producer=JOB_CHAIN_KIND, emitted_at=at,
        payload={"job_ref": source.scope.entity_ref, "settled_amount": str(source.ledger.paid_amount),
                 "currency": plan.currency, "source_digest": source.state_digest}).to_dict()


def _day(stamp: str | None) -> str:
    if not stamp:
        return "?"
    when = parsed(stamp)
    return f"{when.day} {when.strftime('%b')}"


def _slot(stamp: str | None) -> str:
    if not stamp:
        return "?"
    when = parsed(stamp)
    return f"{when.strftime('%a')} {when.strftime('%H:%M')}"


def _short(ref: str | None, *, keep: int = 4) -> str:
    text = str(ref or "?")
    return text if len(text) <= keep + 12 else f"{text[:keep + 8]}…"


def _cash(amount: Any, currency: str) -> str:
    """``A$1,250.00``: a job line always shows the cents so quoted, invoiced and paid line up.

    ``ai_operator.money`` drops the cents on a whole amount, which is right for
    an operator's log line and wrong here -- the whole point of the job line is
    that A$485.00 quoted and A$485.00 paid are visibly the same number.  The
    symbol still comes from ``money`` so the two never disagree on a currency.
    """

    value = decimal_value(Decimal(0) if amount is None else amount, field_name="amount", allow_negative=True)
    symbol = re.sub(r"[\d.,]+$", "", money(Decimal(0), currency))
    return f"{symbol}{value:,.2f}"


def narrate_job(state: Any, *, currency: str | None = None, plan: JobChainPlan | Mapping[str, Any] | None = None) -> str:
    """One line an operator reads: what was quoted, what the provider showed, and what actually landed."""

    parsed_state = _bound(state, plan)
    ledger = parsed_state.ledger
    unit = currency or parsed_state.scope.currency
    rail = None if plan is None else JobChainPlan.model_validate(detached(plan)).rail
    parts: list[str] = []
    if ledger.quote_ref:
        parts.append(f"quoted {_cash(ledger.quote_total, unit)} to {_short(ledger.customer_ref)} (expires {_day(ledger.quote_expiry)})")
    else:
        parts.append(f"lead from {ledger.lead_source} on {_day(ledger.received_at)}")
    if ledger.accepted_at:
        parts.append("accepted")
    if ledger.booking_ref:
        parts.append(f"booked {_slot(ledger.start_at)}")
    if ledger.assignee_ref:
        parts.append(f"assigned {_short(ledger.assignee_ref)}")
    if ledger.completed_at:
        parts.append(f"done {parsed(ledger.completed_at).strftime('%H:%M')} ({len(_evidence(parsed_state))} evidence)")
    if ledger.invoice_ref:
        parts.append(f"invoice {_short(ledger.invoice_ref)} {_cash(ledger.invoice_total, unit)}")
    if ledger.paid_at:
        # the plan owns the rail; an opaque provider record ref is not evidence
        # of which provider issued it, so without a plan the line does not guess.
        where = {"square": "Square", "xero": "Xero"}.get(str(rail or ""), "the provider")
        parts.append(f"paid {_cash(ledger.paid_amount, unit)} on {where}, {ledger.days_lead_to_cash} days lead to cash")
    if ledger.outcome == "cancelled":
        parts.append(f"cancelled ({str(ledger.cancel_reason)[:60]})")
    if ledger.outcome == "reconciliation_required":
        parts.append("reconciliation required")
    return f"{parsed_state.scope.entity_ref}: {' -> '.join(parts)}"


def _evidence(state: Any) -> tuple[Any, ...]:
    for transition in reversed(state.transition_history):
        if transition.command.event == "complete":
            return tuple(transition.command.receipt.completion_evidence_refs)
    return ()


def jobs_summary(states: Sequence[Any]) -> dict[str, Any]:
    """The board line for a services company: how many jobs are open, how many paid, and how long the money takes."""

    parsed_states = [_bound(state) for state in states]
    quoted = [state for state in parsed_states if state.ledger.quote_ref is not None]
    accepted = [state for state in quoted if state.ledger.accepted_at is not None]
    paid = [state for state in parsed_states if state.ledger.paid_at is not None]
    cancelled = [state for state in parsed_states if state.ledger.outcome == "cancelled"]
    days = sorted(int(state.ledger.days_lead_to_cash) for state in paid if state.ledger.days_lead_to_cash is not None)
    median = None if not days else (days[len(days) // 2] if len(days) % 2 else (days[len(days) // 2 - 1] + days[len(days) // 2]) // 2)
    revenue = sum((state.ledger.paid_amount for state in paid), Decimal("0.00"))
    return {
        "open": len([state for state in parsed_states if state.ledger.outcome == "open"]),
        "paid": len(paid),
        "cancelled": len(cancelled),
        "quote_acceptance_rate_percent": None if not quoted else str((Decimal(len(accepted)) * _HUNDRED / Decimal(len(quoted))).quantize(MONEY_QUANTUM)),
        "median_days_lead_to_cash": median,
        "revenue_paid": str(revenue),
    }


def job_summary(state: Any) -> dict[str, Any]:
    parsed_state = _bound(state)
    ledger = parsed_state.ledger
    return {
        "job_ref": str(parsed_state.scope.entity_ref),
        "status": parsed_state.status,
        "lead_source": ledger.lead_source,
        "quote_total": str(ledger.quote_total),
        "invoice_total": str(ledger.invoice_total),
        "paid_amount": str(ledger.paid_amount),
        "days_lead_to_cash": ledger.days_lead_to_cash,
        "outcome": ledger.outcome,
        "state_digest": parsed_state.state_digest,
    }


def job_exception(error: Exception, *, source_ref: str, category: str | None = "job_quote") -> dict[str, Any]:
    """An exceptions-desk opening receipt for a refused hop, through ``authority_matrix.authority_exception``."""

    return authority_exception(error, source_engine=JOB_CHAIN_KIND, source_ref=source_ref, category=category)


JOB_CHAIN_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": JOB_CHAIN_KIND,
    "golden_loop": JOB_GOLDEN_LOOP,
    "stages": ["receive_lead", "quote", "accept", "book", "assign", "complete", "invoice", "apply_payment", "reconcile"],
    "statuses": list(JOB_STATUSES),
    "events": list(JOB_EVENTS),
    "hops": {
        "receive_lead": "pipeline_engine handed_off state, service_delivery case state, a square.observe_bookings row, or a self-naming lightbulb.job_lead_intake.v1 operator input",
        "quote": "xero.create_quote ExecutionReceipt + xero.observe_quote SENT/ACCEPTED observation carrying the LB-JOB correlation (xero rail), or a self-naming lightbulb.job_quote_input.v1 document (square rail); both need a job_quote AuthorizationProof",
        "accept": "xero.observe_quote ACCEPTED, a gmail.get_thread / microsoft.get_conversation observation classified 'accepted', or a signed lightbulb.job_acceptance.v1 input",
        "book": "square.observe_bookings PENDING/ACCEPTED row starting in the future",
        "assign": "employment_chain rostered state, company_workforce dispatch receipt with its approval, or engagement_engine staffed state (consulting)",
        "complete": "a later square.observe_bookings row that has elapsed + a lightbulb.job_completion_signoff.v1 human attestation",
        "invoice": "square.create_invoice + square.publish_invoice ExecutionReceipts, or the xero.create_invoice ExecutionReceipt; both need a job_invoice AuthorizationProof",
        "apply_payment": "square.observe_invoice_payment PAID observation, or a governed xero.list_payments AUTHORISED row for the invoice",
        "reconcile": "finance_close closed with accounts_receivable reconciled",
        "cancel": "an operator reason; no artifact is claimed",
        "require_reconciliation": "an operator reason; the job leaves the automated path",
    },
    "required_connectors": ["square", "xero", "gmail", "lightbulb.sdk_engine_state"],
    "optional_connectors": ["servicem8"],
    "optional_connector_note": "consumed through host.booking / host.job_completion if a later round admits it",
    "missing_reads": ["host.booking", "host.job_completion"],
    "hard_rules": [
        "a job is booked when the provider shows the booking, done when the booking has elapsed and a human attests it, paid when the provider shows the invoice paid",
        "the quote and the invoice are approved by authority, never by a string",
        "period revenue for service_delivery is paid job cash, not quoted value",
        "the SDK never creates a quote, booking or invoice; it binds the receipts the platform produced",
    ],
}

__all__ = [
    "ACCEPTANCE_THREAD_TOOLS",
    "BOOKING_PAGE_SCHEMA",
    "BOOKING_TOOL",
    "CANCELLED_BOOKING_STATUSES",
    "COST_SOURCE_SCHEMA",
    "ENGAGEMENT_FACTS_SCHEMA",
    "ENGAGEMENT_STATUSES",
    "INVOICE_WRITE_TOOLS",
    "JOB_ACCEPTANCE_SCHEMA",
    "JOB_CHAIN_KIND",
    "JOB_CHAIN_MANIFEST",
    "JOB_COMPLETION_SIGNOFF_SCHEMA",
    "JOB_EVENTS",
    "JOB_GOLDEN_LOOP",
    "JOB_LEAD_INTAKE_SCHEMA",
    "JOB_LIFECYCLE",
    "JOB_PLAN_SCHEMA",
    "JOB_QUOTE_INPUT_SCHEMA",
    "JOB_STATUSES",
    "LIVE_QUOTE_STATUSES",
    "MAX_JOB_TRANSITIONS",
    "OPEN_BOOKING_STATUSES",
    "PUBLISH_TOOL",
    "QUOTE_OBSERVATION_SCHEMA",
    "QUOTE_OBSERVATION_TOOL",
    "QUOTE_WRITE_TOOLS",
    "RECEIVABLE_INTAKE_SCHEMA",
    "REVENUE_SOURCE_SCHEMA",
    "REVENUE_STATE_SCHEMAS",
    "ROSTERED_STATUSES",
    "SETTLED_REVENUE_STATUSES",
    "SQUARE_PAYMENT_OBSERVATION_SCHEMA",
    "SQUARE_PAYMENT_TOOL",
    "TERMINAL_JOB_STATUSES",
    "WIP_FACTS_SCHEMA",
    "XERO_PAYMENTS_TOOL",
    "AuthorizationFacts",
    "EngagementFacts",
    "JobChainError",
    "JobChainPlan",
    "JobEffectBoundary",
    "JobLedger",
    "JobReceipt",
    "JobState",
    "WipFacts",
    "accept_receipt",
    "acceptance_input",
    "advance_job",
    "assign_dispatch_receipt",
    "assign_engagement_receipt",
    "assign_receipt",
    "book_receipt",
    "booking_lead_receipt",
    "booking_page_rows",
    "booking_ref_of",
    "case_lead_receipt",
    "chain_revenue_receipt",
    "clearance_receipt",
    "compile_job_chain",
    "complete_receipt",
    "completion_signoff",
    "first_dollar_signal",
    "invoice_receipt",
    "job_correlation",
    "job_cost_sources",
    "job_exception",
    "job_flows",
    "job_invoice_request",
    "job_summary",
    "jobs_summary",
    "lead_input",
    "lead_receipt",
    "narrate_job",
    "open_job",
    "payment_receipt",
    "period_evidence_receipt",
    "quote_input",
    "quote_receipt",
    "receivable_receipt",
    "verify_engagement",
    "verify_wip",
]
