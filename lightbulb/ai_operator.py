"""The AI operator: request every transition with its authority, resume what the ceilings auto-accept, escalate the rest.

The company already runs unattended (``company_cadence_runner``) and already
knows who may approve what (``authority_matrix``).  What was missing is the
thing in between: the principal that *asks*.  An AI operator is an ordinary
platform user with the ``AI_OPERATOR`` role whose whole authority is a
per-category ceiling table owned by one human approver.  Activating that table
mints amount-ceilinged approval preferences for the approver, so the platform's
own fail-closed matcher auto-accepts a transition *in the approver's name*
while everything above a ceiling, in a category with no row, needing a second
approver, or human-only waits in that human's inbox.

This module is the SDK half of that arrangement, and only that half:

* :func:`compile_operator_policy` derives the ceilings from a sealed
  :class:`AuthorityMatrix` -- the operator may never be granted more than the
  role it holds on the matrix already grants -- and
  :meth:`OperatorPolicy.to_platform_body` renders the create-policy body.  No
  identifiers: ``client.create_operator_policy`` names the operator and the
  approver because the client is the platform-facing layer.
* :func:`transition_authority` says, from a closed table, which authority
  category and which money one engine transition needs.  A transition that is
  not in the table has *no* category; it is never defaulted, and the request
  goes out undecorated so the platform escalates it.
* :func:`operator_authorization` consumes the platform's decision.  When the
  platform says it auto-accepted, the SDK re-checks the decision against the
  *sealed* policy before believing it: the same matrix digest, the same
  category, the same amount to the cent, the approver as decider, and a ceiling
  that actually covers it.  An auto-accept above the sealed ceiling is refused
  here even though the platform granted it, and becomes an exceptions-desk case.
* :class:`OperatorLoop` is the minute: request, resume what came back accepted,
  drain what a human decided since, plan the reads the platform must run, tick
  the cadence, fence the unattended spend, and narrate every line of it.

What it hands to other engines: an :class:`AuthorizationProof` for every money
hop that requires one, resumed engine states for the transitions the ceilings
covered, a sealed :class:`EscalationRegister` and an :class:`OperatorLog` the
daily brief reads, and exceptions-desk openings for the refusals.

Nothing here decides anything, holds a credential, or performs a read or a
write.  The client holds the token; the approver's ceilings decide; a human
decides everything else.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from datetime import timedelta
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationError, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    MONEY_QUANTUM,
    BoundedText,
    CurrencyCode,
    OpaqueRef,
    Sha256Digest,
    ShortText,
    StrictModel,
    decimal_value,
    detached,
    iso,
    parsed,
    pct,
    seal,
    sealed_digest,
    skip_digests,
    stable_digest,
    timestamp,
    unique,
)
from lightbulb.company_execution_bridge import (
    APPROVAL_BINDING_SCHEMA,
    HUMAN_ONLY_CATEGORIES,
    ApprovalBinding,
    BridgeError,
    DecoratedApprovalRequest,
    EngineApprovalRequest,
    bind_approval,
    decorate_request,
)

OPERATOR_KIND = "ai_operator"
OPERATOR_GOLDEN_LOOP = "company.blueprint_to_governed_operating_cadence@0.1.0"
OPERATOR_POLICY_SCHEMA = "lightbulb.ai_operator_policy.v1"
OPERATOR_LOG_SCHEMA = "lightbulb.ai_operator_log.v1"
OPERATOR_TICK_SCHEMA = "lightbulb.ai_operator_tick.v1"
OPERATOR_ESCALATION_SCHEMA = "lightbulb.ai_operator_escalation_register.v1"
ESCALATION_BACKLOG_LIMIT = 20
_MONTH_DAYS = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
_ENGINE_NAME = r"^[a-z][a-z0-9_]{2,79}$"
_CURRENCY_SYMBOLS: Mapping[str, str] = {"AUD": "A$", "CAD": "C$", "NZD": "NZ$", "USD": "$", "SGD": "S$", "GBP": "£", "EUR": "€"}


class AiOperatorError(ValueError):
    """The operator refuses to believe a decision, or cannot compile a policy; carries the code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code, self.message = code, message


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise AiOperatorError(code, message)


# --------------------------------------------------------------------------- #
# Authority lives in the central module; operator policy only narrows it.
from lightbulb.authority_matrix import (
    AUTHORITY_MATRIX_SCHEMA, AUTHORIZATION_PROOF_SCHEMA, MATRIX_ADOPTION_SCHEMA,
    AuthorityCategory, AUTHORITY_CATEGORIES, Segregation, AuthorityMatrixError,
    AuthorityRow, ApproverBinding, AuthorityMatrix, MatrixAdoption,
    AuthorizationProof, compile_authority_matrix, authorize, authority_exception,
)

# --------------------------------------------------------------------------- #


#: ``category -> ((engine, event), ...)``: the transitions each authority
#: category may cover.  A ceiling is minted per pair, so the platform matches on
#: the exact hop the operator asked for, never on a category alone.
DEFAULT_BINDINGS: Mapping[str, tuple[tuple[str, str], ...]] = {
    "replan": (("company_operating_system", "replan"),),
    "dispatch": (("company_workforce", "dispatch"),),
    "payable": (("payables_chain", "approve"), ("spend_control_chain", "approve")),
    "payroll": (("payroll_run_chain", "approve"),),
    "disbursement": (("disbursement_run", "approve"), ("disbursement_run", "release_hold")),
    "remedy": (("service_delivery", "submit_resolution"),),
    "pricing": (("deal_desk_engine", "approve_discount"), ("wip_billing", "approve")),
    "commitment": (("spend_control_chain", "confirm_recurring"), ("obligation_paper", "give_notice"), ("engagement_engine", "revise_budget")),
    "job_quote": (("job_chain", "quote"),),
    "job_invoice": (("job_chain", "invoice"),),
    "people_change": (("employment_chain", "hire"), ("employment_chain", "initiate_offboarding")),
    "wind_down": (("wind_down_chain", "decide"),),
}


# --------------------------------------------------------------------------- #
# The policy: the ceilings, derived from the matrix, sealed
# --------------------------------------------------------------------------- #


class OperatorCeiling(StrictModel):
    """One hop the operator may ask the platform to auto-accept, and up to how much."""

    category: AuthorityCategory
    engine: str = Field(pattern=_ENGINE_NAME)
    event: ShortText
    max_amount: Decimal
    requires_second_approver: bool = False
    human_only: bool = False
    segregation: Segregation = "not_requester"

    @field_validator("max_amount", mode="before")
    @classmethod
    def _amount(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="max_amount")

    @property
    def hop(self) -> tuple[str, str]:
        return (self.engine, self.event)

    @property
    def auto_acceptable(self) -> bool:
        return not self.human_only and not self.requires_second_approver


class OperatorPolicy(StrictModel):
    """The AI operator's whole authority: opaque refs, ceilings, and the windows it may run in."""

    schema_id: Literal["lightbulb.ai_operator_policy.v1"] = Field(default=OPERATOR_POLICY_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    operator_role_ref: OpaqueRef
    operator_ref: OpaqueRef
    approver_ref: OpaqueRef
    matrix_digest: Sha256Digest
    effective_from: str
    ceilings: tuple[OperatorCeiling, ...] = Field(min_length=1, max_length=60)
    review_months: int = Field(default=12, ge=1, le=24)
    unattended_window: tuple[tuple[int, int], ...] = Field(default_factory=tuple, max_length=3)
    daily_auto_accept_limit: int = Field(default=50, ge=1, le=500)
    daily_amount_limit: Decimal | None = None
    escalation_stale_hours: int = Field(default=48, ge=1, le=720)
    policy_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("effective_from")
    @classmethod
    def _effective(cls, value: str) -> str:
        return timestamp(value, field_name="effective_from")

    @field_validator("unattended_window", mode="before")
    @classmethod
    def _windows(cls, value: Any) -> Any:
        if isinstance(value, (list, tuple)):
            return tuple(tuple(int(hour) for hour in item) if isinstance(item, (list, tuple)) else item for item in value)
        return value

    @field_validator("daily_amount_limit", mode="before")
    @classmethod
    def _limit(cls, value: Any) -> Any:
        return None if value is None else decimal_value(value, field_name="daily_amount_limit")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> OperatorPolicy:
        unique([f"{item.engine}.{item.event}" for item in self.ceilings], label="operator ceilings (engine, event)")
        if self.operator_ref == self.approver_ref:
            raise ValueError("the operator cannot be its own approver")
        for start, end in self.unattended_window:
            if not (0 <= start <= 23 and 1 <= end <= 24) or start == end:
                raise ValueError("an unattended window is a UTC (start_hour, end_hour) pair inside the day")
        if not skip_digests(info) and self.policy_digest != sealed_digest(OperatorPolicy, self, "policy_digest"):
            raise ValueError("policy_digest must commit the exact policy")
        return self

    def ceiling_for(self, engine: str, event: str) -> OperatorCeiling | None:
        return next((item for item in self.ceilings if item.hop == (engine, event)), None)

    def in_window(self, now: str) -> bool:
        if not self.unattended_window:
            return True
        hour = parsed(timestamp(now, field_name="now")).hour
        return any(start <= hour < end if start < end else (hour >= start or hour < end) for start, end in self.unattended_window)

    def to_platform_body(self) -> dict[str, Any]:
        """The body for ``POST /api/companies/{id}/operator-policy``; the client names the two users, never this."""

        return {
            "currency": self.currency,
            "matrixDigest": self.matrix_digest,
            "effectiveFrom": self.effective_from,
            "reviewMonths": self.review_months,
            "ceilings": [
                {"category": item.category, "engine": item.engine, "event": item.event, "maxAmountCents": int(item.max_amount * 100), "requiresSecondApprover": item.requires_second_approver, "humanOnly": item.human_only, "segregation": item.segregation}
                for item in self.ceilings
            ],
        }


def to_platform_body(policy: OperatorPolicy | Mapping[str, Any]) -> dict[str, Any]:
    """The create-policy body for a sealed :class:`OperatorPolicy`."""

    return (policy if isinstance(policy, OperatorPolicy) else OperatorPolicy.model_validate(detached(policy))).to_platform_body()


_POLICY_SETTINGS = ("review_months", "unattended_window", "daily_auto_accept_limit", "daily_amount_limit", "escalation_stale_hours", "effective_from")


def compile_operator_policy(
    matrix: AuthorityMatrix | Mapping[str, Any],
    *,
    operator_role_ref: str,
    operator_ref: str,
    approver_ref: str,
    bindings: Mapping[str, Sequence[tuple[str, str]]] = DEFAULT_BINDINGS,
    overrides: Mapping[str, Any] | None = None,
) -> OperatorPolicy:
    """Fan the operator role's matrix rows out over the hops each category covers.

    ``overrides`` may carry policy settings (``review_months``,
    ``unattended_window``, ``daily_auto_accept_limit``, ``daily_amount_limit``,
    ``escalation_stale_hours``, ``effective_from``) and a ``ceilings`` map keyed
    ``"engine.event"``.  An override can lower a ceiling or force ``human_only``;
    it can never raise one above the matrix row the operator role holds.

    The policy's effective window is derived the same way and sits *inside* the
    matrix's: it may not begin before the matrix took effect, and its review may
    not fall due after the matrix's own (``POLICY_OUTSIDE_MATRIX``).  The default
    twelve months is lowered to the matrix's review when the matrix is reviewed
    sooner -- the minted preferences must expire with the authority they read.
    """

    parsed_matrix = AuthorityMatrix.model_validate(detached(matrix))
    raw = dict(overrides or {})
    ceiling_overrides = {str(key): dict(value) for key, value in dict(raw.get("ceilings") or {}).items()}
    rows = [row for row in parsed_matrix.rows if row.role_ref == operator_role_ref]
    _require(bool(rows), "OPERATOR_ROLE_UNKNOWN", f"{operator_role_ref} holds no row on this matrix; the operator is granted nothing")
    approver_role = parsed_matrix.role_of(approver_ref)
    _require(approver_role is not None, "APPROVER_NOT_ON_MATRIX", f"{approver_ref} is bound to no role on this matrix and cannot own the ceilings")
    _require(approver_role != operator_role_ref, "APPROVER_NOT_ON_MATRIX", f"{approver_ref} holds the operator's own role {operator_role_ref}; the ceilings need a different role")
    _require(operator_ref != approver_ref, "OPERATOR_IS_APPROVER", "the operator cannot own the ceilings it asks against")
    ceilings: list[dict[str, Any]] = []
    for row in rows:
        hops = tuple(bindings.get(row.category) or ())
        _require(bool(hops), "CATEGORY_UNBOUND", f"{row.category} is granted to {operator_role_ref} but names no engine transition; bind it before the operator may ask")
        for engine, event in hops:
            override = ceiling_overrides.get(f"{engine}.{event}", {})
            max_amount = decimal_value(override.get("max_amount", row.max_amount), field_name="max_amount")
            _require(max_amount <= row.max_amount, "CEILING_ABOVE_MATRIX", f"{engine}.{event} would allow {max_amount}; the {row.row_ref} row grants {row.max_amount}")
            ceilings.append({
                "category": row.category,
                "engine": engine,
                "event": event,
                "max_amount": str(max_amount),
                "requires_second_approver": bool(override.get("requires_second_approver", row.requires_second_approver)),
                "human_only": bool(override.get("human_only", False)) or row.category in HUMAN_ONLY_CATEGORIES,
                "segregation": str(override.get("segregation", row.segregation)),
            })
    payload: dict[str, Any] = {
        "company_ref": parsed_matrix.company_ref,
        "currency": parsed_matrix.currency,
        "operator_role_ref": operator_role_ref,
        "operator_ref": operator_ref,
        "approver_ref": approver_ref,
        "matrix_digest": parsed_matrix.matrix_digest,
        "effective_from": parsed_matrix.effective_from,
        "ceilings": ceilings,
    }
    payload.update({key: raw[key] for key in _POLICY_SETTINGS if key in raw})
    effective_from = timestamp(str(payload["effective_from"]), field_name="effective_from")
    _require(parsed(effective_from) >= parsed(parsed_matrix.effective_from), "POLICY_OUTSIDE_MATRIX", f"the policy would take effect at {effective_from}, before the matrix does at {parsed_matrix.effective_from}")
    payload["effective_from"] = effective_from
    if "review_months" in raw:
        _require(int(raw["review_months"]) <= parsed_matrix.review_months, "POLICY_OUTSIDE_MATRIX", f"the policy would be reviewed after {raw['review_months']} months; the matrix it reads is due for review after {parsed_matrix.review_months}")
    else:
        payload["review_months"] = min(int(OperatorPolicy.model_fields["review_months"].default), parsed_matrix.review_months)
    return seal(OperatorPolicy, payload, "policy_digest")


# --------------------------------------------------------------------------- #
# What one transition is worth, and under which category
# --------------------------------------------------------------------------- #

#: ``(engine, event) -> (category, where the money is, which field, human_only)``.
#: Closed on purpose: a transition that is not here has no category, and the
#: request goes out undecorated so the platform escalates it to a person.
_CLASSIFICATION: Mapping[tuple[str, str], tuple[str, str, str, bool]] = {
    ("company_operating_system", "replan"): ("replan", "shifts", "delta_percent", False),
    ("company_workforce", "dispatch"): ("dispatch", "receipt", "estimated_cost", False),
    ("payables_chain", "approve"): ("payable", "ledger", "amount", False),
    ("spend_control_chain", "approve"): ("payable", "ledger", "amount", False),
    ("payroll_run_chain", "approve"): ("payroll", "ledger", "net", False),
    ("disbursement_run", "approve"): ("disbursement", "ledger", "batch_total", False),
    ("disbursement_run", "release_hold"): ("disbursement", "ledger", "batch_total", False),
    ("service_delivery", "submit_resolution"): ("remedy", "receipt_or_zero", "remedy_value", False),
    ("deal_desk_engine", "approve_discount"): ("pricing", "ledger", "discount_value", False),
    ("wip_billing", "approve"): ("pricing", "ledger", "amount", False),
    ("job_chain", "quote"): ("job_quote", "receipt", "quote_total", False),
    ("job_chain", "invoice"): ("job_invoice", "receipt", "invoice_total", False),
    ("employment_chain", "hire"): ("people_change", "ledger", "commitment_amount", True),
    ("employment_chain", "initiate_offboarding"): ("people_change", "zero", "", True),
    ("wind_down_chain", "decide"): ("wind_down", "plan", "settlement_reserve", True),
}


def _field(source: Any, name: str) -> Any:
    if source is None:
        return None
    if isinstance(source, Mapping):
        return source.get(name)
    return getattr(source, name, None)


def _replan_amount(shifts: Any, plan: Any) -> Decimal:
    from lightbulb.company_operating_system import replan_authority_amount
    _require(bool(shifts) and plan is not None, "AUTHORITY_AMOUNT_UNAVAILABLE", "a replan requires the actual operating plan and its shifts")
    return replan_authority_amount(plan, shifts)


def transition_authority(engine: str, event: str, command: Mapping[str, Any] | Any, state: Any = None, *, plan: Any = None) -> tuple[str, Decimal, bool]:
    """The authority category, the money, and whether a human must decide, for one engine transition.

    ``plan`` is the engine's own loop plan; only the replan (envelope budgets)
    and the wind-down (settlement reserve) draw their money from it.
    """

    classified = _CLASSIFICATION.get((engine, event))
    _require(classified is not None, "AUTHORITY_CATEGORY_UNKNOWN", f"{engine}.{event} maps to no authority category; the request carries none and the platform escalates it")
    assert classified is not None
    category, where, name, human_only = classified
    receipt = _field(command, "receipt") or {}
    ledger = _field(state, "ledger")
    if where == "zero":
        return category, Decimal("0.00"), human_only
    if where == "shifts":
        return category, _replan_amount(_field(receipt, "shifts"), plan), human_only
    if where == "receipt_or_zero":
        value = _field(receipt, name)
        return category, decimal_value(value if value is not None else 0, field_name=name), human_only
    source = {"receipt": receipt, "ledger": ledger, "plan": plan}[where]
    value = _field(source, name)
    if value is None and where == "plan":
        value = _field(ledger, name)
    _require(value is not None, "AUTHORITY_AMOUNT_UNAVAILABLE", f"{engine}.{event} needs {where}.{name} to know what it is worth; it is not in hand")
    return category, decimal_value(value, field_name=name), human_only


# --------------------------------------------------------------------------- #
# Believing the platform's decision
# --------------------------------------------------------------------------- #


def _decorated(request: DecoratedApprovalRequest | Mapping[str, Any]) -> DecoratedApprovalRequest:
    return request if isinstance(request, DecoratedApprovalRequest) else DecoratedApprovalRequest.model_validate(detached(request))


def operator_authorization(
    task: Mapping[str, Any],
    request: DecoratedApprovalRequest | Mapping[str, Any],
    *,
    policy: OperatorPolicy,
    matrix: AuthorityMatrix | Mapping[str, Any],
    adoption: MatrixAdoption | Mapping[str, Any],
    requester_ref: str,
    command: Mapping[str, Any] | None = None,
    prior_proofs: Sequence[AuthorizationProof | Mapping[str, Any]] = (),
    preparer_ref: str | None = None,
    payee_ref: str | None = None,
    now: str | None = None,
) -> AuthorizationProof:
    """Turn one decided platform task into an :class:`AuthorizationProof`, or refuse it.

    An auto-accept is only believed when the platform's own context still names
    the sealed policy this operator compiled: the same matrix digest, the same
    category, the same amount *in the same currency* to the cent, the approver as
    the decider, and a ceiling that covers it.  A request the operator itself sent
    ``human_only`` -- because the ceiling says so, or because the day limit or the
    spend cap was reached -- is refused however the platform answered it.
    ``command`` is the sealed engine command the runtime is holding for this
    transition; :func:`authorize` refuses without it.
    """

    parsed_request = _decorated(request)
    raw = dict(detached(task))
    context = dict(raw.get("contextData") or raw.get("context") or {})
    decided_by = str(raw.get("decidedByRef") or raw.get("decided_by_ref") or raw.get("decidedBy") or raw.get("decided_by") or "")
    _require(decided_by != policy.operator_ref, "SELF_DECISION", "the AI operator cannot decide its own request")
    requested_by = str(context.get("requested_by_user_id") or "")
    _require(not requested_by or decided_by != requested_by, "SELF_DECISION", "the decider is the principal that raised this request")
    _require(parsed_request.currency in (None, policy.currency), "AUTHORITY_CURRENCY_MISMATCH", f"the request is denominated in {parsed_request.currency}; this policy grants {policy.currency} authority and its cents mean nothing in another currency")
    binding: ApprovalBinding = bind_approval(raw, parsed_request.request)
    ceiling = policy.ceiling_for(str(parsed_request.request.engine), str(parsed_request.request.event))
    if bool(context.get("auto_accepted")):
        _require(bool(context.get("operator_policy_id")), "OPERATOR_POLICY_MISSING", "the platform auto-accepted without naming the operator policy that allowed it")
        _require(str(context.get("matrix_digest") or "") == policy.matrix_digest, "OPERATOR_POLICY_DRIFT", "the platform's policy commits a different authority matrix than the sealed one")
        _require(str(context.get("category") or "") == str(parsed_request.category or ""), "AUTHORITY_CATEGORY_MISMATCH", f"the platform decided {context.get('category')!r}; the request asked for {parsed_request.category!r}")
        _require(int(context.get("amount_cents") or -1) == int(parsed_request.amount_cents or -1), "AUTHORITY_AMOUNT_MISMATCH", f"the platform decided {context.get('amount_cents')} cents; the request asked for {parsed_request.amount_cents}")
        _require(str(context.get("currency") or policy.currency).upper() == policy.currency, "AUTHORITY_CURRENCY_MISMATCH", f"the platform decided in {context.get('currency')}; the policy grants {policy.currency}")
        _require(binding.decided_by_ref == policy.approver_ref, "OPERATOR_DECISION_MISATTRIBUTED", f"the standing rule decided as {binding.decided_by_ref}, not the approver {policy.approver_ref}")
        _require(not parsed_request.human_only, "CEILING_EXCEEDED_AT_PLATFORM", "the operator sent this request human-only; no standing rule may accept it, whatever the platform says")
        _require(ceiling is not None and ceiling.auto_acceptable and Decimal(parsed_request.amount_cents or 0) / 100 <= ceiling.max_amount, "CEILING_EXCEEDED_AT_PLATFORM", f"the platform auto-accepted {parsed_request.request.engine}.{parsed_request.request.event} above the sealed ceiling; refuse it and open an exceptions-desk case")
    return authorize(
        matrix,
        category=str(parsed_request.category or ""),
        amount=Decimal(parsed_request.amount_cents or 0) / 100,
        currency=policy.currency,
        approval_binding=binding,
        requester_ref=requester_ref,
        preparer_ref=preparer_ref,
        payee_ref=payee_ref,
        command=command,
        adoption=adoption,
        prior_proofs=prior_proofs,
        now=now,
    )


# --------------------------------------------------------------------------- #
# The log, the escalations, the narration
# --------------------------------------------------------------------------- #

LogKind = Literal["tick", "read_planned", "supplied", "requested", "auto_accepted", "escalated", "resumed", "refused", "stopped", "narrated"]
EscalationReason = Literal["above_ceiling", "no_ceiling_row", "second_approver", "human_only", "no_policy", "category_unknown"]


def money(amount: Any, currency: str) -> str:
    """``A$1,250`` -- what the narration says, quantized to cents and only showing them when there are any."""

    value = decimal_value(amount, field_name="amount", allow_negative=True)
    symbol = _CURRENCY_SYMBOLS.get(str(currency).upper(), f"{str(currency).upper()} ")
    return f"{symbol}{value:,.0f}" if value == value.to_integral_value() else f"{symbol}{value:,.2f}"


class OperatorLogEntry(StrictModel):
    at: str
    kind: LogKind
    said: BoundedText
    engine: ShortText | None = None
    entity_ref: OpaqueRef | None = None
    event: ShortText | None = None
    category: ShortText | None = None
    amount: Decimal | None = None
    ceiling: Decimal | None = None
    task_ref: OpaqueRef | None = None
    code: ShortText | None = None

    @field_validator("at")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="at")

    @field_validator("amount", "ceiling", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Any:
        return None if value is None else decimal_value(value, field_name="amount", allow_negative=True)


class OperatorLog(StrictModel):
    """Every minute the operator ran, in the order it ran them."""

    schema_id: Literal["lightbulb.ai_operator_log.v1"] = Field(default=OPERATOR_LOG_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    policy_digest: Sha256Digest
    started_at: str
    entries: tuple[OperatorLogEntry, ...] = Field(default_factory=tuple, max_length=5000)
    auto_accepted: int = Field(default=0, ge=0)
    escalated: int = Field(default=0, ge=0)
    refused: int = Field(default=0, ge=0)
    unattended_spend: Decimal = Field(default=Decimal("0.00"), validate_default=True)
    log_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("started_at")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="started_at")

    @field_validator("unattended_spend", mode="before")
    @classmethod
    def _spend(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="unattended_spend")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> OperatorLog:
        if not skip_digests(info) and self.log_digest != sealed_digest(OperatorLog, self, "log_digest"):
            raise ValueError("log_digest must commit the exact log")
        return self


def narrate(log: OperatorLog | Mapping[str, Any], *, since: str | None = None) -> str:
    """One line per entry, minute by minute, in the operator's own words."""

    parsed_log = log if isinstance(log, OperatorLog) else OperatorLog.model_validate(detached(log))
    floor = timestamp(since, field_name="since") if since else None
    return "\n".join(f"{item.at[11:16]} {item.said}" for item in parsed_log.entries if floor is None or parsed(item.at) >= parsed(floor))


class Escalation(StrictModel):
    """One transition the ceilings did not cover, waiting in a person's inbox."""

    engine: ShortText
    event: ShortText
    entity_ref: OpaqueRef
    category: ShortText | None = None
    amount: Decimal | None = None
    task_id: OpaqueRef | None = None
    assigned_to_ref: OpaqueRef | None = None
    reason: EscalationReason
    raised_at: str

    @field_validator("raised_at")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="raised_at")

    @field_validator("amount", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Any:
        return None if value is None else decimal_value(value, field_name="amount")


class EscalationRegister(StrictModel):
    """What is waiting on a person, sealed, for the brief and the board pack."""

    schema_id: Literal["lightbulb.ai_operator_escalation_register.v1"] = Field(default=OPERATOR_ESCALATION_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    policy_digest: Sha256Digest
    rendered_at: str
    open_escalations: tuple[Escalation, ...] = Field(default_factory=tuple, max_length=200)
    settled: tuple[Escalation, ...] = Field(default_factory=tuple, max_length=200)
    register_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("rendered_at")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="rendered_at")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> EscalationRegister:
        if not skip_digests(info) and self.register_digest != sealed_digest(EscalationRegister, self, "register_digest"):
            raise ValueError("register_digest must commit the exact register")
        return self


class AutoAcceptedTransition(StrictModel):
    """A transition the approver's standing rule accepted, and the proof it was inside the ceiling."""

    engine: ShortText
    event: ShortText
    entity_ref: OpaqueRef
    category: ShortText
    amount: Decimal
    proof_digest: Sha256Digest
    task_id: OpaqueRef

    @field_validator("amount", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="amount")


class OperatorTick(StrictModel):
    """What one minute did."""

    schema_id: Literal["lightbulb.ai_operator_tick.v1"] = Field(default=OPERATOR_TICK_SCHEMA, alias="schema")
    at: str
    auto_accepted: int = Field(default=0, ge=0)
    escalations: int = Field(default=0, ge=0)
    resumed: int = Field(default=0, ge=0)
    refused: int = Field(default=0, ge=0)
    policy_digest: Sha256Digest
    tick_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("at")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="at")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> OperatorTick:
        if not skip_digests(info) and self.tick_digest != sealed_digest(OperatorTick, self, "tick_digest"):
            raise ValueError("tick_digest must commit the exact tick")
        return self


# --------------------------------------------------------------------------- #
# The loop
# --------------------------------------------------------------------------- #


def _short(value: str, *, keep: int = 4) -> str:
    return f"{value[:keep]}…" if len(value) > keep else value


class OperatorLoop:
    """The minute: request every transition with its authority, resume what came back accepted, escalate the rest.

    The loop installs itself on every runtime the cadence runner holds: a
    ``request_decorator`` that stamps the category and the money on the
    approval request, and an ``approval_requester`` that sends it and, when the
    platform says the approver's standing rule already accepted it, resumes the
    engine there and then (``EngineRuntime.advance_and_persist`` discards the
    requester's return, and the inbox lists only ``PENDING`` tasks, so an
    auto-accepted transition would otherwise stay parked forever).
    """

    def __init__(
        self,
        runner: Any,
        client: Any,
        policy: OperatorPolicy,
        matrix: AuthorityMatrix | Mapping[str, Any],
        adoption: MatrixAdoption | Mapping[str, Any],
        *,
        requester_ref: str,
        clock: Callable[[], str],
        cost_register_loader: Callable[[], Any] | None = None,
    ) -> None:
        self.runner, self.client, self.policy = runner, client, policy
        self.matrix = AuthorityMatrix.model_validate(detached(matrix))
        self.adoption = MatrixAdoption.model_validate(detached(adoption))
        self.requester_ref, self.clock, self.cost_register_loader = requester_ref, clock, cost_register_loader
        self.started_at = timestamp(clock(), field_name="started_at")
        self.entries: list[OperatorLogEntry] = []
        self.escalations: list[Escalation] = []
        self.settled: list[Escalation] = []
        self.proofs: list[AuthorizationProof] = []
        self.accepted: list[AutoAcceptedTransition] = []
        self.exceptions: list[dict[str, Any]] = []
        self.unattended_spend = Decimal("0.00")
        self._open: dict[str, tuple[Escalation, Any, str]] = {}
        self._stale_notified: set[str] = set()
        self._accepts_today: dict[str, int] = {}
        #: Escalations *raised*, ever.  ``len(self.escalations)`` is what is still
        #: open, so a minute that raises one and settles another moves it by zero.
        self._raised = 0
        self._now = self.started_at
        self._blocked = False
        self._resuming = False
        self._spend_capped = False
        self._last_read_at: str | None = None
        self._install()

    # -- installation ------------------------------------------------------- #

    def _install(self) -> None:
        for runtime in self.runner.runtimes.values():
            runtime.request_decorator = self._decorator(runtime)
            runtime.approval_requester = self._requester(runtime)

    def _decorator(self, runtime: Any) -> Callable[[EngineApprovalRequest, Mapping[str, Any]], Any]:
        def decorate(request: EngineApprovalRequest, command: Mapping[str, Any]) -> Any:
            try:
                state = runtime.load(str(request.entity_ref))
            except (LookupError, ValueError):
                state = None
            try:
                category, amount, human_only = transition_authority(str(request.engine), str(request.event), command, state, plan=runtime.plan)
            except AiOperatorError as exc:
                self._say("escalated", f"{request.engine}.{request.event} {request.entity_ref}: {exc.code.lower()}, escalated to the approver", engine=str(request.engine), event=str(request.event), entity_ref=str(request.entity_ref), code=exc.code)
                return decorate_request(request, category=None, amount=None, currency=self.policy.currency, human_only=True)
            forced = human_only or self._spend_capped or self._accepts_today.get(self._now[:10], 0) >= self.policy.daily_auto_accept_limit
            if not human_only and forced:
                code = "UNATTENDED_SPEND_CAP_REACHED" if self._spend_capped else "DECISION_DAY_LIMIT"
                self._say("escalated", f"{request.engine}.{request.event} {request.entity_ref}: {code.lower()}, this request goes to the approver", engine=str(request.engine), event=str(request.event), entity_ref=str(request.entity_ref), category=category, amount=amount, code=code)
            return decorate_request(request, category=category, amount=amount, currency=self.policy.currency, human_only=forced)

        return decorate

    def _requester(self, runtime: Any) -> Callable[[Any], Mapping[str, Any]]:
        def request(payload: Any) -> Mapping[str, Any]:
            return self._request(runtime, payload)

        return request

    # -- log ---------------------------------------------------------------- #

    def _say(self, kind: str, said: str, **fields: Any) -> None:
        self.entries.append(OperatorLogEntry.model_validate({"at": self._now, "kind": kind, "said": said[:4000], **{key: value for key, value in fields.items() if value is not None}}))

    @property
    def log(self) -> OperatorLog:
        counts = {kind: sum(1 for item in self.entries if item.kind == kind) for kind in ("auto_accepted", "escalated", "refused")}
        return seal(OperatorLog, {"company_ref": self.policy.company_ref, "policy_digest": self.policy.policy_digest, "started_at": self.started_at, "entries": tuple(item.to_dict() for item in self.entries), "auto_accepted": counts["auto_accepted"], "escalated": counts["escalated"], "refused": counts["refused"], "unattended_spend": str(self.unattended_spend)}, "log_digest")

    def register(self, *, now: str | None = None) -> EscalationRegister:
        rendered = timestamp(now or self._now, field_name="now")
        return seal(EscalationRegister, {"company_ref": self.policy.company_ref, "policy_digest": self.policy.policy_digest, "rendered_at": rendered, "open_escalations": tuple(item.to_dict() for item in self.escalations), "settled": tuple(item.to_dict() for item in self.settled)}, "register_digest")

    def narrated(self, *, since: str | None = None) -> str:
        return narrate(self.log, since=since)

    # -- requesting --------------------------------------------------------- #

    def _request(self, runtime: Any, payload: Any) -> Mapping[str, Any]:
        decorated = _decorated(payload) if not isinstance(payload, EngineApprovalRequest) else decorate_request(payload, category=None, amount=None, currency=self.policy.currency, human_only=True)
        request = decorated.request
        engine, event, entity_ref = str(request.engine), str(request.event), str(request.entity_ref)
        amount = Decimal(decorated.amount_cents or 0) / 100
        if self._resuming:
            self._say("refused", f"{engine}.{event} {entity_ref}: the re-issued command still needs a decision; left with the approver", engine=engine, event=event, entity_ref=entity_ref, code="APPROVAL_REQUIRED")
            return {}
        if self._blocked:
            self._say("stopped", f"{engine}.{event} {entity_ref}: {len(self.escalations)} escalations already open, no further requests this minute", engine=engine, event=event, entity_ref=entity_ref, code="ESCALATION_BACKLOG")
            return {}
        task = dict(self.client.request_engine_transition_approval(decorated) or {})
        task_id = str(task.get("id") or "")
        self._say("requested", f"{engine}.{event} {entity_ref} {money(amount, self.policy.currency)}: requested as {decorated.category or 'no category'}", engine=engine, event=event, entity_ref=entity_ref, category=decorated.category, amount=amount, task_ref=task_id or None)
        context = dict(task.get("contextData") or {})
        if str(task.get("status") or "").upper() == "APPROVED" and bool(context.get("auto_accepted")):
            self._accept(runtime, decorated, task, amount=amount)
        else:
            self._escalate(runtime, decorated, task, amount=amount, context=context)
        return task

    def _accept(self, runtime: Any, decorated: DecoratedApprovalRequest, task: Mapping[str, Any], *, amount: Decimal) -> None:
        request = decorated.request
        engine, event, entity_ref = str(request.engine), str(request.event), str(request.entity_ref)
        transition_ref = str(request.transition_ref)
        ceiling = self.policy.ceiling_for(engine, event)
        try:
            proof = operator_authorization(task, decorated, policy=self.policy, matrix=self.matrix, adoption=self.adoption, requester_ref=self.requester_ref, command=runtime.pending_commands.get(transition_ref), prior_proofs=tuple(self.proofs), now=self._now)
        except (AiOperatorError, AuthorityMatrixError, BridgeError, ValidationError, ValueError) as exc:
            code = str(getattr(exc, "code", "APPROVAL_NOT_BOUND"))
            self.exceptions.append(authority_exception(exc, source_engine=engine, source_ref=f"{engine}:{entity_ref}:{transition_ref}", category=decorated.category))
            self._say("refused", f"{engine}.{event} {entity_ref}: the platform accepted it but the sealed policy did not ({code}); opened an exceptions-desk case", engine=engine, event=event, entity_ref=entity_ref, category=decorated.category, amount=amount, task_ref=str(task.get("id") or "") or None, code=code)
            return
        self.proofs.append(proof)
        resumed = self._resume(runtime, transition_ref, task, proof)
        ceiling_text = money(ceiling.max_amount, self.policy.currency) if ceiling is not None else "the"
        tail = f", resumed to {resumed}" if resumed else ", the engine did not resume"
        self._say("auto_accepted", f"{engine}.{event} {entity_ref} {money(amount, self.policy.currency)} under the {ceiling_text} {decorated.category} ceiling: auto-accepted by the approver's standing rule (task {_short(str(task.get('id') or ''))}){tail}", engine=engine, event=event, entity_ref=entity_ref, category=decorated.category, amount=amount, ceiling=ceiling.max_amount if ceiling else None, task_ref=str(task.get("id") or "") or None)
        if resumed:
            self._say("resumed", f"{engine}.{event} {entity_ref}: resumed to {resumed}", engine=engine, event=event, entity_ref=entity_ref, task_ref=str(task.get("id") or "") or None)
        self.accepted.append(AutoAcceptedTransition.model_validate({"engine": engine, "event": event, "entity_ref": entity_ref, "category": str(decorated.category), "amount": str(amount), "proof_digest": proof.proof_digest, "task_id": proof.approval_task_id}))
        self._accepts_today[self._now[:10]] = self._accepts_today.get(self._now[:10], 0) + 1

    def _resume(self, runtime: Any, transition_ref: str, task: Mapping[str, Any], proof: AuthorizationProof) -> str | None:
        self._resuming = True
        try:
            outcome = runtime.resume_pending(transition_ref, dict(task), occurred_at=self._now, authorization_proof=proof)
        except (LookupError, ValueError) as exc:
            self._say("refused", f"the engine could not resume {transition_ref}: {exc}"[:900], code="RESUME_REFUSED")
            return None
        finally:
            self._resuming = False
        if not outcome.persisted or outcome.record is None:
            return None
        return f"{outcome.record['status']} v{outcome.record['version']}"

    def _escalate(self, runtime: Any, decorated: DecoratedApprovalRequest, task: Mapping[str, Any], *, amount: Decimal, context: Mapping[str, Any]) -> None:
        request = decorated.request
        engine, event, entity_ref = str(request.engine), str(request.event), str(request.entity_ref)
        ceiling = self.policy.ceiling_for(engine, event)
        if decorated.category is None:
            reason = "category_unknown"
        elif str(context.get("operator_ceiling") or "") == "none" or ceiling is None:
            reason = "no_ceiling_row"
        elif bool(context.get("second_approver_required")) or (ceiling is not None and ceiling.requires_second_approver):
            reason = "second_approver"
        elif bool(context.get("human_only")) or decorated.human_only or (ceiling is not None and ceiling.human_only):
            reason = "human_only"
        elif not context.get("operator_policy_id"):
            reason = "no_policy"
        else:
            reason = "above_ceiling"
        task_id = str(task.get("id") or "") or None
        escalation = Escalation.model_validate({"engine": engine, "event": event, "entity_ref": entity_ref, "category": decorated.category, "amount": str(amount), "task_id": task_id, "assigned_to_ref": str(task.get("assignedToRef") or self.policy.approver_ref), "reason": reason, "raised_at": self._now})
        self.escalations.append(escalation)
        self._raised += 1
        if task_id is not None:
            self._open[task_id] = (escalation, runtime, str(request.transition_ref))
        said = {
            "human_only": f"{engine}.{event} {entity_ref}: human-only, waiting",
            "no_ceiling_row": f"{engine}.{event} {entity_ref} {money(amount, self.policy.currency)}: no {decorated.category} ceiling row, escalated to the approver",
            "second_approver": f"{engine}.{event} {entity_ref} {money(amount, self.policy.currency)}: needs a second approver, escalated to the approver",
            "no_policy": f"{engine}.{event} {entity_ref} {money(amount, self.policy.currency)}: no operator policy at the platform, escalated to the approver",
            "category_unknown": f"{engine}.{event} {entity_ref}: no authority category, escalated to the approver",
        }.get(reason, f"{engine}.{event} {entity_ref} {money(amount, self.policy.currency)} above the {money(ceiling.max_amount, self.policy.currency) if ceiling else 'sealed'} {decorated.category} ceiling: escalated to the approver, expires {request.expires_in_hours}h")
        self._say("escalated", said, engine=engine, event=event, entity_ref=entity_ref, category=decorated.category, amount=amount, ceiling=ceiling.max_amount if ceiling else None, task_ref=task_id, code=reason.upper())

    # -- draining ----------------------------------------------------------- #

    def _drain(self) -> None:
        for task_id in list(self._open):
            escalation, runtime, transition_ref = self._open[task_id]
            task = dict(self.client.get_approval(task_id) or {})
            status = str(task.get("status") or "PENDING").upper()
            if status == "APPROVED":
                decorated = self._pending_decorated(runtime, transition_ref, escalation)
                if decorated is None:
                    continue
                try:
                    proof = operator_authorization(task, decorated, policy=self.policy, matrix=self.matrix, adoption=self.adoption, requester_ref=self.requester_ref, command=runtime.pending_commands.get(transition_ref), prior_proofs=tuple(self.proofs), now=self._now)
                except (AiOperatorError, AuthorityMatrixError, BridgeError, ValidationError, ValueError) as exc:
                    code = str(getattr(exc, "code", "APPROVAL_NOT_BOUND"))
                    self.exceptions.append(authority_exception(exc, source_engine=escalation.engine, source_ref=f"{escalation.engine}:{escalation.entity_ref}:{transition_ref}", category=escalation.category))
                    self._say("refused", f"{escalation.engine}.{escalation.event} {escalation.entity_ref}: the approver's decision did not authorize it ({code})", engine=escalation.engine, event=escalation.event, entity_ref=escalation.entity_ref, task_ref=task_id, code=code)
                    self._settle(task_id)
                    continue
                self.proofs.append(proof)
                resumed = self._resume(runtime, transition_ref, task, proof)
                self._say("resumed", f"{escalation.engine}.{escalation.event} {escalation.entity_ref}: the approver decided it (task {_short(task_id)})" + (f", resumed to {resumed}" if resumed else ", the engine did not resume"), engine=escalation.engine, event=escalation.event, entity_ref=escalation.entity_ref, category=escalation.category, amount=escalation.amount, task_ref=task_id)
                self._settle(task_id)
            elif status in ("REJECTED", "EXPIRED", "CANCELLED"):
                runtime.pending.pop(transition_ref, None)
                runtime.pending_commands.pop(transition_ref, None)
                error = AuthorityMatrixError("APPROVAL_NOT_APPROVED", f"the approver {status.lower()} {escalation.engine}.{escalation.event} on {escalation.entity_ref}")
                self.exceptions.append(authority_exception(error, source_engine=escalation.engine, source_ref=f"{escalation.engine}:{escalation.entity_ref}:{transition_ref}", category=escalation.category))
                self._say("refused", f"{escalation.engine}.{escalation.event} {escalation.entity_ref}: the approver {status.lower()} it; the entity stays where it is", engine=escalation.engine, event=escalation.event, entity_ref=escalation.entity_ref, category=escalation.category, task_ref=task_id, code=status)
                self._settle(task_id)
            elif task_id not in self._stale_notified and parsed(self._now) - parsed(escalation.raised_at) >= timedelta(hours=self.policy.escalation_stale_hours):
                self._stale_notified.add(task_id)
                self._say("escalated", f"{escalation.engine}.{escalation.event} {escalation.entity_ref}: still undecided after {self.policy.escalation_stale_hours}h", engine=escalation.engine, event=escalation.event, entity_ref=escalation.entity_ref, category=escalation.category, task_ref=task_id, code="APPROVAL_STALE")

    def _pending_decorated(self, runtime: Any, transition_ref: str, escalation: Escalation) -> DecoratedApprovalRequest | None:
        request = runtime.pending.get(transition_ref)
        if request is None:
            return None
        return decorate_request(request, category=escalation.category, amount=escalation.amount or Decimal("0"), currency=self.policy.currency, human_only=False)

    def _settle(self, task_id: str) -> None:
        escalation, _, _ = self._open.pop(task_id)
        if escalation in self.escalations:
            self.escalations.remove(escalation)
        self.settled.append(escalation)

    # -- the minute --------------------------------------------------------- #

    def minute(self, now: str | None = None) -> OperatorTick:
        """One unattended minute: drain, plan the reads, tick, fence the spend, narrate."""

        self._now = timestamp(now or self.clock(), field_name="now")
        before = {"auto": len(self.accepted), "esc": self._raised, "res": sum(1 for item in self.entries if item.kind == "resumed"), "ref": sum(1 for item in self.entries if item.kind == "refused")}
        # A runtime registered after the loop started (a late lifecycle, another
        # engine bound into the runner) must not be able to ask the platform
        # without its authority category; installing is idempotent.
        self._install()
        if not self.policy.in_window(self._now):
            self._say("stopped", f"outside the unattended window {self.policy.unattended_window}; nothing requested", code="OUTSIDE_UNATTENDED_WINDOW")
            return self._tick(before)
        self._drain()
        plan = self.runner.plan(now=self._now)
        self._plan_reads(plan)
        self._blocked = len(self.escalations) >= ESCALATION_BACKLOG_LIMIT
        if self._blocked:
            self._say("stopped", f"{len(self.escalations)} escalations are open; no further requests until a person clears them", code="ESCALATION_BACKLOG")
        inputs = [{"action_id": action.action_id, "receipt": {}} for action in plan.actions if action.mode == "needs_approval"]
        result = self.runner.tick(now=self._now, inputs=inputs)
        self._say("tick", f"{len(result.applied)} action(s) applied, {len(result.outstanding)} outstanding, {len(result.approvals_pending)} awaiting a decision", code=None)
        self._fence()
        tick = self._tick(before)
        self._say("narrated", f"minute closed: {tick.auto_accepted} auto-accepted, {tick.escalations} escalated, {tick.resumed} resumed, {tick.refused} refused, {money(self.unattended_spend, self.policy.currency)} unattended spend")
        return tick

    def tick(self, now: str | None = None) -> OperatorTick:
        """:meth:`minute`, under the name the console verb uses."""

        return self.minute(now)

    def run(self, *, minutes: int = 1, now: str | None = None) -> tuple[OperatorTick, ...]:
        stamp = timestamp(now or self.clock(), field_name="now")
        ticks: list[OperatorTick] = []
        for index in range(max(1, min(1440, minutes))):
            ticks.append(self.minute(iso(parsed(stamp) + timedelta(minutes=index))))
        return tuple(ticks)

    def _tick(self, before: Mapping[str, int]) -> OperatorTick:
        resumed = sum(1 for item in self.entries if item.kind == "resumed") - int(before["res"])
        refused = sum(1 for item in self.entries if item.kind == "refused") - int(before["ref"])
        return seal(OperatorTick, {"at": self._now, "auto_accepted": len(self.accepted) - int(before["auto"]), "escalations": max(0, self._raised - int(before["esc"])), "resumed": max(0, resumed), "refused": max(0, refused), "policy_digest": self.policy.policy_digest}, "tick_digest")

    def _plan_reads(self, plan: Any) -> None:
        from lightbulb.company_observation_jobs import plan_observation_jobs

        window_start = self._last_read_at or self.started_at
        if parsed(window_start) >= parsed(self._now):
            return
        try:
            jobs = plan_observation_jobs(self.runner.bundle, plan, window_start=window_start, window_end=self._now)
        except ValueError:
            return
        self._last_read_at = self._now
        if not jobs.jobs:
            return
        self._say("read_planned", f"{len(jobs.jobs)} read(s) planned for the platform: {', '.join(sorted({job.tool for job in jobs.jobs}))}", code=None)

    def _fence(self) -> None:
        if self.cost_register_loader is None:
            return
        register = self.cost_register_loader()
        ledger = _field(register, "ledger") if not isinstance(register, Mapping) else (register.get("ledger") or register)
        engine_spend = _field(ledger, "engine_spend") or {}
        labour = _field(ledger, "labour_spend") or 0
        total = sum((decimal_value(value, field_name="engine_spend") for value in dict(engine_spend).values()), Decimal("0")) + decimal_value(labour, field_name="labour_spend")
        self.unattended_spend = total.quantize(MONEY_QUANTUM)
        limit = self.policy.daily_amount_limit
        if limit is not None and self.unattended_spend > limit and not self._spend_capped:
            self._spend_capped = True
            self.exceptions.append({"kind": "tick_rejection", "source_engine": OPERATOR_KIND, "source_ref": f"{OPERATOR_KIND}:{self.policy.company_ref}", "source_digest": stable_digest({"policy": self.policy.policy_digest, "spend": str(self.unattended_spend)}), "code": "UNATTENDED_SPEND_CAP_REACHED", "detail": f"unattended spend {self.unattended_spend} passed the {limit} daily limit; every later request this period goes to the approver", "evidence_refs": [f"policy:{self.policy.policy_digest[:16]}"]})
            self._say("stopped", f"unattended spend {money(self.unattended_spend, self.policy.currency)} passed the {money(limit, self.policy.currency)} daily limit; every later request goes to the approver", code="UNATTENDED_SPEND_CAP_REACHED")


def operator_summary(loop: OperatorLoop, *, now: str | None = None) -> dict[str, Any]:
    """What the operator did, for the console verb and the daily brief."""

    log = loop.log
    return {
        "company_ref": loop.policy.company_ref,
        "policy_digest": loop.policy.policy_digest,
        "operator_ref": loop.policy.operator_ref,
        "approver_ref": loop.policy.approver_ref,
        "started_at": loop.started_at,
        "auto_accepted": log.auto_accepted,
        "escalated": len(loop.escalations),
        "settled": len(loop.settled),
        "refused": log.refused,
        "unattended_spend": str(loop.unattended_spend),
        "currency": loop.policy.currency,
        "ceilings": [f"{item.engine}.{item.event} <= {item.max_amount}" + (" (human-only)" if item.human_only else "") for item in loop.policy.ceilings],
        "open_escalations": [item.to_dict() for item in loop.escalations],
        "exceptions": list(loop.exceptions),
        "register_digest": loop.register(now=now).register_digest,
        "log_digest": log.log_digest,
    }


AI_OPERATOR_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": OPERATOR_KIND,
    "golden_loop": OPERATOR_GOLDEN_LOOP,
    "stages": ["compile_policy", "activate_policy", "decorate_request", "request", "believe_or_refuse", "resume", "escalate", "drain", "narrate"],
    "artifacts": [OPERATOR_POLICY_SCHEMA, OPERATOR_LOG_SCHEMA, OPERATOR_TICK_SCHEMA, OPERATOR_ESCALATION_SCHEMA],
    "categories": list(AUTHORITY_CATEGORIES),
    "human_only_categories": sorted(HUMAN_ONLY_CATEGORIES),
    "hops": {f"{engine}.{event}": category for category, pairs in DEFAULT_BINDINGS.items() for engine, event in pairs},
    "escalation_reasons": ["above_ceiling", "no_ceiling_row", "second_approver", "human_only", "no_policy", "category_unknown"],
    "guards": [
        "OPERATOR_ROLE_UNKNOWN", "CATEGORY_UNBOUND", "APPROVER_NOT_ON_MATRIX", "OPERATOR_IS_APPROVER", "CEILING_ABOVE_MATRIX", "POLICY_OUTSIDE_MATRIX",
        "AUTHORITY_CATEGORY_UNKNOWN", "AUTHORITY_AMOUNT_UNAVAILABLE", "SELF_DECISION", "OPERATOR_POLICY_MISSING", "OPERATOR_POLICY_DRIFT",
        "AUTHORITY_CATEGORY_MISMATCH", "AUTHORITY_AMOUNT_MISMATCH", "AUTHORITY_CURRENCY_MISMATCH", "OPERATOR_DECISION_MISATTRIBUTED", "CEILING_EXCEEDED_AT_PLATFORM",
        "OUTSIDE_UNATTENDED_WINDOW", "ESCALATION_BACKLOG", "DECISION_DAY_LIMIT", "UNATTENDED_SPEND_CAP_REACHED", "APPROVAL_STALE",
    ],
    "required_connectors": ["lightbulb.sdk_engine_state", "lightbulb.workflow_approvals"],
    "hard_rules": [
        "the operator requests; the approver's ceilings decide; a human decides everything else",
        "an auto-accept above the sealed ceiling is refused by the SDK even though the platform granted it",
        "one platform task authorizes one transition (APPROVAL_REUSED)",
        "hire, termination, wind-down and write-off are human-only at both layers",
        "the operator never holds a credential or an identifier; the client holds the token",
        "every minute is narrated",
    ],
}

#: Only this module's own names.  ``ROOT_EXPORTS`` is one flat dict keyed by
#: name, so a name published from two modules silently resolves to whichever was
#: written last: the ROUND5_SHIM names (``authorize``, ``AuthorityMatrix``,
#: ``AUTHORITY_CATEGORIES``, ...) and ``HUMAN_ONLY_CATEGORIES``, which
#: ``company_execution_bridge`` already publishes, stay module attributes and are
#: deliberately not re-exported from here.
__all__ = [
    "AI_OPERATOR_MANIFEST",
    "DEFAULT_BINDINGS",
    "ESCALATION_BACKLOG_LIMIT",
    "OPERATOR_ESCALATION_SCHEMA",
    "OPERATOR_GOLDEN_LOOP",
    "OPERATOR_KIND",
    "OPERATOR_LOG_SCHEMA",
    "OPERATOR_POLICY_SCHEMA",
    "OPERATOR_TICK_SCHEMA",
    "AiOperatorError",
    "AutoAcceptedTransition",
    "Escalation",
    "EscalationRegister",
    "OperatorCeiling",
    "OperatorLog",
    "OperatorLogEntry",
    "OperatorLoop",
    "OperatorPolicy",
    "OperatorTick",
    "compile_operator_policy",
    "money",
    "narrate",
    "operator_authorization",
    "operator_summary",
    "to_platform_body",
    "transition_authority",
]
