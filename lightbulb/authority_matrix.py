"""The authority matrix: who may approve what, up to how much, and the proof that one approval bound one transition.

Every money hop in the tree asked only whether *an* approval reference was
present.  ``company_operating_system`` applies an above-threshold replan when
``r.approval_ref is not None``, so a model that types ``"approval-required"``
moves the budget; ``company_cadence_runner`` fabricates that exact literal
into a prepared dispatch.  Nothing anywhere checked that the approver held
authority for that amount, that category, or that entity.

This module is not a lifecycle.  It is one sealed operator artifact plus the
enforcement primitives the money hops call:

* :class:`AuthorityMatrix` (``lightbulb.company_authority_matrix.v1``) is an
  explicit operator input that names itself as one (``operator_supplied``):
  rows of ``role x category -> max amount, second approver, segregation``,
  the approvers bound to each role, and a review interval.  It is sealed and
  adopted through a platform task (:func:`adopt_matrix`) before it takes
  effect.
* :func:`bind_authority_approval` turns a *fetched* platform task into an
  ``ApprovalBinding`` through ``company_execution_bridge.bind_approval`` and
  additionally validates ``decided_at`` through ``timestamp()`` (the bridge's
  normalizer can emit ``"...+10:00Z"``, which is not a timestamp).
* :func:`authorize` consumes that binding, the sealed matrix, and the sealed
  command, and seals an :class:`AuthorizationProof`.  A string is never an
  input it accepts.  :func:`require_authorization` is the same guard raising
  ``Rejected`` with the engine recovery disposition, so a money hop can call
  it inside its ``apply`` and emit a rejection receipt.

What it hands to other engines: :func:`authorization_evidence` turns a proof
into the approval fields a hop's ``approve`` receipt already carries, so the
``approval_ref`` an engine records is the id of a platform task that was
proven to authorize *that* transition for *that* amount.  Refusals become
exceptions-desk openings through :func:`authority_exception`.  Nothing here
reads a provider, writes anything, or grants an approval.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationError, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    CurrencyCode,
    OpaqueRef,
    RecoveryDisposition,
    Rejected,
    Sha256Digest,
    ShortText,
    StrictModel,
    decimal_value,
    detached,
    iso,
    parsed,
    seal,
    sealed_digest,
    skip_digests,
    stable_digest,
    timestamp,
    unique,
)
from lightbulb.company_execution_bridge import (
    APPROVAL_BINDING_SCHEMA,
    ENGINE_APPROVAL_TYPE,
    ApprovalBinding,
    BridgeError,
    bind_approval,
)

AUTHORITY_KIND = "authority_matrix"
AUTHORITY_GOLDEN_LOOP = "company.blueprint_to_governed_operating_cadence@0.1.0"
AUTHORITY_MATRIX_SCHEMA = "lightbulb.company_authority_matrix.v1"
AUTHORIZATION_PROOF_SCHEMA = "lightbulb.company_authorization_proof.v1"
MATRIX_ADOPTION_SCHEMA = "lightbulb.company_authority_adoption.v1"

AuthorityCategory = Literal["payable", "payroll", "disbursement", "commitment", "remedy", "payout", "replan", "insurance", "dispatch", "write_off", "pricing", "job_quote", "job_invoice", "people_change", "wind_down"]
AUTHORITY_CATEGORIES: tuple[str, ...] = ("payable", "payroll", "disbursement", "commitment", "remedy", "payout", "replan", "insurance", "dispatch", "write_off", "pricing", "job_quote", "job_invoice", "people_change", "wind_down")
Segregation = Literal["none", "not_requester", "not_preparer", "not_payee"]
SEGREGATION_MODES: tuple[str, ...] = ("none", "not_requester", "not_preparer", "not_payee")

#: The money hops that consume an :class:`AuthorizationProof` instead of a string:
#: ``category -> (module, the engine event the approval must name)``.  The
#: ``dispatch`` category is ``company_workforce``'s ``dispatch`` event for a
#: ``write_with_approval`` effect class; ``write_with_approval`` is the effect
#: class, not an event, so an approval never names it.
ENFORCED_HOPS: dict[str, tuple[str, str]] = {
    "payable": ("payables_chain", "approve"),
    "payroll": ("payroll_run_chain", "approve"),
    "disbursement": ("disbursement_run", "approve"),
    "commitment": ("spend_control_chain", "commit"),
    "remedy": ("refund_and_dispute_chain", "authorize_remedy"),
    "payout": ("payout_chain", "approve"),
    "replan": ("company_operating_system", "replan"),
    "dispatch": ("company_workforce", "dispatch"),
}

RECOVERY_BY_CODE: dict[str, RecoveryDisposition] = {
    "APPROVAL_NOT_BOUND": "correct_input",
    "APPROVAL_NOT_APPROVED": "correct_input",
    "APPROVAL_TASK_TYPE_MISMATCH": "correct_input",
    "APPROVAL_DECIDED_AT_INVALID": "correct_input",
    "APPROVAL_TRANSITION_MISMATCH": "do_not_replay",
    "APPROVER_UNKNOWN": "correct_input",
    "APPROVER_LACKS_AUTHORITY": "await_approval",
    "AUTHORITY_LIMIT_EXCEEDED": "await_approval",
    "SECOND_APPROVER_MISSING": "await_approval",
    "SEGREGATION_VIOLATED": "manual_reconciliation",
    "MATRIX_NOT_EFFECTIVE": "correct_input",
    "MATRIX_NOT_ADOPTED": "await_approval",
    "MATRIX_REVIEW_OVERDUE": "await_approval",
    "APPROVAL_REUSED": "do_not_replay",
    "AUTHORITY_INPUT_INVALID": "correct_input",
}
AUTHORITY_CODES: tuple[str, ...] = tuple(sorted(RECOVERY_BY_CODE))
_MONTH_DAYS = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)


class AuthorityMatrixError(ValueError):
    """A refusal to authorize; carries the rejection code and its recovery disposition."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code, self.message = code, message
        self.recovery: RecoveryDisposition = RECOVERY_BY_CODE.get(code, "correct_input")


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise AuthorityMatrixError(code, message)


def _add_months(stamp: str, months: int) -> str:
    when = parsed(stamp)
    total = when.month - 1 + months
    year, month = when.year + total // 12, total % 12 + 1
    leap = month == 2 and year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
    return iso(when.replace(year=year, month=month, day=min(when.day, _MONTH_DAYS[month - 1] + (1 if leap else 0))))


# --------------------------------------------------------------------------- #
# The sealed operator artifact
# --------------------------------------------------------------------------- #


class AuthorityRow(StrictModel):
    """One grant: this role may approve this category up to this amount, under this segregation."""

    role_ref: OpaqueRef
    category: AuthorityCategory
    max_amount: Decimal
    requires_second_approver: bool = False
    segregation: Segregation = "not_requester"

    @field_validator("max_amount", mode="before")
    @classmethod
    def _amount(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="max_amount")

    @property
    def row_ref(self) -> str:
        return f"{self.role_ref}:{self.category}"


class ApproverBinding(StrictModel):
    """An opaque approver alias bound to one role; never a user identifier."""

    approver_ref: OpaqueRef
    role_ref: OpaqueRef


class AuthorityMatrix(StrictModel):
    """Who may approve what, sealed; an explicit operator input that names itself as one."""

    schema_id: Literal["lightbulb.company_authority_matrix.v1"] = Field(default=AUTHORITY_MATRIX_SCHEMA, alias="schema")
    operator_supplied: Literal[True] = True
    company_ref: OpaqueRef
    currency: CurrencyCode
    effective_from: str
    rows: tuple[AuthorityRow, ...] = Field(min_length=1, max_length=60)
    approvers: tuple[ApproverBinding, ...] = Field(default_factory=tuple, max_length=60)
    blanket_ceiling: Decimal = Field(default=Decimal("0.00"), validate_default=True)
    review_months: int = Field(default=12, ge=1, le=60)
    matrix_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("blanket_ceiling", mode="before")
    @classmethod
    def _ceiling(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="blanket_ceiling")

    @field_validator("effective_from")
    @classmethod
    def _effective(cls, value: str) -> str:
        return timestamp(value, field_name="effective_from")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> AuthorityMatrix:
        unique([row.row_ref for row in self.rows], label="authority rows (role, category)")
        unique([item.approver_ref for item in self.approvers], label="approver bindings")
        roles = {row.role_ref for row in self.rows}
        unknown = sorted({item.role_ref for item in self.approvers} - roles)
        if unknown:
            raise ValueError(f"approvers name roles with no row: {unknown[:3]}")
        if not skip_digests(info) and self.matrix_digest != sealed_digest(AuthorityMatrix, self, "matrix_digest"):
            raise ValueError("matrix_digest must commit the exact matrix")
        return self

    def role_of(self, approver_ref: str) -> str | None:
        return next((item.role_ref for item in self.approvers if item.approver_ref == approver_ref), None)

    def row(self, role_ref: str, category: str) -> AuthorityRow | None:
        return next((item for item in self.rows if item.role_ref == role_ref and item.category == category), None)

    def review_due_at(self) -> str:
        return _add_months(self.effective_from, self.review_months)


def compile_authority_matrix(company_ref: str, *, currency: str, rows: Sequence[Mapping[str, Any] | AuthorityRow], approvers: Sequence[Mapping[str, Any] | ApproverBinding] = (), effective_from: str, overrides: Mapping[str, Any] | None = None) -> AuthorityMatrix:
    """Seal an operator-authored matrix; the digest commits every row, approver, and ceiling."""

    payload = {"company_ref": company_ref, "currency": currency.upper(), "effective_from": effective_from, "rows": [dict(detached(row)) for row in rows], "approvers": [dict(detached(item)) for item in approvers], **dict(overrides or {})}
    return seal(AuthorityMatrix, payload, "matrix_digest")


def _matrix(matrix: AuthorityMatrix | Mapping[str, Any]) -> AuthorityMatrix:
    return AuthorityMatrix.model_validate(detached(matrix))


def matrix_review_due(matrix: AuthorityMatrix | Mapping[str, Any], now: str) -> bool:
    """Has the matrix outlived its review interval by ``now``?"""

    parsed_matrix = _matrix(matrix)
    return parsed(timestamp(now, field_name="now")) >= parsed(parsed_matrix.review_due_at())


# --------------------------------------------------------------------------- #
# Adoption: the matrix itself is approved by a platform task before it bites
# --------------------------------------------------------------------------- #


class MatrixAdoption(StrictModel):
    """The platform decision that put one exact matrix into effect."""

    schema_id: Literal["lightbulb.company_authority_adoption.v1"] = Field(default=MATRIX_ADOPTION_SCHEMA, alias="schema")
    matrix_digest: Sha256Digest
    approval_task_id: OpaqueRef
    approver_ref: OpaqueRef
    decided_at: str
    adoption_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("decided_at")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="decided_at")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> MatrixAdoption:
        if not skip_digests(info) and self.adoption_digest != sealed_digest(MatrixAdoption, self, "adoption_digest"):
            raise ValueError("adoption_digest must commit the exact adoption")
        return self


def _task_decision(task: Mapping[str, Any] | Any) -> tuple[dict[str, Any], str, str, str]:
    raw = dict(detached(task))
    status = str(raw.get("status") or "").upper()
    approved = status == "APPROVED"
    _require(approved, "APPROVAL_NOT_APPROVED", f"the approval task is {status or 'undecided'}, not APPROVED")
    declared = str(raw.get("approvalType") or raw.get("approval_type") or "")
    _require(declared == ENGINE_APPROVAL_TYPE, "APPROVAL_TASK_TYPE_MISMATCH", f"the task declares {declared or 'no approvalType'}, not a {ENGINE_APPROVAL_TYPE} approval")
    task_id = str(raw.get("id") or raw.get("approvalRef") or raw.get("approval_ref") or "")
    decided_by = str(raw.get("decidedBy") or raw.get("decided_by") or "")
    named = bool(task_id) and bool(decided_by)
    _require(named, "APPROVAL_NOT_BOUND", "an approval names its task id and who decided it")
    return raw, task_id, decided_by, _valid_stamp(str(raw.get("decidedAt") or raw.get("decided_at") or ""))


def _valid_stamp(value: str) -> str:
    try:
        return timestamp(value, field_name="decided_at")
    except ValueError as exc:
        raise AuthorityMatrixError("APPROVAL_DECIDED_AT_INVALID", f"decided_at {value!r} is not an ISO-8601 UTC timestamp") from exc


def adopt_matrix(matrix: AuthorityMatrix | Mapping[str, Any], task: Mapping[str, Any] | Any) -> MatrixAdoption:
    """Accept a platform task as the decision that adopts this exact matrix."""

    parsed_matrix = _matrix(matrix)
    raw, task_id, decided_by, decided_at = _task_decision(task)
    context = dict(raw.get("contextData") or raw.get("context") or {})
    commits = str(context.get("matrix_digest", "")) == parsed_matrix.matrix_digest
    _require(commits, "MATRIX_NOT_ADOPTED", "the approval task does not commit this matrix_digest")
    return seal(MatrixAdoption, {"matrix_digest": parsed_matrix.matrix_digest, "approval_task_id": task_id, "approver_ref": decided_by, "decided_at": decided_at}, "adoption_digest")


# --------------------------------------------------------------------------- #
# Binding a fetched platform task to one exact sealed command
# --------------------------------------------------------------------------- #

_BRIDGE_CODES: dict[str, str] = {
    "APPROVAL_NOT_GRANTED": "APPROVAL_NOT_APPROVED",
    "APPROVAL_TYPE_MISMATCH": "APPROVAL_TASK_TYPE_MISMATCH",
    "APPROVAL_BINDING_MISMATCH": "APPROVAL_TRANSITION_MISMATCH",
    "APPROVAL_TASK_INVALID": "APPROVAL_NOT_BOUND",
    "APPROVAL_DECISION_UNATTRIBUTED": "APPROVAL_NOT_BOUND",
}


def bind_authority_approval(task: Mapping[str, Any] | Any, request: Mapping[str, Any] | Any) -> ApprovalBinding:
    """``company_execution_bridge.bind_approval`` with authority codes and a validated ``decided_at``."""

    _task_decision(task)
    try:
        binding = bind_approval(dict(detached(task)), request)
    except BridgeError as exc:
        raise AuthorityMatrixError(_BRIDGE_CODES.get(exc.code, "APPROVAL_NOT_BOUND"), str(exc)) from exc
    _valid_stamp(binding.decided_at)
    return binding


def _bound(value: Any, *, label: str = "approval_binding") -> ApprovalBinding:
    is_mapping = isinstance(value, Mapping) or hasattr(value, "model_dump")
    _require(is_mapping, "APPROVAL_NOT_BOUND", f"{label} is {value!r}; authority is a bound platform decision, never a string a model typed")
    raw = dict(detached(value))
    is_binding = str(raw.get("schema") or raw.get("schema_id") or "") == APPROVAL_BINDING_SCHEMA
    _require(is_binding, "APPROVAL_NOT_BOUND", f"{label} is not an {APPROVAL_BINDING_SCHEMA}; bind the fetched task through bind_authority_approval")
    granted = str(raw.get("task_status") or "").upper() == "APPROVED"
    _require(granted, "APPROVAL_NOT_APPROVED", f"the bound task is {raw.get('task_status') or 'undecided'}, not APPROVED")
    try:
        return ApprovalBinding.model_validate(raw)
    except ValidationError as exc:
        raise AuthorityMatrixError("APPROVAL_NOT_BOUND", f"{label} is not a valid approval binding: {exc.errors()[0].get('msg', 'invalid')}") from exc


# --------------------------------------------------------------------------- #
# The proof
# --------------------------------------------------------------------------- #


class AuthorizationProof(StrictModel):
    """One approval task, proven to authorize one transition for one amount under one row."""

    schema_id: Literal["lightbulb.company_authorization_proof.v1"] = Field(default=AUTHORIZATION_PROOF_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    matrix_digest: Sha256Digest
    plan_digest: Sha256Digest
    row_ref: OpaqueRef
    category: AuthorityCategory
    approval_task_id: OpaqueRef
    approver_ref: OpaqueRef
    role_ref: OpaqueRef
    second_approver_ref: OpaqueRef | None = None
    second_approval_task_id: OpaqueRef | None = None
    decided_at: str
    amount: Decimal
    currency: CurrencyCode
    engine: ShortText
    entity_ref: OpaqueRef
    event: ShortText
    transition_ref: OpaqueRef
    idempotency_key: OpaqueRef
    request_digest: Sha256Digest
    approval_receipt_digest: Sha256Digest
    requester_ref: OpaqueRef | None = None
    preparer_ref: OpaqueRef | None = None
    payee_ref: OpaqueRef | None = None
    source_matrix: AuthorityMatrix
    source_adoption: MatrixAdoption
    source_binding: ApprovalBinding
    source_second_approval: ApprovalBinding | None = None
    approved_command: dict[str, Any]
    proof_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("amount", mode="before")
    @classmethod
    def _amount(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="amount")

    @field_validator("decided_at")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="decided_at")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> AuthorizationProof:
        if self.second_approver_ref is not None and self.second_approver_ref == self.approver_ref:
            raise ValueError("a second approver is a different person")
        if (self.second_approver_ref is None) != (self.second_approval_task_id is None):
            raise ValueError("a second approver is named by the platform task that carried their decision")
        if self.second_approval_task_id is not None and self.second_approval_task_id == self.approval_task_id:
            raise ValueError("one platform task carries one decision; a second approver decides their own task")
        if not skip_digests(info) and self.proof_digest != sealed_digest(AuthorizationProof, self, "proof_digest"):
            raise ValueError("proof_digest must commit the exact proof")
        return self


class AuthorityEffectBoundary(StrictModel):
    """Authorizing decides nothing on a provider and grants no approval; it only proves one was held."""

    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    approval_granted: Literal[False] = False
    payment_sent: Literal[False] = False
    provider_read: Literal[False] = False


def _grant(matrix: AuthorityMatrix, approver_ref: str, category: str, amount: Decimal, *, label: str) -> tuple[str, str, AuthorityRow | None]:
    """The (role, row_ref, row) an approver holds for a category; refuses an unknown approver or an ungranted category."""

    role = matrix.role_of(approver_ref)
    _require(role is not None, "APPROVER_UNKNOWN", f"{label} {approver_ref} is bound to no role in this matrix")
    assert role is not None
    row = matrix.row(role, category)
    if row is None:
        covered = matrix.blanket_ceiling > 0 and amount <= matrix.blanket_ceiling
        _require(covered, "APPROVER_LACKS_AUTHORITY", f"{role} holds no {category} row and the blanket ceiling {matrix.blanket_ceiling} does not cover {amount}")
        return role, f"blanket:{category}", None
    within = amount <= row.max_amount
    _require(within, "AUTHORITY_LIMIT_EXCEEDED", f"{role} may approve {category} up to {row.max_amount}; this is {amount}")
    return role, row.row_ref, row


def _segregation(row: AuthorityRow | None, approver_ref: str, *, requester_ref: str | None, preparer_ref: str | None, payee_ref: str | None, label: str) -> None:
    mode = row.segregation if row is not None else "not_requester"
    if mode == "none":
        return
    party = {"not_requester": ("requester", requester_ref), "not_preparer": ("preparer", preparer_ref), "not_payee": ("payee", payee_ref)}[mode]
    name, ref = party
    _require(ref is not None, "SEGREGATION_VIOLATED", f"the row forbids the {name} approving; name the {name} so it can be checked")
    _require(ref != approver_ref, "SEGREGATION_VIOLATED", f"{label} {approver_ref} is the {name} of this transaction")


def _proof(value: AuthorizationProof | Mapping[str, Any]) -> AuthorizationProof:
    try:
        proof = AuthorizationProof.model_validate(detached(value))
    except (ValueError, TypeError) as exc:
        raise AuthorityMatrixError("APPROVAL_NOT_BOUND", "approval evidence must be a valid sealed AuthorizationProof") from exc
    issued = authorize(proof.source_matrix, category=proof.category, amount=proof.amount, currency=proof.currency, approval_binding=proof.source_binding, adoption=proof.source_adoption, command=proof.approved_command, second_approval=proof.source_second_approval, requester_ref=proof.requester_ref, preparer_ref=proof.preparer_ref, payee_ref=proof.payee_ref)
    _require(issued.proof_digest == proof.proof_digest, "APPROVAL_NOT_BOUND", "proof claims must match their retained matrix, adoption, binding, and command")
    return proof


def _reuse(binding: ApprovalBinding, prior_proofs: Sequence[AuthorizationProof | Mapping[str, Any]], *, matrix: AuthorityMatrix, category: str, amount: Decimal, label: str = "approval") -> None:
    """One platform task authorizes one transition, for one category, for one amount -- as a first or a second approval."""

    for item in prior_proofs:
        prior = _proof(item)
        if binding.approval_ref not in {prior.approval_task_id, prior.second_approval_task_id}:
            continue
        same = (prior.engine, prior.event, prior.transition_ref, prior.idempotency_key, prior.entity_ref, prior.plan_digest, prior.request_digest) == (binding.engine, binding.event, binding.transition_ref, binding.idempotency_key, binding.entity_ref, binding.plan_digest, binding.request_digest)
        _require(same, "APPROVAL_REUSED", f"{label} task {binding.approval_ref} already authorized {prior.entity_ref} {prior.transition_ref}; one approval authorizes one transition")
        unchanged = (prior.category, prior.amount, prior.currency, prior.matrix_digest) == (category, amount, matrix.currency, matrix.matrix_digest)
        _require(unchanged, "APPROVAL_REUSED", f"{label} task {binding.approval_ref} authorized {prior.amount} of {prior.category} on this transition, not {amount} of {category}")
        decider = prior.approver_ref if prior.approval_task_id == binding.approval_ref else prior.second_approver_ref
        _require(decider == binding.decided_by_ref, "APPROVAL_REUSED", "one approval task cannot be reassigned to a different approver")


class _ApprovedCommand(StrictModel):
    """Portable core command shape; its receipt remains committed business input."""

    schema_id: str = Field(alias="schema")
    event: ShortText
    transition_ref: OpaqueRef
    idempotency_key: OpaqueRef
    expected_version: int = Field(ge=0)
    expected_state_digest: Sha256Digest
    occurred_at: str
    actor_ref: OpaqueRef
    receipt: dict[str, Any]
    reason: str | None = None
    request_digest: Sha256Digest

    @field_validator("occurred_at")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="occurred_at")


def _command(value: Any) -> dict[str, Any]:
    try:
        result = _ApprovedCommand.model_validate(detached(value)).to_dict()
        valid = result["schema"].startswith("lightbulb.") and result["schema"].endswith("_command.v1")
        valid = valid and result["request_digest"] == stable_digest({key: item for key, item in result.items() if key != "request_digest"})
        _require(valid, "APPROVAL_TRANSITION_MISMATCH", "approval requires the exact normalized sealed engine command")
        return result
    except (TypeError, ValueError) as exc:
        if isinstance(exc, AuthorityMatrixError):
            raise
        raise AuthorityMatrixError("APPROVAL_TRANSITION_MISMATCH", "approval requires a complete sealed engine command") from exc


def authorize(
    matrix: AuthorityMatrix | Mapping[str, Any],
    *,
    category: str,
    amount: Any,
    currency: str,
    approval_binding: Any,
    requester_ref: str | None = None,
    preparer_ref: str | None = None,
    payee_ref: str | None = None,
    second_approval: Any = None,
    command: Mapping[str, Any] | Any | None = None,
    prior_proofs: Sequence[AuthorizationProof | Mapping[str, Any]] = (),
    adoption: MatrixAdoption | Mapping[str, Any] | None = None,
    now: str | None = None,
) -> AuthorizationProof:
    """Seal the proof that this bound approval authorized this exact transition, or refuse with an authority code.

    ``amount`` and ``currency`` are the transaction's own money as the calling
    engine's sealed ledger holds it, never a number an operator types alongside
    the approval; a limit denominated in the matrix's currency cannot be
    compared with an amount in another, so a mismatch is refused rather than
    assumed away.
    """

    parsed_matrix = _matrix(matrix)
    binding = _bound(approval_binding)
    decided_at = _valid_stamp(binding.decided_at)
    _require(adoption is not None, "MATRIX_NOT_ADOPTED", "the matrix must be adopted by a platform approval task before it grants authority")
    try:
        parsed_adoption = MatrixAdoption.model_validate(detached(adoption))
    except (ValueError, TypeError) as exc:
        raise AuthorityMatrixError("MATRIX_NOT_ADOPTED", "matrix adoption must be a valid sealed platform decision") from exc
    adopted = parsed_adoption.matrix_digest == parsed_matrix.matrix_digest
    _require(adopted, "MATRIX_NOT_ADOPTED", "the adoption approves a different matrix")
    _require(parsed_adoption.approval_task_id != binding.approval_ref, "APPROVAL_REUSED", "one task cannot both adopt the matrix and approve a money transition")
    raw_command = _command(command)
    binds = tuple(raw_command[key] for key in ("event", "transition_ref", "idempotency_key", "request_digest", "actor_ref")) == (binding.event, binding.transition_ref, binding.idempotency_key, binding.request_digest, binding.actor_ref)
    _require(binds, "APPROVAL_TRANSITION_MISMATCH", f"the approval binds {binding.transition_ref}, the sealed command is {raw_command.get('transition_ref')}")
    known_category = category in AUTHORITY_CATEGORIES
    _require(known_category, "APPROVER_LACKS_AUTHORITY", f"{category} is not an authority category; no row can grant it")
    hop = ENFORCED_HOPS.get(category)
    additional_hops = {
        "remedy": {("service_delivery", "submit_resolution")},
        "payable": {("spend_control_chain", "approve")},
        "commitment": {("spend_control_chain", name) for name in ("confirm_recurring", "renew", "decide", "renegotiate")} | {("obligation_paper", name) for name in ("give_notice", "renew", "amend")} | {("permission_register", name) for name in ("approve", "renew_evidence")} | {("engagement_engine", "revise_budget")},
        "disbursement": {("disbursement_run", "release_hold")},
        "insurance": {("obligation_paper", "reinstate")},
        "write_off": {("collections_chain", "write_off"), ("subscription_chain", "write_off")},
        "pricing": {("deal_desk_engine", "approve_discount"), ("wip_billing", "approve"), ("job_chain", "quote")},
        "job_quote": {("job_chain", "quote")},
        "job_invoice": {("job_chain", "invoice")},
        "people_change": {("employment_chain", "hire"), ("employment_chain", "initiate_offboarding")},
        "wind_down": {("wind_down_chain", "decide")},
    }
    allowed_hops = additional_hops.get(category, set()) | ({hop} if hop is not None else set())
    if allowed_hops:
        names_the_hop = (binding.engine, binding.event) in allowed_hops
        _require(names_the_hop, "APPROVAL_TRANSITION_MISMATCH", f"the approval was raised for {binding.engine}.{binding.event}; {category} authority must bind one of {sorted(allowed_hops)}")
    same_currency = str(currency).upper() == parsed_matrix.currency
    _require(same_currency, "APPROVER_LACKS_AUTHORITY", f"this matrix grants {parsed_matrix.currency} authority; this transaction is {currency}, and no row is denominated in it")
    effective = parsed(decided_at) >= parsed(parsed_matrix.effective_from)
    _require(effective, "MATRIX_NOT_EFFECTIVE", f"the decision at {decided_at} precedes the matrix effective from {parsed_matrix.effective_from}")
    _require(parsed(decided_at) >= parsed(parsed_adoption.decided_at), "MATRIX_NOT_ADOPTED", "the approval decision predates adoption of this matrix")
    _require(parsed(decided_at) >= parsed(raw_command["occurred_at"]), "APPROVAL_TRANSITION_MISMATCH", "the approval decision predates the command it approves")
    if now is not None:
        _require(parsed(timestamp(now, field_name="now")) >= parsed(decided_at), "APPROVAL_TRANSITION_MISMATCH", "the approval decision is in the future")
    overdue = matrix_review_due(parsed_matrix, timestamp(now, field_name="now") if now else decided_at)
    _require(not overdue, "MATRIX_REVIEW_OVERDUE", f"the matrix was due for review at {parsed_matrix.review_due_at()}")
    value = decimal_value(amount, field_name="amount")
    role, row_ref, row = _grant(parsed_matrix, binding.decided_by_ref, category, value, label="approver")
    _segregation(row, binding.decided_by_ref, requester_ref=requester_ref, preparer_ref=preparer_ref, payee_ref=payee_ref, label="approver")
    second = _second_approver(parsed_matrix, row, binding, category, value, second_approval=second_approval, requester_ref=requester_ref, preparer_ref=preparer_ref, payee_ref=payee_ref)
    if second is not None:
        _require(parsed_adoption.approval_task_id != second.approval_ref, "APPROVAL_REUSED", "the matrix adoption task cannot also be a second money approval")
        second_at = _valid_stamp(second.decided_at)
        _require(parsed(second_at) >= parsed(parsed_matrix.effective_from), "MATRIX_NOT_EFFECTIVE", "the second approval predates the matrix effective date")
        _require(parsed(second_at) >= parsed(parsed_adoption.decided_at), "MATRIX_NOT_ADOPTED", "the second approval predates adoption of the matrix")
        _require(parsed(second_at) >= parsed(raw_command["occurred_at"]), "APPROVAL_TRANSITION_MISMATCH", "the second approval predates the command it approves")
        _require(not matrix_review_due(parsed_matrix, second_at), "MATRIX_REVIEW_OVERDUE", "the matrix was overdue when the second approval was decided")
        if now is not None:
            _require(parsed(timestamp(now, field_name="now")) >= parsed(second_at), "APPROVAL_TRANSITION_MISMATCH", "the second approval decision is in the future")
        decided_at = max((decided_at, second_at), key=parsed)
    _reuse(binding, prior_proofs, matrix=parsed_matrix, category=category, amount=value)
    if second is not None:
        _reuse(second, prior_proofs, matrix=parsed_matrix, category=category, amount=value, label="second approval")
    payload = {"company_ref": parsed_matrix.company_ref, "matrix_digest": parsed_matrix.matrix_digest, "plan_digest": binding.plan_digest, "row_ref": row_ref, "category": category, "approval_task_id": binding.approval_ref, "approver_ref": binding.decided_by_ref, "role_ref": role, "second_approver_ref": second.decided_by_ref if second else None, "second_approval_task_id": second.approval_ref if second else None, "decided_at": decided_at, "amount": str(value), "currency": parsed_matrix.currency, "engine": binding.engine, "entity_ref": binding.entity_ref, "event": binding.event, "transition_ref": binding.transition_ref, "idempotency_key": binding.idempotency_key, "request_digest": binding.request_digest, "approval_receipt_digest": binding.approval_receipt_digest, "requester_ref": requester_ref, "preparer_ref": preparer_ref, "payee_ref": payee_ref, "source_matrix": parsed_matrix, "source_adoption": parsed_adoption, "source_binding": binding, "source_second_approval": second, "approved_command": raw_command}
    return seal(AuthorizationProof, {key: value_ for key, value_ in payload.items() if value_ is not None}, "proof_digest")


def _second_approver(matrix: AuthorityMatrix, row: AuthorityRow | None, binding: ApprovalBinding, category: str, amount: Decimal, *, second_approval: Any, requester_ref: str | None, preparer_ref: str | None, payee_ref: str | None) -> ApprovalBinding | None:
    if row is None or not row.requires_second_approver:
        return None
    supplied = second_approval is not None
    _require(supplied, "SECOND_APPROVER_MISSING", f"the {row.row_ref} row requires a second approver for {amount}")
    second = _bound(second_approval, label="second_approval")
    distinct = second.decided_by_ref != binding.decided_by_ref
    _require(distinct, "SECOND_APPROVER_MISSING", f"{binding.decided_by_ref} cannot be both approvers")
    own_task = second.approval_ref != binding.approval_ref
    _require(own_task, "SECOND_APPROVER_MISSING", f"approval task {binding.approval_ref} carries one decision; a second approver decides their own task")
    fields = ("engine", "entity_ref", "event", "transition_ref", "idempotency_key", "request_digest", "plan_digest", "actor_ref")
    same_transition = all(getattr(second, key) == getattr(binding, key) for key in fields)
    _require(same_transition, "APPROVAL_TRANSITION_MISMATCH", "the second approval binds a different transition")
    _, _, second_row = _grant(matrix, second.decided_by_ref, category, amount, label="second approver")
    _segregation(second_row, second.decided_by_ref, requester_ref=requester_ref, preparer_ref=preparer_ref, payee_ref=payee_ref, label="second approver")
    return second


def require_authorization(matrix: AuthorityMatrix | Mapping[str, Any], **kwargs: Any) -> AuthorizationProof:
    """:func:`authorize` as an engine guard: an authority refusal becomes ``Rejected`` with its recovery disposition.

    A malformed input (an amount that is not a decimal, a matrix that does not
    validate, a ``now`` that is not a timestamp) is a refusal too, not an
    exception that escapes a hop's ``apply`` and loses the rejection receipt.
    """

    try:
        return authorize(matrix, **kwargs)
    except AuthorityMatrixError as exc:
        raise Rejected(exc.code, exc.message, exc.recovery) from exc
    except (ValueError, TypeError) as exc:
        raise Rejected("AUTHORITY_INPUT_INVALID", f"the authorization inputs are not well formed: {exc}"[:300], RECOVERY_BY_CODE["AUTHORITY_INPUT_INVALID"]) from exc


# --------------------------------------------------------------------------- #
# What the proof hands the money hops
# --------------------------------------------------------------------------- #


_APPROVAL_RECEIPT_FIELDS = frozenset({"authority_proof", "pricing_authority_proof", "pricing_authorization_proof", "authorization_proof", "approval_ref", "approver_ref", "approved_at", "approved_amount"})


def _business_command(command: dict[str, Any], proof: AuthorizationProof) -> dict[str, Any]:
    """Remove only supplied authority metadata; every business field stays committed."""

    receipt = {key: value for key, value in command["receipt"].items() if key not in _APPROVAL_RECEIPT_FIELDS}
    if proof.engine == "company_workforce" and command["event"] == "dispatch":
        # The post-execution journal output is checked against the exact
        # approved dispatch intent by the workforce guard; it cannot exist
        # when the human approves that intent.
        receipt.pop("dispatch_observation", None)
    proof_refs = {f"authority:{proof.proof_digest[:16]}", f"approval:{proof.approval_task_id}"}
    # A priced job may require two independent decisions on the same business
    # command. Their evidence references are authority metadata too; each
    # consuming guard separately verifies the corresponding complete proof.
    for field in ("authorization_proof", "pricing_authorization_proof"):
        supplied = command["receipt"].get(field)
        if supplied is not None:
            other = _proof(supplied)
            proof_refs.update({f"authority:{other.proof_digest[:16]}", f"approval:{other.approval_task_id}"})
    if "evidence_refs" in receipt:
        receipt["evidence_refs"] = [ref for ref in receipt["evidence_refs"] if ref not in proof_refs]
        if not receipt["evidence_refs"]:
            receipt.pop("evidence_refs")
    return {**{key: value for key, value in command.items() if key not in {"request_digest", "occurred_at", "receipt"}}, "receipt": receipt}


def verify_authorization(
    proof: AuthorizationProof | Mapping[str, Any],
    *,
    category: str,
    proof_field: Literal["authorization_proof", "pricing_authorization_proof"] = "authorization_proof",
    amount: Any,
    currency: str,
    command: Mapping[str, Any] | Any,
    plan_digest: str | None = None,
    company_ref: str | None = None,
    entity_ref: str | None = None,
    requester_ref: str | None = None,
    preparer_ref: str | None = None,
    payee_ref: str | None = None,
    prior_proofs: Sequence[AuthorizationProof | Mapping[str, Any]] = (),
    now: str | None = None,
) -> AuthorizationProof:
    """Verify the retained platform evidence against this exact consuming command.

    Engines supply their ledger amount, plan currency/digest, company label and
    entity alias. The approved command's business payload and state fences are
    immutable; only its approval metadata and later occurrence time may differ.
    The platform must supply the durable company-wide approval history to fence
    reuse across independently persisted entities.
    """

    _require(proof_field in {"authorization_proof", "pricing_authorization_proof"}, "APPROVAL_NOT_BOUND", "unknown authority proof field")
    parsed_proof = _proof(proof)
    raw_command = _command(command)
    _require(parsed_proof.category == category, "APPROVER_LACKS_AUTHORITY", "the proof grants a different authority category")
    _require(parsed_proof.currency == str(currency).upper(), "APPROVER_LACKS_AUTHORITY", "the proof grants authority in a different currency")
    _require(parsed_proof.amount == decimal_value(amount, field_name="amount"), "AUTHORITY_LIMIT_EXCEEDED", "the proof does not authorize the exact ledger amount")
    for label, expected, actual in (("company", company_ref, parsed_proof.company_ref), ("plan", plan_digest, parsed_proof.plan_digest), ("entity", entity_ref, parsed_proof.entity_ref)):
        _require(expected is None or expected == actual, "APPROVAL_TRANSITION_MISMATCH", f"the proof belongs to a different {label}")
    for label, expected, actual in (("requester", requester_ref, parsed_proof.requester_ref), ("preparer", preparer_ref, parsed_proof.preparer_ref), ("payee", payee_ref, parsed_proof.payee_ref)):
        _require(expected is None or expected == actual, "SEGREGATION_VIOLATED", f"the proof names a different {label}")
    issued = authorize(parsed_proof.source_matrix, category=category, amount=amount, currency=currency, approval_binding=parsed_proof.source_binding, adoption=parsed_proof.source_adoption, command=parsed_proof.approved_command, second_approval=parsed_proof.source_second_approval, requester_ref=parsed_proof.requester_ref, preparer_ref=parsed_proof.preparer_ref, payee_ref=parsed_proof.payee_ref, prior_proofs=prior_proofs, now=now or raw_command["occurred_at"])
    _require(issued.proof_digest == parsed_proof.proof_digest, "APPROVAL_NOT_BOUND", "proof claims must match their retained matrix, adoption, binding, and command")
    _require(_business_command(raw_command, parsed_proof) == _business_command(parsed_proof.approved_command, parsed_proof), "APPROVAL_TRANSITION_MISMATCH", "the consuming command differs from the approved business transition or its state fences")
    _require(parsed(raw_command["occurred_at"]) >= parsed(parsed_proof.decided_at), "APPROVAL_TRANSITION_MISMATCH", "the consuming transition predates its approval")
    receipt = raw_command["receipt"]
    expected_metadata = {"approval_ref": parsed_proof.approval_task_id, "approver_ref": parsed_proof.approver_ref, "approved_at": parsed_proof.decided_at, "approved_amount": str(parsed_proof.amount)}
    for key, expected in expected_metadata.items():
        _require(key not in receipt or receipt[key] == expected, "APPROVAL_NOT_BOUND", f"{key} differs from the retained proof")
    if receipt.get(proof_field) is not None:
        _require(_proof(receipt[proof_field]).proof_digest == parsed_proof.proof_digest, "APPROVAL_NOT_BOUND", "receipt contains a different authorization proof")
    return parsed_proof


def require_authorization_proof(proof: AuthorizationProof | Mapping[str, Any], **kwargs: Any) -> AuthorizationProof:
    """:func:`verify_authorization` as a lifecycle guard with stable recovery codes."""

    try:
        return verify_authorization(proof, **kwargs)
    except AuthorityMatrixError as exc:
        raise Rejected(exc.code, exc.message, exc.recovery) from exc
    except (ValueError, TypeError) as exc:
        raise Rejected("AUTHORITY_INPUT_INVALID", f"the proof inputs are not well formed: {exc}"[:300], "correct_input") from exc


def authorization_evidence(proof: AuthorizationProof | Mapping[str, Any], *, requester_ref: str | None = None) -> dict[str, Any]:
    """The approval fields a money hop's ``approve`` receipt carries, sourced from the proof rather than typed."""

    parsed_proof = _proof(proof)
    _require(requester_ref is None or requester_ref == parsed_proof.requester_ref, "SEGREGATION_VIOLATED", "approval evidence cannot replace the proven requester")
    out: dict[str, Any] = {"authorization_proof": parsed_proof.to_dict(), "approval_ref": parsed_proof.approval_task_id, "approver_ref": parsed_proof.approver_ref, "approved_at": parsed_proof.decided_at, "approved_amount": str(parsed_proof.amount), "evidence_refs": [f"authority:{parsed_proof.proof_digest[:16]}", f"approval:{parsed_proof.approval_task_id}"]}
    if requester_ref is not None:
        out["requester_ref"] = requester_ref
    return out


def authority_exception(error: AuthorityMatrixError | Rejected, *, source_engine: str, source_ref: str, category: str | None = None) -> dict[str, Any]:
    """An exceptions-desk opening receipt for a refused authorization."""

    code = str(getattr(error, "code", "APPROVAL_NOT_BOUND"))
    detail = str(getattr(error, "message", None) or getattr(error, "instructions", None) or error)
    return {"kind": "tick_rejection", "source_engine": source_engine, "source_ref": source_ref, "source_digest": stable_digest({"source_ref": source_ref, "code": code, "detail": detail}), "code": code, "detail": (f"{category}: {detail}" if category else detail)[:900], "evidence_refs": [f"authority:{code.lower()}"]}


def authority_summary(matrix: AuthorityMatrix | Mapping[str, Any], *, now: str, proofs: Sequence[AuthorizationProof | Mapping[str, Any]] = (), adoption: MatrixAdoption | Mapping[str, Any] | None = None) -> dict[str, Any]:
    """What the operator sees: the grants, the categories with no row, the review date, and the proofs issued."""

    parsed_matrix = _matrix(matrix)
    issued = [_proof(item) for item in proofs]
    granted = sorted({row.category for row in parsed_matrix.rows})
    return {
        "company_ref": parsed_matrix.company_ref,
        "matrix_digest": parsed_matrix.matrix_digest,
        "currency": parsed_matrix.currency,
        "effective_from": parsed_matrix.effective_from,
        "adopted": _matrix_adopted(parsed_matrix, adoption),
        "rows": [{"row_ref": row.row_ref, "role_ref": row.role_ref, "category": row.category, "max_amount": str(row.max_amount), "requires_second_approver": row.requires_second_approver, "segregation": row.segregation} for row in parsed_matrix.rows],
        "approvers": {item.approver_ref: item.role_ref for item in parsed_matrix.approvers},
        "categories_without_a_row": [category for category in AUTHORITY_CATEGORIES if category not in granted],
        "blanket_ceiling": str(parsed_matrix.blanket_ceiling),
        "review_due_at": parsed_matrix.review_due_at(),
        "review_overdue": matrix_review_due(parsed_matrix, now),
        "proofs": [{"approval_task_id": item.approval_task_id, "row_ref": item.row_ref, "amount": str(item.amount), "transition_ref": item.transition_ref, "proof_digest": item.proof_digest} for item in issued],
    }


def _matrix_adopted(matrix: AuthorityMatrix, adoption: MatrixAdoption | Mapping[str, Any] | None) -> bool:
    if adoption is None:
        return False
    parsed_adoption = MatrixAdoption.model_validate(detached(adoption))
    return parsed_adoption.matrix_digest == matrix.matrix_digest


def render_matrix(matrix: AuthorityMatrix | Mapping[str, Any], *, now: str) -> str:
    parsed_matrix = _matrix(matrix)
    lines = [f"**Authority {parsed_matrix.currency}** for {parsed_matrix.company_ref} from {parsed_matrix.effective_from[:10]}: {len(parsed_matrix.rows)} row(s), review due {parsed_matrix.review_due_at()[:10]}" + (" (OVERDUE)" if matrix_review_due(parsed_matrix, now) else "")]
    for row in parsed_matrix.rows:
        holders = ", ".join(item.approver_ref for item in parsed_matrix.approvers if item.role_ref == row.role_ref) or "nobody"
        lines.append(f"- {row.row_ref} up to {row.max_amount} ({row.segregation}{', two approvers' if row.requires_second_approver else ''}): {holders}")
    missing = [category for category in AUTHORITY_CATEGORIES if not any(row.category == category for row in parsed_matrix.rows)]
    if missing:
        lines.append(f"- refused for want of a row: {', '.join(missing)}")
    return "\n".join(lines)


AUTHORITY_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": AUTHORITY_KIND,
    "golden_loop": AUTHORITY_GOLDEN_LOOP,
    "stages": ["compile_matrix", "adopt_matrix", "bind_approval", "authorize", "prove"],
    "artifacts": [AUTHORITY_MATRIX_SCHEMA, MATRIX_ADOPTION_SCHEMA, AUTHORIZATION_PROOF_SCHEMA],
    "categories": list(AUTHORITY_CATEGORIES),
    "segregation_modes": list(SEGREGATION_MODES),
    "guards": list(AUTHORITY_CODES),
    "hops": {category: f"{module}.{event}" for category, (module, event) in ENFORCED_HOPS.items()},
    "required_connectors": ["lightbulb.sdk_engine_state"],
    "hard_rules": [
        "authority is a bound platform decision, never a string a model typed",
        "one approval authorizes one transition, for one category, at one amount, as one approver",
        "an approval authorizes the hop its own transition names; a replan decision never becomes a payable decision",
        "the approver's limit is checked, not just their identity, and only in the currency the matrix is denominated in",
        "a category with no row is refused, not defaulted (only an explicit non-zero blanket_ceiling can cover one)",
        "the matrix is an operator input that names itself as one; adopt_matrix proves the platform task that committed this exact matrix_digest, and authorize refuses an adoption of any other matrix",
    ],
}

__all__ = [
    "AUTHORITY_CATEGORIES",
    "AUTHORITY_CODES",
    "AUTHORITY_GOLDEN_LOOP",
    "AUTHORITY_KIND",
    "AUTHORITY_MANIFEST",
    "AUTHORITY_MATRIX_SCHEMA",
    "AUTHORIZATION_PROOF_SCHEMA",
    "ENFORCED_HOPS",
    "MATRIX_ADOPTION_SCHEMA",
    "RECOVERY_BY_CODE",
    "SEGREGATION_MODES",
    "ApproverBinding",
    "AuthorityEffectBoundary",
    "AuthorityMatrix",
    "AuthorityMatrixError",
    "AuthorityRow",
    "AuthorizationProof",
    "MatrixAdoption",
    "adopt_matrix",
    "authority_exception",
    "authority_summary",
    "authorization_evidence",
    "authorize",
    "bind_authority_approval",
    "compile_authority_matrix",
    "matrix_review_due",
    "render_matrix",
    "require_authorization",
    "require_authorization_proof",
    "verify_authorization",
]
