"""The expense claim chain: one replay-fenced lifecycle per employee claim, from submission to the reimbursement observed.

Card charges and Ramp or Expensify reimbursements reached the spend control
chain as observed money, and a pay run could carry a reimbursement line, but
no lifecycle held the claim: what was claimed, whether it sat inside policy,
who approved it, and whether the money actually reached the claimant.
``EXPENSE_CLAIM_LIFECYCLE`` does:

    submitted -> approved -> reimbursed          (terminal)
    submitted -> returned -> submitted           (policy violations; resubmit)
    submitted | returned -> rejected             (terminal, with a reason)

* ``claim_receipt`` opens the claim from typed lines under an opaque
  claimant commitment; identity is refused.  The guard checks every line
  against the plan's categories and window; violations return the claim
  rather than refusing it, so the claimant can correct it.
* ``approve`` consumes a ``payable`` authority proof for the exact total;
  the approver is never the claimant.
* ``reimbursement_receipt`` consumes a bank or payroll-lane read showing a
  transfer of the exact total to the claimant after approval.

Nothing here pays anyone, posts a journal, or persists anything.
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
    unique,
)

EXPENSE_CLAIM_KIND = "expense_claim_chain"
EXPENSE_CLAIM_GOLDEN_LOOP = "people.expense_claim_to_reimbursed@0.1.0"
EXPENSE_CLAIM_PLAN_SCHEMA = "lightbulb.expense_claim_plan.v1"
MAX_CLAIM_TRANSITIONS = 16
REIMBURSEMENT_TOOLS: frozenset[str] = frozenset({"xero.list_bank_transactions", "quickbooks.list_purchases", "host.bank_transfer", "ramp.list_reimbursements", "xero.observe_payrun"})
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_IDENTITY_MARKERS: tuple[str, ...] = ("displayname", "fullname", "firstname", "lastname", "givenname", "familyname", "surname", "email", "phone", "mobile", "address", "dateofbirth", "bankaccount", "bsb", "accountnumber", "employeename", "claimantname")
ViolationKind = Literal["over_limit", "receipt_missing", "outside_window", "future_spend"]

CLAIM_STATUSES: tuple[str, ...] = ("submitted", "returned", "approved", "reimbursed", "rejected")
TERMINAL_CLAIM_STATUSES: frozenset[str] = frozenset({"reimbursed", "rejected"})
CLAIM_EVENTS: tuple[str, ...] = ("submit", "resubmit", "approve", "reimburse", "reject")
_CLAIM_TABLE: dict[tuple[str, str], str] = {
    ("new", "submit"): "submitted",
    ("returned", "resubmit"): "submitted",
    ("submitted", "approve"): "approved",
    ("submitted", "reject"): "rejected",
    ("returned", "reject"): "rejected",
    ("approved", "reimburse"): "reimbursed",
}


class ExpenseClaimError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise ExpenseClaimError(code, message)


def _normalized(key: str) -> str:
    return str(key).lower().replace("_", "").replace("-", "")


def _reject_identity(payload: Any, *, path: str = "receipt") -> Any:
    if isinstance(payload, str):
        _require(not _EMAIL.search(payload), "IDENTITY_IN_RECEIPT", f"{path} carries an email address; a person never crosses this boundary")
        return payload
    if isinstance(payload, Mapping):
        for key, item in payload.items():
            _require(not any(marker in _normalized(key) for marker in _IDENTITY_MARKERS), "IDENTITY_IN_RECEIPT", f"{path}.{key} names a person; only hashed commitments cross this boundary")
            _reject_identity(item, path=f"{path}.{key}")
        return payload
    if isinstance(payload, (list, tuple)):
        for index, item in enumerate(payload):
            _reject_identity(item, path=f"{path}[{index}]")
    return payload


def _money(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(MONEY_QUANTUM)


# --------------------------------------------------------------------------- #
# Plan
# --------------------------------------------------------------------------- #


class ExpenseCategory(StrictModel):
    category: ShortText
    max_per_claim: Decimal
    receipt_required_over: Decimal = Field(default=Decimal("0"), validate_default=True)

    @field_validator("max_per_claim", "receipt_required_over", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))


class ExpenseClaimPlan(StrictModel):
    """What the chain enforces: the categories and their limits, the claim window, and the reads that prove a reimbursement."""

    schema_id: str = Field(default=EXPENSE_CLAIM_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    categories: tuple[ExpenseCategory, ...] = Field(min_length=1, max_length=40)
    claim_window_days: int = Field(default=60, ge=1, le=365)
    max_days_approval_to_reimbursement: int = Field(default=30, ge=1, le=180)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("categories", mode="before")
    @classmethod
    def _categories(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "ExpenseClaimPlan":
        unique([item.category for item in self.categories], label="expense categories")
        if not skip_digests(info) and self.plan_digest != sealed_digest(ExpenseClaimPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self

    def category(self, name: str) -> ExpenseCategory | None:
        return next((item for item in self.categories if item.category == name), None)


DEFAULT_CATEGORIES: tuple[dict[str, Any], ...] = (
    {"category": "travel", "max_per_claim": "2500", "receipt_required_over": "25"},
    {"category": "meals", "max_per_claim": "300", "receipt_required_over": "25"},
    {"category": "software", "max_per_claim": "1000", "receipt_required_over": "0"},
    {"category": "equipment", "max_per_claim": "1500", "receipt_required_over": "0"},
    {"category": "other", "max_per_claim": "250", "receipt_required_over": "25"},
)


def compile_expense_claim_chain(company_ref: str, *, currency: str, categories: Sequence[Mapping[str, Any]] | None = None, overrides: Mapping[str, Any] | None = None) -> ExpenseClaimPlan:
    raw: dict[str, Any] = {"company_ref": company_ref, "currency": str(currency).upper(), "categories": [dict(detached(item)) for item in (categories or DEFAULT_CATEGORIES)], **dict(overrides or {})}
    return seal(ExpenseClaimPlan, raw, "plan_digest")


# --------------------------------------------------------------------------- #
# Receipts, ledger, lifecycle
# --------------------------------------------------------------------------- #


class ClaimLine(StrictModel):
    line_ref: OpaqueRef
    category: ShortText
    amount: Decimal
    spent_at: str
    description: ShortText
    receipt_sha256: Sha256Digest | None = None
    merchant_ref: OpaqueRef | None = None

    @field_validator("amount", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        result = decimal_value(value, field_name="amount")
        if result <= 0:
            raise ValueError("a claim line is a positive amount")
        return result

    @field_validator("spent_at")
    @classmethod
    def _spent(cls, value: str) -> str:
        return timestamp(value, field_name="spent_at")


class Violation(StrictModel):
    line_ref: OpaqueRef
    kind: ViolationKind
    detail: ShortText


class ExpenseClaimReceipt(StrictModel):
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    claimant_ref: OpaqueRef | None = None
    lines: tuple[ClaimLine, ...] = Field(default_factory=tuple, max_length=100)
    total: Decimal | None = None
    authorization_proof: dict[str, Any] | None = None
    reimbursement_provenance: dict[str, Any] | None = None
    reimbursement_digest: Sha256Digest | None = None
    reimbursed_amount: Decimal | None = None
    reimbursed_at: str | None = None
    channel: Literal["bank_transfer", "payroll", "card_program"] | None = None
    payee_ref: OpaqueRef | None = None
    detail: BoundedText | None = None

    @field_validator("evidence_refs", "lines", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("total", "reimbursed_amount", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))

    @field_validator("reimbursed_at")
    @classmethod
    def _stamp(cls, value: str | None) -> str | None:
        return None if value is None else timestamp(value, field_name="reimbursed_at")

    @model_validator(mode="after")
    def _no_identity(self) -> "ExpenseClaimReceipt":
        _reject_identity([line.to_dict() for line in self.lines], path="lines")
        return self


class ExpenseClaimLedger(StrictModel):
    claimant_ref: str | None = None
    submitted_at: str | None = None
    submissions: int = Field(default=0, ge=0)
    lines: tuple[ClaimLine, ...] = Field(default_factory=tuple, max_length=100)
    total: Decimal = Field(default=Decimal("0"), validate_default=True)
    violations: tuple[Violation, ...] = Field(default_factory=tuple, max_length=200)
    returned_at: str | None = None
    approved_at: str | None = None
    approval_ref: str | None = None
    approver_ref: str | None = None
    reimbursed_at: str | None = None
    reimbursed_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    reimbursement_digest: str | None = None
    channel: str | None = None
    days_to_reimburse: int | None = None
    reject_reason: str | None = None
    outcome: Literal["open", "reimbursed", "rejected"] = "open"

    @field_validator("lines", "violations", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("total", "reimbursed_amount", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))


class ExpenseClaimEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    money_transferred: Literal[False] = False
    journal_posted: Literal[False] = False
    provider_read: Literal[False] = False


def _violations(plan: ExpenseClaimPlan, lines: Sequence[ClaimLine], at: str) -> list[Violation]:
    out: list[Violation] = []
    for line in lines:
        category = plan.category(line.category)
        assert category is not None
        if line.amount > category.max_per_claim:
            out.append(Violation(line_ref=line.line_ref, kind="over_limit", detail=f"{line.amount} exceeds the {category.max_per_claim} limit for {line.category}"))
        if line.amount > category.receipt_required_over and line.receipt_sha256 is None:
            out.append(Violation(line_ref=line.line_ref, kind="receipt_missing", detail=f"{line.category} over {category.receipt_required_over} needs a receipt"))
        age = (parsed(at) - parsed(line.spent_at)).days
        if age > plan.claim_window_days:
            out.append(Violation(line_ref=line.line_ref, kind="outside_window", detail=f"spent {age} days ago; the window is {plan.claim_window_days} days"))
        if parsed(line.spent_at) > parsed(at):
            out.append(Violation(line_ref=line.line_ref, kind="future_spend", detail="spent in the future"))
    return out


def _apply_claim(plan: ExpenseClaimPlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event, at = command.receipt, command.event, command.occurred_at
    if event in ("submit", "resubmit"):
        require(bool(r.lines) and r.total is not None, "CLAIM_EMPTY", "a claim carries at least one line and its total")
        if event == "submit":
            require(r.claimant_ref is not None, "CLAIMANT_MISSING", "a claim names the claimant commitment")
        else:
            require(r.claimant_ref is None or r.claimant_ref == data.get("claimant_ref"), "CLAIMANT_MISMATCH", "a resubmission belongs to the same claimant")
        unique([line.line_ref for line in r.lines], label="claim lines")
        for line in r.lines:
            require(plan.category(line.category) is not None, "CATEGORY_UNKNOWN", f"{line.category} is not an expense category of this plan")
        total = _money(sum((line.amount for line in r.lines), Decimal("0")))
        require(r.total == total, "CLAIM_TOTAL_MISMATCH", f"the lines sum to {total}, not {r.total}")
        violations = _violations(plan, r.lines, at)
        data.update({"claimant_ref": data.get("claimant_ref") or r.claimant_ref, "submitted_at": at, "submissions": int(data.get("submissions", 0)) + 1, "lines": [line.to_dict() for line in r.lines], "total": str(total), "violations": [item.to_dict() for item in violations]})
        if violations:
            data["returned_at"] = at
            return "returned", data
        data["returned_at"] = None
    elif event == "approve":
        require(r.authorization_proof is not None, "CLAIM_NOT_AUTHORIZED", f"reimbursing {data['total']} {plan.currency} is a payable decision; a human decides it", "await_approval")
        from lightbulb.authority_matrix import require_authorization_proof

        proof = require_authorization_proof(r.authorization_proof, category="payable", amount=Decimal(str(data["total"])), currency=plan.currency, command=command, plan_digest=plan.plan_digest, company_ref=plan.company_ref)
        require(proof.engine == EXPENSE_CLAIM_KIND, "APPROVAL_TRANSITION_MISMATCH", "the proof authorizes another engine")
        require(proof.approver_ref != data.get("claimant_ref"), "SEGREGATION_VIOLATED", "the claimant cannot approve their own claim")
        data.update({"approved_at": at, "approval_ref": proof.approval_task_id, "approver_ref": proof.approver_ref})
    elif event == "reimburse":
        require(r.reimbursement_provenance is not None and r.reimbursement_digest is not None and r.reimbursed_amount is not None and r.reimbursed_at is not None and r.channel is not None and r.payee_ref is not None, "REIMBURSEMENT_EVIDENCE_MISSING", "a reimbursement carries the read provenance, its digest, the amount, the time, the channel, and the payee commitment")
        require(str(dict(r.reimbursement_provenance or {}).get("output_digest")) == r.reimbursement_digest, "REIMBURSEMENT_NOT_BOUND", "the provenance does not seal this reimbursement")
        require(r.payee_ref == data.get("claimant_ref"), "PAYEE_MISMATCH", "the money reached someone other than the claimant")
        require(_money(r.reimbursed_amount) == Decimal(str(data["total"])), "REIMBURSEMENT_AMOUNT_MISMATCH", f"the claim total is {data['total']}; the transfer was {r.reimbursed_amount}")
        require(parsed(str(data["approved_at"])) <= parsed(str(r.reimbursed_at)) <= parsed(at), "REIMBURSEMENT_TIME_INVALID", "a reimbursement follows the approval and precedes its recording")
        days = (parsed(str(r.reimbursed_at)) - parsed(str(data["approved_at"]))).days
        require(days <= plan.max_days_approval_to_reimbursement, "REIMBURSEMENT_LATE", f"the transfer landed {days} days after approval; the plan allows {plan.max_days_approval_to_reimbursement}", "manual_reconciliation")
        data.update({"reimbursed_at": r.reimbursed_at, "reimbursed_amount": str(_money(r.reimbursed_amount)), "reimbursement_digest": r.reimbursement_digest, "channel": r.channel, "days_to_reimburse": days, "outcome": "reimbursed"})
    elif event == "reject":
        data.update({"reject_reason": str(command.reason)[:300], "outcome": "rejected"})
    return next_status, data


EXPENSE_CLAIM_LIFECYCLE = LifecycleSpec(entity="expense_claim", schema_prefix=EXPENSE_CLAIM_KIND, statuses=CLAIM_STATUSES, terminal=TERMINAL_CLAIM_STATUSES, events=CLAIM_EVENTS, table=_CLAIM_TABLE, opening_event="submit", reason_events=("reject",), apply=_apply_claim, ledger_model=ExpenseClaimLedger, receipt_model=ExpenseClaimReceipt, effect_boundary_model=ExpenseClaimEffectBoundary, plan_model=ExpenseClaimPlan, max_transitions=MAX_CLAIM_TRANSITIONS)
ExpenseClaimState = EXPENSE_CLAIM_LIFECYCLE.State


def open_expense_claim(plan: ExpenseClaimPlan | Mapping[str, Any], scope: Mapping[str, Any], *, receipt: Mapping[str, Any], opened_at: str, actor_ref: str) -> Any:
    return EXPENSE_CLAIM_LIFECYCLE.open(plan, scope, opened_at=opened_at, actor_ref=actor_ref, receipt=receipt)


def advance_expense_claim(plan: ExpenseClaimPlan | Mapping[str, Any], state: Any, command: Any) -> Any:
    return EXPENSE_CLAIM_LIFECYCLE.advance(plan, state, command)


# --------------------------------------------------------------------------- #
# Receipts
# --------------------------------------------------------------------------- #


def claim_receipt(plan: ExpenseClaimPlan | Mapping[str, Any], lines: Sequence[Mapping[str, Any]], *, claimant_ref: str | None = None) -> dict[str, Any]:
    """The opening (or resubmission) receipt: typed lines and their total; categories are checked before the claim exists."""

    parsed_plan = ExpenseClaimPlan.model_validate(detached(plan))
    parsed_lines = [ClaimLine.model_validate(_reject_identity(dict(detached(item)), path="line")) for item in lines]
    for line in parsed_lines:
        _require(parsed_plan.category(line.category) is not None, "CATEGORY_UNKNOWN", f"{line.category} is not an expense category of this plan")
    total = _money(sum((line.amount for line in parsed_lines), Decimal("0")))
    receipt: dict[str, Any] = {"lines": [line.to_dict() for line in parsed_lines], "total": str(total), "evidence_refs": [f"claim:{stable_digest([line.to_dict() for line in parsed_lines])[:16]}"]}
    if claimant_ref is not None:
        receipt["claimant_ref"] = claimant_ref
    return receipt


def approval_receipt(proof: Mapping[str, Any] | Any) -> dict[str, Any]:
    from lightbulb.authority_matrix import authorization_evidence

    evidence = authorization_evidence(proof)
    return {"authorization_proof": evidence["authorization_proof"], "evidence_refs": list(evidence["evidence_refs"])}


def reimbursement_receipt(provenance: Mapping[str, Any] | Any, payload: Mapping[str, Any] | Any, *, payee_ref: str, channel: str = "bank_transfer") -> dict[str, Any]:
    """From a bank, card-program, or payroll-lane read: the transfer of the claim total to the claimant."""

    prov = dict(detached(provenance))
    _require(str(prov.get("source_tool", "")) in REIMBURSEMENT_TOOLS, "REIMBURSEMENT_NOT_BOUND", f"expected a read from {sorted(REIMBURSEMENT_TOOLS)}, got {prov.get('source_tool')!r}")
    for key in ("observation_ref", "provenance_digest", "output_digest", "completed_at"):
        _require(bool(prov.get(key)), "REIMBURSEMENT_NOT_BOUND", f"the provenance lacks {key}")
    raw = _reject_identity(dict(detached(payload)), path="transfer")
    _require(str(prov["output_digest"]) == stable_digest(raw), "REIMBURSEMENT_NOT_BOUND", "the provenance does not seal this exact transfer")
    amount = raw.get("amount") if raw.get("amount") is not None else (None if raw.get("amount_minor") is None else Decimal(str(raw["amount_minor"])) / 100)
    stamp = raw.get("paid_at") or raw.get("date") or raw.get("completed_at")
    _require(amount is not None and stamp is not None, "REIMBURSEMENT_INCOMPLETE", "a transfer carries its amount and its time")
    return {"reimbursement_provenance": prov, "reimbursement_digest": str(prov["output_digest"]), "reimbursed_amount": str(_money(decimal_value(amount, field_name="amount"))), "reimbursed_at": timestamp(str(stamp), field_name="reimbursed_at"), "channel": channel, "payee_ref": payee_ref, "evidence_refs": [f"transfer:{prov['observation_ref']}"]}


def expense_claim_summary(states: Sequence[Any]) -> dict[str, Any]:
    counts = {status: sum(1 for state in states if state.status == status) for status in CLAIM_STATUSES}
    reimbursed = [state for state in states if state.status == "reimbursed"]
    days = [state.ledger.days_to_reimburse for state in reimbursed if state.ledger.days_to_reimburse is not None]
    return {"claims": len(states), "by_status": counts, "total_claimed": str(_money(sum((state.ledger.total for state in states), Decimal("0")))), "total_reimbursed": str(_money(sum((state.ledger.reimbursed_amount for state in reimbursed), Decimal("0")))), "awaiting_reimbursement": str(_money(sum((state.ledger.total for state in states if state.status == "approved"), Decimal("0")))), "violations": sum(len(state.ledger.violations) for state in states), "average_days_to_reimburse": None if not days else str((Decimal(sum(days)) / Decimal(len(days))).quantize(Decimal("0.1")))}


EXPENSE_CLAIM_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": EXPENSE_CLAIM_KIND,
    "golden_loop": EXPENSE_CLAIM_GOLDEN_LOOP,
    "stages": ["submit", "approve", "reimburse"],
    "statuses": list(CLAIM_STATUSES),
    "events": list(CLAIM_EVENTS),
    "hops": {"submit": "typed lines under an opaque claimant commitment, checked against the plan's categories and window", "approve": "payable authority proof for the exact total by someone other than the claimant", "reimburse": "bank, card-program, or payroll-lane read of the exact transfer to the claimant after approval"},
    "required_connectors": ["xero", "lightbulb.sdk_engine_state"],
    "hard_rules": [
        "a claim outside policy is returned with its violations, never silently trimmed",
        "the claimant never approves their own claim and identity never enters the engine",
        "reimbursement is proven by an observed transfer of the exact total to the claimant, after approval",
    ],
}

__all__ = ["CLAIM_EVENTS", "CLAIM_STATUSES", "DEFAULT_CATEGORIES", "EXPENSE_CLAIM_GOLDEN_LOOP", "EXPENSE_CLAIM_KIND", "EXPENSE_CLAIM_LIFECYCLE", "EXPENSE_CLAIM_MANIFEST", "REIMBURSEMENT_TOOLS", "TERMINAL_CLAIM_STATUSES", "ClaimLine", "ExpenseCategory", "ExpenseClaimError", "ExpenseClaimLedger", "ExpenseClaimPlan", "ExpenseClaimReceipt", "ExpenseClaimState", "Violation", "advance_expense_claim", "approval_receipt", "claim_receipt", "compile_expense_claim_chain", "expense_claim_summary", "open_expense_claim", "reimbursement_receipt"]
