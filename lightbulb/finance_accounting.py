"""Deterministic accounting control evaluations for governed finance workflows.

These primitives assess evidence and control state only.  They never post a
journal entry, close a period, mutate a ledger, or mint approval.  Spring
remains the authority for tenant/company scope, RBAC, persistence, approval,
audit, and any consequential accounting operation.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from datetime import date, datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Annotated, Any, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from lightbulb.connector_execution import ConnectorEffect
from lightbulb.primitive_runtime import (
    BusinessProcessPrimitive,
    PrimitiveEvent,
    PrimitiveEvidence,
    PrimitiveEvidenceRef,
    PrimitiveEvidenceVerificationGrade,
    PrimitiveExecutionContext,
    PrimitiveExecutionResult,
    PrimitiveExecutionStatus,
    PrimitiveOperationFreshnessClass,
    PrimitiveOperationReceipt,
    PrimitiveOperationRecoveryPolicy,
    PrimitiveOperationReplayClass,
    PrimitiveOperationSpec,
    PrimitiveOperationStatus,
    revalidate_model_boundary,
)


JOURNAL_ENTRY_CONTROL_INPUT_SCHEMA = "lightbulb.finance_journal_entry_control_input.v1"
JOURNAL_ENTRY_CONTROL_EVALUATION_SCHEMA = (
    "lightbulb.finance_journal_entry_control_evaluation.v1"
)
PERIOD_CLOSE_READINESS_INPUT_SCHEMA = (
    "lightbulb.finance_period_close_readiness_input.v1"
)
PERIOD_CLOSE_READINESS_EVALUATION_SCHEMA = (
    "lightbulb.finance_period_close_readiness_evaluation.v1"
)

_ZERO_DIGEST = "0" * 64
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_OPAQUE_REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$"
_CONTROL_CODE_PATTERN = r"^[a-z][a-z0-9_.-]{0,119}$"
_CURRENCY_PATTERN = r"^[A-Z]{3}$"
_MAX_MONEY = Decimal("1e24")
_MAX_CONTROL_FINDINGS = 5_000
_JOURNAL_REQUIRED_EVIDENCE_KINDS = (
    "journal_source",
    "chart_of_accounts",
    "period_status",
)
_PERIOD_CLOSE_REQUIRED_EVIDENCE_KINDS = (
    "trial_balance",
    "reconciliation",
    "period_status",
)
_GRADE_ORDER = {
    PrimitiveEvidenceVerificationGrade.UNVERIFIED: 0,
    PrimitiveEvidenceVerificationGrade.ASSERTED: 1,
    PrimitiveEvidenceVerificationGrade.ATTESTED: 2,
    PrimitiveEvidenceVerificationGrade.VERIFIED: 3,
}

FinanceControlDisposition = Literal["blocked", "indeterminate", "ready"]
FinanceControlStatus = Literal["passed", "failed", "indeterminate"]
ControlGateStatus = Literal["passed", "failed", "unknown", "not_applicable"]
ApprovalStatus = Literal["not_required", "pending", "approved", "rejected", "unknown"]
AccountingPeriodState = Literal["open", "soft_closed", "closed", "locked"]
ReconciliationStatus = Literal[
    "complete", "incomplete", "exception", "unknown", "not_applicable"
]


def _bounded_text(value: str) -> str:
    if value != value.strip():
        raise ValueError("text must not contain surrounding whitespace")
    if any(ord(character) < 32 for character in value):
        raise ValueError("text contains an unsupported control character")
    return value


ShortText = Annotated[
    str,
    StringConstraints(min_length=1, max_length=300),
    AfterValidator(_bounded_text),
]
OpaqueRef = Annotated[str, StringConstraints(pattern=_OPAQUE_REF_PATTERN)]
ControlCode = Annotated[str, StringConstraints(pattern=_CONTROL_CODE_PATTERN)]
CurrencyCode = Annotated[str, StringConstraints(pattern=_CURRENCY_PATTERN)]
Sha256Digest = Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)]


def _stable_digest(value: Any) -> str:
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _decimal(value: Any) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (str, int, float, Decimal)):
        raise ValueError("decimal values must be strings or JSON numbers")
    lexical = str(value)
    if lexical != lexical.strip() or len(lexical) > 80:
        raise ValueError("decimal values must use bounded notation")
    try:
        parsed = Decimal(lexical)
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("value must be a finite decimal") from exc
    if not parsed.is_finite() or abs(parsed) > _MAX_MONEY:
        raise ValueError("value must be a bounded finite decimal")
    return parsed


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


def _date(value: str, *, field_name: str) -> str:
    if value != value.strip():
        raise ValueError(f"{field_name} must not contain surrounding whitespace")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be an ISO-8601 date") from exc
    return parsed.isoformat()


def _as_tuple(value: Any) -> Any:
    if isinstance(value, list):
        return tuple(value)
    return value


def _decimal_places(value: Decimal) -> int:
    return max(0, -value.as_tuple().exponent)


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        revalidate_instances="always",
        serialize_by_alias=True,
        strict=True,
    )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


class CompanyAccountingContext(_StrictModel):
    company_ref: OpaqueRef
    functional_currency: CurrencyCode
    allowed_transaction_currencies: tuple[CurrencyCode, ...] = Field(
        min_length=1,
        max_length=20,
    )
    amount_scale: int = Field(default=2, ge=0, le=8)

    @field_validator("allowed_transaction_currencies", mode="before")
    @classmethod
    def _currencies_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _functional_currency_is_allowed(self) -> "CompanyAccountingContext":
        if len(set(self.allowed_transaction_currencies)) != len(
            self.allowed_transaction_currencies
        ):
            raise ValueError("allowed_transaction_currencies must be unique")
        if self.functional_currency not in self.allowed_transaction_currencies:
            raise ValueError(
                "functional_currency must appear in allowed_transaction_currencies"
            )
        return self


class AccountingPeriodContext(_StrictModel):
    period_ref: OpaqueRef
    company_ref: OpaqueRef
    functional_currency: CurrencyCode
    start_date: str
    end_date: str
    state: AccountingPeriodState

    @field_validator("start_date", "end_date")
    @classmethod
    def _valid_dates(cls, value: str, info: Any) -> str:
        return _date(value, field_name=info.field_name)

    @model_validator(mode="after")
    def _ordered_period(self) -> "AccountingPeriodContext":
        if self.start_date > self.end_date:
            raise ValueError("start_date cannot follow end_date")
        return self


class ChartAccountControl(_StrictModel):
    account_ref: OpaqueRef
    company_ref: OpaqueRef
    allowed_currencies: tuple[CurrencyCode, ...] = Field(min_length=1, max_length=20)
    active: bool
    posting_allowed: bool
    reconciliation_required: bool = False

    @field_validator("allowed_currencies", mode="before")
    @classmethod
    def _currencies_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _currencies_are_unique(self) -> "ChartAccountControl":
        if len(set(self.allowed_currencies)) != len(self.allowed_currencies):
            raise ValueError("allowed_currencies must be unique")
        return self


class AccountingEvidencePolicy(_StrictModel):
    required_kinds: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=20)
    maximum_age_hours: int = Field(default=72, ge=1, le=8_760)
    minimum_verification_grade: PrimitiveEvidenceVerificationGrade = (
        PrimitiveEvidenceVerificationGrade.ATTESTED
    )
    require_effective_at: bool = False

    @field_validator("required_kinds", mode="before")
    @classmethod
    def _kinds_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @field_validator("minimum_verification_grade", mode="before")
    @classmethod
    def _grade_enum(cls, value: Any) -> PrimitiveEvidenceVerificationGrade:
        if isinstance(value, PrimitiveEvidenceVerificationGrade):
            return value
        return PrimitiveEvidenceVerificationGrade(str(value))

    @model_validator(mode="after")
    def _kinds_are_unique(self) -> "AccountingEvidencePolicy":
        if len(set(self.required_kinds)) != len(self.required_kinds):
            raise ValueError("required_kinds must be unique")
        return self


class AccountingControlGate(_StrictModel):
    control_ref: OpaqueRef
    name: ShortText
    required: bool = True
    status: ControlGateStatus
    evaluated_by_ref: OpaqueRef | None = None
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=20)

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _refs_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)


class AccountingApprovalGate(_StrictModel):
    required: bool = True
    status: ApprovalStatus
    prepared_by_ref: OpaqueRef
    approved_by_ref: OpaqueRef | None = None
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=20)

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _refs_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)


class FinanceControlFinding(_StrictModel):
    code: ControlCode
    status: FinanceControlStatus
    message: ShortText
    field: ShortText | None = None
    affected_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=100)
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=20)

    @field_validator("affected_refs", "evidence_refs", mode="before")
    @classmethod
    def _refs_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)


class JournalEntryLine(_StrictModel):
    line_ref: OpaqueRef
    account_ref: OpaqueRef
    company_ref: OpaqueRef
    currency: CurrencyCode
    debit: Decimal = Field(default=Decimal("0"), ge=0, le=_MAX_MONEY)
    credit: Decimal = Field(default=Decimal("0"), ge=0, le=_MAX_MONEY)

    @field_validator("debit", "credit", mode="before")
    @classmethod
    def _money_decimal(cls, value: Any) -> Decimal:
        return _decimal(value)


class JournalEntryControlInput(_StrictModel):
    schema_id: Literal["lightbulb.finance_journal_entry_control_input.v1"] = Field(
        default=JOURNAL_ENTRY_CONTROL_INPUT_SCHEMA,
        alias="schema",
    )
    evaluation_ref: OpaqueRef
    evaluation_as_of: str
    entry_ref: OpaqueRef
    entry_date: str
    transaction_currency: CurrencyCode
    company: CompanyAccountingContext
    period: AccountingPeriodContext
    chart_of_accounts_complete: bool
    chart_of_accounts: tuple[ChartAccountControl, ...] = Field(
        min_length=1,
        max_length=2_000,
    )
    lines: tuple[JournalEntryLine, ...] = Field(min_length=2, max_length=1_000)
    approval: AccountingApprovalGate
    control_gates: tuple[AccountingControlGate, ...] = Field(
        default_factory=tuple,
        max_length=100,
    )
    evidence_policy: AccountingEvidencePolicy = Field(
        default_factory=lambda: AccountingEvidencePolicy(
            required_kinds=_JOURNAL_REQUIRED_EVIDENCE_KINDS
        )
    )
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        default_factory=tuple,
        max_length=200,
    )

    @field_validator("evaluation_as_of")
    @classmethod
    def _valid_evaluation_time(cls, value: str) -> str:
        return _timestamp(value, field_name="evaluation_as_of")

    @field_validator("entry_date")
    @classmethod
    def _valid_entry_date(cls, value: str) -> str:
        return _date(value, field_name="entry_date")

    @field_validator(
        "chart_of_accounts",
        "lines",
        "control_gates",
        "evidence_refs",
        mode="before",
    )
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _refs_are_unique(self) -> "JournalEntryControlInput":
        _require_unique(
            [account.account_ref for account in self.chart_of_accounts],
            "chart account_ref",
        )
        _require_unique([line.line_ref for line in self.lines], "journal line_ref")
        _require_unique(
            [gate.control_ref for gate in self.control_gates],
            "control_ref",
        )
        _require_unique(
            [evidence.evidence_ref for evidence in self.evidence_refs],
            "evidence_ref",
        )
        return self


class ReconciliationControl(_StrictModel):
    reconciliation_ref: OpaqueRef
    account_ref: OpaqueRef
    company_ref: OpaqueRef
    period_ref: OpaqueRef
    balance_as_of: str
    status: ReconciliationStatus
    unreconciled_amount: Decimal | None = Field(default=None, ge=0, le=_MAX_MONEY)
    reviewed_by_ref: OpaqueRef | None = None
    completed_at: str | None = None
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=20)

    @field_validator("unreconciled_amount", mode="before")
    @classmethod
    def _amount_decimal(cls, value: Any) -> Decimal | None:
        if value is None:
            return None
        return _decimal(value)

    @field_validator("completed_at")
    @classmethod
    def _valid_completed_at(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _timestamp(value, field_name="completed_at")

    @field_validator("balance_as_of")
    @classmethod
    def _valid_balance_as_of(cls, value: str) -> str:
        return _date(value, field_name="balance_as_of")

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _refs_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _completion_follows_balance_cutoff(self) -> "ReconciliationControl":
        if self.completed_at is not None and datetime.fromisoformat(
            self.completed_at.replace("Z", "+00:00")
        ).date() <= date.fromisoformat(self.balance_as_of):
            raise ValueError(
                "reconciliation completion must follow the balance_as_of cutoff"
            )
        return self


class ConsolidationReadiness(_StrictModel):
    required: bool
    group_currency: CurrencyCode | None = None
    required_entity_refs: tuple[OpaqueRef, ...] = Field(
        default_factory=tuple,
        max_length=200,
    )
    received_entity_refs: tuple[OpaqueRef, ...] = Field(
        default_factory=tuple,
        max_length=200,
    )
    currency_translation_status: ControlGateStatus
    intercompany_matching_status: ControlGateStatus
    elimination_status: ControlGateStatus
    elimination_debits: Decimal | None = Field(default=None, ge=0, le=_MAX_MONEY)
    elimination_credits: Decimal | None = Field(default=None, ge=0, le=_MAX_MONEY)
    approved_by_ref: OpaqueRef | None = None
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=40)

    @field_validator("elimination_debits", "elimination_credits", mode="before")
    @classmethod
    def _money_decimal(cls, value: Any) -> Decimal | None:
        if value is None:
            return None
        return _decimal(value)

    @field_validator(
        "required_entity_refs",
        "received_entity_refs",
        "evidence_refs",
        mode="before",
    )
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _entity_refs_are_unique(self) -> "ConsolidationReadiness":
        _require_unique(self.required_entity_refs, "required_entity_ref")
        _require_unique(self.received_entity_refs, "received_entity_ref")
        return self


class PeriodCloseReadinessInput(_StrictModel):
    schema_id: Literal["lightbulb.finance_period_close_readiness_input.v1"] = Field(
        default=PERIOD_CLOSE_READINESS_INPUT_SCHEMA,
        alias="schema",
    )
    evaluation_ref: OpaqueRef
    evaluation_as_of: str
    close_ref: OpaqueRef
    company: CompanyAccountingContext
    period: AccountingPeriodContext
    chart_of_accounts_complete: bool
    chart_of_accounts: tuple[ChartAccountControl, ...] = Field(
        min_length=1,
        max_length=2_000,
    )
    trial_balance_debits: Decimal = Field(ge=0, le=_MAX_MONEY)
    trial_balance_credits: Decimal = Field(ge=0, le=_MAX_MONEY)
    reconciliations: tuple[ReconciliationControl, ...] = Field(
        default_factory=tuple,
        max_length=2_000,
    )
    consolidation: ConsolidationReadiness
    approval: AccountingApprovalGate
    control_gates: tuple[AccountingControlGate, ...] = Field(
        default_factory=tuple,
        max_length=100,
    )
    evidence_policy: AccountingEvidencePolicy = Field(
        default_factory=lambda: AccountingEvidencePolicy(
            required_kinds=_PERIOD_CLOSE_REQUIRED_EVIDENCE_KINDS
        )
    )
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        default_factory=tuple,
        max_length=200,
    )

    @field_validator("evaluation_as_of")
    @classmethod
    def _valid_evaluation_time(cls, value: str) -> str:
        return _timestamp(value, field_name="evaluation_as_of")

    @field_validator("trial_balance_debits", "trial_balance_credits", mode="before")
    @classmethod
    def _money_decimal(cls, value: Any) -> Decimal:
        return _decimal(value)

    @field_validator(
        "chart_of_accounts",
        "reconciliations",
        "control_gates",
        "evidence_refs",
        mode="before",
    )
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _refs_scope_and_cutoff_are_exact(self) -> "PeriodCloseReadinessInput":
        _require_unique(
            [account.account_ref for account in self.chart_of_accounts],
            "chart account_ref",
        )
        _require_unique(
            [
                reconciliation.reconciliation_ref
                for reconciliation in self.reconciliations
            ],
            "reconciliation_ref",
        )
        _require_unique(
            [reconciliation.account_ref for reconciliation in self.reconciliations],
            "reconciliation account_ref",
        )
        _require_unique(
            [gate.control_ref for gate in self.control_gates],
            "control_ref",
        )
        _require_unique(
            [evidence.evidence_ref for evidence in self.evidence_refs],
            "evidence_ref",
        )
        if datetime.fromisoformat(
            self.evaluation_as_of.replace("Z", "+00:00")
        ).date() <= date.fromisoformat(self.period.end_date):
            raise ValueError("close evaluation must follow the period cutoff")
        for reconciliation in self.reconciliations:
            if reconciliation.company_ref != self.company.company_ref:
                raise ValueError(
                    "reconciliation company_ref must match close company_ref"
                )
            if reconciliation.period_ref != self.period.period_ref:
                raise ValueError(
                    "reconciliation period_ref must match close period_ref"
                )
            if reconciliation.balance_as_of != self.period.end_date:
                raise ValueError(
                    "reconciliation balance_as_of must match the period cutoff"
                )
        return self


class _FinanceControlEvaluation(_StrictModel):
    evaluation_ref: OpaqueRef
    company_ref: OpaqueRef
    period_ref: OpaqueRef
    evaluated_at: str
    disposition: FinanceControlDisposition
    findings: tuple[FinanceControlFinding, ...] = Field(
        max_length=_MAX_CONTROL_FINDINGS
    )
    passed_control_count: int = Field(ge=0, le=_MAX_CONTROL_FINDINGS)
    failed_control_count: int = Field(ge=0, le=_MAX_CONTROL_FINDINGS)
    indeterminate_control_count: int = Field(ge=0, le=_MAX_CONTROL_FINDINGS)
    next_actions: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=50)
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(max_length=200)
    operation_spec: PrimitiveOperationSpec
    operation_digest: Sha256Digest
    evidence_digest: Sha256Digest
    evaluation_digest: Sha256Digest = _ZERO_DIGEST

    @field_validator("evaluated_at")
    @classmethod
    def _valid_evaluated_at(cls, value: str) -> str:
        return _timestamp(value, field_name="evaluated_at")

    @field_validator("findings", "next_actions", "evidence_refs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _validate_control_envelope(self) -> "_FinanceControlEvaluation":
        passed = sum(finding.status == "passed" for finding in self.findings)
        failed = sum(finding.status == "failed" for finding in self.findings)
        indeterminate = sum(
            finding.status == "indeterminate" for finding in self.findings
        )
        if (
            passed != self.passed_control_count
            or failed != self.failed_control_count
            or indeterminate != self.indeterminate_control_count
        ):
            raise ValueError("control counts must match findings")
        expected_disposition: FinanceControlDisposition = (
            "blocked" if failed else "indeterminate" if indeterminate else "ready"
        )
        if self.disposition != expected_disposition:
            raise ValueError("disposition must match control findings")
        if self.disposition == "ready" and self.next_actions:
            raise ValueError("ready evaluations cannot contain next_actions")
        if self.disposition != "ready" and not self.next_actions:
            raise ValueError("non-ready evaluations require bounded next_actions")
        if self.operation_spec.effect != ConnectorEffect.READ:
            raise ValueError("accounting evaluations must remain read-only")
        if self.operation_spec.approval_required:
            raise ValueError("local read-only evaluation cannot require approval")
        expected_evidence_digest = _evidence_digest(self.evidence_refs)
        if self.evidence_digest != expected_evidence_digest:
            raise ValueError("evidence_digest does not match evidence_refs")

        digest_payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"evaluation_digest"},
            exclude_none=True,
        )
        expected_digest = _stable_digest(digest_payload)
        if self.evaluation_digest not in {_ZERO_DIGEST, expected_digest}:
            raise ValueError("evaluation_digest does not match evaluation")
        object.__setattr__(self, "evaluation_digest", expected_digest)
        return self


class JournalEntryControlEvaluation(_FinanceControlEvaluation):
    schema_id: Literal["lightbulb.finance_journal_entry_control_evaluation.v1"] = Field(
        default=JOURNAL_ENTRY_CONTROL_EVALUATION_SCHEMA, alias="schema"
    )
    entry_ref: OpaqueRef
    transaction_currency: CurrencyCode
    debit_total: Decimal
    credit_total: Decimal
    imbalance: Decimal
    posting_authorized: Literal[False] = False

    @field_validator("debit_total", "credit_total", "imbalance", mode="before")
    @classmethod
    def _money_decimal(cls, value: Any) -> Decimal:
        return _decimal(value)

    @model_validator(mode="after")
    def _journal_operation_is_exact(self) -> "JournalEntryControlEvaluation":
        if self.operation_spec != JOURNAL_ENTRY_EVALUATION_OPERATION:
            raise ValueError("operation_spec must identify the journal evaluator")
        if self.imbalance != self.debit_total - self.credit_total:
            raise ValueError("imbalance must equal debit_total minus credit_total")
        return self


class PeriodCloseReadinessEvaluation(_FinanceControlEvaluation):
    schema_id: Literal["lightbulb.finance_period_close_readiness_evaluation.v1"] = (
        Field(default=PERIOD_CLOSE_READINESS_EVALUATION_SCHEMA, alias="schema")
    )
    close_ref: OpaqueRef
    trial_balance_debits: Decimal
    trial_balance_credits: Decimal
    trial_balance_imbalance: Decimal
    required_reconciliation_count: int = Field(ge=0, le=2_000)
    completed_reconciliation_count: int = Field(ge=0, le=2_000)
    consolidation_required: bool
    missing_entity_refs: tuple[OpaqueRef, ...] = Field(
        default_factory=tuple,
        max_length=200,
    )
    close_authorized: Literal[False] = False

    @field_validator(
        "trial_balance_debits",
        "trial_balance_credits",
        "trial_balance_imbalance",
        mode="before",
    )
    @classmethod
    def _money_decimal(cls, value: Any) -> Decimal:
        return _decimal(value)

    @field_validator("missing_entity_refs", mode="before")
    @classmethod
    def _refs_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _close_operation_is_exact(self) -> "PeriodCloseReadinessEvaluation":
        if self.operation_spec != PERIOD_CLOSE_EVALUATION_OPERATION:
            raise ValueError("operation_spec must identify the close evaluator")
        if (
            self.trial_balance_imbalance
            != self.trial_balance_debits - self.trial_balance_credits
        ):
            raise ValueError("trial_balance_imbalance must equal debits minus credits")
        if self.completed_reconciliation_count > self.required_reconciliation_count:
            raise ValueError(
                "completed_reconciliation_count cannot exceed required count"
            )
        return self


JOURNAL_ENTRY_EVALUATION_OPERATION = PrimitiveOperationSpec(
    operation_ref="journal-entry-controls.evaluate",
    tool="finance.evaluate_journal_entry_controls",
    effect=ConnectorEffect.READ,
    approval_required=False,
    replay_class=PrimitiveOperationReplayClass.SAFE,
    freshness_class=PrimitiveOperationFreshnessClass.BOUNDED,
    recovery_policy=PrimitiveOperationRecoveryPolicy.NONE,
)

PERIOD_CLOSE_EVALUATION_OPERATION = PrimitiveOperationSpec(
    operation_ref="period-close-readiness.evaluate",
    tool="finance.evaluate_period_close_readiness",
    effect=ConnectorEffect.READ,
    approval_required=False,
    replay_class=PrimitiveOperationReplayClass.SAFE,
    freshness_class=PrimitiveOperationFreshnessClass.BOUNDED,
    recovery_policy=PrimitiveOperationRecoveryPolicy.NONE,
)


def _require_unique(values: Any, label: str) -> None:
    material = tuple(values)
    if len(set(material)) != len(material):
        raise ValueError(f"{label} values must be unique")


def _evidence_digest(evidence_refs: Any) -> str:
    canonical = [
        evidence.to_dict()
        for evidence in sorted(evidence_refs, key=lambda item: item.evidence_ref)
    ]
    return _stable_digest(canonical)


def _finding(
    findings: list[FinanceControlFinding],
    *,
    code: str,
    status: FinanceControlStatus,
    message: str,
    field: str | None = None,
    affected_refs: Any = (),
    evidence_refs: Any = (),
) -> None:
    findings.append(
        FinanceControlFinding(
            code=code,
            status=status,
            message=message[:300],
            field=field,
            affected_refs=tuple(affected_refs)[:100],
            evidence_refs=tuple(evidence_refs)[:20],
        )
    )


def _evidence_state(
    evidence: PrimitiveEvidenceRef,
    *,
    evaluated_at: datetime,
    policy: AccountingEvidencePolicy,
) -> FinanceControlStatus:
    observed_at = datetime.fromisoformat(evidence.observed_at.replace("Z", "+00:00"))
    if observed_at > evaluated_at:
        return "failed"
    age_hours = (evaluated_at - observed_at).total_seconds() / 3_600
    if age_hours > policy.maximum_age_hours:
        return "indeterminate"
    if (
        _GRADE_ORDER[evidence.verification_grade]
        < _GRADE_ORDER[policy.minimum_verification_grade]
    ):
        return "indeterminate"
    if evidence.effective_at is None:
        return "indeterminate" if policy.require_effective_at else "passed"
    effective_at = datetime.fromisoformat(evidence.effective_at.replace("Z", "+00:00"))
    if effective_at > evaluated_at:
        return "indeterminate"
    return "passed"


def _assess_required_evidence(
    findings: list[FinanceControlFinding],
    *,
    evidence_refs: tuple[PrimitiveEvidenceRef, ...],
    evaluated_at: datetime,
    policy: AccountingEvidencePolicy,
    additional_required_kinds: tuple[str, ...] = (),
) -> dict[str, PrimitiveEvidenceRef]:
    evidence_by_ref = {evidence.evidence_ref: evidence for evidence in evidence_refs}
    required_kinds = tuple(
        dict.fromkeys((*policy.required_kinds, *additional_required_kinds))
    )
    for kind in required_kinds:
        candidates = [evidence for evidence in evidence_refs if evidence.kind == kind]
        if not candidates:
            _finding(
                findings,
                code=f"evidence.{_code_token(kind)}.missing",
                status="indeterminate",
                message=f"Required {kind} evidence was not supplied.",
                field="evidence_refs",
            )
            continue
        states = [
            _evidence_state(evidence, evaluated_at=evaluated_at, policy=policy)
            for evidence in candidates
        ]
        if "passed" in states:
            status: FinanceControlStatus = "passed"
            message = f"Required {kind} evidence is current and sufficiently verified."
        elif "failed" in states:
            status = "failed"
            message = f"Required {kind} evidence is dated after the evaluation time."
        else:
            status = "indeterminate"
            message = (
                f"Required {kind} evidence is stale, not effective, or under-verified."
            )
        _finding(
            findings,
            code=f"evidence.{_code_token(kind)}.freshness",
            status=status,
            message=message,
            field="evidence_refs",
            evidence_refs=[evidence.evidence_ref for evidence in candidates],
        )
    return evidence_by_ref


def _code_token(value: str) -> str:
    token = re.sub(r"[^a-z0-9]+", "_", value.strip().lower()).strip("_")
    return token[:60] or "required"


def _support_status(
    refs: tuple[str, ...],
    *,
    evidence_by_ref: dict[str, PrimitiveEvidenceRef],
    evaluated_at: datetime,
    policy: AccountingEvidencePolicy,
) -> FinanceControlStatus:
    if not refs or any(ref not in evidence_by_ref for ref in refs):
        return "indeterminate"
    states = [
        _evidence_state(
            evidence_by_ref[ref],
            evaluated_at=evaluated_at,
            policy=policy,
        )
        for ref in refs
    ]
    if "failed" in states:
        return "failed"
    if "indeterminate" in states:
        return "indeterminate"
    return "passed"


def _assess_approval(
    findings: list[FinanceControlFinding],
    *,
    approval: AccountingApprovalGate,
    evidence_by_ref: dict[str, PrimitiveEvidenceRef],
    evaluated_at: datetime,
    policy: AccountingEvidencePolicy,
) -> None:
    if not approval.required:
        _finding(
            findings,
            code="approval.not_required",
            status="passed",
            message="Approval is not required by the supplied control policy.",
        )
        return
    if approval.status == "rejected":
        _finding(
            findings,
            code="approval.rejected",
            status="failed",
            message="The required accounting approval was rejected.",
            field="approval.status",
        )
        return
    if approval.status != "approved" or approval.approved_by_ref is None:
        _finding(
            findings,
            code="approval.incomplete",
            status="indeterminate",
            message="Required accounting approval is not complete.",
            field="approval.status",
        )
        return
    if approval.approved_by_ref == approval.prepared_by_ref:
        _finding(
            findings,
            code="approval.segregation_failed",
            status="failed",
            message="Preparer and approver must be different actors.",
            field="approval.approved_by_ref",
            affected_refs=(approval.prepared_by_ref,),
        )
        return
    support = _support_status(
        approval.evidence_refs,
        evidence_by_ref=evidence_by_ref,
        evaluated_at=evaluated_at,
        policy=policy,
    )
    _finding(
        findings,
        code="approval.evidence",
        status=support,
        message=(
            "Required approval and segregation evidence is usable."
            if support == "passed"
            else "Required approval evidence is missing, stale, or invalid."
        ),
        field="approval.evidence_refs",
        evidence_refs=approval.evidence_refs,
    )


def _assess_control_gates(
    findings: list[FinanceControlFinding],
    *,
    gates: tuple[AccountingControlGate, ...],
    evidence_by_ref: dict[str, PrimitiveEvidenceRef],
    evaluated_at: datetime,
    policy: AccountingEvidencePolicy,
) -> None:
    for gate in gates:
        if not gate.required:
            _finding(
                findings,
                code=f"control.{_code_token(gate.control_ref)}.optional",
                status="passed",
                message=f"Optional control {gate.name} does not gate readiness.",
                affected_refs=(gate.control_ref,),
            )
            continue
        if gate.status == "failed":
            status: FinanceControlStatus = "failed"
            message = f"Required control {gate.name} failed."
        elif gate.status != "passed":
            status = "indeterminate"
            message = f"Required control {gate.name} is not conclusively passed."
        elif gate.evaluated_by_ref is None:
            status = "indeterminate"
            message = f"Required control {gate.name} lacks an evaluator identity."
        else:
            status = _support_status(
                gate.evidence_refs,
                evidence_by_ref=evidence_by_ref,
                evaluated_at=evaluated_at,
                policy=policy,
            )
            message = (
                f"Required control {gate.name} passed with usable evidence."
                if status == "passed"
                else f"Required control {gate.name} lacks usable evidence."
            )
        _finding(
            findings,
            code=f"control.{_code_token(gate.control_ref)}",
            status=status,
            message=message,
            affected_refs=(gate.control_ref,),
            evidence_refs=gate.evidence_refs,
        )


def _assess_company_period(
    findings: list[FinanceControlFinding],
    *,
    company: CompanyAccountingContext,
    period: AccountingPeriodContext,
    allowed_period_states: set[str],
) -> None:
    mismatches: list[str] = []
    if period.company_ref != company.company_ref:
        mismatches.append("company")
    if period.functional_currency != company.functional_currency:
        mismatches.append("functional currency")
    _finding(
        findings,
        code="scope.company_period",
        status="failed" if mismatches else "passed",
        message=(
            f"Period context mismatches company {' and '.join(mismatches)}."
            if mismatches
            else "Period company and functional currency match the evaluation scope."
        ),
        field="period",
        affected_refs=(period.period_ref,),
    )
    _finding(
        findings,
        code="period.state",
        status="passed" if period.state in allowed_period_states else "failed",
        message=(
            f"Period state {period.state} permits this readiness evaluation."
            if period.state in allowed_period_states
            else f"Period state {period.state} does not permit the evaluated operation."
        ),
        field="period.state",
        affected_refs=(period.period_ref,),
    )


def _evaluation_counts(
    findings: list[FinanceControlFinding],
) -> tuple[FinanceControlDisposition, int, int, int, tuple[str, ...]]:
    passed = sum(finding.status == "passed" for finding in findings)
    failed = sum(finding.status == "failed" for finding in findings)
    indeterminate = sum(finding.status == "indeterminate" for finding in findings)
    disposition: FinanceControlDisposition = (
        "blocked" if failed else "indeterminate" if indeterminate else "ready"
    )
    actions = tuple(
        dict.fromkeys(
            f"Resolve {finding.code}: {finding.message}"[:300]
            for finding in findings
            if finding.status != "passed"
        )
    )[:50]
    return disposition, passed, failed, indeterminate, actions


def _operation_digest(parsed: _StrictModel, evidence_digest: str) -> str:
    payload = parsed.model_dump(
        mode="json",
        by_alias=True,
        exclude={"evidence_refs"},
        exclude_none=True,
    )
    payload["evidence_digest"] = evidence_digest
    return _stable_digest(payload)


def evaluate_journal_entry_controls(
    inputs: JournalEntryControlInput | Mapping[str, Any],
) -> JournalEntryControlEvaluation:
    """Evaluate a journal package without authorizing or posting it."""

    parsed = revalidate_model_boundary(JournalEntryControlInput, inputs)
    findings: list[FinanceControlFinding] = []
    evaluated_at = datetime.fromisoformat(
        parsed.evaluation_as_of.replace("Z", "+00:00")
    )
    evidence_digest = _evidence_digest(parsed.evidence_refs)
    evidence_by_ref = _assess_required_evidence(
        findings,
        evidence_refs=parsed.evidence_refs,
        evaluated_at=evaluated_at,
        policy=parsed.evidence_policy,
        additional_required_kinds=_JOURNAL_REQUIRED_EVIDENCE_KINDS,
    )

    _assess_company_period(
        findings,
        company=parsed.company,
        period=parsed.period,
        allowed_period_states={"open"},
    )
    entry_in_period = (
        parsed.period.start_date <= parsed.entry_date <= parsed.period.end_date
    )
    _finding(
        findings,
        code="period.entry_date",
        status="passed" if entry_in_period else "failed",
        message=(
            "Entry date falls within the accounting period."
            if entry_in_period
            else "Entry date falls outside the accounting period."
        ),
        field="entry_date",
        affected_refs=(parsed.entry_ref,),
    )
    currency_allowed = (
        parsed.transaction_currency in parsed.company.allowed_transaction_currencies
    )
    _finding(
        findings,
        code="currency.transaction",
        status="passed" if currency_allowed else "failed",
        message=(
            "Transaction currency is allowed for the company."
            if currency_allowed
            else "Transaction currency is not allowed for the company."
        ),
        field="transaction_currency",
    )
    _finding(
        findings,
        code="chart.snapshot_complete",
        status="passed" if parsed.chart_of_accounts_complete else "indeterminate",
        message=(
            "The supplied chart snapshot is declared complete."
            if parsed.chart_of_accounts_complete
            else "The supplied chart snapshot is incomplete, so account coverage cannot be proven."
        ),
        field="chart_of_accounts_complete",
    )

    accounts = {account.account_ref: account for account in parsed.chart_of_accounts}
    missing_accounts: list[str] = []
    invalid_accounts: list[str] = []
    invalid_line_scope: list[str] = []
    invalid_line_shape: list[str] = []
    invalid_scale: list[str] = []
    for line in parsed.lines:
        if (
            line.company_ref != parsed.company.company_ref
            or line.currency != parsed.transaction_currency
        ):
            invalid_line_scope.append(line.line_ref)
        if (line.debit > 0) == (line.credit > 0):
            invalid_line_shape.append(line.line_ref)
        if (
            _decimal_places(line.debit) > parsed.company.amount_scale
            or _decimal_places(line.credit) > parsed.company.amount_scale
        ):
            invalid_scale.append(line.line_ref)
        account = accounts.get(line.account_ref)
        if account is None:
            missing_accounts.append(line.account_ref)
            continue
        if (
            account.company_ref != parsed.company.company_ref
            or not account.active
            or not account.posting_allowed
            or line.currency not in account.allowed_currencies
        ):
            invalid_accounts.append(account.account_ref)

    missing_status: FinanceControlStatus = (
        "failed" if parsed.chart_of_accounts_complete else "indeterminate"
    )
    _finding(
        findings,
        code="chart.accounts_resolved",
        status=missing_status if missing_accounts else "passed",
        message=(
            "All journal accounts resolve in the supplied chart."
            if not missing_accounts
            else "One or more journal accounts are absent from the supplied chart."
        ),
        field="lines.account_ref",
        affected_refs=tuple(dict.fromkeys(missing_accounts)),
    )
    for code, refs, message in (
        (
            "chart.account_controls",
            invalid_accounts,
            "Journal accounts must be active, posting-enabled, in-company, and currency-compatible.",
        ),
        (
            "scope.line_company_currency",
            invalid_line_scope,
            "Every line must match the evaluated company and transaction currency.",
        ),
        (
            "journal.line_sidedness",
            invalid_line_shape,
            "Every line must contain exactly one positive debit or credit.",
        ),
        (
            "currency.amount_scale",
            invalid_scale,
            "Line amounts must fit the company's configured currency scale.",
        ),
    ):
        _finding(
            findings,
            code=code,
            status="failed" if refs else "passed",
            message=message if refs else f"{message[:-1]} validation passed.",
            field="lines",
            affected_refs=tuple(dict.fromkeys(refs)),
        )

    debit_total = sum((line.debit for line in parsed.lines), Decimal("0"))
    credit_total = sum((line.credit for line in parsed.lines), Decimal("0"))
    imbalance = debit_total - credit_total
    balanced = imbalance == 0 and debit_total > 0
    _finding(
        findings,
        code="journal.double_entry_balance",
        status="passed" if balanced else "failed",
        message=(
            "Journal debits and credits balance to a non-zero entry."
            if balanced
            else "Journal debits and credits must balance to a non-zero entry."
        ),
        field="lines",
        affected_refs=(parsed.entry_ref,),
    )

    _assess_approval(
        findings,
        approval=parsed.approval,
        evidence_by_ref=evidence_by_ref,
        evaluated_at=evaluated_at,
        policy=parsed.evidence_policy,
    )
    _assess_control_gates(
        findings,
        gates=parsed.control_gates,
        evidence_by_ref=evidence_by_ref,
        evaluated_at=evaluated_at,
        policy=parsed.evidence_policy,
    )
    disposition, passed, failed, indeterminate, actions = _evaluation_counts(findings)
    operation_digest = _operation_digest(parsed, evidence_digest)
    return JournalEntryControlEvaluation(
        evaluation_ref=parsed.evaluation_ref,
        company_ref=parsed.company.company_ref,
        period_ref=parsed.period.period_ref,
        evaluated_at=parsed.evaluation_as_of,
        disposition=disposition,
        findings=tuple(findings),
        passed_control_count=passed,
        failed_control_count=failed,
        indeterminate_control_count=indeterminate,
        next_actions=actions,
        evidence_refs=parsed.evidence_refs,
        operation_spec=JOURNAL_ENTRY_EVALUATION_OPERATION,
        operation_digest=operation_digest,
        evidence_digest=evidence_digest,
        entry_ref=parsed.entry_ref,
        transaction_currency=parsed.transaction_currency,
        debit_total=debit_total,
        credit_total=credit_total,
        imbalance=imbalance,
        posting_authorized=False,
    )


def evaluate_period_close_readiness(
    inputs: PeriodCloseReadinessInput | Mapping[str, Any],
) -> PeriodCloseReadinessEvaluation:
    """Evaluate close controls without authorizing or closing the period."""

    parsed = revalidate_model_boundary(PeriodCloseReadinessInput, inputs)
    findings: list[FinanceControlFinding] = []
    evaluated_at = datetime.fromisoformat(
        parsed.evaluation_as_of.replace("Z", "+00:00")
    )
    evidence_digest = _evidence_digest(parsed.evidence_refs)
    additional_kinds = (
        *_PERIOD_CLOSE_REQUIRED_EVIDENCE_KINDS,
        *(
            ("consolidation_package", "elimination_support")
            if parsed.consolidation.required
            else ()
        ),
    )
    evidence_by_ref = _assess_required_evidence(
        findings,
        evidence_refs=parsed.evidence_refs,
        evaluated_at=evaluated_at,
        policy=parsed.evidence_policy,
        additional_required_kinds=additional_kinds,
    )
    _assess_company_period(
        findings,
        company=parsed.company,
        period=parsed.period,
        allowed_period_states={"open", "soft_closed"},
    )

    trial_balance_imbalance = parsed.trial_balance_debits - parsed.trial_balance_credits
    _finding(
        findings,
        code="close.trial_balance",
        status=(
            "passed"
            if trial_balance_imbalance == 0 and parsed.trial_balance_debits > 0
            else "failed"
        ),
        message=(
            "Trial balance debits and credits reconcile to a non-zero ledger."
            if trial_balance_imbalance == 0 and parsed.trial_balance_debits > 0
            else "Trial balance must reconcile to a non-zero ledger before close."
        ),
        field="trial_balance_debits",
    )
    trial_balance_scale_valid = (
        _decimal_places(parsed.trial_balance_debits) <= parsed.company.amount_scale
        and _decimal_places(parsed.trial_balance_credits) <= parsed.company.amount_scale
    )
    _finding(
        findings,
        code="close.trial_balance_amount_scale",
        status="passed" if trial_balance_scale_valid else "failed",
        message=(
            "Trial balance amounts fit the company's configured currency scale."
            if trial_balance_scale_valid
            else "Trial balance amounts exceed the company's configured currency scale."
        ),
        field="trial_balance_debits",
    )

    accounts = {account.account_ref: account for account in parsed.chart_of_accounts}
    _finding(
        findings,
        code="close.chart_snapshot_complete",
        status="passed" if parsed.chart_of_accounts_complete else "indeterminate",
        message=(
            "The supplied close chart snapshot is declared complete."
            if parsed.chart_of_accounts_complete
            else "The supplied close chart snapshot is incomplete, so reconciliation coverage cannot be proven."
        ),
        field="chart_of_accounts_complete",
    )
    invalid_chart_accounts = [
        account.account_ref
        for account in parsed.chart_of_accounts
        if account.company_ref != parsed.company.company_ref
        or parsed.company.functional_currency not in account.allowed_currencies
        or not account.active
    ]
    _finding(
        findings,
        code="close.chart_scope",
        status="failed" if invalid_chart_accounts else "passed",
        message=(
            "Close chart contains inactive, out-of-company, or currency-incompatible accounts."
            if invalid_chart_accounts
            else "Close chart accounts match the company and functional currency."
        ),
        field="chart_of_accounts",
        affected_refs=invalid_chart_accounts,
    )

    required_accounts = {
        account.account_ref
        for account in parsed.chart_of_accounts
        if account.reconciliation_required
    }
    reconciliations = {
        reconciliation.account_ref: reconciliation
        for reconciliation in parsed.reconciliations
    }
    completed_reconciliations = 0
    if not required_accounts:
        _finding(
            findings,
            code="close.reconciliation_scope_missing",
            status="indeterminate",
            message="No accounts are identified as requiring reconciliation.",
            field="chart_of_accounts.reconciliation_required",
        )
    for account_ref in sorted(required_accounts):
        reconciliation = reconciliations.get(account_ref)
        if reconciliation is None:
            _finding(
                findings,
                code="close.reconciliation_missing",
                status="failed",
                message="A required account reconciliation is missing.",
                affected_refs=(account_ref,),
            )
            continue
        if reconciliation.status in {"incomplete", "exception", "not_applicable"}:
            _finding(
                findings,
                code="close.reconciliation_incomplete",
                status="failed",
                message="A required account reconciliation is incomplete or excepted.",
                affected_refs=(account_ref,),
                evidence_refs=reconciliation.evidence_refs,
            )
            continue
        if reconciliation.status != "complete":
            _finding(
                findings,
                code="close.reconciliation_unknown",
                status="indeterminate",
                message="A required account reconciliation has unknown status.",
                affected_refs=(account_ref,),
            )
            continue
        if reconciliation.unreconciled_amount is None:
            _finding(
                findings,
                code="close.reconciliation_amount_unknown",
                status="indeterminate",
                message="Completed reconciliation lacks an unreconciled amount.",
                affected_refs=(account_ref,),
            )
            continue
        if reconciliation.unreconciled_amount != 0:
            _finding(
                findings,
                code="close.reconciliation_difference",
                status="failed",
                message="A required reconciliation has a non-zero unexplained difference.",
                affected_refs=(account_ref,),
            )
            continue
        if (
            reconciliation.reviewed_by_ref is None
            or reconciliation.completed_at is None
        ):
            _finding(
                findings,
                code="close.reconciliation_review_missing",
                status="indeterminate",
                message="Completed reconciliation lacks reviewer or completion evidence.",
                affected_refs=(account_ref,),
            )
            continue
        reconciliation_completed_at = datetime.fromisoformat(
            reconciliation.completed_at.replace("Z", "+00:00")
        )
        if reconciliation_completed_at > evaluated_at:
            _finding(
                findings,
                code="close.reconciliation_completion_future",
                status="failed",
                message="A reconciliation completion time is after the evaluation time.",
                affected_refs=(account_ref,),
            )
            continue
        support = _support_status(
            reconciliation.evidence_refs,
            evidence_by_ref=evidence_by_ref,
            evaluated_at=evaluated_at,
            policy=parsed.evidence_policy,
        )
        _finding(
            findings,
            code="close.reconciliation_evidence",
            status=support,
            message=(
                "Required reconciliation is complete, reviewed, and evidenced."
                if support == "passed"
                else "Required reconciliation evidence is missing, stale, or invalid."
            ),
            affected_refs=(account_ref,),
            evidence_refs=reconciliation.evidence_refs,
        )
        if support == "passed":
            completed_reconciliations += 1

    unexpected_reconciliation_accounts = sorted(
        account_ref for account_ref in reconciliations if account_ref not in accounts
    )
    if unexpected_reconciliation_accounts:
        _finding(
            findings,
            code="close.reconciliation_account_unknown",
            status=("failed" if parsed.chart_of_accounts_complete else "indeterminate"),
            message="A reconciliation references an account absent from the chart.",
            affected_refs=unexpected_reconciliation_accounts,
        )

    consolidation = parsed.consolidation
    missing_entity_refs = tuple(
        sorted(
            set(consolidation.required_entity_refs)
            - set(consolidation.received_entity_refs)
        )
    )
    if not consolidation.required:
        _finding(
            findings,
            code="close.consolidation_not_required",
            status="passed",
            message="Consolidation and eliminations are not required for this close.",
        )
    else:
        _finding(
            findings,
            code="close.consolidation_entities",
            status="failed" if missing_entity_refs else "passed",
            message=(
                "All required consolidation entities supplied close packages."
                if not missing_entity_refs
                else "One or more required consolidation entity packages are missing."
            ),
            affected_refs=missing_entity_refs,
        )
        if consolidation.group_currency is None:
            _finding(
                findings,
                code="close.consolidation_currency_missing",
                status="indeterminate",
                message="Required consolidation lacks a group currency.",
            )
        for field_name, status_value in (
            ("currency_translation", consolidation.currency_translation_status),
            ("intercompany_matching", consolidation.intercompany_matching_status),
            ("elimination", consolidation.elimination_status),
        ):
            status: FinanceControlStatus = (
                "passed"
                if status_value == "passed"
                else "indeterminate"
                if status_value == "unknown"
                else "failed"
            )
            _finding(
                findings,
                code=f"close.{field_name}",
                status=status,
                message=f"Required {field_name.replace('_', ' ')} status is {status_value}.",
                field=f"consolidation.{field_name}_status",
            )
        if (
            consolidation.elimination_debits is None
            or consolidation.elimination_credits is None
        ):
            elimination_balance_status: FinanceControlStatus = "indeterminate"
            elimination_message = "Elimination entry totals are not fully supplied."
        elif consolidation.elimination_debits != consolidation.elimination_credits:
            elimination_balance_status = "failed"
            elimination_message = "Elimination entry debits and credits do not balance."
        else:
            elimination_balance_status = "passed"
            elimination_message = "Elimination entry debits and credits balance."
        _finding(
            findings,
            code="close.elimination_balance",
            status=elimination_balance_status,
            message=elimination_message,
            field="consolidation.elimination_debits",
        )
        consolidation_support = _support_status(
            consolidation.evidence_refs,
            evidence_by_ref=evidence_by_ref,
            evaluated_at=evaluated_at,
            policy=parsed.evidence_policy,
        )
        if consolidation.approved_by_ref is None and consolidation_support == "passed":
            consolidation_support = "indeterminate"
        _finding(
            findings,
            code="close.consolidation_evidence",
            status=consolidation_support,
            message=(
                "Consolidation and elimination package is approved and evidenced."
                if consolidation_support == "passed"
                else "Consolidation approval or usable evidence is incomplete."
            ),
            evidence_refs=consolidation.evidence_refs,
        )

    _assess_approval(
        findings,
        approval=parsed.approval,
        evidence_by_ref=evidence_by_ref,
        evaluated_at=evaluated_at,
        policy=parsed.evidence_policy,
    )
    _assess_control_gates(
        findings,
        gates=parsed.control_gates,
        evidence_by_ref=evidence_by_ref,
        evaluated_at=evaluated_at,
        policy=parsed.evidence_policy,
    )
    disposition, passed, failed, indeterminate, actions = _evaluation_counts(findings)
    operation_digest = _operation_digest(parsed, evidence_digest)
    return PeriodCloseReadinessEvaluation(
        evaluation_ref=parsed.evaluation_ref,
        company_ref=parsed.company.company_ref,
        period_ref=parsed.period.period_ref,
        evaluated_at=parsed.evaluation_as_of,
        disposition=disposition,
        findings=tuple(findings),
        passed_control_count=passed,
        failed_control_count=failed,
        indeterminate_control_count=indeterminate,
        next_actions=actions,
        evidence_refs=parsed.evidence_refs,
        operation_spec=PERIOD_CLOSE_EVALUATION_OPERATION,
        operation_digest=operation_digest,
        evidence_digest=evidence_digest,
        close_ref=parsed.close_ref,
        trial_balance_debits=parsed.trial_balance_debits,
        trial_balance_credits=parsed.trial_balance_credits,
        trial_balance_imbalance=trial_balance_imbalance,
        required_reconciliation_count=len(required_accounts),
        completed_reconciliation_count=completed_reconciliations,
        consolidation_required=consolidation.required,
        missing_entity_refs=missing_entity_refs,
        close_authorized=False,
    )


def _primitive_result(
    *,
    primitive_ref: str,
    primitive_version: str,
    output: JournalEntryControlEvaluation | PeriodCloseReadinessEvaluation,
) -> PrimitiveExecutionResult[Any]:
    event_type = (
        "finance.journal_entry_controls_evaluated"
        if isinstance(output, JournalEntryControlEvaluation)
        else "finance.period_close_readiness_evaluated"
    )
    receipt = PrimitiveOperationReceipt(
        spec=output.operation_spec,
        status=PrimitiveOperationStatus.COMPLETED,
        request_digest=output.operation_digest,
        external_refs={"evaluation_digest": output.evaluation_digest},
        evidence_refs=list(output.evidence_refs),
    )
    return PrimitiveExecutionResult(
        status=PrimitiveExecutionStatus.COMPLETED,
        primitive_ref=primitive_ref,
        primitive_version=primitive_version,
        summary=f"Accounting control evaluation completed: {output.disposition}.",
        output=output,
        events=[
            PrimitiveEvent(
                type=event_type,
                payload={
                    "disposition": output.disposition,
                    "operation_digest": output.operation_digest,
                    "evidence_digest": output.evidence_digest,
                    "evaluation_digest": output.evaluation_digest,
                },
            )
        ],
        evidence=[
            PrimitiveEvidence(
                kind="accounting_control_evaluation",
                summary="Deterministic accounting controls evaluated without a ledger write.",
                labels=[output.disposition, "read_only", "spring_authority_required"],
                refs={
                    "operation_digest": output.operation_digest,
                    "evidence_digest": output.evidence_digest,
                    "evaluation_digest": output.evaluation_digest,
                },
            )
        ],
        evidence_refs=list(output.evidence_refs),
        operation_receipts=[receipt],
    )


def _example_evidence(
    evidence_ref: str,
    kind: str,
    digest_character: str,
    *,
    observed_at: str = "2026-08-24T11:00:00Z",
    effective_at: str = "2026-08-24T10:00:00Z",
) -> dict[str, Any]:
    return {
        "schema": "lightbulb.primitive_evidence_ref.v1",
        "evidence_ref": evidence_ref,
        "kind": kind,
        "issuer_ref": "spring-finance-authority",
        "subject_ref": "company-example",
        "sha256": digest_character * 64,
        "observed_at": observed_at,
        "effective_at": effective_at,
        "verification_grade": "verified",
        "classification": "confidential",
    }


def _journal_example_inputs() -> dict[str, Any]:
    return {
        "schema": JOURNAL_ENTRY_CONTROL_INPUT_SCHEMA,
        "evaluation_ref": "journal-evaluation-example",
        "evaluation_as_of": "2026-08-24T12:00:00Z",
        "entry_ref": "journal-entry-example",
        "entry_date": "2026-08-24",
        "transaction_currency": "USD",
        "company": {
            "company_ref": "company-example",
            "functional_currency": "USD",
            "allowed_transaction_currencies": ["USD"],
            "amount_scale": 2,
        },
        "period": {
            "period_ref": "period-2026-08",
            "company_ref": "company-example",
            "functional_currency": "USD",
            "start_date": "2026-08-01",
            "end_date": "2026-08-31",
            "state": "open",
        },
        "chart_of_accounts_complete": True,
        "chart_of_accounts": [
            {
                "account_ref": "account-cash",
                "company_ref": "company-example",
                "allowed_currencies": ["USD"],
                "active": True,
                "posting_allowed": True,
            },
            {
                "account_ref": "account-revenue",
                "company_ref": "company-example",
                "allowed_currencies": ["USD"],
                "active": True,
                "posting_allowed": True,
            },
        ],
        "lines": [
            {
                "line_ref": "line-debit",
                "account_ref": "account-cash",
                "company_ref": "company-example",
                "currency": "USD",
                "debit": "100.00",
                "credit": "0.00",
            },
            {
                "line_ref": "line-credit",
                "account_ref": "account-revenue",
                "company_ref": "company-example",
                "currency": "USD",
                "debit": "0.00",
                "credit": "100.00",
            },
        ],
        "approval": {
            "required": False,
            "status": "not_required",
            "prepared_by_ref": "actor-preparer",
        },
        "evidence_refs": [
            _example_evidence("evidence-journal", "journal_source", "a"),
            _example_evidence("evidence-chart", "chart_of_accounts", "b"),
            _example_evidence("evidence-period", "period_status", "c"),
        ],
    }


def _period_close_example_inputs() -> dict[str, Any]:
    return {
        "schema": PERIOD_CLOSE_READINESS_INPUT_SCHEMA,
        "evaluation_ref": "close-evaluation-example",
        "evaluation_as_of": "2026-09-01T12:00:00Z",
        "close_ref": "close-2026-08",
        "company": {
            "company_ref": "company-example",
            "functional_currency": "USD",
            "allowed_transaction_currencies": ["USD"],
            "amount_scale": 2,
        },
        "period": {
            "period_ref": "period-2026-08",
            "company_ref": "company-example",
            "functional_currency": "USD",
            "start_date": "2026-08-01",
            "end_date": "2026-08-31",
            "state": "soft_closed",
        },
        "chart_of_accounts_complete": True,
        "chart_of_accounts": [
            {
                "account_ref": "account-cash",
                "company_ref": "company-example",
                "allowed_currencies": ["USD"],
                "active": True,
                "posting_allowed": True,
                "reconciliation_required": True,
            }
        ],
        "trial_balance_debits": "1000.00",
        "trial_balance_credits": "1000.00",
        "reconciliations": [
            {
                "reconciliation_ref": "reconciliation-cash",
                "account_ref": "account-cash",
                "company_ref": "company-example",
                "period_ref": "period-2026-08",
                "balance_as_of": "2026-08-31",
                "status": "complete",
                "unreconciled_amount": "0.00",
                "reviewed_by_ref": "actor-reviewer",
                "completed_at": "2026-09-01T10:30:00Z",
                "evidence_refs": ["evidence-reconciliation"],
            }
        ],
        "consolidation": {
            "required": False,
            "currency_translation_status": "not_applicable",
            "intercompany_matching_status": "not_applicable",
            "elimination_status": "not_applicable",
        },
        "approval": {
            "required": False,
            "status": "not_required",
            "prepared_by_ref": "actor-close-preparer",
        },
        "evidence_refs": [
            _example_evidence(
                "evidence-trial-balance",
                "trial_balance",
                "d",
                observed_at="2026-09-01T11:00:00Z",
                effective_at="2026-09-01T10:00:00Z",
            ),
            _example_evidence(
                "evidence-reconciliation",
                "reconciliation",
                "e",
                observed_at="2026-09-01T11:00:00Z",
                effective_at="2026-09-01T10:00:00Z",
            ),
            _example_evidence(
                "evidence-period",
                "period_status",
                "f",
                observed_at="2026-09-01T11:00:00Z",
                effective_at="2026-09-01T10:00:00Z",
            ),
        ],
    }


class EvaluateJournalEntryControlsPrimitive(
    BusinessProcessPrimitive[JournalEntryControlInput, JournalEntryControlEvaluation]
):
    primitive_ref = "finance.evaluate_journal_entry_controls"
    version = "1.0.0"
    title = "Evaluate journal entry controls"
    description = (
        "Deterministically assess journal balance, scope, evidence, approval, and "
        "control gates without authorizing or posting the entry."
    )
    input_model = JournalEntryControlInput
    output_model = JournalEntryControlEvaluation
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    example_inputs = _journal_example_inputs()
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False

    def implementation_contract(self) -> dict[str, Any]:
        contract = super().implementation_contract()
        contract["operation_contract"] = JOURNAL_ENTRY_EVALUATION_OPERATION.to_dict()
        contract["effect_boundary"] = {
            "connector_reads": 0,
            "connector_writes": 0,
            "ledger_writes": 0,
            "posting_authorized": False,
        }
        contract["system_of_record_authority"] = "spring_host_required"
        return contract

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: JournalEntryControlInput,
    ) -> PrimitiveExecutionResult[JournalEntryControlEvaluation]:
        del context
        return _primitive_result(
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            output=evaluate_journal_entry_controls(inputs),
        )


class EvaluatePeriodCloseReadinessPrimitive(
    BusinessProcessPrimitive[
        PeriodCloseReadinessInput,
        PeriodCloseReadinessEvaluation,
    ]
):
    primitive_ref = "finance.evaluate_period_close_readiness"
    version = "1.0.0"
    title = "Evaluate period close readiness"
    description = (
        "Deterministically assess trial balance, reconciliations, consolidation, "
        "eliminations, evidence, and approval without authorizing period close."
    )
    input_model = PeriodCloseReadinessInput
    output_model = PeriodCloseReadinessEvaluation
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    example_inputs = _period_close_example_inputs()
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False

    def implementation_contract(self) -> dict[str, Any]:
        contract = super().implementation_contract()
        contract["operation_contract"] = PERIOD_CLOSE_EVALUATION_OPERATION.to_dict()
        contract["effect_boundary"] = {
            "connector_reads": 0,
            "connector_writes": 0,
            "ledger_writes": 0,
            "period_closes": 0,
            "close_authorized": False,
        }
        contract["system_of_record_authority"] = "spring_host_required"
        return contract

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: PeriodCloseReadinessInput,
    ) -> PrimitiveExecutionResult[PeriodCloseReadinessEvaluation]:
        del context
        return _primitive_result(
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            output=evaluate_period_close_readiness(inputs),
        )


FINANCE_ACCOUNTING_EXECUTABLE_PRIMITIVES: tuple[
    BusinessProcessPrimitive[Any, Any], ...
] = (
    EvaluateJournalEntryControlsPrimitive(),
    EvaluatePeriodCloseReadinessPrimitive(),
)


__all__ = [
    "AccountingApprovalGate",
    "AccountingControlGate",
    "AccountingEvidencePolicy",
    "AccountingPeriodState",
    "AccountingPeriodContext",
    "ApprovalStatus",
    "ChartAccountControl",
    "CompanyAccountingContext",
    "ConsolidationReadiness",
    "ControlGateStatus",
    "EvaluateJournalEntryControlsPrimitive",
    "EvaluatePeriodCloseReadinessPrimitive",
    "FINANCE_ACCOUNTING_EXECUTABLE_PRIMITIVES",
    "FinanceControlDisposition",
    "FinanceControlFinding",
    "FinanceControlStatus",
    "JournalEntryControlEvaluation",
    "JournalEntryControlInput",
    "JournalEntryLine",
    "JOURNAL_ENTRY_CONTROL_EVALUATION_SCHEMA",
    "JOURNAL_ENTRY_CONTROL_INPUT_SCHEMA",
    "JOURNAL_ENTRY_EVALUATION_OPERATION",
    "PERIOD_CLOSE_READINESS_EVALUATION_SCHEMA",
    "PERIOD_CLOSE_EVALUATION_OPERATION",
    "PERIOD_CLOSE_READINESS_INPUT_SCHEMA",
    "PeriodCloseReadinessEvaluation",
    "PeriodCloseReadinessInput",
    "ReconciliationControl",
    "ReconciliationStatus",
    "evaluate_journal_entry_controls",
    "evaluate_period_close_readiness",
]
