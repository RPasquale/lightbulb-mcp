"""Deterministic, evidence-bound finance period-close proposal lifecycle.

The SDK validates and materializes an immutable period-close candidate.  It
does not authenticate actors, open or close a ledger, post an adjustment, lock
a subledger, record an approval, persist audit evidence, or invoke a connector.
Those authoritative effects remain with the Spring Control Plane and the
governed finance systems behind it.

The lifecycle is deliberately bounded to one ordered pass:

``open -> trial balance -> reconciliations -> adjustments -> locks ->
consolidation -> independent approval evidence -> close proposal``.

Every transition is exact-scope, revision fenced, content sealed, globally
evidence-lineage chained, and fail-closed when its host outcome is uncertain.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from typing import Annotated, Any, Literal, TypeAlias
from uuid import UUID

from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationInfo,
    field_validator,
    model_validator,
)

from lightbulb.connector_execution import ConnectorEffect
from lightbulb.primitive_runtime import (
    BusinessProcessPrimitive,
    PrimitiveBlocker,
    PrimitiveEvent,
    PrimitiveEvidence,
    PrimitiveEvidenceClassification,
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
    PrimitiveRecoveryDisposition,
    PrimitiveRecoveryPlan,
    revalidate_model_boundary,
)

PERIOD_CLOSE_SNAPSHOT_SCHEMA = "lightbulb.finance_period_close_snapshot.v1"
PERIOD_CLOSE_COMMAND_SCHEMA = "lightbulb.finance_period_close_command.v1"
PERIOD_CLOSE_INPUT_SCHEMA = "lightbulb.finance_period_close_input.v1"
PERIOD_CLOSE_RECEIPT_SCHEMA = "lightbulb.finance_period_close_receipt.v1"
PERIOD_CLOSE_RESULT_SCHEMA = "lightbulb.finance_period_close_result.v1"

GENESIS_PERIOD_CLOSE_DIGEST = "0" * 64
MAX_PERIOD_CLOSE_TRANSITIONS = 8
MAX_EVIDENCE_AGE = timedelta(days=7)
MINIMUM_EVIDENCE_RETENTION_YEARS = 7
MAX_MONEY = Decimal("1000000000000000000")

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}$"
_CURRENCY_PATTERN = r"^[A-Z]{3}$"


def _visible_ref(value: str) -> str:
    if value != value.strip() or any(ord(character) < 33 for character in value):
        raise ValueError("references must contain visible non-whitespace characters")
    return value


OpaqueRef = Annotated[
    str,
    StringConstraints(pattern=_REF_PATTERN),
    AfterValidator(_visible_ref),
]
Sha256Digest = Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)]
CurrencyCode = Annotated[str, StringConstraints(pattern=_CURRENCY_PATTERN)]


def _integer_literal(value: Any) -> Any:
    if isinstance(value, bool):
        raise ValueError("integer fields cannot use boolean values")
    return value


def _boolean_literal(value: Any) -> Any:
    if not isinstance(value, bool):
        raise ValueError("boolean fields require JSON boolean values")
    return value


def _money_literal(value: Any) -> Decimal:
    if isinstance(value, bool) or isinstance(value, (float, int)):
        raise ValueError("money must be supplied as a decimal string or Decimal")
    if not isinstance(value, (str, Decimal)):
        raise ValueError("money must be supplied as a decimal string or Decimal")
    if isinstance(value, str) and (not value or value != value.strip()):
        raise ValueError("money must be a canonical visible decimal")
    try:
        parsed = Decimal(value)
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("money must be a finite decimal") from exc
    if not parsed.is_finite() or abs(parsed) > MAX_MONEY:
        raise ValueError("money must be finite and within the supported bound")
    if parsed.as_tuple().exponent < -4:
        raise ValueError("money supports at most four decimal places")
    return Decimal(0) if parsed == 0 else parsed.normalize()


StrictZero = Annotated[Literal[0], BeforeValidator(_integer_literal)]
StrictTrue = Annotated[Literal[True], BeforeValidator(_boolean_literal)]
StrictFalse = Annotated[Literal[False], BeforeValidator(_boolean_literal)]
Money = Annotated[Decimal, BeforeValidator(_money_literal)]

TransitionKind = Literal[
    "open_period",
    "capture_trial_balance",
    "reconcile_accounts",
    "record_adjusting_entries",
    "lock_subledgers",
    "consolidate",
    "approve_close",
    "close_period",
]
LifecycleStatus = Literal[
    "period_open_evidence_validated",
    "trial_balance_validated",
    "reconciliations_validated",
    "adjustments_validated",
    "subledger_locks_validated",
    "consolidation_validated",
    "independent_approval_evidence_validated",
    "close_candidate_validated",
]

_COMMAND_ORDER: tuple[TransitionKind, ...] = (
    "open_period",
    "capture_trial_balance",
    "reconcile_accounts",
    "record_adjusting_entries",
    "lock_subledgers",
    "consolidate",
    "approve_close",
    "close_period",
)
_STATUS_ORDER: tuple[LifecycleStatus, ...] = (
    "period_open_evidence_validated",
    "trial_balance_validated",
    "reconciliations_validated",
    "adjustments_validated",
    "subledger_locks_validated",
    "consolidation_validated",
    "independent_approval_evidence_validated",
    "close_candidate_validated",
)
_EVIDENCE_CONTRACT: dict[TransitionKind, tuple[str, str]] = {
    "open_period": ("period_calendar", "period_open_state_attestation"),
    "capture_trial_balance": ("trial_balance_extract", "ledger_extract_attestation"),
    "reconcile_accounts": (
        "account_subledger_reconciliations",
        "reconciliation_review_attestation",
    ),
    "record_adjusting_entries": (
        "adjusting_entry_batch",
        "adjustment_posting_attestation",
    ),
    "lock_subledgers": ("subledger_lock_record", "subledger_lock_attestation"),
    "consolidate": (
        "consolidation_workpaper",
        "intercompany_elimination_attestation",
    ),
    "approve_close": ("close_review_workpaper", "spring_close_approval_attestation"),
    "close_period": ("close_request", "spring_close_readiness_attestation"),
}
_GRADE_RANK = {
    PrimitiveEvidenceVerificationGrade.UNVERIFIED: 0,
    PrimitiveEvidenceVerificationGrade.ASSERTED: 1,
    PrimitiveEvidenceVerificationGrade.ATTESTED: 2,
    PrimitiveEvidenceVerificationGrade.VERIFIED: 3,
}


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


def _as_tuple(value: Any) -> Any:
    return tuple(value) if isinstance(value, list) else value


def _sorted_unique_tuple(value: Any, *, label: str) -> Any:
    values = _as_tuple(value)
    if not isinstance(values, tuple):
        return values
    if any(not isinstance(item, str) for item in values):
        return values
    if tuple(sorted(values)) != values or len(values) != len(set(values)):
        raise ValueError(f"{label} must be unique and canonically sorted")
    return values


def _unique(values: Sequence[str], *, label: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must be unique")


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


def _calendar_years_after(value: datetime, years: int) -> datetime:
    try:
        return value.replace(year=value.year + years)
    except ValueError:
        return value.replace(year=value.year + years, day=28)


def _stable_digest(value: Any) -> str:
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _nonnegative(value: Decimal, *, label: str) -> None:
    if value < 0:
        raise ValueError(f"{label} cannot be negative")


def _distinct(*actors: str, label: str) -> None:
    if len(actors) != len(set(actors)):
        raise ValueError(f"{label} requires structurally distinct actors")


class SubledgerScopeBinding(_StrictModel):
    subledger_ref: OpaqueRef
    control_account_ref: OpaqueRef


class PeriodCloseScope(_StrictModel):
    tenant_ref: OpaqueRef
    company_ref: OpaqueRef
    project_ref: OpaqueRef
    project_id: UUID
    scope_kind: Literal["entity", "consolidation_group"]
    entity_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=100)
    consolidation_group_ref: OpaqueRef | None = None
    ledger_ref: OpaqueRef
    functional_currency: CurrencyCode
    fiscal_period_ref: OpaqueRef
    period_started_at: str
    period_ended_at: str
    jurisdiction_ref: OpaqueRef
    financial_retention_policy_ref: OpaqueRef
    evidence_retention_until: str
    materiality_threshold: Money
    required_subledgers: tuple[SubledgerScopeBinding, ...] = Field(
        min_length=1,
        max_length=100,
    )
    evidence_custody_ref: OpaqueRef
    spring_authority_ref: OpaqueRef
    authorized_evidence_issuer_refs: tuple[OpaqueRef, ...] = Field(
        min_length=2,
        max_length=100,
    )

    @field_validator(
        "period_started_at",
        "period_ended_at",
        "evidence_retention_until",
    )
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=info.field_name)

    @field_validator("project_id", mode="before")
    @classmethod
    def _canonical_project_id(cls, value: Any) -> UUID:
        if isinstance(value, UUID):
            return value
        if not isinstance(value, str) or value != value.strip():
            raise ValueError("project_id must be a canonical UUID")
        try:
            parsed = UUID(value)
        except ValueError as exc:
            raise ValueError("project_id must be a canonical UUID") from exc
        if str(parsed) != value.lower():
            raise ValueError("project_id must be a canonical UUID")
        return parsed

    @field_validator("entity_refs", "authorized_evidence_issuer_refs", mode="before")
    @classmethod
    def _sorted_refs(cls, value: Any, info: Any) -> Any:
        return _sorted_unique_tuple(value, label=info.field_name)

    @field_validator("required_subledgers", mode="before")
    @classmethod
    def _subledgers_tuple(cls, value: Any) -> Any:
        values = _as_tuple(value)
        if isinstance(values, tuple) and all(
            isinstance(item, Mapping) for item in values
        ):
            values = tuple(sorted(values, key=lambda item: str(item["subledger_ref"])))
        return values

    @model_validator(mode="after")
    def _scope_is_exact(self) -> "PeriodCloseScope":
        if self.scope_kind == "entity":
            if len(self.entity_refs) != 1 or self.consolidation_group_ref is not None:
                raise ValueError(
                    "entity close requires one entity and no consolidation group"
                )
        elif len(self.entity_refs) < 2 or self.consolidation_group_ref is None:
            raise ValueError(
                "consolidation-group close requires a group and at least two entities"
            )
        if _parsed_timestamp(self.period_started_at) >= _parsed_timestamp(
            self.period_ended_at
        ):
            raise ValueError("fiscal period must have a positive duration")
        if _parsed_timestamp(self.evidence_retention_until) < _calendar_years_after(
            _parsed_timestamp(self.period_ended_at),
            MINIMUM_EVIDENCE_RETENTION_YEARS,
        ):
            raise ValueError(
                "finance evidence retention must cover at least seven years"
            )
        _nonnegative(self.materiality_threshold, label="materiality threshold")
        subledger_refs = [item.subledger_ref for item in self.required_subledgers]
        control_refs = [item.control_account_ref for item in self.required_subledgers]
        _unique(subledger_refs, label="subledger scope references")
        _unique(control_refs, label="subledger control-account references")
        if tuple(subledger_refs) != tuple(sorted(subledger_refs)):
            raise ValueError("required subledgers must use canonical order")
        if self.spring_authority_ref not in self.authorized_evidence_issuer_refs:
            raise ValueError("Spring authority must be an authorized evidence issuer")
        return self


def period_close_scope_digest(scope: PeriodCloseScope | Mapping[str, Any]) -> str:
    parsed = revalidate_model_boundary(PeriodCloseScope, scope)
    return _stable_digest(parsed.to_dict())


class CloseEvidenceEnvelope(_StrictModel):
    schema_id: Literal["lightbulb.finance_close_evidence_envelope.v1"] = Field(
        default="lightbulb.finance_close_evidence_envelope.v1",
        alias="schema",
    )
    sequence: int = Field(ge=1, le=20)
    use_ref: OpaqueRef
    artifact_ref: OpaqueRef
    artifact_digest: Sha256Digest
    predecessor_lineage_digest: Sha256Digest
    lineage_digest: Sha256Digest
    custody_ref: OpaqueRef
    retained_until: str
    single_use: StrictTrue = True
    reference: PrimitiveEvidenceRef

    @field_validator("retained_until")
    @classmethod
    def _retained_until(cls, value: str) -> str:
        return _timestamp(value, field_name="retained_until")

    @field_validator("artifact_digest")
    @classmethod
    def _artifact_digest_is_material(cls, value: str) -> str:
        if value == GENESIS_PERIOD_CLOSE_DIGEST:
            raise ValueError("artifact digest cannot use the genesis sentinel")
        return value

    @field_validator("reference", mode="before")
    @classmethod
    def _portable_reference_is_revalidated(cls, value: Any) -> Any:
        payload = value.to_dict() if isinstance(value, PrimitiveEvidenceRef) else value
        return PrimitiveEvidenceRef.model_validate(payload)


class _PackageBase(_StrictModel):
    evidence_use_refs: tuple[OpaqueRef, ...] = Field(min_length=2, max_length=20)

    @field_validator("evidence_use_refs", mode="before")
    @classmethod
    def _evidence_refs(cls, value: Any) -> Any:
        return _sorted_unique_tuple(value, label="package evidence use references")


class OpenPeriodPackage(_PackageBase):
    kind: Literal["open_period"] = "open_period"
    period_open_candidate_ref: OpaqueRef
    prior_period_state: Literal["closed", "not_applicable"]
    opened_at: str
    opened_by_ref: OpaqueRef
    reviewed_by_ref: OpaqueRef

    @field_validator("opened_at")
    @classmethod
    def _opened_at(cls, value: str) -> str:
        return _timestamp(value, field_name="opened_at")

    @model_validator(mode="after")
    def _opening_is_reviewed(self) -> "OpenPeriodPackage":
        _distinct(
            self.opened_by_ref,
            self.reviewed_by_ref,
            label="period opening and review",
        )
        return self


class TrialBalanceLine(_StrictModel):
    account_ref: OpaqueRef
    account_class: Literal["asset", "liability", "equity", "revenue", "expense"]
    debit: Money
    credit: Money

    @model_validator(mode="after")
    def _one_sided_balance(self) -> "TrialBalanceLine":
        _nonnegative(self.debit, label="trial-balance debit")
        _nonnegative(self.credit, label="trial-balance credit")
        if (self.debit == 0) == (self.credit == 0):
            raise ValueError(
                "trial-balance line must contain exactly one non-zero side"
            )
        return self


class TrialBalancePackage(_PackageBase):
    kind: Literal["capture_trial_balance"] = "capture_trial_balance"
    trial_balance_ref: OpaqueRef
    as_of: str
    currency: CurrencyCode
    lines: tuple[TrialBalanceLine, ...] = Field(min_length=2, max_length=5_000)
    total_debit: Money
    total_credit: Money
    prepared_by_ref: OpaqueRef
    reviewed_by_ref: OpaqueRef

    @field_validator("as_of")
    @classmethod
    def _as_of(cls, value: str) -> str:
        return _timestamp(value, field_name="as_of")

    @field_validator("lines", mode="before")
    @classmethod
    def _lines_tuple(cls, value: Any) -> Any:
        values = _as_tuple(value)
        if isinstance(values, tuple) and all(
            isinstance(item, Mapping) for item in values
        ):
            values = tuple(sorted(values, key=lambda item: str(item["account_ref"])))
        return values

    @model_validator(mode="after")
    def _trial_balance_is_balanced(self) -> "TrialBalancePackage":
        accounts = [line.account_ref for line in self.lines]
        _unique(accounts, label="trial-balance accounts")
        if tuple(accounts) != tuple(sorted(accounts)):
            raise ValueError("trial-balance lines must use canonical account order")
        debit = sum((line.debit for line in self.lines), Decimal(0))
        credit = sum((line.credit for line in self.lines), Decimal(0))
        if self.total_debit != debit or self.total_credit != credit:
            raise ValueError("trial-balance totals must equal the exact line totals")
        if debit != credit:
            raise ValueError("trial balance must have equal debit and credit totals")
        _distinct(
            self.prepared_by_ref,
            self.reviewed_by_ref,
            label="trial-balance preparation and review",
        )
        return self


class AccountReconciliationRecord(_StrictModel):
    account_ref: OpaqueRef
    reconciliation_ref: OpaqueRef
    ledger_balance: Money
    source_balance: Money
    reconciling_items_total: Money
    unexplained_variance: Money
    materiality_threshold: Money
    status: Literal["reconciled"] = "reconciled"
    prepared_by_ref: OpaqueRef
    reviewed_by_ref: OpaqueRef

    @model_validator(mode="after")
    def _reconciliation_is_explainable(self) -> "AccountReconciliationRecord":
        _nonnegative(self.materiality_threshold, label="account materiality threshold")
        if (
            self.ledger_balance - self.source_balance - self.reconciling_items_total
            != self.unexplained_variance
        ):
            raise ValueError("account reconciliation arithmetic is inconsistent")
        if abs(self.unexplained_variance) > self.materiality_threshold:
            raise ValueError(
                "account reconciliation has a material unexplained variance"
            )
        _distinct(
            self.prepared_by_ref,
            self.reviewed_by_ref,
            label="account reconciliation preparation and review",
        )
        return self


class SubledgerReconciliationRecord(_StrictModel):
    subledger_ref: OpaqueRef
    control_account_ref: OpaqueRef
    reconciliation_ref: OpaqueRef
    subledger_balance: Money
    general_ledger_balance: Money
    reconciling_items_total: Money
    unexplained_variance: Money
    materiality_threshold: Money
    status: Literal["reconciled"] = "reconciled"
    prepared_by_ref: OpaqueRef
    reviewed_by_ref: OpaqueRef

    @model_validator(mode="after")
    def _reconciliation_is_explainable(self) -> "SubledgerReconciliationRecord":
        _nonnegative(
            self.materiality_threshold, label="subledger materiality threshold"
        )
        if (
            self.general_ledger_balance
            - self.subledger_balance
            - self.reconciling_items_total
            != self.unexplained_variance
        ):
            raise ValueError("subledger reconciliation arithmetic is inconsistent")
        if abs(self.unexplained_variance) > self.materiality_threshold:
            raise ValueError(
                "subledger reconciliation has a material unexplained variance"
            )
        _distinct(
            self.prepared_by_ref,
            self.reviewed_by_ref,
            label="subledger reconciliation preparation and review",
        )
        return self


class ReconciliationPackage(_PackageBase):
    kind: Literal["reconcile_accounts"] = "reconcile_accounts"
    reconciliation_set_ref: OpaqueRef
    trial_balance_transition_digest: Sha256Digest
    account_reconciliations: tuple[AccountReconciliationRecord, ...] = Field(
        min_length=2,
        max_length=5_000,
    )
    subledger_reconciliations: tuple[SubledgerReconciliationRecord, ...] = Field(
        min_length=1,
        max_length=100,
    )
    aggregate_unexplained_variance: Money
    review_completed_at: str

    @field_validator("review_completed_at")
    @classmethod
    def _reviewed_at(cls, value: str) -> str:
        return _timestamp(value, field_name="review_completed_at")

    @field_validator("account_reconciliations", mode="before")
    @classmethod
    def _accounts_tuple(cls, value: Any) -> Any:
        values = _as_tuple(value)
        if isinstance(values, tuple) and all(
            isinstance(item, Mapping) for item in values
        ):
            values = tuple(sorted(values, key=lambda item: str(item["account_ref"])))
        return values

    @field_validator("subledger_reconciliations", mode="before")
    @classmethod
    def _subledgers_tuple(cls, value: Any) -> Any:
        values = _as_tuple(value)
        if isinstance(values, tuple) and all(
            isinstance(item, Mapping) for item in values
        ):
            values = tuple(sorted(values, key=lambda item: str(item["subledger_ref"])))
        return values

    @model_validator(mode="after")
    def _records_are_canonical(self) -> "ReconciliationPackage":
        account_refs = [item.account_ref for item in self.account_reconciliations]
        subledger_refs = [item.subledger_ref for item in self.subledger_reconciliations]
        reconciliation_refs = [
            item.reconciliation_ref
            for item in (
                *self.account_reconciliations,
                *self.subledger_reconciliations,
            )
        ]
        _unique(account_refs, label="account reconciliation references")
        _unique(subledger_refs, label="subledger reconciliation references")
        _unique(reconciliation_refs, label="reconciliation record references")
        if tuple(account_refs) != tuple(sorted(account_refs)):
            raise ValueError("account reconciliations must use canonical order")
        if tuple(subledger_refs) != tuple(sorted(subledger_refs)):
            raise ValueError("subledger reconciliations must use canonical order")
        aggregate = sum(
            (abs(item.unexplained_variance) for item in self.account_reconciliations),
            Decimal(0),
        ) + sum(
            (abs(item.unexplained_variance) for item in self.subledger_reconciliations),
            Decimal(0),
        )
        if self.aggregate_unexplained_variance != aggregate:
            raise ValueError("aggregate unexplained variance must equal exact records")
        return self


class JournalEntryLine(_StrictModel):
    line_ref: OpaqueRef
    account_ref: OpaqueRef
    debit: Money
    credit: Money

    @model_validator(mode="after")
    def _line_is_one_sided(self) -> "JournalEntryLine":
        _nonnegative(self.debit, label="journal debit")
        _nonnegative(self.credit, label="journal credit")
        if (self.debit == 0) == (self.credit == 0):
            raise ValueError("journal line must contain exactly one non-zero side")
        return self


class AdjustingJournalEntry(_StrictModel):
    journal_entry_ref: OpaqueRef
    currency: CurrencyCode
    effective_at: str
    lines: tuple[JournalEntryLine, ...] = Field(min_length=2, max_length=1_000)
    total_debit: Money
    total_credit: Money

    @field_validator("effective_at")
    @classmethod
    def _effective_at(cls, value: str) -> str:
        return _timestamp(value, field_name="effective_at")

    @field_validator("lines", mode="before")
    @classmethod
    def _lines_tuple(cls, value: Any) -> Any:
        values = _as_tuple(value)
        if isinstance(values, tuple) and all(
            isinstance(item, Mapping) for item in values
        ):
            values = tuple(sorted(values, key=lambda item: str(item["line_ref"])))
        return values

    @model_validator(mode="after")
    def _entry_is_balanced(self) -> "AdjustingJournalEntry":
        line_refs = [item.line_ref for item in self.lines]
        _unique(line_refs, label="adjusting-entry line references")
        if tuple(line_refs) != tuple(sorted(line_refs)):
            raise ValueError("adjusting-entry lines must use canonical order")
        debit = sum((line.debit for line in self.lines), Decimal(0))
        credit = sum((line.credit for line in self.lines), Decimal(0))
        if self.total_debit != debit or self.total_credit != credit:
            raise ValueError("adjusting-entry totals must equal the exact line totals")
        if debit != credit:
            raise ValueError("adjusting journal entry must balance debit and credit")
        return self


class AdjustingEntriesPackage(_PackageBase):
    kind: Literal["record_adjusting_entries"] = "record_adjusting_entries"
    adjustment_batch_ref: OpaqueRef
    trial_balance_transition_digest: Sha256Digest
    reconciliation_transition_digest: Sha256Digest
    no_adjustments_required: bool
    entries: tuple[AdjustingJournalEntry, ...] = Field(
        default_factory=tuple, max_length=500
    )
    batch_total_debit: Money
    batch_total_credit: Money
    posting_status: Literal["reported_posted", "reported_not_required"]
    reported_posted_at: str
    prepared_by_ref: OpaqueRef
    posted_by_ref: OpaqueRef
    reviewed_by_ref: OpaqueRef

    @field_validator("no_adjustments_required", mode="before")
    @classmethod
    def _strict_bool(cls, value: Any) -> Any:
        return _boolean_literal(value)

    @field_validator("reported_posted_at")
    @classmethod
    def _reported_posted_at(cls, value: str) -> str:
        return _timestamp(value, field_name="reported_posted_at")

    @field_validator("entries", mode="before")
    @classmethod
    def _entries_tuple(cls, value: Any) -> Any:
        values = _as_tuple(value)
        if isinstance(values, tuple) and all(
            isinstance(item, Mapping) for item in values
        ):
            values = tuple(
                sorted(values, key=lambda item: str(item["journal_entry_ref"]))
            )
        return values

    @model_validator(mode="after")
    def _batch_is_exact(self) -> "AdjustingEntriesPackage":
        refs = [item.journal_entry_ref for item in self.entries]
        _unique(refs, label="adjusting journal-entry references")
        if tuple(refs) != tuple(sorted(refs)):
            raise ValueError("adjusting entries must use canonical order")
        if self.no_adjustments_required:
            if self.entries or self.posting_status != "reported_not_required":
                raise ValueError(
                    "no-adjustment batch cannot contain or report posted entries"
                )
        elif not self.entries or self.posting_status != "reported_posted":
            raise ValueError("adjustment batch requires reported posted entries")
        debit = sum((item.total_debit for item in self.entries), Decimal(0))
        credit = sum((item.total_credit for item in self.entries), Decimal(0))
        if self.batch_total_debit != debit or self.batch_total_credit != credit:
            raise ValueError("adjustment batch totals must equal exact entry totals")
        if debit != credit:
            raise ValueError("adjustment batch must balance debit and credit")
        _distinct(
            self.prepared_by_ref,
            self.posted_by_ref,
            self.reviewed_by_ref,
            label="adjustment preparation, reported posting, and review",
        )
        return self


class SubledgerLockPackage(_PackageBase):
    kind: Literal["lock_subledgers"] = "lock_subledgers"
    lock_set_ref: OpaqueRef
    reconciliation_transition_digest: Sha256Digest
    adjustment_transition_digest: Sha256Digest
    locked_subledger_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=100)
    lock_status: Literal["reported_locked"] = "reported_locked"
    locked_at: str
    lock_owner_ref: OpaqueRef
    lock_reviewer_ref: OpaqueRef

    @field_validator("locked_subledger_refs", mode="before")
    @classmethod
    def _locked_refs(cls, value: Any) -> Any:
        return _sorted_unique_tuple(value, label="locked subledger references")

    @field_validator("locked_at")
    @classmethod
    def _locked_at(cls, value: str) -> str:
        return _timestamp(value, field_name="locked_at")

    @model_validator(mode="after")
    def _lock_is_reviewed(self) -> "SubledgerLockPackage":
        _distinct(
            self.lock_owner_ref,
            self.lock_reviewer_ref,
            label="subledger locking and review",
        )
        return self


class EliminationEntry(_StrictModel):
    elimination_ref: OpaqueRef
    from_entity_ref: OpaqueRef
    to_entity_ref: OpaqueRef
    currency: CurrencyCode
    lines: tuple[JournalEntryLine, ...] = Field(min_length=2, max_length=1_000)
    total_debit: Money
    total_credit: Money

    @field_validator("lines", mode="before")
    @classmethod
    def _lines_tuple(cls, value: Any) -> Any:
        values = _as_tuple(value)
        if isinstance(values, tuple) and all(
            isinstance(item, Mapping) for item in values
        ):
            values = tuple(sorted(values, key=lambda item: str(item["line_ref"])))
        return values

    @model_validator(mode="after")
    def _elimination_is_balanced(self) -> "EliminationEntry":
        if self.from_entity_ref == self.to_entity_ref:
            raise ValueError("intercompany elimination requires two distinct entities")
        refs = [line.line_ref for line in self.lines]
        _unique(refs, label="elimination line references")
        if tuple(refs) != tuple(sorted(refs)):
            raise ValueError("elimination lines must use canonical order")
        debit = sum((line.debit for line in self.lines), Decimal(0))
        credit = sum((line.credit for line in self.lines), Decimal(0))
        if self.total_debit != debit or self.total_credit != credit:
            raise ValueError("elimination totals must equal exact line totals")
        if debit != credit:
            raise ValueError("intercompany elimination must balance debit and credit")
        return self


class ConsolidationPackage(_PackageBase):
    kind: Literal["consolidate"] = "consolidate"
    consolidation_workpaper_ref: OpaqueRef
    adjustment_transition_digest: Sha256Digest
    lock_transition_digest: Sha256Digest
    entity_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=100)
    currency: CurrencyCode
    no_intercompany_activity: bool
    elimination_entries: tuple[EliminationEntry, ...] = Field(
        default_factory=tuple,
        max_length=1_000,
    )
    intercompany_input_balance: Money
    eliminated_amount: Money
    residual_balance: Money
    residual_materiality_threshold: Money
    consolidated_at: str
    consolidator_ref: OpaqueRef
    reviewed_by_ref: OpaqueRef

    @field_validator("no_intercompany_activity", mode="before")
    @classmethod
    def _strict_bool(cls, value: Any) -> Any:
        return _boolean_literal(value)

    @field_validator("entity_refs", mode="before")
    @classmethod
    def _entity_refs(cls, value: Any) -> Any:
        return _sorted_unique_tuple(value, label="consolidated entity references")

    @field_validator("elimination_entries", mode="before")
    @classmethod
    def _entries_tuple(cls, value: Any) -> Any:
        values = _as_tuple(value)
        if isinstance(values, tuple) and all(
            isinstance(item, Mapping) for item in values
        ):
            values = tuple(
                sorted(values, key=lambda item: str(item["elimination_ref"]))
            )
        return values

    @field_validator("consolidated_at")
    @classmethod
    def _consolidated_at(cls, value: str) -> str:
        return _timestamp(value, field_name="consolidated_at")

    @model_validator(mode="after")
    def _consolidation_is_exact(self) -> "ConsolidationPackage":
        for label, value in (
            ("intercompany input balance", self.intercompany_input_balance),
            ("eliminated amount", self.eliminated_amount),
            ("residual balance", self.residual_balance),
            ("residual materiality threshold", self.residual_materiality_threshold),
        ):
            _nonnegative(value, label=label)
        refs = [entry.elimination_ref for entry in self.elimination_entries]
        _unique(refs, label="elimination references")
        if tuple(refs) != tuple(sorted(refs)):
            raise ValueError("elimination entries must use canonical order")
        if (
            self.intercompany_input_balance - self.eliminated_amount
            != self.residual_balance
        ):
            raise ValueError("intercompany elimination arithmetic is inconsistent")
        if self.residual_balance > self.residual_materiality_threshold:
            raise ValueError("intercompany residual exceeds materiality")
        if self.no_intercompany_activity:
            if self.elimination_entries or any(
                value != 0
                for value in (
                    self.intercompany_input_balance,
                    self.eliminated_amount,
                    self.residual_balance,
                )
            ):
                raise ValueError("no-activity consolidation must contain zero activity")
        else:
            if not self.elimination_entries or self.intercompany_input_balance <= 0:
                raise ValueError("intercompany activity requires elimination entries")
            eliminated = sum(
                (entry.total_debit for entry in self.elimination_entries),
                Decimal(0),
            )
            if self.eliminated_amount != eliminated:
                raise ValueError(
                    "eliminated amount must equal exact elimination entries"
                )
        _distinct(
            self.consolidator_ref,
            self.reviewed_by_ref,
            label="consolidation preparation and review",
        )
        return self


class CloseApprovalPackage(_PackageBase):
    kind: Literal["approve_close"] = "approve_close"
    approval_candidate_ref: OpaqueRef
    approval_decision_ref: OpaqueRef
    approval_policy_ref: OpaqueRef
    reviewer_qualification_ref: OpaqueRef
    approval_request_digest: Sha256Digest
    approval_observation_digest: Sha256Digest
    review_workpaper_ref: OpaqueRef
    review_workpaper_digest: Sha256Digest
    trial_balance_transition_digest: Sha256Digest
    reconciliation_transition_digest: Sha256Digest
    adjustment_transition_digest: Sha256Digest
    lock_transition_digest: Sha256Digest
    consolidation_transition_digest: Sha256Digest
    decision: Literal["host_reported_approved"] = "host_reported_approved"
    unresolved_material_exception_count: StrictZero = 0
    approved_at: str
    approval_expires_at: str
    review_prepared_by_ref: OpaqueRef
    independent_approver_ref: OpaqueRef

    @field_validator("approved_at", "approval_expires_at")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=info.field_name)

    @model_validator(mode="after")
    def _approval_is_independent(self) -> "CloseApprovalPackage":
        _distinct(
            self.review_prepared_by_ref,
            self.independent_approver_ref,
            label="close review and independent approval",
        )
        if _parsed_timestamp(self.approval_expires_at) <= _parsed_timestamp(
            self.approved_at
        ):
            raise ValueError("close approval expiry must follow its decision")
        return self


class ClosePeriodPackage(_PackageBase):
    kind: Literal["close_period"] = "close_period"
    close_candidate_ref: OpaqueRef
    close_request_ref: OpaqueRef
    close_request_digest: Sha256Digest
    readiness_attestation_ref: OpaqueRef
    readiness_policy_ref: OpaqueRef
    readiness_evaluation_ref: OpaqueRef
    readiness_evaluation_digest: Sha256Digest
    readiness_evidence_digest: Sha256Digest
    readiness_observation_digest: Sha256Digest
    readiness_expires_at: str
    approval_candidate_ref: OpaqueRef
    approval_transition_digest: Sha256Digest
    closed_through_at: str
    close_requested_at: str
    close_operator_ref: OpaqueRef
    hosted_execution_route: Literal["spring_control_plane_required"] = (
        "spring_control_plane_required"
    )

    @field_validator(
        "closed_through_at",
        "close_requested_at",
        "readiness_expires_at",
    )
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=info.field_name)

    @model_validator(mode="after")
    def _readiness_window_is_positive(self) -> "ClosePeriodPackage":
        if _parsed_timestamp(self.readiness_expires_at) <= _parsed_timestamp(
            self.close_requested_at
        ):
            raise ValueError("close readiness must remain valid after its request")
        return self


PeriodClosePackage: TypeAlias = Annotated[
    OpenPeriodPackage
    | TrialBalancePackage
    | ReconciliationPackage
    | AdjustingEntriesPackage
    | SubledgerLockPackage
    | ConsolidationPackage
    | CloseApprovalPackage
    | ClosePeriodPackage,
    Field(discriminator="kind"),
]


def _evidence_lineage_digest(
    envelope: CloseEvidenceEnvelope | Mapping[str, Any],
) -> str:
    payload = (
        envelope.to_dict()
        if isinstance(envelope, CloseEvidenceEnvelope)
        else dict(envelope)
    )
    payload.pop("lineage_digest", None)
    return _stable_digest(payload)


class PeriodCloseTransitionCommand(_StrictModel):
    schema_id: Literal["lightbulb.finance_period_close_command.v1"] = Field(
        default=PERIOD_CLOSE_COMMAND_SCHEMA,
        alias="schema",
    )
    kind: TransitionKind
    scope: PeriodCloseScope
    transition_ref: OpaqueRef
    idempotency_key: OpaqueRef
    expected_version: int = Field(ge=0, le=MAX_PERIOD_CLOSE_TRANSITIONS)
    expected_state_digest: Sha256Digest
    expected_evidence_lineage_digest: Sha256Digest
    occurred_at: str
    host_outcome_report: Literal[
        "reported_certain",
        "reported_in_doubt",
        "unreported",
    ] = "reported_certain"
    requested_by_ref: OpaqueRef
    evidence_custody_ref: OpaqueRef
    evidence: tuple[CloseEvidenceEnvelope, ...] = Field(min_length=2, max_length=20)
    package: PeriodClosePackage
    request_digest: Sha256Digest = GENESIS_PERIOD_CLOSE_DIGEST

    @field_validator("occurred_at")
    @classmethod
    def _occurred_at(cls, value: str) -> str:
        return _timestamp(value, field_name="occurred_at")

    @field_validator("evidence", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _command_is_sealed(
        self, info: ValidationInfo
    ) -> "PeriodCloseTransitionCommand":
        if self.kind != self.package.kind:
            raise ValueError("command kind must exactly match its tagged close package")
        if self.package.evidence_use_refs != tuple(
            sorted(item.use_ref for item in self.evidence)
        ):
            raise ValueError(
                "close package must retain every exact evidence use reference"
            )
        _validate_package_at_command_time(self)
        skip_digests = bool((info.context or {}).get("skip_period_close_digests"))
        _validate_command_evidence(self, skip_digests=skip_digests)
        if not skip_digests and self.request_digest != period_close_command_digest(
            self
        ):
            raise ValueError("request_digest must commit the exact normalized command")
        return self


def _package_actor_refs(package: PeriodClosePackage) -> tuple[str, ...]:
    if isinstance(package, OpenPeriodPackage):
        return (package.opened_by_ref, package.reviewed_by_ref)
    if isinstance(package, TrialBalancePackage):
        return (package.prepared_by_ref, package.reviewed_by_ref)
    if isinstance(package, ReconciliationPackage):
        return tuple(
            actor
            for item in (
                *package.account_reconciliations,
                *package.subledger_reconciliations,
            )
            for actor in (item.prepared_by_ref, item.reviewed_by_ref)
        )
    if isinstance(package, AdjustingEntriesPackage):
        return (
            package.prepared_by_ref,
            package.posted_by_ref,
            package.reviewed_by_ref,
        )
    if isinstance(package, SubledgerLockPackage):
        return (package.lock_owner_ref, package.lock_reviewer_ref)
    if isinstance(package, ConsolidationPackage):
        return (package.consolidator_ref, package.reviewed_by_ref)
    if isinstance(package, CloseApprovalPackage):
        return (package.review_prepared_by_ref, package.independent_approver_ref)
    return (package.close_operator_ref,)


def _package_control_actor_refs(package: PeriodClosePackage) -> tuple[str, ...]:
    """Return actors whose review/execution role must be separate from requester."""

    if isinstance(package, OpenPeriodPackage):
        return (package.reviewed_by_ref,)
    if isinstance(package, TrialBalancePackage):
        return (package.reviewed_by_ref,)
    if isinstance(package, ReconciliationPackage):
        return tuple(
            item.reviewed_by_ref
            for item in (
                *package.account_reconciliations,
                *package.subledger_reconciliations,
            )
        )
    if isinstance(package, AdjustingEntriesPackage):
        return (package.posted_by_ref, package.reviewed_by_ref)
    if isinstance(package, SubledgerLockPackage):
        return (package.lock_reviewer_ref,)
    if isinstance(package, ConsolidationPackage):
        return (package.reviewed_by_ref,)
    if isinstance(package, CloseApprovalPackage):
        return (package.independent_approver_ref,)
    return ()


def _package_reported_fact_at(package: PeriodClosePackage) -> str:
    if isinstance(package, OpenPeriodPackage):
        return package.opened_at
    if isinstance(package, TrialBalancePackage):
        return package.as_of
    if isinstance(package, ReconciliationPackage):
        return package.review_completed_at
    if isinstance(package, AdjustingEntriesPackage):
        return package.reported_posted_at
    if isinstance(package, SubledgerLockPackage):
        return package.locked_at
    if isinstance(package, ConsolidationPackage):
        return package.consolidated_at
    if isinstance(package, CloseApprovalPackage):
        return package.approved_at
    return package.close_requested_at


def _validate_package_at_command_time(command: PeriodCloseTransitionCommand) -> None:
    package = command.package
    scope = command.scope
    occurred = _parsed_timestamp(command.occurred_at)
    if command.evidence_custody_ref != scope.evidence_custody_ref:
        raise ValueError("command evidence custody must exactly match lifecycle scope")
    if command.requested_by_ref in _package_control_actor_refs(package):
        raise ValueError(
            "requester must be separate from package review, posting, or approval"
        )
    if isinstance(package, OpenPeriodPackage):
        if package.opened_at != scope.period_started_at:
            raise ValueError("period opening must bind the exact fiscal-period start")
        if _parsed_timestamp(package.opened_at) > occurred:
            raise ValueError(
                "reported period opening cannot occur after the transition"
            )
    elif isinstance(package, TrialBalancePackage):
        if package.currency != scope.functional_currency:
            raise ValueError(
                "trial balance currency must exactly match lifecycle scope"
            )
        if package.as_of != scope.period_ended_at:
            raise ValueError("trial balance must be captured at the exact period end")
        if _parsed_timestamp(package.as_of) > occurred:
            raise ValueError(
                "future trial balance cannot be captured by this transition"
            )
    elif isinstance(package, ReconciliationPackage):
        if _parsed_timestamp(package.review_completed_at) > occurred:
            raise ValueError("reconciliation review cannot occur after the transition")
        for record in (
            *package.account_reconciliations,
            *package.subledger_reconciliations,
        ):
            if record.materiality_threshold > scope.materiality_threshold:
                raise ValueError("reconciliation threshold exceeds scoped materiality")
        if package.aggregate_unexplained_variance > scope.materiality_threshold:
            raise ValueError(
                "aggregate unexplained variance exceeds scoped materiality"
            )
    elif isinstance(package, AdjustingEntriesPackage):
        if _parsed_timestamp(package.reported_posted_at) > occurred:
            raise ValueError(
                "adjustment posting report cannot occur after transition time"
            )
        if any(
            entry.currency != scope.functional_currency for entry in package.entries
        ):
            raise ValueError(
                "adjusting-entry currency must exactly match lifecycle scope"
            )
        if any(
            _parsed_timestamp(entry.effective_at)
            < _parsed_timestamp(scope.period_started_at)
            or _parsed_timestamp(entry.effective_at)
            > _parsed_timestamp(scope.period_ended_at)
            for entry in package.entries
        ):
            raise ValueError(
                "adjusting entries must be effective inside the fiscal period"
            )
    elif isinstance(package, SubledgerLockPackage):
        if _parsed_timestamp(package.locked_at) > occurred:
            raise ValueError("subledger lock cannot occur after transition time")
    elif isinstance(package, ConsolidationPackage):
        if package.currency != scope.functional_currency:
            raise ValueError(
                "consolidation currency must exactly match lifecycle scope"
            )
        if package.entity_refs != scope.entity_refs:
            raise ValueError(
                "consolidation entities must exactly match lifecycle scope"
            )
        if package.residual_materiality_threshold > scope.materiality_threshold:
            raise ValueError("consolidation threshold exceeds scoped materiality")
        if _parsed_timestamp(package.consolidated_at) > occurred:
            raise ValueError("consolidation cannot occur after transition time")
        scoped_entities = set(scope.entity_refs)
        if any(
            entry.from_entity_ref not in scoped_entities
            or entry.to_entity_ref not in scoped_entities
            or entry.currency != scope.functional_currency
            for entry in package.elimination_entries
        ):
            raise ValueError(
                "elimination entries must retain exact entity and currency scope"
            )
        if scope.scope_kind == "entity" and not package.no_intercompany_activity:
            raise ValueError("single-entity close cannot report intercompany activity")
    elif isinstance(package, CloseApprovalPackage):
        if _parsed_timestamp(package.approved_at) > occurred:
            raise ValueError("approval evidence cannot postdate the transition")
        if occurred >= _parsed_timestamp(package.approval_expires_at):
            raise ValueError("close approval is expired at transition time")
    else:
        if package.closed_through_at != scope.period_ended_at:
            raise ValueError("close proposal must use the exact fiscal-period end")
        if _parsed_timestamp(package.close_requested_at) > occurred:
            raise ValueError("close request cannot occur after transition time")
        if occurred >= _parsed_timestamp(package.readiness_expires_at):
            raise ValueError("close readiness is expired at transition time")


def _validate_command_evidence(
    command: PeriodCloseTransitionCommand,
    *,
    skip_digests: bool,
) -> None:
    evidence = command.evidence
    _unique([item.use_ref for item in evidence], label="evidence use references")
    _unique(
        [item.artifact_ref for item in evidence], label="evidence artifact references"
    )
    _unique(
        [item.artifact_digest for item in evidence], label="evidence artifact digests"
    )
    _unique(
        [item.reference.evidence_ref for item in evidence],
        label="portable evidence references",
    )
    if [item.sequence for item in evidence] != list(range(1, len(evidence) + 1)):
        raise ValueError("evidence sequence must be contiguous and ordered")
    artifact_kind, governance_kind = _EVIDENCE_CONTRACT[command.kind]
    kinds = [item.reference.kind for item in evidence]
    if tuple(kinds) != (artifact_kind, governance_kind):
        raise ValueError("transition requires exact artifact then governance order")

    occurred = _parsed_timestamp(command.occurred_at)
    reported_fact = _parsed_timestamp(_package_reported_fact_at(command.package))
    minimum_transition_retention = _calendar_years_after(
        occurred,
        MINIMUM_EVIDENCE_RETENTION_YEARS,
    )
    predecessor = command.expected_evidence_lineage_digest
    content_digest = (
        None if skip_digests else period_close_command_content_digest(command)
    )
    for envelope in evidence:
        reference = envelope.reference
        observed = _parsed_timestamp(reference.observed_at)
        if envelope.custody_ref != command.scope.evidence_custody_ref:
            raise ValueError("evidence custody must exactly match lifecycle scope")
        if reference.issuer_ref not in command.scope.authorized_evidence_issuer_refs:
            raise ValueError("evidence issuer is not authorized by lifecycle scope")
        if _parsed_timestamp(envelope.retained_until) < _parsed_timestamp(
            command.scope.evidence_retention_until
        ):
            raise ValueError(
                "evidence retention is shorter than the scoped requirement"
            )
        if _parsed_timestamp(envelope.retained_until) < minimum_transition_retention:
            raise ValueError(
                "evidence retention must extend seven years from the transition"
            )
        if reference.subject_ref != command.transition_ref:
            raise ValueError("evidence must bind the exact transition reference")
        if reference.retention_policy != command.scope.financial_retention_policy_ref:
            raise ValueError("evidence retention policy must exactly match close scope")
        if reference.jurisdiction != command.scope.jurisdiction_ref:
            raise ValueError("evidence jurisdiction must exactly match close scope")
        if observed > occurred:
            raise ValueError("evidence cannot be observed after the transition")
        if occurred - observed > MAX_EVIDENCE_AGE:
            raise ValueError("period-close evidence exceeds the freshness bound")
        if observed < reported_fact:
            raise ValueError(
                "evidence cannot be observed before the reported stage fact"
            )
        if reference.effective_at is None:
            raise ValueError("period-close evidence requires an effective timestamp")
        effective = _parsed_timestamp(reference.effective_at)
        if effective > occurred:
            raise ValueError("evidence cannot become effective after the transition")
        if effective > observed:
            raise ValueError(
                "evidence effective timestamp cannot follow its observation"
            )
        if reference.classification == PrimitiveEvidenceClassification.PUBLIC:
            raise ValueError("period-close evidence cannot be public")
        minimum_grade = (
            PrimitiveEvidenceVerificationGrade.VERIFIED
            if reference.kind == governance_kind
            else PrimitiveEvidenceVerificationGrade.ATTESTED
        )
        if _GRADE_RANK[reference.verification_grade] < _GRADE_RANK[minimum_grade]:
            raise ValueError("evidence verification grade is below the stage minimum")
        if reference.kind == governance_kind and (
            reference.issuer_ref != command.scope.spring_authority_ref
        ):
            raise ValueError("governance evidence must remain in exact Spring custody")
        if not skip_digests:
            if envelope.predecessor_lineage_digest != predecessor:
                raise ValueError("evidence lineage predecessor is discontinuous")
            if envelope.lineage_digest != _evidence_lineage_digest(envelope):
                raise ValueError(
                    "evidence lineage digest does not match exact envelope"
                )
            if reference.sha256 != content_digest:
                raise ValueError("evidence reference must commit exact command content")
        predecessor = envelope.lineage_digest

    artifact_reference = evidence[0].reference
    governance_reference = evidence[1].reference
    if _parsed_timestamp(governance_reference.observed_at) < _parsed_timestamp(
        artifact_reference.observed_at
    ) or _parsed_timestamp(governance_reference.effective_at or "") < _parsed_timestamp(
        artifact_reference.effective_at or ""
    ):
        raise ValueError("governance evidence cannot predate its stage artifact")


def _normalized_command_payload(
    command: PeriodCloseTransitionCommand | Mapping[str, Any],
) -> dict[str, Any]:
    payload = deepcopy(
        command.to_dict()
        if isinstance(command, PeriodCloseTransitionCommand)
        else dict(command)
    )
    payload.setdefault("request_digest", GENESIS_PERIOD_CLOSE_DIGEST)
    parsed = PeriodCloseTransitionCommand.model_validate(
        payload,
        context={"skip_period_close_digests": True},
    )
    return parsed.to_dict()


def period_close_command_content_digest(
    command: PeriodCloseTransitionCommand | Mapping[str, Any],
) -> str:
    """Return the normalized semantic digest without circular seal fields."""

    payload = _normalized_command_payload(command)
    payload.pop("request_digest", None)
    for envelope in payload["evidence"]:
        envelope["predecessor_lineage_digest"] = GENESIS_PERIOD_CLOSE_DIGEST
        envelope["lineage_digest"] = GENESIS_PERIOD_CLOSE_DIGEST
        envelope["reference"]["sha256"] = GENESIS_PERIOD_CLOSE_DIGEST
    return _stable_digest(payload)


def period_close_command_digest(
    command: PeriodCloseTransitionCommand | Mapping[str, Any],
) -> str:
    """Return the full normalized command digest excluding request_digest itself."""

    payload = _normalized_command_payload(command)
    payload.pop("request_digest", None)
    return _stable_digest(payload)


def seal_period_close_command(command: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize and seal one caller-prepared command without granting authority."""

    payload = _normalized_command_payload(command)
    content_digest = period_close_command_content_digest(payload)
    predecessor = payload["expected_evidence_lineage_digest"]
    for envelope in payload["evidence"]:
        envelope["predecessor_lineage_digest"] = predecessor
        envelope["reference"]["sha256"] = content_digest
        envelope["lineage_digest"] = _evidence_lineage_digest(envelope)
        predecessor = envelope["lineage_digest"]
    payload["request_digest"] = period_close_command_digest(payload)
    return PeriodCloseTransitionCommand.model_validate(payload).to_dict()


def _evidence_digest(evidence: Sequence[CloseEvidenceEnvelope]) -> str:
    return _stable_digest([item.to_dict() for item in evidence])


def _transition_payload(
    *,
    to_version: int,
    prior_state_digest: str,
    scope_digest: str,
    command_content_digest: str,
    evidence_digest: str,
    command: PeriodCloseTransitionCommand,
) -> dict[str, Any]:
    return {
        "to_version": to_version,
        "prior_state_digest": prior_state_digest,
        "scope_digest": scope_digest,
        "command_content_digest": command_content_digest,
        "evidence_digest": evidence_digest,
        "request_digest": command.request_digest,
        "transition_ref": command.transition_ref,
        "idempotency_key": command.idempotency_key,
        "kind": command.kind,
    }


class PeriodCloseTransitionCandidate(_StrictModel):
    schema_id: Literal["lightbulb.finance_period_close_transition_candidate.v1"] = (
        Field(
            default="lightbulb.finance_period_close_transition_candidate.v1",
            alias="schema",
        )
    )
    to_version: int = Field(ge=1, le=MAX_PERIOD_CLOSE_TRANSITIONS)
    prior_state_digest: Sha256Digest
    scope_digest: Sha256Digest
    command_content_digest: Sha256Digest
    evidence_digest: Sha256Digest
    transition_digest: Sha256Digest
    command: PeriodCloseTransitionCommand

    @model_validator(mode="after")
    def _candidate_is_self_proving(self) -> "PeriodCloseTransitionCandidate":
        if self.command.expected_version != self.to_version - 1:
            raise ValueError("candidate version must match command revision fence")
        if self.command.expected_state_digest != self.prior_state_digest:
            raise ValueError("candidate prior digest must match command state fence")
        if self.scope_digest != period_close_scope_digest(self.command.scope):
            raise ValueError(
                "candidate scope digest does not match exact command scope"
            )
        if self.command_content_digest != period_close_command_content_digest(
            self.command
        ):
            raise ValueError("candidate command-content digest is invalid")
        if self.evidence_digest != _evidence_digest(self.command.evidence):
            raise ValueError("candidate evidence digest is invalid")
        expected = _stable_digest(
            _transition_payload(
                to_version=self.to_version,
                prior_state_digest=self.prior_state_digest,
                scope_digest=self.scope_digest,
                command_content_digest=self.command_content_digest,
                evidence_digest=self.evidence_digest,
                command=self.command,
            )
        )
        if self.transition_digest != expected:
            raise ValueError("transition digest must commit the exact close candidate")
        return self


def _candidate_for(
    command: PeriodCloseTransitionCommand,
    *,
    to_version: int,
    prior_state_digest: str,
) -> PeriodCloseTransitionCandidate:
    scope_digest = period_close_scope_digest(command.scope)
    content_digest = period_close_command_content_digest(command)
    evidence_digest = _evidence_digest(command.evidence)
    payload = _transition_payload(
        to_version=to_version,
        prior_state_digest=prior_state_digest,
        scope_digest=scope_digest,
        command_content_digest=content_digest,
        evidence_digest=evidence_digest,
        command=command,
    )
    return PeriodCloseTransitionCandidate(
        to_version=to_version,
        prior_state_digest=prior_state_digest,
        scope_digest=scope_digest,
        command_content_digest=content_digest,
        evidence_digest=evidence_digest,
        transition_digest=_stable_digest(payload),
        command=command,
    )


_FIELD_BY_KIND: dict[TransitionKind, str] = {
    "open_period": "period_open",
    "capture_trial_balance": "trial_balance",
    "reconcile_accounts": "reconciliations",
    "record_adjusting_entries": "adjusting_entries",
    "lock_subledgers": "subledger_locks",
    "consolidate": "consolidation",
    "approve_close": "close_approval",
    "close_period": "close_candidate",
}


def _derived_packages(
    history: Sequence[PeriodCloseTransitionCandidate],
) -> dict[str, PeriodClosePackage]:
    return {_FIELD_BY_KIND[item.command.kind]: item.command.package for item in history}


def _snapshot_payload(
    scope: PeriodCloseScope,
    history: Sequence[PeriodCloseTransitionCandidate],
) -> dict[str, Any]:
    packages = _derived_packages(history)
    return {
        "schema": PERIOD_CLOSE_SNAPSHOT_SCHEMA,
        "scope": scope.to_dict(),
        "status": _STATUS_ORDER[len(history) - 1],
        "version": len(history),
        "transition_history": [item.to_dict() for item in history],
        "evidence_lineage_digest": history[-1].command.evidence[-1].lineage_digest,
        **{name: package.to_dict() for name, package in packages.items()},
    }


def _snapshot_digest(
    scope: PeriodCloseScope,
    history: Sequence[PeriodCloseTransitionCandidate],
) -> str:
    return _stable_digest(_snapshot_payload(scope, history))


def _prior_state_digest(
    scope: PeriodCloseScope,
    history: Sequence[PeriodCloseTransitionCandidate],
) -> str:
    return (
        GENESIS_PERIOD_CLOSE_DIGEST if not history else _snapshot_digest(scope, history)
    )


def _prior_evidence_lineage(
    history: Sequence[PeriodCloseTransitionCandidate],
) -> str:
    return (
        GENESIS_PERIOD_CLOSE_DIGEST
        if not history
        else history[-1].command.evidence[-1].lineage_digest
    )


def _record_by_kind(
    history: Sequence[PeriodCloseTransitionCandidate],
    kind: TransitionKind,
) -> PeriodCloseTransitionCandidate:
    for item in history:
        if item.command.kind == kind:
            return item
    raise ValueError(f"required prior transition is missing: {kind}")


def _validate_semantic_transition(
    scope: PeriodCloseScope,
    command: PeriodCloseTransitionCommand,
    history: Sequence[PeriodCloseTransitionCandidate],
) -> None:
    expected_kind = _COMMAND_ORDER[len(history)]
    if command.kind != expected_kind:
        raise ValueError(
            f"expected {expected_kind} as the next bounded close transition"
        )
    if command.host_outcome_report != "reported_certain":
        raise ValueError(
            "retained close history requires a certain host outcome report"
        )
    if history:
        prior_occurred = _parsed_timestamp(history[-1].command.occurred_at)
        occurred = _parsed_timestamp(command.occurred_at)
        if occurred <= prior_occurred:
            raise ValueError("period-close transition time must increase monotonically")
        if any(
            _parsed_timestamp(item.reference.observed_at) < prior_occurred
            for item in command.evidence
        ):
            raise ValueError("new evidence cannot predate the retained close state")

    package = command.package
    if isinstance(package, TrialBalancePackage):
        open_record = _record_by_kind(history, "open_period")
        if _parsed_timestamp(package.as_of) < _parsed_timestamp(
            open_record.command.package.opened_at  # type: ignore[union-attr]
        ):
            raise ValueError("trial balance cannot precede the reported period opening")
    elif isinstance(package, ReconciliationPackage):
        trial_record = _record_by_kind(history, "capture_trial_balance")
        trial = trial_record.command.package
        if not isinstance(trial, TrialBalancePackage):
            raise ValueError("retained trial-balance package has invalid type")
        if package.trial_balance_transition_digest != trial_record.transition_digest:
            raise ValueError("reconciliations must bind the exact trial balance")
        actual_accounts = tuple(
            item.account_ref for item in package.account_reconciliations
        )
        expected_accounts = tuple(line.account_ref for line in trial.lines)
        if actual_accounts != expected_accounts:
            raise ValueError("every exact trial-balance account must be reconciled")
        trial_balance_by_account = {
            line.account_ref: line.debit - line.credit for line in trial.lines
        }
        if any(
            item.ledger_balance != trial_balance_by_account[item.account_ref]
            for item in package.account_reconciliations
        ):
            raise ValueError(
                "account reconciliations must bind exact trial-balance balances"
            )
        actual_subledgers = tuple(
            (item.subledger_ref, item.control_account_ref)
            for item in package.subledger_reconciliations
        )
        expected_subledgers = tuple(
            (item.subledger_ref, item.control_account_ref)
            for item in scope.required_subledgers
        )
        if actual_subledgers != expected_subledgers:
            raise ValueError("every exact scoped subledger must be reconciled")
        if any(
            item.control_account_ref not in expected_accounts
            for item in scope.required_subledgers
        ):
            raise ValueError("subledger control account is absent from trial balance")
        if any(
            item.general_ledger_balance
            != trial_balance_by_account[item.control_account_ref]
            for item in package.subledger_reconciliations
        ):
            raise ValueError(
                "subledger reconciliations must bind exact control-account balances"
            )
        if _parsed_timestamp(package.review_completed_at) < _parsed_timestamp(
            trial.as_of
        ):
            raise ValueError("reconciliation review cannot precede the trial balance")
    elif isinstance(package, AdjustingEntriesPackage):
        trial = _record_by_kind(history, "capture_trial_balance")
        reconciliations = _record_by_kind(history, "reconcile_accounts")
        if package.trial_balance_transition_digest != trial.transition_digest:
            raise ValueError("adjustments must bind the exact trial balance")
        if (
            package.reconciliation_transition_digest
            != reconciliations.transition_digest
        ):
            raise ValueError("adjustments must bind the exact reconciliations")
        reconciliation_package = reconciliations.command.package
        if not isinstance(reconciliation_package, ReconciliationPackage):
            raise ValueError("retained reconciliation package has invalid type")
        if _parsed_timestamp(package.reported_posted_at) < _parsed_timestamp(
            reconciliation_package.review_completed_at
        ):
            raise ValueError(
                "adjustment posting evidence cannot precede reconciliation"
            )
        account_refs = {
            line.account_ref
            for line in trial.command.package.lines  # type: ignore[union-attr]
        }
        if any(
            line.account_ref not in account_refs
            for entry in package.entries
            for line in entry.lines
        ):
            raise ValueError(
                "adjusting entry references an account outside trial balance"
            )
    elif isinstance(package, SubledgerLockPackage):
        reconciliation = _record_by_kind(history, "reconcile_accounts")
        adjustments = _record_by_kind(history, "record_adjusting_entries")
        if package.reconciliation_transition_digest != reconciliation.transition_digest:
            raise ValueError("subledger locks must bind exact reconciliations")
        if package.adjustment_transition_digest != adjustments.transition_digest:
            raise ValueError("subledger locks must bind exact adjustments")
        if package.locked_subledger_refs != tuple(
            item.subledger_ref for item in scope.required_subledgers
        ):
            raise ValueError("every exact scoped subledger must be reported locked")
        adjustment_package = adjustments.command.package
        if not isinstance(adjustment_package, AdjustingEntriesPackage):
            raise ValueError("retained adjustment package has invalid type")
        if _parsed_timestamp(package.locked_at) < _parsed_timestamp(
            adjustment_package.reported_posted_at
        ):
            raise ValueError(
                "subledger lock cannot precede adjustment posting evidence"
            )
    elif isinstance(package, ConsolidationPackage):
        adjustments = _record_by_kind(history, "record_adjusting_entries")
        locks = _record_by_kind(history, "lock_subledgers")
        if package.adjustment_transition_digest != adjustments.transition_digest:
            raise ValueError("consolidation must bind exact adjustments")
        if package.lock_transition_digest != locks.transition_digest:
            raise ValueError("consolidation must bind exact subledger locks")
        lock_package = locks.command.package
        if not isinstance(lock_package, SubledgerLockPackage):
            raise ValueError("retained lock package has invalid type")
        if _parsed_timestamp(package.consolidated_at) < _parsed_timestamp(
            lock_package.locked_at
        ):
            raise ValueError("consolidation cannot precede subledger locking")
        trial = _record_by_kind(history, "capture_trial_balance").command.package
        if not isinstance(trial, TrialBalancePackage):
            raise ValueError("retained trial-balance package has invalid type")
        trial_accounts = {line.account_ref for line in trial.lines}
        if any(
            line.account_ref not in trial_accounts
            for entry in package.elimination_entries
            for line in entry.lines
        ):
            raise ValueError(
                "elimination entry references an account outside trial balance"
            )
    elif isinstance(package, CloseApprovalPackage):
        required = {
            "trial_balance_transition_digest": _record_by_kind(
                history, "capture_trial_balance"
            ).transition_digest,
            "reconciliation_transition_digest": _record_by_kind(
                history, "reconcile_accounts"
            ).transition_digest,
            "adjustment_transition_digest": _record_by_kind(
                history, "record_adjusting_entries"
            ).transition_digest,
            "lock_transition_digest": _record_by_kind(
                history, "lock_subledgers"
            ).transition_digest,
            "consolidation_transition_digest": _record_by_kind(
                history, "consolidate"
            ).transition_digest,
        }
        if any(getattr(package, field) != digest for field, digest in required.items()):
            raise ValueError(
                "close approval must bind every exact prerequisite transition"
            )
        consolidation = _record_by_kind(history, "consolidate").command.package
        if not isinstance(consolidation, ConsolidationPackage):
            raise ValueError("retained consolidation package has invalid type")
        if _parsed_timestamp(package.approved_at) < _parsed_timestamp(
            consolidation.consolidated_at
        ):
            raise ValueError("close approval cannot precede consolidation")
        prior_actors: set[str] = set()
        for record in history:
            prior_actors.update(_package_actor_refs(record.command.package))
            prior_actors.add(record.command.requested_by_ref)
        if package.independent_approver_ref in prior_actors:
            raise ValueError(
                "independent close approver cannot be a retained lifecycle actor"
            )
    elif isinstance(package, ClosePeriodPackage):
        approval_record = _record_by_kind(history, "approve_close")
        approval = approval_record.command.package
        if not isinstance(approval, CloseApprovalPackage):
            raise ValueError("retained approval package has invalid type")
        if package.approval_candidate_ref != approval.approval_candidate_ref:
            raise ValueError("close proposal must bind the exact approval candidate")
        if package.approval_transition_digest != approval_record.transition_digest:
            raise ValueError(
                "close proposal must bind exact approval transition evidence"
            )
        if _parsed_timestamp(package.close_requested_at) < _parsed_timestamp(
            approval.approved_at
        ):
            raise ValueError(
                "close request cannot precede independent approval evidence"
            )
        if package.close_operator_ref == approval.independent_approver_ref:
            raise ValueError("independent approver cannot operate the hosted close")
        if command.requested_by_ref == approval.independent_approver_ref:
            raise ValueError("independent approver cannot request the hosted close")


def _validate_history_uniqueness(
    history: Sequence[PeriodCloseTransitionCandidate],
) -> None:
    commands = [item.command for item in history]
    _unique([item.transition_ref for item in commands], label="transition references")
    _unique([item.idempotency_key for item in commands], label="idempotency keys")
    _unique([item.request_digest for item in commands], label="request digests")
    evidence = [item for command in commands for item in command.evidence]
    _unique([item.use_ref for item in evidence], label="global evidence use references")
    _unique([item.artifact_ref for item in evidence], label="global evidence artifacts")
    _unique(
        [item.reference.evidence_ref for item in evidence],
        label="global portable evidence references",
    )
    _unique(
        [item.artifact_digest for item in evidence],
        label="global evidence artifact digests",
    )


class PeriodCloseLifecycleSnapshot(_StrictModel):
    schema_id: Literal["lightbulb.finance_period_close_snapshot.v1"] = Field(
        default=PERIOD_CLOSE_SNAPSHOT_SCHEMA,
        alias="schema",
    )
    scope: PeriodCloseScope
    status: LifecycleStatus
    version: int = Field(ge=1, le=MAX_PERIOD_CLOSE_TRANSITIONS)
    transition_history: tuple[PeriodCloseTransitionCandidate, ...] = Field(
        min_length=1,
        max_length=MAX_PERIOD_CLOSE_TRANSITIONS,
    )
    evidence_lineage_digest: Sha256Digest
    period_open: OpenPeriodPackage
    trial_balance: TrialBalancePackage | None = None
    reconciliations: ReconciliationPackage | None = None
    adjusting_entries: AdjustingEntriesPackage | None = None
    subledger_locks: SubledgerLockPackage | None = None
    consolidation: ConsolidationPackage | None = None
    close_approval: CloseApprovalPackage | None = None
    close_candidate: ClosePeriodPackage | None = None
    state_digest: Sha256Digest

    @field_validator("transition_history", mode="before")
    @classmethod
    def _history_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _snapshot_is_append_only_and_exact(self) -> "PeriodCloseLifecycleSnapshot":
        history = self.transition_history
        if self.version != len(history):
            raise ValueError("snapshot version must equal exact transition count")
        if self.status != _STATUS_ORDER[self.version - 1]:
            raise ValueError("snapshot status must match its bounded lifecycle stage")
        if [item.command.kind for item in history] != list(
            _COMMAND_ORDER[: self.version]
        ):
            raise ValueError("period-close history must be one ordered bounded prefix")
        if [item.to_version for item in history] != list(range(1, self.version + 1)):
            raise ValueError("period-close transition versions must be contiguous")
        _validate_history_uniqueness(history)
        for index, candidate in enumerate(history):
            prior = history[:index]
            if candidate.command.scope != self.scope:
                raise ValueError(
                    "every retained transition must match exact snapshot scope"
                )
            if candidate.prior_state_digest != _prior_state_digest(self.scope, prior):
                raise ValueError("transition prior state digest is discontinuous")
            if (
                candidate.command.expected_evidence_lineage_digest
                != _prior_evidence_lineage(prior)
            ):
                raise ValueError("transition evidence lineage fence is discontinuous")
            _validate_semantic_transition(self.scope, candidate.command, prior)
        packages = _derived_packages(history)
        for kind, field_name in _FIELD_BY_KIND.items():
            expected = packages.get(field_name)
            if getattr(self, field_name) != expected:
                raise ValueError(f"snapshot {field_name} projection is not exact")
        if self.evidence_lineage_digest != _prior_evidence_lineage(history):
            raise ValueError("snapshot evidence lineage digest is not current")
        if self.state_digest != _snapshot_digest(self.scope, history):
            raise ValueError(
                "snapshot state digest does not match exact canonical content"
            )
        return self


def _make_snapshot(
    scope: PeriodCloseScope,
    history: Sequence[PeriodCloseTransitionCandidate],
) -> PeriodCloseLifecycleSnapshot:
    payload = _snapshot_payload(scope, history)
    payload["state_digest"] = _stable_digest(payload)
    return PeriodCloseLifecycleSnapshot.model_validate(payload)


class PeriodCloseLifecycleInput(_StrictModel):
    schema_id: Literal["lightbulb.finance_period_close_input.v1"] = Field(
        default=PERIOD_CLOSE_INPUT_SCHEMA,
        alias="schema",
    )
    scope: PeriodCloseScope
    snapshot: PeriodCloseLifecycleSnapshot | None = None
    command: PeriodCloseTransitionCommand

    @model_validator(mode="after")
    def _input_scope_is_exact(self) -> "PeriodCloseLifecycleInput":
        if self.command.scope != self.scope:
            raise ValueError("command scope must exactly equal lifecycle input scope")
        if self.snapshot is not None and self.snapshot.scope != self.scope:
            raise ValueError("snapshot scope must exactly equal lifecycle input scope")
        return self


class PeriodCloseEffectBoundary(_StrictModel):
    sdk_mode: Literal["preview_only"] = "preview_only"
    connector_calls: StrictZero = 0
    provider_calls: StrictZero = 0
    authoritative_scope_verified: StrictFalse = False
    rbac_authorized: StrictFalse = False
    authoritative_evidence_verified: StrictFalse = False
    hosted_write_executed: StrictFalse = False
    hosted_approval_task_created: StrictFalse = False
    hosted_approval_recorded: StrictFalse = False
    authoritative_audit_persisted: StrictFalse = False
    spring_authority_required: StrictTrue = True


class PeriodCloseRecovery(_StrictModel):
    disposition: Literal["not_required", "manual_reconciliation_required"]
    auto_retry_permitted: StrictFalse = False
    instructions: str | None = Field(default=None, min_length=1, max_length=1_000)

    @model_validator(mode="after")
    def _manual_recovery_has_instructions(self) -> "PeriodCloseRecovery":
        if (self.disposition == "manual_reconciliation_required") != (
            self.instructions is not None
        ):
            raise ValueError("manual recovery requires bounded instructions")
        return self


class PeriodCloseTransitionReceipt(_StrictModel):
    schema_id: Literal["lightbulb.finance_period_close_receipt.v1"] = Field(
        default=PERIOD_CLOSE_RECEIPT_SCHEMA,
        alias="schema",
    )
    transition_ref: OpaqueRef
    idempotency_key: OpaqueRef
    request_digest: Sha256Digest
    command_kind: TransitionKind
    status: Literal["candidate_materialized", "replayed", "rejected", "in_doubt"]
    from_version: int = Field(ge=0, le=MAX_PERIOD_CLOSE_TRANSITIONS)
    to_version: int = Field(ge=0, le=MAX_PERIOD_CLOSE_TRANSITIONS)
    from_state_digest: Sha256Digest
    to_state_digest: Sha256Digest
    evidence_digest: Sha256Digest
    rejection_code: str | None = Field(default=None, min_length=1, max_length=120)
    recovery: PeriodCloseRecovery

    @model_validator(mode="after")
    def _receipt_is_consistent(self) -> "PeriodCloseTransitionReceipt":
        if self.status == "candidate_materialized":
            if self.to_version != self.from_version + 1:
                raise ValueError(
                    "materialized transition must advance exactly one version"
                )
            if self.from_state_digest == self.to_state_digest:
                raise ValueError("materialized transition must change the state digest")
        elif self.status == "replayed":
            if (
                self.to_version < 1
                or self.to_state_digest == GENESIS_PERIOD_CLOSE_DIGEST
            ):
                raise ValueError("replay must reference retained non-genesis state")
            if self.to_version != self.from_version or (
                self.to_state_digest != self.from_state_digest
            ):
                raise ValueError("replay must retain exact current state")
        elif self.to_version != self.from_version or (
            self.to_state_digest != self.from_state_digest
        ):
            raise ValueError("rejected or in-doubt transition cannot change state")
        if (self.status in {"rejected", "in_doubt"}) != (
            self.rejection_code is not None
        ):
            raise ValueError(
                "only rejected or in-doubt receipts require a rejection code"
            )
        if (self.status == "in_doubt") != (
            self.recovery.disposition == "manual_reconciliation_required"
        ):
            raise ValueError("only in-doubt transitions require manual reconciliation")
        return self


class PeriodCloseLifecycleResult(_StrictModel):
    schema_id: Literal["lightbulb.finance_period_close_result.v1"] = Field(
        default=PERIOD_CLOSE_RESULT_SCHEMA,
        alias="schema",
    )
    candidate_validated: bool
    replayed: bool
    snapshot: PeriodCloseLifecycleSnapshot | None = None
    transition_receipt: PeriodCloseTransitionReceipt
    effect_boundary: PeriodCloseEffectBoundary = Field(
        default_factory=PeriodCloseEffectBoundary
    )

    @field_validator("candidate_validated", "replayed", mode="before")
    @classmethod
    def _strict_bool(cls, value: Any) -> Any:
        return _boolean_literal(value)

    @model_validator(mode="after")
    def _result_is_consistent(self) -> "PeriodCloseLifecycleResult":
        expected_validated = self.transition_receipt.status in {
            "candidate_materialized",
            "replayed",
        }
        if self.candidate_validated != expected_validated:
            raise ValueError("result validation flag must match transition receipt")
        if self.replayed != (self.transition_receipt.status == "replayed"):
            raise ValueError("result replay flag must match transition receipt")
        if expected_validated != (self.snapshot is not None):
            raise ValueError("only a validated candidate can return a snapshot")
        if self.snapshot is not None:
            if self.transition_receipt.to_version != self.snapshot.version:
                raise ValueError("receipt version must match returned snapshot")
            if self.transition_receipt.to_state_digest != self.snapshot.state_digest:
                raise ValueError("receipt state digest must match returned snapshot")
            receipt = self.transition_receipt
            if receipt.status == "candidate_materialized":
                retained = self.snapshot.transition_history[-1]
                command = retained.command
                if (
                    receipt.from_version != retained.to_version - 1
                    or receipt.from_state_digest != retained.prior_state_digest
                    or receipt.transition_ref != command.transition_ref
                    or receipt.idempotency_key != command.idempotency_key
                    or receipt.request_digest != command.request_digest
                    or receipt.command_kind != command.kind
                    or receipt.evidence_digest != retained.evidence_digest
                ):
                    raise ValueError(
                        "candidate receipt must exactly identify the retained transition"
                    )
            elif receipt.status == "replayed":
                matches = [
                    retained
                    for retained in self.snapshot.transition_history
                    if (
                        retained.command.transition_ref == receipt.transition_ref
                        and retained.command.idempotency_key == receipt.idempotency_key
                        and retained.command.request_digest == receipt.request_digest
                        and retained.command.kind == receipt.command_kind
                        and retained.evidence_digest == receipt.evidence_digest
                    )
                ]
                if len(matches) != 1:
                    raise ValueError(
                        "replay receipt must identify one exact retained transition"
                    )
        return self


def _unchanged_state(
    scope: PeriodCloseScope,
    snapshot: PeriodCloseLifecycleSnapshot | None,
) -> tuple[int, str]:
    if snapshot is None:
        return 0, GENESIS_PERIOD_CLOSE_DIGEST
    if snapshot.scope != scope:
        raise ValueError("snapshot scope is not exact")
    return snapshot.version, snapshot.state_digest


def _rejected_result(
    parsed: PeriodCloseLifecycleInput,
    *,
    code: str,
    in_doubt: bool = False,
    instructions: str | None = None,
) -> PeriodCloseLifecycleResult:
    version, state_digest = _unchanged_state(parsed.scope, parsed.snapshot)
    return PeriodCloseLifecycleResult(
        candidate_validated=False,
        replayed=False,
        snapshot=None,
        transition_receipt=PeriodCloseTransitionReceipt(
            transition_ref=parsed.command.transition_ref,
            idempotency_key=parsed.command.idempotency_key,
            request_digest=parsed.command.request_digest,
            command_kind=parsed.command.kind,
            status="in_doubt" if in_doubt else "rejected",
            from_version=version,
            to_version=version,
            from_state_digest=state_digest,
            to_state_digest=state_digest,
            evidence_digest=_evidence_digest(parsed.command.evidence),
            rejection_code=code,
            recovery=PeriodCloseRecovery(
                disposition=(
                    "manual_reconciliation_required" if in_doubt else "not_required"
                ),
                instructions=instructions if in_doubt else None,
            ),
        ),
    )


def materialize_period_close_candidate(
    inputs: PeriodCloseLifecycleInput | Mapping[str, Any],
) -> PeriodCloseLifecycleResult:
    """Validate one bounded transition and return a non-authoritative candidate."""

    parsed = PeriodCloseLifecycleInput.model_validate(
        inputs.to_dict() if isinstance(inputs, PeriodCloseLifecycleInput) else inputs
    )
    history = list(parsed.snapshot.transition_history) if parsed.snapshot else []
    current_version, current_digest = _unchanged_state(parsed.scope, parsed.snapshot)

    for existing in history:
        if existing.command.idempotency_key == parsed.command.idempotency_key:
            if (
                existing.command.request_digest == parsed.command.request_digest
                and existing.command.transition_ref == parsed.command.transition_ref
            ):
                return PeriodCloseLifecycleResult(
                    candidate_validated=True,
                    replayed=True,
                    snapshot=parsed.snapshot,
                    transition_receipt=PeriodCloseTransitionReceipt(
                        transition_ref=parsed.command.transition_ref,
                        idempotency_key=parsed.command.idempotency_key,
                        request_digest=parsed.command.request_digest,
                        command_kind=parsed.command.kind,
                        status="replayed",
                        from_version=current_version,
                        to_version=current_version,
                        from_state_digest=current_digest,
                        to_state_digest=current_digest,
                        evidence_digest=existing.evidence_digest,
                        recovery=PeriodCloseRecovery(disposition="not_required"),
                    ),
                )
            return _rejected_result(parsed, code="IDEMPOTENCY_CONFLICT")
        if existing.command.transition_ref == parsed.command.transition_ref:
            return _rejected_result(parsed, code="TRANSITION_REF_CONFLICT")
        if existing.command.request_digest == parsed.command.request_digest:
            return _rejected_result(parsed, code="DUPLICATE_REQUEST")

    if current_version >= MAX_PERIOD_CLOSE_TRANSITIONS:
        return _rejected_result(parsed, code="LIFECYCLE_COMPLETE")
    if parsed.command.expected_version != current_version:
        return _rejected_result(parsed, code="VERSION_CONFLICT")
    if parsed.command.expected_state_digest != current_digest:
        return _rejected_result(parsed, code="STATE_DIGEST_CONFLICT")
    if parsed.command.expected_evidence_lineage_digest != _prior_evidence_lineage(
        history
    ):
        return _rejected_result(parsed, code="EVIDENCE_LINEAGE_CONFLICT")
    if parsed.command.kind != _COMMAND_ORDER[current_version]:
        return _rejected_result(parsed, code="INVALID_TRANSITION_ORDER")
    if parsed.command.host_outcome_report != "reported_certain":
        return _rejected_result(
            parsed,
            code="HOST_OUTCOME_IN_DOUBT",
            in_doubt=True,
            instructions=(
                "Stop automatic continuation. Spring must reconcile the exact ledger, "
                "subledger, approval, and audit records for this request digest before "
                "a newly sealed command may be considered. Do not auto-retry."
            ),
        )
    try:
        _validate_semantic_transition(parsed.scope, parsed.command, history)
        candidate = _candidate_for(
            parsed.command,
            to_version=current_version + 1,
            prior_state_digest=current_digest,
        )
        new_snapshot = _make_snapshot(parsed.scope, (*history, candidate))
    except ValueError:
        return _rejected_result(parsed, code="SEMANTIC_PREREQUISITE_FAILED")
    return PeriodCloseLifecycleResult(
        candidate_validated=True,
        replayed=False,
        snapshot=new_snapshot,
        transition_receipt=PeriodCloseTransitionReceipt(
            transition_ref=parsed.command.transition_ref,
            idempotency_key=parsed.command.idempotency_key,
            request_digest=parsed.command.request_digest,
            command_kind=parsed.command.kind,
            status="candidate_materialized",
            from_version=current_version,
            to_version=new_snapshot.version,
            from_state_digest=current_digest,
            to_state_digest=new_snapshot.state_digest,
            evidence_digest=candidate.evidence_digest,
            recovery=PeriodCloseRecovery(disposition="not_required"),
        ),
    )


PERIOD_CLOSE_TRANSITION_OPERATION = PrimitiveOperationSpec(
    operation_ref="finance-period-close-materialize-transition",
    tool="sdk.finance.materialize_period_close_transition",
    effect=ConnectorEffect.READ,
    approval_required=False,
    replay_class=PrimitiveOperationReplayClass.SAFE,
    freshness_class=PrimitiveOperationFreshnessClass.BOUNDED,
    recovery_policy=PrimitiveOperationRecoveryPolicy.MANUAL_RECONCILIATION,
)


def _scope_matches_context(
    inputs: PeriodCloseLifecycleInput,
    context: PrimitiveExecutionContext,
) -> bool:
    scope = inputs.scope
    return (
        scope.tenant_ref == context.scope.tenant_ref
        and scope.company_ref == context.scope.company_ref
        and scope.project_ref == context.scope.project_ref
        and scope.project_id == context.scope.project_id
        and context.scope.actor_ref == inputs.command.requested_by_ref
        and context.idempotency_key == inputs.command.idempotency_key
    )


def _example_evidence(
    *,
    sequence: int,
    kind: str,
    issuer_ref: str,
    transition_ref: str,
) -> dict[str, Any]:
    suffix = kind.replace("_", "-")
    return {
        "schema": "lightbulb.finance_close_evidence_envelope.v1",
        "sequence": sequence,
        "use_ref": f"use-{suffix}-example",
        "artifact_ref": f"artifact-{suffix}-example",
        "artifact_digest": hashlib.sha256(f"artifact:{kind}".encode()).hexdigest(),
        "predecessor_lineage_digest": GENESIS_PERIOD_CLOSE_DIGEST,
        "lineage_digest": GENESIS_PERIOD_CLOSE_DIGEST,
        "custody_ref": "finance-evidence-custody-example",
        "retained_until": "2034-09-01T00:00:00Z",
        "single_use": True,
        "reference": {
            "schema": "lightbulb.primitive_evidence_ref.v1",
            "evidence_ref": f"evidence-{suffix}-example",
            "kind": kind,
            "issuer_ref": issuer_ref,
            "subject_ref": transition_ref,
            "sha256": GENESIS_PERIOD_CLOSE_DIGEST,
            "observed_at": "2026-09-01T09:00:00Z",
            "effective_at": "2026-09-01T09:00:00Z",
            "verification_grade": (
                "verified" if issuer_ref == "spring-authority-example" else "attested"
            ),
            "classification": "restricted",
            "retention_policy": "finance-retention-example",
            "jurisdiction": "US-NY",
        },
    }


def _period_close_example_inputs() -> dict[str, Any]:
    transition_ref = "period-close-open-example"
    scope: dict[str, Any] = {
        "tenant_ref": "authenticated",
        "company_ref": "selected",
        "project_ref": "workflow-improvement",
        "project_id": "00000000-0000-0000-0000-000000000401",
        "scope_kind": "entity",
        "entity_refs": ["entity-example"],
        "ledger_ref": "ledger-example",
        "functional_currency": "USD",
        "fiscal_period_ref": "period-2026-08",
        "period_started_at": "2026-08-01T00:00:00Z",
        "period_ended_at": "2026-08-31T23:59:59Z",
        "jurisdiction_ref": "US-NY",
        "financial_retention_policy_ref": "finance-retention-example",
        "evidence_retention_until": "2034-09-01T00:00:00Z",
        "materiality_threshold": "10.00",
        "required_subledgers": [
            {
                "subledger_ref": "accounts-receivable-example",
                "control_account_ref": "receivable-example",
            }
        ],
        "evidence_custody_ref": "finance-evidence-custody-example",
        "spring_authority_ref": "spring-authority-example",
        "authorized_evidence_issuer_refs": [
            "ledger-system-example",
            "spring-authority-example",
        ],
    }
    evidence = [
        _example_evidence(
            sequence=1,
            kind="period_calendar",
            issuer_ref="ledger-system-example",
            transition_ref=transition_ref,
        ),
        _example_evidence(
            sequence=2,
            kind="period_open_state_attestation",
            issuer_ref="spring-authority-example",
            transition_ref=transition_ref,
        ),
    ]
    command = seal_period_close_command(
        {
            "kind": "open_period",
            "scope": scope,
            "transition_ref": transition_ref,
            "idempotency_key": "period-close-open-idem-example",
            "expected_version": 0,
            "expected_state_digest": GENESIS_PERIOD_CLOSE_DIGEST,
            "expected_evidence_lineage_digest": GENESIS_PERIOD_CLOSE_DIGEST,
            "occurred_at": "2026-09-01T09:00:00Z",
            "host_outcome_report": "reported_certain",
            "requested_by_ref": "finance-requester-example",
            "evidence_custody_ref": "finance-evidence-custody-example",
            "evidence": evidence,
            "package": {
                "kind": "open_period",
                "evidence_use_refs": sorted(item["use_ref"] for item in evidence),
                "period_open_candidate_ref": "period-open-candidate-example",
                "prior_period_state": "closed",
                "opened_at": "2026-08-01T00:00:00Z",
                "opened_by_ref": "finance-operator-example",
                "reviewed_by_ref": "finance-reviewer-example",
            },
        }
    )
    return {"scope": scope, "command": command}


class ProposePeriodCloseTransitionPrimitive(
    BusinessProcessPrimitive[PeriodCloseLifecycleInput, PeriodCloseLifecycleResult]
):
    primitive_ref = "finance.propose_period_close_transition"
    version = "1.1.0"
    title = "Propose a bounded, evidence-bound finance period-close transition"
    description = (
        "Validate and materialize one exact-scope period-close candidate without "
        "opening or closing a ledger, posting an entry, locking a subledger, "
        "recording approval, persisting audit evidence, or calling a provider."
    )
    input_model = PeriodCloseLifecycleInput
    output_model = PeriodCloseLifecycleResult
    connector_tools = ()
    risk_level = "high"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs: Mapping[str, Any] = _period_close_example_inputs()

    def implementation_contract(self) -> dict[str, Any]:
        contract = super().implementation_contract()
        contract["operation_contract"] = PERIOD_CLOSE_TRANSITION_OPERATION.to_dict()
        contract["effect_boundary"] = PeriodCloseEffectBoundary().to_dict()
        contract["authority_boundary"] = {
            "spring_control_plane": (
                "authenticated scope, RBAC, authoritative ledger/subledger state, "
                "persistence, approvals, audit, recovery, and write admission"
            ),
            "governed_finance_systems": (
                "journal posting, subledger locking, consolidation, and ledger close"
            ),
            "sdk": "deterministic preview-only candidate materialization",
        }
        contract["lifecycle_guarantees"] = {
            "maximum_transitions": MAX_PERIOD_CLOSE_TRANSITIONS,
            "scope": (
                "exact tenant/company/project/entity-or-group/ledger/currency/period"
            ),
            "money": "finite Decimal only; floats, integers, and booleans rejected",
            "history": "canonical append-only state and transition digest chain",
            "evidence": (
                "fresh, causal, retained, single-use global lineage; declared grades "
                "are structurally checked here and authenticated only by Spring"
            ),
            "ambiguous_outcome": "manual Spring reconciliation; never auto-retry",
        }
        return contract

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: PeriodCloseLifecycleInput,
    ) -> PrimitiveExecutionResult[PeriodCloseLifecycleResult]:
        evidence_refs = [item.reference for item in inputs.command.evidence]
        if not _scope_matches_context(inputs, context):
            blocker = PrimitiveBlocker(
                code="SCOPE_MISMATCH",
                message=(
                    "Runtime tenant, company, project UUID/ref, actor, and idempotency "
                    "key must exactly match the period-close request. Spring must "
                    "authorize the remaining finance scope."
                ),
                field="scope",
                retryable=False,
            )
            return PrimitiveExecutionResult[PeriodCloseLifecycleResult](
                status=PrimitiveExecutionStatus.BLOCKED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary="Period-close transition rejected at the runtime scope boundary.",
                blockers=[blocker],
                evidence_refs=evidence_refs,
                operation_receipts=[
                    PrimitiveOperationReceipt(
                        spec=PERIOD_CLOSE_TRANSITION_OPERATION,
                        status=PrimitiveOperationStatus.BLOCKED,
                        request_digest=inputs.command.request_digest,
                        evidence_refs=evidence_refs,
                        error=blocker,
                    )
                ],
            )

        output = materialize_period_close_candidate(inputs)
        receipt = output.transition_receipt
        blocker: PrimitiveBlocker | None = None
        recovery_plan: PrimitiveRecoveryPlan | None = None
        if output.candidate_validated:
            execution_status = PrimitiveExecutionStatus.PREVIEW
            operation_status = PrimitiveOperationStatus.PREVIEW
            disposition = PrimitiveRecoveryDisposition.NOT_REQUIRED
        elif receipt.status == "in_doubt":
            execution_status = PrimitiveExecutionStatus.BLOCKED
            operation_status = PrimitiveOperationStatus.IN_DOUBT
            disposition = PrimitiveRecoveryDisposition.MANUAL_RECONCILIATION_REQUIRED
            recovery_plan = PrimitiveRecoveryPlan(
                policy=PrimitiveOperationRecoveryPolicy.MANUAL_RECONCILIATION,
                disposition=disposition,
                instructions=receipt.recovery.instructions,
            )
            blocker = PrimitiveBlocker(
                code=receipt.rejection_code or "HOST_OUTCOME_IN_DOUBT",
                message=receipt.recovery.instructions
                or "Manual reconciliation required.",
                retryable=False,
            )
        else:
            execution_status = PrimitiveExecutionStatus.BLOCKED
            operation_status = PrimitiveOperationStatus.BLOCKED
            disposition = PrimitiveRecoveryDisposition.NOT_REQUIRED
            blocker = PrimitiveBlocker(
                code=receipt.rejection_code or "PERIOD_CLOSE_TRANSITION_REJECTED",
                message="Period-close candidate was rejected without changing live state.",
                retryable=False,
            )

        operation_receipt = PrimitiveOperationReceipt(
            spec=PERIOD_CLOSE_TRANSITION_OPERATION,
            status=operation_status,
            request_digest=inputs.command.request_digest,
            evidence_refs=evidence_refs,
            external_refs=(
                {
                    "state_digest": output.snapshot.state_digest,
                    "transition_ref": inputs.command.transition_ref,
                }
                if output.snapshot is not None
                else {}
            ),
            replayed=output.replayed,
            recovery_disposition=disposition,
            recovery_plan=recovery_plan,
            error=blocker,
        )
        return PrimitiveExecutionResult[PeriodCloseLifecycleResult](
            status=execution_status,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                "Period-close candidate validated with no authoritative effect."
                if output.candidate_validated
                else "Period-close candidate rejected without changing live state."
            ),
            output=output,
            events=[
                PrimitiveEvent(
                    type="finance.period_close_candidate_evaluated",
                    payload={
                        "transition_ref": inputs.command.transition_ref,
                        "command_kind": inputs.command.kind,
                        "candidate_validated": output.candidate_validated,
                        "replayed": output.replayed,
                        "request_digest": inputs.command.request_digest,
                        "authoritative_scope_verified": False,
                        "rbac_authorized": False,
                        "authoritative_evidence_verified": False,
                        "hosted_write_executed": False,
                        "hosted_approval_task_created": False,
                        "hosted_approval_recorded": False,
                        "connector_effect_executed": False,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="finance_period_close_candidate_receipt",
                    summary=(
                        "Portable SDK candidate receipt; not a ledger close, approval, "
                        "posting, subledger lock, consolidation write, or audit record."
                    ),
                    refs={
                        "transition_ref": inputs.command.transition_ref,
                        "request_digest": inputs.command.request_digest,
                    },
                )
            ],
            evidence_refs=evidence_refs,
            operation_receipts=[operation_receipt],
            recovery_plan=recovery_plan,
            blockers=[blocker] if blocker is not None else [],
        )


FINANCE_CLOSE_LIFECYCLE_EXECUTABLE_PRIMITIVES: tuple[
    BusinessProcessPrimitive[Any, Any], ...
] = (ProposePeriodCloseTransitionPrimitive(),)


__all__ = [
    "FINANCE_CLOSE_LIFECYCLE_EXECUTABLE_PRIMITIVES",
    "GENESIS_PERIOD_CLOSE_DIGEST",
    "MAX_PERIOD_CLOSE_TRANSITIONS",
    "PERIOD_CLOSE_TRANSITION_OPERATION",
    "AccountReconciliationRecord",
    "AdjustingEntriesPackage",
    "AdjustingJournalEntry",
    "CloseApprovalPackage",
    "CloseEvidenceEnvelope",
    "ClosePeriodPackage",
    "ConsolidationPackage",
    "EliminationEntry",
    "JournalEntryLine",
    "OpenPeriodPackage",
    "PeriodCloseEffectBoundary",
    "PeriodCloseLifecycleInput",
    "PeriodCloseLifecycleResult",
    "PeriodCloseLifecycleSnapshot",
    "PeriodCloseRecovery",
    "PeriodCloseScope",
    "PeriodCloseTransitionCandidate",
    "PeriodCloseTransitionCommand",
    "PeriodCloseTransitionReceipt",
    "ProposePeriodCloseTransitionPrimitive",
    "ReconciliationPackage",
    "SubledgerLockPackage",
    "SubledgerReconciliationRecord",
    "SubledgerScopeBinding",
    "TrialBalanceLine",
    "TrialBalancePackage",
    "materialize_period_close_candidate",
    "period_close_command_content_digest",
    "period_close_command_digest",
    "period_close_scope_digest",
    "seal_period_close_command",
]
