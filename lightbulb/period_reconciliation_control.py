"""Typed hosted-control contracts for current Period Reconciliation 0.4.

These models contain only typed period facts and opaque Spring-owned identities. They
deliberately cannot carry QuickBooks report bodies, success flags, evidence digests,
credentials, provider effects, or a ledger-close claim.
"""

from __future__ import annotations

from datetime import date
from decimal import Decimal
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .economic_spine_runs import EconomicSpineRun


def _exact_model_execution_run_id(value: str) -> str:
    if value != value.strip() or any(ord(character) < 32 for character in value):
        raise ValueError("model_execution_run_id must be exact")
    return value


PeriodReconciliationStage = Literal[
    "PERIOD_OPEN_VALIDATED",
    "QUICKBOOKS_READ_SET",
    "RECONCILIATION_EVALUATED",
    "EXCEPTION_DISPOSITION_RETAINED",
    "RECONCILIATION_EVIDENCE_CUSTODY_SEALED",
    "APPROVED_CLOSE_REVIEW_PACKET_RETAINED",
    "APPROVED_CLOSE_CANDIDATE",
]
PeriodReconciliationSourceKind = Literal[
    "PERIOD_SCOPE",
    "PERIOD_OPEN_VALIDATED",
    "QUICKBOOKS_READ_SET",
    "RECONCILIATION_EVALUATED",
    "EXCEPTION_DISPOSITION_RETAINED",
    "RECONCILIATION_EVIDENCE_CUSTODY_SEALED",
    "APPROVED_CLOSE_REVIEW_PACKET_RETAINED",
    "APPROVED_CLOSE_CANDIDATE",
    "FAILED",
    "CANCELLED",
]

PERIOD_RECONCILIATION_REST_ROOT = (
    "/api/projects/{project_id}/finance/period-reconciliation"
)
PERIOD_RECONCILIATION_MCP_TOOLS = (
    "retain_period_reconciliation_scope",
    "start_period_reconciliation_run",
    "restart_period_reconciliation_run",
    "retain_period_reconciliation_quickbooks_reads",
    "evaluate_period_reconciliation_run",
    "retain_period_reconciliation_review",
    "advance_period_reconciliation_stage",
    "get_period_reconciliation_run",
    "get_period_reconciliation_outcomes",
    "get_period_reconciliation_campaign_facts",
    "fail_period_reconciliation_run",
    "cancel_period_reconciliation_run",
)
_OUTCOME_METRICS = frozenset({
    "period_reconciliation_completion_rate",
    "unreconciled_balance_rate",
    "time_to_approved_close_candidate_seconds",
})
_CAMPAIGN_EVIDENCE_KINDS = frozenset({
    "typed_versioned_contracts_evidence",
    "production_shaped_completion_evidence",
    "scope_isolation_and_rbac_evidence",
    "approval_and_effect_control_evidence",
    "restart_replica_and_recovery_evidence",
    "cross_surface_parity_evidence",
    "harness_conformance_evidence",
    "live_provider_conformance_evidence",
    "ambiguous_effect_safety_evidence",
    "measured_customer_outcome_evidence",
})


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid", frozen=True, populate_by_name=True, serialize_by_alias=True
    )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


class PeriodReconciliationScopeRequest(_StrictModel):
    period_ref: str = Field(min_length=1, max_length=160)
    period_start: date
    period_end: date
    ledger_ref: str = Field(min_length=1, max_length=160)
    entity_group_ref: str = Field(min_length=1, max_length=160)
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    accounting_method: Literal["Accrual", "Cash"]
    close_calendar_ref: str = Field(min_length=1, max_length=160)
    materiality_micros: int = Field(ge=0, le=9_223_372_036_854_775_807)
    variance_threshold_micros: int = Field(ge=0, le=9_223_372_036_854_775_807)

    @field_validator(
        "period_ref", "ledger_ref", "entity_group_ref", "close_calendar_ref"
    )
    @classmethod
    def _exact_refs(cls, value: str) -> str:
        if value != value.strip() or any(ord(character) < 32 for character in value):
            raise ValueError("Period references must be exact printable values")
        return value

    @model_validator(mode="after")
    def _bounded_period(self) -> "PeriodReconciliationScopeRequest":
        if self.period_end < self.period_start:
            raise ValueError("period_end cannot precede period_start")
        if (self.period_end - self.period_start).days > 370:
            raise ValueError("Period scope cannot exceed 370 days")
        if self.variance_threshold_micros > self.materiality_micros:
            raise ValueError("Variance threshold cannot exceed materiality")
        return self


class PeriodReconciliationStartRequest(_StrictModel):
    source_record_id: UUID
    command_id: UUID
    model_execution_run_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=512,
        description="Ignored legacy correlation hint; Spring mints runtime authority.",
    )

    @field_validator("model_execution_run_id")
    @classmethod
    def _exact_model_run(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _exact_model_execution_run_id(value)


class PeriodReconciliationRestartRequest(_StrictModel):
    scope_record_id: UUID
    terminal_run_ref: str = Field(pattern=r"^pcr_[0-9a-f]{32}$")
    command_id: UUID
    model_execution_run_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=512,
        description="Ignored legacy correlation hint; Spring mints runtime authority.",
    )

    @field_validator("model_execution_run_id")
    @classmethod
    def _exact_model_run(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _exact_model_execution_run_id(value)


class PeriodReconciliationQuickBooksReadSetRequest(_StrictModel):
    scope_record_id: UUID
    trial_balance_invocation_id: UUID
    balance_sheet_invocation_id: UUID
    cash_flow_invocation_id: UUID
    aged_receivable_invocation_id: UUID
    aged_payable_invocation_id: UUID

    @model_validator(mode="after")
    def _five_distinct_reads(self) -> "PeriodReconciliationQuickBooksReadSetRequest":
        identities = (
            self.trial_balance_invocation_id,
            self.balance_sheet_invocation_id,
            self.cash_flow_invocation_id,
            self.aged_receivable_invocation_id,
            self.aged_payable_invocation_id,
        )
        if len(set(identities)) != 5:
            raise ValueError("The five governed QuickBooks invocation IDs must be distinct")
        return self


class PeriodReconciliationEvaluationRequest(_StrictModel):
    scope_record_id: UUID
    read_set_id: UUID
    journal_settlement_run_ids: tuple[UUID, ...] = Field(min_length=1, max_length=256)

    @field_validator("journal_settlement_run_ids")
    @classmethod
    def _canonical_journal_ids(cls, value: tuple[UUID, ...]) -> tuple[UUID, ...]:
        if len(set(value)) != len(value):
            raise ValueError("Journal settlement run IDs must be unique")
        canonical = tuple(sorted(value))
        if value != canonical:
            raise ValueError("Journal settlement run IDs must use canonical UUID order")
        return value


class PeriodReconciliationReviewRequest(_StrictModel):
    evaluation_id: UUID
    approval_task_id: UUID


class PeriodReconciliationStageRequest(_StrictModel):
    stage: PeriodReconciliationStage
    scope_record_id: UUID
    predecessor_source_id: UUID
    read_set_id: UUID | None = None
    evaluation_id: UUID | None = None
    review_decision_id: UUID | None = None
    command_id: UUID

    @model_validator(mode="after")
    def _exact_stage_bindings(self) -> "PeriodReconciliationStageRequest":
        actual = (
            self.read_set_id is not None,
            self.evaluation_id is not None,
            self.review_decision_id is not None,
        )
        expected = {
            "PERIOD_OPEN_VALIDATED": (False, False, False),
            "QUICKBOOKS_READ_SET": (True, False, False),
            "RECONCILIATION_EVALUATED": (False, True, False),
            "EXCEPTION_DISPOSITION_RETAINED": (False, True, False),
            "RECONCILIATION_EVIDENCE_CUSTODY_SEALED": (False, True, False),
            "APPROVED_CLOSE_REVIEW_PACKET_RETAINED": (False, True, False),
            "APPROVED_CLOSE_CANDIDATE": (False, True, True),
        }[self.stage]
        if actual != expected:
            raise ValueError("Stage artifact IDs differ from the exact Period manifest")
        return self


class PeriodReconciliationTerminalRequest(_StrictModel):
    scope_record_id: UUID
    predecessor_source_id: UUID
    command_id: UUID


class PeriodReconciliationScopeReceipt(_StrictModel):
    schema_id: Literal["lightbulb.period_reconciliation_scope_receipt.v3"] = Field(
        alias="schema"
    )
    scope_record_id: UUID
    scope_ref: str = Field(pattern=r"^prs_[0-9a-f]{32}$")
    start_source_record_id: UUID
    start_source_ref: str = Field(pattern=r"^prc_[0-9a-f]{32}$")
    period_start: date
    period_end: date
    certification_version: Literal["0.4.0"]
    execution_version: Literal["0.2.0"]


class PeriodReconciliationReadSetReceipt(_StrictModel):
    schema_id: Literal["lightbulb.period_reconciliation_read_set_receipt.v3"] = Field(
        alias="schema"
    )
    run_ref: str = Field(pattern=r"^pcr_[0-9a-f]{32}$")
    read_set_id: UUID
    read_set_ref: str = Field(pattern=r"^prr_[0-9a-f]{32}$")
    scope_record_id: UUID
    source_current: Literal[True]
    provider_effect: Literal["READ"]


class PeriodReconciliationRun(EconomicSpineRun):
    """Exact Period projection; structurally valid runs from other loops fail closed."""

    run_ref: str = Field(pattern=r"^pcr_[0-9a-f]{32}$")
    loop_ref: Literal["finance.period_reconciliation_approved_close_candidate"]
    provider_effect_claimed: Literal[False]


class PeriodReconciliationRunReceipt(_StrictModel):
    schema_id: Literal["lightbulb.period_reconciliation_run_receipt.v3"] = Field(
        alias="schema"
    )
    run: PeriodReconciliationRun
    source_record_id: UUID
    source_ref: str | None = Field(default=None, pattern=r"^prc_[0-9a-f]{32}$")
    source_kind: PeriodReconciliationSourceKind | None = None


class PeriodReconciliationOutcomeFact(_StrictModel):
    metric_ref: Literal[
        "period_reconciliation_completion_rate",
        "unreconciled_balance_rate",
        "time_to_approved_close_candidate_seconds",
    ]
    numerator_value: Decimal
    denominator_value: Decimal
    measured_value: Decimal
    source_run_id: UUID
    source_record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_document: dict[str, Any]


class PeriodReconciliationCampaignFact(_StrictModel):
    evidence_kind: Literal[
        "typed_versioned_contracts_evidence",
        "production_shaped_completion_evidence",
        "scope_isolation_and_rbac_evidence",
        "approval_and_effect_control_evidence",
        "restart_replica_and_recovery_evidence",
        "cross_surface_parity_evidence",
        "harness_conformance_evidence",
        "live_provider_conformance_evidence",
        "ambiguous_effect_safety_evidence",
        "measured_customer_outcome_evidence",
    ]
    fact_satisfied: bool
    applicability: Literal[
        "APPLICABLE",
        "APPLICABLE_READ_ONLY",
        "NOT_APPLICABLE_NO_PROVIDER_WRITE",
        "NOT_APPLICABLE_NO_CODING_HARNESS",
    ]
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_document: dict[str, Any]


class PeriodReconciliationEvaluationReceipt(_StrictModel):
    schema_id: Literal["lightbulb.period_reconciliation_evaluation_receipt.v3"] = Field(
        alias="schema"
    )
    run_ref: str = Field(pattern=r"^pcr_[0-9a-f]{32}$")
    evaluation_id: UUID
    evaluation_ref: str = Field(pattern=r"^pre_[0-9a-f]{32}$")
    scope_record_id: UUID
    read_set_id: UUID
    within_threshold: bool
    exception_count: int = Field(ge=0, le=1000)
    cash_variance_micros: int = Field(ge=0)
    ar_variance_micros: int = Field(ge=0)
    ap_variance_micros: int = Field(ge=0)
    ledger_close_claimed: Literal[False]


class PeriodReconciliationReviewReceipt(_StrictModel):
    schema_id: Literal["lightbulb.period_reconciliation_review_receipt.v3"] = Field(
        alias="schema"
    )
    run_ref: str = Field(pattern=r"^pcr_[0-9a-f]{32}$")
    review_decision_id: UUID
    decision_ref: str = Field(pattern=r"^prd_[0-9a-f]{32}$")
    evaluation_id: UUID
    approval_task_id: UUID
    reviewer_user_id: UUID
    decided_at: str
    ledger_close_authorized: Literal[False]


def parse_period_reconciliation_outcomes(
    value: Any,
) -> tuple[PeriodReconciliationOutcomeFact, ...]:
    if not isinstance(value, list):
        raise ValueError("Period Reconciliation outcomes must be a JSON array")
    retained = tuple(
        PeriodReconciliationOutcomeFact.model_validate(item) for item in value
    )
    if (
        len(retained) != len(_OUTCOME_METRICS)
        or {item.metric_ref for item in retained} != _OUTCOME_METRICS
    ):
        raise ValueError("Period Reconciliation outcomes are not the exact three-fact set")
    return retained


def parse_period_reconciliation_campaign_facts(
    value: Any,
) -> tuple[PeriodReconciliationCampaignFact, ...]:
    if not isinstance(value, list):
        raise ValueError("Period Reconciliation campaign facts must be a JSON array")
    retained = tuple(
        PeriodReconciliationCampaignFact.model_validate(item) for item in value
    )
    if (
        len(retained) != len(_CAMPAIGN_EVIDENCE_KINDS)
        or {item.evidence_kind for item in retained} != _CAMPAIGN_EVIDENCE_KINDS
    ):
        raise ValueError("Period Reconciliation campaign facts are not exhaustive")
    return retained


__all__ = [
    "PERIOD_RECONCILIATION_MCP_TOOLS",
    "PERIOD_RECONCILIATION_REST_ROOT",
    "PeriodReconciliationCampaignFact",
    "PeriodReconciliationEvaluationReceipt",
    "PeriodReconciliationEvaluationRequest",
    "PeriodReconciliationOutcomeFact",
    "PeriodReconciliationQuickBooksReadSetRequest",
    "PeriodReconciliationReadSetReceipt",
    "PeriodReconciliationRestartRequest",
    "PeriodReconciliationReviewReceipt",
    "PeriodReconciliationReviewRequest",
    "PeriodReconciliationRun",
    "PeriodReconciliationRunReceipt",
    "PeriodReconciliationScopeReceipt",
    "PeriodReconciliationScopeRequest",
    "PeriodReconciliationStage",
    "PeriodReconciliationSourceKind",
    "PeriodReconciliationStageRequest",
    "PeriodReconciliationStartRequest",
    "PeriodReconciliationTerminalRequest",
    "parse_period_reconciliation_campaign_facts",
    "parse_period_reconciliation_outcomes",
]
