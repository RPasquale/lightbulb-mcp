"""Typed, deterministic Period Reconciliation 0.3 primitive contracts.

The SDK evaluates normalized, source-referenced QuickBooks READ observations.
Spring remains the authority for Tool Runtime invocation custody, journal and
reviewer evidence, run state, RBAC, outcomes, and terminal truth. This module
cannot post a journal, lock a subledger, close books, or call a connector.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Literal, Mapping
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from lightbulb.connector_execution import ConnectorEffect
from lightbulb.primitive_runtime import (
    BusinessProcessPrimitive,
    PrimitiveEvent,
    PrimitiveEvidence,
    PrimitiveExecutionContext,
    PrimitiveExecutionResult,
    PrimitiveExecutionStatus,
    PrimitiveOperationFreshnessClass,
    PrimitiveOperationReceipt,
    PrimitiveOperationRecoveryPolicy,
    PrimitiveOperationReplayClass,
    PrimitiveOperationSpec,
    PrimitiveOperationStatus,
)


PERIOD_RECONCILIATION_INPUT_SCHEMA = "lightbulb.period_reconciliation_input.v3"
PERIOD_RECONCILIATION_RESULT_SCHEMA = "lightbulb.period_reconciliation_result.v3"
PERIOD_RECONCILIATION_TOOL_REFS = (
    "quickbooks.trial_balance_report",
    "quickbooks.balance_sheet_report",
    "quickbooks.cash_flow_report",
    "quickbooks.aged_receivable_report",
    "quickbooks.aged_payable_report",
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid", frozen=True, populate_by_name=True, serialize_by_alias=True
    )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


class PeriodReconciliationScope(_StrictModel):
    period_ref: str = Field(min_length=1, max_length=160)
    period_start: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    period_end: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    ledger_ref: str = Field(min_length=1, max_length=160)
    entity_group_ref: str = Field(min_length=1, max_length=160)
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    accounting_method: Literal["Accrual", "Cash"]
    close_calendar_ref: str = Field(min_length=1, max_length=160)
    materiality_micros: int = Field(ge=0)
    variance_threshold_micros: int = Field(ge=0)

    @model_validator(mode="after")
    def _threshold_is_bounded(self) -> "PeriodReconciliationScope":
        from datetime import date

        start = date.fromisoformat(self.period_start)
        end = date.fromisoformat(self.period_end)
        if end < start or (end - start).days > 370:
            raise ValueError("period must be ordered and bounded to 371 days")
        if self.variance_threshold_micros > self.materiality_micros:
            raise ValueError("variance threshold cannot exceed materiality")
        return self


class QuickBooksPeriodReadObservation(_StrictModel):
    invocation_id: UUID
    tool_ref: Literal[
        "quickbooks.trial_balance_report",
        "quickbooks.balance_sheet_report",
        "quickbooks.cash_flow_report",
        "quickbooks.aged_receivable_report",
        "quickbooks.aged_payable_report",
    ]
    connector_account_ref: str = Field(min_length=1, max_length=200)
    input_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    output_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    period_start: str | None = Field(default=None, pattern=r"^\d{4}-\d{2}-\d{2}$")
    period_end: str | None = Field(default=None, pattern=r"^\d{4}-\d{2}-\d{2}$")
    as_of_date: str | None = Field(default=None, pattern=r"^\d{4}-\d{2}-\d{2}$")
    accounting_method: Literal["Accrual", "Cash"] | None = None
    total_debits_micros: int | None = Field(default=None, ge=0)
    total_credits_micros: int | None = Field(default=None, ge=0)
    cash_total_micros: int | None = None
    accounts_receivable_total_micros: int | None = None
    accounts_payable_total_micros: int | None = None
    ending_cash_micros: int | None = None
    report_total_micros: int | None = None

    @model_validator(mode="after")
    def _exact_tool_shape(self) -> "QuickBooksPeriodReadObservation":
        if self.tool_ref == "quickbooks.trial_balance_report":
            if self.total_debits_micros is None or self.total_credits_micros is None:
                raise ValueError("trial balance requires exact debit and credit totals")
        elif self.tool_ref == "quickbooks.balance_sheet_report":
            if any(value is None for value in (
                self.cash_total_micros,
                self.accounts_receivable_total_micros,
                self.accounts_payable_total_micros,
            )):
                raise ValueError("balance sheet requires cash, AR, and AP totals")
        elif self.tool_ref == "quickbooks.cash_flow_report":
            if self.ending_cash_micros is None:
                raise ValueError("cash flow requires ending cash")
        elif self.report_total_micros is None:
            raise ValueError("aging report requires an exact report total")
        return self


class RetainedJournalEvidence(_StrictModel):
    settlement_run_id: UUID
    settlement_receipt_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    state: Literal["SETTLED_APPLIED"]


class PeriodReconciliationInput(_StrictModel):
    schema_id: Literal["lightbulb.period_reconciliation_input.v3"] = Field(
        default=PERIOD_RECONCILIATION_INPUT_SCHEMA, alias="schema"
    )
    evaluation_ref: str = Field(min_length=1, max_length=160)
    scope: PeriodReconciliationScope
    quickbooks_reads: tuple[QuickBooksPeriodReadObservation, ...] = Field(
        min_length=5, max_length=5
    )
    journal_evidence: tuple[RetainedJournalEvidence, ...] = Field(
        min_length=1, max_length=256
    )

    @field_validator("quickbooks_reads", "journal_evidence", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value)

    @model_validator(mode="after")
    def _exact_source_set(self) -> "PeriodReconciliationInput":
        reads = {item.tool_ref: item for item in self.quickbooks_reads}
        if tuple(sorted(reads)) != tuple(sorted(PERIOD_RECONCILIATION_TOOL_REFS)):
            raise ValueError("QuickBooks report declaration must be exact and exhaustive")
        if len({item.invocation_id for item in self.quickbooks_reads}) != 5:
            raise ValueError("QuickBooks invocation IDs must be unique")
        if len({item.connector_account_ref for item in self.quickbooks_reads}) != 1:
            raise ValueError("all QuickBooks reads must use one connector account")
        if len({item.settlement_run_id for item in self.journal_evidence}) != len(
            self.journal_evidence
        ):
            raise ValueError("journal settlement IDs must be unique")
        for tool_ref in (
            "quickbooks.trial_balance_report",
            "quickbooks.cash_flow_report",
        ):
            report = reads[tool_ref]
            if (
                report.period_start != self.scope.period_start
                or report.period_end != self.scope.period_end
                or report.accounting_method != self.scope.accounting_method
            ):
                raise ValueError(f"{tool_ref} differs from the exact period scope")
        balance = reads["quickbooks.balance_sheet_report"]
        if (
            balance.as_of_date != self.scope.period_end
            or balance.accounting_method != self.scope.accounting_method
        ):
            raise ValueError("balance sheet differs from the exact period scope")
        for tool_ref in (
            "quickbooks.aged_receivable_report",
            "quickbooks.aged_payable_report",
        ):
            if reads[tool_ref].as_of_date != self.scope.period_end:
                raise ValueError(f"{tool_ref} differs from the exact period cutoff")
        return self


class PeriodReconciliationException(_StrictModel):
    code: Literal[
        "trial_balance_out_of_balance",
        "cash_report_variance",
        "accounts_receivable_variance",
        "accounts_payable_variance",
    ]
    variance_micros: int = Field(ge=0)
    threshold_micros: int = Field(ge=0)
    bounded_remediation: str = Field(min_length=1, max_length=160)
    provider_write_required: Literal[False] = False


class PeriodReconciliationResult(_StrictModel):
    schema_id: Literal["lightbulb.period_reconciliation_result.v3"] = Field(
        default=PERIOD_RECONCILIATION_RESULT_SCHEMA, alias="schema"
    )
    evaluation_ref: str
    trial_balance_debits_micros: int = Field(ge=0)
    trial_balance_credits_micros: int = Field(ge=0)
    cash_variance_micros: int = Field(ge=0)
    ar_variance_micros: int = Field(ge=0)
    ap_variance_micros: int = Field(ge=0)
    exceptions: tuple[PeriodReconciliationException, ...]
    within_threshold: bool
    approved_close_candidate_eligible: bool
    provider_read_conformance_required: Literal[True] = True
    provider_write_applicability: Literal["NOT_APPLICABLE"] = "NOT_APPLICABLE"
    ambiguous_provider_write_applicability: Literal["NOT_APPLICABLE"] = (
        "NOT_APPLICABLE"
    )
    ledger_close_authorized: Literal[False] = False
    ledger_close_claimed: Literal[False] = False
    evaluation_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


PERIOD_RECONCILIATION_OPERATION = PrimitiveOperationSpec(
    operation_ref="period-reconciliation.evaluate",
    tool="finance.evaluate_period_reconciliation",
    effect=ConnectorEffect.READ,
    approval_required=False,
    replay_class=PrimitiveOperationReplayClass.SAFE,
    freshness_class=PrimitiveOperationFreshnessClass.BOUNDED,
    recovery_policy=PrimitiveOperationRecoveryPolicy.NONE,
)


def evaluate_period_reconciliation(
    value: PeriodReconciliationInput | dict[str, Any],
) -> PeriodReconciliationResult:
    parsed = (
        value
        if isinstance(value, PeriodReconciliationInput)
        else PeriodReconciliationInput.model_validate(value)
    )
    reads = {item.tool_ref: item for item in parsed.quickbooks_reads}
    trial = reads["quickbooks.trial_balance_report"]
    balance = reads["quickbooks.balance_sheet_report"]
    cash = reads["quickbooks.cash_flow_report"]
    ar = reads["quickbooks.aged_receivable_report"]
    ap = reads["quickbooks.aged_payable_report"]
    assert trial.total_debits_micros is not None
    assert trial.total_credits_micros is not None
    assert balance.cash_total_micros is not None
    assert balance.accounts_receivable_total_micros is not None
    assert balance.accounts_payable_total_micros is not None
    assert cash.ending_cash_micros is not None
    assert ar.report_total_micros is not None
    assert ap.report_total_micros is not None
    cash_variance = abs(balance.cash_total_micros - cash.ending_cash_micros)
    ar_variance = abs(balance.accounts_receivable_total_micros - ar.report_total_micros)
    ap_variance = abs(balance.accounts_payable_total_micros - ap.report_total_micros)
    threshold = parsed.scope.variance_threshold_micros
    exceptions: list[PeriodReconciliationException] = []
    if trial.total_debits_micros != trial.total_credits_micros:
        exceptions.append(PeriodReconciliationException(
            code="trial_balance_out_of_balance",
            variance_micros=abs(
                trial.total_debits_micros - trial.total_credits_micros
            ),
            threshold_micros=threshold,
            bounded_remediation="reconcile_trial_balance_source_rows",
        ))
    for code, variance, remediation in (
        ("cash_report_variance", cash_variance, "tie_cash_flow_to_balance_sheet"),
        (
            "accounts_receivable_variance",
            ar_variance,
            "tie_ar_aging_to_control_account",
        ),
        (
            "accounts_payable_variance",
            ap_variance,
            "tie_ap_aging_to_control_account",
        ),
    ):
        if variance > threshold:
            exceptions.append(PeriodReconciliationException(
                code=code,  # type: ignore[arg-type]
                variance_micros=variance,
                threshold_micros=threshold,
                bounded_remediation=remediation,
            ))
    digest_payload = {
        "schema": PERIOD_RECONCILIATION_RESULT_SCHEMA,
        "evaluation_ref": parsed.evaluation_ref,
        "scope": parsed.scope.to_dict(),
        "read_digests": [
            {
                "tool_ref": item.tool_ref,
                "invocation_id": str(item.invocation_id),
                "input_digest": item.input_digest,
                "output_digest": item.output_digest,
            }
            for item in sorted(parsed.quickbooks_reads, key=lambda item: item.tool_ref)
        ],
        "journal_evidence": [
            {
                "settlement_run_id": str(item.settlement_run_id),
                "settlement_receipt_digest": item.settlement_receipt_digest,
                "state": item.state,
            }
            for item in sorted(
                parsed.journal_evidence,
                key=lambda item: str(item.settlement_run_id),
            )
        ],
        "trial_balance_debits_micros": trial.total_debits_micros,
        "trial_balance_credits_micros": trial.total_credits_micros,
        "cash_variance_micros": cash_variance,
        "ar_variance_micros": ar_variance,
        "ap_variance_micros": ap_variance,
        "exceptions": [item.to_dict() for item in exceptions],
        "provider_write_applicability": "NOT_APPLICABLE",
        "ledger_close_claimed": False,
    }
    digest = hashlib.sha256(json.dumps(
        digest_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")).hexdigest()
    ready = not exceptions
    return PeriodReconciliationResult(
        evaluation_ref=parsed.evaluation_ref,
        trial_balance_debits_micros=trial.total_debits_micros,
        trial_balance_credits_micros=trial.total_credits_micros,
        cash_variance_micros=cash_variance,
        ar_variance_micros=ar_variance,
        ap_variance_micros=ap_variance,
        exceptions=tuple(exceptions),
        within_threshold=ready,
        approved_close_candidate_eligible=ready,
        evaluation_digest=digest,
    )


def _period_reconciliation_example_inputs() -> dict[str, Any]:
    reads: list[dict[str, Any]] = []
    for index, tool_ref in enumerate(PERIOD_RECONCILIATION_TOOL_REFS, start=1):
        read: dict[str, Any] = {
            "invocation_id": str(UUID(int=index)),
            "tool_ref": tool_ref,
            "connector_account_ref": "quickbooks:realm:example",
            "input_digest": f"{index:064x}",
            "output_digest": f"{index + 10:064x}",
        }
        if tool_ref in {
            "quickbooks.trial_balance_report",
            "quickbooks.cash_flow_report",
        }:
            read.update(
                period_start="2026-07-01",
                period_end="2026-07-31",
                accounting_method="Accrual",
            )
        if tool_ref == "quickbooks.trial_balance_report":
            read.update(
                total_debits_micros=12_000_000,
                total_credits_micros=12_000_000,
            )
        elif tool_ref == "quickbooks.balance_sheet_report":
            read.update(
                as_of_date="2026-07-31",
                accounting_method="Accrual",
                cash_total_micros=8_000_000,
                accounts_receivable_total_micros=2_000_000,
                accounts_payable_total_micros=1_500_000,
            )
        elif tool_ref == "quickbooks.cash_flow_report":
            read["ending_cash_micros"] = 8_000_000
        elif tool_ref == "quickbooks.aged_receivable_report":
            read.update(as_of_date="2026-07-31", report_total_micros=2_000_000)
        else:
            read.update(as_of_date="2026-07-31", report_total_micros=1_500_000)
        reads.append(read)
    return {
        "schema": PERIOD_RECONCILIATION_INPUT_SCHEMA,
        "evaluation_ref": "close:2026-07",
        "scope": {
            "period_ref": "2026-07",
            "period_start": "2026-07-01",
            "period_end": "2026-07-31",
            "ledger_ref": "ledger:primary",
            "entity_group_ref": "entity:example",
            "currency": "USD",
            "accounting_method": "Accrual",
            "close_calendar_ref": "calendar:monthly",
            "materiality_micros": 1_000_000,
            "variance_threshold_micros": 100_000,
        },
        "quickbooks_reads": reads,
        "journal_evidence": [
            {
                "settlement_run_id": str(UUID(int=100)),
                "settlement_receipt_digest": "f" * 64,
                "state": "SETTLED_APPLIED",
            }
        ],
    }


class EvaluatePeriodReconciliationPrimitive(
    BusinessProcessPrimitive[PeriodReconciliationInput, PeriodReconciliationResult]
):
    primitive_ref = "finance.evaluate_period_reconciliation"
    version = "0.3.0"
    title = "Evaluate source-bound period reconciliation"
    description = (
        "Deterministically reconcile exact QuickBooks report observations and "
        "retained journal evidence to an approved-close-candidate gate without "
        "posting, locking, or closing a ledger."
    )
    input_model = PeriodReconciliationInput
    output_model = PeriodReconciliationResult
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    example_inputs: Mapping[str, Any] = _period_reconciliation_example_inputs()
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False

    def implementation_contract(self) -> dict[str, Any]:
        contract = super().implementation_contract()
        contract["operation_contract"] = PERIOD_RECONCILIATION_OPERATION.to_dict()
        contract["required_tool_runtime_reads"] = list(
            PERIOD_RECONCILIATION_TOOL_REFS
        )
        contract["effect_boundary"] = {
            "connector_reads": 5,
            "connector_writes": 0,
            "journal_posts": 0,
            "subledger_locks": 0,
            "period_closes": 0,
        }
        contract["system_of_record_authority"] = (
            "spring.period_reconciliation_source.v3"
        )
        return contract

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: PeriodReconciliationInput,
    ) -> PrimitiveExecutionResult[PeriodReconciliationResult]:
        del context
        output = evaluate_period_reconciliation(inputs)
        receipt = PrimitiveOperationReceipt(
            spec=PERIOD_RECONCILIATION_OPERATION,
            status=PrimitiveOperationStatus.COMPLETED,
            request_digest=output.evaluation_digest,
            external_refs={"evaluation_digest": output.evaluation_digest},
        )
        return PrimitiveExecutionResult(
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                "Period reconciliation is within threshold."
                if output.within_threshold
                else "Period reconciliation retained bounded exceptions."
            ),
            output=output,
            events=[PrimitiveEvent(
                type="finance.period_reconciliation_evaluated",
                payload={
                    "evaluation_digest": output.evaluation_digest,
                    "within_threshold": output.within_threshold,
                    "exception_count": len(output.exceptions),
                    "ledger_close_claimed": False,
                },
            )],
            evidence=[PrimitiveEvidence(
                kind="period_reconciliation_evaluation",
                summary=(
                    "Five exact report observations and retained journals were "
                    "evaluated without a provider write or books-close claim."
                ),
                labels=["read_only", "source_bound", "approved_candidate_only"],
                refs={"evaluation_digest": output.evaluation_digest},
            )],
            operation_receipts=[receipt],
        )


PERIOD_RECONCILIATION_EXECUTABLE_PRIMITIVES: tuple[
    BusinessProcessPrimitive[Any, Any], ...
] = (EvaluatePeriodReconciliationPrimitive(),)


__all__ = [
    "EvaluatePeriodReconciliationPrimitive",
    "PERIOD_RECONCILIATION_EXECUTABLE_PRIMITIVES",
    "PERIOD_RECONCILIATION_INPUT_SCHEMA",
    "PERIOD_RECONCILIATION_OPERATION",
    "PERIOD_RECONCILIATION_RESULT_SCHEMA",
    "PERIOD_RECONCILIATION_TOOL_REFS",
    "PeriodReconciliationException",
    "PeriodReconciliationInput",
    "PeriodReconciliationResult",
    "PeriodReconciliationScope",
    "QuickBooksPeriodReadObservation",
    "RetainedJournalEvidence",
    "evaluate_period_reconciliation",
]
