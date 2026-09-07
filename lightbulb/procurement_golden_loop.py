"""Typed contracts for Spring's canonical Procurement Golden Loop 0.3 surface.

These models can describe and request work. They do not persist evidence, resolve actor scope,
approve spend, call Xero, or decide whether an external effect occurred.
"""

from __future__ import annotations

import re
from datetime import datetime
from decimal import Decimal
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from lightbulb.economic_spine_runs import EconomicSpineRun


ProcurementSourceKind = Literal[
    "REQUISITION_SOURCE",
    "REQUISITION_SUBMISSION",
    "APPROVED_COMMITMENT",
    "PURCHASE_ORDER_ISSUED",
    "GOODS_RECEIVED",
    "MATCHED_CLOSE",
    "FAILED",
    "CANCELLED",
    "EFFECT_AMBIGUOUS",
]
ProcurementCommandOperation = Literal[
    "START_REQUISITION",
    "REQUISITION_SUBMISSION",
    "APPROVED_COMMITMENT",
    "PURCHASE_ORDER_ISSUED",
    "RECORD_GOODS_RECEIPT",
    "MATCHED_CLOSE",
    "GET",
    "FAILED",
    "CANCELLED",
    "EFFECT_AMBIGUOUS",
    "RECONCILE",
]


def validate_procurement_run_ref(value: object) -> str:
    """Validate the opaque Spring-owned Procurement run reference."""

    if not isinstance(value, str) or re.fullmatch(r"ppr_[0-9a-f]{32}", value) is None:
        raise ValueError("run_ref must be a canonical Procurement reference")
    return value


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid", frozen=True, populate_by_name=True, serialize_by_alias=True
    )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


class _Command(_StrictModel):
    command_id: UUID
    idempotency_key: str = Field(
        min_length=1, max_length=256,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9:/._#@~-]{0,255}$",
    )


class ProcurementRequisitionLine(_StrictModel):
    line_ref: str = Field(
        min_length=1, max_length=256,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9:/._#@~-]{0,255}$",
    )
    description: str = Field(min_length=1, max_length=500)
    quantity: Decimal = Field(ge=0, max_digits=18, decimal_places=9)
    unit_amount: Decimal = Field(ge=0, max_digits=18, decimal_places=9)
    account_code: str = Field(
        min_length=1, max_length=256,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9:/._#@~-]{0,255}$",
    )

    @field_validator("description")
    @classmethod
    def _exact_description(cls, value: str) -> str:
        if value != value.strip() or any(ord(character) < 32 for character in value):
            raise ValueError("description must be exact")
        return value


class ProcurementStart(_Command):
    model_execution_run_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=512,
        description="Ignored legacy correlation hint; Spring mints runtime authority.",
    )
    supplier_ref: str = Field(
        min_length=1, max_length=256,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9:/._#@~-]{0,255}$",
    )
    cost_center_ref: str = Field(
        min_length=1, max_length=256,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9:/._#@~-]{0,255}$",
    )
    budget_policy_ref: str = Field(
        min_length=1, max_length=256,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9:/._#@~-]{0,255}$",
    )
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    requested_total: Decimal = Field(ge=0, max_digits=18, decimal_places=9)
    lines: tuple[ProcurementRequisitionLine, ...] = Field(min_length=1, max_length=250)

    @field_validator("model_execution_run_id")
    @classmethod
    def _exact_model_run(cls, value: str | None) -> str | None:
        if value is not None and (
            value != value.strip()
            or any(ord(character) < 32 for character in value)
        ):
            raise ValueError("model_execution_run_id must be exact")
        return value


class ProcurementApprovalBinding(_Command):
    requisition_source_id: UUID
    approval_task_id: UUID


class ProcurementPurchaseOrderJournalBinding(_Command):
    """Opaque journals only; Spring derives the provider result and all digests."""

    approved_commitment_source_id: UUID
    write_journal_id: UUID
    readback_journal_id: UUID

    @model_validator(mode="after")
    def _independent_journals(self) -> "ProcurementPurchaseOrderJournalBinding":
        if self.write_journal_id == self.readback_journal_id:
            raise ValueError("write and readback journals must be distinct")
        return self


class ProcurementGoodsReceiptLine(_StrictModel):
    purchase_order_line_ref: str = Field(
        min_length=1, max_length=256,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9:/._#@~-]{0,255}$",
    )
    quantity_received: Decimal = Field(ge=0, max_digits=18, decimal_places=9)


class ProcurementGoodsReceipt(_Command):
    source_artifact_ref: str = Field(
        min_length=1, max_length=256,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9:/._#@~-]{0,255}$",
    )
    received_at: datetime
    lines: tuple[ProcurementGoodsReceiptLine, ...] = Field(min_length=1, max_length=250)


class ProcurementSupplierInvoiceLine(_StrictModel):
    purchase_order_line_ref: str = Field(
        min_length=1, max_length=256,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9:/._#@~-]{0,255}$",
    )
    quantity_invoiced: Decimal = Field(ge=0, max_digits=18, decimal_places=9)
    unit_amount: Decimal = Field(ge=0, max_digits=18, decimal_places=9)
    line_total: Decimal = Field(ge=0, max_digits=18, decimal_places=9)


class ProcurementSupplierInvoice(_StrictModel):
    idempotency_key: str = Field(
        min_length=1, max_length=256,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9:/._#@~-]{0,255}$",
    )
    source_artifact_ref: str = Field(
        min_length=1, max_length=256,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9:/._#@~-]{0,255}$",
    )
    supplier_invoice_number: str = Field(
        min_length=1, max_length=256,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9:/._#@~-]{0,255}$",
    )
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    invoice_total: Decimal = Field(ge=0, max_digits=18, decimal_places=9)
    invoice_received_at: datetime
    lines: tuple[ProcurementSupplierInvoiceLine, ...] = Field(
        min_length=1, max_length=250
    )


class ProcurementThreeWayMatch(_StrictModel):
    idempotency_key: str = Field(
        min_length=1, max_length=256,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9:/._#@~-]{0,255}$",
    )
    purchase_order_source_id: UUID
    goods_receipt_id: UUID
    supplier_invoice_id: UUID
    quantity_tolerance: Decimal = Field(ge=0, max_digits=18, decimal_places=9)
    unit_price_tolerance: Decimal = Field(ge=0, max_digits=18, decimal_places=9)
    subtotal_tolerance: Decimal = Field(ge=0, max_digits=18, decimal_places=9)
    evaluated_at: datetime


class ProcurementMatchedClose(_Command):
    approved_commitment_source_id: UUID
    supplier_invoice_id: UUID
    three_way_match_id: UUID
    close_approval_task_id: UUID


class ProcurementFailure(_Command):
    reason_code: str = Field(
        min_length=1, max_length=256,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9:/._#@~-]{0,255}$",
    )
    approved_commitment_source_id: UUID | None = None
    approval_task_id: UUID | None = None
    write_journal_id: UUID | None = None


class ProcurementCancellation(_Command):
    reason_code: str = Field(
        min_length=1, max_length=256,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9:/._#@~-]{0,255}$",
    )
    approval_task_id: UUID | None = None


class ProcurementAmbiguity(_Command):
    approved_commitment_source_id: UUID
    write_journal_id: UUID


class ProcurementReconciliation(_Command):
    write_journal_id: UUID
    readback_journal_id: UUID
    approval_task_id: UUID
    reconciled_at: datetime

    @model_validator(mode="after")
    def _independent_journals(self) -> "ProcurementReconciliation":
        if self.write_journal_id == self.readback_journal_id:
            raise ValueError("write and readback journals must be distinct")
        return self


class ProcurementCommandReceipt(_StrictModel):
    schema_id: Literal[
        "lightbulb.procurement_golden_loop_command_receipt.v3"
    ] = Field(alias="schema")
    operation: ProcurementCommandOperation
    loop_ref: Literal["procurement.approved_commitment_to_matched_close"]
    certification_version: Literal["0.3.0"]
    execution_version: Literal["0.1.0"]
    run: EconomicSpineRun
    source_record_id: UUID | None = None
    source_ref: str | None = Field(default=None, pattern=r"^psr_[0-9a-f]{32}$")
    source_kind: ProcurementSourceKind | None = None
    observation_id: UUID | None = None
    observation_ref: str | None = Field(default=None, pattern=r"^eso_[0-9a-f]{32}$")
    custody_id: UUID | None = None
    custody_ref: str | None = Field(default=None, pattern=r"^pgr_[0-9a-f]{32}$")
    custody_kind: Literal["GOODS_RECEIPT"] | None = None
    reconciliation_observation_id: UUID | None = None

    @model_validator(mode="after")
    def _exact_procurement_run(self) -> "ProcurementCommandReceipt":
        if self.run.loop_ref != self.loop_ref:
            raise ValueError("receipt run is not Procurement 0.3")
        source = (self.source_record_id, self.source_ref, self.source_kind)
        if any(value is not None for value in source) and not all(
            value is not None for value in source
        ):
            raise ValueError("source receipt fields must be complete")
        observation = (self.observation_id, self.observation_ref)
        if any(value is not None for value in observation) and not all(
            value is not None for value in observation
        ):
            raise ValueError("observation receipt fields must be complete")
        custody = (self.custody_id, self.custody_ref, self.custody_kind)
        if any(value is not None for value in custody) and not all(
            value is not None for value in custody
        ):
            raise ValueError("custody receipt fields must be complete")
        return self


class ProcurementCustodyReceipt(_StrictModel):
    schema_id: Literal[
        "lightbulb.procurement_golden_loop_custody_receipt.v3"
    ] = Field(alias="schema")
    operation: Literal["RECORD_SUPPLIER_INVOICE", "DERIVE_THREE_WAY_MATCH"]
    loop_ref: Literal["procurement.approved_commitment_to_matched_close"]
    certification_version: Literal["0.3.0"]
    execution_version: Literal["0.1.0"]
    run_ref: str = Field(pattern=r"^ppr_[0-9a-f]{32}$")
    custody_kind: Literal["SUPPLIER_INVOICE", "THREE_WAY_MATCH"]
    custody_id: UUID
    custody_ref: str = Field(pattern=r"^(psi|ptm)_[0-9a-f]{32}$")
    matched: bool | None = None
    exception_count: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def _kind_shape(self) -> "ProcurementCustodyReceipt":
        if self.custody_kind == "THREE_WAY_MATCH":
            if self.matched is None or self.exception_count is None:
                raise ValueError("three-way match receipt lacks derived result")
        elif self.matched is not None or self.exception_count is not None:
            raise ValueError("invoice custody cannot claim a match result")
        return self


class ProcurementOutcomeFact(_StrictModel):
    metric_ref: Literal[
        "spend_policy_compliance_rate",
        "matched_procurement_close_rate",
        "duplicate_purchase_order_effect_rate",
    ]
    numerator_value: Decimal
    denominator_value: Decimal
    measured_value: Decimal
    source_run_id: UUID
    source_record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    provider_write_journal_id: UUID | None = None
    provider_readback_journal_id: UUID | None = None


class ProcurementOutcomeReceipt(_StrictModel):
    schema_id: Literal[
        "lightbulb.procurement_golden_loop_outcome_receipt.v3"
    ] = Field(alias="schema")
    loop_ref: Literal["procurement.approved_commitment_to_matched_close"]
    certification_version: Literal["0.3.0"]
    execution_version: Literal["0.1.0"]
    run: EconomicSpineRun
    outcomes: tuple[ProcurementOutcomeFact, ...] = Field(min_length=3, max_length=3)

    @model_validator(mode="after")
    def _exact_metrics(self) -> "ProcurementOutcomeReceipt":
        if {fact.metric_ref for fact in self.outcomes} != {
            "spend_policy_compliance_rate",
            "matched_procurement_close_rate",
            "duplicate_purchase_order_effect_rate",
        }:
            raise ValueError("Procurement outcome set is not exact")
        return self


__all__ = [
    "ProcurementAmbiguity",
    "ProcurementApprovalBinding",
    "ProcurementCancellation",
    "ProcurementCommandOperation",
    "ProcurementCommandReceipt",
    "ProcurementCustodyReceipt",
    "ProcurementFailure",
    "ProcurementGoodsReceipt",
    "ProcurementGoodsReceiptLine",
    "ProcurementMatchedClose",
    "ProcurementOutcomeFact",
    "ProcurementOutcomeReceipt",
    "ProcurementPurchaseOrderJournalBinding",
    "ProcurementReconciliation",
    "ProcurementRequisitionLine",
    "ProcurementStart",
    "ProcurementSourceKind",
    "ProcurementSupplierInvoice",
    "ProcurementSupplierInvoiceLine",
    "ProcurementThreeWayMatch",
    "validate_procurement_run_ref",
]
