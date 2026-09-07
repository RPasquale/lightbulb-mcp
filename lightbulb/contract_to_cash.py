"""Typed continuation from accepted work to a governed invoice-effect candidate.

This module deliberately does not create a second commercial, invoice, connector, or
payment authority.  It binds an already-executed commercial agreement and independently
accepted value to the existing ``finance.create_invoice`` and exact read-back primitives.
Spring alone resolves scope, Tool Binding, approval, persistence, provider execution, and
read-back. Provider write acceptance is explicitly non-terminal; authoritative commercial
custody and independently verified cash settlement remain required.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import date, datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from enum import Enum
from typing import Any, Literal, Mapping
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from lightbulb.primitive_runtime import (
    PrimitiveEvidenceRef,
    PrimitiveEvidenceVerificationGrade,
)


CONTRACT_TO_CASH_WORKFLOW_REF = "finance.contract_to_cash_continuation"
CONTRACT_TO_CASH_WORKFLOW_VERSION = "0.3.0"
EXECUTED_AGREEMENT_BINDING_SCHEMA = (
    "lightbulb.executed_commercial_agreement_binding.v1"
)
VALUE_ACCEPTANCE_BINDING_SCHEMA = "lightbulb.value_acceptance_binding.v1"
CONTRACT_TO_CASH_INPUT_SCHEMA = "lightbulb.contract_to_cash_continuation_input.v1"
CONTRACT_TO_CASH_PLAN_SCHEMA = "lightbulb.contract_to_cash_continuation_plan.v1"
CONTRACT_TO_CASH_INVOICE_ADMISSION_SCHEMA = (
    "lightbulb.contract_to_cash_invoice_admission.v1"
)
CONTRACT_TO_CASH_INVOICE_PROPOSAL_RECEIPT_SCHEMA = (
    "lightbulb.contract_to_cash_invoice_proposal_receipt.v1"
)
CONTRACT_TO_CASH_INVOICE_WRITE_RECEIPT_SCHEMA = (
    "lightbulb.contract_to_cash_invoice_write_receipt.v1"
)
CONTRACT_TO_CASH_EFFECT_BOUNDARY_SCHEMA = (
    "lightbulb.contract_to_cash_effect_boundary.v1"
)
CONTRACT_TO_CASH_SETTLEMENT_POLICY_SCHEMA = (
    "lightbulb.contract_to_cash_settlement_evidence_policy.v1"
)
CONTRACT_TO_CASH_INVOICE_ISSUED_RECORD_SCHEMA = (
    "lightbulb.contract_to_cash_invoice_issued_record.v1"
)
CONTRACT_TO_CASH_COLLECTION_RECORD_SCHEMA = (
    "lightbulb.contract_to_cash_collection_record.v1"
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MODEL_EXECUTION_RUN_ID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_PORTABLE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+\-]{0,199}$")
_CONNECTOR_ACCOUNT_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/\-]{0,199}$")
_CURRENCY = re.compile(r"^[A-Z]{3}$")
_CALENDAR_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_MONEY_QUANTUM = Decimal("0.01")
_QUANTITY_QUANTUM = Decimal("0.000001")
_MAX_DECIMAL = Decimal("1e24")
_AGREEMENT_STATUSES = {
    "contract_order_reviewed",
    "subscription_active",
    "billing_proposed",
    "renewal_reviewed",
    "channel_attributed",
    "revops_handoff_ready",
}
_AGREEMENT_STATUS_BY_VERSION = {
    2: "contract_order_reviewed",
    3: "subscription_active",
    4: "billing_proposed",
    5: "renewal_reviewed",
    6: "channel_attributed",
    7: "revops_handoff_ready",
}
_CASH_EVIDENCE_KINDS = (
    "provider_invoice_readback",
    "provider_payment_application",
    "cash_settlement_readback",
)


def _canonical_sha256(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _utc_timestamp(value: str, *, field_name: str) -> str:
    clean = value.strip()
    if clean != value:
        raise ValueError(f"{field_name} must not contain surrounding whitespace")
    try:
        parsed = datetime.fromisoformat(clean.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field_name} must be valid ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field_name} must include a UTC offset")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_utc_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _decimal(value: Any, *, quantum: Decimal, label: str) -> Decimal:
    if isinstance(value, bool):
        raise ValueError(f"{label} must be a finite decimal")
    try:
        parsed = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"{label} must be a finite decimal") from exc
    if not parsed.is_finite():
        raise ValueError(f"{label} must be a finite decimal")
    if abs(parsed) > _MAX_DECIMAL:
        raise ValueError(f"{label} exceeds the bounded contract-to-cash range")
    try:
        normalized = parsed.quantize(quantum, rounding=ROUND_HALF_UP)
    except InvalidOperation as exc:
        raise ValueError(f"{label} must be a bounded decimal") from exc
    if parsed != normalized:
        raise ValueError(f"{label} has more precision than {quantum}")
    return normalized


def _money_text(value: Decimal) -> str:
    return format(value.quantize(_MONEY_QUANTUM), "f")


def _quantity_text(value: Decimal) -> str:
    return format(value.quantize(_QUANTITY_QUANTUM), "f")


def _correlation_ref(continuation_ref: str) -> str:
    digest = hashlib.sha256(continuation_ref.encode("utf-8")).hexdigest().upper()
    return f"LB-CTC-{digest[:18]}"


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        serialize_by_alias=True,
    )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


class ContractToCashPlanState(str, Enum):
    INVOICE_PROPOSAL_READY = "invoice_proposal_ready"


class ExecutedCommercialAgreementBinding(_StrictModel):
    """Content-bound projection of an executed commercial lifecycle snapshot.

    The binding remains proposal evidence.  Spring must resolve the referenced snapshot
    from authoritative custody before admitting an external effect.
    """

    schema_id: Literal["lightbulb.executed_commercial_agreement_binding.v1"] = Field(
        default=EXECUTED_AGREEMENT_BINDING_SCHEMA,
        alias="schema",
    )
    commercial_snapshot_schema: Literal[
        "lightbulb.commercial_operations_lifecycle_snapshot.v2"
    ]
    commercial_snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    agreement_custody_record_id: UUID
    agreement_custody_record_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    agreement_ref: str = Field(
        pattern=r"^agreement:docusign:[0-9a-f]{32}$"
    )
    agreement_connector_account_ref: str = Field(
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$"
    )
    signed_document_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    commercial_snapshot_version: int = Field(ge=2, le=7)
    commercial_snapshot_status: Literal[
        "contract_order_reviewed",
        "subscription_active",
        "billing_proposed",
        "renewal_reviewed",
        "channel_attributed",
        "revops_handoff_ready",
    ]
    contract_ref: str = Field(min_length=1, max_length=200)
    order_ref: str = Field(min_length=1, max_length=200)
    customer_ref: str = Field(min_length=1, max_length=200)
    contract_status: Literal["executed", "active"]
    signature_status: Literal["completed"]
    amendment_pending: Literal[False] = False
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    contract_value: Decimal = Field(gt=0)
    order_line_refs: tuple[str, ...] = Field(min_length=1, max_length=5_000)
    agreement_evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=1,
        max_length=20,
    )

    @field_validator("contract_ref", "order_ref", "customer_ref")
    @classmethod
    def _portable_refs(cls, value: str) -> str:
        if not _PORTABLE_REF.fullmatch(value):
            raise ValueError("agreement references must be portable")
        return value

    @field_validator("agreement_connector_account_ref")
    @classmethod
    def _agreement_connector_ref(cls, value: str) -> str:
        if not _CONNECTOR_ACCOUNT_REF.fullmatch(value):
            raise ValueError("agreement_connector_account_ref must be portable")
        return value

    @field_validator("order_line_refs")
    @classmethod
    def _order_lines_unique(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)):
            raise ValueError("order_line_refs must be unique")
        if any(not _PORTABLE_REF.fullmatch(value) for value in values):
            raise ValueError("order_line_refs must be portable")
        return values

    @field_validator("contract_value", mode="before")
    @classmethod
    def _contract_money(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_MONEY_QUANTUM, label="contract_value")

    @model_validator(mode="after")
    def _agreement_is_executed(self) -> "ExecutedCommercialAgreementBinding":
        if self.commercial_snapshot_status not in _AGREEMENT_STATUSES:
            raise ValueError("commercial snapshot has not reached contract review")
        if (
            _AGREEMENT_STATUS_BY_VERSION[self.commercial_snapshot_version]
            != self.commercial_snapshot_status
        ):
            raise ValueError("commercial snapshot version and status must be exact")
        matching = [
            evidence
            for evidence in self.agreement_evidence_refs
            if evidence.kind == "contract_signature"
            and evidence.subject_ref == self.contract_ref
            and evidence.verification_grade
            == PrimitiveEvidenceVerificationGrade.VERIFIED
        ]
        if not matching:
            raise ValueError(
                "executed agreement requires independently verified contract_signature evidence"
            )
        if len({item.evidence_ref for item in self.agreement_evidence_refs}) != len(
            self.agreement_evidence_refs
        ):
            raise ValueError("agreement evidence references must be unique")
        return self


class AcceptedValueBinding(_StrictModel):
    schema_id: Literal["lightbulb.value_acceptance_binding.v1"] = Field(
        default=VALUE_ACCEPTANCE_BINDING_SCHEMA,
        alias="schema",
    )
    acceptance_ref: str = Field(min_length=1, max_length=200)
    contract_ref: str = Field(min_length=1, max_length=200)
    order_ref: str = Field(min_length=1, max_length=200)
    customer_ref: str = Field(min_length=1, max_length=200)
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    accepted_amount: Decimal = Field(gt=0)
    accepted_at: str
    accepted_by_ref: str = Field(min_length=1, max_length=200)
    independently_verified_by_ref: str = Field(min_length=1, max_length=200)
    acceptance_evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=1,
        max_length=20,
    )

    @field_validator(
        "acceptance_ref",
        "contract_ref",
        "order_ref",
        "customer_ref",
        "accepted_by_ref",
        "independently_verified_by_ref",
    )
    @classmethod
    def _portable_refs(cls, value: str) -> str:
        if not _PORTABLE_REF.fullmatch(value):
            raise ValueError("acceptance references must be portable")
        return value

    @field_validator("accepted_amount", mode="before")
    @classmethod
    def _accepted_money(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_MONEY_QUANTUM, label="accepted_amount")

    @field_validator("accepted_at")
    @classmethod
    def _accepted_at_utc(cls, value: str) -> str:
        return _utc_timestamp(value, field_name="accepted_at")

    @model_validator(mode="after")
    def _acceptance_is_independent(self) -> "AcceptedValueBinding":
        if self.accepted_by_ref == self.independently_verified_by_ref:
            raise ValueError("value acceptance and independent verification must differ")
        matching = [
            evidence
            for evidence in self.acceptance_evidence_refs
            if evidence.kind
            in {"independent_value_acceptance", "independent_evaluator_verdict"}
            and evidence.verification_grade
            == PrimitiveEvidenceVerificationGrade.VERIFIED
            and evidence.subject_ref == self.acceptance_ref
            and evidence.issuer_ref == self.independently_verified_by_ref
        ]
        if not matching:
            raise ValueError(
                "accepted value requires verified evidence bound to acceptance_ref"
            )
        if len({item.evidence_ref for item in self.acceptance_evidence_refs}) != len(
            self.acceptance_evidence_refs
        ):
            raise ValueError("acceptance evidence references must be unique")
        return self


class ContractToCashInvoiceLine(_StrictModel):
    order_line_ref: str = Field(min_length=1, max_length=200)
    provider_item_id: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1, max_length=500)
    quantity: Decimal = Field(gt=0)
    unit_amount: Decimal = Field(gt=0)
    line_total: Decimal = Field(gt=0)

    @field_validator("order_line_ref")
    @classmethod
    def _portable_order_line(cls, value: str) -> str:
        if not _PORTABLE_REF.fullmatch(value):
            raise ValueError("order_line_ref must be portable")
        return value

    @field_validator("provider_item_id")
    @classmethod
    def _provider_item_id(cls, value: str) -> str:
        if value != value.strip() or any(ord(character) < 33 for character in value):
            raise ValueError("provider_item_id must be a trimmed opaque provider reference")
        return value

    @field_validator("description")
    @classmethod
    def _bounded_description(cls, value: str) -> str:
        if value != value.strip() or any(ord(character) < 32 for character in value):
            raise ValueError("description must be trimmed printable text")
        return value

    @field_validator("quantity", mode="before")
    @classmethod
    def _quantity(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_QUANTITY_QUANTUM, label="quantity")

    @field_validator("unit_amount", "line_total", mode="before")
    @classmethod
    def _money(cls, value: Any, info: Any) -> Decimal:
        return _decimal(value, quantum=_MONEY_QUANTUM, label=info.field_name)

    @model_validator(mode="after")
    def _line_total_is_exact(self) -> "ContractToCashInvoiceLine":
        expected = (self.quantity * self.unit_amount).quantize(
            _MONEY_QUANTUM,
            rounding=ROUND_HALF_UP,
        )
        if expected != self.line_total:
            raise ValueError("line_total must equal quantity multiplied by unit_amount")
        return self


class ContractToCashInvoiceProposal(_StrictModel):
    provider: Literal["quickbooks"] = "quickbooks"
    connector_account_ref: str = Field(min_length=1, max_length=200)
    customer_id: str = Field(min_length=1, max_length=200)
    due_date: str
    memo: str = Field(default="", max_length=500)
    line_items: tuple[ContractToCashInvoiceLine, ...] = Field(
        min_length=1,
        max_length=100,
    )

    @field_validator("connector_account_ref")
    @classmethod
    def _connector_ref(cls, value: str) -> str:
        if not _CONNECTOR_ACCOUNT_REF.fullmatch(value):
            raise ValueError("connector_account_ref must be an opaque portable alias")
        return value

    @field_validator("customer_id")
    @classmethod
    def _customer_id(cls, value: str) -> str:
        if value != value.strip() or any(ord(character) < 33 for character in value):
            raise ValueError("customer_id must be a trimmed opaque provider reference")
        return value

    @field_validator("due_date")
    @classmethod
    def _due_date(cls, value: str) -> str:
        if not _CALENDAR_DATE.fullmatch(value):
            raise ValueError("due_date must be YYYY-MM-DD")
        try:
            parsed = date.fromisoformat(value)
        except ValueError as exc:
            raise ValueError("due_date must be YYYY-MM-DD") from exc
        if parsed.isoformat() != value:
            raise ValueError("due_date must be YYYY-MM-DD")
        return value

    @field_validator("memo")
    @classmethod
    def _memo(cls, value: str) -> str:
        if value != value.strip() or any(ord(character) < 32 for character in value):
            raise ValueError("memo must be trimmed printable text")
        return value

    @model_validator(mode="after")
    def _invoice_lines_unique(self) -> "ContractToCashInvoiceProposal":
        refs = [line.order_line_ref for line in self.line_items]
        if len(refs) != len(set(refs)):
            raise ValueError("invoice order_line_refs must be unique")
        return self


class ContractToCashContinuationInput(_StrictModel):
    schema_id: Literal["lightbulb.contract_to_cash_continuation_input.v1"] = Field(
        default=CONTRACT_TO_CASH_INPUT_SCHEMA,
        alias="schema",
    )
    agreement: ExecutedCommercialAgreementBinding
    accepted_value: AcceptedValueBinding
    invoice: ContractToCashInvoiceProposal

    @model_validator(mode="after")
    def _handoff_is_exact(self) -> "ContractToCashContinuationInput":
        agreement = self.agreement
        acceptance = self.accepted_value
        for label, left, right in (
            ("contract_ref", agreement.contract_ref, acceptance.contract_ref),
            ("order_ref", agreement.order_ref, acceptance.order_ref),
            ("customer_ref", agreement.customer_ref, acceptance.customer_ref),
            ("currency", agreement.currency, acceptance.currency),
        ):
            if left != right:
                raise ValueError(f"accepted value {label} does not match agreement")
        if acceptance.accepted_amount > agreement.contract_value:
            raise ValueError("accepted_amount cannot exceed contract_value")
        invoice_refs = {line.order_line_ref for line in self.invoice.line_items}
        if not invoice_refs.issubset(set(agreement.order_line_refs)):
            raise ValueError("invoice contains a line outside the executed order")
        invoice_total = sum(
            (line.line_total for line in self.invoice.line_items),
            Decimal("0.00"),
        ).quantize(_MONEY_QUANTUM)
        if invoice_total != acceptance.accepted_amount:
            raise ValueError("invoice total must equal independently accepted value")
        return self


class ContractToCashInvoiceAdmissionPayload(ContractToCashInvoiceProposal):
    """Exact provider-neutral invoice payload admitted to Spring's governed Tool seam."""

    reference: str = Field(pattern=r"^LB-CTC-[0-9A-F]{18}$")
    total: Decimal = Field(gt=0)

    @field_validator("total", mode="before")
    @classmethod
    def _total_money(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_MONEY_QUANTUM, label="total")

    @model_validator(mode="after")
    def _total_is_exact(self) -> "ContractToCashInvoiceAdmissionPayload":
        expected = sum(
            (line.line_total for line in self.line_items),
            Decimal("0.00"),
        ).quantize(_MONEY_QUANTUM)
        if expected != self.total:
            raise ValueError("invoice total must equal the exact sum of line_total")
        return self


class ContractToCashInvoiceAdmission(_StrictModel):
    schema_id: Literal["lightbulb.contract_to_cash_invoice_admission.v1"] = Field(
        default=CONTRACT_TO_CASH_INVOICE_ADMISSION_SCHEMA,
        alias="schema",
    )
    workflow_ref: Literal["finance.contract_to_cash_continuation"] = (
        CONTRACT_TO_CASH_WORKFLOW_REF
    )
    workflow_version: Literal["0.3.0"] = CONTRACT_TO_CASH_WORKFLOW_VERSION
    continuation_ref: str = Field(pattern=r"^ctc_[0-9a-f]{32}$")
    commercial_snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    agreement_custody_record_id: UUID
    agreement_custody_record_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    agreement_ref: str = Field(pattern=r"^agreement:docusign:[0-9a-f]{32}$")
    agreement_connector_account_ref: str = Field(
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$"
    )
    signed_document_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    contract_ref: str = Field(min_length=1, max_length=200)
    order_ref: str = Field(min_length=1, max_length=200)
    acceptance_ref: str = Field(min_length=1, max_length=200)
    customer_ref: str = Field(min_length=1, max_length=200)
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    invoice: ContractToCashInvoiceAdmissionPayload
    requested_effect: Literal["invoice_write_proposal"] = "invoice_write_proposal"
    approval_required: Literal[True] = True
    authoritative_write_authorized: Literal[False] = False
    admission_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def _admission_digest_is_exact(self) -> "ContractToCashInvoiceAdmission":
        payload = self.to_dict()
        supplied = payload.pop("admission_sha256")
        if _canonical_sha256(payload) != supplied:
            raise ValueError("admission_sha256 does not bind the exact admission")
        return self


class ContractToCashInvoiceProposalReceipt(_StrictModel):
    schema_id: Literal[
        "lightbulb.contract_to_cash_invoice_proposal_receipt.v1"
    ] = Field(default=CONTRACT_TO_CASH_INVOICE_PROPOSAL_RECEIPT_SCHEMA, alias="schema")
    workflow_ref: Literal["finance.contract_to_cash_continuation"] = (
        CONTRACT_TO_CASH_WORKFLOW_REF
    )
    workflow_version: Literal["0.3.0"] = CONTRACT_TO_CASH_WORKFLOW_VERSION
    continuation_ref: str = Field(pattern=r"^ctc_[0-9a-f]{32}$")
    admission_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    agreement_custody_record_id: UUID
    agreement_custody_record_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    agreement_ref: str = Field(pattern=r"^agreement:docusign:[0-9a-f]{32}$")
    state: Literal["approval_required"] = "approval_required"
    approval_ref: UUID
    approval_receipt_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    provider_reference: str = Field(pattern=r"^LB-CTC-[0-9A-F]{18}$")
    proposal_replayed: bool
    invoice_created: Literal[False] = False
    cash_collected: Literal[False] = False
    authoritative_write_authorized: Literal[False] = False
    authoritative_commercial_custody_verified: Literal[True] = True
    terminal_success: Literal[False] = False
    next_action: Literal["approve_exact_governed_connector_proposal"] = (
        "approve_exact_governed_connector_proposal"
    )


class ContractToCashInvoiceWriteReceipt(_StrictModel):
    schema_id: Literal[
        "lightbulb.contract_to_cash_invoice_write_receipt.v1"
    ] = Field(default=CONTRACT_TO_CASH_INVOICE_WRITE_RECEIPT_SCHEMA, alias="schema")
    workflow_ref: Literal["finance.contract_to_cash_continuation"] = (
        CONTRACT_TO_CASH_WORKFLOW_REF
    )
    workflow_version: Literal["0.3.0"] = CONTRACT_TO_CASH_WORKFLOW_VERSION
    continuation_ref: str = Field(pattern=r"^ctc_[0-9a-f]{32}$")
    admission_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    agreement_custody_record_id: UUID
    agreement_custody_record_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    agreement_ref: str = Field(pattern=r"^agreement:docusign:[0-9a-f]{32}$")
    expected_effect_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    provider_correlation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    approval_ref: UUID
    approval_receipt_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    write_journal_ref: UUID
    state: Literal[
        "awaiting_invoice_issued_observation",
        "invoice_write_outcome_ambiguous",
    ]
    approval_consumed: Literal[True] = True
    provider_dispatch_outcome: Literal["accepted", "unknown"]
    invoice_issued: Literal[False] = False
    cash_collected: Literal[False] = False
    authoritative_commercial_custody_verified: Literal[True] = True
    terminal_success: Literal[False] = False
    next_action: Literal["observe_exact_invoice_effect_without_redispatch"] = (
        "observe_exact_invoice_effect_without_redispatch"
    )

    @model_validator(mode="after")
    def _state_matches_provider_outcome(self) -> "ContractToCashInvoiceWriteReceipt":
        expected = (
            "unknown"
            if self.state == "invoice_write_outcome_ambiguous"
            else "accepted"
        )
        if self.provider_dispatch_outcome != expected:
            raise ValueError("invoice write state differs from provider dispatch outcome")
        return self


class ContractToCashInvoiceIssuedRegistration(_StrictModel):
    admission: ContractToCashInvoiceAdmission
    write_journal_id: UUID


class ContractToCashInvoiceIssuedRecord(_StrictModel):
    schema_id: Literal[
        "lightbulb.contract_to_cash_invoice_issued_record.v1"
    ] = Field(alias="schema")
    record_id: UUID
    tenant_id: UUID
    company_id: UUID
    project_id: UUID
    continuation_ref: str = Field(pattern=r"^ctc_[0-9a-f]{32}$")
    invoice_ref: str = Field(pattern=r"^invoice:quickbooks:[0-9a-f]{32}$")
    provider_reference: str = Field(pattern=r"^LB-CTC-[0-9A-F]{18}$")
    invoice_connector_account_ref: str = Field(
        min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$"
    )
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    invoice_total: Decimal = Field(gt=0)
    admission_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    agreement_custody_record_id: UUID
    agreement_custody_record_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    agreement_ref: str = Field(pattern=r"^agreement:docusign:[0-9a-f]{32}$")
    write_journal_id: UUID
    write_receipt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    observation_journal_id: UUID
    observation_receipt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reconciliation_receipt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    provider_correlation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    observed_issued_at: str
    record_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    registered_by_user_id: UUID
    audit_event_id: int = Field(ge=1)
    created_at: str
    invoice_issued: Literal[True]
    cash_collected: Literal[False]
    terminal_success: Literal[False]
    deployment_authorized: Literal[False]
    external_effect_authorized: Literal[False]

    @field_validator("observed_issued_at", "created_at")
    @classmethod
    def _issued_timestamps(cls, value: str, info: Any) -> str:
        return _utc_timestamp(value, field_name=info.field_name)


class ContractToCashCashCollectionRegistration(_StrictModel):
    invoice_record_id: UUID
    payment_observation_journal_id: UUID
    settlement_observation_journal_id: UUID


class ContractToCashCashCollectionRecord(_StrictModel):
    schema_id: Literal["lightbulb.contract_to_cash_collection_record.v1"] = Field(
        alias="schema"
    )
    record_id: UUID
    tenant_id: UUID
    company_id: UUID
    project_id: UUID
    invoice_record_id: UUID
    invoice_record_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    continuation_ref: str = Field(pattern=r"^ctc_[0-9a-f]{32}$")
    collection_ref: str = Field(pattern=r"^collection:stripe:[0-9a-f]{32}$")
    payment_observation_journal_id: UUID
    payment_observation_receipt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    payment_evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    settlement_observation_journal_id: UUID
    settlement_observation_receipt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    settlement_evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    settlement_connector_account_ref: str = Field(
        min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$"
    )
    collected_amount: Decimal = Field(gt=0)
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    reversal_window_days: int = Field(ge=1, le=180)
    payment_observed_at: str
    settlement_observed_at: str
    payout_arrival_at: str
    record_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    registered_by_user_id: UUID
    audit_event_id: int = Field(ge=1)
    created_at: str
    invoice_issued: Literal[True]
    payment_applied: Literal[True]
    cash_collected: Literal[True]
    terminal_success: Literal[True]
    deployment_authorized: Literal[False]
    external_effect_authorized: Literal[False]

    @field_validator(
        "payment_observed_at",
        "settlement_observed_at",
        "payout_arrival_at",
        "created_at",
    )
    @classmethod
    def _collection_timestamps(cls, value: str, info: Any) -> str:
        return _utc_timestamp(value, field_name=info.field_name)

    @model_validator(mode="after")
    def _settlement_sequence(self) -> "ContractToCashCashCollectionRecord":
        payment = _parse_utc_timestamp(self.payment_observed_at)
        settlement = _parse_utc_timestamp(self.settlement_observed_at)
        payout = _parse_utc_timestamp(self.payout_arrival_at)
        if payout > settlement or payment > settlement:
            raise ValueError("collected-cash evidence sequence is impossible")
        return self


class ContractToCashRunStart(_StrictModel):
    agreement_record_id: UUID
    idempotency_key: str = Field(min_length=1, max_length=500)
    model_execution_run_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=512,
        description="Ignored legacy correlation hint; Spring mints runtime authority.",
    )

    @field_validator("model_execution_run_id")
    @classmethod
    def _exact_legacy_model_hint(cls, value: str | None) -> str | None:
        if value is not None and (
            value != value.strip()
            or any(ord(character) < 32 for character in value)
        ):
            raise ValueError("model_execution_run_id must be exact")
        return value


class ContractToCashRunRecordBinding(_StrictModel):
    record_id: UUID


class ContractToCashRunCancellation(_StrictModel):
    reason: str = Field(min_length=1, max_length=500)


class ContractToCashRun(_StrictModel):
    schema_id: Literal["lightbulb.contract_to_cash_run.v1"] = Field(alias="schema")
    run_ref: str = Field(pattern=r"^ctr_[0-9a-f]{32}$")
    loop_ref: Literal["finance.contract_to_cash_collected_cash"]
    loop_version: Literal["0.1.0"]
    model_execution_run_id: str = Field(
        min_length=1,
        max_length=512,
        description=(
            "Spring-owned UUID on current runs; legacy terminal reads may retain an old hint."
        ),
    )
    tenant_id: UUID
    company_id: UUID
    project_id: UUID
    agreement_record_id: UUID
    agreement_record_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    agreement_ref: str = Field(pattern=r"^agreement:docusign:[0-9a-f]{32}$")
    continuation_ref: str = Field(pattern=r"^ctc_[0-9a-f]{32}$")
    invoice_record_id: UUID | None = None
    invoice_record_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    collection_record_id: UUID | None = None
    collection_record_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    state: Literal[
        "AGREEMENT_EFFECTIVE",
        "INVOICE_ISSUED",
        "CASH_COLLECTED",
        "CANCELLED_BEFORE_INVOICE",
        "RECONCILIATION_REQUIRED",
    ]
    revision: int = Field(ge=0)
    deadline_at: str
    invoice_issued: bool
    cash_collected: bool
    terminal_success: bool
    economic_closure: Literal["NOT_TERMINAL", "RECONCILIATION_REQUIRED"]
    deployment_authorized: Literal[False]
    external_effect_authorized: Literal[False]

    @field_validator("deadline_at")
    @classmethod
    def _deadline(cls, value: str) -> str:
        return _utc_timestamp(value, field_name="deadline_at")

    @field_validator("model_execution_run_id")
    @classmethod
    def _exact_model_execution_identity(cls, value: str) -> str:
        if value != value.strip() or any(ord(character) < 32 for character in value):
            raise ValueError("model_execution_run_id must be exact")
        return value

    @model_validator(mode="after")
    def _state_shape(self) -> "ContractToCashRun":
        has_invoice = self.invoice_record_id is not None
        has_cash = self.collection_record_id is not None
        if has_invoice != (self.invoice_record_digest is not None):
            raise ValueError("invoice custody id and digest must appear together")
        if has_cash != (self.collection_record_digest is not None):
            raise ValueError("cash custody id and digest must appear together")
        if self.invoice_issued != has_invoice:
            raise ValueError("invoice_issued differs from invoice custody")
        expected_cash = self.state == "CASH_COLLECTED"
        if self.cash_collected != expected_cash or self.terminal_success != expected_cash:
            raise ValueError("terminal success differs from collected-cash state")
        if has_cash and not has_invoice:
            raise ValueError("collected cash requires issued invoice custody")
        if self.state == "AGREEMENT_EFFECTIVE" and (has_invoice or has_cash):
            raise ValueError("agreement-effective state cannot contain later custody")
        if self.state == "INVOICE_ISSUED" and (not has_invoice or has_cash):
            raise ValueError("invoice-issued state has invalid custody")
        terminal = self.state in {
            "CASH_COLLECTED",
            "CANCELLED_BEFORE_INVOICE",
            "RECONCILIATION_REQUIRED",
        }
        if (
            not terminal
            and _MODEL_EXECUTION_RUN_ID.fullmatch(self.model_execution_run_id) is None
        ):
            raise ValueError(
                "nonterminal contract-to-cash runs require the retained model execution UUID"
            )
        if self.economic_closure != (
            "RECONCILIATION_REQUIRED" if terminal else "NOT_TERMINAL"
        ):
            raise ValueError("economic closure differs from terminal state")
        return self


class ContractToCashInvoiceProposalRequest(_StrictModel):
    """Exact SDK/API envelope for one Spring-owned invoice proposal."""

    workflow_instance_id: UUID
    workflow_step_generation: int = Field(ge=0)
    admission: ContractToCashInvoiceAdmission


class ContractToCashInvoiceExecutionRequest(ContractToCashInvoiceProposalRequest):
    """Approval-bound SDK/API envelope for the canonical governed write seam."""

    approval_ref: UUID
    approval_receipt_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class ContractToCashEffectBoundary(_StrictModel):
    schema_id: Literal["lightbulb.contract_to_cash_effect_boundary.v1"] = Field(
        default=CONTRACT_TO_CASH_EFFECT_BOUNDARY_SCHEMA,
        alias="schema",
    )
    live_systems_changed: Literal[False] = False
    approval_consumed: Literal[False] = False
    invoice_created: Literal[False] = False
    cash_collected: Literal[False] = False
    authoritative_write_authorized: Literal[False] = False
    spring_scope_verified: Literal[False] = False
    external_settlement_verified: Literal[False] = False


class CashSettlementEvidencePolicy(_StrictModel):
    schema_id: Literal[
        "lightbulb.contract_to_cash_settlement_evidence_policy.v1"
    ] = Field(
        default=CONTRACT_TO_CASH_SETTLEMENT_POLICY_SCHEMA,
        alias="schema",
    )
    required_kinds: tuple[
        Literal["provider_invoice_readback"],
        Literal["provider_payment_application"],
        Literal["cash_settlement_readback"],
    ] = _CASH_EVIDENCE_KINDS
    minimum_verification_grade: Literal["verified"] = "verified"
    minimum_independent_issuers: int = Field(default=2, ge=2, le=3)
    exact_invoice_ref_required: Literal[True] = True
    exact_contract_ref_required: Literal[True] = True
    exact_amount_and_currency_required: Literal[True] = True
    reversal_window_observed_required: Literal[True] = True
    provider_acceptance_alone_is_success: Literal[False] = False
    caller_reported_success_allowed: Literal[False] = False


class ContractToCashPrimitiveStep(_StrictModel):
    position: int = Field(ge=1, le=10)
    primitive_ref: Literal[
        "finance.create_invoice",
        "finance.observe_invoice_issued",
        "accounting.assess_receivables",
    ]
    primitive_version: Literal["1.0.0"] = "1.0.0"
    mode: Literal[
        "spring_approval_proposal",
        "governed_evidence_read",
        "deterministic_read_model",
    ]
    terminal_success_claim: Literal[False] = False


class ContractToCashContinuationPlan(_StrictModel):
    schema_id: Literal["lightbulb.contract_to_cash_continuation_plan.v1"] = Field(
        default=CONTRACT_TO_CASH_PLAN_SCHEMA,
        alias="schema",
    )
    workflow_ref: Literal["finance.contract_to_cash_continuation"] = (
        CONTRACT_TO_CASH_WORKFLOW_REF
    )
    workflow_version: Literal["0.3.0"] = CONTRACT_TO_CASH_WORKFLOW_VERSION
    continuation_ref: str = Field(pattern=r"^ctc_[0-9a-f]{32}$")
    plan_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    state: Literal["invoice_proposal_ready"] = (
        ContractToCashPlanState.INVOICE_PROPOSAL_READY.value
    )
    agreement: ExecutedCommercialAgreementBinding
    accepted_value: AcceptedValueBinding
    spring_invoice_admission: ContractToCashInvoiceAdmission
    primitive_steps: tuple[ContractToCashPrimitiveStep, ...]
    settlement_evidence_policy: CashSettlementEvidencePolicy
    effect_boundary: ContractToCashEffectBoundary
    known_blockers: tuple[str, ...]
    next_action: Literal["submit_to_spring_invoice_admission"] = (
        "submit_to_spring_invoice_admission"
    )

    @model_validator(mode="after")
    def _plan_is_default_failing(self) -> "ContractToCashContinuationPlan":
        expected_steps = (
            (1, "finance.create_invoice", "spring_approval_proposal"),
            (2, "finance.observe_invoice_issued", "governed_evidence_read"),
            (3, "accounting.assess_receivables", "deterministic_read_model"),
        )
        actual_steps = tuple(
            (step.position, step.primitive_ref, step.mode)
            for step in self.primitive_steps
        )
        if actual_steps != expected_steps:
            raise ValueError("contract-to-cash primitive sequence is not canonical")
        if not self.known_blockers:
            raise ValueError("candidate plan must retain unresolved Spring/evidence blockers")
        payload = self.to_dict()
        supplied = payload.pop("plan_sha256")
        if _canonical_sha256(payload) != supplied:
            raise ValueError("plan_sha256 does not bind the exact continuation plan")
        return self


def compile_contract_to_cash_continuation(
    value: ContractToCashContinuationInput | Mapping[str, Any],
) -> ContractToCashContinuationPlan:
    """Compile one exact proposal-only agreement-to-invoice continuation.

    The result never authorizes or reports an effect.  It gives Spring a stable,
    content-bound invoice admission and leaves cash success default-failing until
    independently verified settlement evidence exists.
    """

    payload = value.to_dict() if isinstance(value, ContractToCashContinuationInput) else value
    parsed = ContractToCashContinuationInput.model_validate(payload)
    identity_payload = {
        "schema": CONTRACT_TO_CASH_INPUT_SCHEMA,
        "agreement": parsed.agreement.to_dict(),
        "accepted_value": parsed.accepted_value.to_dict(),
        "invoice": parsed.invoice.to_dict(),
    }
    identity_digest = _canonical_sha256(identity_payload)
    continuation_ref = f"ctc_{identity_digest[:32]}"
    reference = _correlation_ref(continuation_ref)
    invoice_total = sum(
        (line.line_total for line in parsed.invoice.line_items),
        Decimal("0.00"),
    ).quantize(_MONEY_QUANTUM)
    invoice_payload = {
        "provider": "quickbooks",
        "connector_account_ref": parsed.invoice.connector_account_ref,
        "customer_id": parsed.invoice.customer_id,
        "due_date": parsed.invoice.due_date,
        "reference": reference,
        "memo": parsed.invoice.memo,
        "line_items": [
            {
                "order_line_ref": line.order_line_ref,
                "provider_item_id": line.provider_item_id,
                "description": line.description,
                "quantity": _quantity_text(line.quantity),
                "unit_amount": _money_text(line.unit_amount),
                "line_total": _money_text(line.line_total),
            }
            for line in parsed.invoice.line_items
        ],
        "total": _money_text(invoice_total),
    }
    admission_payload = {
        "schema": CONTRACT_TO_CASH_INVOICE_ADMISSION_SCHEMA,
        "workflow_ref": CONTRACT_TO_CASH_WORKFLOW_REF,
        "workflow_version": CONTRACT_TO_CASH_WORKFLOW_VERSION,
        "continuation_ref": continuation_ref,
        "commercial_snapshot_sha256": (
            parsed.agreement.commercial_snapshot_sha256
        ),
        "agreement_custody_record_id": str(
            parsed.agreement.agreement_custody_record_id
        ),
        "agreement_custody_record_digest": (
            parsed.agreement.agreement_custody_record_digest
        ),
        "agreement_ref": parsed.agreement.agreement_ref,
        "agreement_connector_account_ref": (
            parsed.agreement.agreement_connector_account_ref
        ),
        "signed_document_sha256": parsed.agreement.signed_document_sha256,
        "contract_ref": parsed.agreement.contract_ref,
        "order_ref": parsed.agreement.order_ref,
        "acceptance_ref": parsed.accepted_value.acceptance_ref,
        "customer_ref": parsed.agreement.customer_ref,
        "currency": parsed.agreement.currency,
        "invoice": invoice_payload,
        "requested_effect": "invoice_write_proposal",
        "approval_required": True,
        "authoritative_write_authorized": False,
    }
    admission_payload["admission_sha256"] = _canonical_sha256(admission_payload)
    plan_payload = {
        "schema": CONTRACT_TO_CASH_PLAN_SCHEMA,
        "workflow_ref": CONTRACT_TO_CASH_WORKFLOW_REF,
        "workflow_version": CONTRACT_TO_CASH_WORKFLOW_VERSION,
        "continuation_ref": continuation_ref,
        "plan_sha256": "0" * 64,
        "state": ContractToCashPlanState.INVOICE_PROPOSAL_READY.value,
        "agreement": parsed.agreement.to_dict(),
        "accepted_value": parsed.accepted_value.to_dict(),
        "spring_invoice_admission": admission_payload,
        "primitive_steps": [
            {
                "position": 1,
                "primitive_ref": "finance.create_invoice",
                "primitive_version": "1.0.0",
                "mode": "spring_approval_proposal",
                "terminal_success_claim": False,
            },
            {
                "position": 2,
                "primitive_ref": "finance.observe_invoice_issued",
                "primitive_version": "1.0.0",
                "mode": "governed_evidence_read",
                "terminal_success_claim": False,
            },
            {
                "position": 3,
                "primitive_ref": "accounting.assess_receivables",
                "primitive_version": "1.0.0",
                "mode": "deterministic_read_model",
                "terminal_success_claim": False,
            },
        ],
        "settlement_evidence_policy": CashSettlementEvidencePolicy().to_dict(),
        "effect_boundary": ContractToCashEffectBoundary().to_dict(),
        "known_blockers": [
            "Spring must resolve the referenced commercial snapshot from authoritative custody.",
            "The default-dark invoice write/readback pair still needs certified production routes and recovery-profile custody.",
            "Cash collection remains unproven until independent settlement and reversal-window evidence exists.",
        ],
        "next_action": "submit_to_spring_invoice_admission",
    }
    digest_payload = dict(plan_payload)
    digest_payload.pop("plan_sha256")
    plan_payload["plan_sha256"] = _canonical_sha256(digest_payload)
    return ContractToCashContinuationPlan.model_validate(plan_payload)


__all__ = [
    "CONTRACT_TO_CASH_EFFECT_BOUNDARY_SCHEMA",
    "CONTRACT_TO_CASH_INPUT_SCHEMA",
    "CONTRACT_TO_CASH_INVOICE_ADMISSION_SCHEMA",
    "CONTRACT_TO_CASH_INVOICE_PROPOSAL_RECEIPT_SCHEMA",
    "CONTRACT_TO_CASH_INVOICE_WRITE_RECEIPT_SCHEMA",
    "CONTRACT_TO_CASH_PLAN_SCHEMA",
    "CONTRACT_TO_CASH_SETTLEMENT_POLICY_SCHEMA",
    "CONTRACT_TO_CASH_WORKFLOW_REF",
    "CONTRACT_TO_CASH_WORKFLOW_VERSION",
    "CONTRACT_TO_CASH_INVOICE_ISSUED_RECORD_SCHEMA",
    "CONTRACT_TO_CASH_COLLECTION_RECORD_SCHEMA",
    "EXECUTED_AGREEMENT_BINDING_SCHEMA",
    "VALUE_ACCEPTANCE_BINDING_SCHEMA",
    "AcceptedValueBinding",
    "CashSettlementEvidencePolicy",
    "ContractToCashContinuationInput",
    "ContractToCashContinuationPlan",
    "ContractToCashEffectBoundary",
    "ContractToCashInvoiceAdmission",
    "ContractToCashInvoiceAdmissionPayload",
    "ContractToCashInvoiceLine",
    "ContractToCashInvoiceProposal",
    "ContractToCashInvoiceProposalRequest",
    "ContractToCashInvoiceProposalReceipt",
    "ContractToCashInvoiceExecutionRequest",
    "ContractToCashInvoiceWriteReceipt",
    "ContractToCashInvoiceIssuedRecord",
    "ContractToCashInvoiceIssuedRegistration",
    "ContractToCashCashCollectionRecord",
    "ContractToCashRun",
    "ContractToCashRunCancellation",
    "ContractToCashRunRecordBinding",
    "ContractToCashRunStart",
    "ContractToCashCashCollectionRegistration",
    "ContractToCashPlanState",
    "ContractToCashPrimitiveStep",
    "ExecutedCommercialAgreementBinding",
    "compile_contract_to_cash_continuation",
]
