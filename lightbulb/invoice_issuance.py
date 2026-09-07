"""Typed governed observation of a QuickBooks invoice issuance effect.

This primitive does not issue an invoice and cannot settle an ambiguous write.
It performs one exact Spring-hosted READ using the server-generated
contract-to-cash correlation and accepts only bounded, content-addressed
evidence. Spring remains authoritative for scope, Tool Binding, provider
custody, execution journaling, and any later reconciliation decision.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Annotated, Any, Literal, Mapping

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator, model_validator

from lightbulb.connector_execution import (
    ConnectorEffect,
    ConnectorExecutionProvenance,
    ConnectorExecutionRequest,
    ConnectorExecutionStatus,
    HostedConnectorExecutor,
)
from lightbulb.primitive_runtime import (
    BusinessProcessPrimitive,
    PrimitiveBlocker,
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


QUICKBOOKS_INVOICE_ISSUED_OBSERVATION_INPUT_SCHEMA = (
    "lightbulb.quickbooks_invoice_issued_observation_input.v1"
)
QUICKBOOKS_INVOICE_ISSUED_OBSERVATION_SCHEMA = (
    "lightbulb.quickbooks_invoice_issued_observation.v1"
)
QUICKBOOKS_OBSERVE_INVOICE_ISSUED_TOOL = "quickbooks.observe_invoice_issued"

Sha256Digest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
QuickBooksInvoiceCorrelationRef = Annotated[
    str,
    StringConstraints(pattern=r"^LB-CTC-[0-9A-F]{18}$"),
]


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        serialize_by_alias=True,
        strict=True,
    )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


class ObserveInvoiceIssuedInput(_StrictModel):
    schema_id: Literal[
        "lightbulb.quickbooks_invoice_issued_observation_input.v1"
    ] = Field(
        default=QUICKBOOKS_INVOICE_ISSUED_OBSERVATION_INPUT_SCHEMA,
        alias="schema",
    )
    correlation_ref: QuickBooksInvoiceCorrelationRef


class QuickBooksInvoiceIssuedObservation(_StrictModel):
    schema_id: Literal["lightbulb.quickbooks_invoice_issued_observation.v1"] = Field(
        default=QUICKBOOKS_INVOICE_ISSUED_OBSERVATION_SCHEMA,
        alias="schema",
    )
    disposition: Literal["APPLIED", "NOT_FOUND", "NON_UNIQUE"]
    match_count: int = Field(ge=0, le=2)
    unique_match: bool
    exhaustive_read: bool
    provider_correlation_sha256: Sha256Digest
    query_sha256: Sha256Digest
    evidence_sha256: Sha256Digest
    observed_effect_sha256: Sha256Digest | None = None
    observed_at: str

    @field_validator("observed_at")
    @classmethod
    def _timestamp(cls, value: str) -> str:
        if value != value.strip():
            raise ValueError("observed_at must not contain surrounding whitespace")
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("observed_at must be valid ISO-8601") from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("observed_at must include a UTC offset")
        return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    @model_validator(mode="after")
    def _disposition_has_exact_cardinality(self) -> "QuickBooksInvoiceIssuedObservation":
        if self.disposition == "APPLIED":
            if (
                self.match_count != 1
                or not self.unique_match
                or not self.exhaustive_read
                or self.observed_effect_sha256 is None
            ):
                raise ValueError(
                    "APPLIED requires one exhaustive unique match and an effect digest"
                )
        elif self.disposition == "NOT_FOUND":
            if (
                self.match_count != 0
                or self.unique_match
                or not self.exhaustive_read
                or self.observed_effect_sha256 is not None
            ):
                raise ValueError(
                    "NOT_FOUND requires an exhaustive empty result without an effect digest"
                )
        elif (
            self.match_count != 2
            or self.unique_match
            or self.observed_effect_sha256 is not None
        ):
            raise ValueError(
                "NON_UNIQUE requires the bounded two-or-more class without an effect digest"
            )
        return self


QUICKBOOKS_OBSERVE_INVOICE_ISSUED_OPERATION = PrimitiveOperationSpec(
    operation_ref="invoice.observe-issued",
    tool=QUICKBOOKS_OBSERVE_INVOICE_ISSUED_TOOL,
    effect=ConnectorEffect.READ,
    approval_required=False,
    replay_class=PrimitiveOperationReplayClass.SAFE,
    freshness_class=PrimitiveOperationFreshnessClass.CURRENT,
    recovery_policy=PrimitiveOperationRecoveryPolicy.RETRY,
)


class _InvoiceObservationError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _stable_digest(value: Any) -> str:
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _validate_provenance(
    provenance: ConnectorExecutionProvenance | None,
    request: ConnectorExecutionRequest,
) -> ConnectorExecutionProvenance:
    if provenance is None:
        raise _InvoiceObservationError(
            "invoice_observation_provenance_missing",
            "The governed invoice observation has no Spring provenance.",
        )
    if (
        provenance.tool != request.tool
        or provenance.server_effect != ConnectorEffect.READ
        or provenance.connector_account_ref != request.connector_account_ref
        or request.scope.project_id is None
        or provenance.project_id != request.scope.project_id
        or provenance.request_digest != request.custody_fingerprint()
        or provenance.approval_ref is not None
    ):
        raise _InvoiceObservationError(
            "invoice_observation_provenance_mismatch",
            "Invoice observation provenance does not match the exact Spring READ request.",
        )
    return provenance


def _failure_result(
    *,
    primitive_ref: str,
    primitive_version: str,
    spec: PrimitiveOperationSpec,
    request_digest: str,
    correlation_ref: str,
    blocker: PrimitiveBlocker,
    blocked: bool = False,
) -> PrimitiveExecutionResult[QuickBooksInvoiceIssuedObservation]:
    receipt = PrimitiveOperationReceipt(
        spec=spec,
        status=(
            PrimitiveOperationStatus.BLOCKED
            if blocked
            else PrimitiveOperationStatus.FAILED
        ),
        request_digest=request_digest,
        external_refs={"correlation_ref": correlation_ref},
        error=blocker,
    )
    return PrimitiveExecutionResult(
        status=(
            PrimitiveExecutionStatus.BLOCKED
            if blocked
            else PrimitiveExecutionStatus.FAILED
        ),
        primitive_ref=primitive_ref,
        primitive_version=primitive_version,
        summary=blocker.message,
        operation_receipts=[receipt],
        blockers=[blocker],
        connector_tool=spec.tool,
        retryable=blocker.retryable,
    )


class ObserveInvoiceIssuedPrimitive(
    BusinessProcessPrimitive[
        ObserveInvoiceIssuedInput,
        QuickBooksInvoiceIssuedObservation,
    ]
):
    primitive_ref = "finance.observe_invoice_issued"
    version = "1.0.0"
    title = "Observe issued QuickBooks invoice"
    description = (
        "Read one exact contract-to-cash invoice correlation through Spring and "
        "accept only a bounded, exhaustive issuance observation."
    )
    input_model = ObserveInvoiceIssuedInput
    output_model = QuickBooksInvoiceIssuedObservation
    connector_tools = (QUICKBOOKS_OBSERVE_INVOICE_ISSUED_TOOL,)
    risk_level = "medium"
    approval_required = False
    example_inputs: Mapping[str, Any] = {
        "correlation_ref": "LB-CTC-7021C03052E6C40AEA"
    }
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = True

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: ObserveInvoiceIssuedInput,
    ) -> PrimitiveExecutionResult[QuickBooksInvoiceIssuedObservation]:
        spec = QUICKBOOKS_OBSERVE_INVOICE_ISSUED_OPERATION
        if context.preview_only:
            receipt = PrimitiveOperationReceipt(
                spec=spec,
                status=PrimitiveOperationStatus.PLANNED,
                request_digest=_stable_digest(
                    {
                        "schema": "lightbulb.quickbooks_invoice_issued_observation_plan.v1",
                        "tool": spec.tool,
                        "correlation_ref": inputs.correlation_ref,
                        "requires_project_id": True,
                        "requires_connector_account_ref": True,
                    }
                ),
                external_refs={"correlation_ref": inputs.correlation_ref},
            )
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.PREVIEW,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary=(
                    "Invoice observation previewed; no connector read was requested "
                    "and no provider evidence was fabricated."
                ),
                operation_receipts=[receipt],
                connector_tool=spec.tool,
            )

        request = context.connector_request(
            primitive_ref=self.primitive_ref,
            tool=spec.tool,
            arguments={"correlation_ref": inputs.correlation_ref},
            effect=ConnectorEffect.READ,
            approval_required=False,
            operation_ref=spec.operation_ref,
            metadata={
                "source": self.primitive_ref,
                "provider": "quickbooks",
                "correlation_ref": inputs.correlation_ref,
            },
        )
        request_digest = request.custody_fingerprint()
        if context.scope.project_id is None or request.connector_account_ref is None:
            return _failure_result(
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                spec=spec,
                request_digest=request_digest,
                correlation_ref=inputs.correlation_ref,
                blocker=PrimitiveBlocker(
                    code="invoice_observation_scope_required",
                    message=(
                        "Governed invoice observation requires an authenticated project UUID "
                        "and exact QuickBooks connector-account binding."
                    ),
                ),
                blocked=True,
            )

        result = context.connectors.execute(request)
        if result.tool != request.tool:
            return _failure_result(
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                spec=spec,
                request_digest=request_digest,
                correlation_ref=inputs.correlation_ref,
                blocker=PrimitiveBlocker(
                    code="invoice_observation_tool_mismatch",
                    message="The observer response is not bound to the exact QuickBooks Tool.",
                ),
            )
        if result.status != ConnectorExecutionStatus.COMPLETED:
            blocked = result.status == ConnectorExecutionStatus.BLOCKED
            retryable = (
                result.retryable
                and result.error_code != "GOVERNED_EXECUTION_AMBIGUOUS"
            )
            return _failure_result(
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                spec=spec,
                request_digest=request_digest,
                correlation_ref=inputs.correlation_ref,
                blocker=PrimitiveBlocker(
                    code=(
                        "invoice_observation_blocked"
                        if blocked
                        else "invoice_observation_failed"
                    ),
                    message="The governed QuickBooks invoice observation did not complete.",
                    retryable=retryable,
                ),
                blocked=blocked,
            )

        try:
            provenance = _validate_provenance(result.provenance, request)
            observation = QuickBooksInvoiceIssuedObservation.model_validate(result.output)
            expected_correlation_digest = hashlib.sha256(
                inputs.correlation_ref.encode("utf-8")
            ).hexdigest()
            if observation.provider_correlation_sha256 != expected_correlation_digest:
                raise _InvoiceObservationError(
                    "invoice_observation_correlation_mismatch",
                    "The observation is not bound to the requested invoice correlation.",
                )
            if type(context.connectors) is not HostedConnectorExecutor:
                raise _InvoiceObservationError(
                    "invoice_observation_authority_untrusted",
                    "Invoice observation requires exact Spring-hosted READ provenance.",
                )
        except (ValueError, _InvoiceObservationError) as exc:
            return _failure_result(
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                spec=spec,
                request_digest=request_digest,
                correlation_ref=inputs.correlation_ref,
                blocker=PrimitiveBlocker(
                    code=(
                        exc.code
                        if isinstance(exc, _InvoiceObservationError)
                        else "invoice_observation_evidence_invalid"
                    ),
                    message=(
                        exc.message
                        if isinstance(exc, _InvoiceObservationError)
                        else "Spring returned invalid invoice observation evidence."
                    ),
                ),
            )

        external_refs = {
            "execution_journal_ref": provenance.journal_ref,
            "correlation_ref": inputs.correlation_ref,
            "provider_correlation_sha256": observation.provider_correlation_sha256,
            "query_sha256": observation.query_sha256,
            "evidence_sha256": observation.evidence_sha256,
            **(
                {"observed_effect_sha256": observation.observed_effect_sha256}
                if observation.observed_effect_sha256 is not None
                else {}
            ),
        }
        receipt = PrimitiveOperationReceipt(
            spec=spec,
            status=PrimitiveOperationStatus.COMPLETED,
            request_digest=request_digest,
            provenance_receipt_digest=provenance.receipt_digest,
            external_refs=external_refs,
            replayed=result.cached,
        )
        uniquely_applied = observation.disposition == "APPLIED"
        blocker = (
            None
            if uniquely_applied
            else PrimitiveBlocker(
                code=(
                    "invoice_observation_not_found"
                    if observation.disposition == "NOT_FOUND"
                    else "invoice_observation_non_unique"
                ),
                message=(
                    "The deterministic QuickBooks invoice correlation was not found."
                    if observation.disposition == "NOT_FOUND"
                    else "The deterministic QuickBooks invoice correlation is not unique."
                ),
            )
        )
        return PrimitiveExecutionResult(
            status=(
                PrimitiveExecutionStatus.COMPLETED
                if uniquely_applied
                else PrimitiveExecutionStatus.BLOCKED
            ),
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                "QuickBooks uniquely confirmed the issued invoice effect."
                if uniquely_applied
                else blocker.message
            ),
            output=observation,
            events=[
                PrimitiveEvent(
                    type="finance.invoice_issued_observed",
                    payload={
                        "correlation_ref": inputs.correlation_ref,
                        "disposition": observation.disposition,
                        "evidence_sha256": observation.evidence_sha256,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="governed_invoice_issued_observation",
                    summary=(
                        "Spring returned exact QuickBooks READ provenance and bounded "
                        "invoice-effect evidence."
                    ),
                    labels=["quickbooks", observation.disposition.lower()],
                    refs={
                        "correlation_ref": inputs.correlation_ref,
                        "evidence_sha256": observation.evidence_sha256,
                        "provenance_receipt_digest": provenance.receipt_digest,
                    },
                )
            ],
            operation_receipts=[receipt],
            blockers=[] if blocker is None else [blocker],
            connector_tool=spec.tool,
            retryable=False,
        )


INVOICE_ISSUANCE_EXECUTABLE_PRIMITIVES: tuple[
    BusinessProcessPrimitive[Any, Any], ...
] = (ObserveInvoiceIssuedPrimitive(),)


__all__ = [
    "INVOICE_ISSUANCE_EXECUTABLE_PRIMITIVES",
    "ObserveInvoiceIssuedInput",
    "ObserveInvoiceIssuedPrimitive",
    "QUICKBOOKS_INVOICE_ISSUED_OBSERVATION_INPUT_SCHEMA",
    "QUICKBOOKS_INVOICE_ISSUED_OBSERVATION_SCHEMA",
    "QUICKBOOKS_OBSERVE_INVOICE_ISSUED_OPERATION",
    "QUICKBOOKS_OBSERVE_INVOICE_ISSUED_TOOL",
    "QuickBooksInvoiceCorrelationRef",
    "QuickBooksInvoiceIssuedObservation",
]
