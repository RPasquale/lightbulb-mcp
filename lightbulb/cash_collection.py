"""Governed collected-cash observation primitives.

These primitives never initiate or replay a payment. They request exact Spring-hosted
READ operations and accept only bounded QuickBooks payment-application and Stripe
paid-payout evidence. Spring owns scope, Tool Bindings, connector custody, journals,
and terminal collected-cash registration.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from decimal import Decimal
from typing import Annotated, Any, Literal, Mapping

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationInfo, field_validator, model_serializer, model_validator

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

QUICKBOOKS_INVOICE_PAYMENT_OBSERVATION_SCHEMA = (
    "lightbulb.quickbooks_invoice_payment_observation.v1"
)
STRIPE_CASH_SETTLEMENT_OBSERVATION_SCHEMA = (
    "lightbulb.stripe_cash_settlement_observation.v1"
)
QUICKBOOKS_OBSERVE_INVOICE_PAYMENT_TOOL = (
    "quickbooks.observe_invoice_payment_applied"
)
STRIPE_OBSERVE_CASH_SETTLEMENT_TOOL = "stripe.observe_cash_settlement"

Sha256Digest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
CorrelationRef = Annotated[
    str,
    StringConstraints(pattern=r"^LB-CTC-[0-9A-F]{18}$"),
]
ChargeRef = Annotated[str, StringConstraints(pattern=r"^ch_[A-Za-z0-9]{8,128}$")]
PayoutRef = Annotated[str, StringConstraints(pattern=r"^po_[A-Za-z0-9]{8,128}$")]
Currency = Annotated[str, StringConstraints(pattern=r"^[a-z]{3}$")]


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


def _utc_timestamp(value: str) -> str:
    if value != value.strip():
        raise ValueError("timestamp must not contain surrounding whitespace")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamp must be valid ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must include a UTC offset")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _stable_digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        ).encode("utf-8")
    ).hexdigest()


def _verify_native_evidence(value: Any, *, marker: str, other_variant: tuple[str, ...], required: tuple[str, ...]) -> Any:
    """Validate the Java observer's full commitment without inventing SDK fields."""
    raw = value.model_dump(mode="json", by_alias=True) if isinstance(value, BaseModel) else dict(value)
    if raw.get(marker) is None:
        return value
    if any(raw.get(key) is not None for key in other_variant):
        raise ValueError("native and SDK observation fields cannot be mixed")
    # Model-boundary revalidation can add absent optional fields as nulls.
    raw = {key: item for key, item in raw.items() if key not in other_variant}
    if any(key not in raw for key in required):
        raise ValueError("native observation must retain every provider field, including nulls")
    if raw.get("evidence_sha256") != _stable_digest({key: item for key, item in raw.items() if key not in ("evidence_sha256", "observed_at")}):
        raise ValueError("PROVIDER_EVIDENCE_MISMATCH: native evidence must commit every original observer field")
    return raw


class ObserveInvoicePaymentAppliedInput(_StrictModel):
    schema_id: Literal[
        "lightbulb.quickbooks_invoice_payment_observation_input.v1"
    ] = Field(
        default="lightbulb.quickbooks_invoice_payment_observation_input.v1",
        alias="schema",
    )
    correlation_ref: CorrelationRef


class QuickBooksInvoicePaymentObservation(_StrictModel):
    schema_id: Literal[
        "lightbulb.quickbooks_invoice_payment_observation.v1"
    ] = Field(default=QUICKBOOKS_INVOICE_PAYMENT_OBSERVATION_SCHEMA, alias="schema")
    disposition: Literal["APPLIED", "INCOMPLETE", "NOT_FOUND", "NON_UNIQUE", "PARTIAL", "UNPAID", "NON_EXHAUSTIVE"]
    provider_correlation_sha256: Sha256Digest
    invoice_query_sha256: Sha256Digest | None = None
    payment_query_sha256: Sha256Digest | None = None
    invoice_id_sha256: Sha256Digest | None = None
    invoice_total: Decimal | None = Field(default=None, ge=0)
    match_count: int | None = Field(default=None, ge=0, le=2)
    unique_match: bool | None = None
    query_sha256: Sha256Digest | None = None
    observed_effect_sha256: Sha256Digest | None = None
    currency: str | None = Field(default=None, pattern=r"^[A-Z]{3}$")
    applied_amount: Decimal = Field(ge=0)
    payment_count: int = Field(ge=0, le=1_000)
    exhaustive_read: bool
    invoice_balance_zero: bool
    evidence_sha256: Sha256Digest
    observed_at: str

    @model_validator(mode="before")
    @classmethod
    def _native_evidence(cls, value: Any) -> Any:
        raw = _verify_native_evidence(value, marker="query_sha256", other_variant=("invoice_query_sha256", "payment_query_sha256", "invoice_id_sha256"), required=("schema", "invoice_total", "match_count", "unique_match", "query_sha256", "observed_effect_sha256", "currency"))
        if isinstance(raw, Mapping) and raw.get("query_sha256") is not None:
            for key in ("applied_amount", "invoice_total"):
                amount = raw.get(key)
                if amount is not None and (not isinstance(amount, str) or re.fullmatch(r"(?:0|[1-9][0-9]*)\.[0-9]{2,}", amount) is None):
                    raise ValueError("native amounts must retain the provider's plain decimal strings")
        return raw

    @model_serializer(mode="wrap")
    def _serialize_variant(self, handler: Any) -> dict[str, Any]:
        result = handler(self)
        if self.query_sha256 is not None:
            # Java uses BigDecimal.toPlainString; Decimal's default can emit exponents.
            result["applied_amount"] = format(self.applied_amount, "f")
            result["invoice_total"] = None if self.invoice_total is None else format(self.invoice_total, "f")
            for key in ("invoice_query_sha256", "payment_query_sha256", "invoice_id_sha256"):
                result.pop(key, None)
            for key in ("invoice_total", "observed_effect_sha256", "currency"):
                if key not in result:
                    result[key] = None
        else:
            for key in ("invoice_total", "match_count", "unique_match", "query_sha256", "observed_effect_sha256"):
                result.pop(key, None)
        return result

    @field_validator("applied_amount", "invoice_total", mode="before")
    @classmethod
    def _decimal_amount(cls, value: Any) -> Decimal | None:
        if value is None:
            return None
        try:
            return Decimal(str(value))
        except Exception as exc:
            raise ValueError("applied_amount must be a finite decimal") from exc

    @field_validator("observed_at")
    @classmethod
    def _observed_at(cls, value: str, info: ValidationInfo) -> str:
        normalized = _utc_timestamp(value)
        return value if info.data.get("query_sha256") is not None else normalized

    @model_validator(mode="after")
    def _semantics_are_exact(self) -> "QuickBooksInvoicePaymentObservation":
        native = self.query_sha256 is not None
        if native:
            if self.disposition == "INCOMPLETE":
                raise ValueError("INCOMPLETE is not a native invoice disposition")
            if self.match_count is None or self.unique_match is None or self.unique_match != (self.match_count == 1):
                raise ValueError("native invoice evidence must retain exact unique-match counts")
            if self.disposition == "APPLIED" and not all((self.match_count == 1, self.unique_match, self.invoice_total is not None and self.invoice_total > 0, self.observed_effect_sha256, self.currency, self.applied_amount > 0, self.payment_count > 0, self.payment_count <= 10, self.exhaustive_read, self.invoice_balance_zero)):
                raise ValueError("APPLIED requires exhaustive full native invoice-payment evidence")
            if self.disposition == "APPLIED" and self.applied_amount < self.invoice_total:
                raise ValueError("APPLIED must settle the actual native invoice total")
            if self.disposition in {"NOT_FOUND", "NON_UNIQUE"} and any((self.invoice_total is not None, self.observed_effect_sha256, self.currency, self.applied_amount != 0, self.payment_count != 0, self.invoice_balance_zero)):
                raise ValueError("unresolved native invoice identity cannot claim payment")
            return self
        if self.disposition in {"PARTIAL", "UNPAID", "NON_EXHAUSTIVE"} or self.invoice_query_sha256 is None or any(value is not None for value in (self.invoice_total, self.match_count, self.unique_match, self.observed_effect_sha256)):
            raise ValueError("use one complete native or SDK invoice evidence shape")
        if self.disposition == "APPLIED":
            if not all(
                (
                    self.payment_query_sha256,
                    self.invoice_id_sha256,
                    self.currency,
                    self.applied_amount > 0,
                    self.payment_count > 0,
                    self.exhaustive_read,
                    self.invoice_balance_zero,
                )
            ):
                raise ValueError("APPLIED requires exhaustive full-payment evidence")
        elif self.disposition in {"NOT_FOUND", "NON_UNIQUE"}:
            if any(
                (
                    self.payment_query_sha256,
                    self.invoice_id_sha256,
                    self.currency,
                    self.applied_amount != 0,
                    self.payment_count != 0,
                    self.exhaustive_read,
                    self.invoice_balance_zero,
                )
            ):
                raise ValueError("unresolved invoice identity cannot claim payment evidence")
        return self


class ObserveCashSettlementInput(_StrictModel):
    schema_id: Literal[
        "lightbulb.stripe_cash_settlement_observation_input.v1"
    ] = Field(
        default="lightbulb.stripe_cash_settlement_observation_input.v1",
        alias="schema",
    )
    correlation_ref: CorrelationRef
    charge_id: ChargeRef
    payout_id: PayoutRef
    expected_amount_minor: int = Field(gt=0)
    expected_currency: Currency
    reversal_window_days: int = Field(ge=1, le=180)


class StripeCashSettlementObservation(_StrictModel):
    schema_id: Literal[
        "lightbulb.stripe_cash_settlement_observation.v1"
    ] = Field(default=STRIPE_CASH_SETTLEMENT_OBSERVATION_SCHEMA, alias="schema")
    disposition: Literal["SETTLED", "NOT_SETTLED", "NOT_FOUND", "NON_EXHAUSTIVE", "REVERSED", "PENDING"]
    invoice_correlation_sha256: Sha256Digest
    charge_id_sha256: Sha256Digest
    payout_id_sha256: Sha256Digest
    balance_transaction_id_sha256: Sha256Digest | None = None
    amount_minor: int = Field(gt=0)
    currency: Currency
    reversal_window_days: int = Field(ge=1, le=180)
    reversal_window_observed: bool
    exhaustive_read: bool
    charge_created_at: str | None = None
    payout_status: str | None = Field(default=None, min_length=1, max_length=40)
    query_sha256: Sha256Digest | None = None
    payout_arrival_at: str | None = None
    evidence_sha256: Sha256Digest
    observed_at: str

    @model_validator(mode="before")
    @classmethod
    def _native_evidence(cls, value: Any) -> Any:
        return _verify_native_evidence(value, marker="query_sha256", other_variant=("charge_created_at",), required=("schema", "payout_status", "query_sha256", "balance_transaction_id_sha256", "payout_arrival_at"))

    @model_serializer(mode="wrap")
    def _serialize_variant(self, handler: Any) -> dict[str, Any]:
        result = handler(self)
        if self.query_sha256 is not None:
            result.pop("charge_created_at", None)
            for key in ("balance_transaction_id_sha256", "payout_arrival_at"):
                if key not in result:
                    result[key] = None
        else:
            result.pop("payout_status", None)
            result.pop("query_sha256", None)
        return result

    @field_validator("charge_created_at", "payout_arrival_at", "observed_at")
    @classmethod
    def _timestamps(cls, value: str | None, info: ValidationInfo) -> str | None:
        if value is None:
            return None
        normalized = _utc_timestamp(value)
        return value if info.data.get("query_sha256") is not None else normalized

    @model_validator(mode="after")
    def _settlement_is_exact(self) -> "StripeCashSettlementObservation":
        native = self.query_sha256 is not None
        if (native and (self.payout_status is None or self.disposition == "NOT_SETTLED")) or (not native and (self.payout_status is not None or self.disposition not in {"SETTLED", "NOT_SETTLED"})):
            raise ValueError("use one complete native or SDK settlement evidence shape")
        if self.disposition == "SETTLED" and not all(
            (
                self.balance_transaction_id_sha256,
                self.reversal_window_observed,
                self.exhaustive_read,
                self.payout_status == "paid" if native else self.charge_created_at,
                self.payout_arrival_at,
            )
        ):
            raise ValueError("SETTLED requires exhaustive paid-payout evidence")
        if native and self.disposition == "SETTLED":
            arrival = datetime.fromisoformat(self.payout_arrival_at.replace("Z", "+00:00"))
            observed = datetime.fromisoformat(self.observed_at.replace("Z", "+00:00"))
            if (observed - arrival).total_seconds() < self.reversal_window_days * 86400:
                raise ValueError("SETTLED requires the actual reversal window after payout")
        return self


QUICKBOOKS_PAYMENT_OBSERVATION_OPERATION = PrimitiveOperationSpec(
    operation_ref="invoice.observe-payment-applied",
    tool=QUICKBOOKS_OBSERVE_INVOICE_PAYMENT_TOOL,
    effect=ConnectorEffect.READ,
    approval_required=False,
    replay_class=PrimitiveOperationReplayClass.SAFE,
    freshness_class=PrimitiveOperationFreshnessClass.CURRENT,
    recovery_policy=PrimitiveOperationRecoveryPolicy.RETRY,
)
STRIPE_SETTLEMENT_OBSERVATION_OPERATION = PrimitiveOperationSpec(
    operation_ref="cash.observe-paid-payout",
    tool=STRIPE_OBSERVE_CASH_SETTLEMENT_TOOL,
    effect=ConnectorEffect.READ,
    approval_required=False,
    replay_class=PrimitiveOperationReplayClass.SAFE,
    freshness_class=PrimitiveOperationFreshnessClass.CURRENT,
    recovery_policy=PrimitiveOperationRecoveryPolicy.RETRY,
)


class _ObservationError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _validate_provenance(
    provenance: ConnectorExecutionProvenance | None,
    request: ConnectorExecutionRequest,
) -> ConnectorExecutionProvenance:
    if provenance is None:
        raise _ObservationError(
            "cash_observation_provenance_missing",
            "The governed cash observation has no Spring provenance.",
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
        raise _ObservationError(
            "cash_observation_provenance_mismatch",
            "Cash observation provenance differs from the exact Spring READ request.",
        )
    return provenance


def _failed(
    *,
    primitive_ref: str,
    primitive_version: str,
    spec: PrimitiveOperationSpec,
    request_digest: str,
    blocker: PrimitiveBlocker,
    blocked: bool = False,
) -> PrimitiveExecutionResult[Any]:
    return PrimitiveExecutionResult(
        status=(PrimitiveExecutionStatus.BLOCKED if blocked else PrimitiveExecutionStatus.FAILED),
        primitive_ref=primitive_ref,
        primitive_version=primitive_version,
        summary=blocker.message,
        operation_receipts=[
            PrimitiveOperationReceipt(
                spec=spec,
                status=(PrimitiveOperationStatus.BLOCKED if blocked else PrimitiveOperationStatus.FAILED),
                request_digest=request_digest,
                error=blocker,
            )
        ],
        blockers=[blocker],
        connector_tool=spec.tool,
        retryable=blocker.retryable,
    )


class ObserveInvoicePaymentAppliedPrimitive(
    BusinessProcessPrimitive[
        ObserveInvoicePaymentAppliedInput,
        QuickBooksInvoicePaymentObservation,
    ]
):
    primitive_ref = "finance.observe_invoice_payment_applied"
    version = "1.0.0"
    title = "Observe full QuickBooks invoice payment application"
    description = "Verify one exact invoice is fully paid through bounded Spring READ evidence."
    input_model = ObserveInvoicePaymentAppliedInput
    output_model = QuickBooksInvoicePaymentObservation
    connector_tools = (QUICKBOOKS_OBSERVE_INVOICE_PAYMENT_TOOL,)
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
        inputs: ObserveInvoicePaymentAppliedInput,
    ) -> PrimitiveExecutionResult[QuickBooksInvoicePaymentObservation]:
        spec = QUICKBOOKS_PAYMENT_OBSERVATION_OPERATION
        arguments = {"correlation_ref": inputs.correlation_ref}
        return self._run(context, spec, arguments, inputs.correlation_ref)

    def _run(
        self,
        context: PrimitiveExecutionContext,
        spec: PrimitiveOperationSpec,
        arguments: dict[str, Any],
        correlation_ref: str,
    ) -> PrimitiveExecutionResult[QuickBooksInvoicePaymentObservation]:
        if context.preview_only:
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.PREVIEW,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary="Payment observation previewed; no provider read occurred.",
                operation_receipts=[PrimitiveOperationReceipt(
                    spec=spec,
                    status=PrimitiveOperationStatus.PLANNED,
                    request_digest=_stable_digest(arguments),
                )],
                connector_tool=spec.tool,
            )
        request = context.connector_request(
            primitive_ref=self.primitive_ref,
            tool=spec.tool,
            arguments=arguments,
            effect=ConnectorEffect.READ,
            approval_required=False,
            operation_ref=spec.operation_ref,
            metadata={"source": self.primitive_ref, "provider": "quickbooks"},
        )
        request_digest = request.custody_fingerprint()
        if context.scope.project_id is None or request.connector_account_ref is None:
            return _failed(
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                spec=spec,
                request_digest=request_digest,
                blocker=PrimitiveBlocker(
                    code="invoice_payment_observation_scope_required",
                    message="Exact project and QuickBooks connector-account scope are required.",
                ),
                blocked=True,
            )
        result = context.connectors.execute(request)
        if result.tool != request.tool or result.status != ConnectorExecutionStatus.COMPLETED:
            return _failed(
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                spec=spec,
                request_digest=request_digest,
                blocker=PrimitiveBlocker(
                    code="invoice_payment_observation_incomplete",
                    message="The governed QuickBooks payment observation did not complete.",
                    retryable=result.retryable and result.error_code != "GOVERNED_EXECUTION_AMBIGUOUS",
                ),
                blocked=result.status == ConnectorExecutionStatus.BLOCKED,
            )
        try:
            provenance = _validate_provenance(result.provenance, request)
            observation = QuickBooksInvoicePaymentObservation.model_validate(result.output)
            if observation.provider_correlation_sha256 != hashlib.sha256(
                correlation_ref.encode("utf-8")
            ).hexdigest():
                raise _ObservationError(
                    "invoice_payment_observation_correlation_mismatch",
                    "Payment observation is not bound to the requested invoice.",
                )
            if type(context.connectors) is not HostedConnectorExecutor:
                raise _ObservationError(
                    "cash_observation_authority_untrusted",
                    "Collected-cash evidence requires exact Spring-hosted provenance.",
                )
        except (ValueError, _ObservationError) as exc:
            return _failed(
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                spec=spec,
                request_digest=request_digest,
                blocker=PrimitiveBlocker(
                    code=(exc.code if isinstance(exc, _ObservationError) else "invoice_payment_observation_invalid"),
                    message=(exc.message if isinstance(exc, _ObservationError) else "Spring returned invalid payment evidence."),
                ),
            )
        receipt = PrimitiveOperationReceipt(
            spec=spec,
            status=PrimitiveOperationStatus.COMPLETED,
            request_digest=request_digest,
            provenance_receipt_digest=provenance.receipt_digest,
            external_refs={
                "execution_journal_ref": provenance.journal_ref,
                "evidence_sha256": observation.evidence_sha256,
                "provider_correlation_sha256": observation.provider_correlation_sha256,
            },
            replayed=result.cached,
        )
        if observation.disposition != "APPLIED":
            blocker = PrimitiveBlocker(
                code="invoice_payment_not_fully_applied",
                message="QuickBooks does not prove full invoice payment application.",
            )
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.BLOCKED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary=blocker.message,
                output=observation,
                evidence=[PrimitiveEvidence(
                    kind="governed_invoice_payment_observation",
                    summary="Spring returned bounded non-terminal invoice-payment evidence.",
                    labels=["quickbooks", observation.disposition.lower()],
                    refs={"evidence_sha256": observation.evidence_sha256},
                )],
                operation_receipts=[receipt],
                blockers=[blocker],
                connector_tool=spec.tool,
                retryable=False,
            )
        return PrimitiveExecutionResult(
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary="QuickBooks proves the exact invoice is fully paid.",
            output=observation,
            events=[PrimitiveEvent(
                type="finance.invoice_payment_applied_observed",
                payload={"evidence_sha256": observation.evidence_sha256},
            )],
            evidence=[PrimitiveEvidence(
                kind="governed_invoice_payment_observation",
                summary="Spring returned exhaustive invoice-payment READ evidence.",
                labels=["quickbooks", "applied"],
                refs={"evidence_sha256": observation.evidence_sha256},
            )],
            operation_receipts=[receipt],
            connector_tool=spec.tool,
        )


class ObserveCashSettlementPrimitive(
    BusinessProcessPrimitive[ObserveCashSettlementInput, StripeCashSettlementObservation]
):
    primitive_ref = "finance.observe_cash_settlement"
    version = "1.0.0"
    title = "Observe Stripe paid-payout cash settlement"
    description = "Verify exact charge-to-paid-payout settlement after its reversal window."
    input_model = ObserveCashSettlementInput
    output_model = StripeCashSettlementObservation
    connector_tools = (STRIPE_OBSERVE_CASH_SETTLEMENT_TOOL,)
    risk_level = "medium"
    approval_required = False
    example_inputs: Mapping[str, Any] = {
        "correlation_ref": "LB-CTC-7021C03052E6C40AEA",
        "charge_id": "ch_reference12345678",
        "payout_id": "po_reference12345678",
        "expected_amount_minor": 18000,
        "expected_currency": "usd",
        "reversal_window_days": 30,
    }
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = True

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: ObserveCashSettlementInput,
    ) -> PrimitiveExecutionResult[StripeCashSettlementObservation]:
        spec = STRIPE_SETTLEMENT_OBSERVATION_OPERATION
        arguments = inputs.model_dump(mode="json", by_alias=True, exclude={"schema_id"})
        if context.preview_only:
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.PREVIEW,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary="Cash settlement observation previewed; no provider read occurred.",
                operation_receipts=[PrimitiveOperationReceipt(
                    spec=spec,
                    status=PrimitiveOperationStatus.PLANNED,
                    request_digest=_stable_digest({**arguments, "charge_id": "private", "payout_id": "private"}),
                )],
                connector_tool=spec.tool,
            )
        request = context.connector_request(
            primitive_ref=self.primitive_ref,
            tool=spec.tool,
            arguments=arguments,
            effect=ConnectorEffect.READ,
            approval_required=False,
            operation_ref=spec.operation_ref,
            metadata={"source": self.primitive_ref, "provider": "stripe"},
        )
        request_digest = request.custody_fingerprint()
        if context.scope.project_id is None or request.connector_account_ref is None:
            return _failed(
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                spec=spec,
                request_digest=request_digest,
                blocker=PrimitiveBlocker(
                    code="cash_settlement_observation_scope_required",
                    message="Exact project and Stripe connector-account scope are required.",
                ),
                blocked=True,
            )
        result = context.connectors.execute(request)
        if result.tool != request.tool or result.status != ConnectorExecutionStatus.COMPLETED:
            return _failed(
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                spec=spec,
                request_digest=request_digest,
                blocker=PrimitiveBlocker(
                    code="cash_settlement_observation_incomplete",
                    message="The governed Stripe settlement observation did not complete.",
                    retryable=result.retryable and result.error_code != "GOVERNED_EXECUTION_AMBIGUOUS",
                ),
                blocked=result.status == ConnectorExecutionStatus.BLOCKED,
            )
        try:
            provenance = _validate_provenance(result.provenance, request)
            observation = StripeCashSettlementObservation.model_validate(result.output)
            if (
                observation.invoice_correlation_sha256
                != hashlib.sha256(inputs.correlation_ref.encode("utf-8")).hexdigest()
                or observation.charge_id_sha256
                != hashlib.sha256(inputs.charge_id.encode("utf-8")).hexdigest()
                or observation.payout_id_sha256
                != hashlib.sha256(inputs.payout_id.encode("utf-8")).hexdigest()
                or observation.amount_minor != inputs.expected_amount_minor
                or observation.currency != inputs.expected_currency
                or observation.reversal_window_days != inputs.reversal_window_days
            ):
                raise _ObservationError(
                    "cash_settlement_observation_binding_mismatch",
                    "Settlement evidence differs from the exact requested cash identity.",
                )
            if type(context.connectors) is not HostedConnectorExecutor:
                raise _ObservationError(
                    "cash_observation_authority_untrusted",
                    "Collected-cash evidence requires exact Spring-hosted provenance.",
                )
        except (ValueError, _ObservationError) as exc:
            return _failed(
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                spec=spec,
                request_digest=request_digest,
                blocker=PrimitiveBlocker(
                    code=(exc.code if isinstance(exc, _ObservationError) else "cash_settlement_observation_invalid"),
                    message=(exc.message if isinstance(exc, _ObservationError) else "Spring returned invalid settlement evidence."),
                ),
            )
        receipt = PrimitiveOperationReceipt(
            spec=spec,
            status=PrimitiveOperationStatus.COMPLETED,
            request_digest=request_digest,
            provenance_receipt_digest=provenance.receipt_digest,
            external_refs={
                "execution_journal_ref": provenance.journal_ref,
                "evidence_sha256": observation.evidence_sha256,
                "invoice_correlation_sha256": observation.invoice_correlation_sha256,
            },
            replayed=result.cached,
        )
        if observation.disposition != "SETTLED":
            blocker = PrimitiveBlocker(
                code="cash_not_settled",
                message="Stripe does not prove paid-payout settlement after the reversal window.",
            )
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.BLOCKED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary=blocker.message,
                output=observation,
                evidence=[PrimitiveEvidence(
                    kind="governed_cash_settlement_observation",
                    summary="Spring returned bounded non-terminal cash-settlement evidence.",
                    labels=["stripe", "not_settled"],
                    refs={"evidence_sha256": observation.evidence_sha256},
                )],
                operation_receipts=[receipt],
                blockers=[blocker],
                connector_tool=spec.tool,
                retryable=False,
            )
        return PrimitiveExecutionResult(
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary="Stripe proves the exact cash effect settled into a paid payout.",
            output=observation,
            events=[PrimitiveEvent(
                type="finance.cash_settlement_observed",
                payload={"evidence_sha256": observation.evidence_sha256},
            )],
            evidence=[PrimitiveEvidence(
                kind="governed_cash_settlement_observation",
                summary="Spring returned exact charge-to-paid-payout READ evidence.",
                labels=["stripe", "settled"],
                refs={"evidence_sha256": observation.evidence_sha256},
            )],
            operation_receipts=[receipt],
            connector_tool=spec.tool,
        )


CASH_COLLECTION_EXECUTABLE_PRIMITIVES: tuple[
    BusinessProcessPrimitive[Any, Any], ...
] = (
    ObserveInvoicePaymentAppliedPrimitive(),
    ObserveCashSettlementPrimitive(),
)

__all__ = [
    "CASH_COLLECTION_EXECUTABLE_PRIMITIVES",
    "ObserveCashSettlementInput",
    "ObserveCashSettlementPrimitive",
    "ObserveInvoicePaymentAppliedInput",
    "ObserveInvoicePaymentAppliedPrimitive",
    "QuickBooksInvoicePaymentObservation",
    "StripeCashSettlementObservation",
]
