"""Invoice health from exact governed reads, without payment or revenue effects.

The trusted host supplies the actual Connector Runtime request and response.
These contracts validate their correlation and retain the source for replay;
Spring and the authenticated host journal remain the execution and persistence
authorities. Invoice payment observations do not establish settled cash or a
causal benefit from retention work.
"""
from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
import re
from typing import Any, Literal, Mapping

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    CurrencyCode, GENESIS_DIGEST, OpaqueRef, Sha256Digest, StrictModel,
    detached, parsed, seal, sealed_digest, skip_digests, timestamp,
)
from lightbulb.company_execution_bridge import execution_receipt_from_connector
from lightbulb.connector_execution import ConnectorExecutionRequest, ConnectorExecutionResult

INVOICE_HEALTH_TOOL = "stripe.list_invoices"
MAX_INVOICES = 100
MAX_MINOR_AMOUNT = 100_000_000_000_000
SUPPORTED_AMOUNT_CURRENCIES = frozenset({"CAD", "USD", "EUR", "GBP", "AUD", "NZD"})


class BillingHealthError(ValueError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(f"{code}: {message}")


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise BillingHealthError(code, message)


def _minor(value: Any) -> int:
    _require(type(value) is int and 0 <= value <= MAX_MINOR_AMOUNT,
             "BILLING_AMOUNT_INVALID", "amounts must be bounded nonnegative integer minor units")
    return value


def minor_units_to_amount(value: int, currency: str) -> Decimal:
    """Convert only the explicitly supported two-decimal currencies; never infer FX."""
    _require(currency in SUPPORTED_AMOUNT_CURRENCIES, "BILLING_CURRENCY_UNSUPPORTED",
             "this currency has no supported minor-unit conversion")
    return (Decimal(_minor(value)) / Decimal(100)).quantize(Decimal("0.01"))


def _provider_time(value: Any, field: str) -> str:
    _require(type(value) is int and 0 <= value <= 253402300799,
             "BILLING_TIMESTAMP_INVALID", f"{field} must be an explicit Unix timestamp")
    return datetime.fromtimestamp(value, timezone.utc).isoformat().replace("+00:00", "Z")


class InvoiceHealthRow(StrictModel):
    invoice_ref: OpaqueRef
    account_ref: OpaqueRef
    currency: CurrencyCode
    status: Literal["draft", "open", "paid", "uncollectible", "void"]
    amount_due_minor: int = Field(ge=0, le=MAX_MINOR_AMOUNT)
    amount_paid_minor: int = Field(ge=0, le=MAX_MINOR_AMOUNT)
    amount_remaining_minor: int = Field(ge=0, le=MAX_MINOR_AMOUNT)
    created_at: str
    due_at: str | None = None
    paid_at: str | None = None

    @field_validator("created_at", "due_at", "paid_at")
    @classmethod
    def _times(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))

    def days_overdue(self, at: str) -> int | None:
        through = parsed(timestamp(at, field_name="at"))
        if (self.status != "open" or self.amount_remaining_minor == 0
                or self.due_at is None or parsed(self.due_at) >= through):
            return None
        return (through - parsed(self.due_at)).days


def _rows(request: ConnectorExecutionRequest, result: ConnectorExecutionResult,
          *, currency: str, now: str) -> tuple[InvoiceHealthRow, ...]:
    _require(request.tool == INVOICE_HEALTH_TOOL and request.effect.value == "read"
             and not request.preview_only, "BILLING_READ_REQUIRED", "invoice health requires the actual invoice read")
    _require(request.scope.project_id is not None and bool(request.connector_account_ref),
             "BILLING_SCOPE_REQUIRED", "invoice health requires an exact project and connector account")
    customer = request.arguments.get("customer_id")
    _require(set(request.arguments) == {"customer_id", "limit"}
             and isinstance(customer, str) and re.fullmatch(r"cus_[A-Za-z0-9]+", customer) is not None
             and type(request.arguments["limit"]) is int and request.arguments["limit"] == MAX_INVOICES,
             "BILLING_QUERY_INVALID", "read one exact customer with limit 100 and no status, date or cursor filters")
    receipt = execution_receipt_from_connector(result, request)
    _require(receipt.connector_account_ref == request.connector_account_ref
             and receipt.project_id == str(request.scope.project_id),
             "BILLING_SOURCE_MISMATCH", "the receipt must belong to the requested connector account and project")
    _require(receipt.receipt_digest != GENESIS_DIGEST and receipt.route_digest != GENESIS_DIGEST,
             "BILLING_SOURCE_UNSEALED", "the invoice read requires nonempty server receipt and route commitments")
    observed = parsed(receipt.completed_at)
    _require(observed <= parsed(timestamp(now, field_name="now")),
             "BILLING_SOURCE_FROM_FUTURE", "the invoice read must complete before it is consumed")
    output = result.output
    _require(output.get("object") == "list" and output.get("has_more") is False
             and isinstance(output.get("data"), (list, tuple)) and len(output["data"]) <= MAX_INVOICES,
             "BILLING_PAGE_INCOMPLETE", "invoice health requires a complete page of at most 100 invoices")
    allowed = {"id", "object", "customer", "currency", "status", "created", "amount_due",
               "amount_paid", "amount_remaining", "due_date", "status_transitions"}
    rows, seen = [], set()
    for raw in output["data"]:
        _require(isinstance(raw, Mapping) and set(raw) <= allowed,
                 "BILLING_ROW_INVALID", "invoice evidence must use the minimized invoice fields")
        ref = raw.get("id")
        _require(isinstance(ref, str) and re.fullmatch(r"in_[A-Za-z0-9]+", ref) is not None,
                 "BILLING_INVOICE_ID_INVALID", "each invoice needs its provider invoice identity")
        _require(ref not in seen, "BILLING_INVOICE_DUPLICATE", "an invoice may appear only once per complete observation")
        seen.add(ref)
        _require(raw.get("customer") == customer, "BILLING_CUSTOMER_MISMATCH",
                 "every invoice must belong to the exact requested customer")
        _require(isinstance(raw.get("currency"), str) and raw["currency"].upper() == currency,
                 "BILLING_CURRENCY_MISMATCH", "every invoice must use the requested currency")
        transitions = raw.get("status_transitions")
        _require(isinstance(transitions, Mapping) and set(transitions) <= {"paid_at"},
                 "BILLING_ROW_INVALID", "invoice status transitions must retain the minimized paid timestamp")
        created = _provider_time(raw.get("created"), "created")
        due = None if raw.get("due_date") is None else _provider_time(raw["due_date"], "due_date")
        paid = None if transitions.get("paid_at") is None else _provider_time(transitions["paid_at"], "paid_at")
        row = InvoiceHealthRow.model_validate({
            "invoice_ref": ref, "account_ref": customer, "currency": currency, "status": raw.get("status"),
            "amount_due_minor": _minor(raw.get("amount_due")),
            "amount_paid_minor": _minor(raw.get("amount_paid")),
            "amount_remaining_minor": _minor(raw.get("amount_remaining")),
            "created_at": created, "due_at": due, "paid_at": paid,
        })
        _require(parsed(created) <= observed and (paid is None or parsed(created) <= parsed(paid) <= observed),
                 "BILLING_FACT_FROM_FUTURE", "invoice creation and payment must precede the completed read")
        _require(due is None or parsed(due) >= parsed(created), "BILLING_TIMESTAMP_INVALID",
                 "an invoice due date cannot precede its creation")
        _require(row.amount_paid_minor <= row.amount_due_minor and row.amount_remaining_minor <= row.amount_due_minor,
                 "BILLING_AMOUNT_INCONSISTENT", "paid and remaining amounts cannot exceed the invoice amount due")
        _require(row.status != "paid" or (paid is not None and row.amount_remaining_minor == 0),
                 "BILLING_PAYMENT_INCOMPLETE", "a paid invoice requires its explicit payment time and zero remaining balance")
        rows.append(row)
    return tuple(sorted(rows, key=lambda row: row.invoice_ref))


class InvoiceHealthObservation(StrictModel):
    schema_id: Literal["lightbulb.invoice_health_observation.v1"] = Field(default="lightbulb.invoice_health_observation.v1", alias="schema")
    request: ConnectorExecutionRequest
    result: ConnectorExecutionResult
    currency: CurrencyCode
    observed_at: str
    rows: tuple[InvoiceHealthRow, ...] = Field(max_length=MAX_INVOICES)
    observation_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> InvoiceHealthObservation:
        expected = _rows(self.request, self.result, currency=self.currency, now=self.observed_at)
        _require(self.result.provenance is not None and self.observed_at == self.result.provenance.completed_at
                 and self.rows == expected, "BILLING_PROJECTION_MISMATCH",
                 "invoice rows and observation time must rederive from the retained exact response")
        if not skip_digests(info) and self.observation_digest != sealed_digest(type(self), self, "observation_digest"):
            raise BillingHealthError("BILLING_OBSERVATION_DIGEST_MISMATCH", "the observation digest must bind the complete source and projection")
        return self

    def row(self, invoice_ref: str) -> InvoiceHealthRow | None:
        return next((row for row in self.rows if row.invoice_ref == invoice_ref), None)

    @property
    def overdue_rows(self) -> tuple[InvoiceHealthRow, ...]:
        return tuple(row for row in self.rows if row.days_overdue(self.observed_at) is not None)


def invoice_health_observation(request: Any, result: Any, *, currency: str, now: str) -> InvoiceHealthObservation:
    request = ConnectorExecutionRequest.model_validate(detached(request))
    result = ConnectorExecutionResult.model_validate(detached(result))
    rows = _rows(request, result, currency=currency, now=now)
    return seal(InvoiceHealthObservation, {"request": request.to_dict(), "result": result.to_dict(),
        "currency": currency, "observed_at": result.provenance.completed_at,
        "rows": [row.to_dict() for row in rows]}, "observation_digest")


class InvoicePaymentChange(StrictModel):
    schema_id: Literal["lightbulb.invoice_payment_change.v1"] = Field(default="lightbulb.invoice_payment_change.v1", alias="schema")
    invoice_ref: OpaqueRef
    account_ref: OpaqueRef
    currency: CurrencyCode
    previous_observation_digest: Sha256Digest
    current_observation_digest: Sha256Digest
    risk_observed_at: str
    observed_at: str
    paid_at: str | None = None
    disposition: Literal["payment_observed", "not_observed", "not_paid", "no_new_payment", "payment_precedes_risk"]
    observed_payment_minor: int = Field(ge=0, le=MAX_MINOR_AMOUNT)
    revenue_verified: Literal[False] = False
    settlement_verified: Literal[False] = False


def _source(observation: InvoiceHealthObservation) -> tuple[Any, ...]:
    request, provenance = observation.request, observation.result.provenance
    return (request.scope.model_dump(mode="json"), request.connector_account_ref, request.arguments,
            observation.currency, str(provenance.tenant_connector_id), provenance.tool_version, provenance.route_digest)


def invoice_payment_change(previous: Any, current: Any, *, invoice_ref: str, risk_observed_at: str) -> InvoicePaymentChange:
    """Compare one invoice's observations; the host owns durable paid-amount deduplication."""
    before = InvoiceHealthObservation.model_validate(detached(previous))
    after = InvoiceHealthObservation.model_validate(detached(current))
    risk_at = timestamp(risk_observed_at, field_name="risk_observed_at")
    _require(_source(before) == _source(after), "BILLING_SOURCE_MISMATCH", "payment comparisons must retain the same scope, customer and connector route")
    _require(parsed(risk_at) <= parsed(before.observed_at) <= parsed(after.observed_at),
             "BILLING_OBSERVATION_STALE", "payment comparisons require monotonic observations after the recorded risk")
    prior, row = before.row(invoice_ref), after.row(invoice_ref)
    _require(prior is not None, "BILLING_INVOICE_MISSING", "the original observation must contain the tracked invoice")
    disposition, amount = "not_observed", 0
    if row is not None:
        _require(prior.account_ref == row.account_ref and prior.currency == row.currency
                 and prior.created_at == row.created_at and prior.amount_due_minor == row.amount_due_minor,
                 "BILLING_INVOICE_CHANGED", "payment comparisons must refer to the same unchanged invoice obligation")
        _require(row.amount_paid_minor >= prior.amount_paid_minor
                 and row.amount_remaining_minor <= prior.amount_remaining_minor,
                 "BILLING_AMOUNT_REGRESSED", "invoice amount regressions require reconciliation")
        _require(before.observed_at != after.observed_at or prior == row,
                 "BILLING_OBSERVATION_CONFLICT", "different invoice facts cannot share the same observation time")
        disposition = "not_paid"
        if row.status == "paid":
            disposition = "payment_precedes_risk" if parsed(row.paid_at) < parsed(risk_at) else "no_new_payment"
            if disposition == "no_new_payment" and row.amount_paid_minor > prior.amount_paid_minor:
                disposition, amount = "payment_observed", row.amount_paid_minor - prior.amount_paid_minor
    return InvoicePaymentChange(invoice_ref=invoice_ref, account_ref=prior.account_ref, currency=prior.currency,
        previous_observation_digest=before.observation_digest, current_observation_digest=after.observation_digest,
        risk_observed_at=risk_at, observed_at=after.observed_at, paid_at=None if row is None else row.paid_at,
        disposition=disposition, observed_payment_minor=amount)


__all__ = ["BillingHealthError", "InvoiceHealthRow", "InvoiceHealthObservation", "InvoicePaymentChange",
           "invoice_health_observation", "invoice_payment_change", "minor_units_to_amount"]
