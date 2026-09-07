"""Typed SDK contract for Spring-authoritative Stripe/ledger reconciliation.

This module deliberately does not reconcile invoices or perform I/O.  It
validates the bounded request accepted by Spring's finance reconciliation
endpoint and parses the endpoint's normalized response without becoming a
second matching or authority implementation.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from lightbulb.primitive_runtime import (
    detach_model_boundary_value,
    revalidate_model_boundary,
)


FINANCE_RECONCILIATION_REQUEST_SCHEMA = "lightbulb.finance_reconciliation_request.v1"
FINANCE_RECONCILIATION_RESULT_SCHEMA = "lightbulb.finance_reconciliation_result.v1"
FINANCE_RECONCILIATION_RUN_SUMMARY_SCHEMA = (
    "lightbulb.finance_reconciliation_run_summary.v1"
)
FINANCE_RECONCILIATION_RUN_DETAILS_SCHEMA = (
    "lightbulb.finance_reconciliation_run_details.v1"
)

DEFAULT_STRIPE_LIMIT = 100
MAX_STRIPE_LIMIT = 100
DEFAULT_LEDGER_LIMIT = 200
MAX_LEDGER_LIMIT = 1_000
DEFAULT_AMOUNT_TOLERANCE = Decimal("0.01")

_ZERO_DIGEST = "0" * 64
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_JAVA_INTEGER_MIN = -(2**31)
_JAVA_INTEGER_MAX = 2**31 - 1

LedgerProviderRequest = Literal["auto", "quickbooks", "xero"]
LedgerProvider = Literal["quickbooks", "xero"]
SimulationMode = Literal["auto", "simulation", "live"]
ReconciliationStatus = Literal["completed", "failed"]
AuthorityLevel = Literal[
    "authoritative", "controlled_partial", "scenario_grade", "blocked"
]
ServerAuthoritativeness = Literal[
    "authoritative",
    "controlled_partial",
    "scenario_grade",
    "blocked",
    "governed",
    "bounded",
]

BoundedText = Annotated[str, StringConstraints(max_length=1_000)]
ShortText = Annotated[str, StringConstraints(max_length=300)]
ProviderReference = Annotated[str, StringConstraints(max_length=500)]
DateText = Annotated[str, StringConstraints(max_length=100)]


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        revalidate_instances="always",
        serialize_by_alias=True,
        strict=True,
    )


def _finite_decimal(value: Any, *, non_negative: bool = False) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (str, int, float, Decimal)):
        raise ValueError("decimal values must be supplied as strings or JSON numbers")
    lexical = str(value)
    if lexical != lexical.strip() or len(lexical) > 64:
        raise ValueError("value must use bounded decimal notation")
    try:
        parsed = Decimal(lexical)
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("value must be a finite decimal") from exc
    if not parsed.is_finite():
        raise ValueError("value must be a finite decimal")
    if non_negative and parsed < 0:
        raise ValueError("value must be non-negative")
    return parsed


def _as_tuple(value: Any) -> Any:
    if isinstance(value, list):
        return tuple(value)
    return value


def _utc_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("generated_at must be valid ISO-8601") from exc
    else:
        raise ValueError("generated_at must be an ISO-8601 string or datetime")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("generated_at must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def _uuid_or_none(value: Any) -> UUID | None:
    if value is None or isinstance(value, UUID):
        return value
    if isinstance(value, str):
        try:
            return UUID(value)
        except ValueError as exc:
            raise ValueError("run_id must be a UUID") from exc
    raise ValueError("run_id must be a UUID")


def _stable_digest(value: Any) -> str:
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class FinanceReconciliationRequest(_StrictModel):
    """Semantic request; the builder maps it to Spring's nullable booleans."""

    schema_id: Literal["lightbulb.finance_reconciliation_request.v1"] = Field(
        default=FINANCE_RECONCILIATION_REQUEST_SCHEMA,
        alias="schema",
    )
    ledger_provider: LedgerProviderRequest = "auto"
    stripe_limit: int = Field(
        default=DEFAULT_STRIPE_LIMIT,
        ge=1,
        le=MAX_STRIPE_LIMIT,
    )
    ledger_limit: int = Field(
        default=DEFAULT_LEDGER_LIMIT,
        ge=1,
        le=MAX_LEDGER_LIMIT,
    )
    amount_tolerance: Decimal = Field(default=DEFAULT_AMOUNT_TOLERANCE, ge=0)
    include_details: bool = True
    simulation_mode: SimulationMode = "auto"
    simulation_seed: int | None = Field(
        default=None,
        ge=_JAVA_INTEGER_MIN,
        le=_JAVA_INTEGER_MAX,
    )

    @field_validator("amount_tolerance", mode="before")
    @classmethod
    def _amount_tolerance_decimal(cls, value: Any) -> Decimal:
        return _finite_decimal(value, non_negative=True)

    @model_validator(mode="after")
    def _seed_requires_forced_simulation(self) -> "FinanceReconciliationRequest":
        if self.simulation_seed is not None and self.simulation_mode != "simulation":
            raise ValueError(
                "simulation_seed is permitted only when simulation_mode='simulation'"
            )
        return self


class FinanceReconciliationParameters(_StrictModel):
    amount_tolerance: Decimal = Field(ge=0)
    include_details: bool
    simulate_mode: bool
    simulate_requested: bool

    @field_validator("amount_tolerance", mode="before")
    @classmethod
    def _amount_tolerance_decimal(cls, value: Any) -> Decimal:
        return _finite_decimal(value, non_negative=True)


class FinanceReconciliationCoverage(_StrictModel):
    stripe_invoice_count: int = Field(ge=0, le=MAX_STRIPE_LIMIT)
    ledger_invoice_count: int = Field(ge=0, le=MAX_LEDGER_LIMIT)
    matched_count: int = Field(ge=0, le=MAX_STRIPE_LIMIT)
    unmatched_stripe_count: int = Field(ge=0, le=MAX_STRIPE_LIMIT)
    unmatched_ledger_count: int = Field(ge=0, le=MAX_LEDGER_LIMIT)

    @model_validator(mode="after")
    def _counts_fit_source_windows(self) -> "FinanceReconciliationCoverage":
        if self.matched_count > self.stripe_invoice_count:
            raise ValueError("matched_count cannot exceed stripe_invoice_count")
        if self.matched_count > self.ledger_invoice_count:
            raise ValueError("matched_count cannot exceed ledger_invoice_count")
        if self.unmatched_stripe_count > self.stripe_invoice_count:
            raise ValueError(
                "unmatched_stripe_count cannot exceed stripe_invoice_count"
            )
        if self.unmatched_ledger_count > self.ledger_invoice_count:
            raise ValueError(
                "unmatched_ledger_count cannot exceed ledger_invoice_count"
            )
        if (
            self.matched_count + self.unmatched_stripe_count
            != self.stripe_invoice_count
        ):
            raise ValueError(
                "matched_count plus unmatched_stripe_count must equal stripe_invoice_count"
            )
        if (
            self.matched_count + self.unmatched_ledger_count
            != self.ledger_invoice_count
        ):
            raise ValueError(
                "matched_count plus unmatched_ledger_count must equal ledger_invoice_count"
            )
        return self


class FinanceReconciliationTotals(_StrictModel):
    stripe_total: Decimal
    ledger_total: Decimal
    stripe_paid_total: Decimal
    ledger_paid_total: Decimal
    gross_delta: Decimal
    paid_delta: Decimal

    @field_validator(
        "stripe_total",
        "ledger_total",
        "stripe_paid_total",
        "ledger_paid_total",
        "gross_delta",
        "paid_delta",
        mode="before",
    )
    @classmethod
    def _amount_decimal(cls, value: Any) -> Decimal:
        return _finite_decimal(value)

    @model_validator(mode="after")
    def _deltas_match_totals(self) -> "FinanceReconciliationTotals":
        if self.gross_delta != self.stripe_total - self.ledger_total:
            raise ValueError("gross_delta must equal stripe_total minus ledger_total")
        if self.paid_delta != self.stripe_paid_total - self.ledger_paid_total:
            raise ValueError(
                "paid_delta must equal stripe_paid_total minus ledger_paid_total"
            )
        return self


class FinanceReconciliationControlSummary(_StrictModel):
    match_rate: Decimal = Field(ge=0, le=1)
    amount_mismatch_count: int = Field(ge=0, le=MAX_STRIPE_LIMIT)
    status_mismatch_count: int = Field(ge=0, le=MAX_STRIPE_LIMIT)

    @field_validator("match_rate", mode="before")
    @classmethod
    def _match_rate_decimal(cls, value: Any) -> Decimal:
        return _finite_decimal(value, non_negative=True)


class FinanceReconciliationInvoice(_StrictModel):
    provider: Literal["stripe", "quickbooks", "xero"]
    invoice_id: ProviderReference | None = None
    invoice_number: ProviderReference | None = None
    customer_ref: ProviderReference | None = None
    customer_name: ProviderReference | None = None
    status: ShortText | None = None
    total: Decimal
    paid: Decimal
    balance: Decimal
    currency: Annotated[str, StringConstraints(max_length=16)] | None = None
    issued_at: DateText | None = None
    due_at: DateText | None = None

    @field_validator("total", "paid", "balance", mode="before")
    @classmethod
    def _amount_decimal(cls, value: Any) -> Decimal:
        return _finite_decimal(value)


class FinanceReconciliationMatch(_StrictModel):
    match_basis: Literal["invoice_number", "amount_date"]
    stripe_invoice: FinanceReconciliationInvoice
    ledger_invoice: FinanceReconciliationInvoice
    delta_total: Decimal
    delta_paid: Decimal
    delta_balance: Decimal
    stripe_status: ShortText
    ledger_status: ShortText
    amount_mismatch: bool
    status_mismatch: bool

    @field_validator("delta_total", "delta_paid", "delta_balance", mode="before")
    @classmethod
    def _delta_decimal(cls, value: Any) -> Decimal:
        return _finite_decimal(value)


class FinanceReconciliationExceptions(_StrictModel):
    missing_in_ledger: tuple[FinanceReconciliationInvoice, ...] = Field(
        default_factory=tuple,
        max_length=MAX_STRIPE_LIMIT,
    )
    missing_in_stripe: tuple[FinanceReconciliationInvoice, ...] = Field(
        default_factory=tuple,
        max_length=MAX_LEDGER_LIMIT,
    )
    amount_mismatches: tuple[FinanceReconciliationMatch, ...] = Field(
        default_factory=tuple,
        max_length=MAX_STRIPE_LIMIT,
    )
    status_mismatches: tuple[FinanceReconciliationMatch, ...] = Field(
        default_factory=tuple,
        max_length=MAX_STRIPE_LIMIT,
    )

    @field_validator(
        "missing_in_ledger",
        "missing_in_stripe",
        "amount_mismatches",
        "status_mismatches",
        mode="before",
    )
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)


class FinanceReconciliationProposedAction(_StrictModel):
    priority: Literal["high", "medium", "low"]
    action: Annotated[str, StringConstraints(min_length=1, max_length=160)]
    count: int = Field(ge=0, le=MAX_LEDGER_LIMIT)
    description: BoundedText


class FinanceReconciliationResult(_StrictModel):
    """A parsed Spring result with an SDK-derived, non-inflating authority label.

    ``response_digest`` excludes only ``run_id``, ``generated_at``, and the
    digest field itself.  Retries of the same business response therefore have
    the same digest even when Spring assigns a different run envelope or clock
    value; all parameters, counts, totals, details, simulation evidence, and
    authority fields remain committed by the digest.
    """

    schema_id: Literal["lightbulb.finance_reconciliation_result.v1"] = Field(
        default=FINANCE_RECONCILIATION_RESULT_SCHEMA,
        alias="schema",
    )
    run_id: UUID | None = None
    status: Literal["completed"]
    generated_at: datetime
    workflow: Literal["stripe_ledger_reconciliation"]
    ledger_provider: LedgerProvider
    parameters: FinanceReconciliationParameters
    simulation_mode: bool
    simulation_reason: BoundedText | None = None
    warning: BoundedText | None = None
    coverage: FinanceReconciliationCoverage
    totals: FinanceReconciliationTotals
    reconciliation: FinanceReconciliationControlSummary
    exceptions: FinanceReconciliationExceptions
    matches: tuple[FinanceReconciliationMatch, ...] = Field(
        max_length=MAX_STRIPE_LIMIT,
    )
    proposed_actions: tuple[FinanceReconciliationProposedAction, ...] = Field(
        min_length=1,
        max_length=5,
    )
    server_authoritativeness: ServerAuthoritativeness | None = Field(
        default=None,
        alias="authoritativeness",
    )
    authority_level: AuthorityLevel
    response_digest: str = Field(default=_ZERO_DIGEST, pattern=_SHA256_PATTERN)

    @field_validator("run_id", mode="before")
    @classmethod
    def _run_uuid(cls, value: Any) -> UUID | None:
        return _uuid_or_none(value)

    @field_validator("generated_at", mode="before")
    @classmethod
    def _generated_at_utc(cls, value: Any) -> datetime:
        return _utc_datetime(value)

    @field_validator("matches", "proposed_actions", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _validate_semantics_and_digest(self) -> "FinanceReconciliationResult":
        if self.parameters.simulate_mode != self.simulation_mode:
            raise ValueError("parameters.simulate_mode must match simulation_mode")
        if self.parameters.simulate_requested and not self.simulation_mode:
            raise ValueError("simulate_requested cannot be true for a live result")
        if self.simulation_mode:
            if self.authority_level != "scenario_grade":
                raise ValueError("simulation results must be scenario_grade")
        elif self.authority_level not in {
            "controlled_partial",
            "authoritative",
        }:
            raise ValueError(
                "completed live results must be controlled_partial or authoritative"
            )
        if self.reconciliation.amount_mismatch_count > self.coverage.matched_count:
            raise ValueError("amount_mismatch_count cannot exceed matched_count")
        if self.reconciliation.status_mismatch_count > self.coverage.matched_count:
            raise ValueError("status_mismatch_count cannot exceed matched_count")

        expected_match_rate = (
            Decimal(0)
            if self.coverage.stripe_invoice_count == 0
            else (
                Decimal(self.coverage.matched_count)
                / Decimal(self.coverage.stripe_invoice_count)
            ).quantize(Decimal("0.0001"), rounding=ROUND_HALF_UP)
        )
        if self.reconciliation.match_rate != expected_match_rate:
            raise ValueError("match_rate must match the normalized coverage counts")

        detail_limit = MAX_LEDGER_LIMIT if self.parameters.include_details else 25
        expected_detail_counts = {
            "matches": min(self.coverage.matched_count, detail_limit),
            "missing_in_ledger": min(
                self.coverage.unmatched_stripe_count,
                detail_limit,
            ),
            "missing_in_stripe": min(
                self.coverage.unmatched_ledger_count,
                detail_limit,
            ),
            "amount_mismatches": min(
                self.reconciliation.amount_mismatch_count,
                detail_limit,
            ),
            "status_mismatches": min(
                self.reconciliation.status_mismatch_count,
                detail_limit,
            ),
        }
        actual_detail_counts = {
            "matches": len(self.matches),
            "missing_in_ledger": len(self.exceptions.missing_in_ledger),
            "missing_in_stripe": len(self.exceptions.missing_in_stripe),
            "amount_mismatches": len(self.exceptions.amount_mismatches),
            "status_mismatches": len(self.exceptions.status_mismatches),
        }
        for section, expected_count in expected_detail_counts.items():
            if actual_detail_counts[section] != expected_count:
                raise ValueError(
                    f"{section} detail count must match Spring's bounded response"
                )

        digest_payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"run_id", "generated_at", "response_digest"},
            exclude_none=True,
        )
        expected = _stable_digest(digest_payload)
        if self.response_digest not in {_ZERO_DIGEST, expected}:
            raise ValueError("response_digest does not match reconciliation result")
        object.__setattr__(self, "response_digest", expected)
        return self

    @property
    def counts(self) -> FinanceReconciliationCoverage:
        """Business-name alias for Spring's ``coverage`` section."""

        return self.coverage

    @property
    def control_summary(self) -> FinanceReconciliationControlSummary:
        """Business-name alias for Spring's ``reconciliation`` section."""

        return self.reconciliation

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


class FinanceReconciliationStoredRequest(_StrictModel):
    """The exact nullable request record persisted by Spring for one run."""

    ledger_provider: ShortText | None
    stripe_limit: int | None = Field(
        default=None,
        ge=_JAVA_INTEGER_MIN,
        le=_JAVA_INTEGER_MAX,
    )
    ledger_limit: int | None = Field(
        default=None,
        ge=_JAVA_INTEGER_MIN,
        le=_JAVA_INTEGER_MAX,
    )
    amount_tolerance: Decimal | None = None
    include_details: bool | None
    simulate_mode: bool | None
    simulation_seed: int | None = Field(
        default=None,
        ge=_JAVA_INTEGER_MIN,
        le=_JAVA_INTEGER_MAX,
    )

    @field_validator("amount_tolerance", mode="before")
    @classmethod
    def _amount_tolerance_decimal(cls, value: Any) -> Decimal | None:
        if value is None:
            return None
        return _finite_decimal(value)


class FinanceReconciliationCompletedRunSummary(_StrictModel):
    status: Literal["completed"]
    ledger_provider: LedgerProvider
    generated_at: datetime
    started_at: datetime
    matched_count: int = Field(ge=0, le=MAX_STRIPE_LIMIT)
    unmatched_stripe_count: int = Field(ge=0, le=MAX_STRIPE_LIMIT)
    unmatched_ledger_count: int = Field(ge=0, le=MAX_LEDGER_LIMIT)
    match_rate: Decimal = Field(ge=0, le=1)
    amount_mismatch_count: int = Field(ge=0, le=MAX_STRIPE_LIMIT)
    status_mismatch_count: int = Field(ge=0, le=MAX_STRIPE_LIMIT)
    simulation_mode: bool
    simulation_reason: BoundedText

    @field_validator("generated_at", "started_at", mode="before")
    @classmethod
    def _utc_timestamps(cls, value: Any) -> datetime:
        return _utc_datetime(value)

    @field_validator("match_rate", mode="before")
    @classmethod
    def _match_rate_decimal(cls, value: Any) -> Decimal:
        return _finite_decimal(value, non_negative=True)

    @model_validator(mode="after")
    def _started_before_generated(self) -> "FinanceReconciliationCompletedRunSummary":
        if self.started_at > self.generated_at:
            raise ValueError("started_at cannot follow generated_at")
        return self


class FinanceReconciliationFailedRunSummary(_StrictModel):
    status: Literal["failed"]
    generated_at: datetime

    @field_validator("generated_at", mode="before")
    @classmethod
    def _utc_timestamp(cls, value: Any) -> datetime:
        return _utc_datetime(value)


FinanceReconciliationStoredSummary = Annotated[
    FinanceReconciliationCompletedRunSummary | FinanceReconciliationFailedRunSummary,
    Field(discriminator="status"),
]


class FinanceReconciliationStoredFailure(_StrictModel):
    status: Literal["failed"]
    error: BoundedText


class FinanceReconciliationRunSummary(_StrictModel):
    """A strict row returned by Spring's reconciliation run-list route."""

    schema_id: Literal["lightbulb.finance_reconciliation_run_summary.v1"] = Field(
        default=FINANCE_RECONCILIATION_RUN_SUMMARY_SCHEMA,
        alias="schema",
    )
    run_id: UUID
    status: ReconciliationStatus
    workflow_type: Literal["finance_stripe_ledger_reconciliation"]
    ledger_provider: ShortText | None
    created_at: datetime
    updated_at: datetime
    matched_count: int = Field(ge=0, le=MAX_STRIPE_LIMIT)
    unmatched_stripe_count: int = Field(ge=0, le=MAX_STRIPE_LIMIT)
    unmatched_ledger_count: int = Field(ge=0, le=MAX_LEDGER_LIMIT)
    match_rate: Decimal = Field(ge=0, le=1)
    amount_mismatch_count: int = Field(ge=0, le=MAX_STRIPE_LIMIT)
    status_mismatch_count: int = Field(ge=0, le=MAX_STRIPE_LIMIT)
    simulation_mode: bool
    simulation_reason: BoundedText
    error_message: BoundedText | None = None

    @field_validator("run_id", mode="before")
    @classmethod
    def _run_uuid(cls, value: Any) -> UUID:
        parsed = _uuid_or_none(value)
        if parsed is None:
            raise ValueError("run_id is required")
        return parsed

    @field_validator("created_at", "updated_at", mode="before")
    @classmethod
    def _utc_timestamps(cls, value: Any) -> datetime:
        return _utc_datetime(value)

    @field_validator("match_rate", mode="before")
    @classmethod
    def _match_rate_decimal(cls, value: Any) -> Decimal:
        return _finite_decimal(value, non_negative=True)

    @model_validator(mode="after")
    def _validate_run_summary(self) -> "FinanceReconciliationRunSummary":
        if self.updated_at < self.created_at:
            raise ValueError("updated_at cannot precede created_at")
        if self.status == "completed":
            if self.ledger_provider not in {"quickbooks", "xero"}:
                raise ValueError("completed runs require a resolved ledger_provider")
            if self.error_message not in {None, ""}:
                raise ValueError("completed runs cannot contain an error_message")
        elif self.error_message in {None, ""}:
            raise ValueError("failed runs require an error_message")
        return self

    @property
    def authority_level(self) -> AuthorityLevel:
        if self.status == "failed":
            return "blocked"
        return "scenario_grade" if self.simulation_mode else "controlled_partial"

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


class FinanceReconciliationRunDetails(_StrictModel):
    """The Spring-owned stored request, summary, and normalized run result."""

    schema_id: Literal["lightbulb.finance_reconciliation_run_details.v1"] = Field(
        default=FINANCE_RECONCILIATION_RUN_DETAILS_SCHEMA,
        alias="schema",
    )
    run_id: UUID
    status: ReconciliationStatus
    ledger_provider: ShortText | None
    error_message: BoundedText | None = None
    created_at: datetime
    updated_at: datetime
    request: FinanceReconciliationStoredRequest
    summary: FinanceReconciliationStoredSummary
    result: FinanceReconciliationResult | FinanceReconciliationStoredFailure

    @field_validator("run_id", mode="before")
    @classmethod
    def _run_uuid(cls, value: Any) -> UUID:
        parsed = _uuid_or_none(value)
        if parsed is None:
            raise ValueError("run_id is required")
        return parsed

    @field_validator("created_at", "updated_at", mode="before")
    @classmethod
    def _utc_timestamps(cls, value: Any) -> datetime:
        return _utc_datetime(value)

    @model_validator(mode="before")
    @classmethod
    def _parse_stored_result(cls, value: Any) -> Any:
        if not isinstance(value, Mapping):
            return value
        payload = dict(value)
        raw_result = payload.get("result")
        if payload.get("status") == "completed" and isinstance(raw_result, Mapping):
            payload["result"] = parse_finance_reconciliation_result(raw_result)
        return payload

    @model_validator(mode="after")
    def _validate_run_details(self) -> "FinanceReconciliationRunDetails":
        if self.updated_at < self.created_at:
            raise ValueError("updated_at cannot precede created_at")
        if self.summary.status != self.status or self.result.status != self.status:
            raise ValueError("stored summary and result status must match run status")

        if self.status == "completed":
            if not isinstance(self.result, FinanceReconciliationResult):
                raise ValueError("completed runs require a reconciliation result")
            if not isinstance(self.summary, FinanceReconciliationCompletedRunSummary):
                raise ValueError("completed runs require a completed summary")
            if self.ledger_provider != self.result.ledger_provider:
                raise ValueError(
                    "run ledger_provider must match result ledger_provider"
                )
            if self.summary.ledger_provider != self.result.ledger_provider:
                raise ValueError(
                    "summary ledger_provider must match result ledger_provider"
                )
            if self.summary.generated_at != self.result.generated_at:
                raise ValueError("summary generated_at must match result generated_at")
            if self.summary.matched_count != self.result.coverage.matched_count:
                raise ValueError("summary matched_count must match result coverage")
            if (
                self.summary.unmatched_stripe_count
                != self.result.coverage.unmatched_stripe_count
            ):
                raise ValueError(
                    "summary unmatched_stripe_count must match result coverage"
                )
            if (
                self.summary.unmatched_ledger_count
                != self.result.coverage.unmatched_ledger_count
            ):
                raise ValueError(
                    "summary unmatched_ledger_count must match result coverage"
                )
            if self.summary.match_rate != self.result.reconciliation.match_rate:
                raise ValueError("summary match_rate must match result reconciliation")
            if (
                self.summary.amount_mismatch_count
                != self.result.reconciliation.amount_mismatch_count
            ):
                raise ValueError(
                    "summary amount_mismatch_count must match result reconciliation"
                )
            if (
                self.summary.status_mismatch_count
                != self.result.reconciliation.status_mismatch_count
            ):
                raise ValueError(
                    "summary status_mismatch_count must match result reconciliation"
                )
            if self.summary.simulation_mode != self.result.simulation_mode:
                raise ValueError("summary simulation_mode must match stored result")
            if self.result.parameters.simulate_requested != (
                self.request.simulate_mode is True
            ):
                raise ValueError("stored simulate request must match result parameters")
            if self.error_message not in {None, ""}:
                raise ValueError("completed runs cannot contain an error_message")
        else:
            if not isinstance(self.result, FinanceReconciliationStoredFailure):
                raise ValueError("failed runs require a stored failure result")
            if not isinstance(self.summary, FinanceReconciliationFailedRunSummary):
                raise ValueError("failed runs require a failed summary")
            if self.error_message in {None, ""}:
                raise ValueError("failed runs require an error_message")
        return self

    @property
    def authority_level(self) -> AuthorityLevel:
        if isinstance(self.result, FinanceReconciliationResult):
            return self.result.authority_level
        return "blocked"

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def build_finance_reconciliation_request(
    request: FinanceReconciliationRequest | Mapping[str, Any] | None = None,
    /,
    **request_fields: Any,
) -> dict[str, Any]:
    """Build the exact JSON-ready body for Spring's reconciliation endpoint.

    Pass either a typed request/a mapping as the positional argument, or request
    fields as keywords.  ``auto`` provider and simulation choices are omitted:
    that preserves Spring's provider selection and connector-aware simulation
    fallback.  ``simulation`` maps to ``simulate_mode=true`` and ``live`` maps
    to ``false`` (Spring's strict live-only branch).
    """

    if request is not None and request_fields:
        raise TypeError("pass either request or keyword request fields, not both")
    if request is not None and not isinstance(
        request, (FinanceReconciliationRequest, Mapping)
    ):
        raise TypeError("request must be a FinanceReconciliationRequest or mapping")
    parsed = revalidate_model_boundary(
        FinanceReconciliationRequest,
        request_fields if request is None else request,
    )

    tolerance = float(parsed.amount_tolerance)
    if not math.isfinite(tolerance):
        raise ValueError("amount_tolerance is outside Spring's finite Double range")

    payload: dict[str, Any] = {
        "stripe_limit": parsed.stripe_limit,
        "ledger_limit": parsed.ledger_limit,
        "amount_tolerance": tolerance,
        "include_details": parsed.include_details,
    }
    if parsed.ledger_provider != "auto":
        payload["ledger_provider"] = parsed.ledger_provider
    if parsed.simulation_mode == "simulation":
        payload["simulate_mode"] = True
        if parsed.simulation_seed is not None:
            payload["simulation_seed"] = parsed.simulation_seed
    elif parsed.simulation_mode == "live":
        payload["simulate_mode"] = False
    return payload


def parse_finance_reconciliation_result(
    response: Mapping[str, Any],
) -> FinanceReconciliationResult:
    """Strictly parse a Spring response and derive a non-inflating authority.

    Unknown top-level or nested keys are rejected.  Simulation always wins over
    any server authority assertion and is labeled ``scenario_grade``.  A
    completed live response is only ``controlled_partial`` unless Spring
    explicitly returns ``authoritative`` in ``authority_level`` or
    ``authoritativeness``; provider acceptance alone is never promoted.
    """

    if not isinstance(response, Mapping):
        raise TypeError("response must be a mapping")
    payload = dict(detach_model_boundary_value(response))

    raw_authority = payload.pop("authority_level", None)
    if raw_authority is not None:
        if "authoritativeness" in payload:
            raise ValueError(
                "response cannot contain both authority_level and authoritativeness"
            )
        payload["authoritativeness"] = raw_authority
    else:
        raw_authority = payload.get("authoritativeness")

    simulation_mode = payload.get("simulation_mode")
    status = payload.get("status")
    if simulation_mode is True:
        authority_level: AuthorityLevel = "scenario_grade"
    elif status == "completed" and raw_authority == "authoritative":
        authority_level = "authoritative"
    elif status == "completed":
        authority_level = "controlled_partial"
    else:
        authority_level = "blocked"
    payload["authority_level"] = authority_level

    return FinanceReconciliationResult.model_validate(payload)


def parse_finance_reconciliation_run_summaries(
    response: Sequence[Mapping[str, Any]],
) -> tuple[FinanceReconciliationRunSummary, ...]:
    """Strictly parse the bounded list returned by Spring's ``/runs`` route."""

    if isinstance(response, (str, bytes, bytearray)) or not isinstance(
        response, Sequence
    ):
        raise TypeError("response must be a sequence of reconciliation run mappings")
    if len(response) > 200:
        raise ValueError("reconciliation run response cannot exceed 200 rows")

    parsed: list[FinanceReconciliationRunSummary] = []
    for index, item in enumerate(response):
        if not isinstance(item, Mapping):
            raise TypeError(f"response item {index} must be a mapping")
        parsed.append(revalidate_model_boundary(FinanceReconciliationRunSummary, item))
    return tuple(parsed)


def parse_finance_reconciliation_run_details(
    response: Mapping[str, Any],
) -> FinanceReconciliationRunDetails:
    """Strictly parse one exact-scope Spring reconciliation run envelope."""

    if not isinstance(response, Mapping):
        raise TypeError("response must be a reconciliation run mapping")
    return revalidate_model_boundary(FinanceReconciliationRunDetails, response)


__all__ = [
    "DEFAULT_AMOUNT_TOLERANCE",
    "DEFAULT_LEDGER_LIMIT",
    "DEFAULT_STRIPE_LIMIT",
    "FINANCE_RECONCILIATION_REQUEST_SCHEMA",
    "FINANCE_RECONCILIATION_RESULT_SCHEMA",
    "FINANCE_RECONCILIATION_RUN_DETAILS_SCHEMA",
    "FINANCE_RECONCILIATION_RUN_SUMMARY_SCHEMA",
    "MAX_LEDGER_LIMIT",
    "MAX_STRIPE_LIMIT",
    "AuthorityLevel",
    "FinanceReconciliationControlSummary",
    "FinanceReconciliationCompletedRunSummary",
    "FinanceReconciliationCoverage",
    "FinanceReconciliationExceptions",
    "FinanceReconciliationFailedRunSummary",
    "FinanceReconciliationInvoice",
    "FinanceReconciliationMatch",
    "FinanceReconciliationParameters",
    "FinanceReconciliationProposedAction",
    "FinanceReconciliationRequest",
    "FinanceReconciliationResult",
    "FinanceReconciliationRunDetails",
    "FinanceReconciliationRunSummary",
    "FinanceReconciliationStoredFailure",
    "FinanceReconciliationStoredRequest",
    "FinanceReconciliationStoredSummary",
    "FinanceReconciliationTotals",
    "LedgerProvider",
    "LedgerProviderRequest",
    "SimulationMode",
    "build_finance_reconciliation_request",
    "parse_finance_reconciliation_run_details",
    "parse_finance_reconciliation_run_summaries",
    "parse_finance_reconciliation_result",
]
