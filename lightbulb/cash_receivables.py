"""Accounts receivable: the cash you're owed, aged, and its collection calendar.

The rest of the accountant layer watches cash going *out* — burn, runway, the
weekly outflow calendar. It is half-blind: it says nothing about the cash owed
*in*. A fast-growing company can look nearly out of runway on its bank balance
while sitting on a fat book of receivables that, collected on time, changes the
picture entirely. This module is the other half — the AR ledger the CFO reviews:
how much is outstanding, how overdue it is, how fast the company collects (DSO),
and *when* each invoice is expected to land — a schedule that drops straight into
the 13-week cash-flow forecast as its inflow side.

The honesty rule here is specific and it matters: **overdue is not written off.**
An invoice past due is still an asset and still (usually) collectible; aging
flags *risk*, not *loss*. Only invoices the caller explicitly marks uncollectible
are removed from receivables — the engine never decides a debt is dead on its
own, and it never treats an expected collection date as a promise. It also flags
customer concentration, because AR that all sits with one customer carries a
collection risk that is correlated, not diversified.

Holds no keyring, does no I/O. Deterministic and digest-bound.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import datetime, timezone
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from typing import Annotated, Any, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
)

from .primitive_runtime import (
    BusinessProcessPrimitive,
    PrimitiveEvent,
    PrimitiveEvidence,
    PrimitiveExecutionContext,
    PrimitiveExecutionResult,
    PrimitiveExecutionStatus,
)

RECEIVABLES_ASSESSMENT_SCHEMA = "lightbulb.receivables_assessment.v1"

_MONEY_QUANTUM = Decimal("0.01")
_DAYS_QUANTUM = Decimal("0.1")
_SHARE_QUANTUM = Decimal("0.0001")

_PORTABLE_REF_PATTERN = r"^[a-z][a-z0-9_-]{0,63}$"
_CURRENCY_PATTERN = r"^[A-Z]{3}$"

# Concentration flag: AR this fraction or more in a single customer is a
# correlated collection risk, not a diversified book. Labeled heuristic.
_CONCENTRATION_THRESHOLD = Decimal("0.40")


class ReceivablesError(ValueError):
    """The receivables inputs cannot produce an honest assessment."""


def _stable_digest(value: Any) -> str:
    canonical = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _bounded_text(value: str) -> str:
    if value != value.strip():
        raise ValueError("content must not contain surrounding whitespace")
    if any(ord(character) < 32 for character in value):
        raise ValueError("content contains an unsupported control character")
    return value


ShortText = Annotated[
    str,
    StringConstraints(min_length=1, max_length=300),
    AfterValidator(_bounded_text),
]
PortableRef = Annotated[str, StringConstraints(pattern=_PORTABLE_REF_PATTERN)]
CurrencyCode = Annotated[str, StringConstraints(pattern=_CURRENCY_PATTERN)]


def _normalized_timestamp(value: str) -> str:
    clean = value.strip()
    try:
        parsed = datetime.fromisoformat(clean.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamp must be valid ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must include a UTC offset")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _decimal(
    value: Any, *, quantum: Decimal | None = None, allow_negative: bool = False
) -> Decimal:
    if not isinstance(value, (str, Decimal, int, float)) or isinstance(value, bool):
        raise ValueError("decimal values must be supplied as strings or JSON numbers")
    lexical = str(value)
    if len(lexical) > 48 or lexical != lexical.strip():
        raise ValueError("value must use bounded decimal notation")
    try:
        parsed = Decimal(lexical)
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("value must be a finite decimal") from exc
    if not parsed.is_finite():
        raise ValueError("value must be a finite decimal")
    if not allow_negative and parsed < 0:
        raise ValueError("value must be non-negative")
    if quantum is not None:
        try:
            normalized = parsed.quantize(quantum)
        except InvalidOperation as exc:
            raise ValueError(
                "value cannot be represented at the required precision"
            ) from exc
        if parsed != normalized:
            raise ValueError(
                f"value supports at most {-quantum.as_tuple().exponent} decimal places"
            )
        return normalized
    return parsed


def _immutable_sequence(value: Any) -> Any:
    if isinstance(value, list):
        return tuple(value)
    return value


def _quantized_money(value: Decimal) -> Decimal:
    return value.quantize(_MONEY_QUANTUM, rounding=ROUND_HALF_UP)


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=False,
        serialize_by_alias=True,
        strict=True,
    )


# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------


class OutstandingInvoice(_StrictModel):
    """One unpaid invoice: an amount owed, when it's due, when it's expected."""

    invoice_ref: ShortText
    customer: ShortText
    amount: Decimal = Field(gt=0)
    due_at: str
    expected_payment_at: str | None = None
    # The caller has determined this debt will not be collected. It is removed
    # from receivables and reported separately — the engine never decides this.
    uncollectible: bool = False

    @field_validator("due_at")
    @classmethod
    def _valid_due(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator("expected_payment_at")
    @classmethod
    def _valid_expected(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _normalized_timestamp(value)

    @field_validator("amount", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_MONEY_QUANTUM)


class AssessReceivablesInput(_StrictModel):
    assessment_ref: PortableRef
    as_of: str
    currency: CurrencyCode
    invoices: tuple[OutstandingInvoice, ...] = Field(min_length=1, max_length=1000)
    # Credit sales over a trailing period and that period's length, used to
    # compute DSO. Both are required to compute it; absent, DSO is left unknown.
    credit_sales_in_period: Decimal | None = None
    period_days: int | None = Field(default=None, ge=1, le=366)
    horizon_weeks: int = Field(default=13, ge=1, le=52)

    @field_validator("as_of")
    @classmethod
    def _valid_as_of(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator("credit_sales_in_period", mode="before")
    @classmethod
    def _opt_money(cls, value: Any) -> Decimal | None:
        if value is None:
            return None
        return _decimal(value, quantum=_MONEY_QUANTUM)

    @field_validator("invoices", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _immutable_sequence(value)


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


class AgingBuckets(_StrictModel):
    not_yet_due: Decimal = Field(ge=0)
    days_0_30: Decimal = Field(ge=0)
    days_31_60: Decimal = Field(ge=0)
    days_61_90: Decimal = Field(ge=0)
    days_90_plus: Decimal = Field(ge=0)

    @field_validator(
        "not_yet_due", "days_0_30", "days_31_60", "days_61_90", "days_90_plus",
        mode="before",
    )
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_MONEY_QUANTUM)


class ExpectedCollection(_StrictModel):
    invoice_ref: ShortText
    customer: ShortText
    amount: Decimal = Field(gt=0)
    expected_week: int = Field(ge=1, le=520)
    within_horizon: bool
    is_overdue: bool

    @field_validator("amount", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_MONEY_QUANTUM)


class ReceivablesAssessment(_StrictModel):
    """AR aged and scheduled: what's owed, how late, how fast collected, when due."""

    schema_id: Literal["lightbulb.receivables_assessment.v1"] = Field(
        default=RECEIVABLES_ASSESSMENT_SCHEMA,
        alias="schema",
    )
    assessment_ref: PortableRef
    as_of: str
    currency: CurrencyCode
    total_outstanding: Decimal = Field(ge=0)
    overdue_total: Decimal = Field(ge=0)
    written_off_excluded: Decimal = Field(ge=0)
    aging: AgingBuckets
    dso_days: Decimal | None = None
    largest_customer: ShortText | None = None
    largest_customer_share: Decimal | None = None
    concentration_flag: bool = False
    horizon_weeks: int = Field(ge=1, le=52)
    collections_within_horizon: Decimal = Field(ge=0)
    expected_collections: tuple[ExpectedCollection, ...] = Field(default_factory=tuple)
    notes: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=12)
    assessment_digest: str = "0" * 64

    @field_validator("as_of")
    @classmethod
    def _valid_as_of(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator(
        "total_outstanding", "overdue_total", "written_off_excluded",
        "collections_within_horizon", mode="before",
    )
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_MONEY_QUANTUM)

    @field_validator("dso_days", mode="before")
    @classmethod
    def _opt_days(cls, value: Any) -> Decimal | None:
        if value is None:
            return None
        return _decimal(value, quantum=_DAYS_QUANTUM)

    @field_validator("largest_customer_share", mode="before")
    @classmethod
    def _opt_share(cls, value: Any) -> Decimal | None:
        if value is None:
            return None
        return _decimal(value, quantum=_SHARE_QUANTUM)

    @field_validator("expected_collections", "notes", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def _expected_week(as_of: datetime, expected: datetime, horizon: int) -> tuple[int, bool]:
    days = (expected - as_of).days
    week = 1 if days <= 0 else min(520, max(1, (days + 6) // 7))
    return week, week <= horizon


def build_receivables_assessment(
    inputs: AssessReceivablesInput | Mapping[str, Any],
) -> ReceivablesAssessment:
    """Age the receivables, compute DSO, and schedule expected collections.

    Buckets collectible invoices by days past due (not-yet-due / 0-30 / 31-60 /
    61-90 / 90+), sums the book, computes DSO when credit sales and a period are
    supplied, flags single-customer concentration, and emits a per-invoice
    collection schedule (expected payment date, or due date when none is given)
    that feeds the 13-week forecast's inflow side. Invoices the caller marks
    uncollectible are excluded from AR and reported separately; overdue ones are
    not — overdue is risk, not loss.
    """

    parsed = (
        inputs
        if isinstance(inputs, AssessReceivablesInput)
        else AssessReceivablesInput.model_validate(inputs)
    )

    as_of = _parse_utc(parsed.as_of)
    horizon = parsed.horizon_weeks

    not_yet_due = Decimal("0")
    d_0_30 = Decimal("0")
    d_31_60 = Decimal("0")
    d_61_90 = Decimal("0")
    d_90_plus = Decimal("0")
    total_outstanding = Decimal("0")
    overdue_total = Decimal("0")
    written_off = Decimal("0")
    within_horizon_total = Decimal("0")
    by_customer: dict[str, Decimal] = {}
    collections: list[ExpectedCollection] = []

    for invoice in parsed.invoices:
        if invoice.uncollectible:
            written_off += invoice.amount
            continue

        total_outstanding += invoice.amount
        by_customer[invoice.customer] = (
            by_customer.get(invoice.customer, Decimal("0")) + invoice.amount
        )

        due = _parse_utc(invoice.due_at)
        days_overdue = (as_of - due).days
        is_overdue = days_overdue > 0
        # Due-today (0 days) is "current", not past due, so overdue_total equals
        # the sum of the four past-due buckets exactly.
        if days_overdue <= 0:
            not_yet_due += invoice.amount
        elif days_overdue <= 30:
            d_0_30 += invoice.amount
        elif days_overdue <= 60:
            d_31_60 += invoice.amount
        elif days_overdue <= 90:
            d_61_90 += invoice.amount
        else:
            d_90_plus += invoice.amount
        if is_overdue:
            overdue_total += invoice.amount

        expected_dt = (
            _parse_utc(invoice.expected_payment_at)
            if invoice.expected_payment_at is not None
            else due
        )
        week, within = _expected_week(as_of, expected_dt, horizon)
        if within:
            within_horizon_total += invoice.amount
        collections.append(
            ExpectedCollection(
                invoice_ref=invoice.invoice_ref,
                customer=invoice.customer,
                amount=invoice.amount,
                expected_week=week,
                within_horizon=within,
                is_overdue=is_overdue,
            )
        )

    # DSO = (AR / credit sales) * period days, when both are supplied.
    dso: Decimal | None = None
    if parsed.credit_sales_in_period is not None and parsed.period_days is not None:
        if parsed.credit_sales_in_period > 0:
            dso = (
                total_outstanding / parsed.credit_sales_in_period * parsed.period_days
            ).quantize(_DAYS_QUANTUM, rounding=ROUND_HALF_UP)

    largest_customer: str | None = None
    largest_share: Decimal | None = None
    concentration = False
    if by_customer and total_outstanding > 0:
        largest_customer, largest_sum = max(by_customer.items(), key=lambda kv: kv[1])
        largest_share = (largest_sum / total_outstanding).quantize(
            _SHARE_QUANTUM, rounding=ROUND_HALF_UP
        )
        concentration = largest_share >= _CONCENTRATION_THRESHOLD

    notes: list[str] = [
        "overdue balances are still assets until written off; aging flags risk, not loss"
    ]
    if overdue_total > 0:
        notes.append(
            f"{overdue_total} {parsed.currency} is past due; collection is uncertain, "
            "chase before it ages further"
        )
    if dso is None:
        notes.append(
            "DSO not computed; supply credit_sales_in_period and period_days to measure it"
        )
    if written_off > 0:
        notes.append(
            f"{written_off} {parsed.currency} excluded as caller-marked uncollectible"
        )
    if concentration and largest_customer is not None and largest_share is not None:
        pct = (largest_share * 100).quantize(Decimal("0.1"))
        # Bound the customer name so the note can never exceed ShortText (<=300).
        name = largest_customer if len(largest_customer) <= 80 else largest_customer[:77] + "..."
        notes.append(
            f"AR is concentrated: {pct}% sits with '{name}' — collection "
            "risk is correlated, not diversified"
        )
    notes.append(
        "expected collection dates are estimates (expected date, or due date); not promises"
    )

    assessment = ReceivablesAssessment(
        assessment_ref=parsed.assessment_ref,
        as_of=parsed.as_of,
        currency=parsed.currency,
        total_outstanding=_quantized_money(total_outstanding),
        overdue_total=_quantized_money(overdue_total),
        written_off_excluded=_quantized_money(written_off),
        aging=AgingBuckets(
            not_yet_due=_quantized_money(not_yet_due),
            days_0_30=_quantized_money(d_0_30),
            days_31_60=_quantized_money(d_31_60),
            days_61_90=_quantized_money(d_61_90),
            days_90_plus=_quantized_money(d_90_plus),
        ),
        dso_days=dso,
        largest_customer=largest_customer,
        largest_customer_share=largest_share,
        concentration_flag=concentration,
        horizon_weeks=horizon,
        collections_within_horizon=_quantized_money(within_horizon_total),
        expected_collections=tuple(collections),
        notes=tuple(dict.fromkeys(notes))[:12],
    )
    digest = _stable_digest(
        assessment.model_dump(mode="json", exclude={"assessment_digest"})
    )
    return assessment.model_copy(update={"assessment_digest": digest})


# ---------------------------------------------------------------------------
# Executable primitive
# ---------------------------------------------------------------------------


class AssessReceivablesPrimitive(
    BusinessProcessPrimitive[AssessReceivablesInput, ReceivablesAssessment]
):
    """Age accounts receivable, compute DSO, and schedule expected collections."""

    primitive_ref = "accounting.assess_receivables"
    version = "1.0.0"
    title = "Assess accounts receivable"
    description = (
        "Age the open invoice book by days past due (not-yet-due / 0-30 / 31-60 "
        "/ 61-90 / 90+), total the receivables, compute DSO when credit sales and "
        "a period are supplied, flag single-customer concentration, and emit a "
        "per-invoice expected-collection schedule that feeds the 13-week cash-flow "
        "forecast's inflow side. Overdue is treated as risk, not loss — only "
        "caller-marked uncollectible invoices are excluded — and expected "
        "collection dates are estimates, never promises."
    )
    input_model = AssessReceivablesInput
    output_model = ReceivablesAssessment
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs = {
        "assessment_ref": "ar-example",
        "as_of": "2026-08-02T00:00:00Z",
        "currency": "USD",
        "credit_sales_in_period": "300000.00",
        "period_days": 90,
        "horizon_weeks": 13,
        "invoices": (
            {
                "invoice_ref": "INV-1001",
                "customer": "Northwind Traders",
                "amount": "48000.00",
                "due_at": "2026-08-20T00:00:00Z",
            },
            {
                "invoice_ref": "INV-0994",
                "customer": "Contoso Ltd",
                "amount": "22000.00",
                "due_at": "2026-07-15T00:00:00Z",
                "expected_payment_at": "2026-08-25T00:00:00Z",
            },
            {
                "invoice_ref": "INV-0980",
                "customer": "Northwind Traders",
                "amount": "15000.00",
                "due_at": "2026-05-01T00:00:00Z",
            },
            {
                "invoice_ref": "INV-0975",
                "customer": "Fabrikam Inc",
                "amount": "9000.00",
                "due_at": "2026-06-30T00:00:00Z",
                "uncollectible": True,
            },
        ),
    }

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: AssessReceivablesInput,
    ) -> PrimitiveExecutionResult[ReceivablesAssessment]:
        try:
            assessment = build_receivables_assessment(inputs)
        except ValueError as exc:
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.FAILED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary=f"receivables assessment rejected: {exc}",
                output=None,
            )
        dso = (
            f", DSO {assessment.dso_days}d"
            if assessment.dso_days is not None
            else ""
        )
        return PrimitiveExecutionResult[ReceivablesAssessment](
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                f"{assessment.assessment_ref}: {assessment.total_outstanding} "
                f"{assessment.currency} outstanding ({assessment.overdue_total} "
                f"overdue){dso}."
            ),
            output=assessment,
            events=[
                PrimitiveEvent(
                    type="accounting.receivables_assessed",
                    payload={
                        "assessment_ref": assessment.assessment_ref,
                        "total_outstanding": str(assessment.total_outstanding),
                        "concentration_flag": assessment.concentration_flag,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="deterministic_plan",
                    summary="Aging and collection schedule; overdue is risk, not loss.",
                )
            ],
        )


__all__ = [
    "RECEIVABLES_ASSESSMENT_SCHEMA",
    "AgingBuckets",
    "AssessReceivablesInput",
    "AssessReceivablesPrimitive",
    "ExpectedCollection",
    "OutstandingInvoice",
    "ReceivablesAssessment",
    "ReceivablesError",
    "build_receivables_assessment",
]
