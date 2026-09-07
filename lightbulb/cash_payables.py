"""Accounts payable: the cash you owe, aged, and its payment calendar.

Receivables answered "what's owed *in*." This is the other side of working
capital: what's owed *out*. A company that looks comfortable on its bank balance
can be sitting on a stack of bills coming due next week — payroll, rent, a big
supplier invoice — that turn a healthy-looking month into a scramble. This module
is the payables ledger the CFO reviews: how much is outstanding, how much is
already past due, how long the company takes to pay (DPO), and *when* each bill is
expected to go out — a schedule that drops straight into the 13-week cash-flow
forecast as its outflow side.

The honesty rule is NOT the mirror of receivables, and that is the point. In
receivables the caller may mark an invoice uncollectible and it leaves the book,
because overstating an asset is the dangerous direction there. Here the danger
runs the other way: understating a liability flatters the position. So a bill the
caller disputes or withholds is **kept in the total, aged, and scheduled** — a
dispute you lose is still payable — and merely broken out as `on_hold_total`.
Nothing leaves this book.

For the same reason the total is reported as a **floor, not a measurement**: an
invoice book holds invoiced bills, while payroll, rent and tax are owed with no
invoice yet. Unless the caller asserts otherwise, `obligations_are_floor` is true
and says so.

And still: **overdue is not a saving.** A bill past due is money you owe and were late paying — a real
obligation plus a relationship and credit risk, never cash you get to keep.
Leaving upcoming bills out of the forecast understates the outflow side, and by
the layer's direction-aware rule that is the *dangerous* direction — it flatters
the cash position. The engine never decides on its own that a bill won't be paid,
and never treats an expected payment date as a commitment it invented. Vendor
concentration is flagged, because owing most of your payables to one supplier is
leverage that vendor holds over you. Overdue bills to a vendor the caller marks
critical are escalated by name, because stopped supply stops the business. Open
early-payment discounts are priced as an implied annual return — an opportunity,
never a recommendation, since paying early pulls cash forward and only the cash
floor knows whether that is safe.

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
    model_validator,
)

from .primitive_runtime import (
    BusinessProcessPrimitive,
    PrimitiveEvent,
    PrimitiveEvidence,
    PrimitiveExecutionContext,
    PrimitiveExecutionResult,
    PrimitiveExecutionStatus,
)

PAYABLES_ASSESSMENT_SCHEMA = "lightbulb.payables_assessment.v2"

_MONEY_QUANTUM = Decimal("0.01")
_DAYS_QUANTUM = Decimal("0.1")
_SHARE_QUANTUM = Decimal("0.0001")

_PORTABLE_REF_PATTERN = r"^[a-z][a-z0-9_-]{0,63}$"
_CURRENCY_PATTERN = r"^[A-Z]{3}$"

# Concentration flag: payables this fraction or more owed to a single vendor is a
# correlated supply risk, not a diversified book. Labeled heuristic.
_CONCENTRATION_THRESHOLD = Decimal("0.40")

_RATE_QUANTUM = Decimal("0.1")
_DAYS_PER_YEAR = Decimal("365")
_DAY_QUANTUM = Decimal("0.000000000001")
_SECONDS_PER_DAY = Decimal("86400")

# The structured escalation list is bounded; when it truncates, the count that
# was dropped is stated in the notes rather than silently lost.
_MAX_LISTED_CRITICAL = 50


class PayablesError(ValueError):
    """The payables inputs cannot produce an honest assessment."""


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


class EarlyPaymentDiscount(_StrictModel):
    """Pay by `pay_by` and the vendor takes `discount_percent` off.

    The classic "2/10 net 30": 2% off if paid within 10 days, full amount due at
    30. `pay_by` must fall on or before the bill's due date — a discount deadline
    after the due date is not an early-payment term and is refused rather than
    silently priced as free money.
    """

    discount_percent: Decimal = Field(gt=0, lt=100)
    pay_by: str

    @field_validator("pay_by")
    @classmethod
    def _valid_pay_by(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator("discount_percent", mode="before")
    @classmethod
    def _rate(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=Decimal("0.01"))


class OutstandingBill(_StrictModel):
    """One unpaid bill: an amount owed, when it's due, when it's expected to go out."""

    bill_ref: ShortText
    vendor: ShortText
    amount: Decimal = Field(gt=0)
    due_at: str
    scheduled_payment_at: str | None = None
    # The caller is disputing or deliberately withholding this bill. It is NOT
    # removed from what is owed — the vendor still claims it and a dispute you
    # lose is still payable — it is broken out so the contested share is visible.
    on_hold: bool = False
    # DPO is a trade-credit measure. None means the caller has not classified
    # this obligation, so DPO remains unknown rather than silently treating
    # payroll, rent, or tax as supplier credit.
    trade_credit: bool | None = None
    # Caller's judgment, never inferred: losing this vendor interrupts operations.
    # Overdue bills to critical vendors are escalated by name.
    critical_vendor: bool = False
    early_payment_discount: EarlyPaymentDiscount | None = None

    @field_validator("due_at")
    @classmethod
    def _valid_due(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator("scheduled_payment_at")
    @classmethod
    def _valid_scheduled(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _normalized_timestamp(value)

    @field_validator("amount", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_MONEY_QUANTUM)

    @model_validator(mode="after")
    def _discount_precedes_due(self) -> "OutstandingBill":
        discount = self.early_payment_discount
        if discount is not None:
            if _parse_utc(discount.pay_by) > _parse_utc(self.due_at):
                raise ValueError(
                    "early_payment_discount.pay_by must fall on or before due_at"
                )
        return self


class AssessPayablesInput(_StrictModel):
    assessment_ref: PortableRef
    as_of: str
    currency: CurrencyCode
    bills: tuple[OutstandingBill, ...] = Field(min_length=1, max_length=1000)
    # Credit purchases over a trailing period and that period's length, used to
    # compute DPO. Both are required, and every bill must classify trade_credit,
    # so non-trade commitments cannot contaminate the ratio.
    credit_purchases_in_period: Decimal | None = None
    period_days: int | None = Field(default=None, ge=1, le=366)
    horizon_weeks: int = Field(default=13, ge=1, le=52)
    # Whether the supplied book is invoiced bills only, or already includes
    # committed-but-un-invoiced obligations (payroll, rent, subscriptions, tax).
    # Defaults to the honest assumption: invoices only, so the total is a floor.
    book_completeness: Literal["invoices_only", "invoices_and_commitments"] = (
        "invoices_only"
    )

    @field_validator("as_of")
    @classmethod
    def _valid_as_of(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator("credit_purchases_in_period", mode="before")
    @classmethod
    def _opt_money(cls, value: Any) -> Decimal | None:
        if value is None:
            return None
        return _decimal(value, quantum=_MONEY_QUANTUM)

    @field_validator("bills", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _consistent_critical_vendor_classification(self) -> "AssessPayablesInput":
        classifications: dict[str, bool] = {}
        for bill in self.bills:
            prior = classifications.get(bill.vendor)
            if prior is not None and prior is not bill.critical_vendor:
                raise ValueError(
                    "critical_vendor must be consistent across bills for vendor "
                    f"{bill.vendor!r}"
                )
            classifications[bill.vendor] = bill.critical_vendor
        return self


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


class ExpectedPayment(_StrictModel):
    bill_ref: ShortText
    vendor: ShortText
    amount: Decimal = Field(gt=0)
    expected_week: int = Field(ge=1, le=520)
    within_horizon: bool
    is_overdue: bool
    # Contested bills stay on the calendar: omitting them would understate the
    # outflow, and understating money leaving is the dangerous direction.
    on_hold: bool = False
    critical_vendor: bool = False

    @field_validator("amount", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_MONEY_QUANTUM)


class DiscountOpportunity(_StrictModel):
    """An early-payment discount still open at `as_of`.

    `implied_annual_return_percent` is what the discount is worth annualized
    over the days the payment is accelerated — the standard cost-of-forgoing-
    the-discount rate. It is an opportunity, not a recommendation: taking it
    pulls cash forward, and only the cash floor knows whether that is safe.
    """

    bill_ref: ShortText
    vendor: ShortText
    amount: Decimal = Field(gt=0)
    discount_amount: Decimal = Field(gt=0)
    pay_by: str
    days_accelerated: Decimal = Field(gt=0)
    implied_annual_return_percent: Decimal = Field(ge=0)

    @field_validator("pay_by")
    @classmethod
    def _valid_pay_by(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator("amount", "discount_amount", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_MONEY_QUANTUM)

    @field_validator("days_accelerated", mode="before")
    @classmethod
    def _days(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_DAY_QUANTUM)

    @field_validator("implied_annual_return_percent", mode="before")
    @classmethod
    def _rate(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_RATE_QUANTUM)


class PayablesAssessment(_StrictModel):
    """AP aged and scheduled: what's owed, how late, how fast paid, when due out."""

    schema_id: Literal["lightbulb.payables_assessment.v2"] = Field(
        default=PAYABLES_ASSESSMENT_SCHEMA,
        alias="schema",
    )
    assessment_ref: PortableRef
    as_of: str
    currency: CurrencyCode
    # Includes on-hold amounts: the vendor still claims them.
    total_outstanding: Decimal = Field(ge=0)
    overdue_total: Decimal = Field(ge=0)
    on_hold_total: Decimal = Field(ge=0)
    on_hold_overdue_total: Decimal = Field(ge=0)
    trade_payables_outstanding: Decimal | None = Field(default=None, ge=0)
    # True when the book is invoiced bills only, so committed-but-un-invoiced
    # obligations are missing and total_outstanding is a lower bound.
    obligations_are_floor: bool
    aging: AgingBuckets
    dpo_days: Decimal | None = None
    largest_vendor: ShortText | None = None
    largest_vendor_share: Decimal | None = None
    concentration_flag: bool = False
    horizon_weeks: int = Field(ge=1, le=52)
    payments_within_horizon: Decimal = Field(ge=0)
    expected_payments: tuple[ExpectedPayment, ...] = Field(default_factory=tuple)
    discount_opportunities: tuple[DiscountOpportunity, ...] = Field(
        default_factory=tuple
    )
    # Vendors the caller marked critical that hold an overdue bill.
    critical_vendors_overdue: tuple[ShortText, ...] = Field(
        default_factory=tuple, max_length=50
    )
    critical_vendors_overdue_count: int = Field(ge=0)
    critical_vendor_overdue_total: Decimal = Field(ge=0)
    critical_vendors_on_hold: tuple[ShortText, ...] = Field(
        default_factory=tuple, max_length=50
    )
    critical_vendors_on_hold_count: int = Field(ge=0)
    notes: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=16)
    assessment_digest: str = "0" * 64

    @field_validator("as_of")
    @classmethod
    def _valid_as_of(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator(
        "total_outstanding", "overdue_total", "on_hold_total",
        "on_hold_overdue_total", "critical_vendor_overdue_total",
        "payments_within_horizon", mode="before",
    )
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_MONEY_QUANTUM)

    @field_validator("trade_payables_outstanding", mode="before")
    @classmethod
    def _optional_money(cls, value: Any) -> Decimal | None:
        if value is None:
            return None
        return _decimal(value, quantum=_MONEY_QUANTUM)

    @field_validator("dpo_days", mode="before")
    @classmethod
    def _opt_days(cls, value: Any) -> Decimal | None:
        if value is None:
            return None
        return _decimal(value, quantum=_DAYS_QUANTUM)

    @field_validator("largest_vendor_share", mode="before")
    @classmethod
    def _opt_share(cls, value: Any) -> Decimal | None:
        if value is None:
            return None
        return _decimal(value, quantum=_SHARE_QUANTUM)

    @field_validator(
        "expected_payments",
        "discount_opportunities",
        "critical_vendors_overdue",
        "critical_vendors_on_hold",
        "notes",
        mode="before",
    )
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def _expected_week(as_of: datetime, expected: datetime, horizon: int) -> tuple[int, bool]:
    days = (expected - as_of).days
    week = 1 if days <= 0 else min(520, max(1, (days + 6) // 7))
    return week, week <= horizon


def build_payables_assessment(
    inputs: AssessPayablesInput | Mapping[str, Any],
) -> PayablesAssessment:
    """Age the payables, compute DPO, and schedule expected payments.

    Buckets active bills by days past due (not-yet-due / 0-30 / 31-60 / 61-90 /
    90+), sums the book, computes DPO when credit purchases and a period are
    supplied, flags single-vendor concentration, and emits a per-bill payment
    schedule (scheduled payment date, or due date when none is given) that feeds
    the 13-week forecast's outflow side, and prices any still-open early-payment
    discounts. Bills the caller puts on hold stay in the total and on the
    calendar — a dispute you lose is still payable — and are broken out as
    `on_hold_total`; overdue ones are not excluded either, because overdue means
    late, not free. Unless the caller asserts the book already includes
    committed-but-un-invoiced obligations, the total is reported as a floor.
    """

    parsed = (
        inputs
        if isinstance(inputs, AssessPayablesInput)
        else AssessPayablesInput.model_validate(inputs)
    )

    as_of = _parse_utc(parsed.as_of)
    horizon = parsed.horizon_weeks
    is_floor = parsed.book_completeness == "invoices_only"

    not_yet_due = Decimal("0")
    d_0_30 = Decimal("0")
    d_31_60 = Decimal("0")
    d_61_90 = Decimal("0")
    d_90_plus = Decimal("0")
    total_outstanding = Decimal("0")
    overdue_total = Decimal("0")
    on_hold = Decimal("0")
    on_hold_overdue = Decimal("0")
    trade_outstanding = Decimal("0")
    trade_classification_complete = True
    within_horizon_total = Decimal("0")
    by_vendor: dict[str, Decimal] = {}
    payments: list[ExpectedPayment] = []
    discounts: list[DiscountOpportunity] = []
    critical_overdue: list[str] = []
    critical_overdue_total = Decimal("0")
    critical_on_hold: list[str] = []
    expired_discounts = 0
    held_discounts = 0

    for bill in parsed.bills:
        # Nothing leaves the book. A held bill is still claimed against us.
        if bill.on_hold:
            on_hold += bill.amount

        total_outstanding += bill.amount
        if bill.trade_credit is None:
            trade_classification_complete = False
        elif bill.trade_credit:
            trade_outstanding += bill.amount
        by_vendor[bill.vendor] = by_vendor.get(bill.vendor, Decimal("0")) + bill.amount

        due = _parse_utc(bill.due_at)
        days_overdue = (as_of - due).days
        is_overdue = days_overdue > 0
        # Due-today (0 days) is "current", not past due, so overdue_total equals
        # the sum of the four past-due buckets exactly.
        if days_overdue <= 0:
            not_yet_due += bill.amount
        elif days_overdue <= 30:
            d_0_30 += bill.amount
        elif days_overdue <= 60:
            d_31_60 += bill.amount
        elif days_overdue <= 90:
            d_61_90 += bill.amount
        else:
            d_90_plus += bill.amount
        if is_overdue:
            overdue_total += bill.amount
            if bill.on_hold:
                on_hold_overdue += bill.amount
                if bill.critical_vendor and bill.vendor not in critical_on_hold:
                    critical_on_hold.append(bill.vendor)
            elif bill.critical_vendor and bill.vendor not in critical_overdue:
                critical_overdue.append(bill.vendor)
                critical_overdue_total += bill.amount
            elif bill.critical_vendor:
                critical_overdue_total += bill.amount

        expected_dt = (
            _parse_utc(bill.scheduled_payment_at)
            if bill.scheduled_payment_at is not None
            else due
        )
        week, within = _expected_week(as_of, expected_dt, horizon)
        if within:
            within_horizon_total += bill.amount
        payments.append(
            ExpectedPayment(
                bill_ref=bill.bill_ref,
                vendor=bill.vendor,
                amount=bill.amount,
                expected_week=week,
                within_horizon=within,
                is_overdue=is_overdue,
                on_hold=bill.on_hold,
                critical_vendor=bill.critical_vendor,
            )
        )

        discount = bill.early_payment_discount
        if discount is not None:
            pay_by = _parse_utc(discount.pay_by)
            if pay_by < as_of:
                expired_discounts += 1
                continue
            if bill.on_hold:
                held_discounts += 1
                continue
            acceleration = due - pay_by
            acceleration_seconds = (
                Decimal(acceleration.days * 86400 + acceleration.seconds)
                + Decimal(acceleration.microseconds) / Decimal("1000000")
            )
            if acceleration_seconds <= 0:
                # Paying by the due date earns the discount with no acceleration;
                # there is no annualized return to quote.
                continue
            unrounded_days_accelerated = acceleration_seconds / _SECONDS_PER_DAY
            days_accelerated = unrounded_days_accelerated.quantize(
                _DAY_QUANTUM,
                rounding=ROUND_HALF_UP,
            )
            discount_amount = _quantized_money(
                bill.amount * discount.discount_percent / Decimal("100")
            )
            net_payable = bill.amount - discount_amount
            if discount_amount <= 0 or net_payable <= 0:
                continue
            implied = (
                discount_amount
                / net_payable
                * (_DAYS_PER_YEAR / unrounded_days_accelerated)
                * Decimal("100")
            ).quantize(_RATE_QUANTUM, rounding=ROUND_HALF_UP)
            discounts.append(
                DiscountOpportunity(
                    bill_ref=bill.bill_ref,
                    vendor=bill.vendor,
                    amount=bill.amount,
                    discount_amount=discount_amount,
                    pay_by=discount.pay_by,
                    days_accelerated=days_accelerated,
                    implied_annual_return_percent=implied,
                )
            )

    # DPO = (AP / credit purchases) * period days, when both are supplied.
    dpo: Decimal | None = None
    if parsed.credit_purchases_in_period is not None and parsed.period_days is not None:
        if parsed.credit_purchases_in_period > 0 and trade_classification_complete:
            dpo = (
                trade_outstanding
                / parsed.credit_purchases_in_period
                * parsed.period_days
            ).quantize(_DAYS_QUANTUM, rounding=ROUND_HALF_UP)

    largest_vendor: str | None = None
    largest_share: Decimal | None = None
    concentration = False
    if by_vendor and total_outstanding > 0:
        largest_vendor, largest_sum = max(by_vendor.items(), key=lambda kv: kv[1])
        largest_share = (largest_sum / total_outstanding).quantize(
            _SHARE_QUANTUM, rounding=ROUND_HALF_UP
        )
        concentration = largest_share >= _CONCENTRATION_THRESHOLD

    # Structural honesty first: these notes state what the number IS and can never
    # be pushed off the end of the list by incidental findings.
    notes: list[str] = []
    if is_floor:
        notes.append(
            "book covers invoiced bills only; payroll, rent, tax and other committed "
            "un-invoiced obligations are absent — treat the total as a floor"
        )
    else:
        notes.append(
            "caller asserts the book includes committed un-invoiced obligations"
        )
    notes.append(
        "overdue balances are obligations you were late paying, not savings; "
        "settling late risks vendor terms"
    )
    settleable_overdue_total = overdue_total - on_hold_overdue
    if settleable_overdue_total > 0:
        notes.append(
            f"{settleable_overdue_total} {parsed.currency} is past due and not on hold; "
            "clear it before it "
            "damages supplier relationships"
        )
    if dpo is None:
        dpo_inputs_supplied = (
            parsed.credit_purchases_in_period is not None
            and parsed.period_days is not None
        )
        if dpo_inputs_supplied and not trade_classification_complete:
            notes.append(
                "DPO not computed; classify every bill's trade_credit status so payroll, "
                "rent and tax are not mistaken for supplier credit"
            )
        elif dpo_inputs_supplied:
            notes.append(
                "DPO not computed; credit_purchases_in_period must be greater than zero"
            )
        else:
            notes.append(
                "DPO not computed; supply credit_purchases_in_period and period_days to measure it"
            )
    if critical_overdue:
        named = ", ".join(name[:40] for name in critical_overdue[:3])
        more = f" (+{len(critical_overdue) - 3} more)" if len(critical_overdue) > 3 else ""
        notes.append(
            f"overdue bills sit with critical vendors: {named}{more} — "
            "interruption here halts operations"
        )
    if critical_on_hold:
        named = ", ".join(name[:40] for name in critical_on_hold[:3])
        more = (
            f" (+{len(critical_on_hold) - 3} more)"
            if len(critical_on_hold) > 3
            else ""
        )
        notes.append(
            f"held overdue bills involve critical vendors: {named}{more} — resolve "
            "the dispute or reserve for it; a hold is not permission to pay blindly"
        )
    if len(critical_overdue) > _MAX_LISTED_CRITICAL:
        notes.append(
            f"{len(critical_overdue)} critical vendors hold overdue bills; only the "
            f"first {_MAX_LISTED_CRITICAL} are listed in critical_vendors_overdue"
        )
    if on_hold > 0:
        notes.append(
            f"{on_hold} {parsed.currency} is on hold (disputed/withheld) but still "
            "counted; a dispute you lose is still payable — resolve it or reserve for it"
        )
    if discounts:
        best = max(discounts, key=lambda d: d.implied_annual_return_percent)
        notes.append(
            f"{len(discounts)} early-payment discount(s) still open, best "
            f"{best.implied_annual_return_percent}% annualized — worth taking only "
            "if the cash floor allows paying early"
        )
    if expired_discounts:
        notes.append(
            f"{expired_discounts} early-payment discount(s) have already lapsed"
        )
    if held_discounts:
        notes.append(
            f"{held_discounts} open discount(s) sit on held bills and are not priced; "
            "resolve the dispute before considering early payment"
        )
    if concentration and largest_vendor is not None and largest_share is not None:
        pct = (largest_share * 100).quantize(Decimal("0.1"))
        # Bound the vendor name so the note can never exceed ShortText (<=300).
        name = largest_vendor if len(largest_vendor) <= 80 else largest_vendor[:77] + "..."
        notes.append(
            f"payables are concentrated: {pct}% owed to '{name}' — that vendor "
            "holds the supply leverage"
        )
    notes.append(
        "upcoming bills are outflows; leaving them out of the forecast flatters cash "
        "(the dangerous direction)"
    )

    assessment = PayablesAssessment(
        assessment_ref=parsed.assessment_ref,
        as_of=parsed.as_of,
        currency=parsed.currency,
        total_outstanding=_quantized_money(total_outstanding),
        overdue_total=_quantized_money(overdue_total),
        on_hold_total=_quantized_money(on_hold),
        on_hold_overdue_total=_quantized_money(on_hold_overdue),
        trade_payables_outstanding=(
            _quantized_money(trade_outstanding)
            if trade_classification_complete
            else None
        ),
        obligations_are_floor=is_floor,
        aging=AgingBuckets(
            not_yet_due=_quantized_money(not_yet_due),
            days_0_30=_quantized_money(d_0_30),
            days_31_60=_quantized_money(d_31_60),
            days_61_90=_quantized_money(d_61_90),
            days_90_plus=_quantized_money(d_90_plus),
        ),
        dpo_days=dpo,
        largest_vendor=largest_vendor,
        largest_vendor_share=largest_share,
        concentration_flag=concentration,
        horizon_weeks=horizon,
        payments_within_horizon=_quantized_money(within_horizon_total),
        expected_payments=tuple(payments),
        discount_opportunities=tuple(discounts),
        critical_vendors_overdue=tuple(critical_overdue)[:_MAX_LISTED_CRITICAL],
        critical_vendors_overdue_count=len(critical_overdue),
        critical_vendor_overdue_total=_quantized_money(critical_overdue_total),
        critical_vendors_on_hold=tuple(critical_on_hold)[:_MAX_LISTED_CRITICAL],
        critical_vendors_on_hold_count=len(critical_on_hold),
        notes=tuple(dict.fromkeys(notes))[:16],
    )
    digest = _stable_digest(
        assessment.model_dump(mode="json", exclude={"assessment_digest"})
    )
    return assessment.model_copy(update={"assessment_digest": digest})


# ---------------------------------------------------------------------------
# Executable primitive
# ---------------------------------------------------------------------------


class AssessPayablesPrimitive(
    BusinessProcessPrimitive[AssessPayablesInput, PayablesAssessment]
):
    """Age accounts payable, compute DPO, and schedule expected payments."""

    primitive_ref = "accounting.assess_payables"
    version = "2.0.0"
    title = "Assess accounts payable"
    description = (
        "Age the open bill book by days past due (not-yet-due / 0-30 / 31-60 / "
        "61-90 / 90+), total what is owed, compute DPO when credit purchases and "
        "a period are supplied, flag single-vendor concentration, and emit a "
        "per-bill expected payment schedule that feeds the 13-week cash-flow "
        "forecast's outflow side, and price still-open early-payment discounts "
        "as an implied annual return. Nothing is written off: bills the caller "
        "holds stay in the total and on the calendar because a dispute you lose "
        "is still payable, overdue is a late obligation rather than a saving, "
        "and unless the caller asserts committed un-invoiced obligations are "
        "included the total is reported as a floor on what is owed, never a "
        "complete measurement. Overdue bills to a vendor the caller marks "
        "critical are escalated by name."
    )
    input_model = AssessPayablesInput
    output_model = PayablesAssessment
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs = {
        "assessment_ref": "ap-example",
        "as_of": "2026-08-02T00:00:00Z",
        "currency": "USD",
        "credit_purchases_in_period": "240000.00",
        "period_days": 90,
        "horizon_weeks": 13,
        "book_completeness": "invoices_only",
        "bills": (
            {
                "bill_ref": "BILL-5001",
                "vendor": "Cloud Infrastructure Co",
                "amount": "36000.00",
                "due_at": "2026-08-18T00:00:00Z",
                "trade_credit": True,
                "early_payment_discount": {
                    "discount_percent": "2.00",
                    "pay_by": "2026-08-04T00:00:00Z",
                },
            },
            {
                "bill_ref": "BILL-4980",
                "vendor": "Contract Manufacturing Ltd",
                "amount": "52000.00",
                "due_at": "2026-07-12T00:00:00Z",
                "trade_credit": True,
                "critical_vendor": True,
            },
            {
                "bill_ref": "BILL-4975",
                "vendor": "Cloud Infrastructure Co",
                "amount": "8000.00",
                "due_at": "2026-05-05T00:00:00Z",
                "trade_credit": True,
            },
            {
                "bill_ref": "BILL-4960",
                "vendor": "Disputed Freight Inc",
                "amount": "6000.00",
                "due_at": "2026-06-30T00:00:00Z",
                "trade_credit": True,
                "on_hold": True,
            },
        ),
    }

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: AssessPayablesInput,
    ) -> PrimitiveExecutionResult[PayablesAssessment]:
        try:
            assessment = build_payables_assessment(inputs)
        except ValueError as exc:
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.FAILED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary=f"payables assessment rejected: {exc}",
                output=None,
            )
        floor = " (floor)" if assessment.obligations_are_floor else ""
        dpo = (
            f", DPO {assessment.dpo_days}d"
            if assessment.dpo_days is not None
            else ""
        )
        return PrimitiveExecutionResult[PayablesAssessment](
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                f"{assessment.assessment_ref}: {assessment.total_outstanding} "
                f"{assessment.currency} owed{floor} ({assessment.overdue_total} "
                f"overdue){dpo}."
            ),
            output=assessment,
            events=[
                PrimitiveEvent(
                    type="accounting.payables_assessed",
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
                    summary="Aging and payment schedule; overdue is late, not free.",
                )
            ],
        )


__all__ = [
    "PAYABLES_ASSESSMENT_SCHEMA",
    "AgingBuckets",
    "AssessPayablesInput",
    "AssessPayablesPrimitive",
    "DiscountOpportunity",
    "EarlyPaymentDiscount",
    "ExpectedPayment",
    "OutstandingBill",
    "PayablesAssessment",
    "PayablesError",
    "build_payables_assessment",
]
