"""Tax set-aside estimator: the reserve a startup must not forget.

A fast-growing company that spends the cash it owes the tax authority is a
company that gets a nasty surprise. This is the accountant reserving against
that: given the taxable bases for a period it estimates the cash to set aside
for corporate income tax, sales tax (GST/HST in Canada, GST in Australia), and
payroll tax, and totals it as a reservation against otherwise-spendable cash. It
pairs with the runway engine — a tax set-aside is committed future cash, so true
runway is shorter than a naive burn calc suggests.

This is the highest-fabrication-risk corner of the accountant, so it is built
**rate-driven and honest**:

- **The caller's rate wins.** The engine computes ``basis * rate``; the rate is
  the operator's to supply (from their accountant). Indicative default rates
  exist for the flagship cases, but they are labeled ``indicative_default``,
  carry an official source, and shout "confirm with a qualified accountant" —
  they are a starting point, never an assertion of what you owe.
- **Never a promise, never advice.** Every result carries a standing disclaimer
  and ``verification_required``. Thresholds, small-business rates, provincial /
  state variation, and eligibility all move the real number; the engine says so.
- **Skip, don't guess.** A tax type with neither an override nor a default
  (payroll tax is too state/entity-specific to default) is *skipped with a
  reason*, and the provision is marked incomplete — never filled with a made-up
  rate.
- **Sales tax is not income.** The output states plainly that a sales-tax
  set-aside is money collected on the authority's behalf, not the company's.

Canada and Australia to start, matching the grant engine's focus. Holds no
keyring, does no I/O.
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

TAX_PROVISION_SCHEMA = "lightbulb.tax_provision.v1"

_MONEY_QUANTUM = Decimal("0.01")
_RATE_QUANTUM = Decimal("0.000001")

_PORTABLE_REF_PATTERN = r"^[a-z][a-z0-9_-]{0,63}$"
_CURRENCY_PATTERN = r"^[A-Z]{3}$"

Jurisdiction = Literal["CA", "AU"]
TaxType = Literal["corporate_income", "sales_tax", "payroll_tax"]
RateSource = Literal["caller_supplied", "indicative_default"]

_DISCLAIMER = (
    "Estimate only — not tax advice. Rates, thresholds, small-business and "
    "base-rate eligibility, and provincial/state variation all change the real "
    "figure; sales-tax set-asides are cash collected on the authority's behalf, "
    "not income. Confirm your applicable rates with a qualified accountant or "
    "the tax authority before relying on these numbers."
)


class TaxProvisionError(ValueError):
    """The tax-provision inputs cannot produce an honest estimate."""


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
LongText = Annotated[
    str,
    StringConstraints(min_length=1, max_length=600),
    AfterValidator(_bounded_text),
]
PortableRef = Annotated[str, StringConstraints(pattern=_PORTABLE_REF_PATTERN)]
CurrencyCode = Annotated[str, StringConstraints(pattern=_CURRENCY_PATTERN)]
HttpsUrl = Annotated[str, StringConstraints(pattern=r"^https://[^\s]{5,300}$")]


def _normalized_timestamp(value: str) -> str:
    clean = value.strip()
    try:
        parsed = datetime.fromisoformat(clean.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamp must be valid ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must include a UTC offset")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _decimal(value: Any, *, quantum: Decimal | None = None) -> Decimal:
    if not isinstance(value, (str, Decimal, int, float)) or isinstance(value, bool):
        raise ValueError("decimal values must be supplied as strings or JSON numbers")
    lexical = str(value)
    if len(lexical) > 48 or lexical != lexical.strip():
        raise ValueError("value must use bounded decimal notation")
    try:
        parsed = Decimal(lexical)
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("value must be a finite decimal") from exc
    if not parsed.is_finite() or parsed < 0:
        raise ValueError("value must be a finite, non-negative decimal")
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
# Indicative default rates — labeled, sourced, a starting point only.
#
# These are deliberately conservative headline rates for the flagship case.
# The comment on each says what moves it; the engine attaches the source and
# demands verification. Payroll tax has NO default (too state/entity-specific).
# ---------------------------------------------------------------------------

_INDICATIVE_DEFAULTS: dict[tuple[str, str], tuple[str, str, str]] = {
    ("CA", "corporate_income"): (
        "0.150000",
        "https://www.canada.ca/en/revenue-agency/services/tax/businesses/topics/corporations/corporation-tax-rates.html",
        "federal general rate; the CCPC small-business rate (~9% federal) and "
        "provincial rates (roughly 0-16%) change the effective rate materially — "
        "confirm your combined rate",
    ),
    ("CA", "sales_tax"): (
        "0.050000",
        "https://www.canada.ca/en/revenue-agency/services/tax/businesses/topics/gst-hst-businesses.html",
        "federal GST; HST provinces charge 13-15% combined — confirm your province",
    ),
    ("AU", "corporate_income"): (
        "0.250000",
        "https://www.ato.gov.au/businesses-and-organisations/corporate-tax-measures-and-assurance/changes-to-company-tax-rates",
        "base rate entity (aggregated turnover under AUD $50M and passive-income "
        "test met); otherwise 30% — confirm your rate",
    ),
    ("AU", "sales_tax"): (
        "0.100000",
        "https://www.ato.gov.au/businesses-and-organisations/gst-excise-and-indirect-taxes/gst",
        "GST standard rate; confirm registration status and any GST-free supplies",
    ),
}


class ResolvedRate(_StrictModel):
    rate: Decimal = Field(ge=0, le=1)
    source: RateSource
    reference_url: HttpsUrl | None = None
    note: LongText

    @field_validator("rate", mode="before")
    @classmethod
    def _rate_decimal(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_RATE_QUANTUM)


class TaxBasisInput(_StrictModel):
    tax_type: TaxType
    basis_amount: Decimal = Field(ge=0)
    rate_override: Decimal | None = Field(default=None, ge=0, le=1)
    basis_label: ShortText | None = None

    @field_validator("basis_amount", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_MONEY_QUANTUM)

    @field_validator("rate_override", mode="before")
    @classmethod
    def _rate(cls, value: Any) -> Decimal | None:
        if value is None:
            return None
        return _decimal(value, quantum=_RATE_QUANTUM)


class TaxObligation(_StrictModel):
    tax_type: TaxType
    taxable_basis: Decimal = Field(ge=0)
    rate: ResolvedRate
    set_aside: Decimal = Field(ge=0)

    @field_validator("taxable_basis", "set_aside", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_MONEY_QUANTUM)


class SkippedBasis(_StrictModel):
    tax_type: TaxType
    reason: ShortText


class TaxProvision(_StrictModel):
    schema_id: Literal["lightbulb.tax_provision.v1"] = Field(
        default=TAX_PROVISION_SCHEMA,
        alias="schema",
    )
    provision_ref: PortableRef
    as_of: str
    currency: CurrencyCode
    jurisdiction: Jurisdiction
    period_label: ShortText
    obligations: tuple[TaxObligation, ...] = Field(default_factory=tuple)
    skipped: tuple[SkippedBasis, ...] = Field(default_factory=tuple)
    total_set_aside: Decimal = Field(ge=0)
    uses_indicative_defaults: bool
    complete: bool
    disclaimer: LongText = _DISCLAIMER
    notes: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=10)
    provision_digest: str = "0" * 64

    @field_validator("as_of")
    @classmethod
    def _valid_as_of(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator("total_set_aside", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_MONEY_QUANTUM)

    @field_validator("obligations", "skipped", "notes", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


class EstimateTaxSetAsideInput(_StrictModel):
    provision_ref: PortableRef
    as_of: str
    currency: CurrencyCode
    jurisdiction: Jurisdiction
    period_label: ShortText
    bases: tuple[TaxBasisInput, ...] = Field(min_length=1, max_length=20)

    @field_validator("as_of")
    @classmethod
    def _valid_as_of(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator("bases", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _immutable_sequence(value)


def _resolve_rate(
    jurisdiction: str, basis: TaxBasisInput
) -> ResolvedRate | None:
    if basis.rate_override is not None:
        return ResolvedRate(
            rate=basis.rate_override,
            source="caller_supplied",
            reference_url=None,
            note="rate supplied by the caller",
        )
    default = _INDICATIVE_DEFAULTS.get((jurisdiction, basis.tax_type))
    if default is None:
        return None
    rate, url, note = default
    return ResolvedRate(
        rate=rate, source="indicative_default", reference_url=url, note=note
    )


def estimate_tax_set_aside(
    inputs: EstimateTaxSetAsideInput | Mapping[str, Any],
) -> TaxProvision:
    """Estimate the cash to reserve for tax across the supplied bases.

    Each basis's set-aside is ``basis * rate``, where the rate is the caller's
    override if given, else an indicative default for the jurisdiction/tax type.
    A basis with neither is skipped with a reason and the provision is marked
    incomplete — never filled with a guessed rate.
    """

    parsed = (
        inputs
        if isinstance(inputs, EstimateTaxSetAsideInput)
        else EstimateTaxSetAsideInput.model_validate(inputs)
    )

    obligations: list[TaxObligation] = []
    skipped: list[SkippedBasis] = []
    uses_defaults = False
    seen: set[str] = set()
    notes: list[str] = []

    for basis in parsed.bases:
        if basis.tax_type in seen:
            raise TaxProvisionError(
                f"tax type {basis.tax_type!r} appears more than once; combine bases"
            )
        seen.add(basis.tax_type)
        rate = _resolve_rate(parsed.jurisdiction, basis)
        if rate is None:
            skipped.append(
                SkippedBasis(
                    tax_type=basis.tax_type,
                    reason=(
                        "no indicative default for this jurisdiction/tax type; "
                        "supply rate_override"
                    ),
                )
            )
            continue
        if rate.source == "indicative_default":
            uses_defaults = True
        set_aside = _quantized_money(basis.basis_amount * rate.rate)
        obligations.append(
            TaxObligation(
                tax_type=basis.tax_type,
                taxable_basis=basis.basis_amount,
                rate=rate,
                set_aside=set_aside,
            )
        )

    if not obligations:
        raise TaxProvisionError(
            "no tax obligation could be estimated; supply a rate_override for at "
            "least one basis (unknown is not zero)"
        )

    total = _quantized_money(sum((o.set_aside for o in obligations), Decimal("0")))
    complete = not skipped
    if uses_defaults:
        notes.append("some rates are indicative defaults; confirm before relying on them")
    if skipped:
        notes.append(
            "some bases were skipped for lack of a rate; the total is a lower bound"
        )
    if any(o.tax_type == "sales_tax" for o in obligations):
        notes.append("sales-tax set-aside is collected on the authority's behalf, not income")

    provision = TaxProvision(
        provision_ref=parsed.provision_ref,
        as_of=parsed.as_of,
        currency=parsed.currency,
        jurisdiction=parsed.jurisdiction,
        period_label=parsed.period_label,
        obligations=tuple(obligations),
        skipped=tuple(skipped),
        total_set_aside=total,
        uses_indicative_defaults=uses_defaults,
        complete=complete,
        notes=tuple(dict.fromkeys(notes))[:10],
    )
    digest = _stable_digest(
        provision.model_dump(mode="json", exclude={"provision_digest"})
    )
    return provision.model_copy(update={"provision_digest": digest})


def tax_rate_reference() -> tuple[dict[str, Any], ...]:
    """Discoverable list of indicative default rates and their sources."""

    return tuple(
        {
            "jurisdiction": jurisdiction,
            "tax_type": tax_type,
            "indicative_rate": rate,
            "reference_url": url,
            "note": note,
            "status": "indicative_default_verify_at_source",
        }
        for (jurisdiction, tax_type), (rate, url, note) in sorted(
            _INDICATIVE_DEFAULTS.items()
        )
    )


# ---------------------------------------------------------------------------
# Executable primitive
# ---------------------------------------------------------------------------


_EXAMPLE_INPUT: dict[str, Any] = {
    "provision_ref": "q3-tax-example",
    "as_of": "2026-09-30T00:00:00Z",
    "currency": "CAD",
    "jurisdiction": "CA",
    "period_label": "Q3 2026",
    "bases": [
        {"tax_type": "corporate_income", "basis_amount": "80000.00"},
        {"tax_type": "sales_tax", "basis_amount": "300000.00"},
        {"tax_type": "payroll_tax", "basis_amount": "120000.00", "rate_override": "0.0495"},
    ],
}


class EstimateTaxSetAsidePrimitive(
    BusinessProcessPrimitive[EstimateTaxSetAsideInput, TaxProvision]
):
    """Estimate the cash to reserve for tax across the period's bases."""

    primitive_ref = "accounting.estimate_tax_set_aside"
    version = "1.0.0"
    title = "Estimate tax set-aside"
    description = (
        "Estimate the cash to reserve for corporate income tax, sales tax "
        "(GST/HST in Canada, GST in Australia), and payroll tax from the "
        "period's taxable bases. Each set-aside is basis x rate, using the "
        "caller's rate override if supplied, else an indicative default that "
        "carries an official source and must be verified. A tax type with no "
        "rate is skipped and the provision marked incomplete — never guessed. "
        "Estimate only, not tax advice; sales-tax set-asides are collected on "
        "the authority's behalf, not income."
    )
    input_model = EstimateTaxSetAsideInput
    output_model = TaxProvision
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs = _EXAMPLE_INPUT

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: EstimateTaxSetAsideInput,
    ) -> PrimitiveExecutionResult[TaxProvision]:
        try:
            provision = estimate_tax_set_aside(inputs)
        except ValueError as exc:
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.FAILED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary=f"tax provision rejected: {exc}",
                output=None,
            )
        return PrimitiveExecutionResult[TaxProvision](
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                f"Tax set-aside {provision.provision_ref}: "
                f"{provision.total_set_aside} {provision.currency} across "
                f"{len(provision.obligations)} tax type(s)."
            ),
            output=provision,
            events=[
                PrimitiveEvent(
                    type="accounting.tax_set_aside_estimated",
                    payload={
                        "provision_ref": provision.provision_ref,
                        "total_set_aside": str(provision.total_set_aside),
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="deterministic_plan",
                    summary="Estimate only; confirm rates with a qualified accountant.",
                )
            ],
        )


__all__ = [
    "TAX_PROVISION_SCHEMA",
    "EstimateTaxSetAsideInput",
    "EstimateTaxSetAsidePrimitive",
    "ResolvedRate",
    "SkippedBasis",
    "TaxBasisInput",
    "TaxObligation",
    "TaxProvision",
    "TaxProvisionError",
    "estimate_tax_set_aside",
    "tax_rate_reference",
]
