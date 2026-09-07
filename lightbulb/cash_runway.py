"""Cash & runway engine: the financial guardrail of the AI business.

The profit engine (``growth_profit``) knows what a unit is worth; this module
knows whether the business can afford to *acquire* more of them. It turns
per-connector cash-basis flow observations (bank feeds, Stripe payouts, Xero /
QuickBooks cash summaries) into one sealed runway snapshot — observed net burn,
cash on hand, and the months of runway they imply — and then derives the single
number the rest of the network must obey: the **budget envelope**, the
discretionary cash that may be committed without breaching a runway floor.

Every allocation, experiment budget, and acquisition push elsewhere in the
engine is per-unit or per-opportunity; none of them can see the aggregate burn
or how close the business is to the wall. This module is that missing
constraint. It is deliberately conservative: it never turns an optimistic
projection into permission to spend.

Design rules enforced here (mirroring the profit engine's discipline):

- **Evidence is sealed.** Runway is computed from :class:`CashLedgerEvidence`
  envelopes minted by a trusted host; verification recomputes the keyed HMAC,
  so copying a visible scope digest onto fabricated cash numbers is
  insufficient.
- **Unknown is not zero.** A flow the evidence does not carry is *unknown*, not
  zero. If inflows are unobserved, net burn is incomplete and runway is
  ``unknown`` — never silently treated as break-even. Cash on hand with no
  balance evidence and no caller override is ``unknown``, and a business with
  unknown runway gets no budget envelope.
- **Runway is an observed projection, never a forecast.** Net monthly burn is
  the measured net outflow over the observed window, normalized to a month. The
  runway extends that *observed* rate forward and says so; when independent
  periods exist it reports a measured best/worst band, and it never invents a
  distribution to look precise.
- **One currency, cash basis only.** Off-currency evidence is *excluded with a
  reason*; the whole engine is cash-recorded, so accrual/P&L numbers must never
  be fed here (the host maps only cash reports to these capabilities).
- **The floor is law.** :func:`derive_budget_envelope` sizes discretionary
  spend so that runway stays at or above the caller's floor; when the business
  is already below the floor the envelope is a required *cut*, and the shortfall
  is named exactly. There is no code path from "we want to spend" to a budget
  that breaches the floor.

Naming note: this is a peer of the ``growth_*`` money modules but is scoped to
the *whole business*, not the growth funnel — hence ``cash_runway`` rather than
``growth_cash``. It imports only stable primitives and the workflow scope; it
does no I/O and holds no keyring.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping
from datetime import datetime, timezone
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from typing import Annotated, Any, Literal, Protocol

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from .dynamic_workflows import DynamicWorkflowScope
from .primitive_runtime import (
    BusinessProcessPrimitive,
    PrimitiveEvent,
    PrimitiveEvidence,
    PrimitiveExecutionContext,
    PrimitiveExecutionResult,
    PrimitiveExecutionStatus,
)

CASH_LEDGER_EVIDENCE_SCHEMA = "lightbulb.cash_ledger_evidence.v1"
CASH_RUNWAY_SNAPSHOT_SCHEMA = "lightbulb.cash_runway_snapshot.v1"
CASH_BUDGET_ENVELOPE_SCHEMA = "lightbulb.cash_budget_envelope.v1"
CASH_RUNWAY_ASSESSMENT_SCHEMA = "lightbulb.cash_runway_assessment.v1"

_CASH_EVIDENCE_HMAC_DOMAIN = CASH_LEDGER_EVIDENCE_SCHEMA
_RUNWAY_SNAPSHOT_HMAC_DOMAIN = CASH_RUNWAY_SNAPSHOT_SCHEMA
_BUDGET_ENVELOPE_HMAC_DOMAIN = CASH_BUDGET_ENVELOPE_SCHEMA

_MAX_CASH_EVIDENCE = 200
_MAX_ASSESSMENT_OPPORTUNITIES = 20

_MONEY_QUANTUM = Decimal("0.01")
_MULTIPLE_QUANTUM = Decimal("0.01")
_DAYS_PER_MONTH = Decimal("30.4375")

# Runway beyond this is reported as "beyond horizon" rather than a precise
# multiple: a five-year runway derived from one month of burn is not a fact
# worth six significant figures, and treating it as one invites false comfort.
_MAX_REPORTED_RUNWAY_MONTHS = Decimal("120.00")

_PORTABLE_REF_PATTERN = r"^[a-z][a-z0-9_-]{0,63}$"
_OPERATION_REF_PATTERN = r"^[a-z][a-z0-9_.:-]{0,159}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_CURRENCY_PATTERN = r"^[A-Z]{3}$"

CashProvider = Literal["bank", "stripe", "xero", "quickbooks"]

# The host maps only *cash* reports to these capabilities. The whole engine is
# cash-basis; feeding an accrual P&L here would be a host contract violation the
# numbers alone cannot detect, so the capability allow-list is the guard.
#
# Capability names track the platform's REAL connector tools (verified against
# the SDK tool registry, 2026-08-21). There is no bank/Plaid connector, so the
# truest cash source — the bank statement — arrives as an operator/accountant
# import (`bank.statement_import`), not a live feed. Stripe payouts are internal
# balance->bank transfers, not business burn, so they are deliberately absent:
# Stripe sees revenue in and fees out but never payroll/rent/opex, so Stripe
# alone cannot measure burn (the engine flags the missing outflows as a ceiling).
_SOURCE_CAPABILITIES: dict[str, frozenset[str]] = {
    "bank": frozenset({"bank.statement_import"}),
    "stripe": frozenset({"stripe.list_balance_transactions"}),
    "xero": frozenset({"xero.cash_flow_report"}),
    "quickbooks": frozenset({"quickbooks.cash_flow_report"}),
}

CashMetricName = Literal[
    "cash_inflows",
    "cash_outflows",
    "ending_cash_balance",
]

_CASH_METRICS: tuple[CashMetricName, ...] = (
    "cash_inflows",
    "cash_outflows",
    "ending_cash_balance",
)

_FLOW_METRICS = frozenset({"cash_inflows", "cash_outflows"})

RunwayComponentName = Literal[
    "monthly_inflow",
    "gross_monthly_outflow",
    "net_monthly_burn",
    "cash_on_hand",
    "runway_months",
]

_COMPONENT_ORDER: tuple[RunwayComponentName, ...] = (
    "monthly_inflow",
    "gross_monthly_outflow",
    "net_monthly_burn",
    "cash_on_hand",
    "runway_months",
)

CashExclusionReason = Literal[
    "currency_mismatch",
    "future_observation",
    "stale_observation",
    "unverified_evidence",
    "overlapping_window",
]

EvidenceScopeStatus = Literal[
    "caller_supplied_unverified",
    "host_hmac_verified",
]

CashOnHandSource = Literal["ledger_balance", "caller_supplied", "unknown"]

RunwayStatus = Literal["burning", "not_burning", "unknown"]

BurnBandBasis = Literal["observed_across_periods", "single_estimate"]

BudgetStatus = Literal[
    "healthy_surplus",
    "at_floor",
    "below_floor",
    "not_burning",
    "unknown",
]

RunwaySeverity = Literal["healthy", "caution", "danger", "unknown"]

RunwayOpportunityKind = Literal[
    "reduce_burn",
    "extend_runway",
    "raise_capital",
    "collect_evidence",
]

ReferenceQuality = Literal["policy_floor", "default_heuristic"]


class CashRunwayValidationError(ValueError):
    """Cash evidence, a runway snapshot, or a budget envelope broke the contract."""


def _stable_digest(value: Any) -> str:
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
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
OperationRef = Annotated[str, StringConstraints(pattern=_OPERATION_REF_PATTERN)]
Sha256Digest = Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)]
CurrencyCode = Annotated[str, StringConstraints(pattern=_CURRENCY_PATTERN)]


def _parse_timestamp(value: str) -> datetime:
    clean = value.strip()
    try:
        parsed = datetime.fromisoformat(clean.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamp must be valid ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def _normalized_timestamp(value: str) -> str:
    return _parse_timestamp(value).isoformat().replace("+00:00", "Z")


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
    if not parsed.is_finite():
        raise ValueError("value must be a finite decimal")
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


def _quantized_multiple(value: Decimal) -> Decimal:
    return value.quantize(_MULTIPLE_QUANTUM, rounding=ROUND_HALF_UP)


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=False,
        serialize_by_alias=True,
        strict=True,
    )


class ExactScopeDigestProvider(Protocol):
    """Host-held keyed scope digester; raw authority never enters artifacts."""

    active_key_id: str

    def exact_scope_digest(
        self,
        *,
        key_id: str,
        scope: DynamicWorkflowScope,
    ) -> str: ...

    def sign(self, key_id: str, domain: str, payload: Any) -> bytes: ...


def _keyring_signature(
    scope_keyring: ExactScopeDigestProvider,
    *,
    key_id: str,
    domain: str,
    payload: Any,
) -> str:
    try:
        return scope_keyring.sign(key_id, domain, payload).hex()
    except CashRunwayValidationError:
        raise
    except Exception as exc:
        raise CashRunwayValidationError(
            "the cash-runway signing key is unavailable"
        ) from exc


def _keyring_scope_digest(
    scope_keyring: ExactScopeDigestProvider,
    *,
    key_id: str,
    scope: DynamicWorkflowScope,
) -> str:
    try:
        return scope_keyring.exact_scope_digest(key_id=key_id, scope=scope)
    except CashRunwayValidationError:
        raise
    except Exception as exc:
        raise CashRunwayValidationError(
            "the cash-runway signing key is unavailable"
        ) from exc


def _workflow_scope(
    scope: DynamicWorkflowScope | Mapping[str, Any],
) -> DynamicWorkflowScope:
    if isinstance(scope, DynamicWorkflowScope):
        return scope
    return DynamicWorkflowScope.model_validate(scope)


# ---------------------------------------------------------------------------
# Cash-ledger evidence
# ---------------------------------------------------------------------------


class CashFlowMetrics(_StrictModel):
    """Normalized cash-basis values for one observation window.

    Every field is optional because unknown is not zero: a source that cannot
    see a flow must not claim it. ``ending_cash_balance`` is a point-in-time
    balance at ``window_end`` (from a balance report), not a flow.
    """

    cash_inflows: Decimal | None = Field(default=None, ge=0)
    cash_outflows: Decimal | None = Field(default=None, ge=0)
    ending_cash_balance: Decimal | None = Field(default=None, ge=0)

    @field_validator(
        "cash_inflows",
        "cash_outflows",
        "ending_cash_balance",
        mode="before",
    )
    @classmethod
    def _money_decimals(cls, value: Any) -> Decimal | None:
        if value is None:
            return None
        return _decimal(value, quantum=_MONEY_QUANTUM)

    @model_validator(mode="after")
    def _at_least_one_metric(self) -> "CashFlowMetrics":
        if all(value is None for value in self.model_dump(mode="python").values()):
            raise ValueError("at least one cash metric is required")
        return self


class CashLedgerEvidence(_StrictModel):
    """One sealed connector cash observation admissible into a runway snapshot."""

    observation_ref: PortableRef
    connector_account_ref: OperationRef
    provider: CashProvider
    source_capability: str = Field(
        min_length=3,
        max_length=160,
        pattern=r"^[a-z][a-z0-9_-]{0,63}\.[a-z][a-z0-9_.-]{0,127}$",
    )
    currency: CurrencyCode
    observed_at: str
    window_start: str
    window_end: str
    metrics: CashFlowMetrics
    evidence_digest: Sha256Digest
    receipt_key_id: str | None = Field(
        default=None,
        min_length=8,
        max_length=80,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{7,79}$",
    )
    exact_scope_digest: Sha256Digest | None = None
    evidence_hmac: Sha256Digest | None = None

    @field_validator("observed_at", "window_start", "window_end")
    @classmethod
    def _valid_timestamp(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @model_validator(mode="after")
    def _valid_source_and_window(self) -> "CashLedgerEvidence":
        if self.source_capability not in _SOURCE_CAPABILITIES[self.provider]:
            raise ValueError(
                "source_capability is not an allowed evidence source for provider"
            )
        if _parse_timestamp(self.window_end) < _parse_timestamp(self.window_start):
            raise ValueError("evidence window_end must not precede window_start")
        if _parse_timestamp(self.observed_at) < _parse_timestamp(self.window_end):
            raise ValueError("observed_at must not precede the measured window")
        binding_fields = (
            self.receipt_key_id,
            self.exact_scope_digest,
            self.evidence_hmac,
        )
        if any(value is not None for value in binding_fields) and not all(
            value is not None for value in binding_fields
        ):
            raise ValueError(
                "cash evidence attestation fields must be supplied together"
            )
        return self

    @property
    def is_attested(self) -> bool:
        return self.evidence_hmac is not None

    def hmac_payload(self) -> dict[str, Any]:
        """Return the complete canonical observation covered by host HMAC."""

        return self.model_dump(
            mode="json",
            exclude={"evidence_hmac"},
            exclude_none=True,
        )


def mint_cash_ledger_evidence(
    value: CashLedgerEvidence | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ExactScopeDigestProvider,
    scope_key_id: str | None = None,
) -> CashLedgerEvidence:
    """Seal one host-verified cash observation for runway use."""

    evidence = (
        value
        if isinstance(value, CashLedgerEvidence)
        else CashLedgerEvidence.model_validate(value)
    )
    if evidence.is_attested or evidence.receipt_key_id is not None:
        raise CashRunwayValidationError("cash evidence is already attested")
    workflow_scope = _workflow_scope(scope)
    key_id = scope_key_id or str(scope_keyring.active_key_id).strip()
    exact_scope_digest = _keyring_scope_digest(
        scope_keyring,
        key_id=key_id,
        scope=workflow_scope,
    )
    payload = evidence.model_dump(mode="python", exclude_none=True)
    payload.update(
        {
            "receipt_key_id": key_id,
            "exact_scope_digest": exact_scope_digest,
            "evidence_hmac": "0" * 64,
        }
    )
    draft = CashLedgerEvidence.model_validate(payload)
    signature = _keyring_signature(
        scope_keyring,
        key_id=key_id,
        domain=_CASH_EVIDENCE_HMAC_DOMAIN,
        payload=draft.hmac_payload(),
    )
    sealed = draft.model_dump(mode="python", exclude_none=True)
    sealed["evidence_hmac"] = signature
    return CashLedgerEvidence.model_validate(sealed)


def _evidence_attestation_matches(
    evidence: CashLedgerEvidence,
    *,
    scope: DynamicWorkflowScope,
    scope_keyring: ExactScopeDigestProvider,
) -> bool:
    if (
        evidence.receipt_key_id is None
        or evidence.exact_scope_digest is None
        or evidence.evidence_hmac is None
    ):
        return False
    expected_scope_digest = _keyring_scope_digest(
        scope_keyring,
        key_id=evidence.receipt_key_id,
        scope=scope,
    )
    if not hmac.compare_digest(evidence.exact_scope_digest, expected_scope_digest):
        return False
    expected_hmac = _keyring_signature(
        scope_keyring,
        key_id=evidence.receipt_key_id,
        domain=_CASH_EVIDENCE_HMAC_DOMAIN,
        payload=evidence.hmac_payload(),
    )
    return hmac.compare_digest(evidence.evidence_hmac, expected_hmac)


def verify_cash_ledger_evidence(
    value: CashLedgerEvidence | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ExactScopeDigestProvider,
) -> CashLedgerEvidence:
    """Re-validate and verify one sealed cash envelope; raise on failure."""

    evidence = CashLedgerEvidence.model_validate(
        value.model_dump(mode="python")
        if isinstance(value, CashLedgerEvidence)
        else value
    )
    if not evidence.is_attested:
        raise CashRunwayValidationError("cash evidence carries no host attestation")
    workflow_scope = _workflow_scope(scope)
    if not _evidence_attestation_matches(
        evidence,
        scope=workflow_scope,
        scope_keyring=scope_keyring,
    ):
        raise CashRunwayValidationError("cash evidence attestation failed verification")
    return evidence


# ---------------------------------------------------------------------------
# Runway snapshot
# ---------------------------------------------------------------------------


class CashStalenessPolicy(_StrictModel):
    """Admission budget for evidence age and verification requirements."""

    max_evidence_age_hours: int = Field(default=1_440, ge=1, le=8_760)
    require_verified_evidence: bool = False


class RunwayComponent(_StrictModel):
    """One derived cash fact with explicit completeness and provenance."""

    name: RunwayComponentName
    unit: Literal["money", "money_per_month", "multiple"]
    value: Decimal
    complete: bool
    missing_inputs: tuple[CashMetricName, ...] = Field(default_factory=tuple)
    note: ShortText | None = None

    @field_validator("value", mode="before")
    @classmethod
    def _value_decimal(cls, value: Any) -> Decimal:
        return _decimal(value)

    @field_validator("missing_inputs", mode="before")
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _quantized_and_consistent(self) -> "RunwayComponent":
        quantum = _MULTIPLE_QUANTUM if self.unit == "multiple" else _MONEY_QUANTUM
        if self.value != self.value.quantize(quantum):
            raise ValueError("component values must be quantized to their unit")
        if self.complete and self.missing_inputs:
            raise ValueError("complete components cannot list missing inputs")
        if not self.complete and not self.missing_inputs:
            raise ValueError("incomplete components must name their missing inputs")
        return self


class CashMetricPresence(_StrictModel):
    metric: CashMetricName
    status: Literal["present", "unknown"]


class BurnBand(_StrictModel):
    """A measured best/worst runway range, or a single-estimate marker.

    ``observed_across_periods`` is populated only when two or more independent
    (non-overlapping) periods supply a full inflow+outflow pair, so the band is
    the *measured* spread of monthly burn, never an invented distribution.
    """

    basis: BurnBandBasis
    period_count: int = Field(ge=1)
    best_runway_months: Decimal | None = None
    worst_runway_months: Decimal | None = None

    @field_validator("best_runway_months", "worst_runway_months", mode="before")
    @classmethod
    def _multiple_decimals(cls, value: Any) -> Decimal | None:
        if value is None:
            return None
        return _decimal(value, quantum=_MULTIPLE_QUANTUM)

    @model_validator(mode="after")
    def _band_consistency(self) -> "BurnBand":
        if self.basis == "single_estimate":
            if self.best_runway_months is not None or self.worst_runway_months is not None:
                raise ValueError("a single-estimate band carries no bounds")
            if self.period_count != 1:
                raise ValueError("single_estimate implies exactly one period")
        else:
            if self.best_runway_months is None or self.worst_runway_months is None:
                raise ValueError("an observed band must carry both bounds")
            if self.period_count < 2:
                raise ValueError("observed_across_periods needs at least two periods")
            if self.worst_runway_months > self.best_runway_months:
                raise ValueError("worst runway must not exceed best runway")
        return self


class AdmittedCashEvidence(_StrictModel):
    observation_ref: PortableRef
    evidence_digest: Sha256Digest
    provider: CashProvider
    connector_account_ref: OperationRef
    window_start: str
    window_end: str
    verified: bool

    @field_validator("window_start", "window_end")
    @classmethod
    def _valid_timestamp(cls, value: str) -> str:
        return _normalized_timestamp(value)


class ExcludedCashEvidence(_StrictModel):
    observation_ref: PortableRef
    evidence_digest: Sha256Digest
    reason: CashExclusionReason


class CashRunwaySnapshot(_StrictModel):
    """Sealed runway state derived from admissible cash evidence."""

    schema_id: Literal["lightbulb.cash_runway_snapshot.v1"] = Field(
        default=CASH_RUNWAY_SNAPSHOT_SCHEMA,
        alias="schema",
    )
    runway_ref: PortableRef
    analysis_as_of: str
    currency: CurrencyCode
    evidence_scope_status: EvidenceScopeStatus
    staleness_policy: CashStalenessPolicy
    status: RunwayStatus
    observed_window_days: int = Field(ge=0)
    cash_on_hand_source: CashOnHandSource
    metric_presence: tuple[CashMetricPresence, ...]
    components: tuple[RunwayComponent, ...] = Field(default_factory=tuple)
    burn_band: BurnBand | None = None
    data_quality_notes: tuple[ShortText, ...] = Field(default_factory=tuple)
    admitted_evidence: tuple[AdmittedCashEvidence, ...] = Field(default_factory=tuple)
    excluded_evidence: tuple[ExcludedCashEvidence, ...] = Field(default_factory=tuple)
    runway_digest: Sha256Digest = "0" * 64
    receipt_key_id: str | None = Field(
        default=None,
        min_length=8,
        max_length=80,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{7,79}$",
    )
    exact_scope_digest: Sha256Digest | None = None
    runway_hmac: Sha256Digest | None = None

    @field_validator("analysis_as_of")
    @classmethod
    def _valid_analysis_time(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator(
        "metric_presence",
        "components",
        "data_quality_notes",
        "admitted_evidence",
        "excluded_evidence",
        mode="before",
    )
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _sealed_shape(self) -> "CashRunwaySnapshot":
        if tuple(item.metric for item in self.metric_presence) != _CASH_METRICS:
            raise ValueError("metric_presence must cover every cash metric in order")
        component_names = tuple(item.name for item in self.components)
        if len(set(component_names)) != len(component_names):
            raise ValueError("runway components must be unique")
        ordered = tuple(
            name for name in _COMPONENT_ORDER if name in set(component_names)
        )
        if component_names != ordered:
            raise ValueError("runway components must follow the canonical order")
        binding_fields = (
            self.receipt_key_id,
            self.exact_scope_digest,
            self.runway_hmac,
        )
        if any(value is not None for value in binding_fields) and not all(
            value is not None for value in binding_fields
        ):
            raise ValueError("runway attestation fields must be supplied together")
        if self.receipt_key_id is not None and (
            self.evidence_scope_status != "host_hmac_verified"
        ):
            raise ValueError("a sealed snapshot must report host_hmac_verified")
        return self

    @property
    def is_sealed(self) -> bool:
        return self.runway_hmac is not None

    def component(self, name: RunwayComponentName) -> RunwayComponent | None:
        for item in self.components:
            if item.name == name:
                return item
        return None

    def hmac_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            exclude={"runway_hmac"},
            exclude_none=True,
        )


class BuildRunwayInput(_StrictModel):
    analysis_as_of: str
    runway_ref: PortableRef
    currency: CurrencyCode
    evidence: tuple[CashLedgerEvidence, ...] = Field(
        min_length=1,
        max_length=_MAX_CASH_EVIDENCE,
    )
    cash_on_hand_override: Decimal | None = Field(default=None, ge=0)
    staleness_policy: CashStalenessPolicy = Field(default_factory=CashStalenessPolicy)

    @field_validator("analysis_as_of")
    @classmethod
    def _valid_analysis_time(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator("cash_on_hand_override", mode="before")
    @classmethod
    def _money_override(cls, value: Any) -> Decimal | None:
        if value is None:
            return None
        return _decimal(value, quantum=_MONEY_QUANTUM)

    @field_validator("evidence", mode="before")
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)


def _classify_cash_evidence(
    evidence: CashLedgerEvidence,
    *,
    analysis_at: datetime,
    currency: str,
    policy: CashStalenessPolicy,
    scope: DynamicWorkflowScope | None,
    scope_keyring: ExactScopeDigestProvider | None,
) -> tuple[bool, CashExclusionReason | None]:
    """Return (verified, exclusion_reason). reason is None when admitted."""

    if evidence.currency != currency:
        return False, "currency_mismatch"
    observed_at = _parse_timestamp(evidence.observed_at)
    if observed_at > analysis_at:
        return False, "future_observation"
    age_hours = (analysis_at - observed_at).total_seconds() / 3600
    if age_hours > policy.max_evidence_age_hours:
        return False, "stale_observation"
    verified = False
    if scope is not None and scope_keyring is not None and evidence.is_attested:
        verified = _evidence_attestation_matches(
            evidence, scope=scope, scope_keyring=scope_keyring
        )
    if policy.require_verified_evidence and not verified:
        return False, "unverified_evidence"
    return verified, None


def _reject_account_window_overlaps(
    admitted: list[CashLedgerEvidence],
) -> list[ExcludedCashEvidence]:
    """Drop flow observations that overlap another window for the same account.

    Two flow windows for the same account that overlap would double-count the
    flows between them. The earlier-observed one is kept; the later-observed
    overlapper is excluded with a reason. Balance-only evidence never overlaps
    (a point-in-time balance carries no flow to double-count).
    """

    excluded: list[ExcludedCashEvidence] = []
    kept: list[CashLedgerEvidence] = []
    by_account: dict[str, list[tuple[datetime, datetime]]] = {}
    order = sorted(admitted, key=lambda e: _parse_timestamp(e.observed_at))
    for evidence in order:
        has_flow = (
            evidence.metrics.cash_inflows is not None
            or evidence.metrics.cash_outflows is not None
        )
        if not has_flow:
            kept.append(evidence)
            continue
        start = _parse_timestamp(evidence.window_start)
        end = _parse_timestamp(evidence.window_end)
        spans = by_account.setdefault(evidence.connector_account_ref, [])
        if any(start < prior_end and prior_start < end for prior_start, prior_end in spans):
            excluded.append(
                ExcludedCashEvidence(
                    observation_ref=evidence.observation_ref,
                    evidence_digest=evidence.evidence_digest,
                    reason="overlapping_window",
                )
            )
            continue
        spans.append((start, end))
        kept.append(evidence)
    admitted[:] = kept
    return excluded


def _months_between(start: datetime, end: datetime) -> Decimal:
    days = Decimal((end - start).total_seconds()) / Decimal(86_400)
    if days <= 0:
        return Decimal("0")
    return days / _DAYS_PER_MONTH


def build_runway_snapshot(
    inputs: BuildRunwayInput | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any] | None = None,
    scope_keyring: ExactScopeDigestProvider | None = None,
    scope_key_id: str | None = None,
) -> CashRunwaySnapshot:
    """Compute one sealed runway snapshot from admissible cash evidence.

    With ``scope`` and ``scope_keyring`` the snapshot verifies every attested
    envelope, reports ``host_hmac_verified`` only when all admitted evidence
    verified, and seals the snapshot itself. Without them it is
    honest-but-unverified.
    """

    parsed = (
        inputs
        if isinstance(inputs, BuildRunwayInput)
        else BuildRunwayInput.model_validate(inputs)
    )
    if (scope is None) != (scope_keyring is None):
        raise CashRunwayValidationError(
            "verified snapshots require both scope and scope_keyring"
        )
    workflow_scope: DynamicWorkflowScope | None = None
    if scope is not None:
        workflow_scope = _workflow_scope(scope)
    analysis_at = _parse_timestamp(parsed.analysis_as_of)

    admitted: list[CashLedgerEvidence] = []
    admitted_verified: dict[str, bool] = {}
    excluded: list[ExcludedCashEvidence] = []
    for evidence in parsed.evidence:
        verified, reason = _classify_cash_evidence(
            evidence,
            analysis_at=analysis_at,
            currency=parsed.currency,
            policy=parsed.staleness_policy,
            scope=workflow_scope,
            scope_keyring=scope_keyring,
        )
        if reason is not None:
            excluded.append(
                ExcludedCashEvidence(
                    observation_ref=evidence.observation_ref,
                    evidence_digest=evidence.evidence_digest,
                    reason=reason,
                )
            )
            continue
        admitted.append(evidence)
        admitted_verified[evidence.observation_ref] = verified
    excluded.extend(_reject_account_window_overlaps(admitted))

    notes: list[str] = []

    # --- Flow aggregation -------------------------------------------------
    flow_evidence = [
        e
        for e in admitted
        if e.metrics.cash_inflows is not None or e.metrics.cash_outflows is not None
    ]
    inflow_present_all = bool(flow_evidence) and all(
        e.metrics.cash_inflows is not None for e in flow_evidence
    )
    inflow_present_any = any(e.metrics.cash_inflows is not None for e in flow_evidence)
    outflow_present_all = bool(flow_evidence) and all(
        e.metrics.cash_outflows is not None for e in flow_evidence
    )
    outflow_present_any = any(e.metrics.cash_outflows is not None for e in flow_evidence)

    total_inflows = sum(
        (e.metrics.cash_inflows for e in flow_evidence if e.metrics.cash_inflows is not None),
        Decimal("0"),
    )
    total_outflows = sum(
        (e.metrics.cash_outflows for e in flow_evidence if e.metrics.cash_outflows is not None),
        Decimal("0"),
    )

    window_days = 0
    span_months = Decimal("0")
    if flow_evidence:
        span_start = min(_parse_timestamp(e.window_start) for e in flow_evidence)
        span_end = max(_parse_timestamp(e.window_end) for e in flow_evidence)
        window_days = (span_end - span_start).days
        span_months = _months_between(span_start, span_end)

    # --- Cash on hand -----------------------------------------------------
    cash_on_hand: Decimal | None = None
    cash_source: CashOnHandSource = "unknown"
    if parsed.cash_on_hand_override is not None:
        cash_on_hand = parsed.cash_on_hand_override
        cash_source = "caller_supplied"
    else:
        balance_evidence = [
            e for e in admitted if e.metrics.ending_cash_balance is not None
        ]
        if balance_evidence:
            latest_end = max(_parse_timestamp(e.window_end) for e in balance_evidence)
            at_latest = [
                e
                for e in balance_evidence
                if _parse_timestamp(e.window_end) == latest_end
            ]
            seen_accounts: set[str] = set()
            balance_total = Decimal("0")
            for e in at_latest:
                if e.connector_account_ref in seen_accounts:
                    continue
                seen_accounts.add(e.connector_account_ref)
                balance_total += e.metrics.ending_cash_balance  # type: ignore[operator]
            cash_on_hand = _quantized_money(balance_total)
            cash_source = "ledger_balance"
            if len(balance_evidence) != len(at_latest):
                notes.append(
                    "cash on hand uses only the latest-dated balance evidence"
                )

    # --- Derived components ----------------------------------------------
    components: list[RunwayComponent] = []
    monthly_inflow: Decimal | None = None
    gross_monthly_outflow: Decimal | None = None
    net_monthly_burn: Decimal | None = None
    net_burn_complete = False

    # Which direction does incompleteness bend the runway? Missing OUTFLOWS
    # understate burn -> overstate runway (a dangerous ceiling). Missing
    # INFLOWS overstate burn (unobserved inflows treated as the zero-inflow
    # worst case) -> understate runway (a safe floor). The guardrail must
    # never let a missing outflow read as more comfort.
    burn_is_ceiling = False  # runway may be shorter than shown (dangerous)
    burn_is_floor = False  # runway may be longer than shown (conservative)

    if flow_evidence and span_months > 0:
        if inflow_present_any:
            monthly_inflow = _quantized_money(total_inflows / span_months)
            components.append(
                RunwayComponent(
                    name="monthly_inflow",
                    unit="money_per_month",
                    value=monthly_inflow,
                    complete=inflow_present_all,
                    missing_inputs=() if inflow_present_all else ("cash_inflows",),
                    note=None
                    if inflow_present_all
                    else "some periods did not report inflows; total is a lower bound",
                )
            )
        if outflow_present_any:
            gross_monthly_outflow = _quantized_money(total_outflows / span_months)
            components.append(
                RunwayComponent(
                    name="gross_monthly_outflow",
                    unit="money_per_month",
                    value=gross_monthly_outflow,
                    complete=outflow_present_all,
                    missing_inputs=() if outflow_present_all else ("cash_outflows",),
                    note=None
                    if outflow_present_all
                    else "some periods did not report outflows; total is a lower bound",
                )
            )
        # Net burn needs outflows; inflows unobserved are treated as the
        # worst case (zero), which only ever shortens the reported runway.
        if outflow_present_any:
            net_burn_complete = inflow_present_all and outflow_present_all
            net_value = _quantized_money(
                (total_outflows - total_inflows) / span_months
            )
            net_monthly_burn = net_value
            missing = tuple(
                m
                for m, ok in (
                    ("cash_inflows", inflow_present_all),
                    ("cash_outflows", outflow_present_all),
                )
                if not ok
            )
            burn_is_ceiling = not outflow_present_all
            burn_is_floor = outflow_present_all and not inflow_present_all
            if net_burn_complete:
                burn_note = None
            elif burn_is_ceiling:
                burn_note = "outflows missing in some periods; true burn is higher"
            else:
                burn_note = "inflows unobserved; burn assumes the zero-inflow worst case"
            components.append(
                RunwayComponent(
                    name="net_monthly_burn",
                    unit="money_per_month",
                    value=net_value,
                    complete=net_burn_complete,
                    missing_inputs=missing,
                    note=burn_note,
                )
            )
    elif flow_evidence and span_months <= 0:
        notes.append("flow evidence spans zero days; monthly rates are unknown")

    if cash_on_hand is not None:
        components.append(
            RunwayComponent(
                name="cash_on_hand",
                unit="money",
                value=cash_on_hand,
                complete=True,
                missing_inputs=(),
                note=None,
            )
        )

    # --- Runway + status --------------------------------------------------
    status: RunwayStatus = "unknown"
    runway_months: Decimal | None = None
    if net_monthly_burn is not None and net_monthly_burn <= 0 and not burn_is_ceiling:
        # A non-positive net only means "not burning" when outflows are COMPLETE.
        # With outflows missing in some periods the net is understated (a ceiling),
        # so a <=0 result is untrustworthy — the business may well be burning.
        # Refuse to call it not_burning; leave it unknown (no envelope, no permit).
        status = "not_burning"
        notes.append("net cash flow is non-negative over the observed window")
    elif net_monthly_burn is not None and net_monthly_burn <= 0 and burn_is_ceiling:
        notes.append(
            "net looks non-negative but outflows are incomplete; runway is unknown, "
            "not cash-positive"
        )
    elif (
        net_monthly_burn is not None
        and net_monthly_burn > 0
        and cash_on_hand is not None
    ):
        status = "burning"
        raw_runway = cash_on_hand / net_monthly_burn
        runway_complete = net_burn_complete and cash_source != "unknown"
        capped_note: str | None = None
        if raw_runway > _MAX_REPORTED_RUNWAY_MONTHS:
            runway_value = _MAX_REPORTED_RUNWAY_MONTHS
            capped_note = "runway exceeds the reporting horizon; capped"
        else:
            runway_value = _quantized_multiple(raw_runway)
        if runway_complete:
            runway_note = capped_note
            runway_missing: tuple[CashMetricName, ...] = ()
        elif burn_is_ceiling:
            # missing outflows -> burn understated -> runway is a ceiling
            runway_note = capped_note or "true runway may be shorter than shown"
            runway_missing = ("cash_outflows",)
        else:
            # missing inflows -> burn overstated -> runway is a conservative floor
            runway_note = capped_note or "conservative floor; true runway may be longer"
            runway_missing = ("cash_inflows",)
        components.append(
            RunwayComponent(
                name="runway_months",
                unit="multiple",
                value=runway_value,
                complete=runway_complete,
                missing_inputs=runway_missing,
                note=runway_note,
            )
        )
        runway_months = runway_value

    # --- Measured burn band ----------------------------------------------
    burn_band: BurnBand | None = None
    if status == "burning" and cash_on_hand is not None:
        period_burns: list[Decimal] = []
        for e in flow_evidence:
            if (
                e.metrics.cash_inflows is None
                or e.metrics.cash_outflows is None
            ):
                continue
            e_months = _months_between(
                _parse_timestamp(e.window_start), _parse_timestamp(e.window_end)
            )
            if e_months <= 0:
                continue
            e_burn = (e.metrics.cash_outflows - e.metrics.cash_inflows) / e_months
            if e_burn > 0:
                period_burns.append(e_burn)
        if len(period_burns) >= 2:
            worst_burn = max(period_burns)
            best_burn = min(period_burns)
            burn_band = BurnBand(
                basis="observed_across_periods",
                period_count=len(period_burns),
                worst_runway_months=_quantized_multiple(
                    min(cash_on_hand / worst_burn, _MAX_REPORTED_RUNWAY_MONTHS)
                ),
                best_runway_months=_quantized_multiple(
                    min(cash_on_hand / best_burn, _MAX_REPORTED_RUNWAY_MONTHS)
                ),
            )
        else:
            burn_band = BurnBand(basis="single_estimate", period_count=1)

    # --- Presence + notes -------------------------------------------------
    presence_map = {
        "cash_inflows": inflow_present_any,
        "cash_outflows": outflow_present_any,
        "ending_cash_balance": cash_source == "ledger_balance",
    }
    metric_presence = tuple(
        CashMetricPresence(
            metric=metric,
            status="present" if presence_map[metric] else "unknown",
        )
        for metric in _CASH_METRICS
    )
    if not flow_evidence:
        notes.append("no cash-flow evidence admitted; burn and runway are unknown")
    if net_monthly_burn is not None and net_monthly_burn > 0 and cash_on_hand is None:
        notes.append("cash on hand is unknown; runway cannot be computed")
    if net_monthly_burn is not None and burn_is_ceiling:
        notes.append("outflows incomplete; treat runway as a ceiling, not a floor")
    if net_monthly_burn is not None and burn_is_floor:
        notes.append("inflows incomplete; runway shown is a conservative floor")

    scope_status: EvidenceScopeStatus = "caller_supplied_unverified"
    if (
        workflow_scope is not None
        and admitted
        and all(admitted_verified.get(e.observation_ref, False) for e in admitted)
    ):
        scope_status = "host_hmac_verified"

    admitted_records = tuple(
        AdmittedCashEvidence(
            observation_ref=e.observation_ref,
            evidence_digest=e.evidence_digest,
            provider=e.provider,
            connector_account_ref=e.connector_account_ref,
            window_start=e.window_start,
            window_end=e.window_end,
            verified=admitted_verified.get(e.observation_ref, False),
        )
        for e in admitted
    )

    snapshot = CashRunwaySnapshot(
        runway_ref=parsed.runway_ref,
        analysis_as_of=parsed.analysis_as_of,
        currency=parsed.currency,
        evidence_scope_status=scope_status,
        staleness_policy=parsed.staleness_policy,
        status=status,
        observed_window_days=window_days,
        cash_on_hand_source=cash_source,
        metric_presence=metric_presence,
        components=tuple(components),
        burn_band=burn_band,
        data_quality_notes=tuple(dict.fromkeys(notes)),
        admitted_evidence=admitted_records,
        excluded_evidence=tuple(excluded),
    )

    digest = _stable_digest(snapshot.hmac_payload())
    snapshot = snapshot.model_copy(update={"runway_digest": digest})

    if workflow_scope is not None and scope_keyring is not None:
        if scope_status != "host_hmac_verified":
            return snapshot
        key_id = scope_key_id or str(scope_keyring.active_key_id).strip()
        exact_scope_digest = _keyring_scope_digest(
            scope_keyring, key_id=key_id, scope=workflow_scope
        )
        draft = snapshot.model_copy(
            update={
                "receipt_key_id": key_id,
                "exact_scope_digest": exact_scope_digest,
                "runway_hmac": "0" * 64,
            }
        )
        signature = _keyring_signature(
            scope_keyring,
            key_id=key_id,
            domain=_RUNWAY_SNAPSHOT_HMAC_DOMAIN,
            payload=draft.hmac_payload(),
        )
        return draft.model_copy(update={"runway_hmac": signature})
    return snapshot


def verify_cash_runway_snapshot(
    value: CashRunwaySnapshot | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ExactScopeDigestProvider,
) -> CashRunwaySnapshot:
    """Re-validate and verify one sealed runway snapshot; raise on failure."""

    snapshot = CashRunwaySnapshot.model_validate(
        value.model_dump(mode="python", by_alias=True)
        if isinstance(value, CashRunwaySnapshot)
        else value
    )
    if not snapshot.is_sealed:
        raise CashRunwayValidationError("runway snapshot carries no host attestation")
    workflow_scope = _workflow_scope(scope)
    expected_scope_digest = _keyring_scope_digest(
        scope_keyring,
        key_id=snapshot.receipt_key_id,  # type: ignore[arg-type]
        scope=workflow_scope,
    )
    if snapshot.exact_scope_digest is None or not hmac.compare_digest(
        snapshot.exact_scope_digest, expected_scope_digest
    ):
        raise CashRunwayValidationError("runway snapshot scope digest mismatch")
    expected_hmac = _keyring_signature(
        scope_keyring,
        key_id=snapshot.receipt_key_id,  # type: ignore[arg-type]
        domain=_RUNWAY_SNAPSHOT_HMAC_DOMAIN,
        payload=snapshot.hmac_payload(),
    )
    if snapshot.runway_hmac is None or not hmac.compare_digest(
        snapshot.runway_hmac, expected_hmac
    ):
        raise CashRunwayValidationError("runway snapshot attestation failed verification")
    return snapshot


# ---------------------------------------------------------------------------
# Budget envelope — the hard spending constraint
# ---------------------------------------------------------------------------


class CashBudgetEnvelope(_StrictModel):
    """The discretionary spend that keeps runway at or above a floor.

    This is the number the rest of the network must obey. It is derived from a
    runway snapshot and a caller policy floor, and it is honest about ignorance:
    an unknown-runway business gets ``unknown`` status and a zero envelope, not
    an optimistic default.
    """

    schema_id: Literal["lightbulb.cash_budget_envelope.v1"] = Field(
        default=CASH_BUDGET_ENVELOPE_SCHEMA,
        alias="schema",
    )
    envelope_ref: PortableRef
    analysis_as_of: str
    currency: CurrencyCode
    runway_digest: Sha256Digest
    runway_floor_months: Decimal = Field(gt=0)
    status: BudgetStatus
    current_runway_months: Decimal | None = None
    cash_on_hand: Decimal | None = None
    net_monthly_burn: Decimal | None = None
    affordable_incremental_monthly_burn: Decimal | None = None
    one_time_discretionary_capacity: Decimal | None = None
    runway_shortfall_months: Decimal | None = None
    complete: bool
    rationale: ShortText
    receipt_key_id: str | None = Field(
        default=None,
        min_length=8,
        max_length=80,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{7,79}$",
    )
    exact_scope_digest: Sha256Digest | None = None
    envelope_hmac: Sha256Digest | None = None

    @field_validator("analysis_as_of")
    @classmethod
    def _valid_analysis_time(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator("runway_floor_months", mode="before")
    @classmethod
    def _floor_decimal(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_MULTIPLE_QUANTUM)

    @field_validator(
        "current_runway_months",
        "cash_on_hand",
        "net_monthly_burn",
        "affordable_incremental_monthly_burn",
        "one_time_discretionary_capacity",
        "runway_shortfall_months",
        mode="before",
    )
    @classmethod
    def _optional_decimal(cls, value: Any) -> Decimal | None:
        if value is None:
            return None
        return _decimal(value)

    @model_validator(mode="after")
    def _sealed_shape(self) -> "CashBudgetEnvelope":
        binding_fields = (
            self.receipt_key_id,
            self.exact_scope_digest,
            self.envelope_hmac,
        )
        if any(v is not None for v in binding_fields) and not all(
            v is not None for v in binding_fields
        ):
            raise ValueError("envelope attestation fields must be supplied together")
        return self

    @property
    def is_sealed(self) -> bool:
        return self.envelope_hmac is not None

    def hmac_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"envelope_hmac"}, exclude_none=True)


class DeriveBudgetEnvelopeInput(_StrictModel):
    envelope_ref: PortableRef
    analysis_as_of: str
    runway_snapshot: CashRunwaySnapshot
    runway_floor_months: Decimal = Field(gt=0, le=Decimal("120"))

    @field_validator("analysis_as_of")
    @classmethod
    def _valid_analysis_time(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator("runway_floor_months", mode="before")
    @classmethod
    def _floor_decimal(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_MULTIPLE_QUANTUM)


def derive_budget_envelope(
    inputs: DeriveBudgetEnvelopeInput | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any] | None = None,
    scope_keyring: ExactScopeDigestProvider | None = None,
    scope_key_id: str | None = None,
) -> CashBudgetEnvelope:
    """Size the discretionary spend that keeps runway at or above the floor.

    The core identity: to hold runway at exactly ``floor`` months you may carry
    a net burn of ``cash_on_hand / floor``. The affordable *incremental* monthly
    burn is that target minus the current burn; the one-time discretionary
    capacity is ``cash_on_hand - net_burn * floor`` — the cash committable now
    without dropping below the floor. Both go negative when already below it,
    which is reported as a required cut and a named shortfall.
    """

    parsed = (
        inputs
        if isinstance(inputs, DeriveBudgetEnvelopeInput)
        else DeriveBudgetEnvelopeInput.model_validate(inputs)
    )
    if (scope is None) != (scope_keyring is None):
        raise CashRunwayValidationError(
            "sealed envelopes require both scope and scope_keyring"
        )
    snapshot = parsed.runway_snapshot
    floor = parsed.runway_floor_months

    cash_component = snapshot.component("cash_on_hand")
    burn_component = snapshot.component("net_monthly_burn")
    runway_component = snapshot.component("runway_months")
    cash_on_hand = cash_component.value if cash_component is not None else None
    net_burn = burn_component.value if burn_component is not None else None
    current_runway = runway_component.value if runway_component is not None else None

    status: BudgetStatus
    affordable_incremental: Decimal | None = None
    one_time_capacity: Decimal | None = None
    shortfall: Decimal | None = None
    complete = False
    rationale: str

    # Outflows missing in some periods understate burn -> overstate runway (an
    # optimistic ceiling). Granting spend against that would breach the floor,
    # so it is treated as unknown: the floor is law, not a soft advisory.
    outflows_incomplete = (
        burn_component is not None and "cash_outflows" in burn_component.missing_inputs
    )

    if snapshot.status == "not_burning":
        status = "not_burning"
        one_time_capacity = cash_on_hand
        complete = burn_component is not None and burn_component.complete
        rationale = "net cash flow is non-negative; runway is not burn-limited"
    elif (
        snapshot.status == "unknown"
        or net_burn is None
        or cash_on_hand is None
        or outflows_incomplete
    ):
        status = "unknown"
        rationale = (
            "burn understated (outflows incomplete); runway is an optimistic "
            "ceiling, so no discretionary capacity is granted"
            if outflows_incomplete
            else "insufficient evidence: burn or cash on hand is unknown"
        )
    else:
        target_burn = cash_on_hand / floor
        affordable_incremental = _quantized_money(target_burn - net_burn)
        one_time_capacity = _quantized_money(cash_on_hand - net_burn * floor)
        complete = (
            bool(burn_component and burn_component.complete)
            and snapshot.cash_on_hand_source != "unknown"
        )
        if current_runway is not None and current_runway < floor:
            status = "below_floor"
            shortfall = _quantized_multiple(floor - current_runway)
            rationale = (
                f"runway {current_runway} mo is below the {floor} mo floor; "
                "cut burn to restore it"
            )
        elif current_runway is not None and current_runway == floor:
            status = "at_floor"
            rationale = f"runway is exactly at the {floor} mo floor; no new burn"
        else:
            status = "healthy_surplus"
            rationale = (
                f"runway exceeds the {floor} mo floor; the surplus is committable"
            )

    envelope = CashBudgetEnvelope(
        envelope_ref=parsed.envelope_ref,
        analysis_as_of=parsed.analysis_as_of,
        currency=snapshot.currency,
        runway_digest=snapshot.runway_digest,
        runway_floor_months=floor,
        status=status,
        current_runway_months=current_runway,
        cash_on_hand=cash_on_hand,
        net_monthly_burn=net_burn,
        affordable_incremental_monthly_burn=affordable_incremental,
        one_time_discretionary_capacity=one_time_capacity,
        runway_shortfall_months=shortfall,
        complete=complete,
        rationale=_bounded_text(rationale)[:300],
    )

    if scope is not None and scope_keyring is not None:
        workflow_scope = _workflow_scope(scope)
        key_id = scope_key_id or str(scope_keyring.active_key_id).strip()
        exact_scope_digest = _keyring_scope_digest(
            scope_keyring, key_id=key_id, scope=workflow_scope
        )
        draft = envelope.model_copy(
            update={
                "receipt_key_id": key_id,
                "exact_scope_digest": exact_scope_digest,
                "envelope_hmac": "0" * 64,
            }
        )
        signature = _keyring_signature(
            scope_keyring,
            key_id=key_id,
            domain=_BUDGET_ENVELOPE_HMAC_DOMAIN,
            payload=draft.hmac_payload(),
        )
        return draft.model_copy(update={"envelope_hmac": signature})
    return envelope


# ---------------------------------------------------------------------------
# Assessment — severity + ranked opportunities
# ---------------------------------------------------------------------------


class RunwayOpportunity(_StrictModel):
    rank: int = Field(ge=1)
    kind: RunwayOpportunityKind
    title: ShortText
    mechanism: ShortText
    reference_quality: ReferenceQuality


class RunwayAssessment(_StrictModel):
    """Deterministic 'how healthy is the runway, and what next' answer."""

    schema_id: Literal["lightbulb.cash_runway_assessment.v1"] = Field(
        default=CASH_RUNWAY_ASSESSMENT_SCHEMA,
        alias="schema",
    )
    assessment_ref: PortableRef
    analysis_as_of: str
    runway_digest: Sha256Digest
    severity: RunwaySeverity
    runway_floor_months: Decimal = Field(gt=0)
    caution_threshold_months: Decimal = Field(gt=0)
    current_runway_months: Decimal | None = None
    status: RunwayStatus
    opportunities: tuple[RunwayOpportunity, ...] = Field(default_factory=tuple)
    notes: tuple[ShortText, ...] = Field(default_factory=tuple)
    assessment_digest: Sha256Digest = "0" * 64

    @field_validator("analysis_as_of")
    @classmethod
    def _valid_analysis_time(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator("runway_floor_months", "caution_threshold_months", mode="before")
    @classmethod
    def _floor_decimal(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_MULTIPLE_QUANTUM)

    @field_validator("current_runway_months", mode="before")
    @classmethod
    def _optional_multiple(cls, value: Any) -> Decimal | None:
        if value is None:
            return None
        return _decimal(value, quantum=_MULTIPLE_QUANTUM)

    @field_validator("opportunities", "notes", mode="before")
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)


class AssessRunwayInput(_StrictModel):
    assessment_ref: PortableRef
    analysis_as_of: str
    runway_snapshot: CashRunwaySnapshot
    runway_floor_months: Decimal = Field(default=Decimal("12"), gt=0, le=Decimal("120"))
    caution_threshold_months: Decimal = Field(
        default=Decimal("18"), gt=0, le=Decimal("120")
    )

    @field_validator("analysis_as_of")
    @classmethod
    def _valid_analysis_time(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator("runway_floor_months", "caution_threshold_months", mode="before")
    @classmethod
    def _floor_decimal(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_MULTIPLE_QUANTUM)

    @model_validator(mode="after")
    def _thresholds_ordered(self) -> "AssessRunwayInput":
        if self.caution_threshold_months < self.runway_floor_months:
            raise ValueError(
                "caution threshold must be at or above the runway floor"
            )
        return self


def assess_runway(
    inputs: AssessRunwayInput | Mapping[str, Any],
) -> RunwayAssessment:
    """Classify runway health and emit ranked, honestly-labeled next actions."""

    parsed = (
        inputs
        if isinstance(inputs, AssessRunwayInput)
        else AssessRunwayInput.model_validate(inputs)
    )
    snapshot = parsed.runway_snapshot
    floor = parsed.runway_floor_months
    caution = parsed.caution_threshold_months
    runway_component = snapshot.component("net_monthly_burn")
    runway_value_component = snapshot.component("runway_months")
    current_runway = (
        runway_value_component.value if runway_value_component is not None else None
    )

    notes: list[str] = []
    opportunities: list[RunwayOpportunity] = []
    severity: RunwaySeverity

    if snapshot.status == "unknown" or current_runway is None:
        if snapshot.status == "not_burning":
            severity = "healthy"
            notes.append("net cash flow is non-negative; not burn-limited")
        else:
            severity = "unknown"
            notes.append("runway is unknown; collect cash evidence before deciding")
            opportunities.append(
                RunwayOpportunity(
                    rank=1,
                    kind="collect_evidence",
                    title="Connect a cash source to measure burn",
                    mechanism=(
                        "runway needs both cash-flow and balance evidence; one is missing"
                    ),
                    reference_quality="policy_floor",
                )
            )
    elif snapshot.status == "not_burning":
        severity = "healthy"
        notes.append("net cash flow is non-negative over the observed window")
    else:
        incomplete = runway_component is not None and not runway_component.complete
        if current_runway < floor:
            severity = "danger"
            opportunities.append(
                RunwayOpportunity(
                    rank=1,
                    kind="reduce_burn",
                    title="Cut net burn to restore the runway floor",
                    mechanism=(
                        f"runway {current_runway} mo is below the {floor} mo floor"
                    ),
                    reference_quality="policy_floor",
                )
            )
            opportunities.append(
                RunwayOpportunity(
                    rank=2,
                    kind="raise_capital",
                    title="Raise capital to extend runway past the floor",
                    mechanism="new cash directly lifts runway at the current burn",
                    reference_quality="policy_floor",
                )
            )
        elif current_runway < caution:
            severity = "caution"
            opportunities.append(
                RunwayOpportunity(
                    rank=1,
                    kind="extend_runway",
                    title="Extend runway toward the caution threshold",
                    mechanism=(
                        f"runway {current_runway} mo is under the {caution} mo caution line"
                    ),
                    reference_quality="default_heuristic",
                )
            )
        else:
            severity = "healthy"
            notes.append(
                f"runway {current_runway} mo clears the {caution} mo caution line"
            )
        if incomplete:
            notes.append("burn is a lower bound; true runway may be shorter")
            opportunities.append(
                RunwayOpportunity(
                    rank=len(opportunities) + 1,
                    kind="collect_evidence",
                    title="Complete the cash ledger to sharpen runway",
                    mechanism="a flow was missing in some periods, so burn is understated",
                    reference_quality="policy_floor",
                )
            )

    assessment = RunwayAssessment(
        assessment_ref=parsed.assessment_ref,
        analysis_as_of=parsed.analysis_as_of,
        runway_digest=snapshot.runway_digest,
        severity=severity,
        runway_floor_months=floor,
        caution_threshold_months=caution,
        current_runway_months=current_runway,
        status=snapshot.status,
        opportunities=tuple(opportunities[:_MAX_ASSESSMENT_OPPORTUNITIES]),
        notes=tuple(dict.fromkeys(notes)),
    )
    digest = _stable_digest(
        assessment.model_dump(mode="json", exclude={"assessment_digest"})
    )
    return assessment.model_copy(update={"assessment_digest": digest})


# ---------------------------------------------------------------------------
# Executable primitives (agent-invocable catalog surface)
#
# These run the honest-but-unverified path: the primitive computes the
# artifact from caller-supplied evidence, and a trusted host seals it
# afterward with its keyring. They never hold a key or reach a connector.
# ---------------------------------------------------------------------------


_EXAMPLE_CASH_EVIDENCE: tuple[dict[str, Any], ...] = (
    {
        "observation_ref": "bank-june-example",
        "connector_account_ref": "acct.bank.operating",
        "provider": "bank",
        "source_capability": "bank.statement_import",
        "currency": "USD",
        "observed_at": "2026-07-01T00:00:00Z",
        "window_start": "2026-06-01T00:00:00Z",
        "window_end": "2026-07-01T00:00:00Z",
        "metrics": {"cash_inflows": "40000.00", "cash_outflows": "70000.00"},
        "evidence_digest": "a" * 64,
    },
    {
        "observation_ref": "bank-july-example",
        "connector_account_ref": "acct.bank.operating",
        "provider": "bank",
        "source_capability": "bank.statement_import",
        "currency": "USD",
        "observed_at": "2026-08-01T00:00:00Z",
        "window_start": "2026-07-01T00:00:00Z",
        "window_end": "2026-08-01T00:00:00Z",
        "metrics": {
            "cash_inflows": "45000.00",
            "cash_outflows": "72000.00",
            "ending_cash_balance": "300000.00",
        },
        "evidence_digest": "b" * 64,
    },
)

_EXAMPLE_BUILD_INPUT: dict[str, Any] = {
    "analysis_as_of": "2026-08-02T00:00:00Z",
    "runway_ref": "biz-runway-example",
    "currency": "USD",
    "evidence": _EXAMPLE_CASH_EVIDENCE,
}

_EXAMPLE_SNAPSHOT: dict[str, Any] = build_runway_snapshot(
    _EXAMPLE_BUILD_INPUT
).model_dump(mode="json", by_alias=True, exclude_none=True)


def _primitive_failure(
    primitive_ref: str,
    version: str,
    exc: ValueError,
) -> PrimitiveExecutionResult[Any]:
    return PrimitiveExecutionResult(
        status=PrimitiveExecutionStatus.FAILED,
        primitive_ref=primitive_ref,
        primitive_version=version,
        summary=f"cash-runway input rejected: {exc}",
        output=None,
    )


class BuildRunwaySnapshotPrimitive(
    BusinessProcessPrimitive[BuildRunwayInput, CashRunwaySnapshot]
):
    """Compute observed net burn, cash on hand, and runway from cash evidence."""

    primitive_ref = "cash.build_runway_snapshot"
    version = "1.0.0"
    title = "Build cash runway snapshot"
    description = (
        "Aggregate sealed cash-basis flow observations into one runway "
        "snapshot: window-normalized net monthly burn, cash on hand (from "
        "balance evidence or a caller override), and months of runway. Unknown "
        "is not zero — no cash-on-hand evidence yields an unknown runway, and "
        "missing inflows versus outflows are reported as a conservative floor "
        "versus a dangerous ceiling. A measured best/worst band is emitted only "
        "when two or more independent periods exist; the snapshot is sealed by "
        "the host afterward."
    )
    input_model = BuildRunwayInput
    output_model = CashRunwaySnapshot
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs = _EXAMPLE_BUILD_INPUT

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: BuildRunwayInput,
    ) -> PrimitiveExecutionResult[CashRunwaySnapshot]:
        try:
            snapshot = build_runway_snapshot(inputs)
        except ValueError as exc:
            return _primitive_failure(self.primitive_ref, self.version, exc)
        runway = snapshot.component("runway_months")
        runway_text = (
            f"{runway.value} months" if runway is not None else "unknown"
        )
        return PrimitiveExecutionResult[CashRunwaySnapshot](
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=f"Runway {snapshot.runway_ref}: {snapshot.status}; {runway_text}.",
            output=snapshot,
            events=[
                PrimitiveEvent(
                    type="cash.runway_measured",
                    payload={
                        "runway_ref": snapshot.runway_ref,
                        "status": snapshot.status,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="deterministic_plan",
                    summary="Runway bound to evidence digest "
                    + snapshot.runway_digest[:16]
                    + "…",
                )
            ],
        )


class DeriveBudgetEnvelopePrimitive(
    BusinessProcessPrimitive[DeriveBudgetEnvelopeInput, CashBudgetEnvelope]
):
    """Size the discretionary spend that holds runway at or above a floor."""

    primitive_ref = "cash.derive_budget_envelope"
    version = "1.0.0"
    title = "Derive cash budget envelope"
    description = (
        "Turn a runway snapshot and a runway floor into the hard spending "
        "constraint the rest of the network must obey: the affordable "
        "incremental monthly burn and the one-time discretionary cash "
        "committable without dropping below the floor. Below the floor it "
        "reports a required cut and the exact runway shortfall; an "
        "unknown-runway business gets an unknown envelope, never an optimistic "
        "default. Binds to the snapshot's digest."
    )
    input_model = DeriveBudgetEnvelopeInput
    output_model = CashBudgetEnvelope
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs = {
        "envelope_ref": "biz-budget-example",
        "analysis_as_of": "2026-08-02T00:00:00Z",
        "runway_snapshot": _EXAMPLE_SNAPSHOT,
        "runway_floor_months": "12",
    }

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: DeriveBudgetEnvelopeInput,
    ) -> PrimitiveExecutionResult[CashBudgetEnvelope]:
        try:
            envelope = derive_budget_envelope(inputs)
        except ValueError as exc:
            return _primitive_failure(self.primitive_ref, self.version, exc)
        capacity = envelope.one_time_discretionary_capacity
        capacity_text = "unknown" if capacity is None else f"{capacity} {envelope.currency}"
        return PrimitiveExecutionResult[CashBudgetEnvelope](
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                f"Budget {envelope.envelope_ref}: {envelope.status}; "
                f"discretionary capacity {capacity_text}."
            ),
            output=envelope,
            events=[
                PrimitiveEvent(
                    type="cash.budget_envelope_derived",
                    payload={
                        "envelope_ref": envelope.envelope_ref,
                        "status": envelope.status,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="deterministic_plan",
                    summary="Envelope bound to runway "
                    + envelope.runway_digest[:16]
                    + "…",
                )
            ],
        )


class AssessRunwayPrimitive(
    BusinessProcessPrimitive[AssessRunwayInput, RunwayAssessment]
):
    """Classify runway health and emit ranked, honestly-labeled next actions."""

    primitive_ref = "cash.assess_runway"
    version = "1.0.0"
    title = "Assess cash runway"
    description = (
        "Judge a runway snapshot against a floor and a caution threshold: "
        "severity (healthy / caution / danger / unknown) and ranked actions "
        "(reduce burn, extend runway, raise capital, collect evidence). Danger "
        "below the floor, caution between floor and threshold, unknown when "
        "runway cannot be computed; an incomplete burn adds a sharpen-evidence "
        "action. References are labeled policy_floor or default_heuristic."
    )
    input_model = AssessRunwayInput
    output_model = RunwayAssessment
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs = {
        "assessment_ref": "biz-assess-example",
        "analysis_as_of": "2026-08-02T00:00:00Z",
        "runway_snapshot": _EXAMPLE_SNAPSHOT,
        "runway_floor_months": "12",
        "caution_threshold_months": "18",
    }

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: AssessRunwayInput,
    ) -> PrimitiveExecutionResult[RunwayAssessment]:
        try:
            assessment = assess_runway(inputs)
        except ValueError as exc:
            return _primitive_failure(self.primitive_ref, self.version, exc)
        return PrimitiveExecutionResult[RunwayAssessment](
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                f"Runway {assessment.assessment_ref}: {assessment.severity}; "
                f"{len(assessment.opportunities)} action(s)."
            ),
            output=assessment,
            events=[
                PrimitiveEvent(
                    type="cash.runway_assessed",
                    payload={
                        "assessment_ref": assessment.assessment_ref,
                        "severity": assessment.severity,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="deterministic_plan",
                    summary="Assessment bound to runway "
                    + assessment.runway_digest[:16]
                    + "…",
                )
            ],
        )


__all__ = [
    "CASH_LEDGER_EVIDENCE_SCHEMA",
    "CASH_RUNWAY_SNAPSHOT_SCHEMA",
    "CASH_BUDGET_ENVELOPE_SCHEMA",
    "CASH_RUNWAY_ASSESSMENT_SCHEMA",
    "CashRunwayValidationError",
    "CashProvider",
    "CashFlowMetrics",
    "CashLedgerEvidence",
    "mint_cash_ledger_evidence",
    "verify_cash_ledger_evidence",
    "CashStalenessPolicy",
    "RunwayComponent",
    "BurnBand",
    "CashRunwaySnapshot",
    "BuildRunwayInput",
    "build_runway_snapshot",
    "verify_cash_runway_snapshot",
    "CashBudgetEnvelope",
    "DeriveBudgetEnvelopeInput",
    "derive_budget_envelope",
    "RunwayOpportunity",
    "RunwayAssessment",
    "AssessRunwayInput",
    "assess_runway",
    "BuildRunwaySnapshotPrimitive",
    "DeriveBudgetEnvelopePrimitive",
    "AssessRunwayPrimitive",
]
