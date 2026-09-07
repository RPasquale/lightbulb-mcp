"""Consent-safe abandoned-revenue recovery on the governed profit rail.

The module turns one host-attested, privacy-minimised checkout case into the
existing ``commerce.recover_abandoned_revenue`` profit plan.  Eligible treatment
cases may propose a bounded one-use Shopify discount followed by a Gmail
reminder.  Holdouts, opt-outs, unknown consent, exhausted frequency budgets,
expired cases, unavailable inventory, and unprofitable incentives fail closed.

Raw recipient addresses, recovery URLs, and discount codes are never stored in
the case, plan, result, or receipt.  They are supplied only at the execution
boundary and must match SHA-256 commitments already sealed into the case and
the exact connector-arguments digest stored in the plan.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import threading
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import (
    TYPE_CHECKING,
    Any,
    Iterable,
    Literal,
    Mapping,
    Protocol,
    runtime_checkable,
)
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from lightbulb.connector_execution import ConnectorExecutor, ExecutionScope
from lightbulb.dynamic_workflows import DynamicWorkflowScope
from lightbulb.profit_materializer import (
    EcommerceCreateDiscountArguments,
    GmailSendEmailArguments,
    ProfitActionApprovalGrant,
    ProfitActionMaterializationResult,
    _materialize_recovery_profit_action,
    profit_connector_arguments_digest,
)
from lightbulb.profit_workflow_blueprints import ProfitScopeKeyRing
from lightbulb.profit_workflow_runtime import (
    PlanProfitWorkflowInput,
    ProfitActionExecutionReceipt,
    ProfitActionParameter,
    ProfitConnectorAccountBinding,
    ProfitContributionLedger,
    ProfitLeverCandidate,
    ProfitMetricEvidence,
    ProfitOptimizationPolicy,
    ProfitWorkflowPlan,
    mint_profit_connector_account_binding,
    mint_profit_metric_evidence,
    plan_profit_workflow,
    verify_profit_action_execution_receipt,
    verify_profit_workflow_plan,
)

if TYPE_CHECKING:
    from lightbulb.durable_runtime import WorkflowCheckpoint
    from lightbulb.observation_runtime import ObservationRuntime
    from lightbulb.profit_workflow_runtime import ProfitWorkflowEvaluation


ABANDONED_RECOVERY_CASE_SCHEMA = "lightbulb.abandoned_recovery_case.v1"
ABANDONED_RECOVERY_DISPATCH_ATTESTATION_SCHEMA = (
    "lightbulb.abandoned_recovery_dispatch_attestation.v1"
)
RECOVERY_CONTACT_RESERVATION_REQUEST_SCHEMA = (
    "lightbulb.recovery_contact_reservation_request.v1"
)
RECOVERY_CONTACT_RESERVATION_SCHEMA = "lightbulb.recovery_contact_reservation.v1"
RECOVERY_CONTACT_RESERVATION_CONSUMPTION_SCHEMA = (
    "lightbulb.recovery_contact_reservation_consumption.v1"
)
ABANDONED_RECOVERY_PLAN_SCHEMA = "lightbulb.abandoned_recovery_plan.v1"
ABANDONED_RECOVERY_RUN_SCHEMA = "lightbulb.abandoned_recovery_run.v1"

_CASE_HMAC_DOMAIN = ABANDONED_RECOVERY_CASE_SCHEMA
_DISPATCH_HMAC_DOMAIN = ABANDONED_RECOVERY_DISPATCH_ATTESTATION_SCHEMA
_RESERVATION_HMAC_DOMAIN = RECOVERY_CONTACT_RESERVATION_SCHEMA
_RESERVATION_CONSUMPTION_HMAC_DOMAIN = RECOVERY_CONTACT_RESERVATION_CONSUMPTION_SCHEMA
_ACCOUNT_HMAC_DOMAIN = "lightbulb.profit_connector_account_binding.v1"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_REF_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_PLACEHOLDER_RE = re.compile(r"\{([a-z_]+)\}")
_MONEY = Decimal("0.01")
_RATE = Decimal("0.000001")

ConsentStatus = Literal["opted_in", "opted_out", "unknown"]
RecoveryCohort = Literal["treatment", "holdout"]
RecoveryPlanningStatus = Literal["eligible", "holdout", "suppressed"]
RecoverySuppressionCode = Literal[
    "consent_missing",
    "frequency_cap_reached",
    "inventory_unavailable",
    "case_expired",
    "profit_floor_not_met",
]
RecoveryRunStatus = Literal[
    "preview",
    "pending_approval",
    "completed",
    "blocked",
    "failed",
]


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        revalidate_instances="always",
        serialize_by_alias=True,
        strict=True,
    )


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            default=str,
        ).encode("utf-8")
    ).hexdigest()


def _text_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _parse_time(value: str, *, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise ValueError(f"{label} must be valid ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{label} must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def _time(value: str, *, label: str) -> str:
    return _parse_time(value, label=label).isoformat().replace("+00:00", "Z")


def _utc(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must include a UTC offset")
    return value.astimezone(timezone.utc)


def _decimal(value: Any, *, quantum: Decimal) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (str, int, float, Decimal)):
        raise ValueError("value must be a JSON number or decimal string")
    lexical = str(value)
    if len(lexical) > 48 or lexical != lexical.strip():
        raise ValueError("value must use bounded decimal notation")
    try:
        parsed = Decimal(lexical)
        normalized = parsed.quantize(quantum)
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("value must be finite and bounded") from exc
    if not parsed.is_finite() or parsed != normalized:
        raise ValueError("value exceeds supported precision")
    return normalized


def _visible(value: str, *, label: str, maximum: int) -> str:
    if not isinstance(value, str) or value != value.strip() or not value:
        raise ValueError(f"{label} must be non-blank without surrounding whitespace")
    if len(value) > maximum or any(ord(character) < 33 for character in value):
        raise ValueError(f"{label} contains unsupported characters")
    return value


def _content(value: str, *, label: str, maximum: int) -> str:
    if not isinstance(value, str) or value != value.strip() or not value:
        raise ValueError(f"{label} must be non-blank without surrounding whitespace")
    if len(value) > maximum or any(
        ord(character) < 32 and character not in {"\n", "\r", "\t"}
        for character in value
    ):
        raise ValueError(f"{label} contains unsupported content")
    return value


def recovery_recipient_digest(value: str) -> str:
    """Canonical privacy commitment for a resolved mailbox."""

    clean = _visible(value, label="recipient", maximum=998).casefold()
    if "@" not in clean or "\n" in clean or "\r" in clean:
        raise ValueError("recipient is not a bounded mailbox")
    return _text_digest(clean)


def recovery_url_digest(value: str) -> str:
    """Canonical privacy commitment for a resolved recovery URL."""

    clean = _visible(value, label="recovery_url", maximum=2_048)
    if not clean.startswith("https://"):
        raise ValueError("recovery_url must use HTTPS")
    return _text_digest(clean)


def recovery_discount_code_digest(value: str) -> str:
    """Canonical privacy commitment for a one-time discount code."""

    clean = _visible(value, label="discount_code", maximum=64).upper()
    if not re.fullmatch(r"[A-Z0-9][A-Z0-9_-]{3,63}", clean):
        raise ValueError("discount_code contains unsupported characters")
    return _text_digest(clean)


class AbandonedRecoveryCaseInput(_StrictModel):
    case_ref: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    launch_ref: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    checkout_ref: str = Field(min_length=1, max_length=200)
    customer_ref: str = Field(min_length=1, max_length=200)
    shopify_account_ref: str = Field(min_length=1, max_length=200)
    gmail_account_ref: str = Field(min_length=1, max_length=200)
    recipient_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    recovery_url_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    discount_code_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    abandoned_at: str
    observed_at: str
    expires_at: str
    consent_status: ConsentStatus
    cohort: RecoveryCohort
    inventory_available: bool
    prior_recovery_contacts: int = Field(ge=0, le=100)
    frequency_cap: int = Field(default=2, ge=1, le=5)
    baseline: ProfitContributionLedger
    historical_recovery_ledger: ProfitContributionLedger
    historical_sample_size: int = Field(ge=1, le=1_000_000_000)
    historical_window_start: str
    historical_window_end: str
    evidence_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    expected_incremental_revenue: Decimal = Field(ge=0, le=1_000_000_000)
    expected_incremental_cost: Decimal = Field(ge=0, le=1_000_000_000)
    expected_confidence: Decimal = Field(gt=0, le=1)
    target_recovered_profit: Decimal = Field(ge=0, le=1_000_000_000)
    minimum_margin_rate: Decimal = Field(default=Decimal("0.10"), ge=0, le=1)
    discount_percentage: Decimal | None = Field(default=None, gt=0, le=50)
    discount_expires_at: str | None = None
    email_subject: str = Field(min_length=1, max_length=998)
    reminder_body_template: str = Field(min_length=1, max_length=20_000)
    incentive_body_template: str | None = Field(
        default=None,
        min_length=1,
        max_length=20_000,
    )
    measurement_window_hours: int = Field(default=72, ge=1, le=720)
    minimum_sample_size: int = Field(default=1, ge=1, le=1_000_000_000)
    max_observation_age_hours: int = Field(default=168, ge=1, le=8_760)
    max_iterations: int = Field(default=2, ge=1, le=4)

    @field_validator(
        "checkout_ref",
        "customer_ref",
        "shopify_account_ref",
        "gmail_account_ref",
    )
    @classmethod
    def _refs(cls, value: str, info: Any) -> str:
        return _visible(value, label=info.field_name, maximum=200)

    @field_validator(
        "abandoned_at",
        "observed_at",
        "expires_at",
        "historical_window_start",
        "historical_window_end",
        "discount_expires_at",
    )
    @classmethod
    def _timestamps(cls, value: str | None, info: Any) -> str | None:
        return None if value is None else _time(value, label=info.field_name)

    @field_validator(
        "expected_incremental_revenue",
        "expected_incremental_cost",
        "target_recovered_profit",
        mode="before",
    )
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_MONEY)

    @field_validator(
        "expected_confidence",
        "minimum_margin_rate",
        mode="before",
    )
    @classmethod
    def _rate(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_RATE)

    @field_validator("discount_percentage", mode="before")
    @classmethod
    def _discount(cls, value: Any) -> Decimal | None:
        return None if value is None else _decimal(value, quantum=_MONEY)

    @field_validator("email_subject")
    @classmethod
    def _subject(cls, value: str) -> str:
        clean = _content(value, label="email_subject", maximum=998)
        if "\n" in clean or "\r" in clean:
            raise ValueError("email_subject must not contain line breaks")
        return clean

    @field_validator("reminder_body_template", "incentive_body_template")
    @classmethod
    def _template(cls, value: str | None, info: Any) -> str | None:
        return (
            None
            if value is None
            else _content(value, label=info.field_name, maximum=20_000)
        )

    @model_validator(mode="after")
    def _case_contract(self) -> "AbandonedRecoveryCaseInput":
        abandoned = _parse_time(self.abandoned_at, label="abandoned_at")
        observed = _parse_time(self.observed_at, label="observed_at")
        expires = _parse_time(self.expires_at, label="expires_at")
        if observed < abandoned or expires <= observed:
            raise ValueError("case times must be abandoned <= observed < expires")
        window_start = _parse_time(
            self.historical_window_start,
            label="historical_window_start",
        )
        window_end = _parse_time(
            self.historical_window_end,
            label="historical_window_end",
        )
        if window_end < window_start or observed < window_end:
            raise ValueError("historical evidence window is invalid")
        if self.baseline.currency != self.historical_recovery_ledger.currency:
            raise ValueError("recovery economics must use one currency")
        reminder_tokens = set(_PLACEHOLDER_RE.findall(self.reminder_body_template))
        if reminder_tokens != {"recovery_url"}:
            raise ValueError("reminder template must contain only {recovery_url}")
        incentive_parts = (
            self.discount_percentage,
            self.discount_code_sha256,
            self.discount_expires_at,
            self.incentive_body_template,
        )
        if any(item is not None for item in incentive_parts) and not all(
            item is not None for item in incentive_parts
        ):
            raise ValueError("discount policy fields must be supplied together")
        if self.incentive_body_template is not None:
            incentive_tokens = set(
                _PLACEHOLDER_RE.findall(self.incentive_body_template)
            )
            if incentive_tokens != {"recovery_url", "discount_code"}:
                raise ValueError(
                    "incentive template must contain recovery_url and discount_code only"
                )
            discount_expiry = _parse_time(
                self.discount_expires_at,
                label="discount_expires_at",
            )
            if not observed < discount_expiry <= expires:
                raise ValueError("discount expiry must fall inside the case window")
        return self


class AbandonedRecoveryCase(_StrictModel):
    schema_id: Literal["lightbulb.abandoned_recovery_case.v1"] = Field(
        default=ABANDONED_RECOVERY_CASE_SCHEMA,
        alias="schema",
    )
    case_ref: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    launch_ref: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    checkout_ref: str
    customer_ref: str
    account_bindings: tuple[
        ProfitConnectorAccountBinding, ProfitConnectorAccountBinding
    ]
    recipient_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    recovery_url_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    discount_code_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    abandoned_at: str
    observed_at: str
    expires_at: str
    consent_status: ConsentStatus
    cohort: RecoveryCohort
    inventory_available: bool
    prior_recovery_contacts: int
    frequency_cap: int
    baseline: ProfitContributionLedger
    historical_recovery_ledger: ProfitContributionLedger
    historical_sample_size: int
    historical_window_start: str
    historical_window_end: str
    evidence_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    expected_incremental_revenue: Decimal
    expected_incremental_cost: Decimal
    expected_confidence: Decimal
    target_recovered_profit: Decimal
    minimum_margin_rate: Decimal
    discount_percentage: Decimal | None = None
    discount_expires_at: str | None = None
    email_subject: str
    reminder_body_template: str
    incentive_body_template: str | None = None
    measurement_window_hours: int
    minimum_sample_size: int
    max_observation_age_hours: int
    max_iterations: int
    receipt_key_id: str = Field(min_length=8, max_length=80)
    exact_scope_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    case_hmac: str = Field(pattern=r"^[0-9a-f]{64}$")
    case_digest: str = Field(default="0" * 64, pattern=r"^[0-9a-f]{64}$")

    @field_validator("account_bindings", mode="before")
    @classmethod
    def _bindings(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _sealed_case(self) -> "AbandonedRecoveryCase":
        providers = tuple(item.provider for item in self.account_bindings)
        if providers != ("shopify", "gmail"):
            raise ValueError("recovery case requires Shopify then Gmail bindings")
        if any(
            item.receipt_key_id != self.receipt_key_id
            or item.exact_scope_digest != self.exact_scope_digest
            or item.account_hmac is None
            for item in self.account_bindings
        ):
            raise ValueError("recovery connector bindings do not match case scope")
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"case_hmac", "case_digest"},
            exclude_none=True,
        )
        expected = _digest(payload)
        if self.case_digest not in {"0" * 64, expected}:
            raise ValueError("case_digest does not match canonical recovery case")
        object.__setattr__(self, "case_digest", expected)
        return self

    def hmac_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"case_hmac"},
            exclude_none=True,
        )


class RecoveryDispatchAttestation(_StrictModel):
    """Short-lived host proof that consequential recovery gates are still true."""

    schema_id: Literal["lightbulb.abandoned_recovery_dispatch_attestation.v1"] = Field(
        default=ABANDONED_RECOVERY_DISPATCH_ATTESTATION_SCHEMA,
        alias="schema",
    )
    case_ref: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    case_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    plan_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    consent_status: ConsentStatus
    inventory_available: bool
    prior_recovery_contacts: int = Field(ge=0, le=100)
    observed_at: str
    valid_until: str
    receipt_key_id: str = Field(min_length=8, max_length=80)
    exact_scope_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    attestation_hmac: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("observed_at", "valid_until")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _time(value, label=info.field_name)

    @model_validator(mode="after")
    def _bounded_freshness(self) -> "RecoveryDispatchAttestation":
        observed = _parse_time(self.observed_at, label="observed_at")
        valid_until = _parse_time(self.valid_until, label="valid_until")
        if valid_until <= observed or valid_until - observed > timedelta(minutes=15):
            raise ValueError("dispatch attestation lifetime must be 1-15 minutes")
        return self

    def hmac_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"attestation_hmac"},
        )


class RecoveryContactReservationRequest(_StrictModel):
    """Exact contact slot a host must serialize before recovery writes."""

    schema_id: Literal["lightbulb.recovery_contact_reservation_request.v1"] = Field(
        default=RECOVERY_CONTACT_RESERVATION_REQUEST_SCHEMA,
        alias="schema",
    )
    case_ref: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    case_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    plan_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    recipient_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    action_operation_refs: tuple[str, ...] = Field(min_length=1, max_length=2)
    run_ref: str = Field(min_length=1, max_length=200)
    iteration: int = Field(ge=1, le=4)
    receipt_key_id: str = Field(min_length=8, max_length=80)
    exact_scope_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    request_digest: str = Field(default="0" * 64, pattern=r"^[0-9a-f]{64}$")

    @field_validator("action_operation_refs", mode="before")
    @classmethod
    def _operations(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _sealed(self) -> "RecoveryContactReservationRequest":
        if len(set(self.action_operation_refs)) != len(self.action_operation_refs):
            raise ValueError("contact reservation operations must be unique")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"request_digest"},
        )
        expected = _digest(material)
        if self.request_digest not in {"0" * 64, expected}:
            raise ValueError("contact reservation request digest mismatch")
        object.__setattr__(self, "request_digest", expected)
        return self

    @property
    def slot_digest(self) -> str:
        """Run-independent slot; concurrent run refs contend for this identity."""

        return _digest(
            {
                "schema": "lightbulb.recovery_contact_slot.v1",
                "case_digest": self.case_digest,
                "recipient_sha256": self.recipient_sha256,
                "action_operation_refs": self.action_operation_refs,
                "iteration": self.iteration,
                "exact_scope_digest": self.exact_scope_digest,
            }
        )


class RecoveryContactReservation(_StrictModel):
    """Short-lived HMAC proof registered by a transactional host authority."""

    schema_id: Literal["lightbulb.recovery_contact_reservation.v1"] = Field(
        default=RECOVERY_CONTACT_RESERVATION_SCHEMA,
        alias="schema",
    )
    reservation_ref: str = Field(min_length=1, max_length=200)
    request: RecoveryContactReservationRequest
    slot_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    reserved_at: str
    valid_until: str
    reservation_hmac: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("reserved_at", "valid_until")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _time(value, label=info.field_name)

    @model_validator(mode="after")
    def _bounded(self) -> "RecoveryContactReservation":
        reserved = _parse_time(self.reserved_at, label="reserved_at")
        valid_until = _parse_time(self.valid_until, label="valid_until")
        if valid_until <= reserved or valid_until - reserved > timedelta(minutes=15):
            raise ValueError("contact reservation lifetime must be 1-15 minutes")
        if self.slot_digest != self.request.slot_digest:
            raise ValueError("contact reservation slot digest mismatch")
        return self

    def hmac_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"reservation_hmac"},
        )


class RecoveryContactReservationConsumption(_StrictModel):
    """Idempotent proof that one exact reservation owns the contact slot."""

    schema_id: Literal["lightbulb.recovery_contact_reservation_consumption.v1"] = Field(
        default=RECOVERY_CONTACT_RESERVATION_CONSUMPTION_SCHEMA,
        alias="schema",
    )
    consumption_ref: str = Field(min_length=1, max_length=200)
    reservation_ref: str = Field(min_length=1, max_length=200)
    request_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    slot_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    consumed_at: str
    receipt_key_id: str = Field(min_length=8, max_length=80)
    exact_scope_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    consumption_hmac: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("consumed_at")
    @classmethod
    def _consumed(cls, value: str) -> str:
        return _time(value, label="consumed_at")

    def hmac_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude={"consumption_hmac"})


class RecoveryContactReservationConflict(RuntimeError):
    """Another run owns or has consumed the exact recipient/case/action slot."""


@runtime_checkable
class RecoveryContactReservationAuthority(Protocol):
    """Host transaction boundary; production implementations must be durable."""

    def reserve(
        self,
        request: RecoveryContactReservationRequest,
        *,
        reserved_at: datetime,
        valid_until: datetime,
    ) -> RecoveryContactReservation: ...

    def consume(
        self,
        reservation: RecoveryContactReservation,
        *,
        request: RecoveryContactReservationRequest,
        consumed_at: datetime,
    ) -> RecoveryContactReservationConsumption: ...


class RecoveryResolvedSecrets(_StrictModel):
    recipient: str = Field(min_length=3, max_length=998, repr=False)
    recovery_url: str = Field(min_length=9, max_length=2_048, repr=False)
    discount_code: str | None = Field(
        default=None,
        min_length=4,
        max_length=64,
        repr=False,
    )

    @model_validator(mode="after")
    def _secrets(self) -> "RecoveryResolvedSecrets":
        recovery_recipient_digest(self.recipient)
        recovery_url_digest(self.recovery_url)
        if self.discount_code is not None:
            recovery_discount_code_digest(self.discount_code)
        return self


class RecoveryActionBrief(_StrictModel):
    operation_ref: str
    capability: Literal["ecommerce.create_discount", "gmail.send_email"]
    connector_account_ref: str
    connector_arguments_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    depends_on: tuple[str, ...] = ()

    @field_validator("depends_on", mode="before")
    @classmethod
    def _dependencies(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value


class AbandonedRecoveryPlan(_StrictModel):
    schema_id: Literal["lightbulb.abandoned_recovery_plan.v1"] = Field(
        default=ABANDONED_RECOVERY_PLAN_SCHEMA,
        alias="schema",
    )
    status: RecoveryPlanningStatus
    case_ref: str
    case_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    analysis_as_of: str
    suppression_codes: tuple[RecoverySuppressionCode, ...] = ()
    profit_plan: ProfitWorkflowPlan | None = None
    actions: tuple[RecoveryActionBrief, ...] = ()
    discount_included: bool = False
    summary: str = Field(min_length=1, max_length=1_000)

    @field_validator("suppression_codes", "actions", mode="before")
    @classmethod
    def _collections(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("analysis_as_of")
    @classmethod
    def _analysis(cls, value: str) -> str:
        return _time(value, label="analysis_as_of")

    @model_validator(mode="after")
    def _status(self) -> "AbandonedRecoveryPlan":
        eligible = self.status == "eligible"
        if eligible != (self.profit_plan is not None and bool(self.actions)):
            raise ValueError(
                "only eligible recovery plans may contain executable actions"
            )
        if self.status == "holdout" and self.suppression_codes:
            raise ValueError(
                "holdout is an experiment cohort, not a suppression failure"
            )
        if self.status == "suppressed" and not self.suppression_codes:
            raise ValueError("suppressed recovery requires at least one reason")
        if self.profit_plan is not None and (
            self.profit_plan.workflow_id != "commerce.recover_abandoned_revenue"
            or self.case_digest not in self.profit_plan.source_plan_digests
        ):
            raise ValueError("profit plan is not bound to this recovery case")
        return self


class AbandonedRecoveryRun(_StrictModel):
    schema_id: Literal["lightbulb.abandoned_recovery_run.v1"] = Field(
        default=ABANDONED_RECOVERY_RUN_SCHEMA,
        alias="schema",
    )
    status: RecoveryRunStatus
    case_ref: str
    case_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    plan_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    run_ref: str
    iteration: int = Field(ge=1, le=4)
    action_results: tuple[ProfitActionMaterializationResult, ...]
    receipts: tuple[ProfitActionExecutionReceipt, ...]
    observation_due_at: str | None = None
    causal_claim_ready: Literal[False] = False
    summary: str = Field(min_length=1, max_length=1_000)

    @field_validator("action_results", "receipts", mode="before")
    @classmethod
    def _collections(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("observation_due_at")
    @classmethod
    def _due(cls, value: str | None) -> str | None:
        return None if value is None else _time(value, label="observation_due_at")

    @model_validator(mode="after")
    def _completed(self) -> "AbandonedRecoveryRun":
        if (self.status == "completed") != (
            bool(self.receipts) and self.observation_due_at is not None
        ):
            raise ValueError(
                "completed recovery requires receipts and an observation due time"
            )
        if self.status != "completed" and self.observation_due_at is not None:
            raise ValueError("only completed recovery may schedule outcome observation")
        return self


def _workflow_scope(
    value: DynamicWorkflowScope | Mapping[str, Any],
) -> DynamicWorkflowScope:
    return (
        value
        if isinstance(value, DynamicWorkflowScope)
        else DynamicWorkflowScope.model_validate(value)
    )


def mint_abandoned_recovery_case(
    value: AbandonedRecoveryCaseInput | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ProfitScopeKeyRing,
    scope_key_id: str | None = None,
) -> AbandonedRecoveryCase:
    """Host-seal one privacy-minimised recovery case and exact account route."""

    inputs = AbandonedRecoveryCaseInput.model_validate(
        value.model_dump(mode="python")
        if isinstance(value, AbandonedRecoveryCaseInput)
        else value
    )
    workflow_scope = _workflow_scope(scope)
    key_id = scope_key_id or str(scope_keyring.active_key_id).strip()
    shopify_binding = mint_profit_connector_account_binding(
        {
            "provider": "shopify",
            "connector_account_ref": inputs.shopify_account_ref,
        },
        scope=workflow_scope,
        scope_keyring=scope_keyring,
        scope_key_id=key_id,
    )
    gmail_binding = mint_profit_connector_account_binding(
        {
            "provider": "gmail",
            "connector_account_ref": inputs.gmail_account_ref,
        },
        scope=workflow_scope,
        scope_keyring=scope_keyring,
        scope_key_id=key_id,
    )
    exact_scope_digest = scope_keyring.exact_scope_digest(
        key_id=key_id,
        scope=workflow_scope,
    )
    fields = inputs.model_dump(
        mode="python",
        exclude={"shopify_account_ref", "gmail_account_ref"},
    )
    draft = AbandonedRecoveryCase(
        **fields,
        account_bindings=(shopify_binding, gmail_binding),
        receipt_key_id=key_id,
        exact_scope_digest=exact_scope_digest,
        case_hmac="0" * 64,
    )
    signature = scope_keyring.sign(
        key_id,
        _CASE_HMAC_DOMAIN,
        draft.hmac_payload(),
    ).hex()
    return AbandonedRecoveryCase.model_validate(
        {**draft.model_dump(mode="python", by_alias=True), "case_hmac": signature}
    )


def verify_abandoned_recovery_case(
    value: AbandonedRecoveryCase | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ProfitScopeKeyRing,
) -> AbandonedRecoveryCase:
    case = AbandonedRecoveryCase.model_validate(
        value.model_dump(mode="python", by_alias=True)
        if isinstance(value, AbandonedRecoveryCase)
        else value
    )
    workflow_scope = _workflow_scope(scope)
    expected_scope = scope_keyring.exact_scope_digest(
        key_id=case.receipt_key_id,
        scope=workflow_scope,
    )
    if not hmac.compare_digest(case.exact_scope_digest, expected_scope):
        raise ValueError("recovery case scope does not match authenticated scope")
    expected_case_hmac = scope_keyring.sign(
        case.receipt_key_id,
        _CASE_HMAC_DOMAIN,
        case.hmac_payload(),
    ).hex()
    if not hmac.compare_digest(case.case_hmac, expected_case_hmac):
        raise ValueError("recovery case HMAC is invalid")
    for binding in case.account_bindings:
        expected_account_hmac = scope_keyring.sign(
            binding.receipt_key_id,
            _ACCOUNT_HMAC_DOMAIN,
            binding.hmac_payload(),
        ).hex()
        if binding.account_hmac is None or not hmac.compare_digest(
            binding.account_hmac,
            expected_account_hmac,
        ):
            raise ValueError("recovery connector account binding HMAC is invalid")
    return case


def build_recovery_contact_reservation_request(
    recovery_plan_value: AbandonedRecoveryPlan | Mapping[str, Any],
    case_value: AbandonedRecoveryCase | Mapping[str, Any],
    *,
    run_ref: str,
    iteration: int = 1,
) -> RecoveryContactReservationRequest:
    """Bind one run to the complete recovery action graph and recipient hash."""

    recovery_plan = AbandonedRecoveryPlan.model_validate(
        recovery_plan_value.model_dump(mode="python", by_alias=True)
        if isinstance(recovery_plan_value, AbandonedRecoveryPlan)
        else recovery_plan_value
    )
    case = AbandonedRecoveryCase.model_validate(
        case_value.model_dump(mode="python", by_alias=True)
        if isinstance(case_value, AbandonedRecoveryCase)
        else case_value
    )
    if recovery_plan.status != "eligible" or recovery_plan.profit_plan is None:
        raise ValueError("only an eligible recovery plan may reserve contact")
    if recovery_plan.case_digest != case.case_digest:
        raise ValueError("contact reservation plan does not match recovery case")
    return RecoveryContactReservationRequest(
        case_ref=case.case_ref,
        case_digest=case.case_digest,
        plan_digest=recovery_plan.profit_plan.plan_digest,
        recipient_sha256=case.recipient_sha256,
        action_operation_refs=tuple(
            action.operation_ref for action in recovery_plan.profit_plan.actions
        ),
        run_ref=_visible(run_ref, label="run_ref", maximum=200),
        iteration=iteration,
        receipt_key_id=case.receipt_key_id,
        exact_scope_digest=case.exact_scope_digest,
    )


def mint_recovery_contact_reservation(
    request_value: RecoveryContactReservationRequest | Mapping[str, Any],
    *,
    reservation_ref: str,
    reserved_at: datetime,
    valid_until: datetime,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ProfitScopeKeyRing,
) -> RecoveryContactReservation:
    request = RecoveryContactReservationRequest.model_validate(
        request_value.model_dump(mode="python", by_alias=True)
        if isinstance(request_value, RecoveryContactReservationRequest)
        else request_value
    )
    workflow_scope = _workflow_scope(scope)
    expected_scope = scope_keyring.exact_scope_digest(
        key_id=request.receipt_key_id,
        scope=workflow_scope,
    )
    if not hmac.compare_digest(request.exact_scope_digest, expected_scope):
        raise ValueError("contact reservation request scope is invalid")
    draft = RecoveryContactReservation(
        reservation_ref=_visible(reservation_ref, label="reservation_ref", maximum=200),
        request=request,
        slot_digest=request.slot_digest,
        reserved_at=_time(reserved_at.isoformat(), label="reserved_at"),
        valid_until=_time(valid_until.isoformat(), label="valid_until"),
        reservation_hmac="0" * 64,
    )
    signature = scope_keyring.sign(
        request.receipt_key_id,
        _RESERVATION_HMAC_DOMAIN,
        draft.hmac_payload(),
    ).hex()
    return RecoveryContactReservation.model_validate(
        {
            **draft.model_dump(mode="python", by_alias=True),
            "reservation_hmac": signature,
        }
    )


def verify_recovery_contact_reservation(
    value: RecoveryContactReservation | Mapping[str, Any],
    *,
    request: RecoveryContactReservationRequest,
    at: datetime,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ProfitScopeKeyRing,
) -> RecoveryContactReservation:
    reservation = RecoveryContactReservation.model_validate(
        value.model_dump(mode="python", by_alias=True)
        if isinstance(value, RecoveryContactReservation)
        else value
    )
    workflow_scope = _workflow_scope(scope)
    if reservation.request.request_digest != request.request_digest:
        raise ValueError("contact reservation does not match this run")
    expected_scope = scope_keyring.exact_scope_digest(
        key_id=request.receipt_key_id,
        scope=workflow_scope,
    )
    if not hmac.compare_digest(request.exact_scope_digest, expected_scope):
        raise ValueError("contact reservation scope is invalid")
    expected_hmac = scope_keyring.sign(
        request.receipt_key_id,
        _RESERVATION_HMAC_DOMAIN,
        reservation.hmac_payload(),
    ).hex()
    if not hmac.compare_digest(reservation.reservation_hmac, expected_hmac):
        raise ValueError("contact reservation HMAC is invalid")
    timestamp = _utc(at, label="at")
    if timestamp < _parse_time(
        reservation.reserved_at, label="reserved_at"
    ) or timestamp >= _parse_time(reservation.valid_until, label="valid_until"):
        raise ValueError("contact reservation is not current")
    return reservation


def mint_recovery_contact_reservation_consumption(
    reservation: RecoveryContactReservation,
    *,
    consumed_at: datetime,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ProfitScopeKeyRing,
) -> RecoveryContactReservationConsumption:
    request = reservation.request
    verify_recovery_contact_reservation(
        reservation,
        request=request,
        at=consumed_at,
        scope=scope,
        scope_keyring=scope_keyring,
    )
    consumed_text = _time(consumed_at.isoformat(), label="consumed_at")
    draft = RecoveryContactReservationConsumption(
        consumption_ref=f"consumed_{_digest((reservation.reservation_ref, consumed_text))[:40]}",
        reservation_ref=reservation.reservation_ref,
        request_digest=request.request_digest,
        slot_digest=request.slot_digest,
        consumed_at=consumed_text,
        receipt_key_id=request.receipt_key_id,
        exact_scope_digest=request.exact_scope_digest,
        consumption_hmac="0" * 64,
    )
    signature = scope_keyring.sign(
        request.receipt_key_id,
        _RESERVATION_CONSUMPTION_HMAC_DOMAIN,
        draft.hmac_payload(),
    ).hex()
    return RecoveryContactReservationConsumption.model_validate(
        {
            **draft.model_dump(mode="python", by_alias=True),
            "consumption_hmac": signature,
        }
    )


def verify_recovery_contact_reservation_consumption(
    value: RecoveryContactReservationConsumption | Mapping[str, Any],
    *,
    reservation: RecoveryContactReservation,
    request: RecoveryContactReservationRequest,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ProfitScopeKeyRing,
) -> RecoveryContactReservationConsumption:
    consumption = RecoveryContactReservationConsumption.model_validate(
        value.model_dump(mode="python", by_alias=True)
        if isinstance(value, RecoveryContactReservationConsumption)
        else value
    )
    workflow_scope = _workflow_scope(scope)
    expected_scope = scope_keyring.exact_scope_digest(
        key_id=consumption.receipt_key_id,
        scope=workflow_scope,
    )
    if (
        consumption.reservation_ref != reservation.reservation_ref
        or consumption.request_digest != request.request_digest
        or consumption.slot_digest != request.slot_digest
        or consumption.receipt_key_id != request.receipt_key_id
        or not hmac.compare_digest(consumption.exact_scope_digest, expected_scope)
    ):
        raise ValueError("contact reservation consumption does not match this run")
    expected_hmac = scope_keyring.sign(
        consumption.receipt_key_id,
        _RESERVATION_CONSUMPTION_HMAC_DOMAIN,
        consumption.hmac_payload(),
    ).hex()
    if not hmac.compare_digest(consumption.consumption_hmac, expected_hmac):
        raise ValueError("contact reservation consumption HMAC is invalid")
    return consumption


class InMemoryRecoveryContactReservationAuthority:
    """Atomic reference authority; production hosts need durable transactions."""

    def __init__(
        self,
        *,
        scope: DynamicWorkflowScope | Mapping[str, Any],
        scope_keyring: ProfitScopeKeyRing,
    ) -> None:
        self.scope = _workflow_scope(scope)
        self.scope_keyring = scope_keyring
        self._active: dict[str, RecoveryContactReservation] = {}
        self._closed_slots: set[str] = set()
        self._consumptions: dict[str, RecoveryContactReservationConsumption] = {}
        self._lock = threading.RLock()

    def reserve(
        self,
        request: RecoveryContactReservationRequest,
        *,
        reserved_at: datetime,
        valid_until: datetime,
    ) -> RecoveryContactReservation:
        timestamp = _utc(reserved_at, label="reserved_at")
        with self._lock:
            if request.slot_digest in self._closed_slots:
                raise RecoveryContactReservationConflict(
                    "the recovery contact slot was already consumed"
                )
            active = self._active.get(request.slot_digest)
            if active is not None:
                if active.request.request_digest == request.request_digest:
                    if timestamp < _parse_time(active.valid_until, label="valid_until"):
                        return active
                elif timestamp < _parse_time(active.valid_until, label="valid_until"):
                    raise RecoveryContactReservationConflict(
                        "another recovery run owns the contact slot"
                    )
                self._active.pop(request.slot_digest, None)
            reservation = mint_recovery_contact_reservation(
                request,
                reservation_ref=f"reservation_{request.request_digest[:40]}",
                reserved_at=timestamp,
                valid_until=valid_until,
                scope=self.scope,
                scope_keyring=self.scope_keyring,
            )
            self._active[request.slot_digest] = reservation
            return reservation

    def consume(
        self,
        reservation: RecoveryContactReservation,
        *,
        request: RecoveryContactReservationRequest,
        consumed_at: datetime,
    ) -> RecoveryContactReservationConsumption:
        trusted = verify_recovery_contact_reservation(
            reservation,
            request=request,
            at=consumed_at,
            scope=self.scope,
            scope_keyring=self.scope_keyring,
        )
        with self._lock:
            existing = self._consumptions.get(trusted.reservation_ref)
            if existing is not None:
                return verify_recovery_contact_reservation_consumption(
                    existing,
                    reservation=trusted,
                    request=request,
                    scope=self.scope,
                    scope_keyring=self.scope_keyring,
                )
            active = self._active.get(request.slot_digest)
            if active is None or active.reservation_ref != trusted.reservation_ref:
                raise RecoveryContactReservationConflict(
                    "contact reservation is not the active transactional slot"
                )
            consumption = mint_recovery_contact_reservation_consumption(
                trusted,
                consumed_at=consumed_at,
                scope=self.scope,
                scope_keyring=self.scope_keyring,
            )
            self._consumptions[trusted.reservation_ref] = consumption
            self._closed_slots.add(request.slot_digest)
            self._active.pop(request.slot_digest, None)
            return consumption


def mint_recovery_dispatch_attestation(
    recovery_plan_value: AbandonedRecoveryPlan | Mapping[str, Any],
    case_value: AbandonedRecoveryCase | Mapping[str, Any],
    *,
    consent_status: ConsentStatus,
    inventory_available: bool,
    prior_recovery_contacts: int,
    observed_at: datetime,
    valid_until: datetime,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ProfitScopeKeyRing,
) -> RecoveryDispatchAttestation:
    """Host-seal a short-lived recheck immediately before connector dispatch."""

    workflow_scope = _workflow_scope(scope)
    case = verify_abandoned_recovery_case(
        case_value,
        scope=workflow_scope,
        scope_keyring=scope_keyring,
    )
    recovery_plan = AbandonedRecoveryPlan.model_validate(
        recovery_plan_value.model_dump(mode="python", by_alias=True)
        if isinstance(recovery_plan_value, AbandonedRecoveryPlan)
        else recovery_plan_value
    )
    if recovery_plan.status != "eligible" or recovery_plan.profit_plan is None:
        raise ValueError("only an eligible recovery plan may be attested")
    if recovery_plan.case_digest != case.case_digest:
        raise ValueError("dispatch attestation plan does not match the recovery case")
    plan = verify_profit_workflow_plan(
        recovery_plan.profit_plan,
        scope=workflow_scope,
        scope_keyring=scope_keyring,
    )
    if (
        observed_at.tzinfo is None
        or observed_at.utcoffset() is None
        or valid_until.tzinfo is None
        or valid_until.utcoffset() is None
    ):
        raise ValueError("dispatch attestation times must include UTC offsets")
    observed_text = _time(
        observed_at.astimezone(timezone.utc).isoformat(),
        label="observed_at",
    )
    valid_until_text = _time(
        valid_until.astimezone(timezone.utc).isoformat(),
        label="valid_until",
    )
    draft = RecoveryDispatchAttestation(
        case_ref=case.case_ref,
        case_digest=case.case_digest,
        plan_digest=plan.plan_digest,
        consent_status=consent_status,
        inventory_available=inventory_available,
        prior_recovery_contacts=prior_recovery_contacts,
        observed_at=observed_text,
        valid_until=valid_until_text,
        receipt_key_id=case.receipt_key_id,
        exact_scope_digest=case.exact_scope_digest,
        attestation_hmac="0" * 64,
    )
    signature = scope_keyring.sign(
        case.receipt_key_id,
        _DISPATCH_HMAC_DOMAIN,
        draft.hmac_payload(),
    ).hex()
    return RecoveryDispatchAttestation.model_validate(
        {
            **draft.model_dump(mode="python", by_alias=True),
            "attestation_hmac": signature,
        }
    )


def verify_recovery_dispatch_attestation(
    value: RecoveryDispatchAttestation | Mapping[str, Any],
    *,
    recovery_plan: AbandonedRecoveryPlan,
    case: AbandonedRecoveryCase,
    dispatch_at: datetime,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ProfitScopeKeyRing,
) -> RecoveryDispatchAttestation:
    """Verify exact scope, freshness, and mutable safety gates before I/O."""

    attestation = RecoveryDispatchAttestation.model_validate(
        value.model_dump(mode="python", by_alias=True)
        if isinstance(value, RecoveryDispatchAttestation)
        else value
    )
    workflow_scope = _workflow_scope(scope)
    exact_scope_digest = scope_keyring.exact_scope_digest(
        key_id=attestation.receipt_key_id,
        scope=workflow_scope,
    )
    if not hmac.compare_digest(
        attestation.exact_scope_digest,
        exact_scope_digest,
    ):
        raise ValueError(
            "dispatch attestation scope does not match authenticated scope"
        )
    if (
        attestation.case_ref != case.case_ref
        or attestation.case_digest != case.case_digest
        or recovery_plan.profit_plan is None
        or attestation.plan_digest != recovery_plan.profit_plan.plan_digest
        or attestation.receipt_key_id != case.receipt_key_id
    ):
        raise ValueError("dispatch attestation does not match the recovery plan")
    expected_hmac = scope_keyring.sign(
        attestation.receipt_key_id,
        _DISPATCH_HMAC_DOMAIN,
        attestation.hmac_payload(),
    ).hex()
    if not hmac.compare_digest(attestation.attestation_hmac, expected_hmac):
        raise ValueError("dispatch attestation HMAC is invalid")
    dispatch_time = dispatch_at.astimezone(timezone.utc)
    observed = _parse_time(attestation.observed_at, label="observed_at")
    valid_until = _parse_time(attestation.valid_until, label="valid_until")
    if dispatch_time < observed or dispatch_time >= valid_until:
        raise ValueError("dispatch attestation is not current at execution time")
    if dispatch_time >= _parse_time(case.expires_at, label="expires_at"):
        raise ValueError("recovery case expired before connector dispatch")
    if case.discount_expires_at is not None and recovery_plan.discount_included:
        if dispatch_time >= _parse_time(
            case.discount_expires_at,
            label="discount_expires_at",
        ):
            raise ValueError("recovery discount expired before connector dispatch")
    if attestation.consent_status != "opted_in":
        raise ValueError("current recovery consent does not permit contact")
    if not attestation.inventory_available:
        raise ValueError("current recovery inventory is unavailable")
    if attestation.prior_recovery_contacts < case.prior_recovery_contacts:
        raise ValueError("current recovery contact count cannot move backwards")
    if attestation.prior_recovery_contacts >= case.frequency_cap:
        raise ValueError("current recovery frequency cap is exhausted")
    return attestation


def _secrets(
    value: RecoveryResolvedSecrets | Mapping[str, Any],
    case: AbandonedRecoveryCase,
) -> RecoveryResolvedSecrets:
    resolved = RecoveryResolvedSecrets.model_validate(
        value.model_dump(mode="python")
        if isinstance(value, RecoveryResolvedSecrets)
        else value
    )
    if not hmac.compare_digest(
        recovery_recipient_digest(resolved.recipient),
        case.recipient_sha256,
    ):
        raise ValueError("resolved recipient does not match the recovery case")
    if not hmac.compare_digest(
        recovery_url_digest(resolved.recovery_url),
        case.recovery_url_sha256,
    ):
        raise ValueError("resolved recovery URL does not match the recovery case")
    if case.discount_code_sha256 is None:
        if resolved.discount_code is not None:
            raise ValueError("case did not authorize a discount code")
    elif resolved.discount_code is None or not hmac.compare_digest(
        recovery_discount_code_digest(resolved.discount_code),
        case.discount_code_sha256,
    ):
        raise ValueError("resolved discount code does not match the recovery case")
    return resolved


def _margin_after_discount(case: AbandonedRecoveryCase) -> Decimal | None:
    if case.discount_percentage is None:
        return None
    gross = case.baseline.gross_sales
    if gross <= 0:
        return Decimal("0")
    discount_cost = (gross * case.discount_percentage / Decimal("100")).quantize(
        _MONEY, rounding=ROUND_HALF_UP
    )
    return ((case.baseline.contribution_profit - discount_cost) / gross).quantize(
        _RATE,
        rounding=ROUND_HALF_UP,
    )


def _connector_arguments(
    case: AbandonedRecoveryCase,
    secrets: RecoveryResolvedSecrets,
    *,
    capability: str,
    discount_included: bool,
) -> GmailSendEmailArguments | EcommerceCreateDiscountArguments:
    if capability == "ecommerce.create_discount":
        if (
            not discount_included
            or case.discount_percentage is None
            or case.discount_expires_at is None
            or secrets.discount_code is None
        ):
            raise ValueError("recovery plan has no approved discount payload")
        return EcommerceCreateDiscountArguments(
            title=f"Recovery {case.case_ref}",
            code=secrets.discount_code.upper(),
            percentage=case.discount_percentage,
            starts_at=case.observed_at,
            ends_at=case.discount_expires_at,
            usage_limit=1,
        )
    if capability == "gmail.send_email":
        template = (
            case.incentive_body_template
            if discount_included
            else case.reminder_body_template
        )
        if template is None:
            raise ValueError("recovery email template is unavailable")
        body = template.replace("{recovery_url}", secrets.recovery_url)
        if discount_included:
            if secrets.discount_code is None:
                raise ValueError("recovery discount code was not resolved")
            body = body.replace("{discount_code}", secrets.discount_code.upper())
        return GmailSendEmailArguments(
            to=secrets.recipient.casefold(),
            subject=case.email_subject,
            body=body,
            html=False,
        )
    raise ValueError("unsupported recovery action capability")


def plan_abandoned_revenue_recovery(
    case_value: AbandonedRecoveryCase | Mapping[str, Any],
    *,
    resolved_secrets: RecoveryResolvedSecrets | Mapping[str, Any],
    analysis_as_of: datetime,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ProfitScopeKeyRing,
) -> AbandonedRecoveryPlan:
    """Compile a deterministic holdout/suppression/action decision for one case."""

    workflow_scope = _workflow_scope(scope)
    case = verify_abandoned_recovery_case(
        case_value,
        scope=workflow_scope,
        scope_keyring=scope_keyring,
    )
    secrets = _secrets(resolved_secrets, case)
    if analysis_as_of.tzinfo is None or analysis_as_of.utcoffset() is None:
        raise ValueError("analysis_as_of must include a UTC offset")
    analysis = analysis_as_of.astimezone(timezone.utc)
    analysis_text = analysis.isoformat().replace("+00:00", "Z")
    if analysis < _parse_time(case.observed_at, label="observed_at"):
        raise ValueError("analysis_as_of cannot precede case observation")
    if case.cohort == "holdout":
        return AbandonedRecoveryPlan(
            status="holdout",
            case_ref=case.case_ref,
            case_digest=case.case_digest,
            analysis_as_of=analysis_text,
            summary="Holdout case retained for causal measurement; no recovery action was planned.",
        )
    suppression: list[RecoverySuppressionCode] = []
    if case.consent_status != "opted_in":
        suppression.append("consent_missing")
    if case.prior_recovery_contacts >= case.frequency_cap:
        suppression.append("frequency_cap_reached")
    if not case.inventory_available:
        suppression.append("inventory_unavailable")
    if analysis >= _parse_time(case.expires_at, label="expires_at"):
        suppression.append("case_expired")
    expected_profit = (
        case.expected_incremental_revenue - case.expected_incremental_cost
    ).quantize(_MONEY)
    if expected_profit <= 0:
        suppression.append("profit_floor_not_met")
    if suppression:
        return AbandonedRecoveryPlan(
            status="suppressed",
            case_ref=case.case_ref,
            case_digest=case.case_digest,
            analysis_as_of=analysis_text,
            suppression_codes=tuple(dict.fromkeys(suppression)),
            summary="Recovery was suppressed before any approval or connector dispatch.",
        )

    margin_after_discount = _margin_after_discount(case)
    discount_included = (
        margin_after_discount is not None
        and margin_after_discount >= case.minimum_margin_rate
        and case.discount_expires_at is not None
        and secrets.discount_code is not None
    )
    shopify_account = case.account_bindings[0].connector_account_ref
    gmail_account = case.account_bindings[1].connector_account_ref
    candidates: list[ProfitLeverCandidate] = []
    argument_briefs: list[tuple[str, str, str]] = []
    if discount_included:
        discount_args = _connector_arguments(
            case,
            secrets,
            capability="ecommerce.create_discount",
            discount_included=True,
        )
        discount_digest = profit_connector_arguments_digest(
            "ecommerce.create_discount",
            discount_args,
        )
        candidates.append(
            ProfitLeverCandidate(
                candidate_ref="bounded_discount",
                title="Create one bounded recovery discount",
                capability="ecommerce.create_discount",
                target_account_ref=shopify_account,
                rationale="Use one expiring, one-use incentive without breaching the margin floor.",
                parameters=(
                    ProfitActionParameter(
                        name="connector_arguments_digest",
                        value=discount_digest,
                    ),
                    ProfitActionParameter(name="case_ref", value=case.case_ref),
                    ProfitActionParameter(name="usage_limit", value="1"),
                ),
                expected_incremental_revenue=case.expected_incremental_cost,
                expected_incremental_cost=case.expected_incremental_cost,
                implementation_cost="0.00",
                downside_loss="0.00",
                confidence="1.000000",
                time_to_value_days=0,
                measurement_metric="recovered_contribution_profit",
                supported_by_evidence_refs=("recovery_snapshot",),
            )
        )
        argument_briefs.append(
            ("ecommerce.create_discount", shopify_account, discount_digest)
        )

    email_args = _connector_arguments(
        case,
        secrets,
        capability="gmail.send_email",
        discount_included=discount_included,
    )
    email_digest = profit_connector_arguments_digest("gmail.send_email", email_args)
    email_dependencies = ("bounded_discount",) if discount_included else ()
    candidates.append(
        ProfitLeverCandidate(
            candidate_ref="consent_safe_email",
            title="Send one consent-safe checkout reminder",
            capability="gmail.send_email",
            target_account_ref=gmail_account,
            rationale="Recover an in-stock checkout with exact consent and frequency controls.",
            parameters=(
                ProfitActionParameter(
                    name="connector_arguments_digest",
                    value=email_digest,
                ),
                ProfitActionParameter(name="case_ref", value=case.case_ref),
                ProfitActionParameter(
                    name="frequency_cap", value=str(case.frequency_cap)
                ),
                ProfitActionParameter(name="cohort", value=case.cohort),
            ),
            expected_incremental_revenue=case.expected_incremental_revenue,
            expected_incremental_cost=case.expected_incremental_cost,
            implementation_cost="0.00",
            downside_loss="0.00",
            confidence=case.expected_confidence,
            time_to_value_days=1,
            measurement_metric="recovered_contribution_profit",
            supported_by_evidence_refs=("recovery_snapshot",),
            depends_on=email_dependencies,
        )
    )
    argument_briefs.append(("gmail.send_email", gmail_account, email_digest))

    evidence = mint_profit_metric_evidence(
        ProfitMetricEvidence(
            evidence_ref="recovery_snapshot",
            provider="host",
            subject_account_refs=(shopify_account, gmail_account),
            source_capability="host.checkout_recovery_snapshot",
            metric="recovered_contribution_profit",
            unit="money",
            value=case.historical_recovery_ledger.contribution_profit,
            currency=case.baseline.currency,
            sample_size=case.historical_sample_size,
            observed_at=case.observed_at,
            window_start=case.historical_window_start,
            window_end=case.historical_window_end,
            ledger=case.historical_recovery_ledger,
            evidence_digest=case.evidence_digest,
        ),
        scope=workflow_scope,
        scope_keyring=scope_keyring,
        scope_key_id=case.receipt_key_id,
    )
    plan = plan_profit_workflow(
        "commerce.recover_abandoned_revenue",
        PlanProfitWorkflowInput(
            analysis_as_of=analysis_text,
            plan_ref=f"recovery_{case.case_digest[:24]}",
            launch_ref=case.launch_ref,
            objective="Recover incremental contribution profit from one eligible abandoned checkout.",
            account_bindings=case.account_bindings,
            baseline=case.baseline,
            evidence=(evidence,),
            candidates=tuple(candidates),
            policy=ProfitOptimizationPolicy(
                target_metric="recovered_contribution_profit",
                target_value=case.target_recovered_profit,
                max_actions=len(candidates),
                budget_cap=(
                    case.expected_incremental_cost
                    * (Decimal("2") if discount_included else Decimal("1"))
                ).quantize(_MONEY),
                minimum_expected_profit="0.00",
                minimum_confidence="0.01",
                unverified_confidence_haircut="0.50",
                minimum_sample_size=case.minimum_sample_size,
                max_observation_age_hours=case.max_observation_age_hours,
                measurement_window_hours=case.measurement_window_hours,
                max_iterations=case.max_iterations,
            ),
            source_plan_digests=(case.case_digest,),
        ),
        verified_scope=workflow_scope,
        scope_keyring=scope_keyring,
        scope_key_id=case.receipt_key_id,
    )
    expected_capabilities = [item[0] for item in argument_briefs]
    if [item.capability for item in plan.actions] != expected_capabilities:
        raise ValueError(
            "profit optimizer did not select the complete safe recovery graph"
        )
    briefs = tuple(
        RecoveryActionBrief(
            operation_ref=action.operation_ref,
            capability=action.capability,
            connector_account_ref=action.target_account_ref,
            connector_arguments_digest=argument_briefs[index][2],
            depends_on=action.depends_on,
        )
        for index, action in enumerate(plan.actions)
    )
    return AbandonedRecoveryPlan(
        status="eligible",
        case_ref=case.case_ref,
        case_digest=case.case_digest,
        analysis_as_of=analysis_text,
        profit_plan=plan,
        actions=briefs,
        discount_included=discount_included,
        summary=(
            "Planned a bounded discount followed by one recovery email."
            if discount_included
            else "Planned one consent-safe recovery email without a margin-eroding discount."
        ),
    )


def run_abandoned_revenue_recovery(
    recovery_plan_value: AbandonedRecoveryPlan | Mapping[str, Any],
    case_value: AbandonedRecoveryCase | Mapping[str, Any],
    *,
    resolved_secrets: RecoveryResolvedSecrets | Mapping[str, Any],
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ProfitScopeKeyRing,
    execution_scope: ExecutionScope | Mapping[str, Any],
    executor: ConnectorExecutor,
    run_ref: str,
    iteration: int = 1,
    preview_only: bool = True,
    dispatch_at: datetime | None = None,
    dispatch_attestation: RecoveryDispatchAttestation | Mapping[str, Any] | None = None,
    contact_reservation: RecoveryContactReservation | Mapping[str, Any] | None = None,
    contact_reservation_authority: RecoveryContactReservationAuthority | None = None,
    approval_grants: Mapping[
        str,
        ProfitActionApprovalGrant | Mapping[str, Any],
    ]
    | None = None,
    existing_receipts: Iterable[ProfitActionExecutionReceipt | Mapping[str, Any]] = (),
) -> AbandonedRecoveryRun:
    """Run the recovery DAG until preview, approval wait, failure, or completion."""

    workflow_scope = _workflow_scope(scope)
    case = verify_abandoned_recovery_case(
        case_value,
        scope=workflow_scope,
        scope_keyring=scope_keyring,
    )
    recovery_plan = AbandonedRecoveryPlan.model_validate(
        recovery_plan_value.model_dump(mode="python", by_alias=True)
        if isinstance(recovery_plan_value, AbandonedRecoveryPlan)
        else recovery_plan_value
    )
    if recovery_plan.status != "eligible" or recovery_plan.profit_plan is None:
        raise ValueError("only an eligible recovery plan may be materialized")
    if recovery_plan.case_digest != case.case_digest:
        raise ValueError("recovery plan does not match the authenticated case")
    plan = verify_profit_workflow_plan(
        recovery_plan.profit_plan,
        scope=workflow_scope,
        scope_keyring=scope_keyring,
    )
    if preview_only:
        if (dispatch_at is None) != (dispatch_attestation is None):
            raise ValueError(
                "preview dispatch time and attestation must be supplied together"
            )
    elif dispatch_at is None or dispatch_attestation is None:
        raise ValueError(
            "apply requires a current host-sealed recovery dispatch attestation"
        )
    if dispatch_at is not None and dispatch_attestation is not None:
        if dispatch_at.tzinfo is None or dispatch_at.utcoffset() is None:
            raise ValueError("dispatch_at must include a UTC offset")
        verify_recovery_dispatch_attestation(
            dispatch_attestation,
            recovery_plan=recovery_plan,
            case=case,
            dispatch_at=dispatch_at,
            scope=workflow_scope,
            scope_keyring=scope_keyring,
        )
    secrets = _secrets(resolved_secrets, case)
    grants = dict(approval_grants or {})
    known_operations = {item.operation_ref for item in plan.actions}
    if any(key not in known_operations for key in grants):
        raise ValueError("approval grant names an unknown recovery operation")
    receipts: dict[str, ProfitActionExecutionReceipt] = {}
    for raw_receipt in existing_receipts:
        if len(receipts) >= len(plan.actions):
            raise ValueError("too many existing recovery receipts")
        receipt = verify_profit_action_execution_receipt(
            raw_receipt,
            plan=plan,
            scope=workflow_scope,
            scope_keyring=scope_keyring,
        )
        if receipt.run_ref != run_ref or receipt.iteration != iteration:
            raise ValueError("existing recovery receipt run or iteration mismatch")
        if receipt.operation_ref in receipts:
            raise ValueError("existing recovery receipts must be unique")
        receipts[receipt.operation_ref] = receipt

    action_results: list[ProfitActionMaterializationResult] = []
    terminal_status: RecoveryRunStatus = "preview" if preview_only else "completed"
    reservation_consumed = False
    reservation_request = build_recovery_contact_reservation_request(
        recovery_plan,
        case,
        run_ref=run_ref,
        iteration=iteration,
    )
    trusted_reservation: RecoveryContactReservation | None = None
    email_dispatch_authorized = any(
        action.capability == "gmail.send_email"
        and action.operation_ref not in receipts
        and action.operation_ref in grants
        for action in plan.actions
    )
    if not preview_only and email_dispatch_authorized:
        if (
            contact_reservation is None
            or contact_reservation_authority is None
            or not isinstance(
                contact_reservation_authority,
                RecoveryContactReservationAuthority,
            )
        ):
            raise ValueError(
                "live recovery dispatch requires a transactional contact reservation"
            )
        if dispatch_at is None:
            raise ValueError("contact reservation consumption requires dispatch_at")
        trusted_reservation = verify_recovery_contact_reservation(
            contact_reservation,
            request=reservation_request,
            at=dispatch_at,
            scope=workflow_scope,
            scope_keyring=scope_keyring,
        )
    for action in plan.actions:
        if action.operation_ref in receipts and not preview_only:
            continue
        arguments = _connector_arguments(
            case,
            secrets,
            capability=action.capability,
            discount_included=recovery_plan.discount_included,
        )
        dependency_receipts = tuple(
            receipts[dependency]
            for dependency in action.depends_on
            if dependency in receipts
        )
        grant = grants.get(action.operation_ref)
        before_connector_dispatch = None
        if (
            not preview_only
            and action.capability == "gmail.send_email"
            and grant is not None
            and not reservation_consumed
        ):
            if (
                trusted_reservation is None
                or contact_reservation_authority is None
                or dispatch_at is None
            ):
                raise ValueError("contact reservation preflight was not completed")

            def consume_contact_reservation(_: object) -> None:
                nonlocal reservation_consumed
                consumption = contact_reservation_authority.consume(
                    trusted_reservation,
                    request=reservation_request,
                    consumed_at=dispatch_at,
                )
                verify_recovery_contact_reservation_consumption(
                    consumption,
                    reservation=trusted_reservation,
                    request=reservation_request,
                    scope=workflow_scope,
                    scope_keyring=scope_keyring,
                )
                reservation_consumed = True

            before_connector_dispatch = consume_contact_reservation
        result = _materialize_recovery_profit_action(
            plan,
            scope=workflow_scope,
            scope_keyring=scope_keyring,
            execution_scope=execution_scope,
            executor=executor,
            operation_ref=action.operation_ref,
            connector_arguments=arguments,
            run_ref=run_ref,
            iteration=iteration,
            preview_only=preview_only,
            approval_grant=grant,
            dependency_receipts=dependency_receipts,
            before_connector_dispatch=before_connector_dispatch,
        )
        action_results.append(result)
        if preview_only:
            continue
        if result.status == "completed" and result.receipt is not None:
            receipts[action.operation_ref] = result.receipt
            continue
        terminal_status = result.status
        break
    if preview_only:
        return AbandonedRecoveryRun(
            status="preview",
            case_ref=case.case_ref,
            case_digest=case.case_digest,
            plan_digest=plan.plan_digest,
            run_ref=run_ref,
            iteration=iteration,
            action_results=tuple(action_results),
            receipts=(),
            summary="Validated the complete recovery DAG; preview made zero connector calls.",
        )
    if terminal_status != "completed" or set(receipts) != known_operations:
        return AbandonedRecoveryRun(
            status=terminal_status,
            case_ref=case.case_ref,
            case_digest=case.case_digest,
            plan_digest=plan.plan_digest,
            run_ref=run_ref,
            iteration=iteration,
            action_results=tuple(action_results),
            receipts=tuple(receipts[key] for key in sorted(receipts)),
            summary="Recovery paused safely before the full action graph completed.",
        )
    ordered_receipts = tuple(receipts[item.operation_ref] for item in plan.actions)
    latest_completion = max(
        _parse_time(item.completed_at, label="completed_at")
        for item in ordered_receipts
    )
    due = latest_completion + timedelta(
        hours=plan.evaluation_loop.measurement_window_hours
    )
    return AbandonedRecoveryRun(
        status="completed",
        case_ref=case.case_ref,
        case_digest=case.case_digest,
        plan_digest=plan.plan_digest,
        run_ref=run_ref,
        iteration=iteration,
        action_results=tuple(action_results),
        receipts=ordered_receipts,
        observation_due_at=due.isoformat().replace("+00:00", "Z"),
        summary=(
            "Completed the approved recovery graph. Causal success remains unclaimed "
            "until the holdout-aware observation window is evaluated."
        ),
    )


def schedule_abandoned_recovery_observation(
    recovery_plan_value: AbandonedRecoveryPlan | Mapping[str, Any],
    recovery_run_value: AbandonedRecoveryRun | Mapping[str, Any],
    *,
    runtime: "ObservationRuntime",
    scope: DynamicWorkflowScope | Mapping[str, Any],
    project_id: UUID,
    experiment_ref: str,
    expected_reader_version: int = 1,
    previous_evaluation: "ProfitWorkflowEvaluation | None" = None,
) -> "WorkflowCheckpoint":
    """Schedule the privacy-minimised randomized-holdout recovery evaluation."""

    recovery_plan = AbandonedRecoveryPlan.model_validate(
        recovery_plan_value.model_dump(mode="python", by_alias=True)
        if isinstance(recovery_plan_value, AbandonedRecoveryPlan)
        else recovery_plan_value
    )
    recovery_run = AbandonedRecoveryRun.model_validate(
        recovery_run_value.model_dump(mode="python", by_alias=True)
        if isinstance(recovery_run_value, AbandonedRecoveryRun)
        else recovery_run_value
    )
    if recovery_plan.status != "eligible" or recovery_plan.profit_plan is None:
        raise ValueError("only an eligible recovery plan may schedule observation")
    if recovery_run.status != "completed":
        raise ValueError("recovery actions must complete before observation scheduling")
    if (
        recovery_run.case_ref != recovery_plan.case_ref
        or recovery_run.case_digest != recovery_plan.case_digest
        or recovery_run.plan_digest != recovery_plan.profit_plan.plan_digest
    ):
        raise ValueError("recovery run does not match the authenticated recovery plan")
    if (
        not isinstance(expected_reader_version, int)
        or isinstance(expected_reader_version, bool)
        or expected_reader_version < 1
    ):
        raise ValueError("expected_reader_version must be a positive integer")
    clean_experiment_ref = _visible(
        experiment_ref,
        label="experiment_ref",
        maximum=64,
    )
    if not _REF_RE.fullmatch(clean_experiment_ref):
        raise ValueError("experiment_ref must be a portable recovery reference")
    return runtime.schedule_profit(
        recovery_plan.profit_plan,
        action_receipts=recovery_run.receipts,
        scope=scope,
        project_id=project_id,
        provider="host",
        source_capability="host.checkout_recovery_snapshot",
        query_arguments={
            "case_ref": recovery_plan.case_ref,
            "experiment_ref": clean_experiment_ref,
        },
        expected_tool_version=expected_reader_version,
        run_ref=recovery_run.run_ref,
        iteration=recovery_run.iteration,
        previous_evaluation=previous_evaluation,
    )


__all__ = [
    "ABANDONED_RECOVERY_CASE_SCHEMA",
    "ABANDONED_RECOVERY_DISPATCH_ATTESTATION_SCHEMA",
    "ABANDONED_RECOVERY_PLAN_SCHEMA",
    "ABANDONED_RECOVERY_RUN_SCHEMA",
    "RECOVERY_CONTACT_RESERVATION_CONSUMPTION_SCHEMA",
    "RECOVERY_CONTACT_RESERVATION_REQUEST_SCHEMA",
    "RECOVERY_CONTACT_RESERVATION_SCHEMA",
    "AbandonedRecoveryCase",
    "AbandonedRecoveryCaseInput",
    "AbandonedRecoveryPlan",
    "AbandonedRecoveryRun",
    "ConsentStatus",
    "InMemoryRecoveryContactReservationAuthority",
    "RecoveryActionBrief",
    "RecoveryCohort",
    "RecoveryContactReservation",
    "RecoveryContactReservationAuthority",
    "RecoveryContactReservationConflict",
    "RecoveryContactReservationConsumption",
    "RecoveryContactReservationRequest",
    "RecoveryDispatchAttestation",
    "RecoveryPlanningStatus",
    "RecoveryResolvedSecrets",
    "RecoveryRunStatus",
    "RecoverySuppressionCode",
    "build_recovery_contact_reservation_request",
    "mint_abandoned_recovery_case",
    "mint_recovery_dispatch_attestation",
    "mint_recovery_contact_reservation",
    "mint_recovery_contact_reservation_consumption",
    "plan_abandoned_revenue_recovery",
    "recovery_discount_code_digest",
    "recovery_recipient_digest",
    "recovery_url_digest",
    "run_abandoned_revenue_recovery",
    "schedule_abandoned_recovery_observation",
    "verify_abandoned_recovery_case",
    "verify_recovery_contact_reservation",
    "verify_recovery_contact_reservation_consumption",
    "verify_recovery_dispatch_attestation",
]
