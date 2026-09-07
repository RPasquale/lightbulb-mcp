"""Durable, exact-scope ingestion for abandoned-checkout recovery.

This module closes the read-to-plan seam for abandoned revenue recovery without
turning a connector read into permission to contact a customer.  A bounded host
worker reads the exact project Shopify account, validates the governed receipt
and the real Rust output shape, obtains a short-lived HMAC attestation from host
business authorities, and persists only a privacy-minimised recovery case and
plan.  Approval, dispatch re-attestation, connector writes, and outcome
observation remain in :mod:`lightbulb.abandoned_recovery`.

Raw email addresses, recovery URLs, and discount codes exist only in the
connector response, enrichment authority, and ``RecoverySecretResolver`` call.
They are never fields of an ingestion checkpoint.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Literal, Mapping, Protocol, runtime_checkable
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from lightbulb.abandoned_recovery import (
    AbandonedRecoveryCase,
    AbandonedRecoveryCaseInput,
    AbandonedRecoveryPlan,
    ConsentStatus,
    RecoveryCohort,
    RecoveryResolvedSecrets,
    mint_abandoned_recovery_case,
    plan_abandoned_revenue_recovery,
    recovery_discount_code_digest,
    recovery_recipient_digest,
    recovery_url_digest,
    verify_abandoned_recovery_case,
)
from lightbulb.connector_execution import (
    ConnectorEffect,
    ConnectorExecutionProvenance,
    ConnectorExecutionRequest,
    ConnectorExecutionStatus,
    ConnectorExecutor,
    ExecutionScope,
)
from lightbulb.durable_runtime import (
    CheckpointConflictError,
    CheckpointPersistenceError,
    CheckpointScopeError,
)
from lightbulb.dynamic_workflows import DynamicWorkflowScope
from lightbulb.profit_workflow_blueprints import ProfitScopeKeyRing
from lightbulb.profit_workflow_runtime import (
    ProfitContributionLedger,
    verify_profit_workflow_plan,
)


RECOVERY_ENRICHMENT_ATTESTATION_SCHEMA = "lightbulb.recovery_ingestion_enrichment.v1"
RECOVERY_ENRICHMENT_REQUEST_SCHEMA = "lightbulb.recovery_enrichment_request.v1"
RECOVERY_INGESTION_CHECKPOINT_SCHEMA = "lightbulb.recovery_ingestion_checkpoint.v1"
RECOVERY_INGESTION_RUN_SCHEMA = "lightbulb.recovery_ingestion_run.v1"
SHOPIFY_ABANDONED_CHECKOUT_OUTPUT_SCHEMA = (
    "lightbulb.shopify_abandoned_checkout_output.v1"
)

_ENRICHMENT_HMAC_DOMAIN = RECOVERY_ENRICHMENT_ATTESTATION_SCHEMA
_READ_TOOL = "shopify.list_abandoned_checkouts"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_VISIBLE_REF_RE = re.compile(r"^[^\x00-\x20\x7f]{1,200}$")
_CASE_REF_PREFIX = "checkout_"
_MAX_CHECKPOINT_BYTES = 262_144
_MAX_PROVIDER_PAGE_SIZE = 20
_MAX_PAGES_PER_RUN = 13
_MAX_ROWS_PER_RUN = 250
_TRUNCATION_SENTINEL = "[truncated]"


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        revalidate_instances="always",
        serialize_by_alias=True,
        strict=True,
    )


def _canonical(value: Any) -> bytes:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json", by_alias=True, exclude_none=True)
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
        default=str,
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _utc(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must include a UTC offset")
    return value.astimezone(timezone.utc)


def _parse_time(value: str, *, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise ValueError(f"{label} must be valid ISO-8601") from exc
    return _utc(parsed, label=label)


def _time(value: datetime | str, *, label: str) -> str:
    parsed = (
        _parse_time(value, label=label)
        if isinstance(value, str)
        else _utc(value, label=label)
    )
    return parsed.isoformat().replace("+00:00", "Z")


def _visible(value: str, *, label: str) -> str:
    clean = value.strip()
    if clean != value or _VISIBLE_REF_RE.fullmatch(clean) is None:
        raise ValueError(f"{label} must contain 1-200 visible characters")
    return clean


def _opaque_cursor(value: str, *, label: str = "cursor") -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    clean = value.strip()
    if (
        clean != value
        or not 1 <= len(clean) <= 2_048
        or any(ord(character) < 0x21 or ord(character) == 0x7F for character in clean)
    ):
        raise ValueError(f"{label} must contain 1-2048 visible characters")
    return clean


def _contains_truncation_sentinel(value: Any) -> bool:
    if value == _TRUNCATION_SENTINEL:
        return True
    if isinstance(value, Mapping):
        return any(
            _contains_truncation_sentinel(key) or _contains_truncation_sentinel(item)
            for key, item in value.items()
        )
    if isinstance(value, (list, tuple)):
        return any(_contains_truncation_sentinel(item) for item in value)
    return False


def _decimal(value: Any, *, label: str, places: int = 6) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (str, int, float, Decimal)):
        raise ValueError(f"{label} must be a decimal value")
    lexical = str(value)
    if len(lexical) > 48 or lexical != lexical.strip() or "e" in lexical.lower():
        raise ValueError(f"{label} must use bounded decimal notation")
    try:
        parsed = Decimal(lexical)
        quantum = Decimal(1).scaleb(-places)
        normalized = parsed.quantize(quantum)
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"{label} must be a finite decimal") from exc
    if not parsed.is_finite() or parsed < 0 or parsed != normalized:
        raise ValueError(f"{label} is outside the supported precision")
    return parsed


def recovery_ingestion_scope_fingerprint(
    scope: DynamicWorkflowScope | Mapping[str, Any],
) -> str:
    """Opaque full-scope partition for local ingestion checkpoints."""

    parsed = (
        scope
        if isinstance(scope, DynamicWorkflowScope)
        else DynamicWorkflowScope.model_validate(scope)
    )
    return _digest(
        {
            "schema": "lightbulb.recovery_ingestion_scope.v1",
            "tenant_id": parsed.tenant_id,
            "company_id": parsed.company_id,
            "user_id": parsed.user_id,
            "project_ref": parsed.project_ref,
        }
    )


class ShopifyRecoveryMoney(_StrictModel):
    amount: Decimal
    currency_code: str = Field(alias="currencyCode", pattern=r"^[A-Z]{3}$")

    @field_validator("amount", mode="before")
    @classmethod
    def _amount(cls, value: Any) -> Decimal:
        return _decimal(value, label="Shopify money", places=6)


class ShopifyRecoveryMoneySet(_StrictModel):
    shop_money: ShopifyRecoveryMoney = Field(alias="shopMoney")


class ShopifyRecoveryCustomer(_StrictModel):
    id: str
    email: str | None = Field(default=None, repr=False, max_length=998)
    display_name: str | None = Field(default=None, alias="displayName", max_length=500)

    @field_validator("id")
    @classmethod
    def _id(cls, value: str) -> str:
        return _visible(value, label="Shopify customer id")

    @field_validator("email")
    @classmethod
    def _email(cls, value: str | None) -> str | None:
        if value is not None:
            recovery_recipient_digest(value)
        return value


class ShopifyRecoveryVariant(_StrictModel):
    price: Decimal

    @field_validator("price", mode="before")
    @classmethod
    def _price(cls, value: Any) -> Decimal:
        return _decimal(value, label="Shopify variant price", places=6)


class ShopifyRecoveryLineItem(_StrictModel):
    title: str = Field(min_length=1, max_length=500)
    quantity: int = Field(ge=1, le=1_000_000)
    variant: ShopifyRecoveryVariant | None = None


class ShopifyRecoveryLineItemEdge(_StrictModel):
    node: ShopifyRecoveryLineItem


class ShopifyRecoveryLineItems(_StrictModel):
    edges: tuple[ShopifyRecoveryLineItemEdge, ...] = Field(max_length=10)

    @field_validator("edges", mode="before")
    @classmethod
    def _tuple(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value


class ShopifyAbandonedCheckout(_StrictModel):
    """Exact normalized node emitted by the Rust Shopify adapter."""

    id: str
    abandoned_checkout_url: str | None = Field(
        default=None,
        alias="abandonedCheckoutUrl",
        repr=False,
        max_length=2_048,
    )
    created_at: str = Field(alias="createdAt")
    updated_at: str = Field(alias="updatedAt")
    subtotal_price_set: ShopifyRecoveryMoneySet | None = Field(
        default=None, alias="subtotalPriceSet"
    )
    total_line_items_price_set: ShopifyRecoveryMoneySet | None = Field(
        default=None, alias="totalLineItemsPriceSet"
    )
    customer: ShopifyRecoveryCustomer | None = Field(default=None, repr=False)
    line_items: ShopifyRecoveryLineItems = Field(alias="lineItems")
    line_items_subtotal_price: ShopifyRecoveryMoney | None = Field(
        default=None,
        alias="lineItemsSubtotalPrice",
    )

    @field_validator("id")
    @classmethod
    def _id(cls, value: str) -> str:
        return _visible(value, label="Shopify checkout id")

    @field_validator("created_at", "updated_at")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _time(value, label=info.field_name)

    @field_validator("abandoned_checkout_url")
    @classmethod
    def _url(cls, value: str | None) -> str | None:
        if value is not None:
            recovery_url_digest(value)
        return value

    @model_validator(mode="after")
    def _real_rust_contract(self) -> "ShopifyAbandonedCheckout":
        if _parse_time(self.updated_at, label="updated_at") < _parse_time(
            self.created_at, label="created_at"
        ):
            raise ValueError("Shopify checkout version precedes creation")
        subtotal = (
            self.subtotal_price_set.shop_money
            if self.subtotal_price_set is not None
            else None
        )
        if subtotal != self.line_items_subtotal_price:
            raise ValueError(
                "Rust lineItemsSubtotalPrice does not match subtotalPriceSet.shopMoney"
            )
        return self

    @property
    def checkout_digest(self) -> str:
        return _digest(self.model_dump(mode="json", by_alias=True, exclude_none=True))


class ShopifyAbandonedCheckoutOutput(_StrictModel):
    schema_id: Literal["lightbulb.shopify_abandoned_checkout_output.v1"] = Field(
        default=SHOPIFY_ABANDONED_CHECKOUT_OUTPUT_SCHEMA,
        alias="schema",
    )
    abandoned_checkouts: tuple[ShopifyAbandonedCheckout, ...] = Field(
        max_length=_MAX_PROVIDER_PAGE_SIZE
    )
    total: int = Field(ge=0, le=_MAX_PROVIDER_PAGE_SIZE)
    next_cursor: str | None = Field(default=None, max_length=2_048)

    @field_validator("abandoned_checkouts", mode="before")
    @classmethod
    def _rows(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("next_cursor")
    @classmethod
    def _cursor(cls, value: str | None) -> str | None:
        return None if value is None else _opaque_cursor(value, label="next_cursor")

    @model_validator(mode="before")
    @classmethod
    def _wire_schema(cls, value: Any) -> Any:
        if not isinstance(value, Mapping):
            return value
        payload = dict(value)
        payload.setdefault("schema", SHOPIFY_ABANDONED_CHECKOUT_OUTPUT_SCHEMA)
        return payload

    @model_validator(mode="after")
    def _count(self) -> "ShopifyAbandonedCheckoutOutput":
        if self.total != len(self.abandoned_checkouts):
            raise ValueError("Shopify abandoned checkout total does not match rows")
        ids = [(row.id, row.updated_at) for row in self.abandoned_checkouts]
        if len(ids) != len(set(ids)):
            raise ValueError("Shopify abandoned checkout output contains duplicates")
        return self


class RecoveryEnrichmentFacts(_StrictModel):
    """Host-owned business facts absent from the Shopify checkout response."""

    launch_ref: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    gmail_account_ref: str = Field(min_length=1, max_length=200)
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
        default=None, min_length=1, max_length=20_000
    )
    measurement_window_hours: int = Field(default=72, ge=1, le=720)
    minimum_sample_size: int = Field(default=1, ge=1, le=1_000_000_000)
    max_observation_age_hours: int = Field(default=168, ge=1, le=8_760)
    max_iterations: int = Field(default=2, ge=1, le=4)

    @field_validator("gmail_account_ref")
    @classmethod
    def _gmail_ref(cls, value: str) -> str:
        return _visible(value, label="Gmail account ref")

    @field_validator(
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
    def _money(cls, value: Any, info: Any) -> Decimal:
        return _decimal(value, label=info.field_name, places=2)

    @field_validator(
        "expected_confidence",
        "minimum_margin_rate",
        mode="before",
    )
    @classmethod
    def _rate(cls, value: Any, info: Any) -> Decimal:
        return _decimal(value, label=info.field_name, places=6)

    @field_validator("discount_percentage", mode="before")
    @classmethod
    def _discount(cls, value: Any) -> Decimal | None:
        return (
            None
            if value is None
            else _decimal(value, label="discount_percentage", places=2)
        )


class RecoveryEnrichmentRequest(_StrictModel):
    """Transient exact read handed to a trusted host enrichment authority."""

    schema_id: Literal["lightbulb.recovery_enrichment_request.v1"] = Field(
        default=RECOVERY_ENRICHMENT_REQUEST_SCHEMA,
        alias="schema",
    )
    ingestion_key: str = Field(pattern=r"^[0-9a-f]{64}$")
    scope: DynamicWorkflowScope
    exact_scope_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    project_id: UUID
    shopify_account_ref: str = Field(min_length=1, max_length=200)
    source_provenance: ConnectorExecutionProvenance
    checkout: ShopifyAbandonedCheckout = Field(repr=False)
    requested_at: str
    request_digest: str = Field(default="0" * 64, pattern=r"^[0-9a-f]{64}$")

    @field_validator("requested_at")
    @classmethod
    def _requested(cls, value: str) -> str:
        return _time(value, label="requested_at")

    @model_validator(mode="after")
    def _sealed(self) -> "RecoveryEnrichmentRequest":
        provenance = self.source_provenance
        if (
            provenance.tool != _READ_TOOL
            or provenance.server_effect != ConnectorEffect.READ
            or provenance.project_id != self.project_id
            or provenance.connector_account_ref != self.shopify_account_ref
        ):
            raise ValueError("enrichment request provenance route is inconsistent")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"request_digest"},
            exclude_none=True,
        )
        expected = _digest(material)
        if self.request_digest not in {"0" * 64, expected}:
            raise ValueError("enrichment request digest mismatch")
        object.__setattr__(self, "request_digest", expected)
        return self


class RecoveryIngestionEnrichment(_StrictModel):
    """Short-lived host HMAC over all facts used to construct one case."""

    schema_id: Literal["lightbulb.recovery_ingestion_enrichment.v1"] = Field(
        default=RECOVERY_ENRICHMENT_ATTESTATION_SCHEMA,
        alias="schema",
    )
    request_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    ingestion_key: str = Field(pattern=r"^[0-9a-f]{64}$")
    checkout_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_request_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_receipt_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    case_input: AbandonedRecoveryCaseInput
    attested_at: str
    valid_until: str
    receipt_key_id: str = Field(min_length=8, max_length=80)
    exact_scope_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    attestation_hmac: str = Field(pattern=r"^[0-9a-f]{64}$")
    attestation_digest: str = Field(default="0" * 64, pattern=r"^[0-9a-f]{64}$")

    @field_validator("attested_at", "valid_until")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _time(value, label=info.field_name)

    @model_validator(mode="after")
    def _sealed(self) -> "RecoveryIngestionEnrichment":
        attested = _parse_time(self.attested_at, label="attested_at")
        valid_until = _parse_time(self.valid_until, label="valid_until")
        if valid_until <= attested or valid_until - attested > timedelta(minutes=15):
            raise ValueError("enrichment lifetime must be 1-15 minutes")
        if self.case_input.observed_at != self.attested_at:
            raise ValueError("case observation must equal enrichment attestation time")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"attestation_digest"},
            exclude_none=True,
        )
        expected = _digest(material)
        if self.attestation_digest not in {"0" * 64, expected}:
            raise ValueError("enrichment attestation digest mismatch")
        object.__setattr__(self, "attestation_digest", expected)
        return self

    def hmac_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"attestation_hmac", "attestation_digest"},
            exclude_none=True,
        )


@runtime_checkable
class RecoveryEnrichmentAuthority(Protocol):
    """Trusted host authority for consent, stock, frequency, and economics."""

    def attest(
        self, request: RecoveryEnrichmentRequest
    ) -> RecoveryIngestionEnrichment: ...


@runtime_checkable
class RecoverySecretResolver(Protocol):
    """Resolve raw contact/URL/code transiently at planning or dispatch time."""

    def resolve(
        self,
        enrichment: RecoveryIngestionEnrichment,
        *,
        scope: DynamicWorkflowScope,
    ) -> RecoveryResolvedSecrets: ...


def recovery_ingestion_key(
    *,
    scope_fingerprint: str,
    shopify_account_ref: str,
    checkout_ref: str,
    checkout_version: str,
) -> str:
    if _SHA256_RE.fullmatch(scope_fingerprint) is None:
        raise ValueError("scope_fingerprint must be a lowercase SHA-256 value")
    return _digest(
        {
            "schema": "lightbulb.recovery_ingestion_identity.v1",
            # Stable across signing-key rotation while still binding the full
            # tenant/company/user/project identity.
            "scope_fingerprint": scope_fingerprint,
            "shopify_account_ref": _visible(
                shopify_account_ref, label="Shopify account ref"
            ),
            "checkout_ref": _visible(checkout_ref, label="Shopify checkout id"),
            "checkout_version": _time(checkout_version, label="checkout_version"),
        }
    )


def mint_recovery_ingestion_enrichment(
    request_value: RecoveryEnrichmentRequest | Mapping[str, Any],
    facts_value: RecoveryEnrichmentFacts | Mapping[str, Any],
    *,
    resolved_secrets: RecoveryResolvedSecrets | Mapping[str, Any],
    attested_at: datetime,
    valid_until: datetime,
    scope_keyring: ProfitScopeKeyRing,
    scope_key_id: str | None = None,
) -> RecoveryIngestionEnrichment:
    """Host helper that derives source-bound hashes and HMAC-seals enrichment."""

    request = RecoveryEnrichmentRequest.model_validate(
        request_value.model_dump(mode="python", by_alias=True)
        if isinstance(request_value, RecoveryEnrichmentRequest)
        else request_value
    )
    facts = RecoveryEnrichmentFacts.model_validate(
        facts_value.model_dump(mode="python")
        if isinstance(facts_value, RecoveryEnrichmentFacts)
        else facts_value
    )
    secrets = RecoveryResolvedSecrets.model_validate(
        resolved_secrets.model_dump(mode="python")
        if isinstance(resolved_secrets, RecoveryResolvedSecrets)
        else resolved_secrets
    )
    checkout = request.checkout
    if (
        checkout.customer is None
        or checkout.customer.email is None
        or checkout.abandoned_checkout_url is None
        or checkout.line_items_subtotal_price is None
    ):
        raise ValueError("checkout has no contact, recovery URL, or subtotal")
    if not hmac.compare_digest(
        recovery_recipient_digest(secrets.recipient),
        recovery_recipient_digest(checkout.customer.email),
    ):
        raise ValueError("resolved recipient does not match Shopify checkout")
    if not hmac.compare_digest(
        recovery_url_digest(secrets.recovery_url),
        recovery_url_digest(checkout.abandoned_checkout_url),
    ):
        raise ValueError("resolved recovery URL does not match Shopify checkout")
    if facts.baseline.currency != checkout.line_items_subtotal_price.currency_code:
        raise ValueError("host baseline currency does not match Shopify checkout")
    if facts.baseline.gross_sales != checkout.line_items_subtotal_price.amount.quantize(
        Decimal("0.01")
    ):
        raise ValueError("host baseline gross sales does not match Shopify subtotal")
    attested_text = _time(attested_at, label="attested_at")
    valid_until_text = _time(valid_until, label="valid_until")
    completed = _parse_time(
        request.source_provenance.completed_at, label="completed_at"
    )
    checkout_updated = _parse_time(checkout.updated_at, label="updated_at")
    attested = _parse_time(attested_text, label="attested_at")
    if attested < completed or attested < checkout_updated:
        raise ValueError("enrichment cannot predate its connector evidence")
    key_id = scope_key_id or str(scope_keyring.active_key_id).strip()
    expected_scope = scope_keyring.exact_scope_digest(
        key_id=key_id,
        scope=request.scope,
    )
    if not hmac.compare_digest(expected_scope, request.exact_scope_digest):
        raise ValueError("enrichment request exact scope is invalid")
    evidence_digest = _digest(
        {
            "schema": "lightbulb.recovery_ingestion_evidence.v1",
            "source_receipt_digest": request.source_provenance.receipt_digest,
            "checkout_digest": checkout.checkout_digest,
            "facts": facts.model_dump(mode="json", exclude_none=True),
        }
    )
    discount_digest = (
        recovery_discount_code_digest(secrets.discount_code)
        if secrets.discount_code is not None
        else None
    )
    case_input = AbandonedRecoveryCaseInput(
        case_ref=f"{_CASE_REF_PREFIX}{request.ingestion_key[:40]}",
        launch_ref=facts.launch_ref,
        checkout_ref=checkout.id,
        customer_ref=checkout.customer.id,
        shopify_account_ref=request.shopify_account_ref,
        gmail_account_ref=facts.gmail_account_ref,
        recipient_sha256=recovery_recipient_digest(secrets.recipient),
        recovery_url_sha256=recovery_url_digest(secrets.recovery_url),
        discount_code_sha256=discount_digest,
        abandoned_at=checkout.created_at,
        observed_at=attested_text,
        expires_at=facts.expires_at,
        consent_status=facts.consent_status,
        cohort=facts.cohort,
        inventory_available=facts.inventory_available,
        prior_recovery_contacts=facts.prior_recovery_contacts,
        frequency_cap=facts.frequency_cap,
        baseline=facts.baseline,
        historical_recovery_ledger=facts.historical_recovery_ledger,
        historical_sample_size=facts.historical_sample_size,
        historical_window_start=facts.historical_window_start,
        historical_window_end=facts.historical_window_end,
        evidence_digest=evidence_digest,
        expected_incremental_revenue=facts.expected_incremental_revenue,
        expected_incremental_cost=facts.expected_incremental_cost,
        expected_confidence=facts.expected_confidence,
        target_recovered_profit=facts.target_recovered_profit,
        minimum_margin_rate=facts.minimum_margin_rate,
        discount_percentage=facts.discount_percentage,
        discount_expires_at=facts.discount_expires_at,
        email_subject=facts.email_subject,
        reminder_body_template=facts.reminder_body_template,
        incentive_body_template=facts.incentive_body_template,
        measurement_window_hours=facts.measurement_window_hours,
        minimum_sample_size=facts.minimum_sample_size,
        max_observation_age_hours=facts.max_observation_age_hours,
        max_iterations=facts.max_iterations,
    )
    draft = RecoveryIngestionEnrichment(
        request_digest=request.request_digest,
        ingestion_key=request.ingestion_key,
        checkout_digest=checkout.checkout_digest,
        source_request_digest=request.source_provenance.request_digest,
        source_receipt_digest=request.source_provenance.receipt_digest,
        case_input=case_input,
        attested_at=attested_text,
        valid_until=valid_until_text,
        receipt_key_id=key_id,
        exact_scope_digest=request.exact_scope_digest,
        attestation_hmac="0" * 64,
    )
    signature = scope_keyring.sign(
        key_id,
        _ENRICHMENT_HMAC_DOMAIN,
        draft.hmac_payload(),
    ).hex()
    return RecoveryIngestionEnrichment.model_validate(
        {
            **draft.model_dump(mode="python", by_alias=True),
            "attestation_hmac": signature,
            "attestation_digest": "0" * 64,
        }
    )


def verify_recovery_ingestion_enrichment(
    value: RecoveryIngestionEnrichment | Mapping[str, Any],
    *,
    request: RecoveryEnrichmentRequest,
    now: datetime,
    scope_keyring: ProfitScopeKeyRing,
) -> RecoveryIngestionEnrichment:
    enrichment = RecoveryIngestionEnrichment.model_validate(
        value.model_dump(mode="python", by_alias=True)
        if isinstance(value, RecoveryIngestionEnrichment)
        else value
    )
    expected_scope = scope_keyring.exact_scope_digest(
        key_id=enrichment.receipt_key_id,
        scope=request.scope,
    )
    if not hmac.compare_digest(enrichment.exact_scope_digest, expected_scope):
        raise ValueError("enrichment scope does not match authenticated scope")
    if (
        enrichment.request_digest != request.request_digest
        or enrichment.ingestion_key != request.ingestion_key
        or enrichment.checkout_digest != request.checkout.checkout_digest
        or enrichment.exact_scope_digest != request.exact_scope_digest
        or enrichment.source_request_digest != request.source_provenance.request_digest
        or enrichment.source_receipt_digest != request.source_provenance.receipt_digest
        or enrichment.case_input.checkout_ref != request.checkout.id
        or enrichment.case_input.shopify_account_ref != request.shopify_account_ref
    ):
        raise ValueError("enrichment does not match exact connector evidence")
    checkout = request.checkout
    customer = checkout.customer
    subtotal = checkout.line_items_subtotal_price
    if (
        customer is None
        or customer.email is None
        or checkout.abandoned_checkout_url is None
        or subtotal is None
        or enrichment.case_input.case_ref
        != f"{_CASE_REF_PREFIX}{request.ingestion_key[:40]}"
        or enrichment.case_input.customer_ref != customer.id
        or enrichment.case_input.abandoned_at != checkout.created_at
        or enrichment.case_input.recipient_sha256
        != recovery_recipient_digest(customer.email)
        or enrichment.case_input.recovery_url_sha256
        != recovery_url_digest(checkout.abandoned_checkout_url)
        or enrichment.case_input.baseline.currency != subtotal.currency_code
        or enrichment.case_input.baseline.gross_sales
        != subtotal.amount.quantize(Decimal("0.01"))
    ):
        raise ValueError("enrichment business facts do not match Shopify checkout")
    if _parse_time(enrichment.attested_at, label="attested_at") < max(
        _parse_time(request.source_provenance.completed_at, label="completed_at"),
        _parse_time(checkout.updated_at, label="updated_at"),
    ):
        raise ValueError("enrichment predates exact connector evidence")
    expected_hmac = scope_keyring.sign(
        enrichment.receipt_key_id,
        _ENRICHMENT_HMAC_DOMAIN,
        enrichment.hmac_payload(),
    ).hex()
    if not hmac.compare_digest(enrichment.attestation_hmac, expected_hmac):
        raise ValueError("enrichment HMAC is invalid")
    timestamp = _utc(now, label="now")
    attested = _parse_time(enrichment.attested_at, label="attested_at")
    valid_until = _parse_time(enrichment.valid_until, label="valid_until")
    if timestamp < attested or timestamp >= valid_until:
        raise ValueError("enrichment is not current")
    return enrichment


def _validate_resolved_secrets(
    enrichment: RecoveryIngestionEnrichment,
    value: RecoveryResolvedSecrets | Mapping[str, Any],
) -> RecoveryResolvedSecrets:
    secrets = RecoveryResolvedSecrets.model_validate(
        value.model_dump(mode="python")
        if isinstance(value, RecoveryResolvedSecrets)
        else value
    )
    case_input = enrichment.case_input
    if not hmac.compare_digest(
        recovery_recipient_digest(secrets.recipient), case_input.recipient_sha256
    ):
        raise ValueError("secret resolver returned a different recipient")
    if not hmac.compare_digest(
        recovery_url_digest(secrets.recovery_url), case_input.recovery_url_sha256
    ):
        raise ValueError("secret resolver returned a different recovery URL")
    if case_input.discount_code_sha256 is None:
        if secrets.discount_code is not None:
            raise ValueError("secret resolver returned an unauthorized discount code")
    elif secrets.discount_code is None or not hmac.compare_digest(
        recovery_discount_code_digest(secrets.discount_code),
        case_input.discount_code_sha256,
    ):
        raise ValueError("secret resolver returned a different discount code")
    return secrets


class RecoveryIngestionCheckpoint(_StrictModel):
    """Immutable privacy-safe handoff from ingestion to approval/dispatch."""

    schema_id: Literal["lightbulb.recovery_ingestion_checkpoint.v1"] = Field(
        default=RECOVERY_INGESTION_CHECKPOINT_SCHEMA,
        alias="schema",
    )
    ingestion_key: str = Field(pattern=r"^[0-9a-f]{64}$")
    scope_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    project_ref: str = Field(min_length=1, max_length=200)
    exact_scope_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    shopify_account_ref: str = Field(min_length=1, max_length=200)
    expected_tool_version: int = Field(ge=1)
    expected_tenant_connector_id: UUID
    expected_route_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    checkout_ref: str = Field(min_length=1, max_length=200)
    checkout_version: str
    checkout_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_provenance: ConnectorExecutionProvenance
    enrichment: RecoveryIngestionEnrichment
    recovery_case: AbandonedRecoveryCase
    recovery_plan: AbandonedRecoveryPlan
    created_at: str
    checkpoint_digest: str = Field(default="0" * 64, pattern=r"^[0-9a-f]{64}$")

    @field_validator("checkout_version", "created_at")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _time(value, label=info.field_name)

    @model_validator(mode="after")
    def _sealed(self) -> "RecoveryIngestionCheckpoint":
        case_input = self.enrichment.case_input
        if (
            self.ingestion_key != self.enrichment.ingestion_key
            or self.exact_scope_digest != self.enrichment.exact_scope_digest
            or self.checkout_digest != self.enrichment.checkout_digest
            or self.checkout_ref != case_input.checkout_ref
            or self.shopify_account_ref != case_input.shopify_account_ref
            or self.source_provenance.tool_version != self.expected_tool_version
            or self.source_provenance.tenant_connector_id
            != self.expected_tenant_connector_id
            or self.source_provenance.route_digest != self.expected_route_digest
            or self.source_provenance.request_digest
            != self.enrichment.source_request_digest
            or self.source_provenance.receipt_digest
            != self.enrichment.source_receipt_digest
            or self.recovery_case.case_ref != case_input.case_ref
            or self.recovery_plan.case_ref != self.recovery_case.case_ref
            or self.recovery_plan.case_digest != self.recovery_case.case_digest
            or self.recovery_plan.status not in {"eligible", "holdout", "suppressed"}
        ):
            raise ValueError("ingestion checkpoint custody chain is inconsistent")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"checkpoint_digest"},
            exclude_none=True,
        )
        expected = _digest(material)
        if self.checkpoint_digest not in {"0" * 64, expected}:
            raise ValueError("ingestion checkpoint digest mismatch")
        object.__setattr__(self, "checkpoint_digest", expected)
        return self


class RecoveryIngestionFailure(_StrictModel):
    checkout_ref: str = Field(min_length=1, max_length=200)
    checkout_version: str
    code: Literal[
        "contact_unavailable",
        "enrichment_failed",
        "secret_resolution_failed",
        "planning_failed",
        "checkpoint_conflict",
    ]

    @field_validator("checkout_version")
    @classmethod
    def _version(cls, value: str) -> str:
        return _time(value, label="checkout_version")


class RecoveryIngestionRunResult(_StrictModel):
    schema_id: Literal["lightbulb.recovery_ingestion_run.v1"] = Field(
        default=RECOVERY_INGESTION_RUN_SCHEMA,
        alias="schema",
    )
    status: Literal["completed", "partial"]
    source_receipt_digests: tuple[str, ...] = Field(
        min_length=1, max_length=_MAX_PAGES_PER_RUN
    )
    next_cursor: str | None = Field(default=None, max_length=2_048)
    discovered: int = Field(ge=0, le=_MAX_ROWS_PER_RUN)
    planned: int = Field(ge=0, le=_MAX_ROWS_PER_RUN)
    replayed: int = Field(ge=0, le=_MAX_ROWS_PER_RUN)
    failures: tuple[RecoveryIngestionFailure, ...] = Field(max_length=_MAX_ROWS_PER_RUN)
    checkpoints: tuple[RecoveryIngestionCheckpoint, ...] = Field(
        max_length=_MAX_ROWS_PER_RUN
    )

    @field_validator("source_receipt_digests", "failures", "checkpoints", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("source_receipt_digests")
    @classmethod
    def _receipt_digests(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(_SHA256_RE.fullmatch(item) is None for item in value):
            raise ValueError("source receipt digests must be lowercase SHA-256 values")
        return value

    @field_validator("next_cursor")
    @classmethod
    def _next_cursor(cls, value: str | None) -> str | None:
        return None if value is None else _opaque_cursor(value, label="next_cursor")

    @model_validator(mode="after")
    def _counts(self) -> "RecoveryIngestionRunResult":
        if self.planned + self.replayed + len(self.failures) != self.discovered:
            raise ValueError("ingestion result counts do not cover discovered rows")
        if self.status != ("partial" if self.failures else "completed"):
            raise ValueError("ingestion result status does not match failures")
        return self


class RecoveryIngestionRepository(Protocol):
    scope_fingerprint: str

    def get(self, ingestion_key: str) -> RecoveryIngestionCheckpoint | None: ...

    def put(self, checkpoint: RecoveryIngestionCheckpoint) -> None: ...


class InMemoryRecoveryIngestionRepository:
    def __init__(self, *, scope_fingerprint: str) -> None:
        if _SHA256_RE.fullmatch(scope_fingerprint) is None:
            raise ValueError("scope_fingerprint must be a lowercase SHA-256 value")
        self.scope_fingerprint = scope_fingerprint
        self._values: dict[str, RecoveryIngestionCheckpoint] = {}
        self._lock = threading.RLock()

    def get(self, ingestion_key: str) -> RecoveryIngestionCheckpoint | None:
        with self._lock:
            value = self._values.get(ingestion_key)
            return (
                None
                if value is None
                else RecoveryIngestionCheckpoint.model_validate(
                    value.model_dump(mode="python", by_alias=True)
                )
            )

    def put(self, checkpoint: RecoveryIngestionCheckpoint) -> None:
        stored = RecoveryIngestionCheckpoint.model_validate(
            checkpoint.model_dump(mode="python", by_alias=True)
        )
        if stored.scope_fingerprint != self.scope_fingerprint:
            raise CheckpointScopeError(
                "recovery checkpoint does not match repository scope partition"
            )
        with self._lock:
            prior = self._values.get(stored.ingestion_key)
            if (
                prior is not None
                and prior.checkpoint_digest != stored.checkpoint_digest
            ):
                raise CheckpointConflictError(
                    "recovery ingestion identity was reused with different content"
                )
            self._values[stored.ingestion_key] = stored


class JsonFileRecoveryIngestionRepository:
    """Immutable atomic checkpoint store for one host/shared filesystem."""

    def __init__(self, directory: str | Path, *, scope_fingerprint: str) -> None:
        if _SHA256_RE.fullmatch(scope_fingerprint) is None:
            raise ValueError("scope_fingerprint must be a lowercase SHA-256 value")
        requested = Path(directory).expanduser()
        if requested.is_symlink():
            raise CheckpointPersistenceError(
                f"refusing symlinked recovery checkpoint directory: {requested}"
            )
        self.scope_fingerprint = scope_fingerprint
        self.directory = requested.resolve()
        self.directory.mkdir(parents=True, exist_ok=True)
        if not self.directory.is_dir():
            raise ValueError("recovery checkpoint path must be a directory")
        try:
            os.chmod(self.directory, 0o700)
        except OSError:
            pass

    def _path(self, ingestion_key: str) -> Path:
        if _SHA256_RE.fullmatch(ingestion_key) is None:
            raise ValueError("ingestion_key must be a lowercase SHA-256 value")
        # Lexical path: resolve() would follow a planted symlink, making every
        # later is_symlink() refusal examine the target instead of the link.
        path = self.directory / f"{ingestion_key}.recovery.json"
        if path.is_symlink():
            raise CheckpointPersistenceError(
                f"unsafe local recovery checkpoint: {path}"
            )
        if path.resolve().parent != self.directory:
            raise ValueError("recovery checkpoint path escaped repository")
        return path

    @staticmethod
    def _bytes(checkpoint: RecoveryIngestionCheckpoint) -> bytes:
        return _canonical(checkpoint.model_dump(mode="json", by_alias=True)) + b"\n"

    def get(self, ingestion_key: str) -> RecoveryIngestionCheckpoint | None:
        path = self._path(ingestion_key)
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise CheckpointPersistenceError(
                f"unsafe local recovery checkpoint: {path}"
            )
        try:
            encoded = path.read_bytes()
        except FileNotFoundError:
            return None
        if len(encoded) > _MAX_CHECKPOINT_BYTES:
            raise CheckpointPersistenceError("recovery checkpoint exceeds size limit")
        try:
            checkpoint = RecoveryIngestionCheckpoint.model_validate_json(encoded)
        except (UnicodeDecodeError, ValidationError, ValueError) as exc:
            raise CheckpointPersistenceError("recovery checkpoint is invalid") from exc
        if checkpoint.scope_fingerprint != self.scope_fingerprint:
            raise CheckpointScopeError(
                "persisted recovery checkpoint scope partition mismatch"
            )
        if checkpoint.ingestion_key != ingestion_key:
            raise CheckpointPersistenceError("recovery checkpoint identity mismatch")
        if self._bytes(checkpoint) != encoded:
            raise CheckpointPersistenceError("recovery checkpoint is not canonical")
        return checkpoint

    def put(self, checkpoint: RecoveryIngestionCheckpoint) -> None:
        stored = RecoveryIngestionCheckpoint.model_validate(
            checkpoint.model_dump(mode="python", by_alias=True)
        )
        if stored.scope_fingerprint != self.scope_fingerprint:
            raise CheckpointScopeError(
                "recovery checkpoint does not match repository scope partition"
            )
        path = self._path(stored.ingestion_key)
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise CheckpointPersistenceError(
                f"unsafe local recovery checkpoint target: {path}"
            )
        encoded = self._bytes(stored)
        temporary: Path | None = None
        try:
            descriptor, raw_path = tempfile.mkstemp(
                prefix=f".{stored.ingestion_key}.", suffix=".tmp", dir=self.directory
            )
            temporary = Path(raw_path)
            try:
                os.chmod(temporary, 0o600)
            except OSError:
                pass
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(temporary, path)
            except FileExistsError:
                if path.is_symlink() or not path.is_file():
                    raise CheckpointPersistenceError(
                        f"unsafe local recovery checkpoint target: {path}"
                    )
                if path.read_bytes() != encoded:
                    raise CheckpointConflictError(
                        "recovery ingestion identity was reused with different content"
                    )
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            if hasattr(os, "O_DIRECTORY"):
                directory_fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)


class RecoveryIngestionError(RuntimeError):
    """A bounded ingestion run could not establish trusted read custody."""


class RecoveryIngestionWorker:
    """Host-started bounded read→attest→case→plan ingestion worker."""

    def __init__(
        self,
        *,
        executor: ConnectorExecutor,
        enrichment_authority: RecoveryEnrichmentAuthority,
        secret_resolver: RecoverySecretResolver,
        repository: RecoveryIngestionRepository,
        scope: DynamicWorkflowScope | Mapping[str, Any],
        execution_scope: ExecutionScope | Mapping[str, Any],
        scope_keyring: ProfitScopeKeyRing,
        shopify_account_ref: str,
        expected_tool_version: int,
        expected_tenant_connector_id: UUID,
        expected_route_digest: str,
    ) -> None:
        self.executor = executor
        self.enrichment_authority = enrichment_authority
        self.secret_resolver = secret_resolver
        self.repository = repository
        self.scope = (
            scope
            if isinstance(scope, DynamicWorkflowScope)
            else DynamicWorkflowScope.model_validate(scope)
        )
        self.execution_scope = (
            execution_scope
            if isinstance(execution_scope, ExecutionScope)
            else ExecutionScope.model_validate(execution_scope)
        )
        self.scope_keyring = scope_keyring
        self.shopify_account_ref = _visible(
            shopify_account_ref, label="Shopify account ref"
        )
        if isinstance(expected_tool_version, bool) or not isinstance(
            expected_tool_version, int
        ):
            raise ValueError("expected_tool_version must be an integer")
        if expected_tool_version < 1:
            raise ValueError("expected_tool_version must be positive")
        self.expected_tool_version = expected_tool_version
        self.expected_tenant_connector_id = expected_tenant_connector_id
        if not isinstance(expected_tenant_connector_id, UUID):
            raise ValueError("expected_tenant_connector_id must be a UUID")
        clean_route_digest = str(expected_route_digest).strip()
        if _SHA256_RE.fullmatch(clean_route_digest) is None:
            raise ValueError("expected_route_digest must be a lowercase SHA-256 value")
        self.expected_route_digest = clean_route_digest
        if self.execution_scope.project_id is None:
            raise ValueError("recovery ingestion requires authenticated project UUID")
        if (
            self.execution_scope.tenant_ref != self.scope.tenant_id
            or self.execution_scope.company_ref != self.scope.company_id
            or self.execution_scope.actor_ref != self.scope.user_id
            or self.execution_scope.project_ref != self.scope.project_ref
        ):
            raise ValueError("execution scope does not match exact workflow scope")
        expected_partition = recovery_ingestion_scope_fingerprint(self.scope)
        if repository.scope_fingerprint != expected_partition:
            raise CheckpointScopeError(
                "recovery repository is not partitioned by the full authenticated scope"
            )

    def _exact_scope_digest(self, *, key_id: str) -> str:
        return self.scope_keyring.exact_scope_digest(
            key_id=key_id,
            scope=self.scope,
        )

    def _read(
        self, *, limit: int, now: datetime, cursor: str | None = None
    ) -> tuple[
        ShopifyAbandonedCheckoutOutput,
        ConnectorExecutionProvenance,
        ConnectorExecutionRequest,
    ]:
        if not self.executor.supports(_READ_TOOL):
            raise RecoveryIngestionError(
                "governed abandoned-checkout read is unavailable"
            )
        if not 1 <= limit <= _MAX_PROVIDER_PAGE_SIZE:
            raise ValueError("provider page limit must be from 1 to 20")
        arguments: dict[str, Any] = {"limit": limit}
        if cursor is not None:
            arguments["cursor"] = _opaque_cursor(cursor)
        request = ConnectorExecutionRequest(
            tool=_READ_TOOL,
            arguments=arguments,
            scope=self.execution_scope,
            connector_account_ref=self.shopify_account_ref,
            effect=ConnectorEffect.READ,
        )
        result = self.executor.execute(request)
        if result.status != ConnectorExecutionStatus.COMPLETED:
            raise RecoveryIngestionError(
                "governed abandoned-checkout read did not complete"
            )
        provenance = result.provenance
        if provenance is None:
            raise RecoveryIngestionError(
                "governed abandoned-checkout read has no provenance"
            )
        if (
            provenance.tool != request.tool
            or provenance.server_effect != ConnectorEffect.READ
            or provenance.project_id != self.execution_scope.project_id
            or provenance.connector_account_ref != self.shopify_account_ref
            or provenance.tool_version != self.expected_tool_version
            or provenance.tenant_connector_id != self.expected_tenant_connector_id
            or provenance.route_digest != self.expected_route_digest
            or provenance.request_digest != request.custody_fingerprint()
            or provenance.approval_ref is not None
            or provenance.approval_receipt_digest is not None
        ):
            raise RecoveryIngestionError(
                "governed abandoned-checkout provenance mismatch"
            )
        completed = _parse_time(provenance.completed_at, label="completed_at")
        timestamp = _utc(now, label="now")
        if completed > timestamp + timedelta(
            minutes=1
        ) or timestamp - completed > timedelta(minutes=15):
            raise RecoveryIngestionError("governed abandoned-checkout read is stale")
        if _contains_truncation_sentinel(result.output):
            raise RecoveryIngestionError(
                "governed abandoned-checkout output contains a truncation sentinel"
            )
        try:
            output = ShopifyAbandonedCheckoutOutput.model_validate(result.output)
        except ValidationError as exc:
            raise RecoveryIngestionError(
                "governed abandoned-checkout output failed the Rust schema"
            ) from exc
        if output.total > limit:
            raise RecoveryIngestionError(
                "governed abandoned-checkout output exceeds the requested provider page"
            )
        return output, provenance, request

    def _verify_checkpoint(
        self, checkpoint: RecoveryIngestionCheckpoint
    ) -> RecoveryIngestionCheckpoint:
        if checkpoint.scope_fingerprint != self.repository.scope_fingerprint:
            raise CheckpointScopeError("replayed recovery checkpoint scope mismatch")
        if checkpoint.project_ref != self.scope.project_ref:
            raise CheckpointScopeError("replayed recovery checkpoint project mismatch")
        expected_scope = self.scope_keyring.exact_scope_digest(
            key_id=checkpoint.enrichment.receipt_key_id,
            scope=self.scope,
        )
        if not hmac.compare_digest(checkpoint.exact_scope_digest, expected_scope):
            raise CheckpointScopeError(
                "replayed recovery checkpoint exact scope mismatch"
            )
        expected_enrichment_hmac = self.scope_keyring.sign(
            checkpoint.enrichment.receipt_key_id,
            _ENRICHMENT_HMAC_DOMAIN,
            checkpoint.enrichment.hmac_payload(),
        ).hex()
        if not hmac.compare_digest(
            checkpoint.enrichment.attestation_hmac, expected_enrichment_hmac
        ):
            raise CheckpointPersistenceError(
                "replayed recovery enrichment HMAC is invalid"
            )
        expected_key = recovery_ingestion_key(
            scope_fingerprint=checkpoint.scope_fingerprint,
            shopify_account_ref=checkpoint.shopify_account_ref,
            checkout_ref=checkpoint.checkout_ref,
            checkout_version=checkpoint.checkout_version,
        )
        provenance = checkpoint.source_provenance
        if (
            checkpoint.ingestion_key != expected_key
            or provenance.tool != _READ_TOOL
            or provenance.server_effect != ConnectorEffect.READ
            or provenance.project_id != self.execution_scope.project_id
            or provenance.connector_account_ref != self.shopify_account_ref
            or provenance.tool_version != self.expected_tool_version
            or provenance.tenant_connector_id != self.expected_tenant_connector_id
            or provenance.route_digest != self.expected_route_digest
            or provenance.approval_ref is not None
            or provenance.approval_receipt_digest is not None
        ):
            raise CheckpointPersistenceError(
                "replayed recovery checkpoint read custody is invalid"
            )
        verify_abandoned_recovery_case(
            checkpoint.recovery_case,
            scope=self.scope,
            scope_keyring=self.scope_keyring,
        )
        if checkpoint.recovery_plan.profit_plan is not None:
            verify_profit_workflow_plan(
                checkpoint.recovery_plan.profit_plan,
                scope=self.scope,
                scope_keyring=self.scope_keyring,
            )
        return checkpoint

    def resolve_dispatch_secrets(
        self, checkpoint: RecoveryIngestionCheckpoint
    ) -> RecoveryResolvedSecrets:
        """Resolve but never persist raw secrets for later approved dispatch."""

        trusted = self._verify_checkpoint(checkpoint)
        raw = self.secret_resolver.resolve(trusted.enrichment, scope=self.scope)
        return _validate_resolved_secrets(trusted.enrichment, raw)

    def run_once(
        self,
        *,
        now: datetime,
        limit: int = 20,
        cursor: str | None = None,
    ) -> RecoveryIngestionRunResult:
        """Process at most 250 rows across 20-row governed provider pages.

        ``next_cursor`` is returned when Shopify has more rows than this bounded
        run.  The embedding host owns scheduling and durable scan-cursor custody;
        checkout checkpoints make replaying a page after a host crash idempotent.
        """

        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= _MAX_ROWS_PER_RUN
        ):
            raise ValueError("limit must be an integer from 1 to 250")
        timestamp = _utc(now, label="now")
        page_cursor = None if cursor is None else _opaque_cursor(cursor)
        seen_cursors = set() if page_cursor is None else {page_cursor}
        row_sources: list[
            tuple[ShopifyAbandonedCheckout, ConnectorExecutionProvenance]
        ] = []
        source_receipt_digests: list[str] = []
        next_cursor: str | None = None
        remaining = limit
        for _ in range(_MAX_PAGES_PER_RUN):
            page_limit = min(_MAX_PROVIDER_PAGE_SIZE, remaining)
            output, provenance, _ = self._read(
                limit=page_limit,
                now=timestamp,
                cursor=page_cursor,
            )
            source_receipt_digests.append(provenance.receipt_digest)
            row_sources.extend(
                (checkout, provenance) for checkout in output.abandoned_checkouts
            )
            remaining -= output.total
            next_cursor = output.next_cursor
            if next_cursor is None:
                break
            if next_cursor in seen_cursors:
                raise RecoveryIngestionError(
                    "Shopify abandoned-checkout pagination repeated a cursor"
                )
            seen_cursors.add(next_cursor)
            if remaining == 0:
                break
            page_cursor = next_cursor

        row_versions: dict[tuple[str, str], str] = {}
        for checkout, _ in row_sources:
            identity = (checkout.id, checkout.updated_at)
            prior_digest = row_versions.get(identity)
            if prior_digest is not None:
                if not hmac.compare_digest(prior_digest, checkout.checkout_digest):
                    raise RecoveryIngestionError(
                        "Shopify checkout changed without a new updatedAt version"
                    )
                raise RecoveryIngestionError(
                    "Shopify abandoned-checkout pagination returned a duplicate version"
                )
            row_versions[identity] = checkout.checkout_digest
        key_id = str(self.scope_keyring.active_key_id).strip()
        exact_scope_digest = self._exact_scope_digest(key_id=key_id)
        scope_fingerprint = recovery_ingestion_scope_fingerprint(self.scope)
        planned = 0
        replayed = 0
        failures: list[RecoveryIngestionFailure] = []
        checkpoints: list[RecoveryIngestionCheckpoint] = []
        rows = sorted(row_sources, key=lambda item: (item[0].updated_at, item[0].id))
        for checkout, provenance in rows:
            ingestion_key = recovery_ingestion_key(
                scope_fingerprint=scope_fingerprint,
                shopify_account_ref=self.shopify_account_ref,
                checkout_ref=checkout.id,
                checkout_version=checkout.updated_at,
            )
            existing = self.repository.get(ingestion_key)
            if existing is not None:
                if existing.checkout_digest != checkout.checkout_digest:
                    raise RecoveryIngestionError(
                        "Shopify checkout changed without a new updatedAt version"
                    )
                checkpoints.append(self._verify_checkpoint(existing))
                replayed += 1
                continue
            if (
                checkout.customer is None
                or checkout.customer.email is None
                or checkout.abandoned_checkout_url is None
                or checkout.line_items_subtotal_price is None
            ):
                failures.append(
                    RecoveryIngestionFailure(
                        checkout_ref=checkout.id,
                        checkout_version=checkout.updated_at,
                        code="contact_unavailable",
                    )
                )
                continue
            enrichment_request = RecoveryEnrichmentRequest(
                ingestion_key=ingestion_key,
                scope=self.scope,
                exact_scope_digest=exact_scope_digest,
                project_id=self.execution_scope.project_id,
                shopify_account_ref=self.shopify_account_ref,
                source_provenance=provenance,
                checkout=checkout,
                requested_at=_time(timestamp, label="now"),
            )
            try:
                enrichment = verify_recovery_ingestion_enrichment(
                    self.enrichment_authority.attest(enrichment_request),
                    request=enrichment_request,
                    now=timestamp,
                    scope_keyring=self.scope_keyring,
                )
            except Exception:
                failures.append(
                    RecoveryIngestionFailure(
                        checkout_ref=checkout.id,
                        checkout_version=checkout.updated_at,
                        code="enrichment_failed",
                    )
                )
                continue
            try:
                secrets = _validate_resolved_secrets(
                    enrichment,
                    self.secret_resolver.resolve(enrichment, scope=self.scope),
                )
            except Exception:
                failures.append(
                    RecoveryIngestionFailure(
                        checkout_ref=checkout.id,
                        checkout_version=checkout.updated_at,
                        code="secret_resolution_failed",
                    )
                )
                continue
            try:
                recovery_case = mint_abandoned_recovery_case(
                    enrichment.case_input,
                    scope=self.scope,
                    scope_keyring=self.scope_keyring,
                    scope_key_id=enrichment.receipt_key_id,
                )
                recovery_plan = plan_abandoned_revenue_recovery(
                    recovery_case,
                    resolved_secrets=secrets,
                    analysis_as_of=_parse_time(
                        enrichment.attested_at, label="attested_at"
                    ),
                    scope=self.scope,
                    scope_keyring=self.scope_keyring,
                )
                checkpoint = RecoveryIngestionCheckpoint(
                    ingestion_key=ingestion_key,
                    scope_fingerprint=scope_fingerprint,
                    project_ref=self.scope.project_ref,
                    exact_scope_digest=exact_scope_digest,
                    shopify_account_ref=self.shopify_account_ref,
                    expected_tool_version=self.expected_tool_version,
                    expected_tenant_connector_id=self.expected_tenant_connector_id,
                    expected_route_digest=self.expected_route_digest,
                    checkout_ref=checkout.id,
                    checkout_version=checkout.updated_at,
                    checkout_digest=checkout.checkout_digest,
                    source_provenance=provenance,
                    enrichment=enrichment,
                    recovery_case=recovery_case,
                    recovery_plan=recovery_plan,
                    created_at=_time(timestamp, label="now"),
                )
            except Exception:
                failures.append(
                    RecoveryIngestionFailure(
                        checkout_ref=checkout.id,
                        checkout_version=checkout.updated_at,
                        code="planning_failed",
                    )
                )
                continue
            try:
                self.repository.put(checkpoint)
            except CheckpointConflictError:
                winner = self.repository.get(ingestion_key)
                if winner is None:
                    failures.append(
                        RecoveryIngestionFailure(
                            checkout_ref=checkout.id,
                            checkout_version=checkout.updated_at,
                            code="checkpoint_conflict",
                        )
                    )
                    continue
                checkpoints.append(self._verify_checkpoint(winner))
                replayed += 1
                continue
            checkpoints.append(checkpoint)
            planned += 1
        return RecoveryIngestionRunResult(
            status="partial" if failures else "completed",
            source_receipt_digests=tuple(source_receipt_digests),
            next_cursor=next_cursor,
            discovered=len(rows),
            planned=planned,
            replayed=replayed,
            failures=tuple(failures),
            checkpoints=tuple(checkpoints),
        )


__all__ = [
    "RECOVERY_ENRICHMENT_ATTESTATION_SCHEMA",
    "RECOVERY_ENRICHMENT_REQUEST_SCHEMA",
    "RECOVERY_INGESTION_CHECKPOINT_SCHEMA",
    "RECOVERY_INGESTION_RUN_SCHEMA",
    "SHOPIFY_ABANDONED_CHECKOUT_OUTPUT_SCHEMA",
    "InMemoryRecoveryIngestionRepository",
    "JsonFileRecoveryIngestionRepository",
    "RecoveryEnrichmentAuthority",
    "RecoveryEnrichmentFacts",
    "RecoveryEnrichmentRequest",
    "RecoveryIngestionCheckpoint",
    "RecoveryIngestionEnrichment",
    "RecoveryIngestionError",
    "RecoveryIngestionFailure",
    "RecoveryIngestionRepository",
    "RecoveryIngestionRunResult",
    "RecoveryIngestionWorker",
    "RecoverySecretResolver",
    "ShopifyAbandonedCheckout",
    "ShopifyAbandonedCheckoutOutput",
    "ShopifyRecoveryCustomer",
    "ShopifyRecoveryLineItem",
    "ShopifyRecoveryLineItemEdge",
    "ShopifyRecoveryLineItems",
    "ShopifyRecoveryMoney",
    "ShopifyRecoveryMoneySet",
    "ShopifyRecoveryVariant",
    "mint_recovery_ingestion_enrichment",
    "recovery_ingestion_key",
    "recovery_ingestion_scope_fingerprint",
    "verify_recovery_ingestion_enrichment",
]
