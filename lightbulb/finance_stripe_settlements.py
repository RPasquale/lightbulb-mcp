"""Governed Stripe settlement observation for the finance close lighthouse.

The primitive consumes every page of one complete UTC calendar month through
``stripe.list_balance_transactions`` and emits a deterministic, provider-
specific settlement observation. Spring remains authoritative for tenant,
company, project, connector account, credential, route, provider dispatch,
durable execution evidence, certification, and production enablement.

This module deliberately does not reconcile Stripe to a ledger, persist an
observation, post an adjustment, advance a close state, or claim connector
certification. A completed result means only that every page returned through
one exact Spring-attested route passed the bounded normalization contract.
"""

from __future__ import annotations

import hashlib
import json
import re
from calendar import monthrange
from collections.abc import Mapping
from datetime import date, datetime, time, timezone
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from lightbulb.connector_execution import (
    ConnectorEffect,
    ConnectorExecutionProvenance,
    ConnectorExecutionRequest,
    ConnectorExecutionResult,
    ConnectorExecutionStatus,
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

STRIPE_SETTLEMENT_OBSERVATION_INPUT_SCHEMA = (
    "lightbulb.finance_stripe_settlement_observation_input.v1"
)
STRIPE_SETTLEMENT_MOVEMENT_SCHEMA = "lightbulb.stripe_settlement_movement.v1"
STRIPE_SETTLEMENT_OBSERVATION_RESULT_SCHEMA = (
    "lightbulb.finance_stripe_settlement_observation_result.v1"
)
STRIPE_LIST_BALANCE_TRANSACTIONS_TOOL = "stripe.list_balance_transactions"
STRIPE_SETTLEMENT_TOOL_VERSION = 2

_PAGE_SIZE = 100
_MAX_PAGES = 100
_MAX_MOVEMENTS = _PAGE_SIZE * _MAX_PAGES
_MAX_EPOCH_SECOND = 253_402_300_799
_MIN_SIGNED_64 = -(2**63)
_MAX_SIGNED_64 = 2**63 - 1
_ZERO_DIGEST = "0" * 64
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_CURRENCY_PATTERN = r"^[A-Z]{3}$"
_PORTABLE_REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@+\-]{0,199}$"
_STRIPE_TRANSACTION_PATTERN = re.compile(r"^txn_[A-Za-z0-9]{8,64}$")
_STRIPE_SOURCE_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_]{1,199}$")
_STRIPE_ENUM_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,79}$")
_STRIPE_LIST_URL = "/v1/balance_transactions"


def _visible_ref(value: str) -> str:
    if value != value.strip() or any(ord(character) < 33 for character in value):
        raise ValueError("references must contain visible non-whitespace characters")
    return value


def _strict_integer(value: Any) -> Any:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("integer fields require exact integers, not booleans")
    return value


OpaqueRef = Annotated[
    str,
    StringConstraints(pattern=_PORTABLE_REF_PATTERN),
    AfterValidator(_visible_ref),
]
Sha256Digest = Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)]
CurrencyCode = Annotated[str, StringConstraints(pattern=_CURRENCY_PATTERN)]
ExactInteger = Annotated[int, BeforeValidator(_strict_integer)]


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        revalidate_instances="always",
        serialize_by_alias=True,
        strict=True,
        allow_inf_nan=False,
    )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def _stable_digest(value: Any) -> str:
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _parse_complete_month(start_date: str, end_date: str) -> tuple[date, date]:
    try:
        start = date.fromisoformat(start_date)
        end = date.fromisoformat(end_date)
    except (TypeError, ValueError) as exc:
        raise ValueError("settlement dates must be exact ISO calendar dates") from exc
    if start.isoformat() != start_date or end.isoformat() != end_date:
        raise ValueError("settlement dates must use YYYY-MM-DD")
    if start.day != 1 or (start.year, start.month) != (end.year, end.month):
        raise ValueError("settlement scope must be one complete calendar month")
    if end.day != monthrange(end.year, end.month)[1]:
        raise ValueError("settlement scope must end on the month's final day")
    return start, end


def _month_epoch_bounds(start: date, end: date) -> tuple[int, int]:
    started_at = datetime.combine(start, time.min, tzinfo=timezone.utc)
    ended_at = datetime.combine(end, time(23, 59, 59), tzinfo=timezone.utc)
    return int(started_at.timestamp()), int(ended_at.timestamp())


def _utc_timestamp(epoch_second: int) -> str:
    return (
        datetime.fromtimestamp(epoch_second, tz=timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _parsed_utc_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class StripeSettlementObservationInput(_StrictModel):
    schema_id: Literal["lightbulb.finance_stripe_settlement_observation_input.v1"] = (
        Field(default=STRIPE_SETTLEMENT_OBSERVATION_INPUT_SCHEMA, alias="schema")
    )
    provider: Literal["stripe"] = "stripe"
    start_date: str
    end_date: str
    currency: CurrencyCode

    @model_validator(mode="after")
    def _complete_month(self) -> "StripeSettlementObservationInput":
        _parse_complete_month(self.start_date, self.end_date)
        return self


class StripeSettlementMovement(_StrictModel):
    """Canonical fields retained from one Stripe BalanceTransaction."""

    schema_id: Literal["lightbulb.stripe_settlement_movement.v1"] = Field(
        default=STRIPE_SETTLEMENT_MOVEMENT_SCHEMA,
        alias="schema",
    )
    provider: Literal["stripe"] = "stripe"
    transaction_ref: str = Field(pattern=r"^txn_[A-Za-z0-9]{8,64}$")
    amount_minor: ExactInteger = Field(ge=_MIN_SIGNED_64, le=_MAX_SIGNED_64)
    fee_minor: ExactInteger = Field(ge=_MIN_SIGNED_64, le=_MAX_SIGNED_64)
    net_minor: ExactInteger = Field(ge=_MIN_SIGNED_64, le=_MAX_SIGNED_64)
    currency: CurrencyCode
    created_epoch_second: ExactInteger = Field(ge=0, le=_MAX_EPOCH_SECOND)
    created_at: str
    available_on_epoch_second: ExactInteger = Field(ge=0, le=_MAX_EPOCH_SECOND)
    available_on: str
    movement_type: str = Field(pattern=r"^[a-z][a-z0-9_]{0,79}$")
    reporting_category: str = Field(pattern=r"^[a-z][a-z0-9_]{0,79}$")
    status: Literal["available", "pending"]
    source_ref: str | None = Field(
        default=None,
        pattern=r"^[A-Za-z][A-Za-z0-9_]{1,199}$",
    )

    @field_validator("created_at", "available_on")
    @classmethod
    def _canonical_utc(cls, value: str, info: Any) -> str:
        if not isinstance(value, str) or value != value.strip():
            raise ValueError(f"{info.field_name} must be a trimmed UTC timestamp")
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"{info.field_name} must be valid ISO-8601") from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError(f"{info.field_name} must include a UTC offset")
        return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    @model_validator(mode="after")
    def _exact_amount_and_times(self) -> "StripeSettlementMovement":
        if self.amount_minor - self.fee_minor != self.net_minor:
            raise ValueError("Stripe amount minus fee must equal net")
        if self.created_at != _utc_timestamp(self.created_epoch_second):
            raise ValueError("created_at must match created_epoch_second")
        if self.available_on != _utc_timestamp(self.available_on_epoch_second):
            raise ValueError("available_on must match available_on_epoch_second")
        return self


class StripeSettlementObservationResult(_StrictModel):
    schema_id: Literal["lightbulb.finance_stripe_settlement_observation_result.v1"] = (
        Field(default=STRIPE_SETTLEMENT_OBSERVATION_RESULT_SCHEMA, alias="schema")
    )
    provider: Literal["stripe"] = "stripe"
    tool: Literal["stripe.list_balance_transactions"] = (
        STRIPE_LIST_BALANCE_TRANSACTIONS_TOOL
    )
    tool_version: Literal[2] = STRIPE_SETTLEMENT_TOOL_VERSION
    project_id: UUID
    tenant_connector_id: UUID
    connector_account_ref: OpaqueRef
    route_digest: Sha256Digest
    start_date: str
    end_date: str
    currency: CurrencyCode
    movements: tuple[StripeSettlementMovement, ...] = Field(max_length=_MAX_MOVEMENTS)
    movement_count: ExactInteger = Field(ge=0, le=_MAX_MOVEMENTS)
    page_count: ExactInteger = Field(ge=1, le=_MAX_PAGES)
    final_cursor_ref: str | None = Field(
        default=None,
        pattern=r"^txn_[A-Za-z0-9]{8,64}$",
    )
    page_digests: tuple[Sha256Digest, ...] = Field(
        min_length=1,
        max_length=_MAX_PAGES,
    )
    provenance_receipt_digests: tuple[Sha256Digest, ...] = Field(
        min_length=1,
        max_length=_MAX_PAGES,
    )
    observation_completed_ats: tuple[str, ...] = Field(
        min_length=1,
        max_length=_MAX_PAGES,
    )
    observed_at: str
    freshness: Literal["current"] = "current"
    classification: Literal["restricted"] = "restricted"
    retention_requirement: Literal["spring_financial_evidence_policy"] = (
        "spring_financial_evidence_policy"
    )
    complete: Literal[True] = True
    authoritative_read: Literal[True] = True
    reconciliation_authority: Literal[False] = False
    close_authority: Literal[False] = False
    source_digest: Sha256Digest = _ZERO_DIGEST

    @field_validator(
        "movements",
        "page_digests",
        "provenance_receipt_digests",
        "observation_completed_ats",
        mode="before",
    )
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("observed_at", "observation_completed_ats")
    @classmethod
    def _utc_observation_times(cls, value: Any, info: Any) -> Any:
        values = value if isinstance(value, tuple) else (value,)
        normalized: list[str] = []
        for item in values:
            if not isinstance(item, str) or item != item.strip():
                raise ValueError(f"{info.field_name} must contain UTC timestamps")
            try:
                parsed = datetime.fromisoformat(item.replace("Z", "+00:00"))
            except ValueError as exc:
                raise ValueError(
                    f"{info.field_name} must contain valid ISO-8601 timestamps"
                ) from exc
            if parsed.tzinfo is None or parsed.utcoffset() is None:
                raise ValueError(f"{info.field_name} timestamps require UTC offsets")
            normalized.append(
                parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
            )
        return tuple(normalized) if isinstance(value, tuple) else normalized[0]

    def _source_digest_payload(self) -> dict[str, Any]:
        return {
            "schema": self.schema_id,
            "provider": self.provider,
            "tool": self.tool,
            "tool_version": self.tool_version,
            "project_id": str(self.project_id),
            "tenant_connector_id": str(self.tenant_connector_id),
            "connector_account_ref": self.connector_account_ref,
            "route_digest": self.route_digest,
            "start_date": self.start_date,
            "end_date": self.end_date,
            "currency": self.currency,
            "movements": [item.to_dict() for item in self.movements],
            "page_digests": self.page_digests,
            "provenance_receipt_digests": self.provenance_receipt_digests,
            "observation_completed_ats": self.observation_completed_ats,
        }

    @model_validator(mode="after")
    def _complete_and_sealed(self) -> "StripeSettlementObservationResult":
        _parse_complete_month(self.start_date, self.end_date)
        if self.movement_count != len(self.movements):
            raise ValueError("movement_count must match movements")
        if not (
            self.page_count
            == len(self.page_digests)
            == len(self.provenance_receipt_digests)
            == len(self.observation_completed_ats)
        ):
            raise ValueError("page_count must match all page evidence")
        refs = [item.transaction_ref for item in self.movements]
        if len(refs) != len(set(refs)):
            raise ValueError("Stripe settlement transaction references must be unique")
        if any(item.currency != self.currency for item in self.movements):
            raise ValueError("all settlement movements must use the requested currency")
        if len(set(self.provenance_receipt_digests)) != self.page_count:
            raise ValueError("each page requires a distinct provenance receipt")
        completed = [
            _parsed_utc_timestamp(item) for item in self.observation_completed_ats
        ]
        if completed != sorted(completed):
            raise ValueError("page completion observations must be nondecreasing")
        if self.observed_at != self.observation_completed_ats[-1]:
            raise ValueError("observed_at must be the final page completion time")
        expected = _stable_digest(self._source_digest_payload())
        if self.source_digest not in {_ZERO_DIGEST, expected}:
            raise ValueError(
                "source_digest does not match canonical settlement evidence"
            )
        object.__setattr__(self, "source_digest", expected)
        return self


class _StripeSettlementError(Exception):
    def __init__(self, code: str, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable


def _read_operation_spec(page_number: int) -> PrimitiveOperationSpec:
    return PrimitiveOperationSpec(
        operation_ref=f"stripe-settlements.read-page-{page_number}",
        tool=STRIPE_LIST_BALANCE_TRANSACTIONS_TOOL,
        effect=ConnectorEffect.READ,
        approval_required=False,
        replay_class=PrimitiveOperationReplayClass.SAFE,
        freshness_class=PrimitiveOperationFreshnessClass.CURRENT,
        recovery_policy=PrimitiveOperationRecoveryPolicy.RETRY,
    )


def _exact_int(value: Any, *, field_name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise _StripeSettlementError(
            "stripe_settlement_response_invalid",
            f"Stripe {field_name} must be an exact integer.",
        )
    if value < minimum or value > maximum:
        raise _StripeSettlementError(
            "stripe_settlement_response_invalid",
            f"Stripe {field_name} is outside the supported range.",
        )
    return value


def _exact_string(
    value: Any,
    *,
    field_name: str,
    pattern: re.Pattern[str],
) -> str:
    if (
        not isinstance(value, str)
        or value != value.strip()
        or pattern.fullmatch(value) is None
    ):
        raise _StripeSettlementError(
            "stripe_settlement_response_invalid",
            f"Stripe {field_name} is malformed.",
        )
    return value


def _normalize_movement(
    raw: Any,
    *,
    currency: str,
    created_gte: int,
    created_lte: int,
) -> StripeSettlementMovement:
    if not isinstance(raw, Mapping):
        raise _StripeSettlementError(
            "stripe_settlement_response_invalid",
            "A Stripe balance transaction is not an object.",
        )
    if raw.get("object") != "balance_transaction":
        raise _StripeSettlementError(
            "stripe_settlement_response_invalid",
            "A Stripe balance transaction has the wrong object type.",
        )
    transaction_ref = _exact_string(
        raw.get("id"),
        field_name="balance transaction id",
        pattern=_STRIPE_TRANSACTION_PATTERN,
    )
    raw_currency = raw.get("currency")
    if not isinstance(raw_currency, str) or raw_currency != currency.lower():
        raise _StripeSettlementError(
            "stripe_settlement_currency_mismatch",
            "A Stripe balance transaction does not use the requested base currency.",
        )
    amount = _exact_int(
        raw.get("amount"),
        field_name="amount",
        minimum=_MIN_SIGNED_64,
        maximum=_MAX_SIGNED_64,
    )
    fee = _exact_int(
        raw.get("fee"),
        field_name="fee",
        minimum=_MIN_SIGNED_64,
        maximum=_MAX_SIGNED_64,
    )
    net = _exact_int(
        raw.get("net"),
        field_name="net",
        minimum=_MIN_SIGNED_64,
        maximum=_MAX_SIGNED_64,
    )
    if amount - fee != net:
        raise _StripeSettlementError(
            "stripe_settlement_amount_invariant_failed",
            "A Stripe balance transaction violates amount minus fee equals net.",
        )
    created = _exact_int(
        raw.get("created"),
        field_name="created",
        minimum=0,
        maximum=_MAX_EPOCH_SECOND,
    )
    if created < created_gte or created > created_lte:
        raise _StripeSettlementError(
            "stripe_settlement_scope_mismatch",
            "A Stripe balance transaction falls outside the requested month.",
        )
    available_on = _exact_int(
        raw.get("available_on"),
        field_name="available_on",
        minimum=0,
        maximum=_MAX_EPOCH_SECOND,
    )
    movement_type = _exact_string(
        raw.get("type"),
        field_name="type",
        pattern=_STRIPE_ENUM_PATTERN,
    )
    reporting_category = _exact_string(
        raw.get("reporting_category"),
        field_name="reporting_category",
        pattern=_STRIPE_ENUM_PATTERN,
    )
    status = raw.get("status")
    if status not in {"available", "pending"}:
        raise _StripeSettlementError(
            "stripe_settlement_response_invalid",
            "A Stripe balance transaction has an unsupported status.",
        )
    source_ref: str | None = None
    if raw.get("source") is not None:
        source_ref = _exact_string(
            raw.get("source"),
            field_name="source",
            pattern=_STRIPE_SOURCE_PATTERN,
        )
    try:
        return StripeSettlementMovement(
            transaction_ref=transaction_ref,
            amount_minor=amount,
            fee_minor=fee,
            net_minor=net,
            currency=currency,
            created_epoch_second=created,
            created_at=_utc_timestamp(created),
            available_on_epoch_second=available_on,
            available_on=_utc_timestamp(available_on),
            movement_type=movement_type,
            reporting_category=reporting_category,
            status=status,
            source_ref=source_ref,
        )
    except Exception as exc:
        raise _StripeSettlementError(
            "stripe_settlement_response_invalid",
            "A Stripe balance transaction failed canonical validation.",
        ) from exc


def _normalize_page(
    raw: Any,
    *,
    page_number: int,
    requested_cursor: str | None,
    currency: str,
    created_gte: int,
    created_lte: int,
) -> tuple[tuple[StripeSettlementMovement, ...], bool, str | None, str]:
    if not isinstance(raw, Mapping) or set(raw) != {
        "object",
        "data",
        "has_more",
        "url",
    }:
        raise _StripeSettlementError(
            "stripe_settlement_response_invalid",
            "Stripe settlement pagination returned an unexpected collection shape.",
        )
    if raw.get("object") != "list" or raw.get("url") != _STRIPE_LIST_URL:
        raise _StripeSettlementError(
            "stripe_settlement_response_invalid",
            "Stripe settlement pagination returned the wrong list identity.",
        )
    has_more = raw.get("has_more")
    if type(has_more) is not bool:
        raise _StripeSettlementError(
            "stripe_settlement_response_invalid",
            "Stripe has_more must be an exact boolean.",
        )
    data = raw.get("data")
    if not isinstance(data, list) or len(data) > _PAGE_SIZE:
        raise _StripeSettlementError(
            "stripe_settlement_response_invalid",
            "Stripe settlement page data must contain at most 100 records.",
        )
    if has_more and not data:
        raise _StripeSettlementError(
            "stripe_settlement_pagination_invalid",
            "Stripe reported another page without returning a cursor record.",
        )
    movements = tuple(
        _normalize_movement(
            item,
            currency=currency,
            created_gte=created_gte,
            created_lte=created_lte,
        )
        for item in data
    )
    refs = [item.transaction_ref for item in movements]
    if len(refs) != len(set(refs)):
        raise _StripeSettlementError(
            "stripe_settlement_page_overlap",
            "A Stripe settlement page contains duplicate transaction references.",
        )
    terminal_cursor = movements[-1].transaction_ref if movements else None
    if has_more and terminal_cursor == requested_cursor:
        raise _StripeSettlementError(
            "stripe_settlement_cursor_loop",
            "Stripe settlement pagination repeated the same cursor.",
        )
    page_digest = _stable_digest(
        {
            "schema": "lightbulb.stripe_settlement_page.v1",
            "page_number": page_number,
            "requested_cursor": requested_cursor,
            "has_more": has_more,
            "terminal_cursor": terminal_cursor,
            "movements": [item.to_dict() for item in movements],
        }
    )
    return movements, has_more, terminal_cursor, page_digest


def _validate_provenance(
    provenance: ConnectorExecutionProvenance | None,
    request: ConnectorExecutionRequest,
) -> ConnectorExecutionProvenance:
    if provenance is None:
        raise _StripeSettlementError(
            "stripe_settlement_provenance_missing",
            "The governed Stripe result has no Spring provenance.",
        )
    if (
        provenance.tool != request.tool
        or provenance.tool_version != STRIPE_SETTLEMENT_TOOL_VERSION
        or provenance.server_effect != ConnectorEffect.READ
        or provenance.connector_account_ref != request.connector_account_ref
        or request.scope.project_id is None
        or provenance.project_id != request.scope.project_id
        or provenance.request_digest != request.custody_fingerprint()
        or provenance.approval_ref is not None
        or provenance.approval_receipt_digest is not None
    ):
        raise _StripeSettlementError(
            "stripe_settlement_provenance_mismatch",
            "The Spring provenance does not match this exact Stripe page request.",
        )
    return provenance


def _page_receipt(
    *,
    page_number: int,
    request: ConnectorExecutionRequest,
    result: ConnectorExecutionResult,
    blocker: PrimitiveBlocker | None = None,
    provenance_valid: bool = False,
    force_failed: bool = False,
) -> PrimitiveOperationReceipt:
    status = {
        ConnectorExecutionStatus.COMPLETED: PrimitiveOperationStatus.COMPLETED,
        ConnectorExecutionStatus.PREVIEW: PrimitiveOperationStatus.PREVIEW,
        ConnectorExecutionStatus.PENDING_APPROVAL: PrimitiveOperationStatus.BLOCKED,
        ConnectorExecutionStatus.BLOCKED: PrimitiveOperationStatus.BLOCKED,
        ConnectorExecutionStatus.FAILED: PrimitiveOperationStatus.FAILED,
    }[result.status]
    if force_failed:
        status = PrimitiveOperationStatus.FAILED
    provenance = result.provenance if provenance_valid else None
    return PrimitiveOperationReceipt(
        spec=_read_operation_spec(page_number),
        status=status,
        request_digest=request.custody_fingerprint(),
        provenance_receipt_digest=(
            provenance.receipt_digest if provenance is not None else None
        ),
        external_refs=(
            {
                "execution_journal_ref": provenance.journal_ref,
                "route_digest": provenance.route_digest,
            }
            if provenance is not None
            else {}
        ),
        replayed=result.cached,
        error=(
            blocker
            if status
            in {PrimitiveOperationStatus.BLOCKED, PrimitiveOperationStatus.FAILED}
            else None
        ),
    )


class DiscoverStripeSettlementMovementsPrimitive(
    BusinessProcessPrimitive[
        StripeSettlementObservationInput,
        StripeSettlementObservationResult,
    ]
):
    primitive_ref = "finance.discover_stripe_settlement_movements"
    version = "1.0.0"
    title = "Discover governed Stripe settlement movements"
    description = (
        "Read every Stripe balance transaction for one complete UTC month through "
        "one exact governed project/account route and normalize exact minor-unit "
        "settlement movements without reconciling or advancing a close."
    )
    input_model = StripeSettlementObservationInput
    output_model = StripeSettlementObservationResult
    connector_tools = (STRIPE_LIST_BALANCE_TRANSACTIONS_TOOL,)
    risk_level = "low"
    approval_required = False
    example_inputs = {
        "provider": "stripe",
        "start_date": "2026-08-01",
        "end_date": "2026-08-31",
        "currency": "USD",
    }
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = True

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: StripeSettlementObservationInput,
    ) -> PrimitiveExecutionResult[StripeSettlementObservationResult]:
        start, end = _parse_complete_month(inputs.start_date, inputs.end_date)
        created_gte, created_lte = _month_epoch_bounds(start, end)
        if context.preview_only:
            arguments = {
                "limit": _PAGE_SIZE,
                "created": {"gte": created_gte, "lte": created_lte},
            }
            receipt = PrimitiveOperationReceipt(
                spec=_read_operation_spec(1),
                status=PrimitiveOperationStatus.PLANNED,
                request_digest=_stable_digest(
                    {
                        "schema": "lightbulb.stripe_settlement_observation_plan.v1",
                        "provider": inputs.provider,
                        "tool": STRIPE_LIST_BALANCE_TRANSACTIONS_TOOL,
                        "arguments": arguments,
                        "currency": inputs.currency,
                        "requires_project_id": True,
                        "requires_connector_account_ref": True,
                    }
                ),
            )
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.PREVIEW,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary=(
                    "Stripe settlement discovery previewed; no connector read was "
                    "requested and no settlement evidence was fabricated."
                ),
                operation_receipts=[receipt],
                connector_tool=STRIPE_LIST_BALANCE_TRANSACTIONS_TOOL,
            )

        account_ref = context.connector_account_refs.get(
            STRIPE_LIST_BALANCE_TRANSACTIONS_TOOL
        )
        if account_ref is None:
            account_ref = context.connector_account_refs.get("stripe")
        if context.scope.project_id is None or not str(account_ref or "").strip():
            blocker = PrimitiveBlocker(
                code="stripe_settlement_scope_required",
                message=(
                    "Governed Stripe settlement discovery requires an authenticated "
                    "project UUID and exact Stripe connector-account binding."
                ),
            )
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.BLOCKED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary=blocker.message,
                blockers=[blocker],
                connector_tool=STRIPE_LIST_BALANCE_TRANSACTIONS_TOOL,
            )

        receipts: list[PrimitiveOperationReceipt] = []
        movements: list[StripeSettlementMovement] = []
        seen_refs: set[str] = set()
        page_digests: list[str] = []
        provenance_digests: list[str] = []
        completed_ats: list[str] = []
        journal_refs: set[str] = set()
        expected_route: tuple[UUID, str, str] | None = None
        cursor: str | None = None

        for page_number in range(1, _MAX_PAGES + 1):
            arguments: dict[str, Any] = {
                "limit": _PAGE_SIZE,
                "created": {"gte": created_gte, "lte": created_lte},
            }
            if cursor is not None:
                arguments["starting_after"] = cursor
            spec = _read_operation_spec(page_number)
            request = context.connector_request(
                primitive_ref=self.primitive_ref,
                tool=STRIPE_LIST_BALANCE_TRANSACTIONS_TOOL,
                arguments=arguments,
                effect=ConnectorEffect.READ,
                approval_required=False,
                operation_ref=spec.operation_ref,
                connector_account_ref=str(account_ref),
                metadata={"source": self.primitive_ref, "page_number": page_number},
            )
            result = context.connectors.execute(request)
            if result.tool != request.tool:
                blocker = PrimitiveBlocker(
                    code="stripe_settlement_tool_mismatch",
                    message="The connector response is not bound to the requested Stripe Tool.",
                )
                receipts.append(
                    _page_receipt(
                        page_number=page_number,
                        request=request,
                        result=result,
                        blocker=blocker,
                        force_failed=True,
                    )
                )
                return PrimitiveExecutionResult(
                    status=PrimitiveExecutionStatus.FAILED,
                    primitive_ref=self.primitive_ref,
                    primitive_version=self.version,
                    summary=blocker.message,
                    blockers=[blocker],
                    operation_receipts=receipts,
                    connector_tool=STRIPE_LIST_BALANCE_TRANSACTIONS_TOOL,
                )
            if result.status != ConnectorExecutionStatus.COMPLETED:
                primitive_status = (
                    PrimitiveExecutionStatus.BLOCKED
                    if result.status
                    in {
                        ConnectorExecutionStatus.BLOCKED,
                        ConnectorExecutionStatus.PENDING_APPROVAL,
                    }
                    else PrimitiveExecutionStatus.FAILED
                )
                blocker = PrimitiveBlocker(
                    code="stripe_settlement_read_failed",
                    message="The governed Stripe settlement page did not complete.",
                    retryable=result.retryable,
                )
                receipts.append(
                    _page_receipt(
                        page_number=page_number,
                        request=request,
                        result=result,
                        blocker=blocker,
                    )
                )
                return PrimitiveExecutionResult(
                    status=primitive_status,
                    primitive_ref=self.primitive_ref,
                    primitive_version=self.version,
                    summary=blocker.message,
                    blockers=[blocker],
                    operation_receipts=receipts,
                    connector_tool=STRIPE_LIST_BALANCE_TRANSACTIONS_TOOL,
                    retryable=result.retryable,
                )

            provenance: ConnectorExecutionProvenance | None = None
            try:
                provenance = _validate_provenance(result.provenance, request)
                route = (
                    provenance.tenant_connector_id,
                    provenance.connector_account_ref,
                    provenance.route_digest,
                )
                if expected_route is None:
                    expected_route = route
                elif route != expected_route:
                    raise _StripeSettlementError(
                        "stripe_settlement_route_drift",
                        "Stripe settlement pagination changed its exact Spring route.",
                    )
                if provenance.journal_ref in journal_refs:
                    raise _StripeSettlementError(
                        "stripe_settlement_provenance_reused",
                        "Stripe settlement pages reused an execution journal reference.",
                    )
                if completed_ats and _parsed_utc_timestamp(
                    provenance.completed_at
                ) < _parsed_utc_timestamp(completed_ats[-1]):
                    raise _StripeSettlementError(
                        "stripe_settlement_observation_time_invalid",
                        "Stripe settlement page completion times moved backwards.",
                    )
                page, has_more, terminal_cursor, page_digest = _normalize_page(
                    result.output,
                    page_number=page_number,
                    requested_cursor=cursor,
                    currency=inputs.currency,
                    created_gte=created_gte,
                    created_lte=created_lte,
                )
                page_refs = {item.transaction_ref for item in page}
                if page_refs & seen_refs:
                    raise _StripeSettlementError(
                        "stripe_settlement_page_overlap",
                        "Stripe settlement pages overlap transaction references.",
                    )
                if len(movements) + len(page) > _MAX_MOVEMENTS:
                    raise _StripeSettlementError(
                        "stripe_settlement_record_limit_exceeded",
                        "Stripe settlement observation exceeds 10,000 records.",
                    )
                if has_more and page_number == _MAX_PAGES:
                    raise _StripeSettlementError(
                        "stripe_settlement_page_limit_exceeded",
                        "Stripe settlement observation exceeds 100 pages.",
                    )
            except _StripeSettlementError as exc:
                blocker = PrimitiveBlocker(
                    code=exc.code,
                    message=exc.message,
                    retryable=exc.retryable,
                )
                receipts.append(
                    _page_receipt(
                        page_number=page_number,
                        request=request,
                        result=result,
                        blocker=blocker,
                        provenance_valid=provenance is not None,
                        force_failed=True,
                    )
                )
                return PrimitiveExecutionResult(
                    status=PrimitiveExecutionStatus.FAILED,
                    primitive_ref=self.primitive_ref,
                    primitive_version=self.version,
                    summary=blocker.message,
                    blockers=[blocker],
                    operation_receipts=receipts,
                    connector_tool=STRIPE_LIST_BALANCE_TRANSACTIONS_TOOL,
                    retryable=exc.retryable,
                )

            assert provenance is not None
            receipts.append(
                _page_receipt(
                    page_number=page_number,
                    request=request,
                    result=result,
                    provenance_valid=True,
                )
            )
            journal_refs.add(provenance.journal_ref)
            seen_refs.update(page_refs)
            movements.extend(page)
            page_digests.append(page_digest)
            provenance_digests.append(provenance.receipt_digest)
            completed_ats.append(provenance.completed_at)
            cursor = terminal_cursor
            if not has_more:
                break
        else:  # pragma: no cover - the explicit page-limit branch returns first
            raise AssertionError("bounded Stripe pagination did not terminate")

        assert expected_route is not None
        ordered_movements = tuple(
            sorted(
                movements,
                key=lambda item: (item.created_epoch_second, item.transaction_ref),
            )
        )
        output = StripeSettlementObservationResult(
            project_id=context.scope.project_id,
            tenant_connector_id=expected_route[0],
            connector_account_ref=expected_route[1],
            route_digest=expected_route[2],
            start_date=inputs.start_date,
            end_date=inputs.end_date,
            currency=inputs.currency,
            movements=ordered_movements,
            movement_count=len(ordered_movements),
            page_count=len(page_digests),
            final_cursor_ref=cursor,
            page_digests=tuple(page_digests),
            provenance_receipt_digests=tuple(provenance_digests),
            observation_completed_ats=tuple(completed_ats),
            observed_at=completed_ats[-1],
        )
        return PrimitiveExecutionResult(
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                f"Discovered {output.movement_count} governed Stripe settlement "
                "movements for one complete UTC month."
            ),
            output=output,
            events=[
                PrimitiveEvent(
                    type="finance.stripe_settlement_movements_discovered",
                    payload={
                        "provider": output.provider,
                        "start_date": output.start_date,
                        "end_date": output.end_date,
                        "currency": output.currency,
                        "movement_count": output.movement_count,
                        "source_digest": output.source_digest,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="governed_stripe_settlement_observation",
                    summary=(
                        "A complete bounded monthly Stripe balance-transaction "
                        "observation was read with exact Spring provenance."
                    ),
                    labels=[
                        "stripe",
                        "authoritative_read",
                        "complete",
                        "monthly",
                        "reconciliation_not_performed",
                    ],
                    refs={"source_digest": output.source_digest},
                )
            ],
            operation_receipts=receipts,
            connector_tool=STRIPE_LIST_BALANCE_TRANSACTIONS_TOOL,
        )


FINANCE_STRIPE_SETTLEMENT_EXECUTABLE_PRIMITIVES: tuple[
    BusinessProcessPrimitive[Any, Any], ...
] = (DiscoverStripeSettlementMovementsPrimitive(),)


__all__ = [
    "DiscoverStripeSettlementMovementsPrimitive",
    "FINANCE_STRIPE_SETTLEMENT_EXECUTABLE_PRIMITIVES",
    "STRIPE_LIST_BALANCE_TRANSACTIONS_TOOL",
    "STRIPE_SETTLEMENT_MOVEMENT_SCHEMA",
    "STRIPE_SETTLEMENT_OBSERVATION_INPUT_SCHEMA",
    "STRIPE_SETTLEMENT_OBSERVATION_RESULT_SCHEMA",
    "STRIPE_SETTLEMENT_TOOL_VERSION",
    "StripeSettlementMovement",
    "StripeSettlementObservationInput",
    "StripeSettlementObservationResult",
]
