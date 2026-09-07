"""Governed Xero source transactions for the monthly-close lighthouse.

The primitive reads every Xero sales invoice, purchase bill, and payment in one
complete calendar month through three reviewed Tool-v2 routes. Spring owns
authenticated scope, exact organisation and credential custody, dispatch,
durable audit, certification, and production enablement. The connector runtime
fixes provider filters and minimizes responses. The SDK proves bounded provider
pagination, validates canonical records and source revisions, and seals the
complete observation.

A completed observation is source evidence only. It does not persist records,
reconcile balances, authorize a journal, or advance the accounting period.
"""

from __future__ import annotations

import hashlib
import json
import re
from calendar import monthrange
from collections.abc import Mapping
from datetime import date, datetime, timezone
from decimal import Decimal
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StringConstraints,
    field_serializer,
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

XERO_CLOSE_SOURCE_TRANSACTION_INPUT_SCHEMA = (
    "lightbulb.finance_xero_close_source_transaction_input.v1"
)
XERO_CLOSE_SOURCE_TRANSACTION_SCHEMA = (
    "lightbulb.finance_xero_close_source_transaction.v1"
)
XERO_CLOSE_SOURCE_TRANSACTION_LINK_SCHEMA = (
    "lightbulb.finance_xero_close_source_transaction_link.v1"
)
XERO_CLOSE_SOURCE_PAGE_CHECKPOINT_SCHEMA = (
    "lightbulb.finance_xero_close_source_page_checkpoint.v1"
)
XERO_CLOSE_SOURCE_TRANSACTION_RESULT_SCHEMA = (
    "lightbulb.finance_xero_close_source_transaction_result.v1"
)
XERO_CLOSE_SOURCE_PAGE_SCHEMA = "lightbulb.xero_close_source_page.v1"

XERO_LIST_INVOICES_TOOL = "xero.list_invoices"
XERO_LIST_BILLS_TOOL = "xero.list_bills"
XERO_LIST_PAYMENTS_TOOL = "xero.list_payments"
XERO_CLOSE_SOURCE_TOOL_VERSION = 2

_SOURCE_SPECS: tuple[tuple[str, str], ...] = (
    (XERO_LIST_INVOICES_TOOL, "invoice"),
    (XERO_LIST_BILLS_TOOL, "bill"),
    (XERO_LIST_PAYMENTS_TOOL, "payment"),
)
_PAGE_SIZE = 100
_MAX_PAGES_PER_TYPE = 100
_MAX_TRANSACTIONS_PER_TYPE = _PAGE_SIZE * _MAX_PAGES_PER_TYPE
_MAX_TRANSACTIONS = _MAX_TRANSACTIONS_PER_TYPE * len(_SOURCE_SPECS)
_MAX_PAGE_READS = _MAX_PAGES_PER_TYPE * len(_SOURCE_SPECS)
_MAX_MONEY_CHARS = 64
_ZERO_DIGEST = "0" * 64
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_CURRENCY_PATTERN = r"^[A-Z]{3}$"
_PORTABLE_REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@+\-]{0,199}$"
_MONEY_PATTERN = re.compile(r"^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$")
_TRANSACTION_TYPES = {"invoice", "bill", "payment"}


def _visible_ref(value: str) -> str:
    if value != value.strip() or any(ord(character) < 33 for character in value):
        raise ValueError("references must contain visible non-whitespace characters")
    return value


def _strict_integer(value: Any) -> Any:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("integer fields require exact integers")
    return value


def _strict_decimal(value: Any) -> Decimal:
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise ValueError("money values must be finite")
        return value
    if (
        not isinstance(value, str)
        or len(value) > _MAX_MONEY_CHARS
        or _MONEY_PATTERN.fullmatch(value) is None
    ):
        raise ValueError("money values require canonical decimal strings")
    parsed = Decimal(value)
    if not parsed.is_finite():
        raise ValueError("money values must be finite")
    return parsed


OpaqueRef = Annotated[
    str,
    StringConstraints(pattern=_PORTABLE_REF_PATTERN),
    AfterValidator(_visible_ref),
]
Sha256Digest = Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)]
CurrencyCode = Annotated[str, StringConstraints(pattern=_CURRENCY_PATTERN)]
ExactInteger = Annotated[int, BeforeValidator(_strict_integer)]
ExactDecimal = Annotated[Decimal, BeforeValidator(_strict_decimal)]
TransactionType = Literal["invoice", "bill", "payment"]


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
        raise ValueError("Xero source-transaction dates must be exact ISO dates") from exc
    if start.isoformat() != start_date or end.isoformat() != end_date:
        raise ValueError("Xero source-transaction dates must use YYYY-MM-DD")
    if start.day != 1 or (start.year, start.month) != (end.year, end.month):
        raise ValueError("Xero source-transaction scope must be one complete month")
    if end.day != monthrange(end.year, end.month)[1]:
        raise ValueError("Xero source-transaction scope must end on the final day")
    return start, end


def _utc_timestamp(value: str, *, field_name: str) -> str:
    if not isinstance(value, str) or value != value.strip():
        raise ValueError(f"{field_name} must be a trimmed timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field_name} must be valid ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field_name} must include an offset")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parsed_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _canonical_money(value: Decimal) -> str:
    rendered = format(value, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return "0" if rendered in {"-0", ""} else rendered


class XeroCloseSourceTransactionInput(_StrictModel):
    schema_id: Literal[
        "lightbulb.finance_xero_close_source_transaction_input.v1"
    ] = Field(default=XERO_CLOSE_SOURCE_TRANSACTION_INPUT_SCHEMA, alias="schema")
    provider: Literal["xero"] = "xero"
    start_date: str
    end_date: str
    currency: CurrencyCode

    @model_validator(mode="after")
    def _complete_month(self) -> "XeroCloseSourceTransactionInput":
        _parse_complete_month(self.start_date, self.end_date)
        return self


class XeroCloseSourceTransactionLink(_StrictModel):
    schema_id: Literal[
        "lightbulb.finance_xero_close_source_transaction_link.v1"
    ] = Field(default=XERO_CLOSE_SOURCE_TRANSACTION_LINK_SCHEMA, alias="schema")
    source_ref: OpaqueRef
    source_type: Literal["invoice", "bill", "credit_note", "prepayment", "overpayment"]


class XeroCloseSourceTransaction(_StrictModel):
    schema_id: Literal["lightbulb.finance_xero_close_source_transaction.v1"] = Field(
        default=XERO_CLOSE_SOURCE_TRANSACTION_SCHEMA,
        alias="schema",
    )
    provider: Literal["xero"] = "xero"
    transaction_type: TransactionType
    source_ref: OpaqueRef
    source_revision_kind: Literal["content_sha256"] = "content_sha256"
    source_revision: Sha256Digest
    transaction_date: str
    source_updated_at: str
    source_status: str = Field(min_length=1, max_length=50)
    document_number: str | None = Field(default=None, max_length=100)
    counterparty_ref: OpaqueRef | None = None
    counterparty_name: str | None = Field(default=None, max_length=500)
    currency: CurrencyCode
    total_amount: ExactDecimal
    open_balance: ExactDecimal | None = None
    links: tuple[XeroCloseSourceTransactionLink, ...] = Field(
        default=(), max_length=1
    )
    source_digest: Sha256Digest = _ZERO_DIGEST

    @field_validator("transaction_date")
    @classmethod
    def _date(cls, value: str) -> str:
        parsed = date.fromisoformat(value)
        if parsed.isoformat() != value:
            raise ValueError("transaction_date must use YYYY-MM-DD")
        return value

    @field_validator("source_updated_at")
    @classmethod
    def _updated_at(cls, value: str) -> str:
        return _utc_timestamp(value, field_name="source_updated_at")

    @field_validator("source_status", "document_number", "counterparty_name")
    @classmethod
    def _bounded_text(cls, value: str | None, info: Any) -> str | None:
        if value is None:
            return None
        if not value or value != value.strip() or any(ord(char) < 32 for char in value):
            raise ValueError(f"{info.field_name} must be bounded visible text")
        return value

    @field_validator("links", mode="before")
    @classmethod
    def _links_tuple(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_serializer("total_amount", "open_balance")
    def _serialize_money(self, value: Decimal | None) -> str | None:
        return None if value is None else _canonical_money(value)

    @model_validator(mode="after")
    def _sealed(self) -> "XeroCloseSourceTransaction":
        if self.transaction_type in {"invoice", "bill"}:
            if self.open_balance is None or self.links:
                raise ValueError("Xero invoices and bills require a balance and no links")
        elif self.open_balance is not None or len(self.links) != 1:
            raise ValueError("Xero payments require one link and no open balance")
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"source_digest"},
            exclude_none=True,
        )
        expected = _stable_digest(payload)
        if self.source_digest not in {_ZERO_DIGEST, expected}:
            raise ValueError("source_digest does not match the canonical transaction")
        object.__setattr__(self, "source_digest", expected)
        return self


class XeroCloseSourcePageCheckpoint(_StrictModel):
    schema_id: Literal[
        "lightbulb.finance_xero_close_source_page_checkpoint.v1"
    ] = Field(default=XERO_CLOSE_SOURCE_PAGE_CHECKPOINT_SCHEMA, alias="schema")
    tool: Literal[
        "xero.list_invoices",
        "xero.list_bills",
        "xero.list_payments",
    ]
    tool_version: Literal[2] = XERO_CLOSE_SOURCE_TOOL_VERSION
    transaction_type: TransactionType
    page: ExactInteger = Field(ge=1, le=_MAX_PAGES_PER_TYPE)
    record_count: ExactInteger = Field(ge=0, le=_PAGE_SIZE)
    provider_page_count: ExactInteger = Field(ge=0, le=_MAX_PAGES_PER_TYPE)
    provider_item_count: ExactInteger = Field(ge=0, le=_MAX_TRANSACTIONS_PER_TYPE)
    terminal: bool
    provider_observed_at: str
    page_digest: Sha256Digest
    provenance_receipt_digest: Sha256Digest
    execution_journal_ref: OpaqueRef
    completed_at: str

    @field_validator("provider_observed_at", "completed_at")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _utc_timestamp(value, field_name=info.field_name)

    @model_validator(mode="after")
    def _provider_time_precedes_completion(self) -> "XeroCloseSourcePageCheckpoint":
        if _parsed_timestamp(self.provider_observed_at) > _parsed_timestamp(
            self.completed_at
        ):
            raise ValueError("provider observation cannot follow execution completion")
        return self


class XeroCloseSourceTransactionResult(_StrictModel):
    schema_id: Literal[
        "lightbulb.finance_xero_close_source_transaction_result.v1"
    ] = Field(default=XERO_CLOSE_SOURCE_TRANSACTION_RESULT_SCHEMA, alias="schema")
    provider: Literal["xero"] = "xero"
    tool_version: Literal[2] = XERO_CLOSE_SOURCE_TOOL_VERSION
    project_id: UUID
    tenant_connector_id: UUID
    connector_account_ref: OpaqueRef
    route_digest: Sha256Digest
    start_date: str
    end_date: str
    currency: CurrencyCode
    transactions: tuple[XeroCloseSourceTransaction, ...] = Field(
        max_length=_MAX_TRANSACTIONS
    )
    transaction_count: ExactInteger = Field(ge=0, le=_MAX_TRANSACTIONS)
    invoice_count: ExactInteger = Field(ge=0, le=_MAX_TRANSACTIONS_PER_TYPE)
    bill_count: ExactInteger = Field(ge=0, le=_MAX_TRANSACTIONS_PER_TYPE)
    payment_count: ExactInteger = Field(ge=0, le=_MAX_TRANSACTIONS_PER_TYPE)
    checkpoints: tuple[XeroCloseSourcePageCheckpoint, ...] = Field(
        min_length=3, max_length=_MAX_PAGE_READS
    )
    observed_at: str
    freshness: Literal["bounded_observation"] = "bounded_observation"
    classification: Literal["restricted"] = "restricted"
    retention_requirement: Literal["spring_financial_evidence_policy"] = (
        "spring_financial_evidence_policy"
    )
    complete: Literal[True] = True
    authoritative_read: Literal[True] = True
    reconciliation_authority: Literal[False] = False
    close_authority: Literal[False] = False
    source_digest: Sha256Digest = _ZERO_DIGEST

    @field_validator("transactions", "checkpoints", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("observed_at")
    @classmethod
    def _observed_at(cls, value: str) -> str:
        return _utc_timestamp(value, field_name="observed_at")

    @model_validator(mode="after")
    def _complete_and_sealed(self) -> "XeroCloseSourceTransactionResult":
        start, end = _parse_complete_month(self.start_date, self.end_date)
        if self.transaction_count != len(self.transactions):
            raise ValueError("transaction_count must match transactions")
        counts = {
            kind: sum(item.transaction_type == kind for item in self.transactions)
            for kind in _TRANSACTION_TYPES
        }
        if (
            self.invoice_count != counts["invoice"]
            or self.bill_count != counts["bill"]
            or self.payment_count != counts["payment"]
        ):
            raise ValueError("transaction type counts must match transactions")
        identities = [
            (item.transaction_type, item.source_ref) for item in self.transactions
        ]
        if len(identities) != len(set(identities)):
            raise ValueError("source transaction identities must be unique")
        if any(item.currency != self.currency for item in self.transactions):
            raise ValueError("all source transactions must use the requested currency")
        if any(
            not start <= date.fromisoformat(item.transaction_date) <= end
            for item in self.transactions
        ):
            raise ValueError("all source transactions must be inside the requested month")

        expected_tools = {tool for tool, _kind in _SOURCE_SPECS}
        if {checkpoint.tool for checkpoint in self.checkpoints} != expected_tools:
            raise ValueError("all three Xero source Tools require checkpoint evidence")
        for tool, kind in _SOURCE_SPECS:
            pages = [item for item in self.checkpoints if item.tool == tool]
            if not pages:
                raise ValueError(f"{tool} requires page evidence")
            page_count = pages[0].provider_page_count
            item_count = pages[0].provider_item_count
            expected_reads = max(page_count, 1)
            if len(pages) != expected_reads:
                raise ValueError("Xero checkpoints do not prove every provider page")
            if [item.page for item in pages] != list(range(1, expected_reads + 1)):
                raise ValueError("Xero source pages must be contiguous")
            if any(
                item.transaction_type != kind
                or item.provider_page_count != page_count
                or item.provider_item_count != item_count
                for item in pages
            ):
                raise ValueError("Xero pagination metadata or transaction type drifted")
            if any(item.terminal for item in pages[:-1]) or not pages[-1].terminal:
                raise ValueError("only the final Xero provider page may be terminal")
            if sum(item.record_count for item in pages) != item_count:
                raise ValueError("Xero page record counts do not match provider itemCount")
            if page_count == 0 and (item_count != 0 or pages[0].record_count != 0):
                raise ValueError("an empty Xero population requires an empty page one")

        receipts = [item.provenance_receipt_digest for item in self.checkpoints]
        journals = [item.execution_journal_ref for item in self.checkpoints]
        if len(receipts) != len(set(receipts)) or len(journals) != len(set(journals)):
            raise ValueError("every Xero source page requires distinct Spring provenance")
        completed = [_parsed_timestamp(item.completed_at) for item in self.checkpoints]
        provider_times = [
            _parsed_timestamp(item.provider_observed_at) for item in self.checkpoints
        ]
        if completed != sorted(completed) or provider_times != sorted(provider_times):
            raise ValueError("Xero source observation times cannot move backwards")
        if self.observed_at != self.checkpoints[-1].completed_at:
            raise ValueError("observed_at must match the final source page")
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"source_digest"},
            exclude_none=True,
        )
        expected = _stable_digest(payload)
        if self.source_digest not in {_ZERO_DIGEST, expected}:
            raise ValueError("source_digest does not match the complete Xero observation")
        object.__setattr__(self, "source_digest", expected)
        return self


class _XeroCloseSourceError(Exception):
    def __init__(self, code: str, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable


def _read_spec(tool: str, kind: str, page: int) -> PrimitiveOperationSpec:
    return PrimitiveOperationSpec(
        operation_ref=f"xero-close-source.{kind}.read-page-{page}",
        tool=tool,
        effect=ConnectorEffect.READ,
        approval_required=False,
        replay_class=PrimitiveOperationReplayClass.SAFE,
        freshness_class=PrimitiveOperationFreshnessClass.CURRENT,
        recovery_policy=PrimitiveOperationRecoveryPolicy.RETRY,
    )


def _exact_int(
    value: Any,
    *,
    field_name: str,
    minimum: int = 0,
    maximum: int,
) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < minimum
        or value > maximum
    ):
        raise _XeroCloseSourceError(
            "xero_close_source_response_invalid",
            f"Xero {field_name} must be an exact bounded integer.",
        )
    return value


def _normalize_transaction(
    raw: Any,
    *,
    kind: str,
    start: date,
    end: date,
    currency: str,
) -> XeroCloseSourceTransaction:
    required = {
        "provider",
        "transaction_type",
        "source_ref",
        "source_revision_kind",
        "source_revision",
        "transaction_date",
        "source_updated_at",
        "source_status",
        "currency",
        "total_amount",
        "links",
    }
    optional = {"document_number", "counterparty_ref", "counterparty_name"}
    if kind in {"invoice", "bill"}:
        required.add("open_balance")
    if not isinstance(raw, Mapping) or not required <= set(raw) <= required | optional:
        raise _XeroCloseSourceError(
            "xero_close_source_response_invalid",
            "A Xero source transaction has an unexpected canonical shape.",
        )
    revision = raw.get("source_revision")
    revision_payload = dict(raw)
    revision_payload.pop("source_revision")
    if not isinstance(revision, str) or revision != _stable_digest(revision_payload):
        raise _XeroCloseSourceError(
            "xero_close_source_revision_mismatch",
            "A Xero source revision does not match its canonical provider projection.",
        )
    try:
        transaction = XeroCloseSourceTransaction.model_validate(dict(raw))
    except Exception as exc:
        raise _XeroCloseSourceError(
            "xero_close_source_response_invalid",
            "A Xero source transaction failed canonical validation.",
        ) from exc
    parsed_date = date.fromisoformat(transaction.transaction_date)
    if transaction.transaction_type != kind or not start <= parsed_date <= end:
        raise _XeroCloseSourceError(
            "xero_close_source_scope_mismatch",
            "A Xero source transaction escaped the requested type or month.",
        )
    if transaction.currency != currency:
        raise _XeroCloseSourceError(
            "xero_close_source_currency_mismatch",
            "A Xero source transaction uses another currency.",
        )
    return transaction


def _normalize_page(
    raw: Any,
    *,
    kind: str,
    requested_page: int,
    start: date,
    end: date,
    currency: str,
) -> tuple[
    tuple[XeroCloseSourceTransaction, ...],
    int,
    int,
    str,
    str,
]:
    expected_keys = {
        "schema",
        "provider",
        "transaction_type",
        "page",
        "page_size",
        "provider_observed_at",
        "pagination",
        "records",
    }
    if not isinstance(raw, Mapping) or set(raw) != expected_keys:
        raise _XeroCloseSourceError(
            "xero_close_source_response_invalid",
            "Xero returned an unexpected source-page envelope.",
        )
    if (
        raw.get("schema") != XERO_CLOSE_SOURCE_PAGE_SCHEMA
        or raw.get("provider") != "xero"
        or raw.get("transaction_type") != kind
        or raw.get("page") != requested_page
        or raw.get("page_size") != _PAGE_SIZE
    ):
        raise _XeroCloseSourceError(
            "xero_close_source_cursor_drift",
            "Xero source-page identity drifted from the fixed request.",
        )
    pagination = raw.get("pagination")
    if not isinstance(pagination, Mapping) or set(pagination) != {
        "page",
        "page_size",
        "page_count",
        "item_count",
    }:
        raise _XeroCloseSourceError(
            "xero_close_source_response_invalid",
            "Xero pagination metadata has an unexpected shape.",
        )
    page = _exact_int(
        pagination.get("page"),
        field_name="pagination.page",
        minimum=1,
        maximum=_MAX_PAGES_PER_TYPE,
    )
    page_size = _exact_int(
        pagination.get("page_size"),
        field_name="pagination.page_size",
        minimum=_PAGE_SIZE,
        maximum=_PAGE_SIZE,
    )
    page_count = _exact_int(
        pagination.get("page_count"),
        field_name="pagination.page_count",
        maximum=_MAX_PAGES_PER_TYPE,
    )
    item_count = _exact_int(
        pagination.get("item_count"),
        field_name="pagination.item_count",
        maximum=_MAX_TRANSACTIONS_PER_TYPE,
    )
    rows = raw.get("records")
    if (
        page != requested_page
        or page_size != _PAGE_SIZE
        or not isinstance(rows, list)
        or len(rows) > _PAGE_SIZE
    ):
        raise _XeroCloseSourceError(
            "xero_close_source_cursor_drift",
            "Xero pagination did not match the requested page.",
        )
    if page_count == 0:
        if requested_page != 1 or item_count != 0 or rows:
            raise _XeroCloseSourceError(
                "xero_close_source_page_count_drift",
                "Xero empty-population pagination is contradictory.",
            )
    else:
        expected_page_count = (item_count + _PAGE_SIZE - 1) // _PAGE_SIZE
        expected_records = (
            _PAGE_SIZE
            if requested_page < page_count
            else item_count - (_PAGE_SIZE * (page_count - 1))
        )
        if (
            page_count != expected_page_count
            or requested_page > page_count
            or expected_records < 1
            or len(rows) != expected_records
        ):
            raise _XeroCloseSourceError(
                "xero_close_source_page_count_drift",
                "Xero pagination counts do not prove a complete population.",
            )
    try:
        provider_observed_at = _utc_timestamp(
            raw.get("provider_observed_at"),
            field_name="provider_observed_at",
        )
    except (TypeError, ValueError) as exc:
        raise _XeroCloseSourceError(
            "xero_close_source_response_invalid",
            "Xero provider observation time is invalid.",
        ) from exc
    transactions = tuple(
        _normalize_transaction(
            row,
            kind=kind,
            start=start,
            end=end,
            currency=currency,
        )
        for row in rows
    )
    identities = [item.source_ref for item in transactions]
    if len(identities) != len(set(identities)):
        raise _XeroCloseSourceError(
            "xero_close_source_page_overlap",
            "A Xero source page contains duplicate identities.",
        )
    return (
        transactions,
        page_count,
        item_count,
        provider_observed_at,
        _stable_digest(raw),
    )


def _validate_provenance(
    provenance: ConnectorExecutionProvenance | None,
    request: ConnectorExecutionRequest,
) -> ConnectorExecutionProvenance:
    if provenance is None:
        raise _XeroCloseSourceError(
            "xero_close_source_provenance_missing",
            "The governed Xero source page has no Spring provenance.",
        )
    if (
        provenance.tool != request.tool
        or provenance.tool_version != XERO_CLOSE_SOURCE_TOOL_VERSION
        or provenance.server_effect != ConnectorEffect.READ
        or provenance.connector_account_ref != request.connector_account_ref
        or request.scope.project_id is None
        or provenance.project_id != request.scope.project_id
        or provenance.request_digest != request.custody_fingerprint()
        or provenance.approval_ref is not None
        or provenance.approval_receipt_digest is not None
    ):
        raise _XeroCloseSourceError(
            "xero_close_source_provenance_mismatch",
            "Spring provenance does not match this exact Xero source-page request.",
        )
    return provenance


def _receipt(
    *,
    tool: str,
    kind: str,
    page: int,
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
        spec=_read_spec(tool, kind, page),
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


class DiscoverXeroCloseSourceTransactionsPrimitive(
    BusinessProcessPrimitive[
        XeroCloseSourceTransactionInput,
        XeroCloseSourceTransactionResult,
    ]
):
    primitive_ref = "finance.discover_xero_close_source_transactions"
    version = "1.0.0"
    title = "Discover governed Xero monthly close source transactions"
    description = (
        "Read every Xero sales invoice, purchase bill, and payment for one complete "
        "month through exact governed routes and seal canonical revision evidence."
    )
    input_model = XeroCloseSourceTransactionInput
    output_model = XeroCloseSourceTransactionResult
    connector_tools = tuple(tool for tool, _kind in _SOURCE_SPECS)
    risk_level = "low"
    approval_required = False
    example_inputs = {
        "provider": "xero",
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
        inputs: XeroCloseSourceTransactionInput,
    ) -> PrimitiveExecutionResult[XeroCloseSourceTransactionResult]:
        start, end = _parse_complete_month(inputs.start_date, inputs.end_date)
        if context.preview_only:
            receipts = [
                PrimitiveOperationReceipt(
                    spec=_read_spec(tool, kind, 1),
                    status=PrimitiveOperationStatus.PLANNED,
                    request_digest=_stable_digest(
                        {
                            "schema": "lightbulb.finance_xero_close_source_plan.v1",
                            "tool": tool,
                            "arguments": {
                                "start_date": inputs.start_date,
                                "end_date": inputs.end_date,
                                "page": 1,
                            },
                            "currency": inputs.currency,
                            "requires_project_id": True,
                            "requires_connector_account_ref": True,
                        }
                    ),
                )
                for tool, kind in _SOURCE_SPECS
            ]
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.PREVIEW,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary=(
                    "Xero invoice, bill, and payment discovery previewed; no "
                    "connector read was requested and no evidence was fabricated."
                ),
                operation_receipts=receipts,
            )

        account_refs = {
            context.connector_account_refs.get(tool)
            or context.connector_account_refs.get("xero")
            for tool, _kind in _SOURCE_SPECS
        }
        if (
            context.scope.project_id is None
            or None in account_refs
            or len(account_refs) != 1
            or not str(next(iter(account_refs)) or "").strip()
        ):
            blocker = PrimitiveBlocker(
                code="xero_close_source_scope_required",
                message=(
                    "Governed Xero close-source discovery requires one authenticated "
                    "project and the same exact organisation for all three Tools."
                ),
            )
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.BLOCKED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary=blocker.message,
                blockers=[blocker],
            )
        account_ref = str(next(iter(account_refs)))

        receipts: list[PrimitiveOperationReceipt] = []
        transactions: list[XeroCloseSourceTransaction] = []
        checkpoints: list[XeroCloseSourcePageCheckpoint] = []
        seen: set[tuple[str, str]] = set()
        journal_refs: set[str] = set()
        expected_route: tuple[UUID, str, str] | None = None
        previous_completed_at: str | None = None
        previous_provider_observed_at: str | None = None

        for tool, kind in _SOURCE_SPECS:
            expected_pagination: tuple[int, int] | None = None
            for page in range(1, _MAX_PAGES_PER_TYPE + 1):
                spec = _read_spec(tool, kind, page)
                arguments = {
                    "start_date": inputs.start_date,
                    "end_date": inputs.end_date,
                    "page": page,
                }
                request = context.connector_request(
                    primitive_ref=self.primitive_ref,
                    tool=tool,
                    arguments=arguments,
                    effect=ConnectorEffect.READ,
                    approval_required=False,
                    operation_ref=spec.operation_ref,
                    connector_account_ref=account_ref,
                    metadata={
                        "source": self.primitive_ref,
                        "transaction_type": kind,
                        "page": page,
                    },
                )
                result = context.connectors.execute(request)
                if result.tool != request.tool:
                    blocker = PrimitiveBlocker(
                        code="xero_close_source_tool_mismatch",
                        message="The connector result is not bound to the requested Tool.",
                    )
                    receipts.append(
                        _receipt(
                            tool=tool,
                            kind=kind,
                            page=page,
                            request=request,
                            result=result,
                            blocker=blocker,
                            force_failed=True,
                        )
                    )
                    return self._failed(blocker, receipts)
                if result.status != ConnectorExecutionStatus.COMPLETED:
                    blocker = PrimitiveBlocker(
                        code="xero_close_source_read_failed",
                        message="A governed Xero source page did not complete.",
                        retryable=result.retryable,
                    )
                    receipts.append(
                        _receipt(
                            tool=tool,
                            kind=kind,
                            page=page,
                            request=request,
                            result=result,
                            blocker=blocker,
                        )
                    )
                    status = (
                        PrimitiveExecutionStatus.BLOCKED
                        if result.status
                        in {
                            ConnectorExecutionStatus.BLOCKED,
                            ConnectorExecutionStatus.PENDING_APPROVAL,
                        }
                        else PrimitiveExecutionStatus.FAILED
                    )
                    return PrimitiveExecutionResult(
                        status=status,
                        primitive_ref=self.primitive_ref,
                        primitive_version=self.version,
                        summary=blocker.message,
                        blockers=[blocker],
                        operation_receipts=receipts,
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
                        raise _XeroCloseSourceError(
                            "xero_close_source_route_drift",
                            "Xero source pagination changed its exact Spring route.",
                        )
                    if provenance.journal_ref in journal_refs:
                        raise _XeroCloseSourceError(
                            "xero_close_source_provenance_reused",
                            "Xero source pages reused an execution journal reference.",
                        )
                    if previous_completed_at is not None and _parsed_timestamp(
                        provenance.completed_at
                    ) < _parsed_timestamp(previous_completed_at):
                        raise _XeroCloseSourceError(
                            "xero_close_source_observation_time_invalid",
                            "Xero source execution times moved backwards.",
                        )
                    (
                        page_transactions,
                        provider_page_count,
                        provider_item_count,
                        provider_observed_at,
                        page_digest,
                    ) = _normalize_page(
                        result.output,
                        kind=kind,
                        requested_page=page,
                        start=start,
                        end=end,
                        currency=inputs.currency,
                    )
                    pagination = (provider_page_count, provider_item_count)
                    if expected_pagination is None:
                        expected_pagination = pagination
                    elif pagination != expected_pagination:
                        raise _XeroCloseSourceError(
                            "xero_close_source_page_count_drift",
                            "Xero pagination metadata changed between pages.",
                        )
                    if previous_provider_observed_at is not None and _parsed_timestamp(
                        provider_observed_at
                    ) < _parsed_timestamp(previous_provider_observed_at):
                        raise _XeroCloseSourceError(
                            "xero_close_source_observation_time_invalid",
                            "Xero provider observation times moved backwards.",
                        )
                    page_keys = {
                        (item.transaction_type, item.source_ref)
                        for item in page_transactions
                    }
                    if page_keys & seen:
                        raise _XeroCloseSourceError(
                            "xero_close_source_page_overlap",
                            "Xero source pages overlap transaction identities.",
                        )
                    if len(transactions) + len(page_transactions) > _MAX_TRANSACTIONS:
                        raise _XeroCloseSourceError(
                            "xero_close_source_record_limit_exceeded",
                            "The monthly Xero observation exceeds 30,000 records.",
                        )
                except _XeroCloseSourceError as exc:
                    blocker = PrimitiveBlocker(
                        code=exc.code,
                        message=exc.message,
                        retryable=exc.retryable,
                    )
                    receipts.append(
                        _receipt(
                            tool=tool,
                            kind=kind,
                            page=page,
                            request=request,
                            result=result,
                            blocker=blocker,
                            provenance_valid=provenance is not None,
                            force_failed=True,
                        )
                    )
                    return self._failed(blocker, receipts)

                assert provenance is not None
                terminal = page == max(provider_page_count, 1)
                receipts.append(
                    _receipt(
                        tool=tool,
                        kind=kind,
                        page=page,
                        request=request,
                        result=result,
                        provenance_valid=True,
                    )
                )
                checkpoints.append(
                    XeroCloseSourcePageCheckpoint(
                        tool=tool,
                        transaction_type=kind,
                        page=page,
                        record_count=len(page_transactions),
                        provider_page_count=provider_page_count,
                        provider_item_count=provider_item_count,
                        terminal=terminal,
                        provider_observed_at=provider_observed_at,
                        page_digest=page_digest,
                        provenance_receipt_digest=provenance.receipt_digest,
                        execution_journal_ref=provenance.journal_ref,
                        completed_at=provenance.completed_at,
                    )
                )
                journal_refs.add(provenance.journal_ref)
                seen.update(page_keys)
                transactions.extend(page_transactions)
                previous_completed_at = provenance.completed_at
                previous_provider_observed_at = provider_observed_at
                if terminal:
                    break
            else:  # pragma: no cover - page-count validation terminates by page 100
                raise AssertionError("bounded Xero pagination did not terminate")

        assert expected_route is not None
        ordered = tuple(
            sorted(
                transactions,
                key=lambda item: (
                    item.transaction_type,
                    item.transaction_date,
                    item.source_ref,
                ),
            )
        )
        output = XeroCloseSourceTransactionResult(
            project_id=context.scope.project_id,
            tenant_connector_id=expected_route[0],
            connector_account_ref=expected_route[1],
            route_digest=expected_route[2],
            start_date=inputs.start_date,
            end_date=inputs.end_date,
            currency=inputs.currency,
            transactions=ordered,
            transaction_count=len(ordered),
            invoice_count=sum(item.transaction_type == "invoice" for item in ordered),
            bill_count=sum(item.transaction_type == "bill" for item in ordered),
            payment_count=sum(item.transaction_type == "payment" for item in ordered),
            checkpoints=tuple(checkpoints),
            observed_at=checkpoints[-1].completed_at,
        )
        return PrimitiveExecutionResult(
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                f"Discovered {output.invoice_count} Xero invoices, "
                f"{output.bill_count} bills, and {output.payment_count} payments "
                "for one complete month."
            ),
            output=output,
            events=[
                PrimitiveEvent(
                    type="finance.xero_close_source_transactions_discovered",
                    payload={
                        "provider": output.provider,
                        "start_date": output.start_date,
                        "end_date": output.end_date,
                        "currency": output.currency,
                        "transaction_count": output.transaction_count,
                        "source_digest": output.source_digest,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="governed_close_source_transaction_observation",
                    summary=(
                        "Complete bounded monthly Xero invoice, bill, and payment "
                        "evidence was read with exact Spring provenance."
                    ),
                    labels=[
                        "xero",
                        "authoritative_read",
                        "complete",
                        "monthly",
                        "source_revisions",
                        "close_not_advanced",
                    ],
                    refs={"source_digest": output.source_digest},
                )
            ],
            operation_receipts=receipts,
        )

    def _failed(
        self,
        blocker: PrimitiveBlocker,
        receipts: list[PrimitiveOperationReceipt],
    ) -> PrimitiveExecutionResult[XeroCloseSourceTransactionResult]:
        return PrimitiveExecutionResult(
            status=PrimitiveExecutionStatus.FAILED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=blocker.message,
            blockers=[blocker],
            operation_receipts=receipts,
            retryable=blocker.retryable,
        )


FINANCE_XERO_CLOSE_SOURCE_TRANSACTION_EXECUTABLE_PRIMITIVES: tuple[
    BusinessProcessPrimitive[Any, Any], ...
] = (DiscoverXeroCloseSourceTransactionsPrimitive(),)


__all__ = [
    "DiscoverXeroCloseSourceTransactionsPrimitive",
    "FINANCE_XERO_CLOSE_SOURCE_TRANSACTION_EXECUTABLE_PRIMITIVES",
    "XERO_CLOSE_SOURCE_PAGE_CHECKPOINT_SCHEMA",
    "XERO_CLOSE_SOURCE_PAGE_SCHEMA",
    "XERO_CLOSE_SOURCE_TOOL_VERSION",
    "XERO_CLOSE_SOURCE_TRANSACTION_INPUT_SCHEMA",
    "XERO_CLOSE_SOURCE_TRANSACTION_LINK_SCHEMA",
    "XERO_CLOSE_SOURCE_TRANSACTION_RESULT_SCHEMA",
    "XERO_CLOSE_SOURCE_TRANSACTION_SCHEMA",
    "XERO_LIST_BILLS_TOOL",
    "XERO_LIST_INVOICES_TOOL",
    "XERO_LIST_PAYMENTS_TOOL",
    "XeroCloseSourcePageCheckpoint",
    "XeroCloseSourceTransaction",
    "XeroCloseSourceTransactionInput",
    "XeroCloseSourceTransactionLink",
    "XeroCloseSourceTransactionResult",
]
