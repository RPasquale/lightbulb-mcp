"""Governed monthly accounting source transactions for the close lighthouse.

The primitive reads every QuickBooks Invoice, Bill, and Payment in one complete
calendar month through three reviewed Tool-v2 routes. Spring owns authenticated
scope, exact connector-account and credential custody, dispatch, durable audit,
certification, and production enablement. The SDK owns bounded pagination,
typed normalization, source-revision evidence, and deterministic sealing.

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
from decimal import Decimal, InvalidOperation
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

CLOSE_SOURCE_TRANSACTION_INPUT_SCHEMA = (
    "lightbulb.finance_close_source_transaction_input.v1"
)
CLOSE_SOURCE_TRANSACTION_SCHEMA = "lightbulb.finance_close_source_transaction.v1"
CLOSE_SOURCE_TRANSACTION_LINK_SCHEMA = (
    "lightbulb.finance_close_source_transaction_link.v1"
)
CLOSE_SOURCE_PAGE_CHECKPOINT_SCHEMA = (
    "lightbulb.finance_close_source_page_checkpoint.v1"
)
CLOSE_SOURCE_TRANSACTION_RESULT_SCHEMA = (
    "lightbulb.finance_close_source_transaction_result.v1"
)

QUICKBOOKS_LIST_INVOICES_TOOL = "quickbooks.list_invoices"
QUICKBOOKS_LIST_BILLS_TOOL = "quickbooks.list_bills"
QUICKBOOKS_LIST_PAYMENTS_TOOL = "quickbooks.list_payments"
QUICKBOOKS_CLOSE_SOURCE_TOOL_VERSION = 2

_SOURCE_SPECS: tuple[tuple[str, str, str], ...] = (
    (QUICKBOOKS_LIST_INVOICES_TOOL, "Invoice", "invoice"),
    (QUICKBOOKS_LIST_BILLS_TOOL, "Bill", "bill"),
    (QUICKBOOKS_LIST_PAYMENTS_TOOL, "Payment", "payment"),
)
_PAGE_SIZE = 1000
_MAX_DATA_PAGES_PER_TYPE = 100
_MAX_PAGE_READS_PER_TYPE = _MAX_DATA_PAGES_PER_TYPE + 1
_MAX_TRANSACTIONS_PER_TYPE = _PAGE_SIZE * _MAX_DATA_PAGES_PER_TYPE
_MAX_TRANSACTIONS = _MAX_TRANSACTIONS_PER_TYPE * len(_SOURCE_SPECS)
_MAX_PAGE_READS = _MAX_PAGE_READS_PER_TYPE * len(_SOURCE_SPECS)
_MAX_LINKS_PER_TRANSACTION = 5000
_MAX_LINES_PER_TRANSACTION = 5000
_MAX_MONEY_CHARS = 64
_ZERO_DIGEST = "0" * 64
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_CURRENCY_PATTERN = r"^[A-Z]{3}$"
_PORTABLE_REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@+\-]{0,199}$"
_SYNC_TOKEN_PATTERN = r"^[0-9]{1,20}$"
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
        raise ValueError("source-transaction dates must be exact ISO dates") from exc
    if start.isoformat() != start_date or end.isoformat() != end_date:
        raise ValueError("source-transaction dates must use YYYY-MM-DD")
    if start.day != 1 or (start.year, start.month) != (end.year, end.month):
        raise ValueError("source-transaction scope must be one complete month")
    if end.day != monthrange(end.year, end.month)[1]:
        raise ValueError("source-transaction scope must end on the month's final day")
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


def _money_string(value: Any, *, field_name: str) -> Decimal:
    if (
        not isinstance(value, str)
        or len(value) > _MAX_MONEY_CHARS
        or _MONEY_PATTERN.fullmatch(value) is None
    ):
        raise _CloseSourceError(
            "close_source_response_invalid",
            f"QuickBooks {field_name} is not a canonical decimal string.",
        )
    try:
        parsed = Decimal(value)
    except InvalidOperation as exc:  # pragma: no cover - regex guards syntax
        raise _CloseSourceError(
            "close_source_response_invalid",
            f"QuickBooks {field_name} is invalid.",
        ) from exc
    if not parsed.is_finite():
        raise _CloseSourceError(
            "close_source_response_invalid",
            f"QuickBooks {field_name} must be finite.",
        )
    return parsed


def _canonical_money(value: Decimal) -> str:
    rendered = format(value, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return "0" if rendered in {"-0", ""} else rendered


class CloseSourceTransactionInput(_StrictModel):
    schema_id: Literal["lightbulb.finance_close_source_transaction_input.v1"] = (
        Field(default=CLOSE_SOURCE_TRANSACTION_INPUT_SCHEMA, alias="schema")
    )
    provider: Literal["quickbooks"] = "quickbooks"
    start_date: str
    end_date: str
    currency: CurrencyCode

    @model_validator(mode="after")
    def _complete_month(self) -> "CloseSourceTransactionInput":
        _parse_complete_month(self.start_date, self.end_date)
        return self


class CloseSourceTransactionLink(_StrictModel):
    schema_id: Literal["lightbulb.finance_close_source_transaction_link.v1"] = Field(
        default=CLOSE_SOURCE_TRANSACTION_LINK_SCHEMA,
        alias="schema",
    )
    source_ref: OpaqueRef
    source_type: OpaqueRef


class CloseSourceTransaction(_StrictModel):
    schema_id: Literal["lightbulb.finance_close_source_transaction.v1"] = Field(
        default=CLOSE_SOURCE_TRANSACTION_SCHEMA,
        alias="schema",
    )
    provider: Literal["quickbooks"] = "quickbooks"
    transaction_type: TransactionType
    source_ref: OpaqueRef
    source_revision: str = Field(pattern=_SYNC_TOKEN_PATTERN)
    transaction_date: str
    source_updated_at: str
    document_number: str | None = Field(default=None, max_length=100)
    counterparty_ref: OpaqueRef | None = None
    counterparty_name: str | None = Field(default=None, max_length=500)
    currency: CurrencyCode
    total_amount: ExactDecimal
    open_balance: ExactDecimal | None = None
    links: tuple[CloseSourceTransactionLink, ...] = Field(
        default=(), max_length=_MAX_LINKS_PER_TRANSACTION
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

    @field_validator("document_number", "counterparty_name")
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
    def _sealed(self) -> "CloseSourceTransaction":
        if self.transaction_type in {"invoice", "bill"} and self.open_balance is None:
            raise ValueError("invoice and bill records require open_balance")
        if self.transaction_type == "payment" and self.open_balance is not None:
            raise ValueError("payment records cannot invent open_balance")
        link_keys = [(link.source_type, link.source_ref) for link in self.links]
        if len(link_keys) != len(set(link_keys)):
            raise ValueError("transaction links must be unique")
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


class CloseSourcePageCheckpoint(_StrictModel):
    schema_id: Literal["lightbulb.finance_close_source_page_checkpoint.v1"] = Field(
        default=CLOSE_SOURCE_PAGE_CHECKPOINT_SCHEMA,
        alias="schema",
    )
    tool: Literal[
        "quickbooks.list_invoices",
        "quickbooks.list_bills",
        "quickbooks.list_payments",
    ]
    tool_version: Literal[2] = QUICKBOOKS_CLOSE_SOURCE_TOOL_VERSION
    transaction_type: TransactionType
    start_position: ExactInteger = Field(ge=1)
    record_count: ExactInteger = Field(ge=0, le=_PAGE_SIZE)
    terminal: bool
    page_digest: Sha256Digest
    provenance_receipt_digest: Sha256Digest
    execution_journal_ref: OpaqueRef
    completed_at: str

    @field_validator("completed_at")
    @classmethod
    def _completed_at(cls, value: str) -> str:
        return _utc_timestamp(value, field_name="completed_at")


class CloseSourceTransactionResult(_StrictModel):
    schema_id: Literal["lightbulb.finance_close_source_transaction_result.v1"] = (
        Field(default=CLOSE_SOURCE_TRANSACTION_RESULT_SCHEMA, alias="schema")
    )
    provider: Literal["quickbooks"] = "quickbooks"
    tool_version: Literal[2] = QUICKBOOKS_CLOSE_SOURCE_TOOL_VERSION
    project_id: UUID
    tenant_connector_id: UUID
    connector_account_ref: OpaqueRef
    route_digest: Sha256Digest
    start_date: str
    end_date: str
    currency: CurrencyCode
    transactions: tuple[CloseSourceTransaction, ...] = Field(max_length=_MAX_TRANSACTIONS)
    transaction_count: ExactInteger = Field(ge=0, le=_MAX_TRANSACTIONS)
    invoice_count: ExactInteger = Field(ge=0, le=_MAX_TRANSACTIONS_PER_TYPE)
    bill_count: ExactInteger = Field(ge=0, le=_MAX_TRANSACTIONS_PER_TYPE)
    payment_count: ExactInteger = Field(ge=0, le=_MAX_TRANSACTIONS_PER_TYPE)
    checkpoints: tuple[CloseSourcePageCheckpoint, ...] = Field(
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
    def _complete_and_sealed(self) -> "CloseSourceTransactionResult":
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
        expected_tools = {item[0] for item in _SOURCE_SPECS}
        if {checkpoint.tool for checkpoint in self.checkpoints} != expected_tools:
            raise ValueError("all three source Tools require checkpoint evidence")
        for tool, _entity, kind in _SOURCE_SPECS:
            pages = [item for item in self.checkpoints if item.tool == tool]
            if not pages or pages[-1].terminal is not True:
                raise ValueError(f"{tool} requires an explicit terminal page")
            if any(item.transaction_type != kind for item in pages):
                raise ValueError("checkpoint transaction type drifted")
            expected_position = 1
            for page in pages:
                if page.start_position != expected_position:
                    raise ValueError("source cursor positions must be contiguous")
                if page.terminal and page.record_count != 0:
                    raise ValueError("terminal source pages must be empty")
                expected_position += page.record_count
        receipts = [item.provenance_receipt_digest for item in self.checkpoints]
        journals = [item.execution_journal_ref for item in self.checkpoints]
        if len(receipts) != len(set(receipts)) or len(journals) != len(set(journals)):
            raise ValueError("every source page requires distinct Spring provenance")
        completed = [_parsed_timestamp(item.completed_at) for item in self.checkpoints]
        if completed != sorted(completed):
            raise ValueError("source observation times cannot move backwards")
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
            raise ValueError("source_digest does not match the complete observation")
        object.__setattr__(self, "source_digest", expected)
        return self


class _CloseSourceError(Exception):
    def __init__(self, code: str, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable


def _read_spec(tool: str, kind: str, page_number: int) -> PrimitiveOperationSpec:
    return PrimitiveOperationSpec(
        operation_ref=f"qbo-close-source.{kind}.read-page-{page_number}",
        tool=tool,
        effect=ConnectorEffect.READ,
        approval_required=False,
        replay_class=PrimitiveOperationReplayClass.SAFE,
        freshness_class=PrimitiveOperationFreshnessClass.CURRENT,
        recovery_policy=PrimitiveOperationRecoveryPolicy.RETRY,
    )


def _text(
    value: Any,
    *,
    field_name: str,
    maximum: int,
    optional: bool = False,
) -> str | None:
    if value is None and optional:
        return None
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 for character in value)
    ):
        raise _CloseSourceError(
            "close_source_response_invalid",
            f"QuickBooks {field_name} is malformed.",
        )
    return value


def _reference(value: Any, *, field_name: str) -> str:
    result = _text(value, field_name=field_name, maximum=200)
    assert result is not None
    if re.fullmatch(_PORTABLE_REF_PATTERN, result) is None:
        raise _CloseSourceError(
            "close_source_response_invalid",
            f"QuickBooks {field_name} is malformed.",
        )
    return result


def _exact_int(value: Any, *, field_name: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise _CloseSourceError(
            "close_source_response_invalid",
            f"QuickBooks {field_name} must be an exact bounded integer.",
        )
    return value


def _optional_reference_object(
    value: Any,
    *,
    field_name: str,
) -> tuple[str | None, str | None]:
    if value is None:
        return None, None
    if not isinstance(value, Mapping) or not set(value).issubset({"value", "name"}):
        raise _CloseSourceError(
            "close_source_response_invalid",
            f"QuickBooks {field_name} is malformed.",
        )
    reference = _reference(value.get("value"), field_name=f"{field_name}.value")
    name = _text(
        value.get("name"),
        field_name=f"{field_name}.name",
        maximum=500,
        optional=True,
    )
    return reference, name


def _normalize_links(raw_lines: Any) -> tuple[CloseSourceTransactionLink, ...]:
    if raw_lines is None:
        return ()
    if not isinstance(raw_lines, list) or len(raw_lines) > _MAX_LINES_PER_TRANSACTION:
        raise _CloseSourceError(
            "close_source_response_invalid",
            "QuickBooks transaction lines are malformed or over the bound.",
        )
    links: dict[tuple[str, str], CloseSourceTransactionLink] = {}
    for line in raw_lines:
        if not isinstance(line, Mapping):
            raise _CloseSourceError(
                "close_source_response_invalid",
                "A QuickBooks transaction line is malformed.",
            )
        raw_links = line.get("LinkedTxn")
        if raw_links is None:
            continue
        if not isinstance(raw_links, list):
            raise _CloseSourceError(
                "close_source_response_invalid",
                "QuickBooks linked transactions are malformed.",
            )
        for raw_link in raw_links:
            if not isinstance(raw_link, Mapping):
                raise _CloseSourceError(
                    "close_source_response_invalid",
                    "A QuickBooks linked transaction is malformed.",
                )
            source_ref = _reference(
                raw_link.get("TxnId"), field_name="LinkedTxn.TxnId"
            )
            source_type = _reference(
                raw_link.get("TxnType"), field_name="LinkedTxn.TxnType"
            )
            links[(source_type, source_ref)] = CloseSourceTransactionLink(
                source_ref=source_ref,
                source_type=source_type,
            )
            if len(links) > _MAX_LINKS_PER_TRANSACTION:
                raise _CloseSourceError(
                    "close_source_response_invalid",
                    "QuickBooks linked transactions exceed the supported bound.",
                )
    return tuple(links[key] for key in sorted(links))


def _normalize_transaction(
    raw: Any,
    *,
    kind: str,
    start: date,
    end: date,
    currency: str,
) -> CloseSourceTransaction:
    if not isinstance(raw, Mapping):
        raise _CloseSourceError(
            "close_source_response_invalid",
            "A QuickBooks source transaction is not an object.",
        )
    source_ref = _reference(raw.get("Id"), field_name="Id")
    revision = _text(
        raw.get("SyncToken"), field_name="SyncToken", maximum=20
    )
    assert revision is not None
    if re.fullmatch(_SYNC_TOKEN_PATTERN, revision) is None:
        raise _CloseSourceError(
            "close_source_response_invalid",
            "QuickBooks SyncToken is malformed.",
        )
    transaction_date = _text(
        raw.get("TxnDate"), field_name="TxnDate", maximum=10
    )
    assert transaction_date is not None
    try:
        parsed_date = date.fromisoformat(transaction_date)
    except ValueError as exc:
        raise _CloseSourceError(
            "close_source_response_invalid",
            "QuickBooks TxnDate is invalid.",
        ) from exc
    if parsed_date.isoformat() != transaction_date or not start <= parsed_date <= end:
        raise _CloseSourceError(
            "close_source_scope_mismatch",
            "A QuickBooks source transaction falls outside the requested month.",
        )
    metadata = raw.get("MetaData")
    if not isinstance(metadata, Mapping):
        raise _CloseSourceError(
            "close_source_response_invalid",
            "QuickBooks MetaData is missing.",
        )
    updated_raw = _text(
        metadata.get("LastUpdatedTime"),
        field_name="MetaData.LastUpdatedTime",
        maximum=50,
    )
    assert updated_raw is not None
    try:
        updated_at = _utc_timestamp(
            updated_raw, field_name="MetaData.LastUpdatedTime"
        )
    except ValueError as exc:
        raise _CloseSourceError(
            "close_source_response_invalid",
            "QuickBooks LastUpdatedTime is invalid.",
        ) from exc
    currency_ref = raw.get("CurrencyRef")
    if currency_ref is not None:
        currency_value, _currency_name = _optional_reference_object(
            currency_ref, field_name="CurrencyRef"
        )
        if currency_value != currency:
            raise _CloseSourceError(
                "close_source_currency_mismatch",
                "A QuickBooks source transaction uses another currency.",
            )
    counterparty_field = "VendorRef" if kind == "bill" else "CustomerRef"
    counterparty_ref, counterparty_name = _optional_reference_object(
        raw.get(counterparty_field), field_name=counterparty_field
    )
    total_amount = _money_string(raw.get("TotalAmt"), field_name="TotalAmt")
    open_balance = None
    if kind in {"invoice", "bill"}:
        open_balance = _money_string(raw.get("Balance"), field_name="Balance")
    document_number = _text(
        raw.get("DocNumber"),
        field_name="DocNumber",
        maximum=100,
        optional=True,
    )
    try:
        return CloseSourceTransaction(
            transaction_type=kind,
            source_ref=source_ref,
            source_revision=revision,
            transaction_date=transaction_date,
            source_updated_at=updated_at,
            document_number=document_number,
            counterparty_ref=counterparty_ref,
            counterparty_name=counterparty_name,
            currency=currency,
            total_amount=total_amount,
            open_balance=open_balance,
            links=_normalize_links(raw.get("Line")),
        )
    except _CloseSourceError:
        raise
    except Exception as exc:
        raise _CloseSourceError(
            "close_source_response_invalid",
            "A QuickBooks source transaction failed canonical validation.",
        ) from exc


def _normalize_page(
    raw: Any,
    *,
    entity: str,
    kind: str,
    start_position: int,
    start: date,
    end: date,
    currency: str,
) -> tuple[tuple[CloseSourceTransaction, ...], str]:
    if not isinstance(raw, Mapping) or set(raw) != {"QueryResponse"}:
        raise _CloseSourceError(
            "close_source_response_invalid",
            "QuickBooks returned an unexpected source-page envelope.",
        )
    query_response = raw.get("QueryResponse")
    allowed = {entity, "startPosition", "maxResults", "totalCount"}
    if not isinstance(query_response, Mapping) or not set(query_response).issubset(allowed):
        raise _CloseSourceError(
            "close_source_response_invalid",
            "QuickBooks returned an unexpected QueryResponse shape.",
        )
    rows = query_response.get(entity)
    if not isinstance(rows, list) or len(rows) > _PAGE_SIZE:
        raise _CloseSourceError(
            "close_source_response_invalid",
            f"QuickBooks {entity} page exceeds the 1,000-record bound.",
        )
    if rows:
        if _exact_int(
            query_response.get("startPosition"), field_name="startPosition", minimum=1
        ) != start_position:
            raise _CloseSourceError(
                "close_source_cursor_drift",
                "QuickBooks changed the requested start position.",
            )
        if _exact_int(
            query_response.get("maxResults"), field_name="maxResults"
        ) != len(rows):
            raise _CloseSourceError(
                "close_source_page_count_drift",
                "QuickBooks maxResults does not match the returned page.",
            )
    else:
        if query_response.get("startPosition") is not None and _exact_int(
            query_response.get("startPosition"), field_name="startPosition", minimum=1
        ) != start_position:
            raise _CloseSourceError(
                "close_source_cursor_drift",
                "QuickBooks changed the terminal start position.",
            )
        if query_response.get("maxResults") is not None and _exact_int(
            query_response.get("maxResults"), field_name="maxResults"
        ) != 0:
            raise _CloseSourceError(
                "close_source_page_count_drift",
                "QuickBooks terminal maxResults must be zero.",
            )
    if query_response.get("totalCount") is not None:
        total_count = _exact_int(
            query_response.get("totalCount"), field_name="totalCount"
        )
        if total_count < start_position - 1 + len(rows):
            raise _CloseSourceError(
                "close_source_page_count_drift",
                "QuickBooks totalCount is inconsistent with this page.",
            )
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
        raise _CloseSourceError(
            "close_source_page_overlap",
            f"QuickBooks {entity} page contains duplicate identities.",
        )
    digest = _stable_digest(
        {
            "schema": "lightbulb.finance_close_source_page.v1",
            "entity": entity,
            "transaction_type": kind,
            "start_position": start_position,
            "records": [item.to_dict() for item in transactions],
        }
    )
    return transactions, digest


def _validate_provenance(
    provenance: ConnectorExecutionProvenance | None,
    request: ConnectorExecutionRequest,
) -> ConnectorExecutionProvenance:
    if provenance is None:
        raise _CloseSourceError(
            "close_source_provenance_missing",
            "The governed QuickBooks source page has no Spring provenance.",
        )
    if (
        provenance.tool != request.tool
        or provenance.tool_version != QUICKBOOKS_CLOSE_SOURCE_TOOL_VERSION
        or provenance.server_effect != ConnectorEffect.READ
        or provenance.connector_account_ref != request.connector_account_ref
        or request.scope.project_id is None
        or provenance.project_id != request.scope.project_id
        or provenance.request_digest != request.custody_fingerprint()
        or provenance.approval_ref is not None
        or provenance.approval_receipt_digest is not None
    ):
        raise _CloseSourceError(
            "close_source_provenance_mismatch",
            "Spring provenance does not match this exact source-page request.",
        )
    return provenance


def _receipt(
    *,
    tool: str,
    kind: str,
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
        spec=_read_spec(tool, kind, page_number),
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
            if status in {PrimitiveOperationStatus.BLOCKED, PrimitiveOperationStatus.FAILED}
            else None
        ),
    )


class DiscoverCloseSourceTransactionsPrimitive(
    BusinessProcessPrimitive[
        CloseSourceTransactionInput,
        CloseSourceTransactionResult,
    ]
):
    primitive_ref = "finance.discover_close_source_transactions"
    version = "1.0.0"
    title = "Discover governed monthly close source transactions"
    description = (
        "Read every QuickBooks invoice, bill, and payment for one complete month "
        "through exact governed routes and seal canonical revisions and evidence."
    )
    input_model = CloseSourceTransactionInput
    output_model = CloseSourceTransactionResult
    connector_tools = tuple(item[0] for item in _SOURCE_SPECS)
    risk_level = "low"
    approval_required = False
    example_inputs = {
        "provider": "quickbooks",
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
        inputs: CloseSourceTransactionInput,
    ) -> PrimitiveExecutionResult[CloseSourceTransactionResult]:
        start, end = _parse_complete_month(inputs.start_date, inputs.end_date)
        if context.preview_only:
            receipts = [
                PrimitiveOperationReceipt(
                    spec=_read_spec(tool, kind, 1),
                    status=PrimitiveOperationStatus.PLANNED,
                    request_digest=_stable_digest(
                        {
                            "schema": "lightbulb.finance_close_source_plan.v1",
                            "tool": tool,
                            "arguments": {
                                "start_date": inputs.start_date,
                                "end_date": inputs.end_date,
                                "start_position": 1,
                            },
                            "currency": inputs.currency,
                            "requires_project_id": True,
                            "requires_connector_account_ref": True,
                        }
                    ),
                )
                for tool, _entity, kind in _SOURCE_SPECS
            ]
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.PREVIEW,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary=(
                    "Monthly invoice, bill, and payment discovery previewed; no "
                    "connector read was requested and no evidence was fabricated."
                ),
                operation_receipts=receipts,
            )

        account_refs = {
            context.connector_account_refs.get(tool)
            or context.connector_account_refs.get("quickbooks")
            for tool, _entity, _kind in _SOURCE_SPECS
        }
        if (
            context.scope.project_id is None
            or None in account_refs
            or len(account_refs) != 1
            or not str(next(iter(account_refs)) or "").strip()
        ):
            blocker = PrimitiveBlocker(
                code="close_source_scope_required",
                message=(
                    "Governed close-source discovery requires one authenticated "
                    "project and the same exact QuickBooks account for all three Tools."
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
        transactions: list[CloseSourceTransaction] = []
        checkpoints: list[CloseSourcePageCheckpoint] = []
        seen: set[tuple[str, str]] = set()
        journal_refs: set[str] = set()
        expected_route: tuple[UUID, str, str] | None = None
        previous_completed_at: str | None = None

        for tool, entity, kind in _SOURCE_SPECS:
            start_position = 1
            for page_number in range(1, _MAX_PAGE_READS_PER_TYPE + 1):
                spec = _read_spec(tool, kind, page_number)
                arguments = {
                    "start_date": inputs.start_date,
                    "end_date": inputs.end_date,
                    "start_position": start_position,
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
                        "page_number": page_number,
                    },
                )
                result = context.connectors.execute(request)
                if result.tool != request.tool:
                    blocker = PrimitiveBlocker(
                        code="close_source_tool_mismatch",
                        message="The connector result is not bound to the requested Tool.",
                    )
                    receipts.append(
                        _receipt(
                            tool=tool,
                            kind=kind,
                            page_number=page_number,
                            request=request,
                            result=result,
                            blocker=blocker,
                            force_failed=True,
                        )
                    )
                    return self._failed(blocker, receipts)
                if result.status != ConnectorExecutionStatus.COMPLETED:
                    blocker = PrimitiveBlocker(
                        code="close_source_read_failed",
                        message="A governed QuickBooks source page did not complete.",
                        retryable=result.retryable,
                    )
                    receipts.append(
                        _receipt(
                            tool=tool,
                            kind=kind,
                            page_number=page_number,
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
                        raise _CloseSourceError(
                            "close_source_route_drift",
                            "QuickBooks source pagination changed its exact Spring route.",
                        )
                    if provenance.journal_ref in journal_refs:
                        raise _CloseSourceError(
                            "close_source_provenance_reused",
                            "QuickBooks source pages reused an execution journal reference.",
                        )
                    if previous_completed_at is not None and _parsed_timestamp(
                        provenance.completed_at
                    ) < _parsed_timestamp(previous_completed_at):
                        raise _CloseSourceError(
                            "close_source_observation_time_invalid",
                            "QuickBooks source observation times moved backwards.",
                        )
                    page, page_digest = _normalize_page(
                        result.output,
                        entity=entity,
                        kind=kind,
                        start_position=start_position,
                        start=start,
                        end=end,
                        currency=inputs.currency,
                    )
                    page_keys = {(item.transaction_type, item.source_ref) for item in page}
                    if page_keys & seen:
                        raise _CloseSourceError(
                            "close_source_page_overlap",
                            "QuickBooks source pages overlap transaction identities.",
                        )
                    if page and page_number > _MAX_DATA_PAGES_PER_TYPE:
                        raise _CloseSourceError(
                            "close_source_page_limit_exceeded",
                            f"QuickBooks {entity} pagination exceeds 100 data pages.",
                        )
                    if len(transactions) + len(page) > _MAX_TRANSACTIONS:
                        raise _CloseSourceError(
                            "close_source_record_limit_exceeded",
                            "The monthly source observation exceeds 300,000 records.",
                        )
                except _CloseSourceError as exc:
                    blocker = PrimitiveBlocker(
                        code=exc.code,
                        message=exc.message,
                        retryable=exc.retryable,
                    )
                    receipts.append(
                        _receipt(
                            tool=tool,
                            kind=kind,
                            page_number=page_number,
                            request=request,
                            result=result,
                            blocker=blocker,
                            provenance_valid=provenance is not None,
                            force_failed=True,
                        )
                    )
                    return self._failed(blocker, receipts)

                assert provenance is not None
                terminal = not page
                receipts.append(
                    _receipt(
                        tool=tool,
                        kind=kind,
                        page_number=page_number,
                        request=request,
                        result=result,
                        provenance_valid=True,
                    )
                )
                checkpoints.append(
                    CloseSourcePageCheckpoint(
                        tool=tool,
                        transaction_type=kind,
                        start_position=start_position,
                        record_count=len(page),
                        terminal=terminal,
                        page_digest=page_digest,
                        provenance_receipt_digest=provenance.receipt_digest,
                        execution_journal_ref=provenance.journal_ref,
                        completed_at=provenance.completed_at,
                    )
                )
                journal_refs.add(provenance.journal_ref)
                seen.update(page_keys)
                transactions.extend(page)
                previous_completed_at = provenance.completed_at
                if terminal:
                    break
                start_position += len(page)
            else:  # pragma: no cover - non-empty page 101 fails above
                raise AssertionError("bounded QuickBooks pagination did not terminate")

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
        output = CloseSourceTransactionResult(
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
                f"Discovered {output.invoice_count} invoices, {output.bill_count} "
                f"bills, and {output.payment_count} payments for one complete month."
            ),
            output=output,
            events=[
                PrimitiveEvent(
                    type="finance.close_source_transactions_discovered",
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
                        "Complete bounded monthly QuickBooks invoice, bill, and "
                        "payment evidence was read with exact Spring provenance."
                    ),
                    labels=[
                        "quickbooks",
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
    ) -> PrimitiveExecutionResult[CloseSourceTransactionResult]:
        return PrimitiveExecutionResult(
            status=PrimitiveExecutionStatus.FAILED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=blocker.message,
            blockers=[blocker],
            operation_receipts=receipts,
            retryable=blocker.retryable,
        )


FINANCE_CLOSE_SOURCE_TRANSACTION_EXECUTABLE_PRIMITIVES: tuple[
    BusinessProcessPrimitive[Any, Any], ...
] = (DiscoverCloseSourceTransactionsPrimitive(),)


__all__ = [
    "CLOSE_SOURCE_PAGE_CHECKPOINT_SCHEMA",
    "CLOSE_SOURCE_TRANSACTION_INPUT_SCHEMA",
    "CLOSE_SOURCE_TRANSACTION_LINK_SCHEMA",
    "CLOSE_SOURCE_TRANSACTION_RESULT_SCHEMA",
    "CLOSE_SOURCE_TRANSACTION_SCHEMA",
    "CloseSourcePageCheckpoint",
    "CloseSourceTransaction",
    "CloseSourceTransactionInput",
    "CloseSourceTransactionLink",
    "CloseSourceTransactionResult",
    "DiscoverCloseSourceTransactionsPrimitive",
    "FINANCE_CLOSE_SOURCE_TRANSACTION_EXECUTABLE_PRIMITIVES",
    "QUICKBOOKS_CLOSE_SOURCE_TOOL_VERSION",
    "QUICKBOOKS_LIST_BILLS_TOOL",
    "QUICKBOOKS_LIST_INVOICES_TOOL",
    "QUICKBOOKS_LIST_PAYMENTS_TOOL",
]
