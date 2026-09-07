"""Governed provider-neutral General Ledger activity normalization.

The primitive reads one complete calendar month through an exact
Spring-authorized QuickBooks or Xero route and converts provider rows into a
bounded canonical activity stream. QuickBooks supplies a bounded monthly
report. Xero supplies ordered journal pages, which must be read through an
empty terminal page before the requested month is filtered because journals
may be backdated. Spring remains authoritative for tenant, company, project,
connector account, credential, route, dispatch, durable evidence,
certification, and production enablement.

A completed result proves only that the returned provider evidence passed the
typed SDK contract with exact Spring provenance. It does not reconcile payment activity,
persist a canonical ledger, post an adjustment, or advance a period close.
"""

from __future__ import annotations

import hashlib
import json
import re
from calendar import monthrange
from collections.abc import Mapping
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import (
    AfterValidator,
    BaseModel,
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

GENERAL_LEDGER_ACTIVITY_INPUT_SCHEMA = (
    "lightbulb.finance_general_ledger_activity_input.v1"
)
GENERAL_LEDGER_ACTIVITY_LINE_SCHEMA = "lightbulb.general_ledger_activity_line.v1"
GENERAL_LEDGER_ACTIVITY_RESULT_SCHEMA = (
    "lightbulb.finance_general_ledger_activity_result.v1"
)
QUICKBOOKS_GENERAL_LEDGER_TOOL = "quickbooks.general_ledger_report"
QUICKBOOKS_GENERAL_LEDGER_TOOL_VERSION = 2
XERO_JOURNAL_TOOL = "xero.list_journals"
XERO_JOURNAL_TOOL_VERSION = 2

_MAX_ACTIVITY_LINES = 10_000
_MAX_REPORT_COLUMNS = 100
_MAX_REPORT_ROW_DEPTH = 4
_MAX_MONEY_CHARS = 64
_MAX_MEMO_CHARS = 4_000
_XERO_JOURNAL_PAGE_SIZE = 100
_MAX_XERO_JOURNALS = 10_000
_MAX_XERO_PAGE_READS = (_MAX_XERO_JOURNALS // _XERO_JOURNAL_PAGE_SIZE) + 1
_ZERO_DIGEST = "0" * 64
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_PORTABLE_REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@+\-]{0,199}$"
_TOOL_PATTERN = r"^[a-z][a-z0-9_-]{0,63}\.[a-z][a-z0-9_.-]{0,127}$"
_CURRENCY_PATTERN = r"^[A-Z]{3}$"
_SIGNED_MONEY_PATTERN = re.compile(
    r"^-?(?:0|[1-9][0-9]*|[1-9][0-9]{0,2}(?:,[0-9]{3})+)(?:\.[0-9]{1,9})?$"
)
_XERO_DOTNET_DATE_PATTERN = re.compile(
    r"^/Date\((?P<milliseconds>-?[0-9]{1,17})(?P<offset>[+-][0-9]{4})?\)/$"
)

_COLUMN_ROLE_ALIASES = {
    "txdate": "transaction_date",
    "date": "transaction_date",
    "txntype": "transaction_type",
    "transactiontype": "transaction_type",
    "docnum": "document_number",
    "documentnumber": "document_number",
    "num": "document_number",
    "name": "counterparty",
    "memo": "memo",
    "memodescription": "memo",
    "description": "memo",
    "splitacc": "split_account",
    "splitaccount": "split_account",
    "split": "split_account",
    "amount": "amount",
    "natamount": "amount",
    "subtamount": "amount",
    "subtnatamount": "amount",
    "rbal": "running_balance",
    "runningbalance": "running_balance",
    "balance": "running_balance",
}
_REQUIRED_COLUMN_ROLES = frozenset(
    {
        "transaction_date",
        "transaction_type",
        "document_number",
        "counterparty",
        "memo",
        "split_account",
        "amount",
        "running_balance",
    }
)


def _bounded_visible_ref(value: str) -> str:
    if value != value.strip() or any(ord(character) < 33 for character in value):
        raise ValueError("reference must contain visible characters without whitespace")
    return value


OpaqueRef = Annotated[
    str,
    StringConstraints(pattern=_PORTABLE_REF_PATTERN),
    AfterValidator(_bounded_visible_ref),
]
Sha256Digest = Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)]
CurrencyCode = Annotated[str, StringConstraints(pattern=_CURRENCY_PATTERN)]
ToolName = Annotated[str, StringConstraints(pattern=_TOOL_PATTERN)]
_LedgerProvider = Literal["quickbooks", "xero"]


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        serialize_by_alias=True,
        strict=True,
    )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def _stable_digest(value: Any) -> str:
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _text_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _parse_complete_month(start_date: str, end_date: str) -> tuple[date, date]:
    try:
        start = date.fromisoformat(start_date)
        end = date.fromisoformat(end_date)
    except ValueError as exc:
        raise ValueError(
            "General Ledger dates must be exact ISO calendar dates"
        ) from exc
    if start.isoformat() != start_date or end.isoformat() != end_date:
        raise ValueError("General Ledger dates must use YYYY-MM-DD")
    if start.day != 1 or (start.year, start.month) != (end.year, end.month):
        raise ValueError("General Ledger scope must be one complete calendar month")
    if end.day != monthrange(end.year, end.month)[1]:
        raise ValueError("General Ledger scope must end on the month's final day")
    return start, end


def _normalized_utc_timestamp(value: str, *, field_name: str) -> str:
    if not isinstance(value, str) or value != value.strip():
        raise ValueError(f"{field_name} must be a trimmed UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field_name} must be valid ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field_name} must include a UTC offset")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _bounded_text(
    value: Any,
    *,
    field_name: str,
    maximum: int,
    allow_empty: bool = False,
) -> str | None:
    if not isinstance(value, str):
        raise _GeneralLedgerError(
            "general_ledger_response_invalid",
            f"The provider General Ledger {field_name} is malformed.",
        )
    if value == "" and allow_empty:
        return None
    if (
        not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 for character in value)
    ):
        raise _GeneralLedgerError(
            "general_ledger_response_invalid",
            f"The provider General Ledger {field_name} is malformed.",
        )
    return value


def _optional_text(value: Any, *, field_name: str, maximum: int) -> str | None:
    if value in (None, ""):
        return None
    return _bounded_text(value, field_name=field_name, maximum=maximum)


def _exact_money(
    value: Any, *, field_name: str, optional: bool = False
) -> Decimal | None:
    if value in (None, "") and optional:
        return None
    if (
        not isinstance(value, str)
        or len(value) > _MAX_MONEY_CHARS
        or _SIGNED_MONEY_PATTERN.fullmatch(value) is None
    ):
        raise _GeneralLedgerError(
            "general_ledger_response_invalid",
            f"The provider General Ledger {field_name} is not a canonical decimal string.",
        )
    try:
        parsed = Decimal(value.replace(",", ""))
    except InvalidOperation as exc:  # pragma: no cover - guarded by the pattern
        raise _GeneralLedgerError(
            "general_ledger_response_invalid",
            f"The provider General Ledger {field_name} is invalid.",
        ) from exc
    if not parsed.is_finite():
        raise _GeneralLedgerError(
            "general_ledger_response_invalid",
            f"The provider General Ledger {field_name} must be finite.",
        )
    return parsed


class GeneralLedgerActivityInput(_StrictModel):
    schema_id: Literal["lightbulb.finance_general_ledger_activity_input.v1"] = Field(
        default=GENERAL_LEDGER_ACTIVITY_INPUT_SCHEMA,
        alias="schema",
    )
    provider: _LedgerProvider = "quickbooks"
    start_date: str
    end_date: str
    currency: CurrencyCode | None = None

    @model_validator(mode="after")
    def _complete_month(self) -> "GeneralLedgerActivityInput":
        _parse_complete_month(self.start_date, self.end_date)
        if self.provider == "quickbooks" and self.currency is not None:
            raise ValueError(
                "QuickBooks General Ledger currency must come from the provider report"
            )
        if self.provider == "xero" and self.currency is None:
            raise ValueError(
                "Xero General Ledger discovery requires the configured base currency"
            )
        return self


class GeneralLedgerActivityLine(_StrictModel):
    """Canonical, restricted activity retained from one provider Data row."""

    schema_id: Literal["lightbulb.general_ledger_activity_line.v1"] = Field(
        default=GENERAL_LEDGER_ACTIVITY_LINE_SCHEMA,
        alias="schema",
    )
    provider: _LedgerProvider = "quickbooks"
    line_ref: Sha256Digest
    transaction_ref: OpaqueRef
    account_ref: OpaqueRef
    account_name: str = Field(min_length=1, max_length=500)
    transaction_date: str
    transaction_type: str = Field(min_length=1, max_length=160)
    document_number: str | None = Field(default=None, max_length=100)
    counterparty_ref: OpaqueRef | None = None
    counterparty_name: str | None = Field(default=None, max_length=500)
    memo: str | None = Field(default=None, max_length=_MAX_MEMO_CHARS)
    memo_digest: Sha256Digest | None = None
    split_account_ref: OpaqueRef | None = None
    split_account_name: str | None = Field(default=None, max_length=500)
    amount: Decimal
    running_balance: Decimal | None = None
    currency: CurrencyCode
    source_row_ordinal: int = Field(ge=1, le=_MAX_ACTIVITY_LINES)
    source_row_digest: Sha256Digest

    @field_validator(
        "account_name",
        "transaction_type",
        "document_number",
        "counterparty_name",
        "memo",
        "split_account_name",
    )
    @classmethod
    def _canonical_text(cls, value: str | None, info: Any) -> str | None:
        if value is None:
            return None
        maximum = {
            "account_name": 500,
            "transaction_type": 160,
            "document_number": 100,
            "counterparty_name": 500,
            "memo": _MAX_MEMO_CHARS,
            "split_account_name": 500,
        }[info.field_name]
        if (
            not value
            or value != value.strip()
            or len(value) > maximum
            or any(ord(character) < 32 for character in value)
        ):
            raise ValueError(f"{info.field_name} must be bounded canonical text")
        return value

    @field_validator("transaction_date")
    @classmethod
    def _canonical_date(cls, value: str) -> str:
        try:
            parsed = date.fromisoformat(value)
        except ValueError as exc:
            raise ValueError("transaction_date must use YYYY-MM-DD") from exc
        if parsed.isoformat() != value:
            raise ValueError("transaction_date must use YYYY-MM-DD")
        return value

    @field_validator("amount", "running_balance", mode="before")
    @classmethod
    def _exact_decimal(cls, value: Any, info: Any) -> Decimal | None:
        if value is None and info.field_name == "running_balance":
            return None
        if isinstance(value, Decimal):
            parsed = value
        elif (
            isinstance(value, str)
            and len(value) <= _MAX_MONEY_CHARS
            and _SIGNED_MONEY_PATTERN.fullmatch(value)
        ):
            parsed = Decimal(value.replace(",", ""))
        else:
            raise ValueError(f"{info.field_name} must be an exact decimal")
        if not parsed.is_finite():
            raise ValueError(f"{info.field_name} must be finite")
        return parsed

    @model_validator(mode="after")
    def _identity_and_memo_commitments(self) -> "GeneralLedgerActivityLine":
        expected = _text_digest(self.memo) if self.memo is not None else None
        if self.memo_digest != expected:
            raise ValueError("memo_digest must commit to the retained memo")
        if self.counterparty_ref is not None and self.counterparty_name is None:
            raise ValueError("counterparty_ref requires a counterparty_name")
        if self.split_account_ref is not None and self.split_account_name is None:
            raise ValueError("split_account_ref requires a split_account_name")
        expected_line_ref = _stable_digest(
            {
                "schema": GENERAL_LEDGER_ACTIVITY_LINE_SCHEMA,
                "provider": self.provider,
                "transaction_ref": self.transaction_ref,
                "account_ref": self.account_ref,
                "transaction_date": self.transaction_date,
                "amount": str(self.amount),
                "source_row_ordinal": self.source_row_ordinal,
                "source_row_digest": self.source_row_digest,
            }
        )
        if self.line_ref != expected_line_ref:
            raise ValueError(
                "line_ref must commit to the canonical source-row identity"
            )
        return self


class GeneralLedgerActivityObservation(_StrictModel):
    schema_id: Literal["lightbulb.finance_general_ledger_activity_result.v1"] = Field(
        default=GENERAL_LEDGER_ACTIVITY_RESULT_SCHEMA,
        alias="schema",
    )
    provider: _LedgerProvider
    tool: ToolName
    tool_version: int = Field(ge=1, le=2_147_483_647)
    project_id: UUID
    tenant_connector_id: UUID
    connector_account_ref: OpaqueRef
    route_digest: Sha256Digest
    start_date: str
    end_date: str
    currency: CurrencyCode
    lines: tuple[GeneralLedgerActivityLine, ...] = Field(max_length=_MAX_ACTIVITY_LINES)
    line_count: int = Field(ge=0, le=_MAX_ACTIVITY_LINES)
    provider_report_digest: Sha256Digest
    provenance_receipt_digest: Sha256Digest
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
    certification_authority: Literal[False] = False
    source_digest: Sha256Digest = _ZERO_DIGEST

    @field_validator("lines", mode="before")
    @classmethod
    def _line_tuple(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("observed_at")
    @classmethod
    def _observation_time(cls, value: str) -> str:
        return _normalized_utc_timestamp(value, field_name="observed_at")

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
            "lines": [line.to_dict() for line in self.lines],
            "provider_report_digest": self.provider_report_digest,
            "provenance_receipt_digest": self.provenance_receipt_digest,
            "observed_at": self.observed_at,
        }

    @model_validator(mode="after")
    def _complete_and_sealed(self) -> "GeneralLedgerActivityObservation":
        start, end = _parse_complete_month(self.start_date, self.end_date)
        if self.tool.split(".", 1)[0] != self.provider:
            raise ValueError("General Ledger Tool namespace must match its provider")
        if self.line_count != len(self.lines):
            raise ValueError("line_count must match General Ledger lines")
        if len({line.line_ref for line in self.lines}) != len(self.lines):
            raise ValueError("General Ledger line references must be unique")
        if any(line.provider != self.provider for line in self.lines):
            raise ValueError("General Ledger lines must use the report provider")
        if any(line.currency != self.currency for line in self.lines):
            raise ValueError("General Ledger lines must use the report currency")
        if any(
            not start <= date.fromisoformat(line.transaction_date) <= end
            for line in self.lines
        ):
            raise ValueError(
                "General Ledger lines must stay within the requested month"
            )
        ordered = tuple(
            sorted(
                self.lines,
                key=lambda line: (
                    line.transaction_date,
                    line.account_ref,
                    line.transaction_ref,
                    line.source_row_ordinal,
                    line.line_ref,
                ),
            )
        )
        if self.lines != ordered:
            raise ValueError("General Ledger lines must use canonical ordering")
        expected = _stable_digest(self._source_digest_payload())
        if self.source_digest not in {_ZERO_DIGEST, expected}:
            raise ValueError("source_digest does not match canonical ledger evidence")
        object.__setattr__(self, "source_digest", expected)
        return self


class GeneralLedgerActivityResult(GeneralLedgerActivityObservation):
    """Provider-neutral observation returned by the executable primitive."""

    provider: _LedgerProvider = "quickbooks"
    tool: ToolName = QUICKBOOKS_GENERAL_LEDGER_TOOL
    tool_version: int = Field(default=QUICKBOOKS_GENERAL_LEDGER_TOOL_VERSION, ge=1)

    @model_validator(mode="after")
    def _exact_provider_tool_contract(self) -> "GeneralLedgerActivityResult":
        expected = {
            "quickbooks": (
                QUICKBOOKS_GENERAL_LEDGER_TOOL,
                QUICKBOOKS_GENERAL_LEDGER_TOOL_VERSION,
            ),
            "xero": (XERO_JOURNAL_TOOL, XERO_JOURNAL_TOOL_VERSION),
        }[self.provider]
        if (self.tool, self.tool_version) != expected:
            raise ValueError(
                "General Ledger provider, Tool, and Tool version must match exactly"
            )
        return self


class _GeneralLedgerError(Exception):
    def __init__(self, code: str, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable


def _read_operation_spec(
    tool: str = QUICKBOOKS_GENERAL_LEDGER_TOOL,
    *,
    operation_ref: str = "general-ledger-activity.read",
) -> PrimitiveOperationSpec:
    return PrimitiveOperationSpec(
        operation_ref=operation_ref,
        tool=tool,
        effect=ConnectorEffect.READ,
        approval_required=False,
        replay_class=PrimitiveOperationReplayClass.SAFE,
        freshness_class=PrimitiveOperationFreshnessClass.CURRENT,
        recovery_policy=PrimitiveOperationRecoveryPolicy.RETRY,
    )


def _column_positions(report: Mapping[str, Any]) -> tuple[dict[str, int], int]:
    columns = report.get("Columns")
    if not isinstance(columns, Mapping):
        raise _GeneralLedgerError(
            "general_ledger_response_invalid",
            "The provider General Ledger column contract is missing.",
        )
    raw_columns = columns.get("Column")
    if (
        not isinstance(raw_columns, list)
        or not 1 <= len(raw_columns) <= _MAX_REPORT_COLUMNS
    ):
        raise _GeneralLedgerError(
            "general_ledger_response_invalid",
            "The provider General Ledger columns are malformed or exceed their bound.",
        )
    positions: dict[str, int] = {}
    for index, raw_column in enumerate(raw_columns):
        if not isinstance(raw_column, Mapping):
            raise _GeneralLedgerError(
                "general_ledger_response_invalid",
                "The provider General Ledger contains a malformed column.",
            )
        raw_role = raw_column.get("ColType") or raw_column.get("ColTitle")
        role_text = _bounded_text(
            raw_role,
            field_name="column role",
            maximum=100,
        )
        assert role_text is not None
        normalized = re.sub(r"[^a-z]", "", role_text.lower())
        role = _COLUMN_ROLE_ALIASES.get(normalized)
        if role is None:
            continue
        if role in positions:
            raise _GeneralLedgerError(
                "general_ledger_response_invalid",
                f"The provider General Ledger repeats the {role} column.",
            )
        positions[role] = index
    if set(positions) != _REQUIRED_COLUMN_ROLES:
        missing = sorted(_REQUIRED_COLUMN_ROLES - set(positions))
        raise _GeneralLedgerError(
            "general_ledger_response_invalid",
            "The provider General Ledger is missing required columns: "
            + ", ".join(missing)
            + ".",
        )
    return positions, len(raw_columns)


def _cell(
    raw_cells: list[Any],
    position: int,
    *,
    field_name: str,
) -> tuple[str, str | None]:
    raw_cell = raw_cells[position]
    if not isinstance(raw_cell, Mapping) or "value" not in raw_cell:
        raise _GeneralLedgerError(
            "general_ledger_response_invalid",
            f"The provider General Ledger {field_name} cell is malformed.",
        )
    raw_value = raw_cell.get("value")
    if not isinstance(raw_value, str):
        raise _GeneralLedgerError(
            "general_ledger_response_invalid",
            f"The provider General Ledger {field_name} value is malformed.",
        )
    raw_ref = raw_cell.get("id")
    if raw_ref is not None and (
        not isinstance(raw_ref, str) or raw_ref != raw_ref.strip() or not raw_ref
    ):
        raise _GeneralLedgerError(
            "general_ledger_response_invalid",
            f"The provider General Ledger {field_name} identifier is malformed.",
        )
    return raw_value, raw_ref


def _section_account(
    row: Mapping[str, Any],
    inherited: tuple[str, str] | None,
) -> tuple[str, str] | None:
    header = row.get("Header")
    if header is None:
        return inherited
    if not isinstance(header, Mapping):
        raise _GeneralLedgerError(
            "general_ledger_response_invalid",
            "A provider General Ledger section header is malformed.",
        )
    cells = header.get("ColData")
    if not isinstance(cells, list) or len(cells) > _MAX_REPORT_COLUMNS:
        raise _GeneralLedgerError(
            "general_ledger_response_invalid",
            "A provider General Ledger section account header is malformed.",
        )
    candidates: list[tuple[str, str]] = []
    for cell in cells:
        if not isinstance(cell, Mapping):
            raise _GeneralLedgerError(
                "general_ledger_response_invalid",
                "A provider General Ledger section header cell is malformed.",
            )
        raw_ref = cell.get("id")
        raw_name = cell.get("value")
        if raw_ref in (None, "") and raw_name in (None, ""):
            continue
        if raw_ref in (None, ""):
            continue
        account_ref = _bounded_text(
            raw_ref,
            field_name="section account identifier",
            maximum=200,
        )
        account_name = _bounded_text(
            raw_name,
            field_name="section account name",
            maximum=500,
        )
        assert account_ref is not None and account_name is not None
        candidates.append((account_ref, account_name))
    if not candidates:
        return inherited
    if len(candidates) != 1:
        raise _GeneralLedgerError(
            "general_ledger_response_invalid",
            "A provider General Ledger section has ambiguous account identity.",
        )
    return candidates[0]


def _is_non_activity_balance_row(
    *,
    transaction_date: str,
    transaction_type: str,
    transaction_ref: str | None,
    memo: str,
) -> bool:
    if transaction_date or transaction_type or transaction_ref is not None:
        return False
    label = re.sub(r"[^a-z]", "", memo.lower())
    return label in {"beginningbalance", "openingbalance", "endingbalance"}


def _normalize_data_row(
    *,
    raw_cells: list[Any],
    positions: Mapping[str, int],
    column_count: int,
    account: tuple[str, str] | None,
    row_ordinal: int,
    inputs: GeneralLedgerActivityInput,
    currency: str,
) -> GeneralLedgerActivityLine | None:
    if len(raw_cells) != column_count:
        raise _GeneralLedgerError(
            "general_ledger_response_invalid",
            "A provider General Ledger row does not match its column contract.",
        )
    transaction_date, _ = _cell(
        raw_cells,
        positions["transaction_date"],
        field_name="transaction date",
    )
    transaction_type, transaction_ref = _cell(
        raw_cells,
        positions["transaction_type"],
        field_name="transaction type",
    )
    document_number, _ = _cell(
        raw_cells,
        positions["document_number"],
        field_name="document number",
    )
    counterparty_name, counterparty_ref = _cell(
        raw_cells,
        positions["counterparty"],
        field_name="counterparty",
    )
    memo, _ = _cell(raw_cells, positions["memo"], field_name="memo")
    split_account_name, split_account_ref = _cell(
        raw_cells,
        positions["split_account"],
        field_name="split account",
    )
    amount, _ = _cell(raw_cells, positions["amount"], field_name="amount")
    running_balance, _ = _cell(
        raw_cells,
        positions["running_balance"],
        field_name="running balance",
    )

    if _is_non_activity_balance_row(
        transaction_date=transaction_date,
        transaction_type=transaction_type,
        transaction_ref=transaction_ref,
        memo=memo,
    ):
        opening_amount = _exact_money(
            amount,
            field_name="balance-row amount",
            optional=True,
        )
        opening_balance = _exact_money(
            running_balance,
            field_name="balance-row running balance",
            optional=True,
        )
        if opening_amount is None and opening_balance is None:
            raise _GeneralLedgerError(
                "general_ledger_response_invalid",
                "A provider General Ledger balance row has no monetary balance.",
            )
        return None
    if account is None:
        raise _GeneralLedgerError(
            "general_ledger_response_invalid",
            "A provider General Ledger activity row is outside a stable account section.",
        )
    if not transaction_ref:
        raise _GeneralLedgerError(
            "general_ledger_response_invalid",
            "A provider General Ledger activity row is missing its transaction identifier.",
        )
    transaction_date_text = _bounded_text(
        transaction_date,
        field_name="transaction date",
        maximum=10,
    )
    transaction_type_text = _bounded_text(
        transaction_type,
        field_name="transaction type",
        maximum=160,
    )
    assert transaction_date_text is not None and transaction_type_text is not None
    try:
        parsed_date = date.fromisoformat(transaction_date_text)
    except ValueError as exc:
        raise _GeneralLedgerError(
            "general_ledger_response_invalid",
            "A provider General Ledger transaction date is not YYYY-MM-DD.",
        ) from exc
    start, end = _parse_complete_month(inputs.start_date, inputs.end_date)
    if (
        parsed_date.isoformat() != transaction_date_text
        or not start <= parsed_date <= end
    ):
        raise _GeneralLedgerError(
            "general_ledger_scope_mismatch",
            "A provider General Ledger activity row falls outside the requested month.",
        )

    account_ref, account_name = account
    normalized_document_number = _optional_text(
        document_number,
        field_name="document number",
        maximum=100,
    )
    normalized_counterparty_name = _optional_text(
        counterparty_name,
        field_name="counterparty name",
        maximum=500,
    )
    normalized_memo = _optional_text(
        memo,
        field_name="memo",
        maximum=_MAX_MEMO_CHARS,
    )
    normalized_split_name = _optional_text(
        split_account_name,
        field_name="split account name",
        maximum=500,
    )
    normalized_amount = _exact_money(amount, field_name="amount")
    normalized_running_balance = _exact_money(
        running_balance,
        field_name="running balance",
        optional=True,
    )
    assert normalized_amount is not None
    source_row_digest = _stable_digest(
        {
            "schema": "lightbulb.quickbooks_general_ledger_source_row.v1",
            "account_ref": account_ref,
            "account_name": account_name,
            "row_ordinal": row_ordinal,
            "col_data": raw_cells,
        }
    )
    line_ref = _stable_digest(
        {
            "schema": GENERAL_LEDGER_ACTIVITY_LINE_SCHEMA,
            "provider": "quickbooks",
            "transaction_ref": transaction_ref,
            "account_ref": account_ref,
            "transaction_date": transaction_date_text,
            "amount": str(normalized_amount),
            "source_row_ordinal": row_ordinal,
            "source_row_digest": source_row_digest,
        }
    )
    try:
        return GeneralLedgerActivityLine(
            line_ref=line_ref,
            transaction_ref=transaction_ref,
            account_ref=account_ref,
            account_name=account_name,
            transaction_date=transaction_date_text,
            transaction_type=transaction_type_text,
            document_number=normalized_document_number,
            counterparty_ref=counterparty_ref,
            counterparty_name=normalized_counterparty_name,
            memo=normalized_memo,
            memo_digest=(
                _text_digest(normalized_memo) if normalized_memo is not None else None
            ),
            split_account_ref=split_account_ref,
            split_account_name=normalized_split_name,
            amount=normalized_amount,
            running_balance=normalized_running_balance,
            currency=currency,
            source_row_ordinal=row_ordinal,
            source_row_digest=source_row_digest,
        )
    except Exception as exc:
        raise _GeneralLedgerError(
            "general_ledger_response_invalid",
            "A provider General Ledger activity row failed canonical validation.",
        ) from exc


def _activity_rows(
    report: Mapping[str, Any],
    *,
    positions: Mapping[str, int],
    column_count: int,
    inputs: GeneralLedgerActivityInput,
    currency: str,
) -> tuple[GeneralLedgerActivityLine, ...]:
    lines: list[GeneralLedgerActivityLine] = []
    visited = 0

    def visit(container: Any, depth: int, account: tuple[str, str] | None) -> None:
        nonlocal visited
        if depth > _MAX_REPORT_ROW_DEPTH or not isinstance(container, Mapping):
            raise _GeneralLedgerError(
                "general_ledger_response_invalid",
                "The provider General Ledger row hierarchy is malformed or too deep.",
            )
        rows = container.get("Row")
        if not isinstance(rows, list) or len(rows) > _MAX_ACTIVITY_LINES:
            raise _GeneralLedgerError(
                "general_ledger_response_invalid",
                "The provider General Ledger rows are malformed or exceed their bound.",
            )
        for row in rows:
            visited += 1
            if visited > _MAX_ACTIVITY_LINES:
                raise _GeneralLedgerError(
                    "general_ledger_record_limit_exceeded",
                    "The provider General Ledger exceeds 10,000 total rows.",
                )
            if not isinstance(row, Mapping):
                raise _GeneralLedgerError(
                    "general_ledger_response_invalid",
                    "The provider General Ledger contains a malformed row.",
                )
            row_type_raw = row.get("type") or "Data"
            row_type = _bounded_text(
                row_type_raw,
                field_name="row type",
                maximum=20,
            )
            assert row_type is not None
            row_type = row_type.lower()
            if row_type not in {"data", "section"}:
                raise _GeneralLedgerError(
                    "general_ledger_response_invalid",
                    "The provider General Ledger contains an unsupported row type.",
                )
            current_account = (
                _section_account(row, account) if row_type == "section" else account
            )
            if row_type == "data":
                raw_cells = row.get("ColData")
                if not isinstance(raw_cells, list):
                    raise _GeneralLedgerError(
                        "general_ledger_response_invalid",
                        "A provider General Ledger Data row has no column data.",
                    )
                line = _normalize_data_row(
                    raw_cells=raw_cells,
                    positions=positions,
                    column_count=column_count,
                    account=current_account,
                    row_ordinal=visited,
                    inputs=inputs,
                    currency=currency,
                )
                if line is not None:
                    lines.append(line)
            nested = row.get("Rows")
            if nested is not None:
                visit(nested, depth + 1, current_account)

    visit(report.get("Rows"), 0, None)
    if len(lines) > _MAX_ACTIVITY_LINES:
        raise _GeneralLedgerError(
            "general_ledger_record_limit_exceeded",
            "The provider General Ledger exceeds 10,000 activity lines.",
        )
    return tuple(
        sorted(
            lines,
            key=lambda line: (
                line.transaction_date,
                line.account_ref,
                line.transaction_ref,
                line.source_row_ordinal,
                line.line_ref,
            ),
        )
    )


def _normalize_report(
    output: Any,
    *,
    inputs: GeneralLedgerActivityInput,
    context: PrimitiveExecutionContext,
    provenance: ConnectorExecutionProvenance,
) -> GeneralLedgerActivityResult:
    if not isinstance(output, Mapping) or set(output) != {"Header", "Columns", "Rows"}:
        raise _GeneralLedgerError(
            "general_ledger_response_invalid",
            "QuickBooks returned an unexpected General Ledger report shape.",
        )
    header = output.get("Header")
    if not isinstance(header, Mapping):
        raise _GeneralLedgerError(
            "general_ledger_response_invalid",
            "The provider General Ledger header is missing.",
        )
    report_name = _bounded_text(
        header.get("ReportName"),
        field_name="report name",
        maximum=100,
    )
    start_date = _bounded_text(
        header.get("StartPeriod"),
        field_name="start period",
        maximum=10,
    )
    end_date = _bounded_text(
        header.get("EndPeriod"),
        field_name="end period",
        maximum=10,
    )
    currency_text = _bounded_text(
        header.get("Currency"),
        field_name="currency",
        maximum=3,
    )
    assert (
        report_name is not None
        and start_date is not None
        and end_date is not None
        and currency_text is not None
    )
    normalized_report_name = re.sub(r"[^a-z]", "", report_name.lower())
    currency = currency_text.upper()
    if (
        normalized_report_name != "generalledger"
        or start_date != inputs.start_date
        or end_date != inputs.end_date
        or re.fullmatch(_CURRENCY_PATTERN, currency) is None
    ):
        raise _GeneralLedgerError(
            "general_ledger_scope_mismatch",
            "The provider General Ledger does not match the requested month and currency contract.",
        )
    positions, column_count = _column_positions(output)
    lines = _activity_rows(
        output,
        positions=positions,
        column_count=column_count,
        inputs=inputs,
        currency=currency,
    )
    assert context.scope.project_id is not None
    return GeneralLedgerActivityResult(
        project_id=context.scope.project_id,
        tenant_connector_id=provenance.tenant_connector_id,
        connector_account_ref=provenance.connector_account_ref,
        route_digest=provenance.route_digest,
        start_date=inputs.start_date,
        end_date=inputs.end_date,
        currency=currency,
        lines=lines,
        line_count=len(lines),
        provider_report_digest=_stable_digest(output),
        provenance_receipt_digest=provenance.receipt_digest,
        observed_at=provenance.completed_at,
    )


def _xero_journal_date(value: Any) -> date:
    if not isinstance(value, str) or value != value.strip():
        raise _GeneralLedgerError(
            "general_ledger_response_invalid",
            "A Xero journal date is malformed.",
        )
    match = _XERO_DOTNET_DATE_PATTERN.fullmatch(value)
    if match is not None:
        offset = match.group("offset")
        if offset is not None and (
            int(offset[1:3]) > 23 or int(offset[3:5]) > 59
        ):
            raise _GeneralLedgerError(
                "general_ledger_response_invalid",
                "A Xero journal date has an invalid UTC offset.",
            )
        try:
            epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
            instant = epoch + timedelta(milliseconds=int(match.group("milliseconds")))
        except (OverflowError, ValueError) as exc:
            raise _GeneralLedgerError(
                "general_ledger_response_invalid",
                "A Xero journal date is outside the supported range.",
            ) from exc
        return instant.date()
    try:
        if len(value) == 10:
            parsed_date = date.fromisoformat(value)
            if parsed_date.isoformat() == value:
                return parsed_date
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise _GeneralLedgerError(
            "general_ledger_response_invalid",
            "A Xero journal date is not an exact provider date.",
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise _GeneralLedgerError(
            "general_ledger_response_invalid",
            "A Xero journal timestamp must include a UTC offset.",
        )
    return parsed.astimezone(timezone.utc).date()


def _xero_journal_page(output: Any) -> list[Mapping[str, Any]]:
    if not isinstance(output, Mapping) or set(output) != {"Journals"}:
        raise _GeneralLedgerError(
            "general_ledger_response_invalid",
            "Xero returned an unexpected governed journal page shape.",
        )
    raw_journals = output.get("Journals")
    if (
        not isinstance(raw_journals, list)
        or len(raw_journals) > _XERO_JOURNAL_PAGE_SIZE
        or any(not isinstance(journal, Mapping) for journal in raw_journals)
    ):
        raise _GeneralLedgerError(
            "general_ledger_response_invalid",
            "Xero returned a malformed or oversized journal page.",
        )
    return raw_journals


def _xero_journal_number(journal: Mapping[str, Any]) -> int:
    number = journal.get("JournalNumber")
    if isinstance(number, bool) or not isinstance(number, int) or number <= 0:
        raise _GeneralLedgerError(
            "general_ledger_response_invalid",
            "A Xero journal has an invalid JournalNumber.",
        )
    return number


def _validate_xero_journal_content(journal: Mapping[str, Any]) -> None:
    _bounded_text(
        journal.get("JournalID"),
        field_name="Xero JournalID",
        maximum=200,
    )
    _xero_journal_date(journal.get("JournalDate"))
    _optional_text(
        journal.get("SourceID"),
        field_name="Xero SourceID",
        maximum=200,
    )
    _optional_text(
        journal.get("SourceType"),
        field_name="Xero SourceType",
        maximum=160,
    )
    _optional_text(
        journal.get("Reference"),
        field_name="Xero journal reference",
        maximum=_MAX_MEMO_CHARS,
    )
    raw_lines = journal.get("JournalLines")
    if not isinstance(raw_lines, list):
        raise _GeneralLedgerError(
            "general_ledger_response_invalid",
            "A Xero journal has malformed JournalLines.",
        )
    for raw_line in raw_lines:
        if not isinstance(raw_line, Mapping):
            raise _GeneralLedgerError(
                "general_ledger_response_invalid",
                "A Xero journal contains a malformed line.",
            )
        _bounded_text(
            raw_line.get("JournalLineID"),
            field_name="Xero JournalLineID",
            maximum=200,
        )
        _bounded_text(
            raw_line.get("AccountID"),
            field_name="Xero AccountID",
            maximum=200,
        )
        _bounded_text(
            raw_line.get("AccountName"),
            field_name="Xero account name",
            maximum=500,
        )
        _optional_text(
            raw_line.get("Description"),
            field_name="Xero line description",
            maximum=_MAX_MEMO_CHARS,
        )
        _exact_money(raw_line.get("NetAmount"), field_name="Xero NetAmount")


def _normalize_xero_journals(
    journals: list[Mapping[str, Any]],
    *,
    inputs: GeneralLedgerActivityInput,
    context: PrimitiveExecutionContext,
    provenances: list[ConnectorExecutionProvenance],
    page_digests: list[str],
) -> GeneralLedgerActivityResult:
    assert context.scope.project_id is not None
    assert inputs.currency is not None
    if not provenances or len(provenances) != len(page_digests):
        raise _GeneralLedgerError(
            "general_ledger_provenance_missing",
            "The complete Xero journal history has incomplete Spring provenance.",
        )
    start, end = _parse_complete_month(inputs.start_date, inputs.end_date)
    lines: list[GeneralLedgerActivityLine] = []
    seen_journal_ids: set[str] = set()
    seen_line_ids: set[str] = set()
    source_line_ordinal = 0

    for journal in journals:
        journal_id = _bounded_text(
            journal.get("JournalID"),
            field_name="Xero JournalID",
            maximum=200,
        )
        assert journal_id is not None
        if journal_id in seen_journal_ids:
            raise _GeneralLedgerError(
                "general_ledger_pagination_invalid",
                "Xero repeated a journal across the governed history read.",
            )
        seen_journal_ids.add(journal_id)
        journal_number = _xero_journal_number(journal)
        journal_date = _xero_journal_date(journal.get("JournalDate"))
        transaction_ref = _optional_text(
            journal.get("SourceID"),
            field_name="Xero SourceID",
            maximum=200,
        ) or journal_id
        transaction_type = _optional_text(
            journal.get("SourceType"),
            field_name="Xero SourceType",
            maximum=160,
        ) or "Journal"
        journal_reference = _optional_text(
            journal.get("Reference"),
            field_name="Xero journal reference",
            maximum=_MAX_MEMO_CHARS,
        )
        raw_lines = journal.get("JournalLines")
        if not isinstance(raw_lines, list):
            raise _GeneralLedgerError(
                "general_ledger_response_invalid",
                "A Xero journal has malformed JournalLines.",
            )
        for raw_line in raw_lines:
            source_line_ordinal += 1
            if source_line_ordinal > _MAX_ACTIVITY_LINES:
                raise _GeneralLedgerError(
                    "general_ledger_record_limit_exceeded",
                    "The complete Xero journal history exceeds 10,000 lines.",
                )
            if not isinstance(raw_line, Mapping):
                raise _GeneralLedgerError(
                    "general_ledger_response_invalid",
                    "A Xero journal contains a malformed line.",
                )
            journal_line_id = _bounded_text(
                raw_line.get("JournalLineID"),
                field_name="Xero JournalLineID",
                maximum=200,
            )
            account_ref = _bounded_text(
                raw_line.get("AccountID"),
                field_name="Xero AccountID",
                maximum=200,
            )
            account_name = _bounded_text(
                raw_line.get("AccountName"),
                field_name="Xero account name",
                maximum=500,
            )
            assert journal_line_id is not None
            assert account_ref is not None
            assert account_name is not None
            if journal_line_id in seen_line_ids:
                raise _GeneralLedgerError(
                    "general_ledger_pagination_invalid",
                    "Xero repeated a journal line across the governed history read.",
                )
            seen_line_ids.add(journal_line_id)
            amount = _exact_money(
                raw_line.get("NetAmount"),
                field_name="Xero NetAmount",
            )
            assert amount is not None
            if not start <= journal_date <= end:
                continue
            description = _optional_text(
                raw_line.get("Description"),
                field_name="Xero line description",
                maximum=_MAX_MEMO_CHARS,
            )
            memo = description or journal_reference
            source_row_digest = _stable_digest(
                {
                    "schema": "lightbulb.xero_journal_line_source.v1",
                    "journal_id": journal_id,
                    "journal_number": journal_number,
                    "journal_date": journal_date.isoformat(),
                    "journal_line_id": journal_line_id,
                    "source_line_ordinal": source_line_ordinal,
                    "line": raw_line,
                }
            )
            line_ref = _stable_digest(
                {
                    "schema": GENERAL_LEDGER_ACTIVITY_LINE_SCHEMA,
                    "provider": "xero",
                    "transaction_ref": transaction_ref,
                    "account_ref": account_ref,
                    "transaction_date": journal_date.isoformat(),
                    "amount": str(amount),
                    "source_row_ordinal": source_line_ordinal,
                    "source_row_digest": source_row_digest,
                }
            )
            try:
                lines.append(
                    GeneralLedgerActivityLine(
                        provider="xero",
                        line_ref=line_ref,
                        transaction_ref=transaction_ref,
                        account_ref=account_ref,
                        account_name=account_name,
                        transaction_date=journal_date.isoformat(),
                        transaction_type=transaction_type,
                        document_number=str(journal_number),
                        memo=memo,
                        memo_digest=_text_digest(memo) if memo is not None else None,
                        amount=amount,
                        currency=inputs.currency,
                        source_row_ordinal=source_line_ordinal,
                        source_row_digest=source_row_digest,
                    )
                )
            except Exception as exc:
                raise _GeneralLedgerError(
                    "general_ledger_response_invalid",
                    "A Xero journal line failed canonical validation.",
                ) from exc

    lines.sort(
        key=lambda line: (
            line.transaction_date,
            line.account_ref,
            line.transaction_ref,
            line.source_row_ordinal,
            line.line_ref,
        )
    )
    first = provenances[0]
    return GeneralLedgerActivityResult(
        provider="xero",
        tool=XERO_JOURNAL_TOOL,
        tool_version=XERO_JOURNAL_TOOL_VERSION,
        project_id=context.scope.project_id,
        tenant_connector_id=first.tenant_connector_id,
        connector_account_ref=first.connector_account_ref,
        route_digest=first.route_digest,
        start_date=inputs.start_date,
        end_date=inputs.end_date,
        currency=inputs.currency,
        lines=tuple(lines),
        line_count=len(lines),
        provider_report_digest=_stable_digest(
            {
                "schema": "lightbulb.xero_complete_journal_history.v1",
                "page_digests": page_digests,
                "terminal_empty_page": True,
            }
        ),
        provenance_receipt_digest=_stable_digest(
            {
                "schema": "lightbulb.xero_journal_page_provenance_collection.v1",
                "receipt_digests": [item.receipt_digest for item in provenances],
            }
        ),
        observed_at=provenances[-1].completed_at,
    )


def _validate_provenance(
    provenance: ConnectorExecutionProvenance | None,
    request: ConnectorExecutionRequest,
    *,
    expected_tool_version: int = QUICKBOOKS_GENERAL_LEDGER_TOOL_VERSION,
) -> ConnectorExecutionProvenance:
    if provenance is None:
        raise _GeneralLedgerError(
            "general_ledger_provenance_missing",
            "The governed General Ledger result has no Spring provenance.",
        )
    if (
        provenance.tool != request.tool
        or provenance.tool_version != expected_tool_version
        or provenance.server_effect != ConnectorEffect.READ
        or provenance.connector_account_ref != request.connector_account_ref
        or request.scope.project_id is None
        or provenance.project_id != request.scope.project_id
        or provenance.request_digest != request.custody_fingerprint()
        or provenance.approval_ref is not None
        or provenance.approval_receipt_digest is not None
    ):
        raise _GeneralLedgerError(
            "general_ledger_provenance_mismatch",
            "The Spring provenance does not match this exact General Ledger request.",
        )
    return provenance


def _receipt(
    *,
    request: ConnectorExecutionRequest,
    result: ConnectorExecutionResult,
    blocker: PrimitiveBlocker | None = None,
    provenance_valid: bool = False,
    force_failed: bool = False,
    spec: PrimitiveOperationSpec | None = None,
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
        spec=spec or _read_operation_spec(request.tool),
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


class DiscoverGeneralLedgerActivityPrimitive(
    BusinessProcessPrimitive[GeneralLedgerActivityInput, GeneralLedgerActivityResult]
):
    primitive_ref = "finance.discover_general_ledger_activity"
    version = "1.0.0"
    title = "Discover governed General Ledger activity"
    description = (
        "Read and normalize one complete month of QuickBooks or Xero General Ledger "
        "activity through the exact governed project/account route without "
        "reconciling or advancing a close."
    )
    input_model = GeneralLedgerActivityInput
    output_model = GeneralLedgerActivityResult
    connector_tools = (QUICKBOOKS_GENERAL_LEDGER_TOOL, XERO_JOURNAL_TOOL)
    risk_level = "low"
    approval_required = False
    example_inputs = {
        "provider": "quickbooks",
        "start_date": "2026-08-01",
        "end_date": "2026-08-31",
    }
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = True

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: GeneralLedgerActivityInput,
    ) -> PrimitiveExecutionResult[GeneralLedgerActivityResult]:
        tool = (
            QUICKBOOKS_GENERAL_LEDGER_TOOL
            if inputs.provider == "quickbooks"
            else XERO_JOURNAL_TOOL
        )
        if context.preview_only:
            receipt = PrimitiveOperationReceipt(
                spec=_read_operation_spec(
                    tool,
                    operation_ref=(
                        "general-ledger-activity.read"
                        if inputs.provider == "quickbooks"
                        else "general-ledger-activity.read-complete-history"
                    ),
                ),
                status=PrimitiveOperationStatus.PLANNED,
                request_digest=_stable_digest(
                    {
                        "schema": "lightbulb.general_ledger_activity_plan.v1",
                        "provider": inputs.provider,
                        "tool": tool,
                        "start_date": inputs.start_date,
                        "end_date": inputs.end_date,
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
                    "General Ledger discovery previewed; no connector read was "
                    "requested and no ledger activity was fabricated."
                ),
                operation_receipts=[receipt],
                connector_tool=tool,
            )

        account_ref = context.connector_account_refs.get(tool)
        if account_ref is None:
            account_ref = context.connector_account_refs.get(inputs.provider)
        if context.scope.project_id is None or not str(account_ref or "").strip():
            blocker = PrimitiveBlocker(
                code="general_ledger_scope_required",
                message=(
                    "Governed General Ledger discovery requires an authenticated "
                    f"project UUID and exact {inputs.provider} connector-account binding."
                ),
            )
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.BLOCKED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary=blocker.message,
                blockers=[blocker],
                connector_tool=tool,
            )

        if inputs.provider == "xero":
            return self._execute_xero(context, inputs, str(account_ref))

        spec = _read_operation_spec()
        request = context.connector_request(
            primitive_ref=self.primitive_ref,
            tool=QUICKBOOKS_GENERAL_LEDGER_TOOL,
            arguments={
                "start_date": inputs.start_date,
                "end_date": inputs.end_date,
            },
            effect=ConnectorEffect.READ,
            approval_required=False,
            operation_ref=spec.operation_ref,
            connector_account_ref=str(account_ref),
            metadata={"source": self.primitive_ref},
        )
        result = context.connectors.execute(request)
        if result.tool != request.tool:
            blocker = PrimitiveBlocker(
                code="general_ledger_tool_mismatch",
                message="The connector response is not bound to the requested General Ledger Tool.",
            )
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.FAILED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary=blocker.message,
                blockers=[blocker],
                operation_receipts=[
                    _receipt(
                        request=request,
                        result=result,
                        blocker=blocker,
                        force_failed=True,
                    )
                ],
                connector_tool=QUICKBOOKS_GENERAL_LEDGER_TOOL,
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
                code="general_ledger_read_failed",
                message="The governed General Ledger read did not complete.",
                retryable=result.retryable,
            )
            return PrimitiveExecutionResult(
                status=primitive_status,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary=blocker.message,
                blockers=[blocker],
                operation_receipts=[
                    _receipt(request=request, result=result, blocker=blocker)
                ],
                connector_tool=QUICKBOOKS_GENERAL_LEDGER_TOOL,
                retryable=result.retryable,
            )

        provenance: ConnectorExecutionProvenance | None = None
        try:
            provenance = _validate_provenance(result.provenance, request)
            output = _normalize_report(
                result.output,
                inputs=inputs,
                context=context,
                provenance=provenance,
            )
        except _GeneralLedgerError as exc:
            blocker = PrimitiveBlocker(
                code=exc.code,
                message=exc.message,
                retryable=exc.retryable,
            )
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.FAILED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary=blocker.message,
                blockers=[blocker],
                operation_receipts=[
                    _receipt(
                        request=request,
                        result=result,
                        blocker=blocker,
                        provenance_valid=provenance is not None,
                        force_failed=True,
                    )
                ],
                connector_tool=QUICKBOOKS_GENERAL_LEDGER_TOOL,
                retryable=exc.retryable,
            )

        return PrimitiveExecutionResult(
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                f"Discovered {output.line_count} governed QuickBooks General Ledger "
                "activity lines for one complete month."
            ),
            output=output,
            events=[
                PrimitiveEvent(
                    type="finance.general_ledger_activity_discovered",
                    payload={
                        "provider": output.provider,
                        "start_date": output.start_date,
                        "end_date": output.end_date,
                        "currency": output.currency,
                        "line_count": output.line_count,
                        "source_digest": output.source_digest,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="governed_general_ledger_activity_observation",
                    summary=(
                        "A complete bounded monthly QuickBooks General Ledger report "
                        "was normalized with exact Spring provenance."
                    ),
                    labels=[
                        "quickbooks",
                        "authoritative_read",
                        "complete",
                        "monthly",
                        "reconciliation_not_performed",
                        "close_not_advanced",
                    ],
                    refs={"source_digest": output.source_digest},
                )
            ],
            operation_receipts=[
                _receipt(
                    request=request,
                    result=result,
                    provenance_valid=True,
                )
            ],
            connector_tool=QUICKBOOKS_GENERAL_LEDGER_TOOL,
        )

    def _execute_xero(
        self,
        context: PrimitiveExecutionContext,
        inputs: GeneralLedgerActivityInput,
        account_ref: str,
    ) -> PrimitiveExecutionResult[GeneralLedgerActivityResult]:
        receipts: list[PrimitiveOperationReceipt] = []
        journals: list[Mapping[str, Any]] = []
        provenances: list[ConnectorExecutionProvenance] = []
        page_digests: list[str] = []
        seen_journal_numbers: set[int] = set()
        seen_journal_refs: set[str] = set()
        seen_receipt_digests: set[str] = set()
        offset = 0
        previous_completed_at: str | None = None

        def failed(
            blocker: PrimitiveBlocker,
            *,
            request: ConnectorExecutionRequest | None = None,
            result: ConnectorExecutionResult | None = None,
            spec: PrimitiveOperationSpec | None = None,
            provenance_valid: bool = False,
            blocked: bool = False,
        ) -> PrimitiveExecutionResult[GeneralLedgerActivityResult]:
            failure_receipts = list(receipts)
            if request is not None and result is not None:
                failure_receipts.append(
                    _receipt(
                        request=request,
                        result=result,
                        blocker=blocker,
                        provenance_valid=provenance_valid,
                        force_failed=not blocked,
                        spec=spec,
                    )
                )
            return PrimitiveExecutionResult(
                status=(
                    PrimitiveExecutionStatus.BLOCKED
                    if blocked
                    else PrimitiveExecutionStatus.FAILED
                ),
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary=blocker.message,
                blockers=[blocker],
                operation_receipts=failure_receipts,
                connector_tool=XERO_JOURNAL_TOOL,
                retryable=blocker.retryable,
            )

        for page_number in range(1, _MAX_XERO_PAGE_READS + 1):
            spec = _read_operation_spec(
                XERO_JOURNAL_TOOL,
                operation_ref=f"general-ledger-activity.read-page-{page_number:03d}",
            )
            request = context.connector_request(
                primitive_ref=self.primitive_ref,
                tool=XERO_JOURNAL_TOOL,
                arguments={"offset": offset},
                effect=ConnectorEffect.READ,
                approval_required=False,
                operation_ref=spec.operation_ref,
                connector_account_ref=account_ref,
                metadata={
                    "source": self.primitive_ref,
                    "page_number": page_number,
                    "offset": offset,
                },
            )
            result = context.connectors.execute(request)
            if result.tool != request.tool:
                return failed(
                    PrimitiveBlocker(
                        code="general_ledger_tool_mismatch",
                        message=(
                            "The connector response is not bound to the requested "
                            "Xero journal Tool."
                        ),
                    ),
                    request=request,
                    result=result,
                    spec=spec,
                )
            if result.status != ConnectorExecutionStatus.COMPLETED:
                blocked = result.status in {
                    ConnectorExecutionStatus.BLOCKED,
                    ConnectorExecutionStatus.PENDING_APPROVAL,
                }
                return failed(
                    PrimitiveBlocker(
                        code="general_ledger_read_failed",
                        message="The governed Xero journal page read did not complete.",
                        retryable=result.retryable,
                    ),
                    request=request,
                    result=result,
                    spec=spec,
                    blocked=blocked,
                )

            provenance: ConnectorExecutionProvenance | None = None
            try:
                provenance = _validate_provenance(
                    result.provenance,
                    request,
                    expected_tool_version=XERO_JOURNAL_TOOL_VERSION,
                )
                completed_at = _normalized_utc_timestamp(
                    provenance.completed_at,
                    field_name="Xero journal page completed_at",
                )
                if provenances:
                    first = provenances[0]
                    if (
                        provenance.tenant_connector_id != first.tenant_connector_id
                        or provenance.connector_account_ref
                        != first.connector_account_ref
                        or provenance.project_id != first.project_id
                        or provenance.route_digest != first.route_digest
                    ):
                        raise _GeneralLedgerError(
                            "general_ledger_provenance_mismatch",
                            "Xero journal pages crossed an exact governed route boundary.",
                        )
                if (
                    provenance.journal_ref in seen_journal_refs
                    or provenance.receipt_digest in seen_receipt_digests
                ):
                    raise _GeneralLedgerError(
                        "general_ledger_provenance_mismatch",
                        "Xero journal pages reused execution provenance.",
                    )
                if (
                    previous_completed_at is not None
                    and completed_at < previous_completed_at
                ):
                    raise _GeneralLedgerError(
                        "general_ledger_provenance_mismatch",
                        "Xero journal page completion times are not monotonic.",
                    )
                page = _xero_journal_page(result.output)
                page_numbers = [_xero_journal_number(journal) for journal in page]
                for journal in page:
                    _validate_xero_journal_content(journal)
                if page_numbers and (
                    page_numbers != sorted(page_numbers)
                    or len(set(page_numbers)) != len(page_numbers)
                    or page_numbers[0] <= offset
                    or any(number in seen_journal_numbers for number in page_numbers)
                ):
                    raise _GeneralLedgerError(
                        "general_ledger_pagination_invalid",
                        "Xero journal pagination overlapped, repeated, or failed to advance.",
                    )
                if len(journals) + len(page) > _MAX_XERO_JOURNALS:
                    raise _GeneralLedgerError(
                        "general_ledger_record_limit_exceeded",
                        "The complete Xero journal history exceeds 10,000 journals.",
                    )
                if page and page_number == _MAX_XERO_PAGE_READS:
                    raise _GeneralLedgerError(
                        "general_ledger_record_limit_exceeded",
                        "Xero did not return an empty terminal page within the bounded history read.",
                    )
            except _GeneralLedgerError as exc:
                return failed(
                    PrimitiveBlocker(
                        code=exc.code,
                        message=exc.message,
                        retryable=exc.retryable,
                    ),
                    request=request,
                    result=result,
                    spec=spec,
                    provenance_valid=provenance is not None,
                )

            assert provenance is not None
            seen_journal_refs.add(provenance.journal_ref)
            seen_receipt_digests.add(provenance.receipt_digest)
            previous_completed_at = completed_at
            provenances.append(provenance)
            page_digests.append(_stable_digest(result.output))
            if not page:
                receipts.append(
                    _receipt(
                        request=request,
                        result=result,
                        provenance_valid=True,
                        spec=spec,
                    )
                )
                try:
                    output = _normalize_xero_journals(
                        journals,
                        inputs=inputs,
                        context=context,
                        provenances=provenances,
                        page_digests=page_digests,
                    )
                except _GeneralLedgerError as exc:
                    return failed(
                        PrimitiveBlocker(
                            code=exc.code,
                            message=exc.message,
                            retryable=exc.retryable,
                        )
                    )
                return PrimitiveExecutionResult(
                    status=PrimitiveExecutionStatus.COMPLETED,
                    primitive_ref=self.primitive_ref,
                    primitive_version=self.version,
                    summary=(
                        f"Discovered {output.line_count} governed Xero General Ledger "
                        "activity lines for one complete month."
                    ),
                    output=output,
                    events=[
                        PrimitiveEvent(
                            type="finance.general_ledger_activity_discovered",
                            payload={
                                "provider": output.provider,
                                "start_date": output.start_date,
                                "end_date": output.end_date,
                                "currency": output.currency,
                                "line_count": output.line_count,
                                "source_digest": output.source_digest,
                            },
                        )
                    ],
                    evidence=[
                        PrimitiveEvidence(
                            kind="governed_general_ledger_activity_observation",
                            summary=(
                                "A complete bounded Xero journal history was read "
                                "through its empty terminal page and the requested "
                                "month was normalized with exact Spring provenance."
                            ),
                            labels=[
                                "xero",
                                "authoritative_read",
                                "complete_history",
                                "monthly",
                                "reconciliation_not_performed",
                                "close_not_advanced",
                            ],
                            refs={"source_digest": output.source_digest},
                        )
                    ],
                    operation_receipts=receipts,
                    connector_tool=XERO_JOURNAL_TOOL,
                )

            journals.extend(page)
            seen_journal_numbers.update(page_numbers)
            offset = page_numbers[-1]
            receipts.append(
                _receipt(
                    request=request,
                    result=result,
                    provenance_valid=True,
                    spec=spec,
                )
            )

        raise AssertionError("bounded Xero journal loop did not terminate")


FINANCE_GENERAL_LEDGER_EXECUTABLE_PRIMITIVES: tuple[
    BusinessProcessPrimitive[Any, Any], ...
] = (DiscoverGeneralLedgerActivityPrimitive(),)


__all__ = [
    "DiscoverGeneralLedgerActivityPrimitive",
    "FINANCE_GENERAL_LEDGER_EXECUTABLE_PRIMITIVES",
    "GENERAL_LEDGER_ACTIVITY_INPUT_SCHEMA",
    "GENERAL_LEDGER_ACTIVITY_LINE_SCHEMA",
    "GENERAL_LEDGER_ACTIVITY_RESULT_SCHEMA",
    "GeneralLedgerActivityInput",
    "GeneralLedgerActivityLine",
    "GeneralLedgerActivityObservation",
    "GeneralLedgerActivityResult",
    "QUICKBOOKS_GENERAL_LEDGER_TOOL",
    "QUICKBOOKS_GENERAL_LEDGER_TOOL_VERSION",
    "XERO_JOURNAL_TOOL",
    "XERO_JOURNAL_TOOL_VERSION",
]
