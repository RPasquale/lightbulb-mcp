"""Typed general-ledger journal lifecycle primitives.

The SDK owns deterministic journal preparation, normalized chart-of-accounts
discovery, and fail-closed recovery proposals.  Spring remains authoritative
for tenant/company/project scope, exact connector-account routing, approval,
the governed execution journal, provider dispatch, and recovery settlement.

Only the reviewed QuickBooks and Xero chart-of-accounts and Trial Balance
governed reads are admitted for ledger discovery. Journal writes use the reviewed
``quickbooks.create_journal_entry`` and ``xero.create_manual_journal`` Tools.
An ambiguous write is never retried or resolved from caller-supplied evidence;
the recovery primitive can describe independently evidenced readback, but only
Spring may settle the execution journal and authorize any continuation.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
from calendar import monthrange
from collections.abc import Mapping, Sequence
from datetime import date, datetime, timezone
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
    HostedConnectorExecutor,
)
from lightbulb.finance_accounting import (
    EvaluateJournalEntryControlsPrimitive,
    JOURNAL_ENTRY_EVALUATION_OPERATION,
    JournalEntryControlEvaluation,
    JournalEntryControlInput,
    evaluate_journal_entry_controls,
)
from lightbulb.primitive_runtime import (
    BusinessProcessPrimitive,
    PrimitiveBlocker,
    PrimitiveEvent,
    PrimitiveEvidence,
    PrimitiveEvidenceRef,
    PrimitiveEvidenceVerificationGrade,
    PrimitiveExecutionContext,
    PrimitiveExecutionResult,
    PrimitiveExecutionStatus,
    PrimitiveOperationFreshnessClass,
    PrimitiveOperationReceipt,
    PrimitiveOperationRecoveryPolicy,
    PrimitiveOperationReplayClass,
    PrimitiveOperationSpec,
    PrimitiveOperationStatus,
    PrimitiveRecoveryDisposition,
    PrimitiveRecoveryPlan,
)

LEDGER_ACCOUNT_DISCOVERY_INPUT_SCHEMA = (
    "lightbulb.finance_ledger_account_discovery_input.v1"
)
LEDGER_ACCOUNT_DISCOVERY_RESULT_SCHEMA = (
    "lightbulb.finance_ledger_account_discovery_result.v2"
)
TRIAL_BALANCE_DISCOVERY_INPUT_SCHEMA = (
    "lightbulb.finance_trial_balance_discovery_input.v1"
)
TRIAL_BALANCE_DISCOVERY_RESULT_SCHEMA = (
    "lightbulb.finance_trial_balance_discovery_result.v2"
)
GOVERNED_LEDGER_READ_RECEIPT_SCHEMA = (
    "lightbulb.finance_governed_ledger_read_receipt.v2"
)
JOURNAL_ENTRY_PREPARATION_INPUT_SCHEMA = (
    "lightbulb.finance_journal_entry_preparation_input.v1"
)
JOURNAL_ENTRY_PREPARATION_SCHEMA = "lightbulb.finance_journal_entry_preparation.v1"
JOURNAL_ENTRY_POST_INPUT_SCHEMA = "lightbulb.finance_journal_entry_post_input.v1"
JOURNAL_ENTRY_POST_RESULT_SCHEMA = "lightbulb.finance_journal_entry_post_result.v2"
JOURNAL_POST_READBACK_SCHEMA = "lightbulb.finance_journal_post_readback.v2"
JOURNAL_POST_RECOVERY_INPUT_SCHEMA = "lightbulb.finance_journal_post_recovery_input.v2"
JOURNAL_POST_RECOVERY_RESULT_SCHEMA = (
    "lightbulb.finance_journal_post_recovery_result.v2"
)
GOVERNED_FINANCE_WRITE_RESULT_SCHEMA = "lightbulb.governed_finance_write_result.v2"
QUICKBOOKS_JOURNAL_EFFECT_SCHEMA = "lightbulb.quickbooks_journal_effect.v1"
_LEGACY_XERO_GOVERNED_FINANCE_WRITE_RESULT_SCHEMA = (
    "lightbulb.governed_finance_write_result.v1"
)

QUICKBOOKS_LIST_ACCOUNTS_TOOL = "quickbooks.list_accounts"
QUICKBOOKS_TRIAL_BALANCE_TOOL = "quickbooks.trial_balance_report"
XERO_LIST_ACCOUNTS_TOOL = "xero.list_accounts"
XERO_TRIAL_BALANCE_TOOL = "xero.trial_balance_report"
QUICKBOOKS_CREATE_JOURNAL_TOOL = "quickbooks.create_journal_entry"
XERO_CREATE_MANUAL_JOURNAL_TOOL = "xero.create_manual_journal"
QUICKBOOKS_GET_JOURNAL_TOOL = "quickbooks.get_journal_entry"
XERO_LIST_JOURNALS_TOOL = "xero.list_journals"

_REVIEWED_TOOL_VERSIONS = {
    QUICKBOOKS_LIST_ACCOUNTS_TOOL: 2,
    QUICKBOOKS_TRIAL_BALANCE_TOOL: 2,
    XERO_LIST_ACCOUNTS_TOOL: 2,
    XERO_TRIAL_BALANCE_TOOL: 2,
    QUICKBOOKS_CREATE_JOURNAL_TOOL: 1,
    XERO_CREATE_MANUAL_JOURNAL_TOOL: 1,
    QUICKBOOKS_GET_JOURNAL_TOOL: 1,
    XERO_LIST_JOURNALS_TOOL: 2,
}

_ACCOUNT_PAGE_SIZE = 500
_MAX_ACCOUNTS = 5_000
_MAX_ACCOUNT_PAGES = _MAX_ACCOUNTS // _ACCOUNT_PAGE_SIZE
_MAX_TRIAL_BALANCE_LINES = 5_000
_MAX_REPORT_COLUMNS = 100
_MAX_REPORT_ROW_DEPTH = 4
_MAX_REPORT_MONEY_CHARS = 64
_AMBIGUOUS_ERROR_CODE = "GOVERNED_EXECUTION_AMBIGUOUS"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_PORTABLE_REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}$"
_CURRENCY_PATTERN = r"^[A-Z]{3}$"
_QUICKBOOKS_CORRELATION_PATTERN = r"^LB-[A-Z2-7]{18}$"
_REPORT_MONEY_PATTERN = re.compile(
    r"^(?:0|[1-9][0-9]*|[1-9][0-9]{0,2}(?:,[0-9]{3})+)(?:\.[0-9]{1,9})?$"
)


def _bounded_visible(value: str) -> str:
    if value != value.strip() or any(ord(character) < 33 for character in value):
        raise ValueError("reference must contain visible characters without whitespace")
    return value


def _canonical_uuid(value: Any, *, field_name: str) -> UUID:
    if isinstance(value, UUID):
        return value
    if not isinstance(value, str) or value != value.strip():
        raise ValueError(f"{field_name} must be a canonical UUID")
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError) as exc:
        raise ValueError(f"{field_name} must be a canonical UUID") from exc
    if str(parsed) != value:
        raise ValueError(f"{field_name} must be a canonical UUID")
    return parsed


def _optional_canonical_uuid(value: Any, *, field_name: str) -> UUID | None:
    if value is None:
        return None
    return _canonical_uuid(value, field_name=field_name)


def _external_uuid(
    external_refs: Mapping[str, str], key: str, *, required: bool
) -> UUID | None:
    value = external_refs.get(key)
    if value is None:
        if required:
            raise ValueError(f"completed post_receipt requires {key}")
        return None
    return _canonical_uuid(value, field_name=key)


def _external_tool_version(
    external_refs: Mapping[str, str], *, required: bool
) -> int | None:
    value = external_refs.get("tool_version")
    if value is None:
        if required:
            raise ValueError("completed post_receipt requires tool_version")
        return None
    if not value.isascii() or not value.isdigit() or str(int(value)) != value:
        raise ValueError("post_receipt tool_version must be canonical")
    return int(value)


def _external_opaque_ref(
    external_refs: Mapping[str, str], key: str, *, required: bool
) -> str | None:
    value = external_refs.get(key)
    if value is None:
        if required:
            raise ValueError(f"completed post_receipt requires {key}")
        return None
    if not re.fullmatch(_PORTABLE_REF_PATTERN, value):
        raise ValueError(f"post_receipt {key} is not a portable reference")
    return _bounded_visible(value)


def _external_sha256(
    external_refs: Mapping[str, str], key: str, *, required: bool
) -> str | None:
    value = external_refs.get(key)
    if value is None:
        if required:
            raise ValueError(f"completed post_receipt requires {key}")
        return None
    if not re.fullmatch(_SHA256_PATTERN, value):
        raise ValueError(f"post_receipt {key} must be a lowercase SHA-256 digest")
    return value


OpaqueRef = Annotated[
    str,
    StringConstraints(pattern=_PORTABLE_REF_PATTERN),
    AfterValidator(_bounded_visible),
]
Sha256Digest = Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)]
CurrencyCode = Annotated[str, StringConstraints(pattern=_CURRENCY_PATTERN)]
QuickBooksJournalCorrelationRef = Annotated[
    str,
    StringConstraints(pattern=_QUICKBOOKS_CORRELATION_PATTERN),
]
JournalProvider = Literal["quickbooks", "xero"]


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


def quickbooks_journal_correlation_ref(entry_ref: str) -> str:
    """Derive the immutable QuickBooks DocNumber correlation key."""

    encoded = base64.b32encode(hashlib.sha256(entry_ref.encode("utf-8")).digest())
    return "LB-" + encoded.decode("ascii").rstrip("=")[:18]


def _normalized_timestamp(value: str, *, field_name: str) -> str:
    if value != value.strip():
        raise ValueError(f"{field_name} must not contain surrounding whitespace")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field_name} must be valid ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field_name} must include a UTC offset")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _decimal_or_none(value: Any) -> Decimal | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool) or not isinstance(value, (str, int, float, Decimal)):
        raise ValueError("account balance must be a decimal value")
    try:
        parsed = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("account balance must be a decimal value") from exc
    if not parsed.is_finite():
        raise ValueError("account balance must be finite")
    return parsed


def _provider_number(value: Decimal) -> int | float:
    """Return a JSON number only when its decimal spelling round-trips exactly."""

    if value == value.to_integral_value():
        integer = int(value)
        if abs(integer) <= 9_007_199_254_740_991:
            return integer
    candidate = float(value)
    if not math.isfinite(candidate) or Decimal(str(candidate)) != value:
        raise ValueError(
            "journal amount is not losslessly representable by the reviewed provider JSON contract"
        )
    return candidate


def _canonical_decimal(value: Decimal) -> str:
    text = format(value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text or "0"


def _provider_tool(provider: JournalProvider) -> str:
    return (
        QUICKBOOKS_CREATE_JOURNAL_TOOL
        if provider == "quickbooks"
        else XERO_CREATE_MANUAL_JOURNAL_TOOL
    )


def _provider_read_tool(provider: JournalProvider) -> str:
    return (
        QUICKBOOKS_GET_JOURNAL_TOOL
        if provider == "quickbooks"
        else XERO_LIST_JOURNALS_TOOL
    )


def _provider_record_type(provider: JournalProvider) -> str:
    return "journal_entry" if provider == "quickbooks" else "manual_journal"


def _account_read_tool(provider: JournalProvider) -> str:
    return (
        QUICKBOOKS_LIST_ACCOUNTS_TOOL
        if provider == "quickbooks"
        else XERO_LIST_ACCOUNTS_TOOL
    )


def _trial_balance_read_tool(provider: JournalProvider) -> str:
    return (
        QUICKBOOKS_TRIAL_BALANCE_TOOL
        if provider == "quickbooks"
        else XERO_TRIAL_BALANCE_TOOL
    )


def _post_operation_spec(provider: JournalProvider) -> PrimitiveOperationSpec:
    return PrimitiveOperationSpec(
        operation_ref="journal-entry.post",
        tool=_provider_tool(provider),
        effect=ConnectorEffect.WRITE,
        approval_required=True,
        atomicity_group="journal-entry-post",
        replay_class=PrimitiveOperationReplayClass.PROBE_BEFORE_RETRY,
        freshness_class=PrimitiveOperationFreshnessClass.CURRENT,
        recovery_policy=PrimitiveOperationRecoveryPolicy.MANUAL_RECONCILIATION,
    )


def _account_read_operation_spec(
    provider: JournalProvider, page_number: int
) -> PrimitiveOperationSpec:
    return PrimitiveOperationSpec(
        operation_ref=f"ledger-accounts.read-page-{page_number}",
        tool=_account_read_tool(provider),
        effect=ConnectorEffect.READ,
        approval_required=False,
        replay_class=PrimitiveOperationReplayClass.SAFE,
        freshness_class=PrimitiveOperationFreshnessClass.CURRENT,
        recovery_policy=PrimitiveOperationRecoveryPolicy.RETRY,
    )


def _trial_balance_read_operation_spec(
    provider: JournalProvider,
) -> PrimitiveOperationSpec:
    return PrimitiveOperationSpec(
        operation_ref="trial-balance.read",
        tool=_trial_balance_read_tool(provider),
        effect=ConnectorEffect.READ,
        approval_required=False,
        replay_class=PrimitiveOperationReplayClass.SAFE,
        freshness_class=PrimitiveOperationFreshnessClass.CURRENT,
        recovery_policy=PrimitiveOperationRecoveryPolicy.RETRY,
    )


JOURNAL_POST_RECOVERY_EVALUATION_OPERATION = PrimitiveOperationSpec(
    operation_ref="journal-post-recovery.evaluate",
    tool="finance.reconcile_journal_post",
    effect=ConnectorEffect.READ,
    approval_required=False,
    replay_class=PrimitiveOperationReplayClass.SAFE,
    freshness_class=PrimitiveOperationFreshnessClass.CURRENT,
    recovery_policy=PrimitiveOperationRecoveryPolicy.NONE,
)


class LedgerAccountDiscoveryInput(_StrictModel):
    schema_id: Literal["lightbulb.finance_ledger_account_discovery_input.v1"] = Field(
        default=LEDGER_ACCOUNT_DISCOVERY_INPUT_SCHEMA,
        alias="schema",
    )
    provider: JournalProvider = "quickbooks"


class GovernedLedgerReadReceipt(_StrictModel):
    """Sanitized source-page custody from one completed Spring-governed read."""

    schema_id: Literal["lightbulb.finance_governed_ledger_read_receipt.v2"] = Field(
        default=GOVERNED_LEDGER_READ_RECEIPT_SCHEMA, alias="schema"
    )
    page_number: int = Field(ge=1, le=_MAX_ACCOUNT_PAGES)
    tool: Literal[
        "quickbooks.list_accounts",
        "quickbooks.trial_balance_report",
        "xero.list_accounts",
        "xero.trial_balance_report",
    ]
    tool_version: Literal[2] = 2
    project_id: UUID
    tenant_connector_id: UUID
    connector_account_ref: OpaqueRef
    route_digest: Sha256Digest
    execution_journal_ref: OpaqueRef
    request_digest: Sha256Digest
    provenance_receipt_digest: Sha256Digest
    completed_at: str
    provider_output_digest: Sha256Digest
    source_page_digest: Sha256Digest

    @field_validator("completed_at")
    @classmethod
    def _completed_timestamp(cls, value: str) -> str:
        return _normalized_timestamp(value, field_name="completed_at")


class LedgerAccount(_StrictModel):
    provider: JournalProvider = "quickbooks"
    account_ref: OpaqueRef
    account_code: str | None = Field(default=None, max_length=160)
    name: str = Field(min_length=1, max_length=500)
    fully_qualified_name: str | None = Field(default=None, max_length=1_000)
    account_type: str | None = Field(default=None, max_length=160)
    account_subtype: str | None = Field(default=None, max_length=160)
    classification: str | None = Field(default=None, max_length=160)
    currency: CurrencyCode | None = None
    active: bool
    current_balance: Decimal | None = None
    source_updated_at: str | None = None
    source_revision_kind: Literal["content_sha256"] | None = None
    source_revision: Sha256Digest | None = None

    @field_validator(
        "name",
        "account_code",
        "fully_qualified_name",
        "account_type",
        "account_subtype",
        "classification",
    )
    @classmethod
    def _bounded_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        clean = value.strip()
        if (
            not clean
            or clean != value
            or any(ord(character) < 32 for character in value)
        ):
            raise ValueError(
                "account text must be non-empty and contain no control characters"
            )
        return value

    @field_validator("current_balance", mode="before")
    @classmethod
    def _balance_decimal(cls, value: Any) -> Decimal | None:
        return _decimal_or_none(value)

    @field_validator("source_updated_at")
    @classmethod
    def _source_timestamp(cls, value: str | None) -> str | None:
        return (
            _normalized_timestamp(value, field_name="source_updated_at")
            if value is not None
            else None
        )

    @model_validator(mode="after")
    def _revision_pair_is_complete(self) -> "LedgerAccount":
        if (self.source_revision_kind is None) != (self.source_revision is None):
            raise ValueError("account source revision fields must be supplied together")
        return self


class LedgerAccountDiscoveryResult(_StrictModel):
    schema_id: Literal["lightbulb.finance_ledger_account_discovery_result.v2"] = Field(
        default=LEDGER_ACCOUNT_DISCOVERY_RESULT_SCHEMA,
        alias="schema",
    )
    provider: JournalProvider = "quickbooks"
    tool: Literal["quickbooks.list_accounts", "xero.list_accounts"] = (
        QUICKBOOKS_LIST_ACCOUNTS_TOOL
    )
    accounts: tuple[LedgerAccount, ...] = Field(max_length=_MAX_ACCOUNTS)
    account_count: int = Field(ge=0, le=_MAX_ACCOUNTS)
    page_count: int = Field(ge=1, le=_MAX_ACCOUNT_PAGES)
    provider_total_count: int | None = Field(default=None, ge=0, le=_MAX_ACCOUNTS)
    complete: Literal[True] = True
    authoritative_read: Literal[True] = True
    source_digest: Sha256Digest
    provider_observed_at: str | None = None
    provenance_receipt_digests: tuple[Sha256Digest, ...] = Field(
        min_length=1,
        max_length=_MAX_ACCOUNT_PAGES,
    )
    read_receipts: tuple[GovernedLedgerReadReceipt, ...] = Field(
        min_length=1,
        max_length=_MAX_ACCOUNT_PAGES,
    )

    @field_validator(
        "accounts",
        "provenance_receipt_digests",
        "read_receipts",
        mode="before",
    )
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value or ())

    @field_validator("provider_observed_at")
    @classmethod
    def _provider_timestamp(cls, value: str | None) -> str | None:
        return (
            _normalized_timestamp(value, field_name="provider_observed_at")
            if value is not None
            else None
        )

    @classmethod
    def source_digest_for(cls, accounts: Sequence[LedgerAccount]) -> str:
        return _stable_digest(
            [
                account.model_dump(mode="json", by_alias=True)
                for account in sorted(accounts, key=lambda item: item.account_ref)
            ]
        )

    @classmethod
    def source_page_digest_for(
        cls,
        *,
        provider: JournalProvider,
        tool: str,
        page_number: int,
        accounts: Sequence[LedgerAccount],
    ) -> str:
        return _stable_digest(
            {
                "schema": "lightbulb.finance_ledger_account_source_page.v1",
                "provider": provider,
                "tool": tool,
                "page_number": page_number,
                "records": [
                    account.model_dump(mode="json", by_alias=True, exclude_none=True)
                    for account in sorted(accounts, key=lambda item: item.account_ref)
                ],
            }
        )

    @model_validator(mode="after")
    def _counts_match(self) -> "LedgerAccountDiscoveryResult":
        if self.tool != _account_read_tool(self.provider):
            raise ValueError("chart-of-accounts Tool must match provider")
        if any(account.provider != self.provider for account in self.accounts):
            raise ValueError("ledger account provider must match result provider")
        if self.account_count != len(self.accounts):
            raise ValueError("account_count must match accounts")
        if self.page_count != len(self.provenance_receipt_digests):
            raise ValueError("page_count must match provenance receipts")
        if self.page_count != len(self.read_receipts):
            raise ValueError("page_count must match governed read receipts")
        if tuple(item.page_number for item in self.read_receipts) != tuple(
            range(1, self.page_count + 1)
        ):
            raise ValueError("governed read receipt pages must be exact and contiguous")
        if any(item.tool != self.tool for item in self.read_receipts):
            raise ValueError("governed read receipt Tool must match account discovery")
        if (
            tuple(item.provenance_receipt_digest for item in self.read_receipts)
            != self.provenance_receipt_digests
        ):
            raise ValueError("governed read receipts must match provenance digests")
        bindings = {
            (
                item.project_id,
                item.tenant_connector_id,
                item.connector_account_ref,
                item.route_digest,
            )
            for item in self.read_receipts
        }
        if len(bindings) != 1:
            raise ValueError("account read pages must use one exact governed binding")
        if (
            self.provider_total_count is not None
            and self.provider_total_count != self.account_count
        ):
            raise ValueError("complete provider total must match account_count")
        if len({account.account_ref for account in self.accounts}) != len(
            self.accounts
        ):
            raise ValueError("ledger account references must be unique")
        if self.source_digest != self.source_digest_for(self.accounts):
            raise ValueError("chart-of-accounts source_digest must seal exact accounts")
        if self.page_count == 1 and self.read_receipts[
            0
        ].source_page_digest != self.source_page_digest_for(
            provider=self.provider,
            tool=self.tool,
            page_number=1,
            accounts=self.accounts,
        ):
            raise ValueError(
                "single-page chart-of-accounts receipt must seal exact accounts"
            )
        return self


class TrialBalanceDiscoveryInput(_StrictModel):
    schema_id: Literal["lightbulb.finance_trial_balance_discovery_input.v1"] = Field(
        default=TRIAL_BALANCE_DISCOVERY_INPUT_SCHEMA,
        alias="schema",
    )
    provider: JournalProvider = "quickbooks"
    start_date: str
    end_date: str

    @model_validator(mode="after")
    def _complete_month(self) -> "TrialBalanceDiscoveryInput":
        try:
            start = date.fromisoformat(self.start_date)
            end = date.fromisoformat(self.end_date)
        except ValueError as exc:
            raise ValueError(
                "trial-balance dates must be exact ISO calendar dates"
            ) from exc
        if start.isoformat() != self.start_date or end.isoformat() != self.end_date:
            raise ValueError("trial-balance dates must use YYYY-MM-DD")
        if start.day != 1 or (start.year, start.month) != (end.year, end.month):
            raise ValueError("trial-balance scope must be one complete calendar month")
        if end.day != monthrange(end.year, end.month)[1]:
            raise ValueError("trial-balance scope must end on the month's final day")
        return self


class DiscoveredTrialBalanceLine(_StrictModel):
    provider: JournalProvider = "quickbooks"
    account_ref: OpaqueRef
    account_name: str = Field(min_length=1, max_length=500)
    currency: CurrencyCode
    debit: Decimal = Field(ge=0)
    credit: Decimal = Field(ge=0)

    @field_validator("account_name")
    @classmethod
    def _account_name(cls, value: str) -> str:
        if value != value.strip() or any(ord(character) < 32 for character in value):
            raise ValueError("trial-balance account name must be bounded visible text")
        return value

    @field_validator("debit", "credit", mode="before")
    @classmethod
    def _exact_money(cls, value: Any) -> Decimal:
        if isinstance(value, Decimal):
            parsed = value
        elif isinstance(value, str) and _REPORT_MONEY_PATTERN.fullmatch(value):
            parsed = Decimal(value.replace(",", ""))
        else:
            raise ValueError("trial-balance money must be a canonical decimal string")
        if not parsed.is_finite():
            raise ValueError("trial-balance money must be finite")
        return parsed

    @model_validator(mode="after")
    def _one_sided_balance(self) -> "DiscoveredTrialBalanceLine":
        if (self.debit == 0) == (self.credit == 0):
            raise ValueError("trial-balance line requires exactly one non-zero side")
        return self


class TrialBalanceDiscoveryResult(_StrictModel):
    schema_id: Literal["lightbulb.finance_trial_balance_discovery_result.v2"] = Field(
        default=TRIAL_BALANCE_DISCOVERY_RESULT_SCHEMA,
        alias="schema",
    )
    provider: JournalProvider = "quickbooks"
    tool: Literal["quickbooks.trial_balance_report", "xero.trial_balance_report"] = (
        QUICKBOOKS_TRIAL_BALANCE_TOOL
    )
    start_date: str
    end_date: str
    currency: CurrencyCode
    lines: tuple[DiscoveredTrialBalanceLine, ...] = Field(
        min_length=2,
        max_length=_MAX_TRIAL_BALANCE_LINES,
    )
    line_count: int = Field(ge=2, le=_MAX_TRIAL_BALANCE_LINES)
    total_debit: Decimal = Field(gt=0)
    total_credit: Decimal = Field(gt=0)
    complete: Literal[True] = True
    authoritative_read: Literal[True] = True
    source_digest: Sha256Digest
    provenance_receipt_digest: Sha256Digest
    read_receipt: GovernedLedgerReadReceipt
    provider_observed_at: str | None = None
    source_updated_at: str | None = None
    source_revision_kind: Literal["content_sha256"] | None = None
    source_revision: Sha256Digest | None = None

    @field_validator("lines", mode="before")
    @classmethod
    def _line_tuple(cls, value: Any) -> Any:
        return tuple(value or ())

    @field_validator("total_debit", "total_credit", mode="before")
    @classmethod
    def _totals(cls, value: Any) -> Decimal:
        if not isinstance(value, Decimal):
            raise ValueError("trial-balance totals must be exact decimals")
        return value

    @field_validator("provider_observed_at", "source_updated_at")
    @classmethod
    def _source_timestamps(cls, value: str | None, info: Any) -> str | None:
        return (
            _normalized_timestamp(value, field_name=info.field_name)
            if value is not None
            else None
        )

    @classmethod
    def source_digest_for(
        cls,
        *,
        start_date: str,
        end_date: str,
        currency: str,
        lines: Sequence[DiscoveredTrialBalanceLine],
    ) -> str:
        return _stable_digest(
            {
                "schema": TRIAL_BALANCE_DISCOVERY_RESULT_SCHEMA,
                "start_date": start_date,
                "end_date": end_date,
                "currency": currency,
                "lines": [
                    line.to_dict()
                    for line in sorted(lines, key=lambda item: item.account_ref)
                ],
            }
        )

    @model_validator(mode="after")
    def _complete_balanced_result(self) -> "TrialBalanceDiscoveryResult":
        if self.tool != _trial_balance_read_tool(self.provider):
            raise ValueError("trial-balance Tool must match provider")
        if (
            self.read_receipt.tool != self.tool
            or self.read_receipt.page_number != 1
            or self.read_receipt.provenance_receipt_digest
            != self.provenance_receipt_digest
            or self.read_receipt.source_page_digest != self.source_digest
        ):
            raise ValueError(
                "trial-balance governed read receipt must bind the exact source"
            )
        if (self.source_revision_kind is None) != (self.source_revision is None):
            raise ValueError(
                "trial-balance source revision fields must be supplied together"
            )
        if self.line_count != len(self.lines):
            raise ValueError("line_count must match trial-balance lines")
        if len({line.account_ref for line in self.lines}) != len(self.lines):
            raise ValueError("trial-balance account references must be unique")
        if any(line.currency != self.currency for line in self.lines):
            raise ValueError("trial-balance line currency must match report currency")
        debit = sum((line.debit for line in self.lines), Decimal(0))
        credit = sum((line.credit for line in self.lines), Decimal(0))
        if self.total_debit != debit or self.total_credit != credit:
            raise ValueError("trial-balance totals must match exact line totals")
        if debit != credit:
            raise ValueError("trial balance must have equal debit and credit totals")
        if self.source_digest != self.source_digest_for(
            start_date=self.start_date,
            end_date=self.end_date,
            currency=self.currency,
            lines=self.lines,
        ):
            raise ValueError("trial-balance source_digest must seal exact lines")
        return self


class QuickBooksValueRef(_StrictModel):
    value: OpaqueRef


class QuickBooksJournalEntryLineDetail(_StrictModel):
    posting_type: Literal["Debit", "Credit"] = Field(alias="PostingType")
    account_ref: QuickBooksValueRef = Field(alias="AccountRef")


class QuickBooksJournalEntryLine(_StrictModel):
    amount: int | float = Field(alias="Amount", gt=0)
    detail_type: Literal["JournalEntryLineDetail"] = Field(
        default="JournalEntryLineDetail",
        alias="DetailType",
    )
    detail: QuickBooksJournalEntryLineDetail = Field(alias="JournalEntryLineDetail")
    line_num: int = Field(alias="LineNum", ge=1, le=1_000)


class QuickBooksJournalEntryPayload(_StrictModel):
    lines: tuple[QuickBooksJournalEntryLine, ...] = Field(
        alias="Line",
        min_length=2,
        max_length=100,
    )
    transaction_date: str = Field(alias="TxnDate")
    document_number: str = Field(alias="DocNumber", min_length=1, max_length=100)
    currency_ref: QuickBooksValueRef = Field(alias="CurrencyRef")
    adjustment: Literal[False] = Field(default=False, alias="Adjustment")

    @field_validator("lines", mode="before")
    @classmethod
    def _lines_tuple(cls, value: Any) -> Any:
        return tuple(value or ())


def quickbooks_journal_effect_sha256(
    payload: QuickBooksJournalEntryPayload | Mapping[str, Any],
) -> str:
    """Commit the provider-stable accounting effect of one QBO journal payload.

    The digest deliberately excludes provider enrichment such as record IDs,
    sync tokens, metadata, names, and response totals. A governed QuickBooks
    read observer can therefore project the returned JournalEntry onto this
    same schema while retaining the raw WRITE and READ response digests as
    separate custody facts.
    """

    parsed = QuickBooksJournalEntryPayload.model_validate(
        payload.to_dict()
        if isinstance(payload, QuickBooksJournalEntryPayload)
        else dict(payload)
    )
    if (
        not re.fullmatch(_PORTABLE_REF_PATTERN, parsed.document_number)
        or _bounded_visible(parsed.document_number) != parsed.document_number
    ):
        raise ValueError("QuickBooks journal effect DocNumber is invalid")
    try:
        if date.fromisoformat(parsed.transaction_date).isoformat() != (
            parsed.transaction_date
        ):
            raise ValueError
    except ValueError as exc:
        raise ValueError("QuickBooks journal effect TxnDate is invalid") from exc
    if not re.fullmatch(_CURRENCY_PATTERN, parsed.currency_ref.value):
        raise ValueError("QuickBooks journal effect CurrencyRef is invalid")
    line_numbers = [line.line_num for line in parsed.lines]
    if len(set(line_numbers)) != len(line_numbers):
        raise ValueError("QuickBooks journal effect line numbers must be unique")
    amounts = tuple(Decimal(str(line.amount)) for line in parsed.lines)
    if any(not amount.is_finite() for amount in amounts):
        raise ValueError("QuickBooks journal effect amounts must be finite")
    debit = sum(
        (
            Decimal(str(line.amount))
            for line in parsed.lines
            if line.detail.posting_type == "Debit"
        ),
        Decimal(0),
    )
    credit = sum(
        (
            Decimal(str(line.amount))
            for line in parsed.lines
            if line.detail.posting_type == "Credit"
        ),
        Decimal(0),
    )
    if debit != credit:
        raise ValueError("QuickBooks journal effect must balance debit and credit")
    effect = {
        "schema": QUICKBOOKS_JOURNAL_EFFECT_SCHEMA,
        "doc_number": parsed.document_number,
        "txn_date": parsed.transaction_date,
        "adjustment": parsed.adjustment,
        "currency": parsed.currency_ref.value,
        "exchange_rate": "1",
        "lines": [
            {
                "account_ref": line.detail.account_ref.value,
                "amount": _canonical_decimal(Decimal(str(line.amount))),
                "line_num": line.line_num,
                "posting_type": line.detail.posting_type,
            }
            for line in sorted(parsed.lines, key=lambda item: item.line_num)
        ],
    }
    return _stable_digest(effect)


class XeroManualJournalLine(_StrictModel):
    account_code: str = Field(alias="AccountCode", min_length=1, max_length=50)
    line_amount: int | float = Field(alias="LineAmount")
    description: str = Field(alias="Description", min_length=1, max_length=4_000)

    @field_validator("line_amount")
    @classmethod
    def _non_zero_amount(cls, value: int | float) -> int | float:
        if value == 0:
            raise ValueError("Xero journal line amount must be non-zero")
        return value


class XeroManualJournalPayload(_StrictModel):
    narration: str = Field(alias="Narration", min_length=1, max_length=4_000)
    journal_lines: tuple[XeroManualJournalLine, ...] = Field(
        alias="JournalLines",
        min_length=2,
        max_length=100,
    )
    transaction_date: str = Field(alias="Date")
    status: Literal["POSTED"] = Field(default="POSTED", alias="Status")

    @field_validator("journal_lines", mode="before")
    @classmethod
    def _lines_tuple(cls, value: Any) -> Any:
        return tuple(value or ())


JournalProviderPayload = QuickBooksJournalEntryPayload | XeroManualJournalPayload


class PrepareJournalEntryInput(_StrictModel):
    schema_id: Literal["lightbulb.finance_journal_entry_preparation_input.v1"] = Field(
        default=JOURNAL_ENTRY_PREPARATION_INPUT_SCHEMA,
        alias="schema",
    )
    provider: JournalProvider
    journal: JournalEntryControlInput

    @model_validator(mode="after")
    def _provider_bounds(self) -> "PrepareJournalEntryInput":
        if len(self.journal.lines) > 100:
            raise ValueError(
                "the reviewed QuickBooks and Xero journal routes support at most 100 lines"
            )
        if self.provider == "quickbooks" and len(self.journal.entry_ref) > 100:
            raise ValueError(
                "QuickBooks journal entry_ref cannot exceed 100 characters"
            )
        if self.provider == "xero" and any(
            len(line.account_ref) > 50 for line in self.journal.lines
        ):
            raise ValueError("Xero account_ref cannot exceed 50 characters")
        return self


class JournalEntryPreparation(_StrictModel):
    schema_id: Literal["lightbulb.finance_journal_entry_preparation.v1"] = Field(
        default=JOURNAL_ENTRY_PREPARATION_SCHEMA,
        alias="schema",
    )
    provider: JournalProvider
    tool: Literal[
        "quickbooks.create_journal_entry",
        "xero.create_manual_journal",
    ]
    entry_ref: OpaqueRef
    control_evaluation: JournalEntryControlEvaluation
    provider_payload: JournalProviderPayload | None = None
    provider_payload_digest: Sha256Digest | None = None
    preparation_digest: Sha256Digest
    ready_for_posting: bool
    posting_authorized: Literal[False] = False
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        default_factory=tuple,
        max_length=200,
    )

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return tuple(value or ())

    @model_validator(mode="after")
    def _payload_matches_readiness(self) -> "JournalEntryPreparation":
        if self.tool != _provider_tool(self.provider):
            raise ValueError("journal preparation Tool must match the provider")
        if self.entry_ref != self.control_evaluation.entry_ref:
            raise ValueError("journal preparation must match the evaluated entry_ref")
        if self.ready_for_posting != (self.control_evaluation.disposition == "ready"):
            raise ValueError("ready_for_posting must match the control disposition")
        if self.ready_for_posting != (self.provider_payload is not None):
            raise ValueError("only a ready preparation may contain provider payload")
        if (self.provider_payload is None) != (self.provider_payload_digest is None):
            raise ValueError("provider payload and digest must be present together")
        if (
            self.provider_payload is not None
            and self.provider_payload_digest
            != _stable_digest(
                self.provider_payload.model_dump(
                    mode="json",
                    by_alias=True,
                    exclude_none=True,
                )
            )
        ):
            raise ValueError("provider_payload_digest does not match provider payload")
        if (
            self.provider == "quickbooks"
            and self.provider_payload is not None
            and not isinstance(self.provider_payload, QuickBooksJournalEntryPayload)
        ):
            raise ValueError("QuickBooks preparation requires a QuickBooks payload")
        if (
            self.provider == "xero"
            and self.provider_payload is not None
            and not isinstance(self.provider_payload, XeroManualJournalPayload)
        ):
            raise ValueError("Xero preparation requires a Xero payload")
        return self


class PostJournalEntryInput(PrepareJournalEntryInput):
    schema_id: Literal["lightbulb.finance_journal_entry_post_input.v1"] = Field(
        default=JOURNAL_ENTRY_POST_INPUT_SCHEMA,
        alias="schema",
    )
    expected_preparation_digest: Sha256Digest
    commit: bool = False


class GovernedJournalWriteResult(_StrictModel):
    schema_id: Literal["lightbulb.governed_finance_write_result.v2"] = Field(
        default=GOVERNED_FINANCE_WRITE_RESULT_SCHEMA,
        alias="schema",
    )
    provider: JournalProvider
    provider_record_type: Literal["journal_entry", "manual_journal"]
    provider_record_ref: OpaqueRef
    write_provider_output_sha256: Sha256Digest
    expected_effect_sha256: Sha256Digest | None = None
    provider_output_sha256: Sha256Digest | None = Field(
        default=None,
        exclude=True,
        repr=False,
        description=(
            "Deprecated raw-digest alias accepted only when it exactly matches "
            "write_provider_output_sha256; it is never semantic evidence."
        ),
    )

    @model_validator(mode="before")
    @classmethod
    def _normalize_safe_legacy_xero(cls, value: Any) -> Any:
        if not isinstance(value, Mapping):
            return value
        payload = dict(value)
        if payload.get("schema") != _LEGACY_XERO_GOVERNED_FINANCE_WRITE_RESULT_SCHEMA:
            return value
        if payload.get("provider") != "xero":
            raise ValueError("legacy governed write results are admitted only for Xero")
        if (
            "write_provider_output_sha256" in payload
            or "expected_effect_sha256" in payload
        ):
            raise ValueError("legacy Xero governed write result is ambiguous")
        raw_digest = payload.pop("provider_output_sha256", None)
        payload["schema"] = GOVERNED_FINANCE_WRITE_RESULT_SCHEMA
        payload["write_provider_output_sha256"] = raw_digest
        return payload

    @model_validator(mode="after")
    def _record_type_matches_provider(self) -> "GovernedJournalWriteResult":
        if self.provider_record_type != _provider_record_type(self.provider):
            raise ValueError("provider record type does not match journal provider")
        if (
            self.provider_output_sha256 is not None
            and self.provider_output_sha256 != self.write_provider_output_sha256
        ):
            raise ValueError(
                "legacy raw provider-output alias conflicts with the WRITE digest"
            )
        if (self.expected_effect_sha256 is not None) != (self.provider == "quickbooks"):
            raise ValueError(
                "only QuickBooks governed writes have a supported semantic effect digest"
            )
        return self


class PostJournalEntryResult(_StrictModel):
    schema_id: Literal["lightbulb.finance_journal_entry_post_result.v2"] = Field(
        default=JOURNAL_ENTRY_POST_RESULT_SCHEMA,
        alias="schema",
    )
    provider: JournalProvider
    tool: Literal[
        "quickbooks.create_journal_entry",
        "xero.create_manual_journal",
    ]
    entry_ref: OpaqueRef
    preparation_digest: Sha256Digest
    state: Literal[
        "preview",
        "pending_approval",
        "posted",
        "blocked",
        "failed",
        "in_doubt",
    ]
    provider_record_ref: OpaqueRef | None = None
    write_provider_output_sha256: Sha256Digest | None = None
    expected_effect_sha256: Sha256Digest | None = None
    execution_journal_ref: OpaqueRef | None = None
    tool_version: int | None = Field(default=None, ge=1)
    project_id: UUID | None = None
    tenant_connector_id: UUID | None = None
    connector_account_ref: OpaqueRef | None = None
    route_digest: Sha256Digest | None = None
    provenance_receipt_digest: Sha256Digest | None = None
    unverified_recovery_journal_locator: OpaqueRef | None = Field(
        default=None,
        description=(
            "Untrusted routing hint from an ambiguous hosted response; Spring must "
            "authenticate, scope, and reauthorize it before recovery."
        ),
    )
    recovery_required: bool = False
    readback_required: bool = False
    automatic_retry_allowed: Literal[False] = False
    additional_posting_authorized: Literal[False] = False

    @field_validator("project_id", "tenant_connector_id", mode="before")
    @classmethod
    def _canonical_lineage_ids(cls, value: Any, info: Any) -> UUID | None:
        return _optional_canonical_uuid(value, field_name=info.field_name)

    @model_validator(mode="after")
    def _state_has_exact_evidence(self) -> "PostJournalEntryResult":
        if self.tool != _provider_tool(self.provider):
            raise ValueError("journal post Tool must match the provider")
        posted = self.state == "posted"
        if posted != (self.provider_record_ref is not None):
            raise ValueError("only a posted journal has a provider record reference")
        if posted != (self.write_provider_output_sha256 is not None):
            raise ValueError("only a posted journal has a raw WRITE output digest")
        if posted != (self.execution_journal_ref is not None):
            raise ValueError(
                "only a posted journal has a Spring execution journal reference"
            )
        lineage = (
            self.tool_version,
            self.project_id,
            self.tenant_connector_id,
            self.connector_account_ref,
            self.route_digest,
            self.provenance_receipt_digest,
        )
        if posted and any(value is None for value in lineage):
            raise ValueError(
                "posted journal requires exact Spring WRITE provenance lineage"
            )
        if not posted and any(value is not None for value in lineage):
            raise ValueError(
                "only a posted journal may retain WRITE provenance lineage"
            )
        if posted and self.tool_version != _REVIEWED_TOOL_VERSIONS[self.tool]:
            raise ValueError("posted journal Tool version is not the reviewed version")
        if posted and self.provider == "quickbooks":
            if self.expected_effect_sha256 is None:
                raise ValueError(
                    "posted QuickBooks journal requires a canonical expected effect digest"
                )
        elif self.expected_effect_sha256 is not None:
            raise ValueError(
                "only a posted QuickBooks journal has a supported expected effect digest"
            )
        if (
            self.unverified_recovery_journal_locator is not None
            and self.state != "in_doubt"
        ):
            raise ValueError(
                "only an in-doubt journal has an unverified recovery locator"
            )
        if self.recovery_required != (self.state == "in_doubt"):
            raise ValueError("only an in-doubt journal requires recovery")
        if self.readback_required != (self.state in {"posted", "in_doubt"}):
            raise ValueError("posted and in-doubt journals require readback")
        return self


class JournalPostReadback(_StrictModel):
    schema_id: Literal["lightbulb.finance_journal_post_readback.v2"] = Field(
        default=JOURNAL_POST_READBACK_SCHEMA,
        alias="schema",
    )
    provider: JournalProvider
    read_tool: Literal[
        "quickbooks.get_journal_entry",
        "xero.list_journals",
    ]
    entry_ref: OpaqueRef
    post_request_digest: Sha256Digest
    preparation_digest: Sha256Digest
    read_tool_version: int = Field(ge=1)
    project_id: UUID
    tenant_connector_id: UUID
    connector_account_ref: OpaqueRef
    route_digest: Sha256Digest
    provenance_receipt_digest: Sha256Digest
    read_execution_journal_ref: OpaqueRef
    governed_read_source_ref: OpaqueRef
    observed_at: str
    state: Literal["found", "not_found", "unknown"]
    provider_record_ref: OpaqueRef | None = None
    read_provider_output_sha256: Sha256Digest | None = None
    observed_effect_sha256: Sha256Digest | None = None
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=1,
        max_length=20,
    )

    @field_validator("project_id", "tenant_connector_id", mode="before")
    @classmethod
    def _canonical_lineage_ids(cls, value: Any, info: Any) -> UUID:
        return _canonical_uuid(value, field_name=info.field_name)

    @field_validator("observed_at")
    @classmethod
    def _timestamp(cls, value: str) -> str:
        return _normalized_timestamp(value, field_name="observed_at")

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return tuple(value or ())

    @model_validator(mode="after")
    def _found_state_has_provider_proof(self) -> "JournalPostReadback":
        if self.read_tool != _provider_read_tool(self.provider):
            raise ValueError("journal readback Tool must match the provider")
        if self.read_tool_version != _REVIEWED_TOOL_VERSIONS[self.read_tool]:
            raise ValueError(
                "journal readback Tool version is not the reviewed version"
            )
        if self.read_execution_journal_ref == self.governed_read_source_ref:
            raise ValueError(
                "read execution journal and governed source references must be distinct"
            )
        found = self.state == "found"
        if found != (self.provider_record_ref is not None):
            raise ValueError("found readback requires a provider record reference")
        if found != (self.read_provider_output_sha256 is not None):
            raise ValueError("found readback requires a raw READ output digest")
        if found and self.provider == "quickbooks":
            if self.observed_effect_sha256 is None:
                raise ValueError(
                    "found QuickBooks readback requires an observed effect digest"
                )
        elif self.observed_effect_sha256 is not None:
            raise ValueError(
                "Xero journal effect fingerprinting is not yet supported"
                if self.provider == "xero"
                else "only a found readback has an observed effect digest"
            )
        evidence_refs = [evidence.evidence_ref for evidence in self.evidence_refs]
        if len(set(evidence_refs)) != len(evidence_refs):
            raise ValueError("journal readback evidence references must be unique")
        evidence_digests = [evidence.sha256 for evidence in self.evidence_refs]
        if len(set(evidence_digests)) != len(evidence_digests):
            raise ValueError("journal readback evidence digests must be unique")
        if any(
            evidence.subject_ref != self.entry_ref for evidence in self.evidence_refs
        ):
            raise ValueError(
                "every journal readback evidence reference must bind the exact entry_ref"
            )
        if any(
            evidence.observed_at != self.observed_at for evidence in self.evidence_refs
        ):
            raise ValueError(
                "every journal readback evidence reference must bind the exact observed_at"
            )
        return self


class ReconcileJournalPostInput(_StrictModel):
    schema_id: Literal["lightbulb.finance_journal_post_recovery_input.v2"] = Field(
        default=JOURNAL_POST_RECOVERY_INPUT_SCHEMA,
        alias="schema",
    )
    provider: JournalProvider
    entry_ref: OpaqueRef
    post_receipt: PrimitiveOperationReceipt
    expected_provider_record_ref: OpaqueRef | None = None
    expected_effect_sha256: Sha256Digest | None = None
    readback: JournalPostReadback

    @model_validator(mode="after")
    def _receipt_and_readback_are_bound(self) -> "ReconcileJournalPostInput":
        expected_spec = _post_operation_spec(self.provider)
        if self.post_receipt.spec != expected_spec:
            raise ValueError(
                "post_receipt does not match the exact journal post operation"
            )
        if self.post_receipt.status not in {
            PrimitiveOperationStatus.COMPLETED,
            PrimitiveOperationStatus.IN_DOUBT,
        }:
            raise ValueError(
                "journal recovery accepts only completed or in-doubt post receipts"
            )
        if (
            self.readback.provider != self.provider
            or self.readback.entry_ref != self.entry_ref
        ):
            raise ValueError(
                "readback does not match the journal provider and entry_ref"
            )
        receipt_entry_ref = self.post_receipt.external_refs.get("entry_ref")
        preparation_digest = self.post_receipt.external_refs.get("preparation_digest")
        if receipt_entry_ref != self.entry_ref or preparation_digest is None:
            raise ValueError("post_receipt is not bound to this exact prepared journal")
        if (
            self.readback.post_request_digest != self.post_receipt.request_digest
            or self.readback.preparation_digest != preparation_digest
        ):
            raise ValueError("readback is not bound to the exact journal post request")
        if (self.expected_provider_record_ref is None) != (
            self.expected_effect_sha256 is None
        ):
            raise ValueError(
                "expected provider record reference and effect digest must be paired"
            )
        external = self.post_receipt.external_refs
        if "provider_output_sha256" in external:
            raise ValueError(
                "legacy ambiguous provider output digests cannot confirm journal effects"
            )
        receipt_record_ref = external.get("provider_record_ref")
        write_output_digest = external.get("write_provider_output_sha256")
        expected_effect_digest = external.get("expected_effect_sha256")
        write_execution_journal_ref = external.get("execution_journal_ref")
        write_tool_version = _external_tool_version(
            external,
            required=self.post_receipt.status == PrimitiveOperationStatus.COMPLETED,
        )
        write_project_id = _external_uuid(
            external,
            "project_id",
            required=self.post_receipt.status == PrimitiveOperationStatus.COMPLETED,
        )
        write_tenant_connector_id = _external_uuid(
            external,
            "tenant_connector_id",
            required=self.post_receipt.status == PrimitiveOperationStatus.COMPLETED,
        )
        write_connector_account_ref = _external_opaque_ref(
            external,
            "connector_account_ref",
            required=self.post_receipt.status == PrimitiveOperationStatus.COMPLETED,
        )
        write_route_digest = _external_sha256(
            external,
            "route_digest",
            required=self.post_receipt.status == PrimitiveOperationStatus.COMPLETED,
        )
        if self.post_receipt.status == PrimitiveOperationStatus.COMPLETED:
            if (
                receipt_record_ref is None
                or write_output_digest is None
                or write_execution_journal_ref is None
                or self.post_receipt.provenance_receipt_digest is None
            ):
                raise ValueError(
                    "completed post_receipt requires exact provider record, raw WRITE evidence, WRITE execution journal custody, and WRITE provenance receipt"
                )
            if (
                write_tool_version
                != _REVIEWED_TOOL_VERSIONS[_provider_tool(self.provider)]
            ):
                raise ValueError(
                    "completed post_receipt Tool version is not the reviewed version"
                )
            if any(
                value is None
                for value in (
                    write_project_id,
                    write_tenant_connector_id,
                    write_connector_account_ref,
                    write_route_digest,
                )
            ):
                raise ValueError(
                    "completed post_receipt requires complete WRITE provenance lineage"
                )
            if self.provider == "quickbooks" and expected_effect_digest is None:
                raise ValueError(
                    "completed QuickBooks post_receipt requires an expected effect digest"
                )
            if self.provider == "xero" and expected_effect_digest is not None:
                raise ValueError(
                    "Xero journal effect fingerprinting is not yet supported"
                )
            if self.expected_provider_record_ref not in {None, receipt_record_ref}:
                raise ValueError(
                    "caller expectations conflict with the completed post receipt"
                )
            if self.expected_effect_sha256 not in {None, expected_effect_digest}:
                raise ValueError(
                    "caller effect expectation conflicts with the completed post receipt"
                )
        else:
            if (
                self.expected_provider_record_ref is not None
                or self.expected_effect_sha256 is not None
            ):
                raise ValueError(
                    "in-doubt recovery cannot accept caller-authored provider expectations"
                )
            trusted_write_refs = {
                "provider_record_ref",
                "write_provider_output_sha256",
                "expected_effect_sha256",
                "execution_journal_ref",
                "tool_version",
                "project_id",
                "tenant_connector_id",
                "connector_account_ref",
                "route_digest",
            }
            if (
                self.post_receipt.provenance_receipt_digest is not None
                or trusted_write_refs.intersection(external)
            ):
                raise ValueError(
                    "in-doubt recovery cannot accept caller-authored WRITE provenance lineage"
                )
        if (
            write_execution_journal_ref is not None
            and len(
                {
                    write_execution_journal_ref,
                    self.readback.read_execution_journal_ref,
                    self.readback.governed_read_source_ref,
                }
            )
            != 3
        ):
            raise ValueError(
                "WRITE journal, READ execution journal, and governed read source references must be pairwise distinct"
            )
        return self


class ReconcileJournalPostResult(_StrictModel):
    schema_id: Literal["lightbulb.finance_journal_post_recovery_result.v2"] = Field(
        default=JOURNAL_POST_RECOVERY_RESULT_SCHEMA,
        alias="schema",
    )
    provider: JournalProvider
    entry_ref: OpaqueRef
    post_request_digest: Sha256Digest
    disposition: Literal[
        "effect_confirmed_candidate",
        "manual_reconciliation_required",
        "readback_mismatch",
        "evidence_insufficient",
    ]
    readback_matches: bool
    expected_provider_record_ref: OpaqueRef | None = None
    observed_provider_record_ref: OpaqueRef | None = None
    write_provider_output_sha256: Sha256Digest | None = None
    read_provider_output_sha256: Sha256Digest | None = None
    expected_effect_sha256: Sha256Digest | None = None
    observed_effect_sha256: Sha256Digest | None = None
    write_execution_journal_ref: OpaqueRef | None = None
    read_execution_journal_ref: OpaqueRef
    governed_read_source_ref: OpaqueRef
    write_tool_version: int | None = Field(default=None, ge=1)
    read_tool_version: int = Field(ge=1)
    write_project_id: UUID | None = None
    read_project_id: UUID
    write_tenant_connector_id: UUID | None = None
    read_tenant_connector_id: UUID
    write_connector_account_ref: OpaqueRef | None = None
    read_connector_account_ref: OpaqueRef
    write_route_digest: Sha256Digest | None = None
    read_route_digest: Sha256Digest
    write_provenance_receipt_digest: Sha256Digest | None = None
    read_provenance_receipt_digest: Sha256Digest
    spring_settlement_required: Literal[True] = True
    replay_permitted: Literal[False] = False
    recovery_plan: PrimitiveRecoveryPlan
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=1,
        max_length=20,
    )
    evaluation_digest: Sha256Digest

    @field_validator(
        "write_project_id",
        "read_project_id",
        "write_tenant_connector_id",
        "read_tenant_connector_id",
        mode="before",
    )
    @classmethod
    def _canonical_lineage_ids(cls, value: Any, info: Any) -> UUID | None:
        if info.field_name.startswith("write_"):
            return _optional_canonical_uuid(value, field_name=info.field_name)
        return _canonical_uuid(value, field_name=info.field_name)

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return tuple(value or ())

    @model_validator(mode="after")
    def _result_remains_non_authoritative(self) -> "ReconcileJournalPostResult":
        if (
            self.recovery_plan.policy
            != PrimitiveOperationRecoveryPolicy.MANUAL_RECONCILIATION
        ):
            raise ValueError(
                "journal recovery must remain manual until Spring settlement"
            )
        if (
            self.recovery_plan.disposition
            != PrimitiveRecoveryDisposition.MANUAL_RECONCILIATION_REQUIRED
        ):
            raise ValueError("journal recovery cannot claim platform settlement")
        if (self.write_execution_journal_ref is None) != (
            self.write_provider_output_sha256 is None
        ):
            raise ValueError(
                "reconciliation results must retain completed WRITE execution journal custody"
            )
        write_lineage = (
            self.write_tool_version,
            self.write_project_id,
            self.write_tenant_connector_id,
            self.write_connector_account_ref,
            self.write_route_digest,
            self.write_provenance_receipt_digest,
        )
        if self.write_execution_journal_ref is not None and any(
            value is None for value in write_lineage
        ):
            raise ValueError(
                "reconciliation results must retain complete WRITE provenance lineage"
            )
        if self.write_execution_journal_ref is None and any(
            value is not None for value in write_lineage
        ):
            raise ValueError(
                "reconciliation results cannot retain partial WRITE provenance lineage"
            )
        if (
            self.read_tool_version
            != _REVIEWED_TOOL_VERSIONS[_provider_read_tool(self.provider)]
        ):
            raise ValueError("reconciliation result READ Tool version is not reviewed")
        if (
            self.write_tool_version is not None
            and self.write_tool_version
            != _REVIEWED_TOOL_VERSIONS[_provider_tool(self.provider)]
        ):
            raise ValueError("reconciliation result WRITE Tool version is not reviewed")
        if (
            self.write_execution_journal_ref is not None
            and len(
                {
                    self.write_execution_journal_ref,
                    self.read_execution_journal_ref,
                    self.governed_read_source_ref,
                }
            )
            != 3
        ):
            raise ValueError(
                "WRITE journal, READ execution journal, and governed read source references must be pairwise distinct"
            )
        if self.disposition == "effect_confirmed_candidate" and (
            not self.readback_matches
            or self.provider != "quickbooks"
            or self.expected_provider_record_ref is None
            or self.expected_provider_record_ref != self.observed_provider_record_ref
            or self.expected_effect_sha256 is None
            or self.expected_effect_sha256 != self.observed_effect_sha256
            or self.write_provider_output_sha256 is None
            or self.read_provider_output_sha256 is None
            or self.write_execution_journal_ref is None
            or self.write_project_id != self.read_project_id
            or self.write_tenant_connector_id != self.read_tenant_connector_id
            or self.write_connector_account_ref != self.read_connector_account_ref
            or self.write_provenance_receipt_digest
            == self.read_provenance_receipt_digest
        ):
            raise ValueError(
                "a confirmed recovery candidate requires matching provider, project, connector account, provider record, semantic effect, and independent provenance receipts"
            )
        if (
            self.disposition
            in {
                "manual_reconciliation_required",
                "readback_mismatch",
            }
            and self.readback_matches
        ):
            raise ValueError(
                "unmatched recovery dispositions cannot claim matching readback"
            )
        return self


class _JournalLifecycleError(ValueError):
    def __init__(self, code: str, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable


def _extract_ref(value: Any) -> str | None:
    if not isinstance(value, Mapping):
        return None
    candidate = (
        value.get("value")
        or value.get("Value")
        or value.get("name")
        or value.get("Name")
    )
    if candidate is None:
        return None
    clean = str(candidate).strip()
    return clean or None


def _normalize_account(value: Mapping[str, Any]) -> LedgerAccount:
    account_ref = str(value.get("Id") or "").strip()
    name = str(value.get("Name") or "").strip()
    if not account_ref or not name:
        raise _JournalLifecycleError(
            "ledger_account_response_invalid",
            "A provider account is missing its stable identifier or name.",
        )
    raw_active = value.get("Active", True)
    if not isinstance(raw_active, bool):
        raise _JournalLifecycleError(
            "ledger_account_response_invalid",
            "A provider account has an invalid active flag.",
        )
    currency = _extract_ref(value.get("CurrencyRef"))
    normalized_currency = currency.upper() if currency else None

    def optional_text(key: str) -> str | None:
        if value.get(key) is None:
            return None
        clean = str(value[key]).strip()
        return clean or None

    try:
        metadata = value.get("MetaData")
        source_updated_at = (
            metadata.get("LastUpdatedTime") if isinstance(metadata, Mapping) else None
        )
        return LedgerAccount(
            provider="quickbooks",
            account_ref=account_ref,
            name=name,
            fully_qualified_name=optional_text("FullyQualifiedName"),
            account_type=optional_text("AccountType"),
            account_subtype=optional_text("AccountSubType"),
            classification=optional_text("Classification"),
            currency=normalized_currency,
            active=raw_active,
            current_balance=value.get("CurrentBalance"),
            source_updated_at=source_updated_at,
            source_revision_kind="content_sha256",
            source_revision=_stable_digest(value),
        )
    except Exception as exc:
        raise _JournalLifecycleError(
            "ledger_account_response_invalid",
            "A provider account failed normalized contract validation.",
        ) from exc


def _normalize_xero_account(value: Mapping[str, Any]) -> LedgerAccount:
    if value.get("provider") != "xero":
        raise _JournalLifecycleError(
            "ledger_account_response_invalid",
            "A Xero account is not bound to the expected provider.",
        )
    required = {
        "account_ref",
        "name",
        "account_type",
        "active",
        "source_revision_kind",
        "source_revision",
    }
    if not required.issubset(value):
        raise _JournalLifecycleError(
            "ledger_account_response_invalid",
            "A Xero account is missing its canonical identity or revision.",
        )
    try:
        return LedgerAccount(
            provider="xero",
            account_ref=value["account_ref"],
            account_code=value.get("account_code"),
            name=value["name"],
            account_type=value["account_type"],
            classification=value.get("classification"),
            currency=value.get("currency"),
            active=value["active"],
            source_updated_at=value.get("source_updated_at"),
            source_revision_kind=value["source_revision_kind"],
            source_revision=value["source_revision"],
        )
    except Exception as exc:
        raise _JournalLifecycleError(
            "ledger_account_response_invalid",
            "A Xero account failed canonical contract validation.",
        ) from exc


def _account_source_page_digest(
    *,
    provider: JournalProvider,
    tool: str,
    page_number: int,
    accounts: list[LedgerAccount],
) -> str:
    return LedgerAccountDiscoveryResult.source_page_digest_for(
        provider=provider,
        tool=tool,
        page_number=page_number,
        accounts=accounts,
    )


def _report_text(value: Any, *, field_name: str, maximum: int = 500) -> str:
    if not isinstance(value, str):
        raise _JournalLifecycleError(
            "trial_balance_response_invalid",
            f"The provider Trial Balance {field_name} is missing or malformed.",
        )
    clean = value.strip()
    if (
        not clean
        or clean != value
        or len(value) > maximum
        or any(ord(character) < 32 for character in value)
    ):
        raise _JournalLifecycleError(
            "trial_balance_response_invalid",
            f"The provider Trial Balance {field_name} is missing or malformed.",
        )
    return value


def _trial_balance_column_positions(
    report: Mapping[str, Any],
) -> dict[str, int]:
    columns = report.get("Columns")
    if not isinstance(columns, Mapping):
        raise _JournalLifecycleError(
            "trial_balance_response_invalid",
            "The provider Trial Balance column contract is missing.",
        )
    raw_columns = columns.get("Column")
    if (
        not isinstance(raw_columns, list)
        or not 1 <= len(raw_columns) <= _MAX_REPORT_COLUMNS
    ):
        raise _JournalLifecycleError(
            "trial_balance_response_invalid",
            "The provider Trial Balance columns are malformed or exceed their bound.",
        )
    positions: dict[str, int] = {}
    for index, raw_column in enumerate(raw_columns):
        if not isinstance(raw_column, Mapping):
            raise _JournalLifecycleError(
                "trial_balance_response_invalid",
                "The provider Trial Balance contains a malformed column.",
            )
        raw_role = raw_column.get("ColType") or raw_column.get("ColTitle")
        role = re.sub(
            r"[^a-z]",
            "",
            _report_text(raw_role, field_name="column role", maximum=100).lower(),
        )
        role = {"accountname": "account"}.get(role, role)
        if role not in {"account", "debit", "credit"} or role in positions:
            raise _JournalLifecycleError(
                "trial_balance_response_invalid",
                "The provider Trial Balance must expose one Account, Debit, and Credit column.",
            )
        positions[role] = index
    if set(positions) != {"account", "debit", "credit"}:
        raise _JournalLifecycleError(
            "trial_balance_response_invalid",
            "The provider Trial Balance must expose one Account, Debit, and Credit column.",
        )
    return positions


def _trial_balance_data_rows(
    report: Mapping[str, Any],
) -> tuple[Mapping[str, Any], ...]:
    candidates: list[Mapping[str, Any]] = []
    visited = 0

    def visit_rows(container: Any, depth: int) -> None:
        nonlocal visited
        if depth > _MAX_REPORT_ROW_DEPTH or not isinstance(container, Mapping):
            raise _JournalLifecycleError(
                "trial_balance_response_invalid",
                "The provider Trial Balance row hierarchy is malformed or too deep.",
            )
        rows = container.get("Row")
        if not isinstance(rows, list) or len(rows) > _MAX_TRIAL_BALANCE_LINES:
            raise _JournalLifecycleError(
                "trial_balance_response_invalid",
                "The provider Trial Balance rows are malformed or exceed their bound.",
            )
        for row in rows:
            visited += 1
            if visited > _MAX_TRIAL_BALANCE_LINES:
                raise _JournalLifecycleError(
                    "trial_balance_response_invalid",
                    "The provider Trial Balance exceeds its total row bound.",
                )
            if not isinstance(row, Mapping):
                raise _JournalLifecycleError(
                    "trial_balance_response_invalid",
                    "The provider Trial Balance contains a malformed row.",
                )
            row_type = _report_text(
                row.get("type") or "Data",
                field_name="row type",
                maximum=20,
            ).lower()
            if row_type not in {"data", "section"}:
                raise _JournalLifecycleError(
                    "trial_balance_response_invalid",
                    "The provider Trial Balance contains an unsupported row type.",
                )
            if "ColData" in row and row_type == "data":
                candidates.append(row)
            nested = row.get("Rows")
            if nested is not None:
                visit_rows(nested, depth + 1)

    rows = report.get("Rows")
    visit_rows(rows, 0)
    return tuple(candidates)


def _trial_balance_money(value: Any) -> Decimal:
    if value in (None, ""):
        return Decimal(0)
    if (
        not isinstance(value, str)
        or len(value) > _MAX_REPORT_MONEY_CHARS
        or not _REPORT_MONEY_PATTERN.fullmatch(value)
    ):
        raise _JournalLifecycleError(
            "trial_balance_response_invalid",
            "The provider Trial Balance contains a non-canonical monetary value.",
        )
    parsed = Decimal(value.replace(",", ""))
    if not parsed.is_finite() or parsed < 0:
        raise _JournalLifecycleError(
            "trial_balance_response_invalid",
            "The provider Trial Balance contains an invalid monetary value.",
        )
    return parsed


def _normalize_trial_balance(
    output: Mapping[str, Any],
    inputs: TrialBalanceDiscoveryInput,
    request: ConnectorExecutionRequest,
    provenance: ConnectorExecutionProvenance,
) -> TrialBalanceDiscoveryResult:
    header = output.get("Header")
    if not isinstance(header, Mapping):
        raise _JournalLifecycleError(
            "trial_balance_response_invalid",
            "The provider Trial Balance header is missing.",
        )
    report_name = re.sub(
        r"[^a-z]",
        "",
        _report_text(header.get("ReportName"), field_name="report name").lower(),
    )
    start_date = _report_text(header.get("StartPeriod"), field_name="start period")
    end_date = _report_text(header.get("EndPeriod"), field_name="end period")
    currency = _report_text(
        header.get("Currency"), field_name="currency", maximum=3
    ).upper()
    if (
        report_name != "trialbalance"
        or start_date != inputs.start_date
        or end_date != inputs.end_date
        or not re.fullmatch(_CURRENCY_PATTERN, currency)
    ):
        raise _JournalLifecycleError(
            "trial_balance_scope_mismatch",
            "The provider Trial Balance does not match the exact requested period and currency contract.",
        )

    positions = _trial_balance_column_positions(output)
    lines: list[DiscoveredTrialBalanceLine] = []
    seen_refs: set[str] = set()
    for row in _trial_balance_data_rows(output):
        raw_cells = row.get("ColData")
        if not isinstance(raw_cells, list) or len(raw_cells) != len(positions):
            raise _JournalLifecycleError(
                "trial_balance_response_invalid",
                "The provider Trial Balance row does not match its column contract.",
            )
        if any(not isinstance(cell, Mapping) for cell in raw_cells):
            raise _JournalLifecycleError(
                "trial_balance_response_invalid",
                "The provider Trial Balance contains a malformed cell.",
            )
        account_cell = raw_cells[positions["account"]]
        debit_cell = raw_cells[positions["debit"]]
        credit_cell = raw_cells[positions["credit"]]
        raw_account_ref = account_cell.get("id")
        raw_account_name = account_cell.get("value")
        if raw_account_ref is not None and not isinstance(raw_account_ref, str):
            raise _JournalLifecycleError(
                "trial_balance_response_invalid",
                "A provider Trial Balance account identifier is malformed.",
            )
        if raw_account_name is not None and not isinstance(raw_account_name, str):
            raise _JournalLifecycleError(
                "trial_balance_response_invalid",
                "A provider Trial Balance account name is malformed.",
            )
        account_ref = raw_account_ref or ""
        account_name = raw_account_name or ""
        debit = _trial_balance_money(debit_cell.get("value"))
        credit = _trial_balance_money(credit_cell.get("value"))
        if not account_ref and not account_name and debit == 0 and credit == 0:
            continue
        if not account_ref or not account_name:
            raise _JournalLifecycleError(
                "trial_balance_response_invalid",
                "A provider Trial Balance line is missing its stable account identity.",
            )
        if account_ref != account_ref.strip() or account_name != account_name.strip():
            raise _JournalLifecycleError(
                "trial_balance_response_invalid",
                "A provider Trial Balance account identity is not canonical text.",
            )
        if account_ref in seen_refs:
            raise _JournalLifecycleError(
                "trial_balance_response_invalid",
                "The provider Trial Balance contains a duplicate account line.",
            )
        if debit == 0 and credit == 0:
            continue
        try:
            line = DiscoveredTrialBalanceLine(
                account_ref=account_ref,
                account_name=account_name,
                currency=currency,
                debit=debit,
                credit=credit,
            )
        except Exception as exc:
            raise _JournalLifecycleError(
                "trial_balance_response_invalid",
                "A provider Trial Balance line failed canonical validation.",
            ) from exc
        seen_refs.add(account_ref)
        lines.append(line)

    normalized = tuple(sorted(lines, key=lambda item: item.account_ref))
    total_debit = sum((line.debit for line in normalized), Decimal(0))
    total_credit = sum((line.credit for line in normalized), Decimal(0))
    source_digest = TrialBalanceDiscoveryResult.source_digest_for(
        start_date=inputs.start_date,
        end_date=inputs.end_date,
        currency=currency,
        lines=normalized,
    )
    try:
        return TrialBalanceDiscoveryResult(
            provider="quickbooks",
            tool=QUICKBOOKS_TRIAL_BALANCE_TOOL,
            start_date=inputs.start_date,
            end_date=inputs.end_date,
            currency=currency,
            lines=normalized,
            line_count=len(normalized),
            total_debit=total_debit,
            total_credit=total_credit,
            source_digest=source_digest,
            provenance_receipt_digest=provenance.receipt_digest,
            read_receipt=_governed_read_receipt(
                page_number=1,
                request=request,
                provenance=provenance,
                provider_output_digest=_stable_digest(output),
                source_page_digest=source_digest,
            ),
        )
    except Exception as exc:
        raise _JournalLifecycleError(
            "trial_balance_response_invalid",
            "The provider Trial Balance is incomplete or unbalanced.",
        ) from exc


def _normalize_xero_trial_balance(
    output: Mapping[str, Any],
    inputs: TrialBalanceDiscoveryInput,
    request: ConnectorExecutionRequest,
    provenance: ConnectorExecutionProvenance,
) -> TrialBalanceDiscoveryResult:
    if (
        output.get("schema") != "lightbulb.xero_trial_balance.v1"
        or output.get("provider") != "xero"
        or output.get("dataset") != "trial_balance"
        or output.get("start_date") != inputs.start_date
        or output.get("end_date") != inputs.end_date
    ):
        raise _JournalLifecycleError(
            "trial_balance_scope_mismatch",
            "The Xero Trial Balance does not match the requested canonical month.",
        )
    raw_currency = output.get("currency")
    raw_lines = output.get("lines")
    raw_count = output.get("line_count")
    if (
        not isinstance(raw_currency, str)
        or not re.fullmatch(_CURRENCY_PATTERN, raw_currency)
        or not isinstance(raw_lines, list)
        or not 2 <= len(raw_lines) <= _MAX_TRIAL_BALANCE_LINES
        or isinstance(raw_count, bool)
        or not isinstance(raw_count, int)
        or raw_count != len(raw_lines)
    ):
        raise _JournalLifecycleError(
            "trial_balance_response_invalid",
            "The Xero Trial Balance canonical line contract is malformed.",
        )
    lines: list[DiscoveredTrialBalanceLine] = []
    for raw_line in raw_lines:
        if not isinstance(raw_line, Mapping) or raw_line.get("provider") != "xero":
            raise _JournalLifecycleError(
                "trial_balance_response_invalid",
                "The Xero Trial Balance contains a malformed canonical line.",
            )
        try:
            lines.append(
                DiscoveredTrialBalanceLine(
                    provider="xero",
                    account_ref=raw_line.get("account_ref"),
                    account_name=raw_line.get("account_name"),
                    currency=raw_line.get("currency"),
                    debit=raw_line.get("debit"),
                    credit=raw_line.get("credit"),
                )
            )
        except Exception as exc:
            raise _JournalLifecycleError(
                "trial_balance_response_invalid",
                "A Xero Trial Balance line failed canonical validation.",
            ) from exc
    normalized = tuple(sorted(lines, key=lambda item: item.account_ref))
    if len({line.account_ref for line in normalized}) != len(normalized):
        raise _JournalLifecycleError(
            "trial_balance_response_invalid",
            "The Xero Trial Balance contains duplicate account lines.",
        )
    total_debit = sum((line.debit for line in normalized), Decimal(0))
    total_credit = sum((line.credit for line in normalized), Decimal(0))
    if str(output.get("total_debit")) != _canonical_decimal(total_debit) or str(
        output.get("total_credit")
    ) != _canonical_decimal(total_credit):
        raise _JournalLifecycleError(
            "trial_balance_response_invalid",
            "The Xero Trial Balance totals do not match its canonical lines.",
        )
    provider_observed_at = output.get("provider_observed_at")
    report_updated_at = output.get("report_updated_at")
    source_revision_kind = output.get("source_revision_kind")
    source_revision = output.get("source_revision")
    if (
        not isinstance(provider_observed_at, str)
        or not isinstance(report_updated_at, str)
        or source_revision_kind != "content_sha256"
        or not isinstance(source_revision, str)
        or not re.fullmatch(_SHA256_PATTERN, source_revision)
    ):
        raise _JournalLifecycleError(
            "trial_balance_response_invalid",
            "The Xero Trial Balance observation revision is malformed.",
        )
    source_digest = TrialBalanceDiscoveryResult.source_digest_for(
        start_date=inputs.start_date,
        end_date=inputs.end_date,
        currency=raw_currency,
        lines=normalized,
    )
    try:
        return TrialBalanceDiscoveryResult(
            provider="xero",
            tool=XERO_TRIAL_BALANCE_TOOL,
            start_date=inputs.start_date,
            end_date=inputs.end_date,
            currency=raw_currency,
            lines=normalized,
            line_count=len(normalized),
            total_debit=total_debit,
            total_credit=total_credit,
            source_digest=source_digest,
            provenance_receipt_digest=provenance.receipt_digest,
            read_receipt=_governed_read_receipt(
                page_number=1,
                request=request,
                provenance=provenance,
                provider_output_digest=_stable_digest(output),
                source_page_digest=source_digest,
            ),
            provider_observed_at=provider_observed_at,
            source_updated_at=report_updated_at,
            source_revision_kind="content_sha256",
            source_revision=source_revision,
        )
    except Exception as exc:
        raise _JournalLifecycleError(
            "trial_balance_response_invalid",
            "The Xero Trial Balance is incomplete or unbalanced.",
        ) from exc


def _validate_provenance(
    provenance: ConnectorExecutionProvenance | None,
    request: ConnectorExecutionRequest,
) -> ConnectorExecutionProvenance:
    if provenance is None:
        raise _JournalLifecycleError(
            "connector_provenance_missing",
            "The governed connector result has no Spring provenance.",
        )
    if (
        provenance.tool != request.tool
        or provenance.tool_version != _REVIEWED_TOOL_VERSIONS.get(request.tool)
        or provenance.server_effect != request.effect
        or provenance.connector_account_ref != request.connector_account_ref
        or request.scope.project_id is None
        or provenance.project_id != request.scope.project_id
        or provenance.request_digest != request.custody_fingerprint()
        or (
            request.effect == ConnectorEffect.WRITE
            and provenance.approval_ref != request.approval_ref
        )
    ):
        raise _JournalLifecycleError(
            "connector_provenance_mismatch",
            "The governed connector provenance does not match this exact request.",
        )
    return provenance


def _governed_read_receipt(
    *,
    page_number: int,
    request: ConnectorExecutionRequest,
    provenance: ConnectorExecutionProvenance,
    provider_output_digest: str,
    source_page_digest: str,
) -> GovernedLedgerReadReceipt:
    return GovernedLedgerReadReceipt(
        page_number=page_number,
        tool=request.tool,
        tool_version=provenance.tool_version,
        project_id=provenance.project_id,
        tenant_connector_id=provenance.tenant_connector_id,
        connector_account_ref=provenance.connector_account_ref,
        route_digest=provenance.route_digest,
        execution_journal_ref=provenance.journal_ref,
        request_digest=provenance.request_digest,
        provenance_receipt_digest=provenance.receipt_digest,
        completed_at=provenance.completed_at,
        provider_output_digest=provider_output_digest,
        source_page_digest=source_page_digest,
    )


def _read_receipt(
    *,
    provider: JournalProvider,
    page_number: int,
    request: ConnectorExecutionRequest,
    result: ConnectorExecutionResult,
) -> PrimitiveOperationReceipt:
    status = {
        ConnectorExecutionStatus.COMPLETED: PrimitiveOperationStatus.COMPLETED,
        ConnectorExecutionStatus.PREVIEW: PrimitiveOperationStatus.PREVIEW,
        ConnectorExecutionStatus.PENDING_APPROVAL: PrimitiveOperationStatus.BLOCKED,
        ConnectorExecutionStatus.BLOCKED: PrimitiveOperationStatus.BLOCKED,
        ConnectorExecutionStatus.FAILED: PrimitiveOperationStatus.FAILED,
    }[result.status]
    provenance = result.provenance
    external_refs = (
        {
            "execution_journal_ref": provenance.journal_ref,
            "route_digest": provenance.route_digest,
        }
        if provenance is not None
        else {}
    )
    blocker = None
    if status in {PrimitiveOperationStatus.BLOCKED, PrimitiveOperationStatus.FAILED}:
        blocker = PrimitiveBlocker(
            code="ledger_account_read_failed",
            message="The governed chart-of-accounts read did not complete.",
            retryable=result.retryable,
        )
    return PrimitiveOperationReceipt(
        spec=_account_read_operation_spec(provider, page_number),
        status=status,
        request_digest=request.custody_fingerprint(),
        provenance_receipt_digest=(
            provenance.receipt_digest if provenance is not None else None
        ),
        external_refs=external_refs,
        replayed=result.cached,
        error=blocker,
    )


def _trial_balance_receipt(
    *,
    provider: JournalProvider,
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
        spec=_trial_balance_read_operation_spec(provider),
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
        error=blocker,
    )


def prepare_journal_entry(
    inputs: PrepareJournalEntryInput,
) -> JournalEntryPreparation:
    evaluation = evaluate_journal_entry_controls(inputs.journal)
    payload: JournalProviderPayload | None = None
    payload_digest: str | None = None
    ready = evaluation.disposition == "ready"
    if ready:
        payload = _journal_provider_payload(inputs.provider, inputs.journal)
        payload_dump = payload.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        )
        payload_digest = _stable_digest(payload_dump)
    digest_payload = {
        "schema": JOURNAL_ENTRY_PREPARATION_SCHEMA,
        "provider": inputs.provider,
        "tool": _provider_tool(inputs.provider),
        "entry_ref": inputs.journal.entry_ref,
        "journal": inputs.journal.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        ),
        "control_evaluation_digest": evaluation.evaluation_digest,
        "provider_payload_digest": payload_digest,
        "ready_for_posting": ready,
    }
    return JournalEntryPreparation(
        provider=inputs.provider,
        tool=_provider_tool(inputs.provider),
        entry_ref=inputs.journal.entry_ref,
        control_evaluation=evaluation,
        provider_payload=payload,
        provider_payload_digest=payload_digest,
        preparation_digest=_stable_digest(digest_payload),
        ready_for_posting=ready,
        evidence_refs=inputs.journal.evidence_refs,
    )


def _journal_provider_payload(
    provider: JournalProvider,
    journal: JournalEntryControlInput,
) -> JournalProviderPayload:
    if provider == "quickbooks":
        return QuickBooksJournalEntryPayload(
            Line=tuple(
                QuickBooksJournalEntryLine(
                    Amount=_provider_number(line.debit or line.credit),
                    LineNum=index,
                    JournalEntryLineDetail=QuickBooksJournalEntryLineDetail(
                        PostingType="Debit" if line.debit > 0 else "Credit",
                        AccountRef=QuickBooksValueRef(value=line.account_ref),
                    ),
                )
                for index, line in enumerate(journal.lines, start=1)
            ),
            TxnDate=journal.entry_date,
            DocNumber=journal.entry_ref,
            CurrencyRef=QuickBooksValueRef(value=journal.transaction_currency),
        )
    return XeroManualJournalPayload(
        Narration=journal.entry_ref,
        JournalLines=tuple(
            XeroManualJournalLine(
                AccountCode=line.account_ref,
                LineAmount=_provider_number(line.debit - line.credit),
                Description=line.line_ref,
            )
            for line in journal.lines
        ),
        Date=journal.entry_date,
    )


def _preparation_receipt(
    preparation: JournalEntryPreparation,
) -> PrimitiveOperationReceipt:
    return PrimitiveOperationReceipt(
        spec=JOURNAL_ENTRY_EVALUATION_OPERATION,
        status=PrimitiveOperationStatus.COMPLETED,
        request_digest=preparation.control_evaluation.operation_digest,
        external_refs={
            "control_evaluation_digest": preparation.control_evaluation.evaluation_digest,
            "preparation_digest": preparation.preparation_digest,
        },
        evidence_refs=list(preparation.evidence_refs),
    )


def _post_output(
    preparation: JournalEntryPreparation,
    *,
    state: Literal[
        "preview",
        "pending_approval",
        "posted",
        "blocked",
        "failed",
        "in_doubt",
    ],
    write_result: GovernedJournalWriteResult | None = None,
    execution_journal_ref: str | None = None,
    provenance: ConnectorExecutionProvenance | None = None,
    unverified_recovery_journal_locator: str | None = None,
) -> PostJournalEntryResult:
    return PostJournalEntryResult(
        provider=preparation.provider,
        tool=preparation.tool,
        entry_ref=preparation.entry_ref,
        preparation_digest=preparation.preparation_digest,
        state=state,
        provider_record_ref=(
            write_result.provider_record_ref if write_result is not None else None
        ),
        write_provider_output_sha256=(
            write_result.write_provider_output_sha256
            if write_result is not None
            else None
        ),
        expected_effect_sha256=(
            write_result.expected_effect_sha256 if write_result is not None else None
        ),
        execution_journal_ref=execution_journal_ref,
        tool_version=provenance.tool_version if provenance is not None else None,
        project_id=provenance.project_id if provenance is not None else None,
        tenant_connector_id=(
            provenance.tenant_connector_id if provenance is not None else None
        ),
        connector_account_ref=(
            provenance.connector_account_ref if provenance is not None else None
        ),
        route_digest=provenance.route_digest if provenance is not None else None,
        provenance_receipt_digest=(
            provenance.receipt_digest if provenance is not None else None
        ),
        unverified_recovery_journal_locator=unverified_recovery_journal_locator,
        recovery_required=state == "in_doubt",
        readback_required=state in {"posted", "in_doubt"},
    )


def _manual_recovery_plan() -> PrimitiveRecoveryPlan:
    return PrimitiveRecoveryPlan(
        policy=PrimitiveOperationRecoveryPolicy.MANUAL_RECONCILIATION,
        disposition=PrimitiveRecoveryDisposition.MANUAL_RECONCILIATION_REQUIRED,
        instructions=(
            "Use independently verified provider readback, then ask Spring to settle "
            "the exact governed execution journal. Do not resend automatically."
        ),
    )


def _in_doubt_post_result(
    preparation: JournalEntryPreparation,
    *,
    spec: PrimitiveOperationSpec,
    request_digest: str,
    blocker_code: str,
    blocker_message: str,
    summary: str,
    unverified_recovery_journal_locator: str | None = None,
) -> PrimitiveExecutionResult[PostJournalEntryResult]:
    recovery_plan = _manual_recovery_plan()
    blocker = PrimitiveBlocker(
        code=blocker_code,
        message=blocker_message,
        retryable=False,
    )
    receipt = PrimitiveOperationReceipt(
        spec=spec,
        status=PrimitiveOperationStatus.IN_DOUBT,
        request_digest=request_digest,
        external_refs={
            "entry_ref": preparation.entry_ref,
            "preparation_digest": preparation.preparation_digest,
        },
        evidence_refs=list(preparation.evidence_refs),
        recovery_disposition=PrimitiveRecoveryDisposition.MANUAL_RECONCILIATION_REQUIRED,
        recovery_plan=recovery_plan,
        error=blocker,
    )
    return PrimitiveExecutionResult(
        status=PrimitiveExecutionStatus.FAILED,
        primitive_ref=PostJournalEntryPrimitive.primitive_ref,
        primitive_version=PostJournalEntryPrimitive.version,
        summary=summary,
        output=_post_output(
            preparation,
            state="in_doubt",
            unverified_recovery_journal_locator=unverified_recovery_journal_locator,
        ),
        events=[
            PrimitiveEvent(
                type="finance.journal_entry_post_in_doubt",
                payload={
                    "provider": preparation.provider,
                    "entry_ref": preparation.entry_ref,
                    "request_digest": request_digest,
                },
            )
        ],
        evidence_refs=list(preparation.evidence_refs),
        operation_receipts=[receipt],
        recovery_plan=recovery_plan,
        blockers=[blocker],
        connector_tool=spec.tool,
        retryable=False,
    )


def _example_journal() -> dict[str, Any]:
    return json.loads(
        json.dumps(dict(EvaluateJournalEntryControlsPrimitive.example_inputs))
    )


def _prepare_example_inputs() -> dict[str, Any]:
    return {
        "provider": "quickbooks",
        "journal": _example_journal(),
    }


def _example_preparation() -> JournalEntryPreparation:
    return prepare_journal_entry(
        PrepareJournalEntryInput.model_validate(_prepare_example_inputs())
    )


def _post_example_inputs() -> dict[str, Any]:
    preparation = _example_preparation()
    return {
        **_prepare_example_inputs(),
        "expected_preparation_digest": preparation.preparation_digest,
        "commit": False,
    }


def _reconcile_example_inputs() -> dict[str, Any]:
    preparation = _example_preparation()
    request_digest = "d" * 64
    write_output_digest = "e" * 64
    read_output_digest = "b" * 64
    if not isinstance(preparation.provider_payload, QuickBooksJournalEntryPayload):
        raise RuntimeError("QuickBooks example preparation is required")
    effect_digest = quickbooks_journal_effect_sha256(preparation.provider_payload)
    provider_record_ref = "quickbooks-journal-example"
    receipt = PrimitiveOperationReceipt(
        spec=_post_operation_spec("quickbooks"),
        status=PrimitiveOperationStatus.COMPLETED,
        request_digest=request_digest,
        approval_ref="approval-journal-example",
        provenance_receipt_digest="f" * 64,
        external_refs={
            "execution_journal_ref": "execution-journal:quickbooks-write-example",
            "tool_version": "1",
            "project_id": "00000000-0000-0000-0000-000000000401",
            "tenant_connector_id": "00000000-0000-0000-0000-000000000402",
            "connector_account_ref": "quickbooks-account-1",
            "route_digest": "7" * 64,
            "entry_ref": preparation.entry_ref,
            "preparation_digest": preparation.preparation_digest,
            "provider_record_ref": provider_record_ref,
            "write_provider_output_sha256": write_output_digest,
            "expected_effect_sha256": effect_digest,
        },
    )
    return {
        "provider": "quickbooks",
        "entry_ref": preparation.entry_ref,
        "post_receipt": receipt.to_dict(),
        "expected_provider_record_ref": provider_record_ref,
        "expected_effect_sha256": effect_digest,
        "readback": {
            "provider": "quickbooks",
            "read_tool": QUICKBOOKS_GET_JOURNAL_TOOL,
            "entry_ref": preparation.entry_ref,
            "post_request_digest": request_digest,
            "preparation_digest": preparation.preparation_digest,
            "read_tool_version": 1,
            "project_id": "00000000-0000-0000-0000-000000000401",
            "tenant_connector_id": "00000000-0000-0000-0000-000000000402",
            "connector_account_ref": "quickbooks-account-1",
            "route_digest": "8" * 64,
            "provenance_receipt_digest": "9" * 64,
            "read_execution_journal_ref": "execution-journal:quickbooks-read-example",
            "governed_read_source_ref": "finance.read-source.example",
            "observed_at": "2026-08-25T12:05:00Z",
            "state": "found",
            "provider_record_ref": provider_record_ref,
            "read_provider_output_sha256": read_output_digest,
            "observed_effect_sha256": effect_digest,
            "evidence_refs": [
                {
                    "schema": "lightbulb.primitive_evidence_ref.v1",
                    "evidence_ref": "evidence-provider-journal-readback",
                    "kind": "provider_journal_readback",
                    "issuer_ref": "spring-finance-readback-authority",
                    "subject_ref": preparation.entry_ref,
                    "sha256": "a" * 64,
                    "observed_at": "2026-08-25T12:05:00Z",
                    "verification_grade": "verified",
                    "classification": "confidential",
                    "retention_policy": "finance-seven-years",
                    "jurisdiction": "US",
                }
            ],
        },
    }


class DiscoverLedgerAccountsPrimitive(
    BusinessProcessPrimitive[LedgerAccountDiscoveryInput, LedgerAccountDiscoveryResult]
):
    primitive_ref = "finance.discover_ledger_accounts"
    version = "2.0.0"
    title = "Discover governed ledger accounts"
    description = (
        "Read a complete QuickBooks or Xero chart of accounts through the exact "
        "governed project binding and normalize a bounded typed result."
    )
    input_model = LedgerAccountDiscoveryInput
    output_model = LedgerAccountDiscoveryResult
    connector_tools = (QUICKBOOKS_LIST_ACCOUNTS_TOOL, XERO_LIST_ACCOUNTS_TOOL)
    risk_level = "low"
    approval_required = False
    example_inputs = {"provider": "quickbooks"}
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = True

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: LedgerAccountDiscoveryInput,
    ) -> PrimitiveExecutionResult[LedgerAccountDiscoveryResult]:
        if context.preview_only:
            receipt = PrimitiveOperationReceipt(
                spec=_account_read_operation_spec(inputs.provider, 1),
                status=PrimitiveOperationStatus.PLANNED,
                request_digest=_stable_digest(
                    {
                        "schema": "lightbulb.finance_ledger_account_discovery_plan.v1",
                        "provider": inputs.provider,
                        "tool": _account_read_tool(inputs.provider),
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
                    "Ledger account discovery previewed; no connector read was "
                    "requested and no authoritative account data was fabricated."
                ),
                operation_receipts=[receipt],
                connector_tool=_account_read_tool(inputs.provider),
            )
        tool = _account_read_tool(inputs.provider)
        account_ref = context.connector_account_refs.get(tool)
        if account_ref is None:
            account_ref = context.connector_account_refs.get(inputs.provider)
        if context.scope.project_id is None or not str(account_ref or "").strip():
            blocker = PrimitiveBlocker(
                code="ledger_account_scope_required",
                message=(
                    "Governed account discovery requires an authenticated project UUID "
                    f"and exact {inputs.provider} connector-account binding."
                ),
            )
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.BLOCKED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary=blocker.message,
                blockers=[blocker],
            )

        accounts: list[LedgerAccount] = []
        seen_refs: set[str] = set()
        expected_total: int | None = None
        provider_observed_at: str | None = None
        start_position = 1
        receipts: list[PrimitiveOperationReceipt] = []
        provenance_digests: list[str] = []
        governed_read_receipts: list[GovernedLedgerReadReceipt] = []
        try:
            page_limit = 1 if inputs.provider == "xero" else _MAX_ACCOUNT_PAGES
            for page_index in range(page_limit):
                page_number = page_index + 1
                account_offset = len(accounts)
                request = context.connector_request(
                    primitive_ref=self.primitive_ref,
                    tool=tool,
                    arguments=(
                        {}
                        if inputs.provider == "xero"
                        else {
                            "max_results": _ACCOUNT_PAGE_SIZE,
                            "start_position": start_position,
                        }
                    ),
                    effect=ConnectorEffect.READ,
                    approval_required=False,
                    operation_ref=f"ledger-accounts.read-page-{page_number}",
                    connector_account_ref=str(account_ref),
                    metadata={"source": self.primitive_ref, "page_index": page_index},
                )
                result = context.connectors.execute(request)
                if result.tool != request.tool:
                    mismatch = _JournalLifecycleError(
                        "ledger_account_tool_mismatch",
                        "The connector response is not bound to the requested account-read Tool.",
                    )
                    blocker = PrimitiveBlocker(
                        code=mismatch.code,
                        message=mismatch.message,
                    )
                    receipts.append(
                        PrimitiveOperationReceipt(
                            spec=_account_read_operation_spec(
                                inputs.provider, page_number
                            ),
                            status=PrimitiveOperationStatus.FAILED,
                            request_digest=request.custody_fingerprint(),
                            error=blocker,
                        )
                    )
                    raise mismatch
                provenance: ConnectorExecutionProvenance | None = None
                if result.status == ConnectorExecutionStatus.COMPLETED:
                    try:
                        provenance = _validate_provenance(result.provenance, request)
                    except _JournalLifecycleError as exc:
                        blocker = PrimitiveBlocker(
                            code=exc.code,
                            message=exc.message,
                            retryable=False,
                        )
                        receipts.append(
                            PrimitiveOperationReceipt(
                                spec=_account_read_operation_spec(
                                    inputs.provider, page_number
                                ),
                                status=PrimitiveOperationStatus.FAILED,
                                request_digest=request.custody_fingerprint(),
                                error=blocker,
                            )
                        )
                        raise
                receipt = _read_receipt(
                    provider=inputs.provider,
                    page_number=page_number,
                    request=request,
                    result=result,
                )
                receipts.append(receipt)
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
                    blocker = receipt.error or PrimitiveBlocker(
                        code="ledger_account_read_failed",
                        message="The governed chart-of-accounts read did not complete.",
                        retryable=result.retryable,
                    )
                    return PrimitiveExecutionResult(
                        status=primitive_status,
                        primitive_ref=self.primitive_ref,
                        primitive_version=self.version,
                        summary=blocker.message,
                        blockers=[blocker],
                        operation_receipts=receipts,
                        connector_tool=tool,
                        retryable=result.retryable,
                    )
                if provenance is None:
                    raise _JournalLifecycleError(
                        "connector_provenance_missing",
                        "The completed account read has no validated Spring provenance.",
                    )
                provenance_digests.append(provenance.receipt_digest)
                if inputs.provider == "xero":
                    raw_accounts = result.output.get("records")
                    page_total = result.output.get("record_count")
                    raw_observed_at = result.output.get("provider_observed_at")
                    if (
                        result.output.get("schema")
                        != "lightbulb.xero_chart_of_accounts.v1"
                        or result.output.get("provider") != "xero"
                        or result.output.get("dataset") != "chart_of_accounts"
                        or not isinstance(raw_accounts, list)
                        or len(raw_accounts) > _MAX_ACCOUNTS
                        or isinstance(page_total, bool)
                        or not isinstance(page_total, int)
                        or page_total != len(raw_accounts)
                        or not isinstance(raw_observed_at, str)
                    ):
                        raise _JournalLifecycleError(
                            "ledger_account_response_invalid",
                            "The Xero chart-of-accounts canonical response is malformed.",
                        )
                    expected_total = page_total
                    try:
                        provider_observed_at = _normalized_timestamp(
                            raw_observed_at,
                            field_name="provider_observed_at",
                        )
                    except ValueError as exc:
                        raise _JournalLifecycleError(
                            "ledger_account_response_invalid",
                            "The Xero chart-of-accounts observation time is malformed.",
                        ) from exc
                    for raw_account in raw_accounts:
                        if not isinstance(raw_account, Mapping):
                            raise _JournalLifecycleError(
                                "ledger_account_response_invalid",
                                "The Xero chart of accounts contains a malformed row.",
                            )
                        account = _normalize_xero_account(raw_account)
                        if account.account_ref in seen_refs:
                            raise _JournalLifecycleError(
                                "ledger_account_snapshot_overlap",
                                "The Xero chart of accounts contains duplicate accounts.",
                            )
                        seen_refs.add(account.account_ref)
                        accounts.append(account)
                    source_page_digest = _account_source_page_digest(
                        provider=inputs.provider,
                        tool=tool,
                        page_number=page_number,
                        accounts=accounts[account_offset:],
                    )
                    governed_read_receipts.append(
                        _governed_read_receipt(
                            page_number=page_number,
                            request=request,
                            provenance=provenance,
                            provider_output_digest=_stable_digest(result.output),
                            source_page_digest=source_page_digest,
                        )
                    )
                    break
                query_response = result.output.get("QueryResponse")
                if not isinstance(query_response, Mapping):
                    raise _JournalLifecycleError(
                        "ledger_account_response_invalid",
                        "The provider chart-of-accounts response is malformed.",
                    )
                returned_start = query_response.get("startPosition")
                if returned_start is not None and (
                    isinstance(returned_start, bool)
                    or not isinstance(returned_start, int)
                    or returned_start != start_position
                ):
                    raise _JournalLifecycleError(
                        "ledger_account_response_invalid",
                        "The provider returned inconsistent account pagination.",
                    )
                page_total = query_response.get("totalCount")
                if page_total is not None:
                    if (
                        isinstance(page_total, bool)
                        or not isinstance(page_total, int)
                        or page_total < 0
                        or page_total > _MAX_ACCOUNTS
                    ):
                        raise _JournalLifecycleError(
                            "ledger_account_snapshot_incomplete",
                            "The provider account total exceeds the governed completeness bound.",
                        )
                    if expected_total is not None and expected_total != page_total:
                        raise _JournalLifecycleError(
                            "ledger_account_snapshot_changed",
                            "The chart of accounts changed while it was being read.",
                        )
                    expected_total = page_total
                raw_accounts = query_response.get("Account", [])
                if (
                    not isinstance(raw_accounts, list)
                    or len(raw_accounts) > _ACCOUNT_PAGE_SIZE
                ):
                    raise _JournalLifecycleError(
                        "ledger_account_response_invalid",
                        "The provider account page is malformed or exceeds its bound.",
                    )
                for raw_account in raw_accounts:
                    if not isinstance(raw_account, Mapping):
                        raise _JournalLifecycleError(
                            "ledger_account_response_invalid",
                            "The provider account page contains a malformed row.",
                        )
                    account = _normalize_account(raw_account)
                    if account.account_ref in seen_refs:
                        raise _JournalLifecycleError(
                            "ledger_account_snapshot_overlap",
                            "The provider returned overlapping account pages.",
                        )
                    seen_refs.add(account.account_ref)
                    accounts.append(account)
                source_page_digest = _account_source_page_digest(
                    provider=inputs.provider,
                    tool=tool,
                    page_number=page_number,
                    accounts=accounts[account_offset:],
                )
                governed_read_receipts.append(
                    _governed_read_receipt(
                        page_number=page_number,
                        request=request,
                        provenance=provenance,
                        provider_output_digest=_stable_digest(result.output),
                        source_page_digest=source_page_digest,
                    )
                )
                if expected_total is not None:
                    if len(accounts) == expected_total:
                        break
                    if len(accounts) > expected_total or not raw_accounts:
                        raise _JournalLifecycleError(
                            "ledger_account_snapshot_incomplete",
                            "The provider returned an incomplete chart of accounts.",
                        )
                elif len(raw_accounts) < _ACCOUNT_PAGE_SIZE:
                    break
                start_position += len(raw_accounts)
            else:
                raise _JournalLifecycleError(
                    "ledger_account_snapshot_incomplete",
                    "The chart-of-accounts read reached its governed completeness cap.",
                )
        except _JournalLifecycleError as exc:
            blocker = PrimitiveBlocker(
                code=exc.code,
                message=exc.message,
                retryable=exc.retryable,
            )
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.FAILED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary=exc.message,
                blockers=[blocker],
                operation_receipts=receipts,
                connector_tool=tool,
                retryable=exc.retryable,
            )

        normalized_accounts = tuple(sorted(accounts, key=lambda item: item.account_ref))
        source_digest = LedgerAccountDiscoveryResult.source_digest_for(
            normalized_accounts
        )
        output = LedgerAccountDiscoveryResult(
            provider=inputs.provider,
            tool=tool,
            accounts=normalized_accounts,
            account_count=len(normalized_accounts),
            page_count=len(receipts),
            provider_total_count=expected_total,
            source_digest=source_digest,
            provider_observed_at=provider_observed_at,
            provenance_receipt_digests=tuple(provenance_digests),
            read_receipts=tuple(governed_read_receipts),
        )
        return PrimitiveExecutionResult(
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                f"Discovered {output.account_count} governed "
                f"{inputs.provider} accounts."
            ),
            output=output,
            events=[
                PrimitiveEvent(
                    type="finance.ledger_accounts_discovered",
                    payload={
                        "provider": output.provider,
                        "account_count": output.account_count,
                        "source_digest": output.source_digest,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="governed_chart_of_accounts",
                    summary="A complete bounded chart of accounts was read with exact Spring provenance.",
                    labels=[inputs.provider, "authoritative_read", "complete"],
                    refs={"source_digest": output.source_digest},
                )
            ],
            operation_receipts=receipts,
            connector_tool=tool,
        )


class DiscoverTrialBalancePrimitive(
    BusinessProcessPrimitive[TrialBalanceDiscoveryInput, TrialBalanceDiscoveryResult]
):
    primitive_ref = "finance.discover_trial_balance"
    version = "2.0.0"
    title = "Discover governed trial balance"
    description = (
        "Read one complete monthly QuickBooks or Xero Trial Balance through the exact "
        "governed project binding and normalize bounded debit and credit lines."
    )
    input_model = TrialBalanceDiscoveryInput
    output_model = TrialBalanceDiscoveryResult
    connector_tools = (QUICKBOOKS_TRIAL_BALANCE_TOOL, XERO_TRIAL_BALANCE_TOOL)
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
        inputs: TrialBalanceDiscoveryInput,
    ) -> PrimitiveExecutionResult[TrialBalanceDiscoveryResult]:
        tool = _trial_balance_read_tool(inputs.provider)
        spec = _trial_balance_read_operation_spec(inputs.provider)
        if context.preview_only:
            receipt = PrimitiveOperationReceipt(
                spec=spec,
                status=PrimitiveOperationStatus.PLANNED,
                request_digest=_stable_digest(
                    {
                        "schema": "lightbulb.finance_trial_balance_discovery_plan.v1",
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
                    "Trial Balance discovery previewed; no connector read was "
                    "requested and no authoritative ledger data was fabricated."
                ),
                operation_receipts=[receipt],
                connector_tool=tool,
            )

        account_ref = context.connector_account_refs.get(tool)
        if account_ref is None:
            account_ref = context.connector_account_refs.get(inputs.provider)
        if context.scope.project_id is None or not str(account_ref or "").strip():
            blocker = PrimitiveBlocker(
                code="trial_balance_scope_required",
                message=(
                    "Governed Trial Balance discovery requires an authenticated project "
                    f"UUID and exact {inputs.provider} connector-account binding."
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

        request = context.connector_request(
            primitive_ref=self.primitive_ref,
            tool=tool,
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
                code="trial_balance_tool_mismatch",
                message=(
                    "The connector response is not bound to the requested Trial Balance Tool."
                ),
            )
            receipt = _trial_balance_receipt(
                provider=inputs.provider,
                request=request,
                result=result,
                blocker=blocker,
                force_failed=True,
            )
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.FAILED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary=blocker.message,
                blockers=[blocker],
                operation_receipts=[receipt],
                connector_tool=tool,
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
                code="trial_balance_read_failed",
                message="The governed Trial Balance read did not complete.",
                retryable=result.retryable,
            )
            receipt = _trial_balance_receipt(
                provider=inputs.provider,
                request=request,
                result=result,
                blocker=blocker,
            )
            return PrimitiveExecutionResult(
                status=primitive_status,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary=blocker.message,
                blockers=[blocker],
                operation_receipts=[receipt],
                connector_tool=tool,
                retryable=result.retryable,
            )

        provenance: ConnectorExecutionProvenance | None = None
        try:
            provenance = _validate_provenance(result.provenance, request)
            output = (
                _normalize_trial_balance(
                    result.output,
                    inputs,
                    request,
                    provenance,
                )
                if inputs.provider == "quickbooks"
                else _normalize_xero_trial_balance(
                    result.output,
                    inputs,
                    request,
                    provenance,
                )
            )
        except _JournalLifecycleError as exc:
            blocker = PrimitiveBlocker(
                code=exc.code,
                message=exc.message,
                retryable=exc.retryable,
            )
            receipt = _trial_balance_receipt(
                provider=inputs.provider,
                request=request,
                result=result,
                blocker=blocker,
                provenance_valid=provenance is not None,
                force_failed=True,
            )
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.FAILED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary=blocker.message,
                blockers=[blocker],
                operation_receipts=[receipt],
                connector_tool=tool,
                retryable=exc.retryable,
            )

        receipt = _trial_balance_receipt(
            provider=inputs.provider,
            request=request,
            result=result,
            provenance_valid=True,
        )
        return PrimitiveExecutionResult(
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                f"Discovered {output.line_count} governed {inputs.provider} "
                "Trial Balance lines."
            ),
            output=output,
            events=[
                PrimitiveEvent(
                    type="finance.trial_balance_discovered",
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
                    kind="governed_trial_balance",
                    summary=(
                        "A complete bounded monthly Trial Balance was read with exact "
                        "Spring provenance."
                    ),
                    labels=[
                        inputs.provider,
                        "authoritative_read",
                        "complete",
                        "monthly",
                    ],
                    refs={"source_digest": output.source_digest},
                )
            ],
            operation_receipts=[receipt],
            connector_tool=tool,
        )


class PrepareJournalEntryPrimitive(
    BusinessProcessPrimitive[PrepareJournalEntryInput, JournalEntryPreparation]
):
    primitive_ref = "finance.prepare_journal_entry"
    version = "1.0.0"
    title = "Prepare controlled journal entry"
    description = (
        "Evaluate the existing accounting controls and compile one content-bound "
        "QuickBooks or Xero journal proposal without a connector call."
    )
    input_model = PrepareJournalEntryInput
    output_model = JournalEntryPreparation
    connector_tools = ()
    risk_level = "medium"
    approval_required = False
    example_inputs: Mapping[str, Any] = _prepare_example_inputs()
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: PrepareJournalEntryInput,
    ) -> PrimitiveExecutionResult[JournalEntryPreparation]:
        del context
        preparation = prepare_journal_entry(inputs)
        return PrimitiveExecutionResult(
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                "Journal proposal passed all controls and is ready for governed posting."
                if preparation.ready_for_posting
                else "Journal proposal is not ready for posting; resolve its control findings."
            ),
            output=preparation,
            events=[
                PrimitiveEvent(
                    type="finance.journal_entry_prepared",
                    payload={
                        "provider": preparation.provider,
                        "entry_ref": preparation.entry_ref,
                        "disposition": preparation.control_evaluation.disposition,
                        "preparation_digest": preparation.preparation_digest,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="journal_entry_preparation",
                    summary="The proposal is content-bound and grants no posting authority.",
                    labels=[
                        preparation.provider,
                        preparation.control_evaluation.disposition,
                        "no_connector_call",
                    ],
                    refs={"preparation_digest": preparation.preparation_digest},
                )
            ],
            evidence_refs=list(preparation.evidence_refs),
            operation_receipts=[_preparation_receipt(preparation)],
        )


class PostJournalEntryPrimitive(
    BusinessProcessPrimitive[PostJournalEntryInput, PostJournalEntryResult]
):
    primitive_ref = "finance.post_journal_entry"
    version = "2.0.0"
    title = "Post governed journal entry"
    description = (
        "Re-evaluate and bind a prepared journal, then request the exact approved "
        "QuickBooks or Xero write through Spring-owned governed execution."
    )
    input_model = PostJournalEntryInput
    output_model = PostJournalEntryResult
    connector_tools = (
        QUICKBOOKS_CREATE_JOURNAL_TOOL,
        XERO_CREATE_MANUAL_JOURNAL_TOOL,
    )
    risk_level = "high"
    approval_required = True
    example_inputs: Mapping[str, Any] = _post_example_inputs()
    mcp_read_only = False
    mcp_destructive = True
    mcp_idempotent = True
    mcp_open_world = True

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: PostJournalEntryInput,
    ) -> PrimitiveExecutionResult[PostJournalEntryResult]:
        preparation = prepare_journal_entry(
            PrepareJournalEntryInput(provider=inputs.provider, journal=inputs.journal)
        )
        if inputs.expected_preparation_digest != preparation.preparation_digest:
            blocker = PrimitiveBlocker(
                code="journal_preparation_digest_mismatch",
                message="The journal changed after preparation; prepare and review it again.",
            )
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.BLOCKED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary=blocker.message,
                output=_post_output(preparation, state="blocked"),
                blockers=[blocker],
            )
        if not preparation.ready_for_posting or preparation.provider_payload is None:
            blocker = PrimitiveBlocker(
                code="journal_controls_not_ready",
                message="Journal controls must be ready before governed posting.",
            )
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.BLOCKED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary=blocker.message,
                output=_post_output(preparation, state="blocked"),
                blockers=[blocker],
                evidence_refs=list(preparation.evidence_refs),
            )

        spec = _post_operation_spec(inputs.provider)
        provider_payload = preparation.provider_payload.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        )
        if not inputs.commit:
            receipt = PrimitiveOperationReceipt(
                spec=spec,
                status=PrimitiveOperationStatus.PREVIEW,
                request_digest=preparation.preparation_digest,
                evidence_refs=list(preparation.evidence_refs),
            )
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.PREVIEW,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary="Journal posting preview completed; no connector write was requested.",
                output=_post_output(preparation, state="preview"),
                events=[
                    PrimitiveEvent(
                        type="finance.journal_entry_post_previewed",
                        payload={
                            "provider": inputs.provider,
                            "entry_ref": preparation.entry_ref,
                            "preparation_digest": preparation.preparation_digest,
                        },
                    )
                ],
                evidence_refs=list(preparation.evidence_refs),
                operation_receipts=[receipt],
                connector_tool=spec.tool,
            )

        request = context.connector_request(
            primitive_ref=self.primitive_ref,
            tool=spec.tool,
            arguments={"payload": provider_payload},
            effect=ConnectorEffect.WRITE,
            approval_required=True,
            operation_ref=spec.operation_ref,
            metadata={
                "source": self.primitive_ref,
                "provider": inputs.provider,
                "entry_ref": inputs.journal.entry_ref,
                "preparation_digest": preparation.preparation_digest,
            },
        )
        if context.scope.project_id is None or request.connector_account_ref is None:
            blocker = PrimitiveBlocker(
                code="journal_post_scope_required",
                message=(
                    "Governed journal posting requires an authenticated project UUID "
                    "and exact provider connector-account binding."
                ),
            )
            receipt = PrimitiveOperationReceipt(
                spec=spec,
                status=PrimitiveOperationStatus.BLOCKED,
                request_digest=request.custody_fingerprint(),
                evidence_refs=list(preparation.evidence_refs),
                error=blocker,
            )
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.BLOCKED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary=blocker.message,
                output=_post_output(preparation, state="blocked"),
                blockers=[blocker],
                evidence_refs=list(preparation.evidence_refs),
                operation_receipts=[receipt],
                connector_tool=spec.tool,
            )
        result = context.connectors.execute(request)
        request_digest = request.custody_fingerprint()
        if result.tool != request.tool:
            return _in_doubt_post_result(
                preparation,
                spec=spec,
                request_digest=request_digest,
                blocker_code="journal_connector_tool_mismatch",
                blocker_message=(
                    "The connector response is not bound to the requested journal Tool; "
                    "the provider effect must be reconciled before any continuation."
                ),
                summary=(
                    "Journal connector evidence names a different Tool; the outcome is "
                    "in doubt and automatic retry is blocked."
                ),
            )

        if result.status == ConnectorExecutionStatus.PREVIEW:
            receipt = PrimitiveOperationReceipt(
                spec=spec,
                status=PrimitiveOperationStatus.PREVIEW,
                request_digest=request_digest,
                evidence_refs=list(preparation.evidence_refs),
            )
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.PREVIEW,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary="Hosted runtime kept the journal write in preview.",
                output=_post_output(preparation, state="preview"),
                evidence_refs=list(preparation.evidence_refs),
                operation_receipts=[receipt],
                connector_tool=spec.tool,
            )
        if result.status == ConnectorExecutionStatus.PENDING_APPROVAL:
            if (
                request.approval_ref is not None
                or result.approval_ref is None
                or result.approval_receipt_digest is None
            ):
                blocker = PrimitiveBlocker(
                    code="journal_approval_state_invalid",
                    message=(
                        "Spring returned an invalid journal approval state; no posting "
                        "continuation is authorized."
                    ),
                )
                receipt = PrimitiveOperationReceipt(
                    spec=spec,
                    status=PrimitiveOperationStatus.FAILED,
                    request_digest=request_digest,
                    evidence_refs=list(preparation.evidence_refs),
                    error=blocker,
                )
                return PrimitiveExecutionResult(
                    status=PrimitiveExecutionStatus.FAILED,
                    primitive_ref=self.primitive_ref,
                    primitive_version=self.version,
                    summary=blocker.message,
                    output=_post_output(preparation, state="failed"),
                    blockers=[blocker],
                    evidence_refs=list(preparation.evidence_refs),
                    operation_receipts=[receipt],
                    connector_tool=spec.tool,
                    retryable=False,
                )
            receipt = PrimitiveOperationReceipt(
                spec=spec,
                status=PrimitiveOperationStatus.PENDING_APPROVAL,
                request_digest=request_digest,
                approval_ref=result.approval_ref,
                external_refs={
                    "approval_receipt_digest": result.approval_receipt_digest,
                    "entry_ref": preparation.entry_ref,
                    "preparation_digest": preparation.preparation_digest,
                },
                evidence_refs=list(preparation.evidence_refs),
            )
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.PENDING_APPROVAL,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary="Spring staged the exact journal write for approval.",
                output=_post_output(preparation, state="pending_approval"),
                events=[
                    PrimitiveEvent(
                        type="finance.journal_entry_pending_approval",
                        payload={
                            "provider": inputs.provider,
                            "entry_ref": preparation.entry_ref,
                            "preparation_digest": preparation.preparation_digest,
                        },
                    )
                ],
                evidence_refs=list(preparation.evidence_refs),
                operation_receipts=[receipt],
                approval_ref=result.approval_ref,
                connector_tool=spec.tool,
            )
        if result.status == ConnectorExecutionStatus.COMPLETED:
            try:
                provenance = _validate_provenance(result.provenance, request)
                write_result = GovernedJournalWriteResult.model_validate(result.output)
                if write_result.provider != inputs.provider:
                    raise _JournalLifecycleError(
                        "journal_write_result_mismatch",
                        "The governed write result does not match the requested provider.",
                    )
                if inputs.provider == "quickbooks":
                    if not isinstance(
                        preparation.provider_payload, QuickBooksJournalEntryPayload
                    ):
                        raise _JournalLifecycleError(
                            "journal_write_effect_unsupported",
                            "The QuickBooks journal has no canonical provider payload.",
                        )
                    expected_effect = quickbooks_journal_effect_sha256(
                        preparation.provider_payload
                    )
                    if write_result.expected_effect_sha256 != expected_effect:
                        raise _JournalLifecycleError(
                            "journal_write_effect_mismatch",
                            "The governed write does not bind the canonical QuickBooks effect.",
                        )
            except (ValueError, _JournalLifecycleError):
                return _in_doubt_post_result(
                    preparation,
                    spec=spec,
                    request_digest=request_digest,
                    blocker_code="journal_write_evidence_invalid",
                    blocker_message=(
                        "Spring reported completion without exact governed evidence; "
                        "the provider effect must be reconciled before any continuation."
                    ),
                    summary=(
                        "Journal completion evidence is invalid; the outcome is in doubt "
                        "and automatic retry is blocked."
                    ),
                )
            # Provenance models are caller-constructible. Require the exact hosted
            # adapter because a subclass may replace execute() with fabricated data.
            if type(context.connectors) is not HostedConnectorExecutor:
                return _in_doubt_post_result(
                    preparation,
                    spec=spec,
                    request_digest=request_digest,
                    blocker_code="journal_write_authority_untrusted",
                    blocker_message=(
                        "A caller-supplied connector reported completion without "
                        "Spring-hosted execution authority; reconcile the provider "
                        "effect before any continuation."
                    ),
                    summary=(
                        "Journal completion came from an untrusted execution boundary; "
                        "the outcome is in doubt and automatic retry is blocked."
                    ),
                )
            receipt = PrimitiveOperationReceipt(
                spec=spec,
                status=PrimitiveOperationStatus.COMPLETED,
                request_digest=request_digest,
                approval_ref=provenance.approval_ref,
                provenance_receipt_digest=provenance.receipt_digest,
                external_refs={
                    "execution_journal_ref": provenance.journal_ref,
                    "tool_version": str(provenance.tool_version),
                    "project_id": str(provenance.project_id),
                    "tenant_connector_id": str(provenance.tenant_connector_id),
                    "connector_account_ref": provenance.connector_account_ref,
                    "route_digest": provenance.route_digest,
                    "entry_ref": preparation.entry_ref,
                    "preparation_digest": preparation.preparation_digest,
                    "provider_record_ref": write_result.provider_record_ref,
                    "write_provider_output_sha256": (
                        write_result.write_provider_output_sha256
                    ),
                    **(
                        {
                            "expected_effect_sha256": (
                                write_result.expected_effect_sha256
                            )
                        }
                        if write_result.expected_effect_sha256 is not None
                        else {}
                    ),
                },
                evidence_refs=list(preparation.evidence_refs),
                replayed=result.cached,
            )
            output = _post_output(
                preparation,
                state="posted",
                write_result=write_result,
                execution_journal_ref=provenance.journal_ref,
                provenance=provenance,
            )
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.COMPLETED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary="Journal entry posted through Spring-governed connector execution.",
                output=output,
                events=[
                    PrimitiveEvent(
                        type="finance.journal_entry_posted",
                        payload={
                            "provider": inputs.provider,
                            "entry_ref": preparation.entry_ref,
                            "provider_record_ref": write_result.provider_record_ref,
                            "preparation_digest": preparation.preparation_digest,
                        },
                    )
                ],
                evidence=[
                    PrimitiveEvidence(
                        kind="governed_journal_post",
                        summary="Spring returned exact approval, route, journal, and provider-record provenance.",
                        labels=[inputs.provider, "governed_write", "readback_required"],
                        refs={
                            "execution_journal_ref": provenance.journal_ref,
                            "tool_version": str(provenance.tool_version),
                            "project_id": str(provenance.project_id),
                            "tenant_connector_id": str(provenance.tenant_connector_id),
                            "connector_account_ref": (provenance.connector_account_ref),
                            "route_digest": provenance.route_digest,
                            "provenance_receipt_digest": provenance.receipt_digest,
                            "provider_record_ref": write_result.provider_record_ref,
                            "write_provider_output_sha256": (
                                write_result.write_provider_output_sha256
                            ),
                            **(
                                {
                                    "expected_effect_sha256": (
                                        write_result.expected_effect_sha256
                                    )
                                }
                                if write_result.expected_effect_sha256 is not None
                                else {}
                            ),
                        },
                    )
                ],
                evidence_refs=list(preparation.evidence_refs),
                operation_receipts=[receipt],
                approval_ref=provenance.approval_ref,
                connector_tool=spec.tool,
            )

        ambiguous = result.error_code == _AMBIGUOUS_ERROR_CODE
        if ambiguous:
            unverified_recovery_journal_locator = (
                result.unverified_recovery_journal_locator
                if type(context.connectors) is HostedConnectorExecutor
                else None
            )
            return _in_doubt_post_result(
                preparation,
                spec=spec,
                request_digest=request_digest,
                blocker_code="journal_post_outcome_ambiguous",
                blocker_message=(
                    "Provider effect is ambiguous; independently verify readback and "
                    "settle the Spring execution journal before any continuation."
                ),
                summary="Journal outcome is ambiguous; automatic retry is blocked.",
                unverified_recovery_journal_locator=(
                    unverified_recovery_journal_locator
                ),
            )

        blocked = result.status == ConnectorExecutionStatus.BLOCKED
        blocker = PrimitiveBlocker(
            code="journal_post_blocked" if blocked else "journal_post_failed",
            message=(
                "Spring blocked the governed journal write."
                if blocked
                else "The governed journal write failed before a conclusive provider effect."
            ),
            retryable=False,
        )
        receipt = PrimitiveOperationReceipt(
            spec=spec,
            status=(
                PrimitiveOperationStatus.BLOCKED
                if blocked
                else PrimitiveOperationStatus.FAILED
            ),
            request_digest=request_digest,
            evidence_refs=list(preparation.evidence_refs),
            error=blocker,
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
            output=_post_output(
                preparation,
                state="blocked" if blocked else "failed",
            ),
            evidence_refs=list(preparation.evidence_refs),
            operation_receipts=[receipt],
            blockers=[blocker],
            connector_tool=spec.tool,
            retryable=False,
        )


def reconcile_journal_post(
    inputs: ReconcileJournalPostInput,
) -> ReconcileJournalPostResult:
    """Evaluate exact post/readback evidence without settling Spring authority."""

    usable_evidence = all(
        evidence.verification_grade
        in {
            PrimitiveEvidenceVerificationGrade.ATTESTED,
            PrimitiveEvidenceVerificationGrade.VERIFIED,
        }
        for evidence in inputs.readback.evidence_refs
    )
    external = inputs.post_receipt.external_refs
    expected_ref = external.get("provider_record_ref")
    write_output_digest = external.get("write_provider_output_sha256")
    expected_effect_digest = external.get("expected_effect_sha256")
    write_execution_journal_ref = external.get("execution_journal_ref")
    completed_write = inputs.post_receipt.status == PrimitiveOperationStatus.COMPLETED
    write_tool_version = _external_tool_version(external, required=completed_write)
    write_project_id = _external_uuid(external, "project_id", required=completed_write)
    write_tenant_connector_id = _external_uuid(
        external, "tenant_connector_id", required=completed_write
    )
    write_connector_account_ref = _external_opaque_ref(
        external, "connector_account_ref", required=completed_write
    )
    write_route_digest = _external_sha256(
        external, "route_digest", required=completed_write
    )
    write_provenance_receipt_digest = (
        inputs.post_receipt.provenance_receipt_digest if completed_write else None
    )
    semantic_effect_supported = inputs.provider == "quickbooks"
    lineage_matches = bool(
        completed_write
        and inputs.readback.provider == inputs.provider
        and write_project_id == inputs.readback.project_id
        and write_tenant_connector_id == inputs.readback.tenant_connector_id
        and write_connector_account_ref == inputs.readback.connector_account_ref
        and write_provenance_receipt_digest != inputs.readback.provenance_receipt_digest
    )
    readback_matches = bool(
        semantic_effect_supported
        and lineage_matches
        and inputs.readback.state == "found"
        and expected_ref is not None
        and inputs.readback.provider_record_ref == expected_ref
        and expected_effect_digest is not None
        and inputs.readback.observed_effect_sha256 == expected_effect_digest
    )
    if not semantic_effect_supported or not usable_evidence:
        disposition: Literal[
            "effect_confirmed_candidate",
            "manual_reconciliation_required",
            "readback_mismatch",
            "evidence_insufficient",
        ] = "evidence_insufficient"
    elif inputs.readback.state == "found" and not readback_matches:
        disposition = "readback_mismatch"
    elif readback_matches:
        disposition = "effect_confirmed_candidate"
    else:
        disposition = "manual_reconciliation_required"

    recovery_plan = _manual_recovery_plan()
    digest_payload = {
        "schema": JOURNAL_POST_RECOVERY_RESULT_SCHEMA,
        "provider": inputs.provider,
        "entry_ref": inputs.entry_ref,
        "post_request_digest": inputs.post_receipt.request_digest,
        "disposition": disposition,
        "readback": inputs.readback.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        ),
        "expected_provider_record_ref": expected_ref,
        "write_provider_output_sha256": write_output_digest,
        "read_provider_output_sha256": (inputs.readback.read_provider_output_sha256),
        "expected_effect_sha256": expected_effect_digest,
        "observed_effect_sha256": inputs.readback.observed_effect_sha256,
        "write_execution_journal_ref": write_execution_journal_ref,
        "read_execution_journal_ref": inputs.readback.read_execution_journal_ref,
        "governed_read_source_ref": inputs.readback.governed_read_source_ref,
        "write_tool_version": write_tool_version,
        "read_tool_version": inputs.readback.read_tool_version,
        "write_project_id": write_project_id,
        "read_project_id": inputs.readback.project_id,
        "write_tenant_connector_id": write_tenant_connector_id,
        "read_tenant_connector_id": inputs.readback.tenant_connector_id,
        "write_connector_account_ref": write_connector_account_ref,
        "read_connector_account_ref": inputs.readback.connector_account_ref,
        "write_route_digest": write_route_digest,
        "read_route_digest": inputs.readback.route_digest,
        "write_provenance_receipt_digest": write_provenance_receipt_digest,
        "read_provenance_receipt_digest": (inputs.readback.provenance_receipt_digest),
        "spring_settlement_required": True,
        "replay_permitted": False,
    }
    return ReconcileJournalPostResult(
        provider=inputs.provider,
        entry_ref=inputs.entry_ref,
        post_request_digest=inputs.post_receipt.request_digest,
        disposition=disposition,
        readback_matches=readback_matches,
        expected_provider_record_ref=expected_ref,
        observed_provider_record_ref=inputs.readback.provider_record_ref,
        write_provider_output_sha256=write_output_digest,
        read_provider_output_sha256=inputs.readback.read_provider_output_sha256,
        expected_effect_sha256=expected_effect_digest,
        observed_effect_sha256=inputs.readback.observed_effect_sha256,
        write_execution_journal_ref=write_execution_journal_ref,
        read_execution_journal_ref=inputs.readback.read_execution_journal_ref,
        governed_read_source_ref=inputs.readback.governed_read_source_ref,
        write_tool_version=write_tool_version,
        read_tool_version=inputs.readback.read_tool_version,
        write_project_id=write_project_id,
        read_project_id=inputs.readback.project_id,
        write_tenant_connector_id=write_tenant_connector_id,
        read_tenant_connector_id=inputs.readback.tenant_connector_id,
        write_connector_account_ref=write_connector_account_ref,
        read_connector_account_ref=inputs.readback.connector_account_ref,
        write_route_digest=write_route_digest,
        read_route_digest=inputs.readback.route_digest,
        write_provenance_receipt_digest=write_provenance_receipt_digest,
        read_provenance_receipt_digest=inputs.readback.provenance_receipt_digest,
        recovery_plan=recovery_plan,
        evidence_refs=inputs.readback.evidence_refs,
        evaluation_digest=_stable_digest(digest_payload),
    )


class ReconcileJournalPostPrimitive(
    BusinessProcessPrimitive[ReconcileJournalPostInput, ReconcileJournalPostResult]
):
    primitive_ref = "finance.reconcile_journal_post"
    version = "2.0.0"
    title = "Reconcile journal post readback"
    description = (
        "Evaluate independently evidenced journal readback after a completed or "
        "ambiguous post without settling Spring authority or permitting replay."
    )
    input_model = ReconcileJournalPostInput
    output_model = ReconcileJournalPostResult
    connector_tools = ()
    risk_level = "medium"
    approval_required = False
    example_inputs: Mapping[str, Any] = _reconcile_example_inputs()
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: ReconcileJournalPostInput,
    ) -> PrimitiveExecutionResult[ReconcileJournalPostResult]:
        del context
        output = reconcile_journal_post(inputs)
        disposition = output.disposition
        receipt = PrimitiveOperationReceipt(
            spec=JOURNAL_POST_RECOVERY_EVALUATION_OPERATION,
            status=PrimitiveOperationStatus.COMPLETED,
            request_digest=output.evaluation_digest,
            external_refs={"post_request_digest": output.post_request_digest},
            evidence_refs=list(output.evidence_refs),
        )
        blocked = disposition in {"readback_mismatch", "evidence_insufficient"}
        blockers = (
            [
                PrimitiveBlocker(
                    code=disposition,
                    message=(
                        "Journal readback evidence is insufficient or conflicts with the expected post."
                    ),
                )
            ]
            if blocked
            else []
        )
        return PrimitiveExecutionResult(
            status=(
                PrimitiveExecutionStatus.BLOCKED
                if blocked
                else PrimitiveExecutionStatus.COMPLETED
            ),
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                "Readback found the expected journal; Spring settlement remains required."
                if disposition == "effect_confirmed_candidate"
                else "Journal post still requires manual reconciliation and Spring settlement."
            ),
            output=output,
            events=[
                PrimitiveEvent(
                    type="finance.journal_post_readback_evaluated",
                    payload={
                        "provider": inputs.provider,
                        "entry_ref": inputs.entry_ref,
                        "disposition": disposition,
                        "evaluation_digest": output.evaluation_digest,
                        "replay_permitted": False,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="journal_post_readback",
                    summary=(
                        "Readback was evaluated as a non-authoritative recovery candidate; "
                        "Spring must settle the governed journal."
                    ),
                    labels=[
                        disposition,
                        "no_replay_authority",
                        "spring_settlement_required",
                    ],
                    refs={"evaluation_digest": output.evaluation_digest},
                )
            ],
            evidence_refs=list(output.evidence_refs),
            operation_receipts=[receipt],
            blockers=blockers,
            retryable=False,
        )


FINANCE_JOURNAL_LIFECYCLE_EXECUTABLE_PRIMITIVES: tuple[
    BusinessProcessPrimitive[Any, Any], ...
] = (
    DiscoverLedgerAccountsPrimitive(),
    DiscoverTrialBalancePrimitive(),
    PrepareJournalEntryPrimitive(),
    PostJournalEntryPrimitive(),
    ReconcileJournalPostPrimitive(),
)


__all__ = [
    "DiscoverLedgerAccountsPrimitive",
    "DiscoverTrialBalancePrimitive",
    "FINANCE_JOURNAL_LIFECYCLE_EXECUTABLE_PRIMITIVES",
    "GOVERNED_LEDGER_READ_RECEIPT_SCHEMA",
    "GOVERNED_FINANCE_WRITE_RESULT_SCHEMA",
    "GovernedLedgerReadReceipt",
    "GovernedJournalWriteResult",
    "JOURNAL_ENTRY_POST_INPUT_SCHEMA",
    "JOURNAL_ENTRY_POST_RESULT_SCHEMA",
    "JOURNAL_ENTRY_PREPARATION_INPUT_SCHEMA",
    "JOURNAL_ENTRY_PREPARATION_SCHEMA",
    "JOURNAL_POST_READBACK_SCHEMA",
    "JOURNAL_POST_RECOVERY_EVALUATION_OPERATION",
    "JOURNAL_POST_RECOVERY_INPUT_SCHEMA",
    "JOURNAL_POST_RECOVERY_RESULT_SCHEMA",
    "JournalEntryPreparation",
    "JournalPostReadback",
    "LEDGER_ACCOUNT_DISCOVERY_INPUT_SCHEMA",
    "LEDGER_ACCOUNT_DISCOVERY_RESULT_SCHEMA",
    "LedgerAccount",
    "LedgerAccountDiscoveryInput",
    "LedgerAccountDiscoveryResult",
    "PostJournalEntryInput",
    "PostJournalEntryPrimitive",
    "PostJournalEntryResult",
    "PrepareJournalEntryInput",
    "PrepareJournalEntryPrimitive",
    "prepare_journal_entry",
    "QUICKBOOKS_CREATE_JOURNAL_TOOL",
    "QUICKBOOKS_GET_JOURNAL_TOOL",
    "QUICKBOOKS_JOURNAL_EFFECT_SCHEMA",
    "QUICKBOOKS_LIST_ACCOUNTS_TOOL",
    "QUICKBOOKS_TRIAL_BALANCE_TOOL",
    "QuickBooksJournalCorrelationRef",
    "QuickBooksJournalEntryLine",
    "QuickBooksJournalEntryLineDetail",
    "QuickBooksJournalEntryPayload",
    "QuickBooksValueRef",
    "quickbooks_journal_correlation_ref",
    "quickbooks_journal_effect_sha256",
    "ReconcileJournalPostInput",
    "ReconcileJournalPostPrimitive",
    "ReconcileJournalPostResult",
    "reconcile_journal_post",
    "TRIAL_BALANCE_DISCOVERY_INPUT_SCHEMA",
    "TRIAL_BALANCE_DISCOVERY_RESULT_SCHEMA",
    "TrialBalanceDiscoveryInput",
    "TrialBalanceDiscoveryResult",
    "DiscoveredTrialBalanceLine",
    "XERO_CREATE_MANUAL_JOURNAL_TOOL",
    "XERO_LIST_JOURNALS_TOOL",
    "XeroManualJournalLine",
    "XeroManualJournalPayload",
]
