"""Provider-neutral, fixture-safe finance source record contracts.

These immutable models describe a complete chart-of-accounts and trial-balance
observation without interpreting provider-specific response fields.  They
perform deterministic structural validation only.  They do not authenticate a
scope, verify provider data, certify a connector, persist an observation, or
grant read or write authority.  A hosted authority must derive and verify all
scope, custody, retention, and evidence claims before publishing these records.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Annotated, Any, Literal

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

from lightbulb.primitive_runtime import PrimitiveEvidenceRef


FINANCE_LEDGER_SCOPE_SCHEMA = "lightbulb.finance_ledger_scope.v1"
FINANCE_SOURCE_IDENTITY_SCHEMA = "lightbulb.finance_source_identity.v1"
FINANCE_SOURCE_CHECKPOINT_SCHEMA = "lightbulb.finance_source_checkpoint.v1"
FINANCE_SOURCE_PAGE_EVIDENCE_KIND = "finance_source_page"
FINANCE_OBSERVATION_ENVELOPE_SCHEMA = "lightbulb.finance_observation_envelope.v1"
CANONICAL_LEDGER_ACCOUNT_SCHEMA = "lightbulb.canonical_ledger_account.v1"
CANONICAL_TRIAL_BALANCE_LINE_SCHEMA = "lightbulb.canonical_trial_balance_line.v1"
CANONICAL_LEDGER_SNAPSHOT_SCHEMA = "lightbulb.canonical_ledger_snapshot.v1"

_ZERO_DIGEST = "0" * 64
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@+\-]{0,199}$"
_PROVIDER_PATTERN = r"^[a-z][a-z0-9_\-]{1,39}$"
_TOOL_PATTERN = r"^[a-z][a-z0-9_\-]*(?:\.[a-z][a-z0-9_\-]*)+$"
_CURRENCY_PATTERN = r"^[A-Z]{3}$"
_CANONICAL_DECIMAL_PATTERN = re.compile(r"^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$")
_MAX_MONEY = Decimal("1000000000000000000000000")
_MAX_DECIMAL_PLACES = 8
_MAX_REVISION = 9_223_372_036_854_775_807


def _visible_ref(value: str) -> str:
    if value != value.strip() or any(ord(character) < 33 for character in value):
        raise ValueError("references must contain visible non-whitespace characters")
    return value


def _visible_text(value: str) -> str:
    if value != value.strip() or any(ord(character) < 32 for character in value):
        raise ValueError("text must be trimmed and contain no control characters")
    return value


def _strict_integer(value: Any) -> Any:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("integer fields require integers, not booleans")
    return value


def _strict_boolean(value: Any) -> Any:
    if type(value) is not bool:
        raise ValueError("boolean fields require JSON boolean values")
    return value


def _strict_true(value: Any) -> Any:
    if value is not True:
        raise ValueError("complete must be the JSON boolean true")
    return value


def _money_decimal(value: Any) -> Decimal:
    """Accept Decimal or lossless canonical JSON strings; never JSON numbers."""

    if isinstance(value, Decimal):
        parsed = value
    elif isinstance(value, str):
        if value != value.strip() or not _CANONICAL_DECIMAL_PATTERN.fullmatch(value):
            raise ValueError(
                "money strings must use non-negative plain decimal notation"
            )
        try:
            parsed = Decimal(value)
        except InvalidOperation as exc:  # pragma: no cover - guarded by the regex
            raise ValueError("money must be a finite decimal") from exc
    else:
        raise ValueError("money requires Decimal or a canonical decimal string")
    if not parsed.is_finite() or parsed < 0 or parsed > _MAX_MONEY:
        raise ValueError("money must be a bounded non-negative finite decimal")
    if max(0, -parsed.as_tuple().exponent) > _MAX_DECIMAL_PLACES:
        raise ValueError(f"money supports at most {_MAX_DECIMAL_PLACES} decimal places")
    return Decimal(0) if parsed == 0 else parsed


def _canonical_decimal(value: Decimal) -> str:
    if not value.is_finite():
        raise ValueError("canonical finance decimals must be finite")
    if value == 0:
        return "0"
    rendered = format(value, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return rendered


def _canonical_value(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return _canonical_value(
            value.model_dump(mode="python", by_alias=True, exclude_none=True)
        )
    if isinstance(value, Decimal):
        return _canonical_decimal(value)
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("canonical finance datetimes must include a UTC offset")
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, Mapping):
        return {str(key): _canonical_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_canonical_value(item) for item in value]
    if value is None or isinstance(value, (str, int, bool)):
        return value
    if isinstance(value, float):
        raise TypeError("floats are not canonical finance values")
    raise TypeError(f"unsupported canonical finance value: {type(value)!r}")


def finance_canonical_json(value: Any) -> bytes:
    """Serialize supported finance values into deterministic JSON bytes."""

    return json.dumps(
        _canonical_value(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def finance_canonical_digest(value: Any) -> str:
    """Return the lowercase SHA-256 digest of canonical finance JSON."""

    return hashlib.sha256(finance_canonical_json(value)).hexdigest()


def _timestamp(value: str, *, field_name: str) -> str:
    if not isinstance(value, str) or value != value.strip():
        raise ValueError(f"{field_name} must be a trimmed ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field_name} must be valid ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field_name} must include a UTC offset")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _as_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _tuple(value: Any) -> Any:
    return tuple(value) if isinstance(value, list) else value


def _sorted_tuple(value: Any, *, keys: tuple[str, ...]) -> Any:
    if not isinstance(value, (list, tuple)):
        return value

    def sort_key(item: Any) -> tuple[str, ...]:
        if isinstance(item, Mapping):
            return tuple(str(item.get(key, "")) for key in keys)
        return tuple(str(getattr(item, key, "")) for key in keys)

    return tuple(sorted(value, key=sort_key))


def _seal_digest(model: BaseModel, field_name: str, expected: str) -> None:
    supplied = getattr(model, field_name)
    if supplied not in {_ZERO_DIGEST, expected}:
        raise ValueError(f"{field_name} does not match canonical payload")
    object.__setattr__(model, field_name, expected)


OpaqueRef = Annotated[
    str,
    StringConstraints(pattern=_REF_PATTERN),
    AfterValidator(_visible_ref),
]
OpaqueCursor = Annotated[
    str,
    StringConstraints(min_length=1, max_length=1_000),
    AfterValidator(_visible_ref),
]
BoundedText = Annotated[
    str,
    StringConstraints(min_length=1, max_length=500),
    AfterValidator(_visible_text),
]
ProviderSlug = Annotated[str, StringConstraints(pattern=_PROVIDER_PATTERN)]
ToolName = Annotated[str, StringConstraints(pattern=_TOOL_PATTERN)]
CurrencyCode = Annotated[str, StringConstraints(pattern=_CURRENCY_PATTERN)]
Sha256Digest = Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)]
PositiveRevision = Annotated[
    int,
    BeforeValidator(_strict_integer),
    Field(ge=1, le=_MAX_REVISION),
]
NonnegativeCount = Annotated[
    int,
    BeforeValidator(_strict_integer),
    Field(ge=0, le=100_000),
]
PositivePageCount = Annotated[
    int,
    BeforeValidator(_strict_integer),
    Field(ge=1, le=10_000),
]
StrictBool = Annotated[bool, BeforeValidator(_strict_boolean)]
StrictTrue = Annotated[Literal[True], BeforeValidator(_strict_true)]
Money = Annotated[Decimal, BeforeValidator(_money_decimal)]

FinanceDataset = Literal["chart_of_accounts", "trial_balance"]
AccountClass = Literal["asset", "liability", "equity", "revenue", "expense"]
PeriodStatus = Literal["open", "soft_closed", "closed", "locked"]
FreshnessClass = Literal["current", "bounded", "historical"]
EvidenceClassification = Literal["public", "internal", "confidential", "restricted"]
CursorKind = Literal["none", "offset", "opaque"]


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


class FinanceLedgerScope(_StrictModel):
    """Exact caller-supplied scope candidate; never an authorization grant."""

    schema_id: Literal["lightbulb.finance_ledger_scope.v1"] = Field(
        default=FINANCE_LEDGER_SCOPE_SCHEMA,
        alias="schema",
    )
    tenant_ref: OpaqueRef
    company_ref: OpaqueRef
    project_ref: OpaqueRef
    legal_entity_ref: OpaqueRef
    ledger_ref: OpaqueRef
    functional_currency: CurrencyCode
    fiscal_period_ref: OpaqueRef
    period_revision: PositiveRevision
    period_status: PeriodStatus
    period_started_at: str
    period_ended_at: str
    jurisdiction_ref: OpaqueRef
    classification: EvidenceClassification
    retention_policy_ref: OpaqueRef
    required_retained_until: str

    @field_validator("period_started_at", "period_ended_at", "required_retained_until")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=info.field_name)

    @model_validator(mode="after")
    def _ordered_period_and_retention(self) -> "FinanceLedgerScope":
        started = _as_datetime(self.period_started_at)
        ended = _as_datetime(self.period_ended_at)
        retained = _as_datetime(self.required_retained_until)
        if started > ended:
            raise ValueError("period_started_at cannot follow period_ended_at")
        if retained <= ended:
            raise ValueError("required_retained_until must follow the fiscal period")
        return self


class FinanceSourceIdentity(_StrictModel):
    """Provider details confined to source provenance, outside canonical facts."""

    schema_id: Literal["lightbulb.finance_source_identity.v1"] = Field(
        default=FINANCE_SOURCE_IDENTITY_SCHEMA,
        alias="schema",
    )
    dataset: FinanceDataset
    provider: ProviderSlug
    tool: ToolName
    tool_version: PositiveRevision
    tenant_connector_ref: OpaqueRef
    connector_account_ref: OpaqueRef
    provider_account_ref: OpaqueRef
    route_ref: OpaqueRef
    execution_journal_ref: OpaqueRef

    @model_validator(mode="after")
    def _tool_uses_provider_namespace(self) -> "FinanceSourceIdentity":
        if self.tool.split(".", maxsplit=1)[0] != self.provider:
            raise ValueError("source tool namespace must exactly match provider")
        return self


class FinanceSourceCheckpoint(_StrictModel):
    """Bounded proof that every page in one source observation was consumed."""

    schema_id: Literal["lightbulb.finance_source_checkpoint.v1"] = Field(
        default=FINANCE_SOURCE_CHECKPOINT_SCHEMA,
        alias="schema",
    )
    cursor_kind: CursorKind
    initial_cursor: OpaqueCursor | None = None
    terminal_cursor: OpaqueCursor | None = None
    next_cursor: OpaqueCursor | None = None
    page_count: PositivePageCount
    record_count: NonnegativeCount
    provider_total_count: NonnegativeCount | None = None
    provider_revision: OpaqueCursor | None = None
    complete: StrictTrue
    page_digests: tuple[Sha256Digest, ...] = Field(
        min_length=1,
        max_length=10_000,
    )

    @field_validator("page_digests", mode="before")
    @classmethod
    def _page_digest_tuple(cls, value: Any) -> Any:
        return _tuple(value)

    @model_validator(mode="after")
    def _complete_checkpoint(self) -> "FinanceSourceCheckpoint":
        if self.page_count != len(self.page_digests):
            raise ValueError("page_count must match page_digests")
        if len(set(self.page_digests)) != len(self.page_digests):
            raise ValueError("page_digests must uniquely identify source pages")
        if self.next_cursor is not None:
            raise ValueError("complete checkpoints cannot retain a next_cursor")
        if (
            self.provider_total_count is not None
            and self.provider_total_count != self.record_count
        ):
            raise ValueError("complete provider total must match record_count")
        if self.cursor_kind == "none":
            if self.initial_cursor is not None or self.terminal_cursor is not None:
                raise ValueError("cursor_kind none cannot carry cursor values")
        elif self.terminal_cursor is None:
            raise ValueError("offset and opaque checkpoints require a terminal_cursor")
        return self


class FinanceObservationEnvelope(_StrictModel):
    """A content-bound source observation candidate with retained evidence refs."""

    schema_id: Literal["lightbulb.finance_observation_envelope.v1"] = Field(
        default=FINANCE_OBSERVATION_ENVELOPE_SCHEMA,
        alias="schema",
    )
    observation_ref: OpaqueRef
    observation_revision: PositiveRevision
    source: FinanceSourceIdentity
    scope: FinanceLedgerScope
    checkpoint: FinanceSourceCheckpoint
    observed_at: str
    effective_at: str
    freshness_class: FreshnessClass
    fresh_until: str
    retained_until: str
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=1,
        max_length=100,
    )
    source_payload_digest: Sha256Digest = _ZERO_DIGEST
    content_digest: Sha256Digest = _ZERO_DIGEST
    evidence_digest: Sha256Digest = _ZERO_DIGEST

    @field_validator("observed_at", "effective_at", "fresh_until", "retained_until")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=info.field_name)

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _revalidated_ordered_evidence(cls, value: Any) -> Any:
        if not isinstance(value, (list, tuple)):
            return value
        revalidated: list[PrimitiveEvidenceRef] = []
        for item in value:
            if isinstance(item, PrimitiveEvidenceRef):
                detached: Any = item.model_dump(
                    mode="python",
                    by_alias=True,
                    exclude_none=False,
                    warnings=False,
                )
            elif isinstance(item, Mapping):
                detached = dict(item)
            else:
                detached = item
            revalidated.append(PrimitiveEvidenceRef.model_validate(detached))
        return tuple(sorted(revalidated, key=lambda item: item.evidence_ref))

    def source_payload_digest_payload(self) -> dict[str, Any]:
        return {
            "dataset": self.source.dataset,
            "provider_revision": self.checkpoint.provider_revision,
            "record_count": self.checkpoint.record_count,
            "page_digests": self.checkpoint.page_digests,
        }

    def content_digest_payload(self) -> dict[str, Any]:
        return {
            "observation_ref": self.observation_ref,
            "observation_revision": self.observation_revision,
            "source": self.source,
            "scope": self.scope,
            "checkpoint": self.checkpoint,
            "observed_at": self.observed_at,
            "effective_at": self.effective_at,
            "freshness_class": self.freshness_class,
            "fresh_until": self.fresh_until,
            "retained_until": self.retained_until,
            "source_payload_digest": self.source_payload_digest,
        }

    def evidence_digest_payload(self) -> dict[str, Any]:
        return {
            "content_digest": self.content_digest,
            "evidence_refs": self.evidence_refs,
        }

    @model_validator(mode="after")
    def _validate_and_seal(self) -> "FinanceObservationEnvelope":
        effective = _as_datetime(self.effective_at)
        observed = _as_datetime(self.observed_at)
        fresh_until = _as_datetime(self.fresh_until)
        retained_until = _as_datetime(self.retained_until)
        if effective > observed:
            raise ValueError("effective_at cannot follow observed_at")
        if observed >= fresh_until:
            raise ValueError("fresh_until must follow observed_at")
        if fresh_until > retained_until:
            raise ValueError("retained_until cannot precede fresh_until")
        if self.retained_until != self.scope.required_retained_until:
            raise ValueError("retained_until must match exact scope retention")

        evidence_refs = [item.evidence_ref for item in self.evidence_refs]
        if len(evidence_refs) != len(set(evidence_refs)):
            raise ValueError("evidence references must be unique")
        evidence_sha = [item.sha256 for item in self.evidence_refs]
        if len(evidence_sha) != len(set(evidence_sha)):
            raise ValueError("source-page evidence SHA-256 digests must be unique")
        if set(evidence_sha) != set(self.checkpoint.page_digests):
            raise ValueError(
                "source-page evidence SHA-256 set must match checkpoint page_digests"
            )
        for evidence in self.evidence_refs:
            if evidence.kind != FINANCE_SOURCE_PAGE_EVIDENCE_KIND:
                raise ValueError(
                    "finance observations require source-page evidence only"
                )
            if evidence.subject_ref != self.observation_ref:
                raise ValueError("evidence subject must match observation_ref")
            if evidence.classification.value != self.scope.classification:
                raise ValueError("evidence classification must match exact scope")
            if evidence.retention_policy != self.scope.retention_policy_ref:
                raise ValueError("evidence retention policy must match exact scope")
            if evidence.jurisdiction != self.scope.jurisdiction_ref:
                raise ValueError("evidence jurisdiction must match exact scope")
            if evidence.verification_grade.value not in {"attested", "verified"}:
                raise ValueError("finance source evidence must be attested or verified")
            if evidence.observed_at != self.observed_at:
                raise ValueError("source-page evidence observed_at must match envelope")
            if evidence.effective_at != self.effective_at:
                raise ValueError(
                    "source-page evidence effective_at must match envelope"
                )

        source_payload_digest = finance_canonical_digest(
            self.source_payload_digest_payload()
        )
        _seal_digest(self, "source_payload_digest", source_payload_digest)
        content_digest = finance_canonical_digest(self.content_digest_payload())
        _seal_digest(self, "content_digest", content_digest)
        evidence_digest = finance_canonical_digest(self.evidence_digest_payload())
        _seal_digest(self, "evidence_digest", evidence_digest)
        return self


class CanonicalLedgerAccount(_StrictModel):
    """Provider-neutral ledger account fact."""

    schema_id: Literal["lightbulb.canonical_ledger_account.v1"] = Field(
        default=CANONICAL_LEDGER_ACCOUNT_SCHEMA,
        alias="schema",
    )
    account_ref: OpaqueRef
    account_code: BoundedText | None = None
    account_name: BoundedText
    account_class: AccountClass
    currency: CurrencyCode
    active: StrictBool


class CanonicalTrialBalanceLine(_StrictModel):
    """One exact, one-sided provider-neutral trial-balance line."""

    schema_id: Literal["lightbulb.canonical_trial_balance_line.v1"] = Field(
        default=CANONICAL_TRIAL_BALANCE_LINE_SCHEMA,
        alias="schema",
    )
    account_ref: OpaqueRef
    account_class: AccountClass
    currency: CurrencyCode
    debit: Money
    credit: Money

    @model_validator(mode="after")
    def _one_sided_amount(self) -> "CanonicalTrialBalanceLine":
        if (self.debit == 0) == (self.credit == 0):
            raise ValueError("trial-balance line requires exactly one non-zero side")
        return self


class CanonicalLedgerSnapshot(_StrictModel):
    """A sealed fixture representation, not a certified or authoritative read."""

    schema_id: Literal["lightbulb.canonical_ledger_snapshot.v1"] = Field(
        default=CANONICAL_LEDGER_SNAPSHOT_SCHEMA,
        alias="schema",
    )
    snapshot_ref: OpaqueRef
    snapshot_revision: PositiveRevision
    scope: FinanceLedgerScope
    as_of: str
    materialized_at: str
    source_observations: tuple[FinanceObservationEnvelope, ...] = Field(
        min_length=2,
        max_length=20,
    )
    accounts: tuple[CanonicalLedgerAccount, ...] = Field(
        min_length=2,
        max_length=5_000,
    )
    trial_balance_lines: tuple[CanonicalTrialBalanceLine, ...] = Field(
        min_length=2,
        max_length=5_000,
    )
    total_debit: Money
    total_credit: Money
    content_digest: Sha256Digest = _ZERO_DIGEST
    evidence_digest: Sha256Digest = _ZERO_DIGEST
    materialization_idempotency_digest: Sha256Digest = _ZERO_DIGEST
    artifact_digest: Sha256Digest = _ZERO_DIGEST

    @field_validator("as_of", "materialized_at")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=info.field_name)

    @field_validator("source_observations", mode="before")
    @classmethod
    def _ordered_sources(cls, value: Any) -> Any:
        if not isinstance(value, (list, tuple)):
            return value

        def source_key(item: Any) -> tuple[str, str]:
            if isinstance(item, Mapping):
                source = item.get("source", {})
                dataset = (
                    source.get("dataset", "") if isinstance(source, Mapping) else ""
                )
                return str(dataset), str(item.get("observation_ref", ""))
            return item.source.dataset, item.observation_ref

        return tuple(sorted(value, key=source_key))

    @field_validator("accounts", "trial_balance_lines", mode="before")
    @classmethod
    def _ordered_records(cls, value: Any) -> Any:
        return _sorted_tuple(value, keys=("account_ref",))

    def content_digest_payload(self) -> dict[str, Any]:
        return {
            "scope": self.scope,
            "as_of": self.as_of,
            "accounts": self.accounts,
            "trial_balance_lines": self.trial_balance_lines,
            "total_debit": self.total_debit,
            "total_credit": self.total_credit,
        }

    def evidence_digest_payload(self) -> dict[str, Any]:
        return {
            "content_digest": self.content_digest,
            "source_observations": self.source_observations,
        }

    def materialization_idempotency_digest_payload(self) -> dict[str, Any]:
        sources = tuple(
            {
                "source": observation.source,
                "checkpoint": observation.checkpoint,
                "source_payload_digest": observation.source_payload_digest,
            }
            for observation in self.source_observations
        )
        return {
            "scope": self.scope,
            "as_of": self.as_of,
            "sources": sources,
            "content_digest": self.content_digest,
        }

    def artifact_digest_payload(self) -> dict[str, Any]:
        return {
            "schema": self.schema_id,
            "snapshot_ref": self.snapshot_ref,
            "snapshot_revision": self.snapshot_revision,
            "materialized_at": self.materialized_at,
            "content_digest": self.content_digest,
            "evidence_digest": self.evidence_digest,
            "materialization_idempotency_digest": (
                self.materialization_idempotency_digest
            ),
        }

    @model_validator(mode="after")
    def _validate_and_seal(self) -> "CanonicalLedgerSnapshot":
        as_of = _as_datetime(self.as_of)
        materialized_at = _as_datetime(self.materialized_at)
        period_started = _as_datetime(self.scope.period_started_at)
        period_ended = _as_datetime(self.scope.period_ended_at)
        if not period_started <= as_of <= period_ended:
            raise ValueError("as_of must fall within the exact fiscal period")
        if materialized_at < as_of:
            raise ValueError("materialized_at cannot precede as_of")

        observations_by_dataset = {
            item.source.dataset: item for item in self.source_observations
        }
        if len(observations_by_dataset) != len(self.source_observations):
            raise ValueError("source observations must use unique datasets")
        if set(observations_by_dataset) != {"chart_of_accounts", "trial_balance"}:
            raise ValueError(
                "ledger snapshots require chart_of_accounts and trial_balance sources"
            )

        binding: tuple[str, str, str, str] | None = None
        for observation in self.source_observations:
            if observation.scope != self.scope:
                raise ValueError("source observation scope must match snapshot scope")
            current_binding = (
                observation.source.provider,
                observation.source.tenant_connector_ref,
                observation.source.connector_account_ref,
                observation.source.provider_account_ref,
            )
            if binding is None:
                binding = current_binding
            elif current_binding != binding:
                raise ValueError(
                    "source observations must use one exact provider binding"
                )
            if observation.effective_at != self.as_of:
                raise ValueError("source effective_at must match snapshot as_of")
            if _as_datetime(observation.observed_at) > materialized_at:
                raise ValueError("source observation cannot follow materialization")
            if materialized_at >= _as_datetime(observation.retained_until):
                raise ValueError("source evidence is expired at materialization")
            if materialized_at > _as_datetime(observation.fresh_until):
                raise ValueError("source evidence is stale at materialization")

        account_refs = [account.account_ref for account in self.accounts]
        if len(account_refs) != len(set(account_refs)):
            raise ValueError("ledger account references must be unique")
        account_codes = [
            account.account_code
            for account in self.accounts
            if account.account_code is not None
        ]
        if len(account_codes) != len(set(account_codes)):
            raise ValueError("ledger account codes must be unique when present")

        accounts_by_ref = {account.account_ref: account for account in self.accounts}
        for account in self.accounts:
            if account.currency != self.scope.functional_currency:
                raise ValueError(
                    "ledger account currency must match functional currency"
                )

        line_refs = [line.account_ref for line in self.trial_balance_lines]
        if len(line_refs) != len(set(line_refs)):
            raise ValueError("trial-balance account references must be unique")
        for line in self.trial_balance_lines:
            account = accounts_by_ref.get(line.account_ref)
            if account is None:
                raise ValueError("trial-balance lines must reference known accounts")
            if line.account_class != account.account_class:
                raise ValueError(
                    "trial-balance account class must match chart of accounts"
                )
            if line.currency != self.scope.functional_currency:
                raise ValueError(
                    "trial-balance currency must match functional currency"
                )

        coa_checkpoint = observations_by_dataset["chart_of_accounts"].checkpoint
        if coa_checkpoint.record_count != len(self.accounts):
            raise ValueError("chart-of-accounts checkpoint count must match accounts")
        trial_checkpoint = observations_by_dataset["trial_balance"].checkpoint
        if trial_checkpoint.record_count != len(self.trial_balance_lines):
            raise ValueError("trial-balance checkpoint count must match lines")

        debit = sum((line.debit for line in self.trial_balance_lines), Decimal(0))
        credit = sum((line.credit for line in self.trial_balance_lines), Decimal(0))
        if self.total_debit != debit or self.total_credit != credit:
            raise ValueError("trial-balance totals must equal exact line totals")
        if debit != credit:
            raise ValueError("trial balance must have equal debit and credit totals")

        content_digest = finance_canonical_digest(self.content_digest_payload())
        _seal_digest(self, "content_digest", content_digest)
        evidence_digest = finance_canonical_digest(self.evidence_digest_payload())
        _seal_digest(self, "evidence_digest", evidence_digest)
        idempotency_digest = finance_canonical_digest(
            self.materialization_idempotency_digest_payload()
        )
        _seal_digest(
            self,
            "materialization_idempotency_digest",
            idempotency_digest,
        )
        artifact_digest = finance_canonical_digest(self.artifact_digest_payload())
        _seal_digest(self, "artifact_digest", artifact_digest)
        return self


__all__ = [
    "CANONICAL_LEDGER_ACCOUNT_SCHEMA",
    "CANONICAL_LEDGER_SNAPSHOT_SCHEMA",
    "CANONICAL_TRIAL_BALANCE_LINE_SCHEMA",
    "FINANCE_LEDGER_SCOPE_SCHEMA",
    "FINANCE_OBSERVATION_ENVELOPE_SCHEMA",
    "FINANCE_SOURCE_CHECKPOINT_SCHEMA",
    "FINANCE_SOURCE_PAGE_EVIDENCE_KIND",
    "FINANCE_SOURCE_IDENTITY_SCHEMA",
    "CanonicalLedgerAccount",
    "CanonicalLedgerSnapshot",
    "CanonicalTrialBalanceLine",
    "FinanceLedgerScope",
    "FinanceObservationEnvelope",
    "FinanceSourceCheckpoint",
    "FinanceSourceIdentity",
    "finance_canonical_digest",
    "finance_canonical_json",
]
