"""Governed provider lock-status evidence for the finance close lighthouse.

QuickBooks and Xero express accounting locks differently. This primitive keeps
those provider meanings explicit while presenting one typed observation shape.
Spring remains authoritative for tenant/company/project scope, the exact
connector account and credential, dispatch, durable evidence, and rollout.

Completion proves only a bounded read of provider lock configuration. It does
not prove Lightbulb close readiness, reconcile balances, post entries, mutate a
provider lock, or authorize a period transition.
"""

from __future__ import annotations

import hashlib
import json
import re
from calendar import monthrange
from collections.abc import Mapping
from datetime import date, datetime, timezone
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

PROVIDER_PERIOD_STATUS_INPUT_SCHEMA = (
    "lightbulb.finance_provider_period_status_input.v1"
)
PROVIDER_PERIOD_LOCK_SCHEMA = "lightbulb.finance_provider_period_lock.v1"
PROVIDER_PERIOD_STATUS_RESULT_SCHEMA = (
    "lightbulb.finance_provider_period_status_result.v1"
)
PROVIDER_PERIOD_STATUS_RESPONSE_SCHEMA = "lightbulb.provider_period_status.v1"

QUICKBOOKS_PERIOD_STATUS_TOOL = "quickbooks.get_period_status"
XERO_PERIOD_STATUS_TOOL = "xero.get_period_status"
PROVIDER_PERIOD_STATUS_TOOL_VERSION = 2

Provider = Literal["quickbooks", "xero"]
LockKind = Literal[
    "books_closed_through",
    "period_lock_through",
    "year_end_lock_through",
]
PeriodRelation = Literal[
    "no_provider_lock_configured",
    "fully_at_or_before_provider_lock",
    "overlaps_provider_lock_boundary",
    "after_provider_locks",
]

_TOOL_BY_PROVIDER: dict[str, str] = {
    "quickbooks": QUICKBOOKS_PERIOD_STATUS_TOOL,
    "xero": XERO_PERIOD_STATUS_TOOL,
}
_LOCK_KINDS_BY_PROVIDER: dict[str, frozenset[str]] = {
    "quickbooks": frozenset({"books_closed_through"}),
    "xero": frozenset({"period_lock_through", "year_end_lock_through"}),
}
_REVISION_KIND_BY_PROVIDER = {
    "quickbooks": "sync_token",
    "xero": "content_sha256",
}
_LOCK_KIND_ORDER = {
    "books_closed_through": 0,
    "period_lock_through": 0,
    "year_end_lock_through": 1,
}
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_PORTABLE_REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@+\-]{0,199}$"


def _visible_ref(value: str) -> str:
    if value != value.strip() or any(ord(character) < 33 for character in value):
        raise ValueError("references must contain visible non-whitespace characters")
    return value


OpaqueRef = Annotated[
    str,
    StringConstraints(pattern=_PORTABLE_REF_PATTERN),
    AfterValidator(_visible_ref),
]
Sha256Digest = Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)]


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        revalidate_instances="always",
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
        raise ValueError("period-status dates must be exact ISO dates") from exc
    if start.isoformat() != start_date or end.isoformat() != end_date:
        raise ValueError("period-status dates must use YYYY-MM-DD")
    if start.day != 1 or (start.year, start.month) != (end.year, end.month):
        raise ValueError("period-status scope must be one complete calendar month")
    if end.day != monthrange(end.year, end.month)[1]:
        raise ValueError("period-status scope must end on the month's final day")
    return start, end


def _canonical_timestamp(value: str, *, field_name: str) -> str:
    if not isinstance(value, str) or value != value.strip():
        raise ValueError(f"{field_name} must be a trimmed timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field_name} must be valid ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field_name} must include an offset")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class ProviderPeriodStatusInput(_StrictModel):
    schema_id: Literal["lightbulb.finance_provider_period_status_input.v1"] = Field(
        default=PROVIDER_PERIOD_STATUS_INPUT_SCHEMA,
        alias="schema",
    )
    provider: Provider
    start_date: str
    end_date: str

    @model_validator(mode="after")
    def _complete_month(self) -> "ProviderPeriodStatusInput":
        _parse_complete_month(self.start_date, self.end_date)
        return self


class ProviderPeriodLock(_StrictModel):
    schema_id: Literal["lightbulb.finance_provider_period_lock.v1"] = Field(
        default=PROVIDER_PERIOD_LOCK_SCHEMA,
        alias="schema",
    )
    lock_kind: LockKind
    through_date: str

    @field_validator("through_date")
    @classmethod
    def _exact_date(cls, value: str) -> str:
        try:
            parsed = date.fromisoformat(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("through_date must be an exact ISO date") from exc
        if parsed.isoformat() != value:
            raise ValueError("through_date must use YYYY-MM-DD")
        return value


class ProviderPeriodStatusResult(_StrictModel):
    schema_id: Literal["lightbulb.finance_provider_period_status_result.v1"] = Field(
        default=PROVIDER_PERIOD_STATUS_RESULT_SCHEMA,
        alias="schema",
    )
    provider: Provider
    tool: Literal[
        "quickbooks.get_period_status",
        "xero.get_period_status",
    ]
    tool_version: Literal[2] = PROVIDER_PERIOD_STATUS_TOOL_VERSION
    project_id: UUID
    tenant_connector_id: UUID
    connector_account_ref: OpaqueRef
    route_digest: Sha256Digest
    start_date: str
    end_date: str
    locks: tuple[ProviderPeriodLock, ...] = Field(max_length=2)
    period_relation: PeriodRelation
    source_revision_kind: Literal["sync_token", "content_sha256"]
    source_revision: str = Field(min_length=1, max_length=128)
    source_updated_at: str | None = None
    provider_observed_at: str
    provider_response_sha256: Sha256Digest
    execution_journal_ref: OpaqueRef
    provenance_receipt_digest: Sha256Digest
    execution_completed_at: str
    authoritative_read: Literal[True] = True
    bounded_observation: Literal[True] = True
    provider_lock_configuration_only: Literal[True] = True
    close_transition_authority: Literal[False] = False
    source_digest: Sha256Digest = "0" * 64

    @field_validator(
        "source_updated_at",
        "provider_observed_at",
        "execution_completed_at",
    )
    @classmethod
    def _timestamps(cls, value: str | None, info: Any) -> str | None:
        if value is None:
            return None
        return _canonical_timestamp(value, field_name=info.field_name)

    @model_validator(mode="after")
    def _coherent(self) -> "ProviderPeriodStatusResult":
        start, end = _parse_complete_month(self.start_date, self.end_date)
        if self.tool != _TOOL_BY_PROVIDER[self.provider]:
            raise ValueError("provider and period-status Tool must match")
        if self.source_revision_kind != _REVISION_KIND_BY_PROVIDER[self.provider]:
            raise ValueError("provider and source revision kind must match")
        if self.source_revision_kind == "content_sha256" and not re.fullmatch(
            _SHA256_PATTERN, self.source_revision
        ):
            raise ValueError("content source revision must be SHA-256")
        if self.source_revision_kind == "sync_token" and not re.fullmatch(
            r"^[0-9]{1,20}$", self.source_revision
        ):
            raise ValueError("QuickBooks source revision must be an exact SyncToken")
        if (self.provider == "quickbooks") != (self.source_updated_at is not None):
            raise ValueError("source update time must match provider semantics")
        lock_kinds = [lock.lock_kind for lock in self.locks]
        if len(lock_kinds) != len(set(lock_kinds)):
            raise ValueError("provider period lock kinds must be unique")
        if not set(lock_kinds).issubset(_LOCK_KINDS_BY_PROVIDER[self.provider]):
            raise ValueError("provider period lock kind is not supported")
        if tuple(self.locks) != tuple(
            sorted(self.locks, key=lambda lock: _LOCK_KIND_ORDER[lock.lock_kind])
        ):
            raise ValueError("provider period locks are not canonically ordered")
        expected_relation = _period_relation(start, end, self.locks)
        if self.period_relation != expected_relation:
            raise ValueError("period relation does not match provider lock dates")
        expected_digest = _status_digest(self)
        if self.source_digest == "0" * 64:
            object.__setattr__(self, "source_digest", expected_digest)
        elif self.source_digest != expected_digest:
            raise ValueError("period-status source digest does not match content")
        return self


def _period_relation(
    start: date,
    end: date,
    locks: tuple[ProviderPeriodLock, ...],
) -> PeriodRelation:
    if not locks:
        return "no_provider_lock_configured"
    latest_lock = max(date.fromisoformat(lock.through_date) for lock in locks)
    if end <= latest_lock:
        return "fully_at_or_before_provider_lock"
    if start <= latest_lock < end:
        return "overlaps_provider_lock_boundary"
    return "after_provider_locks"


def _status_digest(result: ProviderPeriodStatusResult) -> str:
    payload = result.to_dict()
    payload.pop("source_digest", None)
    return _stable_digest(payload)


class _PeriodStatusError(ValueError):
    def __init__(self, code: str, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable


def _operation_spec(provider: Provider) -> PrimitiveOperationSpec:
    return PrimitiveOperationSpec(
        operation_ref=f"read_{provider}_period_status",
        tool=_TOOL_BY_PROVIDER[provider],
        effect=ConnectorEffect.READ,
        replay_class=PrimitiveOperationReplayClass.SAFE,
        freshness_class=PrimitiveOperationFreshnessClass.CURRENT,
        recovery_policy=PrimitiveOperationRecoveryPolicy.RETRY,
        approval_required=False,
    )


def _validate_provenance(
    provenance: ConnectorExecutionProvenance | None,
    request: ConnectorExecutionRequest,
) -> ConnectorExecutionProvenance:
    if provenance is None:
        raise _PeriodStatusError(
            "provider_period_status_provenance_missing",
            "The governed period-status result has no Spring provenance.",
        )
    if (
        provenance.tool != request.tool
        or provenance.tool_version != PROVIDER_PERIOD_STATUS_TOOL_VERSION
        or provenance.server_effect != ConnectorEffect.READ
        or provenance.connector_account_ref != request.connector_account_ref
        or request.scope.project_id is None
        or provenance.project_id != request.scope.project_id
        or provenance.request_digest != request.custody_fingerprint()
        or provenance.approval_ref is not None
        or provenance.approval_receipt_digest is not None
    ):
        raise _PeriodStatusError(
            "provider_period_status_provenance_mismatch",
            "Spring provenance does not match the exact period-status request.",
        )
    return provenance


def _normalize_output(
    output: Mapping[str, Any] | None,
    *,
    provider: Provider,
    start: date,
    end: date,
) -> tuple[
    tuple[ProviderPeriodLock, ...],
    PeriodRelation,
    str,
    str,
    str | None,
    str,
    str,
]:
    if not isinstance(output, Mapping):
        raise _PeriodStatusError(
            "provider_period_status_response_invalid",
            "The provider period-status response is not an object.",
        )
    required = {
        "schema",
        "provider",
        "locks",
        "source_revision_kind",
        "source_revision",
        "provider_observed_at",
        "provider_response_sha256",
    }
    allowed = required | {"source_updated_at"}
    if set(output) != required and set(output) != allowed:
        raise _PeriodStatusError(
            "provider_period_status_response_invalid",
            "The provider period-status response shape drifted.",
        )
    if (
        output.get("schema") != PROVIDER_PERIOD_STATUS_RESPONSE_SCHEMA
        or output.get("provider") != provider
    ):
        raise _PeriodStatusError(
            "provider_period_status_response_invalid",
            "The provider period-status response identity drifted.",
        )
    raw_locks = output.get("locks")
    if not isinstance(raw_locks, list) or len(raw_locks) > 2:
        raise _PeriodStatusError(
            "provider_period_status_response_invalid",
            "The provider period-status lock collection is invalid.",
        )
    try:
        locks = tuple(ProviderPeriodLock.model_validate(lock) for lock in raw_locks)
        revision_kind = output.get("source_revision_kind")
        revision = output.get("source_revision")
        source_updated_at = output.get("source_updated_at")
        provider_observed_at = output.get("provider_observed_at")
        response_digest = output.get("provider_response_sha256")
        if revision_kind != _REVISION_KIND_BY_PROVIDER[provider]:
            raise ValueError("source revision kind drifted")
        if not isinstance(revision, str) or not revision or revision != revision.strip():
            raise ValueError("source revision is invalid")
        if revision_kind == "content_sha256" and not re.fullmatch(
            _SHA256_PATTERN, revision
        ):
            raise ValueError("content revision is not SHA-256")
        if revision_kind == "sync_token" and not re.fullmatch(
            r"^[0-9]{1,20}$", revision
        ):
            raise ValueError("QuickBooks revision is not an exact SyncToken")
        if source_updated_at is not None:
            source_updated_at = _canonical_timestamp(
                source_updated_at,
                field_name="source_updated_at",
            )
        provider_observed_at = _canonical_timestamp(
            provider_observed_at,
            field_name="provider_observed_at",
        )
        if not isinstance(response_digest, str) or not re.fullmatch(
            _SHA256_PATTERN, response_digest
        ):
            raise ValueError("provider response digest is invalid")
        if (provider == "quickbooks") != (source_updated_at is not None):
            raise ValueError("source update time does not match provider semantics")
    except (TypeError, ValueError) as exc:
        raise _PeriodStatusError(
            "provider_period_status_response_invalid",
            "The provider period-status evidence is invalid.",
        ) from exc
    kinds = [lock.lock_kind for lock in locks]
    if len(kinds) != len(set(kinds)) or not set(kinds).issubset(
        _LOCK_KINDS_BY_PROVIDER[provider]
    ):
        raise _PeriodStatusError(
            "provider_period_status_response_invalid",
            "The provider period-status lock kinds drifted.",
        )
    locks = tuple(sorted(locks, key=lambda lock: _LOCK_KIND_ORDER[lock.lock_kind]))
    return (
        locks,
        _period_relation(start, end, locks),
        revision_kind,
        revision,
        source_updated_at,
        provider_observed_at,
        response_digest,
    )


def _receipt(
    *,
    provider: Provider,
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
        spec=_operation_spec(provider),
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


class DiscoverProviderPeriodStatusPrimitive(
    BusinessProcessPrimitive[ProviderPeriodStatusInput, ProviderPeriodStatusResult]
):
    primitive_ref = "finance.discover_provider_period_status"
    version = "1.0.0"
    title = "Discover governed provider period status"
    description = (
        "Read QuickBooks books-close or Xero lock-date configuration through one "
        "exact governed route without changing provider or Lightbulb close state."
    )
    input_model = ProviderPeriodStatusInput
    output_model = ProviderPeriodStatusResult
    connector_tools = (QUICKBOOKS_PERIOD_STATUS_TOOL, XERO_PERIOD_STATUS_TOOL)
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
        inputs: ProviderPeriodStatusInput,
    ) -> PrimitiveExecutionResult[ProviderPeriodStatusResult]:
        start, end = _parse_complete_month(inputs.start_date, inputs.end_date)
        tool = _TOOL_BY_PROVIDER[inputs.provider]
        spec = _operation_spec(inputs.provider)
        if context.preview_only:
            receipt = PrimitiveOperationReceipt(
                spec=spec,
                status=PrimitiveOperationStatus.PLANNED,
                request_digest=_stable_digest(
                    {
                        "schema": "lightbulb.provider_period_status_plan.v1",
                        "provider": inputs.provider,
                        "tool": tool,
                        "arguments": {},
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
                    f"{inputs.provider} period status previewed; no connector read "
                    "was requested and no lock evidence was fabricated."
                ),
                operation_receipts=[receipt],
                connector_tool=tool,
            )

        account_ref = context.connector_account_refs.get(tool)
        if account_ref is None:
            account_ref = context.connector_account_refs.get(inputs.provider)
        if context.scope.project_id is None or not str(account_ref or "").strip():
            blocker = PrimitiveBlocker(
                code="provider_period_status_scope_required",
                message=(
                    "Governed period-status discovery requires an authenticated "
                    "project UUID and exact provider connector-account binding."
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
            arguments={},
            effect=ConnectorEffect.READ,
            approval_required=False,
            operation_ref=spec.operation_ref,
            connector_account_ref=str(account_ref),
            metadata={
                "source": self.primitive_ref,
                "provider": inputs.provider,
                "start_date": inputs.start_date,
                "end_date": inputs.end_date,
            },
        )
        result = context.connectors.execute(request)
        if result.tool != request.tool:
            blocker = PrimitiveBlocker(
                code="provider_period_status_tool_mismatch",
                message="The connector response is not bound to the requested Tool.",
            )
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.FAILED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary=blocker.message,
                blockers=[blocker],
                operation_receipts=[
                    _receipt(
                        provider=inputs.provider,
                        request=request,
                        result=result,
                        blocker=blocker,
                        force_failed=True,
                    )
                ],
                connector_tool=tool,
            )
        if result.status != ConnectorExecutionStatus.COMPLETED:
            blocked = result.status in {
                ConnectorExecutionStatus.BLOCKED,
                ConnectorExecutionStatus.PENDING_APPROVAL,
            }
            blocker = PrimitiveBlocker(
                code="provider_period_status_read_failed",
                message="The governed provider period-status read did not complete.",
                retryable=result.retryable,
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
                operation_receipts=[
                    _receipt(
                        provider=inputs.provider,
                        request=request,
                        result=result,
                        blocker=blocker,
                    )
                ],
                connector_tool=tool,
                retryable=result.retryable,
            )

        provenance: ConnectorExecutionProvenance | None = None
        try:
            provenance = _validate_provenance(result.provenance, request)
            (
                locks,
                relation,
                revision_kind,
                revision,
                source_updated_at,
                provider_observed_at,
                response_digest,
            ) = _normalize_output(
                result.output,
                provider=inputs.provider,
                start=start,
                end=end,
            )
            output = ProviderPeriodStatusResult(
                provider=inputs.provider,
                tool=tool,
                project_id=context.scope.project_id,
                tenant_connector_id=provenance.tenant_connector_id,
                connector_account_ref=provenance.connector_account_ref,
                route_digest=provenance.route_digest,
                start_date=inputs.start_date,
                end_date=inputs.end_date,
                locks=locks,
                period_relation=relation,
                source_revision_kind=revision_kind,
                source_revision=revision,
                source_updated_at=source_updated_at,
                provider_observed_at=provider_observed_at,
                provider_response_sha256=response_digest,
                execution_journal_ref=provenance.journal_ref,
                provenance_receipt_digest=provenance.receipt_digest,
                execution_completed_at=provenance.completed_at,
            )
        except (_PeriodStatusError, ValueError) as exc:
            if isinstance(exc, _PeriodStatusError):
                code, message, retryable = exc.code, exc.message, exc.retryable
            else:
                code = "provider_period_status_response_invalid"
                message = "The provider period-status evidence is invalid."
                retryable = False
            blocker = PrimitiveBlocker(code=code, message=message, retryable=retryable)
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.FAILED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary=blocker.message,
                blockers=[blocker],
                operation_receipts=[
                    _receipt(
                        provider=inputs.provider,
                        request=request,
                        result=result,
                        blocker=blocker,
                        provenance_valid=provenance is not None,
                        force_failed=True,
                    )
                ],
                connector_tool=tool,
                retryable=retryable,
            )

        return PrimitiveExecutionResult(
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                f"Observed {len(output.locks)} governed {output.provider} provider "
                f"lock controls; the requested period is {output.period_relation}."
            ),
            output=output,
            events=[
                PrimitiveEvent(
                    type="finance.provider_period_status_discovered",
                    payload={
                        "provider": output.provider,
                        "start_date": output.start_date,
                        "end_date": output.end_date,
                        "period_relation": output.period_relation,
                        "source_digest": output.source_digest,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="governed_provider_period_status",
                    summary=(
                        "Provider lock configuration was read through exact Spring "
                        "provenance without granting close-transition authority."
                    ),
                    labels=[
                        output.provider,
                        "authoritative_read",
                        "bounded_observation",
                        "provider_lock_configuration",
                        "close_transition_not_authorized",
                    ],
                    refs={"source_digest": output.source_digest},
                )
            ],
            operation_receipts=[
                _receipt(
                    provider=inputs.provider,
                    request=request,
                    result=result,
                    provenance_valid=True,
                )
            ],
            connector_tool=tool,
        )


FINANCE_PROVIDER_PERIOD_STATUS_EXECUTABLE_PRIMITIVES: tuple[
    BusinessProcessPrimitive[Any, Any], ...
] = (DiscoverProviderPeriodStatusPrimitive(),)


__all__ = [
    "DiscoverProviderPeriodStatusPrimitive",
    "FINANCE_PROVIDER_PERIOD_STATUS_EXECUTABLE_PRIMITIVES",
    "PROVIDER_PERIOD_LOCK_SCHEMA",
    "PROVIDER_PERIOD_STATUS_INPUT_SCHEMA",
    "PROVIDER_PERIOD_STATUS_RESPONSE_SCHEMA",
    "PROVIDER_PERIOD_STATUS_RESULT_SCHEMA",
    "PROVIDER_PERIOD_STATUS_TOOL_VERSION",
    "ProviderPeriodLock",
    "ProviderPeriodStatusInput",
    "ProviderPeriodStatusResult",
    "QUICKBOOKS_PERIOD_STATUS_TOOL",
    "XERO_PERIOD_STATUS_TOOL",
]
