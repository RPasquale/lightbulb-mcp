"""Durable, scope-bound post-action observation and evaluation runtime.

The runtime intentionally keeps connector payloads, plans, and receipts out of
``WorkflowCheckpoint``.  Checkpoints contain only a bounded job contract and
content digests; a trusted artifact repository owns the larger signed objects.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Literal, Mapping, Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from lightbulb.connector_execution import (
    ConnectorEffect,
    ConnectorExecutionRequest,
    ConnectorExecutionResult,
    ConnectorExecutionStatus,
    ConnectorExecutor,
    ExecutionScope,
)
from lightbulb.durable_runtime import (
    CheckpointConflictError,
    CheckpointPersistenceError,
    CheckpointScopeError,
    CheckpointStatus,
    WorkflowCheckpoint,
    WorkflowCheckpointStore,
    WorkflowEventEnvelope,
)
from lightbulb.dynamic_workflows import DynamicWorkflowScope
from lightbulb.gtm_primitives import (
    OmnichannelProductLaunchPlan,
    ProductLaunchIterationEvaluation,
    ProductLaunchReceipt,
    evaluate_product_launch_iteration,
    mint_product_launch_receipt,
    verify_product_launch_plan,
)
from lightbulb.primitive_runtime import PrimitiveBlocker
from lightbulb.profit_workflow_runtime import (
    ProfitActionExecutionReceipt,
    ProfitContributionLedger,
    ProfitMetricEvidence,
    ProfitOutcomeEvidence,
    ProfitWorkflowEvaluation,
    ProfitWorkflowPlan,
    evaluate_profit_workflow_iteration,
    get_profit_workflow_definition,
    mint_profit_metric_evidence,
    mint_profit_outcome_evidence,
    verify_profit_action_execution_receipt,
    verify_profit_workflow_plan,
)


OBSERVATION_JOB_SCHEMA = "lightbulb.post_action_observation_job.v1"
OBSERVATION_READ_RECEIPT_SCHEMA = "lightbulb.observation_read_receipt.v1"
OBSERVATION_RESULT_SCHEMA = "lightbulb.post_action_observation_result.v1"
STOREFRONT_PHASE_EVALUATION_SCHEMA = "lightbulb.storefront_phase_evaluation.v1"
SHOPIFY_ANALYTICS_PAYLOAD_SCHEMA = "lightbulb.shopify_analytics_observation.v1"
GOOGLE_ANALYTICS_PAYLOAD_SCHEMA = "lightbulb.google_analytics_observation.v1"
CHECKOUT_RECOVERY_SNAPSHOT_PAYLOAD_SCHEMA = "lightbulb.checkout_recovery_snapshot.v1"
HOST_OBSERVATION_READ_REQUEST_SCHEMA = "lightbulb.host_observation_read_request.v1"
HOST_OBSERVATION_PROVENANCE_SCHEMA = "lightbulb.host_observation_provenance.v1"
OBSERVATION_RUNTIME_VERSION = "1.0.0"

_OBSERVATION_RECEIPT_HMAC_DOMAIN = "lightbulb.observation_read_receipt.v1"
_STOREFRONT_PHASE_EVALUATION_HMAC_DOMAIN = STOREFRONT_PHASE_EVALUATION_SCHEMA
_HOST_OBSERVATION_PROVENANCE_HMAC_DOMAIN = "lightbulb.host_observation_provenance.v1"
_MAX_QUERY_ARGUMENT_BYTES = 16_384
_MAX_OBSERVATION_OUTPUT_BYTES = 65_536
_SHA256_RE = r"^[0-9a-f]{64}$"
_PORTABLE_REF_RE = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"
_TOOL_RE = r"^[a-z][a-z0-9_-]{0,63}\.[a-z][a-z0-9_.-]{0,127}$"
_FORBIDDEN_ARGUMENT_KEYS = frozenset(
    {
        "access_token",
        "api_key",
        "apikey",
        "authorization",
        "cookie",
        "credential",
        "password",
        "private_key",
        "refresh_token",
        "secret",
        "token",
    }
)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must include a UTC offset")
    return value.astimezone(timezone.utc)


def _timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamp must be valid ISO-8601") from exc
    return _utc(parsed)


def _iso(value: datetime) -> str:
    return _utc(value).isoformat().replace("+00:00", "Z")


def _digest(value: Any) -> str:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json", by_alias=True, exclude_none=True)
    material = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _claim_partition_ref(scope: DynamicWorkflowScope) -> str:
    """Opaque full-scope claim key; project_ref alone is not tenant-safe."""

    return f"observation-scope-{_digest(scope)[:48]}"


def _decimal(value: Any, *, quantum: Decimal | None = None) -> Decimal:
    if isinstance(value, bool):
        raise ValueError("boolean values are not numeric observations")
    lexical = str(value)
    if len(lexical) > 64:
        raise ValueError("observation numeric value is too large")
    try:
        result = Decimal(lexical)
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("observation value is not a decimal") from exc
    if not result.is_finite():
        raise ValueError("observation values must be finite")
    try:
        return result.quantize(quantum, rounding=ROUND_HALF_UP) if quantum else result
    except InvalidOperation as exc:
        raise ValueError("observation value exceeds supported precision") from exc


def _ratio(numerator: int, denominator: int) -> Decimal:
    if denominator <= 0:
        raise ValueError("ratio denominator must be positive")
    if numerator < 0 or numerator > denominator:
        raise ValueError("ratio numerator must be between zero and its denominator")
    return (Decimal(numerator) / Decimal(denominator)).quantize(
        Decimal("0.000001"), rounding=ROUND_HALF_UP
    )


def _assert_no_secret_keys(value: Any, *, path: str = "arguments") -> None:
    if isinstance(value, Mapping):
        for raw_key, nested in value.items():
            key = str(raw_key).strip().lower()
            if key in _FORBIDDEN_ARGUMENT_KEYS or any(
                forbidden in key for forbidden in ("password", "secret", "token")
            ):
                raise ValueError(
                    f"{path} must not contain credential field {raw_key!r}"
                )
            _assert_no_secret_keys(nested, path=f"{path}.{raw_key}")
    elif isinstance(value, (list, tuple)):
        for index, nested in enumerate(value):
            _assert_no_secret_keys(nested, path=f"{path}[{index}]")


def _bounded_query_arguments(value: Mapping[str, Any]) -> dict[str, Any]:
    arguments = dict(value)
    _assert_no_secret_keys(arguments)
    try:
        encoded = json.dumps(
            arguments,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("observation query arguments must be canonical JSON") from exc
    if len(encoded) > _MAX_QUERY_ARGUMENT_BYTES:
        raise ValueError("observation query arguments exceed 16384 bytes")
    return arguments


def _bounded_observation_output(value: Mapping[str, Any]) -> dict[str, Any]:
    output = dict(value)
    try:
        encoded = json.dumps(
            output,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("observation output must be canonical JSON") from exc
    if len(encoded) > _MAX_OBSERVATION_OUTPUT_BYTES:
        raise ValueError("observation output exceeds 65536 bytes")
    return output


def _checkout_recovery_query_arguments(
    value: Mapping[str, Any], *, launch_ref: str
) -> dict[str, Any]:
    arguments = dict(value)
    allowed = {"case_ref", "experiment_ref", "launch_ref"}
    unexpected = set(arguments).difference(allowed)
    if unexpected:
        raise ValueError(
            "checkout recovery query accepts only opaque case/experiment/launch refs"
        )
    if "launch_ref" in arguments and arguments["launch_ref"] != launch_ref:
        raise ValueError("checkout recovery query launch_ref does not match the plan")
    arguments["launch_ref"] = launch_ref
    for key, item in arguments.items():
        if not isinstance(item, str) or not re.fullmatch(_PORTABLE_REF_RE, item):
            raise ValueError(f"checkout recovery {key} must be an opaque portable ref")
    return arguments


def _assert_artifact_has_no_raw_output(value: Any, *, path: str = "artifact") -> None:
    if isinstance(value, Mapping):
        for raw_key, nested in value.items():
            key = str(raw_key).strip().lower()
            if key in {
                "connector_output",
                "connector_response",
                "raw_connector_output",
                "raw_output",
                "resolved_secrets",
            }:
                raise ValueError(f"{path} must not persist {raw_key!r}")
            _assert_artifact_has_no_raw_output(nested, path=f"{path}.{raw_key}")
    elif isinstance(value, (list, tuple)):
        for index, nested in enumerate(value):
            _assert_artifact_has_no_raw_output(nested, path=f"{path}[{index}]")


def _privacy_safe_artifact_payload(value: Mapping[str, Any]) -> dict[str, Any]:
    payload = dict(value)
    _assert_no_secret_keys(payload, path="artifact")
    _assert_artifact_has_no_raw_output(payload)
    _bounded_observation_output(payload)
    return payload


class _FrozenModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        revalidate_instances="always",
    )


class ObservationJobSpec(_FrozenModel):
    """The complete bounded contract safe to persist in a checkpoint."""

    schema_id: Literal["lightbulb.post_action_observation_job.v1"] = Field(
        default=OBSERVATION_JOB_SCHEMA,
        alias="schema",
    )
    job_ref: str = Field(pattern=_PORTABLE_REF_RE)
    kind: Literal["gtm", "storefront_phase", "profit"]
    project_ref: str = Field(min_length=1, max_length=200)
    exact_scope_digest: str = Field(pattern=_SHA256_RE)
    receipt_key_id: str = Field(min_length=8, max_length=80)
    project_id: UUID
    plan_digest: str = Field(pattern=_SHA256_RE)
    run_ref: str = Field(pattern=_PORTABLE_REF_RE)
    iteration: int = Field(ge=1, le=4)
    provider: Literal["shopify", "google_analytics", "host"]
    source_capability: str = Field(pattern=_TOOL_RE)
    connector_account_ref: str | None = Field(
        default=None, min_length=1, max_length=200
    )
    subject_account_refs: tuple[str, ...] = Field(default_factory=tuple, max_length=20)
    tenant_connector_id: UUID | None = None
    expected_tool_version: int = Field(ge=1)
    expected_route_digest: str | None = Field(default=None, pattern=_SHA256_RE)
    query_digest: str = Field(pattern=_SHA256_RE)
    context_digest: str = Field(pattern=_SHA256_RE)
    target_metric: str = Field(min_length=1, max_length=80)
    target_unit: Literal["money", "ratio", "count", "days", "multiple"]
    currency: str | None = Field(default=None, pattern=r"^[A-Z]{3}$")
    latest_action_completed_at: str
    window_start: str
    window_end: str
    due_at: str
    minimum_sample_size: int = Field(ge=1, le=1_000_000_000)
    max_observation_age_hours: int = Field(ge=1, le=8_760)
    max_attempts: int = Field(default=3, ge=1, le=10)
    job_digest: str = Field(default="0" * 64, pattern=_SHA256_RE)

    @field_validator(
        "latest_action_completed_at", "window_start", "window_end", "due_at"
    )
    @classmethod
    def _valid_time(cls, value: str) -> str:
        return _iso(_timestamp(value))

    @field_validator("subject_account_refs", mode="before")
    @classmethod
    def _immutable_accounts(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _closed_contract(self) -> "ObservationJobSpec":
        latest = _timestamp(self.latest_action_completed_at)
        start = _timestamp(self.window_start)
        end = _timestamp(self.window_end)
        due = _timestamp(self.due_at)
        if start <= latest:
            raise ValueError(
                "observation window must start after every action completed"
            )
        if end <= start:
            raise ValueError("observation window must have positive duration")
        if due <= end or due <= latest + (end - start):
            raise ValueError(
                "due_at must be strictly after latest completion plus the full window"
            )
        if self.provider == "host":
            if (
                self.connector_account_ref is not None
                or self.tenant_connector_id is not None
                or self.expected_route_digest is not None
            ):
                raise ValueError("host observations must not claim connector custody")
            if not self.subject_account_refs:
                raise ValueError("host observations require exact subject accounts")
        else:
            if (
                self.connector_account_ref is None
                or self.tenant_connector_id is None
                or self.expected_route_digest is None
            ):
                raise ValueError(
                    "connector observations require an exact account and route digest"
                )
            if self.subject_account_refs:
                raise ValueError(
                    "connector observations cannot claim host subject accounts"
                )
        if len(self.subject_account_refs) != len(set(self.subject_account_refs)):
            raise ValueError("subject_account_refs must be unique")
        if self.target_unit == "money" and self.currency is None:
            raise ValueError("money observations require currency")
        if self.target_unit != "money" and self.currency is not None:
            raise ValueError("only money observations may declare currency")
        payload = self.model_dump(
            mode="json", by_alias=True, exclude={"job_digest"}, exclude_none=True
        )
        expected = _digest(payload)
        if self.job_digest not in {"0" * 64, expected}:
            raise ValueError("job_digest does not match the observation contract")
        object.__setattr__(self, "job_digest", expected)
        return self


class NormalizedObservation(_FrozenModel):
    metric: str = Field(min_length=1, max_length=80)
    unit: Literal["money", "ratio", "count", "days", "multiple"]
    value: Decimal
    sample_size: int = Field(ge=0, le=10_000_000_000)
    currency: str | None = Field(default=None, pattern=r"^[A-Z]{3}$")
    exposure_count: int | None = Field(default=None, ge=1, le=10_000_000_000)
    ledger: ProfitContributionLedger | None = None

    @field_validator("value", mode="before")
    @classmethod
    def _numeric(cls, value: Any) -> Decimal:
        return _decimal(value)

    @model_validator(mode="after")
    def _valid_unit(self) -> "NormalizedObservation":
        if self.unit == "money" and self.currency is None:
            raise ValueError("money observation requires currency")
        if self.unit != "money" and self.currency is not None:
            raise ValueError("only money observation may declare currency")
        if self.unit == "ratio" and not Decimal("0") <= self.value <= Decimal("1"):
            raise ValueError("ratio observation must be between zero and one")
        if self.unit in {"count", "days", "multiple"} and self.value < 0:
            raise ValueError("non-money observation must not be negative")
        return self


class ObservationReadReceipt(_FrozenModel):
    """Host-HMAC evidence that one exact governed read produced a metric."""

    schema_id: Literal["lightbulb.observation_read_receipt.v1"] = Field(
        default=OBSERVATION_READ_RECEIPT_SCHEMA,
        alias="schema",
    )
    receipt_ref: str = Field(pattern=_PORTABLE_REF_RE)
    job_ref: str = Field(pattern=_PORTABLE_REF_RE)
    job_digest: str = Field(pattern=_SHA256_RE)
    scope: DynamicWorkflowScope
    exact_scope_digest: str = Field(pattern=_SHA256_RE)
    project_id: UUID
    provider: Literal["shopify", "google_analytics", "host"]
    source_capability: str = Field(pattern=_TOOL_RE)
    connector_account_ref: str | None = None
    subject_account_refs: tuple[str, ...] = Field(default_factory=tuple)
    tenant_connector_id: UUID | None = None
    tool_version: int = Field(ge=1)
    query_digest: str = Field(pattern=_SHA256_RE)
    request_digest: str = Field(pattern=_SHA256_RE)
    execution_receipt_digest: str = Field(pattern=_SHA256_RE)
    journal_ref: str = Field(min_length=1, max_length=200)
    raw_output_digest: str = Field(pattern=_SHA256_RE)
    window_start: str
    window_end: str
    observed_at: str
    normalized: NormalizedObservation
    receipt_key_id: str = Field(min_length=8, max_length=80)
    receipt_hmac: str = Field(pattern=_SHA256_RE)
    receipt_digest: str = Field(default="0" * 64, pattern=_SHA256_RE)

    @field_validator("window_start", "window_end", "observed_at")
    @classmethod
    def _valid_time(cls, value: str) -> str:
        return _iso(_timestamp(value))

    @field_validator("subject_account_refs", mode="before")
    @classmethod
    def _immutable_accounts(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _seal_digest(self) -> "ObservationReadReceipt":
        if _timestamp(self.observed_at) < _timestamp(self.window_end):
            raise ValueError("observation receipt predates its measurement window")
        if self.provider == "host":
            if (
                self.connector_account_ref is not None
                or self.tenant_connector_id is not None
            ):
                raise ValueError("host receipts must not claim connector custody")
            if not self.subject_account_refs:
                raise ValueError("host receipts require exact subject accounts")
        else:
            if self.connector_account_ref is None or self.tenant_connector_id is None:
                raise ValueError("connector receipts require exact account custody")
            if self.subject_account_refs:
                raise ValueError(
                    "connector receipts cannot claim host subject accounts"
                )
        if len(self.subject_account_refs) != len(set(self.subject_account_refs)):
            raise ValueError("receipt subject account refs must be unique")
        payload = self.model_dump(
            mode="json", by_alias=True, exclude={"receipt_digest"}, exclude_none=True
        )
        expected = _digest(payload)
        if self.receipt_digest not in {"0" * 64, expected}:
            raise ValueError("receipt_digest does not match canonical read evidence")
        object.__setattr__(self, "receipt_digest", expected)
        return self

    def hmac_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"receipt_hmac", "receipt_digest"},
            exclude_none=True,
        )


class ShopifyAnalyticsPayload(_FrozenModel):
    schema_id: Literal["lightbulb.shopify_analytics_observation.v1"] = Field(
        default=SHOPIFY_ANALYTICS_PAYLOAD_SCHEMA,
        alias="schema",
    )
    query_digest: str = Field(pattern=_SHA256_RE)
    window_start: str
    window_end: str
    sample_size: int = Field(ge=0, le=10_000_000_000)
    sessions: int | None = Field(default=None, ge=0)
    sessions_that_completed_checkout: int | None = Field(default=None, ge=0)
    sessions_with_cart_additions: int | None = Field(default=None, ge=0)
    sessions_that_reached_checkout: int | None = Field(default=None, ge=0)
    orders: int | None = Field(default=None, ge=0)
    currency: str | None = Field(default=None, pattern=r"^[A-Z]{3}$")
    total_sales: Decimal | None = None

    @field_validator("window_start", "window_end")
    @classmethod
    def _valid_time(cls, value: str) -> str:
        return _iso(_timestamp(value))

    @field_validator(
        "total_sales",
        mode="before",
    )
    @classmethod
    def _money(cls, value: Any) -> Decimal | None:
        return None if value is None else _decimal(value, quantum=Decimal("0.01"))


class GoogleAnalyticsPayload(_FrozenModel):
    schema_id: Literal["lightbulb.google_analytics_observation.v1"] = Field(
        default=GOOGLE_ANALYTICS_PAYLOAD_SCHEMA,
        alias="schema",
    )
    query_digest: str = Field(pattern=_SHA256_RE)
    window_start: str
    window_end: str
    sample_size: int = Field(ge=0, le=10_000_000_000)
    sessions: int = Field(ge=0)
    conversions: int | None = Field(default=None, ge=0)
    impressions: int | None = Field(default=None, ge=0)
    clicks: int | None = Field(default=None, ge=0)
    add_to_cart_sessions: int | None = Field(default=None, ge=0)
    checkout_sessions: int | None = Field(default=None, ge=0)
    completed_checkout_sessions: int | None = Field(default=None, ge=0)

    @field_validator("window_start", "window_end")
    @classmethod
    def _valid_time(cls, value: str) -> str:
        return _iso(_timestamp(value))


class CheckoutRecoverySnapshotPayload(_FrozenModel):
    """Aggregate, privacy-minimised randomized-holdout recovery snapshot."""

    schema_id: Literal["lightbulb.checkout_recovery_snapshot.v1"] = Field(
        default=CHECKOUT_RECOVERY_SNAPSHOT_PAYLOAD_SCHEMA,
        alias="schema",
    )
    query_digest: str = Field(pattern=_SHA256_RE)
    exact_scope_digest: str = Field(pattern=_SHA256_RE)
    subject_account_refs: tuple[str, ...] = Field(min_length=1, max_length=20)
    window_start: str
    window_end: str
    attribution_method: Literal["randomized_holdout"]
    sample_size: int = Field(ge=2, le=10_000_000_000)
    treatment_sample_size: int = Field(ge=1, le=10_000_000_000)
    holdout_sample_size: int = Field(ge=1, le=10_000_000_000)
    treatment_contribution_profit: Decimal = Field(
        ge=-1_000_000_000_000, le=1_000_000_000_000
    )
    holdout_contribution_profit: Decimal = Field(
        ge=-1_000_000_000_000, le=1_000_000_000_000
    )
    incremental_ledger: ProfitContributionLedger

    @field_validator("window_start", "window_end")
    @classmethod
    def _valid_time(cls, value: str) -> str:
        return _iso(_timestamp(value))

    @field_validator("subject_account_refs", mode="before")
    @classmethod
    def _immutable_accounts(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator(
        "treatment_contribution_profit",
        "holdout_contribution_profit",
        mode="before",
    )
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=Decimal("0.01"))

    @model_validator(mode="after")
    def _deterministic_holdout_effect(self) -> "CheckoutRecoverySnapshotPayload":
        if len(self.subject_account_refs) != len(set(self.subject_account_refs)):
            raise ValueError("snapshot subject accounts must be unique")
        if _timestamp(self.window_end) <= _timestamp(self.window_start):
            raise ValueError("snapshot window must have positive duration")
        if self.sample_size != (self.treatment_sample_size + self.holdout_sample_size):
            raise ValueError("snapshot sample_size must cover both cohorts exactly")
        expected = (
            self.treatment_contribution_profit
            - (
                self.holdout_contribution_profit
                * Decimal(self.treatment_sample_size)
                / Decimal(self.holdout_sample_size)
            )
        ).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
        if self.incremental_ledger.contribution_profit != expected:
            raise ValueError(
                "incremental ledger does not match the randomized holdout effect"
            )
        return self


class ObservationNormalizer(Protocol):
    tool: str
    provider: str

    def supports_metric(self, metric: str) -> bool: ...

    def normalize(
        self, output: Mapping[str, Any], *, spec: ObservationJobSpec
    ) -> NormalizedObservation: ...


class ObservationScopeKeyRing(Protocol):
    active_key_id: str

    def exact_scope_digest(
        self, *, key_id: str, scope: DynamicWorkflowScope
    ) -> str: ...

    def sign(self, key_id: str, domain: str, payload: Any) -> bytes: ...


class HostObservationReadRequest(_FrozenModel):
    """Exact, idempotent request crossing into a trusted host data reader."""

    schema_id: Literal["lightbulb.host_observation_read_request.v1"] = Field(
        default=HOST_OBSERVATION_READ_REQUEST_SCHEMA,
        alias="schema",
    )
    job_ref: str = Field(pattern=_PORTABLE_REF_RE)
    job_digest: str = Field(pattern=_SHA256_RE)
    scope: DynamicWorkflowScope
    exact_scope_digest: str = Field(pattern=_SHA256_RE)
    receipt_key_id: str = Field(min_length=8, max_length=80)
    project_id: UUID
    source_capability: str = Field(pattern=_TOOL_RE)
    tool_version: int = Field(ge=1)
    subject_account_refs: tuple[str, ...] = Field(min_length=1, max_length=20)
    query_arguments: Dict[str, Any]
    query_digest: str = Field(pattern=_SHA256_RE)
    target_metric: str = Field(min_length=1, max_length=80)
    target_unit: Literal["money", "ratio", "count", "days", "multiple"]
    currency: str | None = Field(default=None, pattern=r"^[A-Z]{3}$")
    window_start: str
    window_end: str
    idempotency_key: str = Field(min_length=1, max_length=200)
    request_digest: str = Field(default="0" * 64, pattern=_SHA256_RE)

    @field_validator("window_start", "window_end")
    @classmethod
    def _valid_time(cls, value: str) -> str:
        return _iso(_timestamp(value))

    @field_validator("subject_account_refs", mode="before")
    @classmethod
    def _immutable_accounts(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _closed_request(self) -> "HostObservationReadRequest":
        _bounded_query_arguments(self.query_arguments)
        if len(self.subject_account_refs) != len(set(self.subject_account_refs)):
            raise ValueError("host read subject accounts must be unique")
        if tuple(sorted(self.subject_account_refs)) != self.subject_account_refs:
            raise ValueError("host read subject accounts must be canonical")
        if _timestamp(self.window_end) <= _timestamp(self.window_start):
            raise ValueError("host read window must have positive duration")
        if _digest(self.query_arguments) != self.query_digest:
            raise ValueError("host read query arguments do not match query_digest")
        if self.target_unit == "money" and self.currency is None:
            raise ValueError("money host reads require currency")
        if self.target_unit != "money" and self.currency is not None:
            raise ValueError("only money host reads may declare currency")
        payload = self.model_dump(
            mode="json", by_alias=True, exclude={"request_digest"}, exclude_none=True
        )
        expected = _digest(payload)
        if self.request_digest not in {"0" * 64, expected}:
            raise ValueError("host request_digest does not match request custody")
        object.__setattr__(self, "request_digest", expected)
        return self


class HostObservationReadProvenance(_FrozenModel):
    """Scope-HMAC custody receipt returned by the trusted host reader."""

    schema_id: Literal["lightbulb.host_observation_provenance.v1"] = Field(
        default=HOST_OBSERVATION_PROVENANCE_SCHEMA,
        alias="schema",
    )
    reader_ref: str = Field(pattern=_PORTABLE_REF_RE)
    source_capability: str = Field(pattern=_TOOL_RE)
    tool_version: int = Field(ge=1)
    project_id: UUID
    exact_scope_digest: str = Field(pattern=_SHA256_RE)
    subject_account_refs: tuple[str, ...] = Field(min_length=1, max_length=20)
    query_digest: str = Field(pattern=_SHA256_RE)
    request_digest: str = Field(pattern=_SHA256_RE)
    output_digest: str = Field(pattern=_SHA256_RE)
    journal_ref: str = Field(min_length=1, max_length=200)
    completed_at: str
    receipt_key_id: str = Field(min_length=8, max_length=80)
    provenance_hmac: str = Field(pattern=_SHA256_RE)
    provenance_digest: str = Field(default="0" * 64, pattern=_SHA256_RE)

    @field_validator("completed_at")
    @classmethod
    def _valid_time(cls, value: str) -> str:
        return _iso(_timestamp(value))

    @field_validator("subject_account_refs", mode="before")
    @classmethod
    def _immutable_accounts(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _sealed_provenance(self) -> "HostObservationReadProvenance":
        if len(self.subject_account_refs) != len(set(self.subject_account_refs)):
            raise ValueError("host provenance subject accounts must be unique")
        if tuple(sorted(self.subject_account_refs)) != self.subject_account_refs:
            raise ValueError("host provenance subject accounts must be canonical")
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"provenance_digest"},
            exclude_none=True,
        )
        expected = _digest(payload)
        if self.provenance_digest not in {"0" * 64, expected}:
            raise ValueError("host provenance_digest does not match its receipt")
        object.__setattr__(self, "provenance_digest", expected)
        return self

    def hmac_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"provenance_hmac", "provenance_digest"},
            exclude_none=True,
        )


class HostObservationReadResult(_FrozenModel):
    status: Literal["completed", "failed"]
    output: Dict[str, Any] | None = None
    provenance: HostObservationReadProvenance | None = None
    retryable: bool = False
    error_code: str | None = Field(default=None, pattern=_PORTABLE_REF_RE)

    @model_validator(mode="after")
    def _closed_result(self) -> "HostObservationReadResult":
        completed = self.status == "completed"
        if completed != (self.output is not None and self.provenance is not None):
            raise ValueError("completed host reads require output and provenance")
        if completed and (self.retryable or self.error_code is not None):
            raise ValueError("completed host reads cannot declare a failure")
        if not completed and (self.output is not None or self.provenance is not None):
            raise ValueError("failed host reads cannot return untrusted output")
        if not completed and self.error_code is None:
            raise ValueError("failed host reads require a bounded error code")
        if self.output is not None:
            _bounded_observation_output(self.output)
        return self


class HostObservationReader(Protocol):
    def supports(self, source_capability: str) -> bool: ...

    def read(
        self, request: HostObservationReadRequest
    ) -> HostObservationReadResult: ...


def mint_host_observation_read_result(
    request_value: HostObservationReadRequest | Mapping[str, Any],
    output_value: Mapping[str, Any],
    *,
    completed_at: datetime,
    reader_ref: str,
    journal_ref: str,
    scope_keyring: ObservationScopeKeyRing,
) -> HostObservationReadResult:
    """Seal one trusted host read for consumption by ``ObservationRuntime``."""

    request = HostObservationReadRequest.model_validate(
        request_value.model_dump(mode="python", by_alias=True)
        if isinstance(request_value, HostObservationReadRequest)
        else request_value
    )
    output = _bounded_observation_output(output_value)
    expected_scope = scope_keyring.exact_scope_digest(
        key_id=request.receipt_key_id,
        scope=request.scope,
    )
    if not hmac.compare_digest(expected_scope, request.exact_scope_digest):
        raise ValueError("host read request does not match authenticated scope")
    draft = HostObservationReadProvenance(
        reader_ref=reader_ref,
        source_capability=request.source_capability,
        tool_version=request.tool_version,
        project_id=request.project_id,
        exact_scope_digest=request.exact_scope_digest,
        subject_account_refs=request.subject_account_refs,
        query_digest=request.query_digest,
        request_digest=request.request_digest,
        output_digest=_digest(output),
        journal_ref=journal_ref,
        completed_at=_iso(completed_at),
        receipt_key_id=request.receipt_key_id,
        provenance_hmac="0" * 64,
    )
    signature = scope_keyring.sign(
        request.receipt_key_id,
        _HOST_OBSERVATION_PROVENANCE_HMAC_DOMAIN,
        draft.hmac_payload(),
    ).hex()
    payload = draft.model_dump(mode="python", by_alias=True)
    payload["provenance_hmac"] = signature
    payload["provenance_digest"] = "0" * 64
    provenance = HostObservationReadProvenance.model_validate(payload)
    return HostObservationReadResult(
        status="completed",
        output=output,
        provenance=provenance,
    )


def _require_payload_binding(
    payload: ShopifyAnalyticsPayload | GoogleAnalyticsPayload,
    spec: ObservationJobSpec,
) -> None:
    if payload.query_digest != spec.query_digest:
        raise ValueError("connector output query digest does not match the job")
    if (
        payload.window_start != spec.window_start
        or payload.window_end != spec.window_end
    ):
        raise ValueError("connector output window does not match the scheduled job")
    if payload.sample_size < spec.minimum_sample_size:
        raise ValueError("observation sample is below the configured floor")


class ShopifyAnalyticsNormalizer:
    tool = "shopify.analytics_query"
    provider = "shopify"
    supported_metrics = frozenset(
        {
            "conversion_rate",
            "storefront_conversion_rate",
            "add_to_cart_rate",
            "checkout_completion_rate",
            "average_order_value",
        }
    )

    def supports_metric(self, metric: str) -> bool:
        return metric in self.supported_metrics

    def normalize(
        self, output: Mapping[str, Any], *, spec: ObservationJobSpec
    ) -> NormalizedObservation:
        payload = ShopifyAnalyticsPayload.model_validate(output)
        _require_payload_binding(payload, spec)
        metric = spec.target_metric
        if not self.supports_metric(metric):
            raise ValueError(f"Shopify analytics cannot normalize metric {metric!r}")
        currency: str | None = None
        sample_basis: int | None = None
        if metric in {"conversion_rate", "storefront_conversion_rate"}:
            if (
                payload.sessions_that_completed_checkout is None
                or payload.sessions is None
            ):
                raise ValueError(
                    "conversion rate requires completed-checkout and total sessions"
                )
            value = _ratio(
                payload.sessions_that_completed_checkout,
                payload.sessions,
            )
            sample_basis = payload.sessions
        elif metric == "add_to_cart_rate":
            if payload.sessions_with_cart_additions is None or payload.sessions is None:
                raise ValueError(
                    "add-to-cart rate requires cart-addition and total sessions"
                )
            value = _ratio(payload.sessions_with_cart_additions, payload.sessions)
            sample_basis = payload.sessions
        elif metric == "checkout_completion_rate":
            if (
                payload.sessions_that_completed_checkout is None
                or payload.sessions_that_reached_checkout is None
            ):
                raise ValueError(
                    "checkout completion requires reached-checkout and "
                    "completed-checkout sessions"
                )
            value = _ratio(
                payload.sessions_that_completed_checkout,
                payload.sessions_that_reached_checkout,
            )
            sample_basis = payload.sessions_that_reached_checkout
        elif metric == "average_order_value":
            if payload.total_sales is None or not payload.orders:
                raise ValueError("average order value requires total sales and orders")
            value = (payload.total_sales / Decimal(payload.orders)).quantize(
                Decimal("0.01"), rounding=ROUND_HALF_UP
            )
            currency = payload.currency
            sample_basis = payload.orders
        else:
            raise ValueError(f"Shopify analytics cannot normalize metric {metric!r}")
        if sample_basis is None or payload.sample_size != sample_basis:
            raise ValueError(
                "Shopify sample_size does not match the metric denominator"
            )
        return NormalizedObservation(
            metric=metric,
            unit=spec.target_unit,
            value=value,
            sample_size=payload.sample_size,
            currency=currency,
        )


class GoogleAnalyticsNormalizer:
    tool = "google_analytics.fetch_metrics"
    provider = "google_analytics"
    supported_metrics = frozenset(
        {
            "conversion_rate",
            "storefront_conversion_rate",
            "click_through_rate",
            "add_to_cart_rate",
            "checkout_completion_rate",
        }
    )

    def supports_metric(self, metric: str) -> bool:
        return metric in self.supported_metrics

    def normalize(
        self, output: Mapping[str, Any], *, spec: ObservationJobSpec
    ) -> NormalizedObservation:
        payload = GoogleAnalyticsPayload.model_validate(output)
        _require_payload_binding(payload, spec)
        metric = spec.target_metric
        sample_basis: int
        if metric in {"conversion_rate", "storefront_conversion_rate"}:
            if payload.conversions is None:
                raise ValueError("conversion rate requires conversions")
            value = _ratio(payload.conversions, payload.sessions)
            sample_basis = payload.sessions
        elif metric == "click_through_rate":
            if payload.clicks is None or payload.impressions is None:
                raise ValueError("click-through rate requires clicks and impressions")
            value = _ratio(payload.clicks, payload.impressions)
            sample_basis = payload.impressions
        elif metric == "add_to_cart_rate":
            if payload.add_to_cart_sessions is None:
                raise ValueError("add-to-cart rate requires add-to-cart sessions")
            value = _ratio(payload.add_to_cart_sessions, payload.sessions)
            sample_basis = payload.sessions
        elif metric == "checkout_completion_rate":
            if (
                payload.completed_checkout_sessions is None
                or payload.checkout_sessions is None
            ):
                raise ValueError("checkout completion requires checkout sessions")
            value = _ratio(
                payload.completed_checkout_sessions, payload.checkout_sessions
            )
            sample_basis = payload.checkout_sessions
        else:
            raise ValueError(f"Google Analytics cannot normalize metric {metric!r}")
        if payload.sample_size != sample_basis:
            raise ValueError(
                "Google Analytics sample_size does not match the metric denominator"
            )
        return NormalizedObservation(
            metric=metric,
            unit=spec.target_unit,
            value=value,
            sample_size=payload.sample_size,
        )


class CheckoutRecoverySnapshotNormalizer:
    tool = "host.checkout_recovery_snapshot"
    provider = "host"
    supported_metrics = frozenset({"recovered_contribution_profit"})

    def supports_metric(self, metric: str) -> bool:
        return metric in self.supported_metrics

    def normalize(
        self, output: Mapping[str, Any], *, spec: ObservationJobSpec
    ) -> NormalizedObservation:
        payload = CheckoutRecoverySnapshotPayload.model_validate(output)
        if spec.target_metric != "recovered_contribution_profit":
            raise ValueError(
                "checkout recovery snapshots only measure recovered contribution profit"
            )
        if payload.query_digest != spec.query_digest:
            raise ValueError("host output query digest does not match the job")
        if payload.exact_scope_digest != spec.exact_scope_digest:
            raise ValueError("host output scope does not match the scheduled job")
        if payload.subject_account_refs != spec.subject_account_refs:
            raise ValueError("host output subject accounts do not match the job")
        if (
            payload.window_start != spec.window_start
            or payload.window_end != spec.window_end
        ):
            raise ValueError("host output window does not match the scheduled job")
        if (
            min(payload.treatment_sample_size, payload.holdout_sample_size)
            < spec.minimum_sample_size
        ):
            raise ValueError(
                "each randomized holdout cohort must meet the configured sample floor"
            )
        ledger = payload.incremental_ledger
        if ledger.currency != spec.currency:
            raise ValueError("host observation currency does not match the job")
        return NormalizedObservation(
            metric=spec.target_metric,
            unit=spec.target_unit,
            value=ledger.contribution_profit,
            sample_size=payload.sample_size,
            currency=ledger.currency,
            ledger=ledger,
        )


class StorefrontPhaseEvaluation(_FrozenModel):
    """Sealed Shopify-storefront phase result; never omnichannel completion."""

    schema_id: Literal["lightbulb.storefront_phase_evaluation.v1"] = Field(
        default=STOREFRONT_PHASE_EVALUATION_SCHEMA,
        alias="schema",
    )
    evaluation_ref: str = Field(pattern=_PORTABLE_REF_RE)
    plan_digest: str = Field(pattern=_SHA256_RE)
    exact_scope_digest: str = Field(pattern=_SHA256_RE)
    receipt_key_id: str = Field(min_length=8, max_length=80)
    run_ref: str = Field(pattern=_PORTABLE_REF_RE)
    iteration: int = Field(ge=1, le=4)
    max_iterations: int = Field(ge=1, le=4)
    provider: Literal["shopify", "google_analytics"]
    source_capability: Literal[
        "shopify.analytics_query", "google_analytics.fetch_metrics"
    ]
    connector_account_ref: str = Field(min_length=1, max_length=200)
    primary_metric: Literal["conversion_rate", "click_through_rate"]
    observed_value: Decimal
    target_value: Decimal
    sample_size: int = Field(ge=1, le=10_000_000_000)
    window_start: str
    window_end: str
    evaluated_at: str
    evidence_receipt_digest: str = Field(pattern=_SHA256_RE)
    storefront_receipt_digests: tuple[str, ...] = Field(min_length=4, max_length=4)
    previous_evaluation_digest: str | None = Field(default=None, pattern=_SHA256_RE)
    decision: Literal["target_met", "revise_plan", "iteration_limit_reached"]
    next_iteration: int | None = Field(default=None, ge=2, le=4)
    evaluation_hmac: str = Field(pattern=_SHA256_RE)
    evaluation_digest: str = Field(default="0" * 64, pattern=_SHA256_RE)

    @field_validator("observed_value", "target_value", mode="before")
    @classmethod
    def _rate(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=Decimal("0.000001"))

    @field_validator("window_start", "window_end", "evaluated_at")
    @classmethod
    def _valid_time(cls, value: str) -> str:
        return _iso(_timestamp(value))

    @field_validator("storefront_receipt_digests", mode="before")
    @classmethod
    def _immutable_receipts(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _deterministic_decision(self) -> "StorefrontPhaseEvaluation":
        if self.iteration > self.max_iterations:
            raise ValueError("storefront iteration exceeds the plan limit")
        if not Decimal("0") <= self.observed_value <= Decimal("1"):
            raise ValueError("storefront observed rate must be between zero and one")
        if not Decimal("0") <= self.target_value <= Decimal("1"):
            raise ValueError("storefront target rate must be between zero and one")
        if len(set(self.storefront_receipt_digests)) != 4:
            raise ValueError("storefront phase requires four unique receipt digests")
        if (self.iteration == 1) != (self.previous_evaluation_digest is None):
            raise ValueError("storefront evaluation chain is incomplete")
        if self.observed_value >= self.target_value:
            expected_decision = "target_met"
            expected_next = None
        elif self.iteration < self.max_iterations:
            expected_decision = "revise_plan"
            expected_next = self.iteration + 1
        else:
            expected_decision = "iteration_limit_reached"
            expected_next = None
        if self.decision != expected_decision or self.next_iteration != expected_next:
            raise ValueError("storefront phase decision is not deterministic")
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"evaluation_digest"},
            exclude_none=True,
        )
        expected = _digest(payload)
        if self.evaluation_digest not in {"0" * 64, expected}:
            raise ValueError("storefront evaluation digest mismatch")
        object.__setattr__(self, "evaluation_digest", expected)
        return self

    def hmac_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"evaluation_hmac", "evaluation_digest"},
            exclude_none=True,
        )


class GtmObservationContext(_FrozenModel):
    spec_digest: str = Field(pattern=_SHA256_RE)
    scope: DynamicWorkflowScope
    query_arguments: Dict[str, Any]
    plan: OmnichannelProductLaunchPlan
    action_receipts: tuple[ProductLaunchReceipt, ...]
    previous_evaluation: ProductLaunchIterationEvaluation | None = None
    context_digest: str = Field(default="0" * 64, pattern=_SHA256_RE)

    @field_validator("action_receipts", mode="before")
    @classmethod
    def _immutable_receipts(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _sealed(self) -> "GtmObservationContext":
        _bounded_query_arguments(self.query_arguments)
        expected = _digest(
            self.model_dump(mode="json", exclude={"context_digest"}, exclude_none=True)
        )
        if self.context_digest not in {"0" * 64, expected}:
            raise ValueError("GTM observation context digest mismatch")
        object.__setattr__(self, "context_digest", expected)
        return self


class StorefrontPhaseObservationContext(_FrozenModel):
    spec_digest: str = Field(pattern=_SHA256_RE)
    scope: DynamicWorkflowScope
    query_arguments: Dict[str, Any]
    plan: OmnichannelProductLaunchPlan
    storefront_receipts: tuple[ProductLaunchReceipt, ...] = Field(
        min_length=4, max_length=4
    )
    previous_evaluation: StorefrontPhaseEvaluation | None = None
    context_digest: str = Field(default="0" * 64, pattern=_SHA256_RE)

    @field_validator("storefront_receipts", mode="before")
    @classmethod
    def _immutable_receipts(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _sealed(self) -> "StorefrontPhaseObservationContext":
        _bounded_query_arguments(self.query_arguments)
        expected = _digest(
            self.model_dump(mode="json", exclude={"context_digest"}, exclude_none=True)
        )
        if self.context_digest not in {"0" * 64, expected}:
            raise ValueError("storefront observation context digest mismatch")
        object.__setattr__(self, "context_digest", expected)
        return self


class ProfitObservationContext(_FrozenModel):
    spec_digest: str = Field(pattern=_SHA256_RE)
    scope: DynamicWorkflowScope
    query_arguments: Dict[str, Any]
    plan: ProfitWorkflowPlan
    action_receipts: tuple[ProfitActionExecutionReceipt, ...]
    previous_evaluation: ProfitWorkflowEvaluation | None = None
    context_digest: str = Field(default="0" * 64, pattern=_SHA256_RE)

    @field_validator("action_receipts", mode="before")
    @classmethod
    def _immutable_receipts(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _sealed(self) -> "ProfitObservationContext":
        _bounded_query_arguments(self.query_arguments)
        expected = _digest(
            self.model_dump(mode="json", exclude={"context_digest"}, exclude_none=True)
        )
        if self.context_digest not in {"0" * 64, expected}:
            raise ValueError("profit observation context digest mismatch")
        object.__setattr__(self, "context_digest", expected)
        return self


ObservationContext = (
    GtmObservationContext | StorefrontPhaseObservationContext | ProfitObservationContext
)


class ObservationRunResult(_FrozenModel):
    schema_id: Literal["lightbulb.post_action_observation_result.v1"] = Field(
        default=OBSERVATION_RESULT_SCHEMA,
        alias="schema",
    )
    job_ref: str = Field(pattern=_PORTABLE_REF_RE)
    job_digest: str = Field(pattern=_SHA256_RE)
    status: Literal["completed"] = "completed"
    read_receipt: ObservationReadReceipt
    storefront_phase_evaluation: StorefrontPhaseEvaluation | None = None
    gtm_performance_receipt: ProductLaunchReceipt | None = None
    gtm_evaluation: ProductLaunchIterationEvaluation | None = None
    profit_metric_evidence: ProfitMetricEvidence | None = None
    profit_outcome: ProfitOutcomeEvidence | None = None
    profit_evaluation: ProfitWorkflowEvaluation | None = None
    next_iteration_event: WorkflowEventEnvelope | None = None
    result_digest: str = Field(default="0" * 64, pattern=_SHA256_RE)

    @model_validator(mode="after")
    def _one_evaluation_kind(self) -> "ObservationRunResult":
        storefront = self.storefront_phase_evaluation is not None
        gtm = (
            self.gtm_performance_receipt is not None or self.gtm_evaluation is not None
        )
        profit = any(
            value is not None
            for value in (
                self.profit_metric_evidence,
                self.profit_outcome,
                self.profit_evaluation,
            )
        )
        if sum((storefront, gtm, profit)) != 1:
            raise ValueError("result must contain exactly one evaluation kind")
        if gtm and (
            self.gtm_performance_receipt is None or self.gtm_evaluation is None
        ):
            raise ValueError("GTM result is incomplete")
        if profit and any(
            value is None
            for value in (
                self.profit_metric_evidence,
                self.profit_outcome,
                self.profit_evaluation,
            )
        ):
            raise ValueError("profit result is incomplete")
        evaluation = (
            self.storefront_phase_evaluation
            or self.gtm_evaluation
            or self.profit_evaluation
        )
        if evaluation is None:
            raise ValueError("result has no evaluation")
        decision = evaluation.decision
        if (decision == "revise_plan") != (self.next_iteration_event is not None):
            raise ValueError("only revise decisions emit one next-iteration event")
        payload = self.model_dump(
            mode="json", by_alias=True, exclude={"result_digest"}, exclude_none=True
        )
        expected = _digest(payload)
        if self.result_digest not in {"0" * 64, expected}:
            raise ValueError("result_digest does not match observation result")
        object.__setattr__(self, "result_digest", expected)
        return self


class ObservationArtifactRepository(Protocol):
    def put_context(self, job_ref: str, context: ObservationContext) -> None: ...

    def get_context(self, job_ref: str) -> ObservationContext | None: ...

    def put_result(self, result: ObservationRunResult) -> None: ...

    def get_result(self, job_ref: str) -> ObservationRunResult | None: ...


class InMemoryObservationArtifactRepository:
    """Conflict-detecting test/reference repository; production may use object storage."""

    def __init__(self) -> None:
        self._contexts: dict[str, ObservationContext] = {}
        self._results: dict[str, ObservationRunResult] = {}
        self._lock = threading.RLock()

    def put_context(self, job_ref: str, context: ObservationContext) -> None:
        stored = type(context).model_validate(context.model_dump(mode="python"))
        with self._lock:
            prior = self._contexts.get(job_ref)
            if prior is not None and prior.context_digest != stored.context_digest:
                raise CheckpointConflictError("observation context ref was reused")
            self._contexts[job_ref] = stored

    def get_context(self, job_ref: str) -> ObservationContext | None:
        with self._lock:
            value = self._contexts.get(job_ref)
            if value is None:
                return None
            return type(value).model_validate(value.model_dump(mode="python"))

    def put_result(self, result: ObservationRunResult) -> None:
        stored = ObservationRunResult.model_validate(result.model_dump(mode="python"))
        with self._lock:
            prior = self._results.get(result.job_ref)
            if prior is not None and prior.result_digest != stored.result_digest:
                raise CheckpointConflictError("observation result ref was reused")
            self._results[result.job_ref] = stored

    def get_result(self, job_ref: str) -> ObservationRunResult | None:
        with self._lock:
            value = self._results.get(job_ref)
            if value is None:
                return None
            return ObservationRunResult.model_validate(value.model_dump(mode="python"))


class _JsonObservationArtifactEnvelope(_FrozenModel):
    schema_id: Literal["lightbulb.observation_artifact.v1"] = Field(
        default="lightbulb.observation_artifact.v1",
        alias="schema",
    )
    artifact_kind: Literal[
        "gtm_context", "storefront_context", "profit_context", "result"
    ]
    job_ref: str = Field(pattern=_PORTABLE_REF_RE)
    scope_fingerprint: str = Field(pattern=_SHA256_RE)
    project_ref: str = Field(min_length=1, max_length=200)
    exact_scope_digest: str = Field(pattern=_SHA256_RE)
    artifact_digest: str = Field(pattern=_SHA256_RE)
    payload: Dict[str, Any]
    envelope_digest: str = Field(default="0" * 64, pattern=_SHA256_RE)

    @model_validator(mode="after")
    def _canonical_envelope(self) -> "_JsonObservationArtifactEnvelope":
        _privacy_safe_artifact_payload(self.payload)
        if _digest(self.payload) != self.artifact_digest:
            raise ValueError("artifact payload does not match artifact_digest")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"envelope_digest"},
            exclude_none=True,
        )
        expected = _digest(material)
        if self.envelope_digest not in {"0" * 64, expected}:
            raise ValueError("observation artifact envelope digest mismatch")
        object.__setattr__(self, "envelope_digest", expected)
        return self


class JsonFileObservationArtifactRepository:
    """Immutable, atomic JSON artifact store suitable for one shared filesystem."""

    def __init__(self, directory: str | Path, *, scope_fingerprint: str) -> None:
        requested = Path(directory).expanduser()
        if requested.is_symlink():
            raise CheckpointPersistenceError(
                f"refusing symlinked observation artifact directory: {requested}"
            )
        normalized_scope = str(scope_fingerprint).strip().lower()
        if re.fullmatch(_SHA256_RE, normalized_scope) is None:
            raise ValueError("scope_fingerprint must be a lowercase SHA-256 value")
        self.scope_fingerprint = normalized_scope
        self.directory = requested.resolve()
        self.directory.mkdir(parents=True, exist_ok=True)
        if not self.directory.is_dir():
            raise ValueError("observation artifact path must be a directory")
        try:
            os.chmod(self.directory, 0o700)
        except OSError:
            pass

    @staticmethod
    def _scope_fields(
        context: ObservationContext,
    ) -> tuple[
        str, str, Literal["gtm_context", "storefront_context", "profit_context"]
    ]:
        if isinstance(context, GtmObservationContext):
            digest = context.plan.analytics_scope.exact_scope_digest
            if digest is None:
                raise ValueError("GTM context has no exact scope binding")
            return context.scope.project_ref, digest, "gtm_context"
        if isinstance(context, StorefrontPhaseObservationContext):
            digest = context.plan.analytics_scope.exact_scope_digest
            if digest is None:
                raise ValueError("storefront context has no exact scope binding")
            return context.scope.project_ref, digest, "storefront_context"
        return (
            context.scope.project_ref,
            context.plan.exact_scope_digest,
            "profit_context",
        )

    def _path(self, job_ref: str, *, suffix: Literal["context", "result"]) -> Path:
        if re.fullmatch(_PORTABLE_REF_RE, job_ref) is None:
            raise ValueError("job_ref is not portable")
        filename = (
            f"{hashlib.sha256(job_ref.encode('utf-8')).hexdigest()}.{suffix}.json"
        )
        # Keep the lexical path: resolve() would FOLLOW a symlink planted at
        # the artifact name, so every later is_symlink() refusal would examine
        # the target instead of the link and pass a swapped artifact through.
        path = self.directory / filename
        if path.is_symlink():
            raise CheckpointPersistenceError(
                f"unsafe local observation artifact target: {path}"
            )
        if path.resolve().parent != self.directory:
            raise ValueError("artifact path escaped its repository")
        return path

    @staticmethod
    def _canonical_bytes(envelope: _JsonObservationArtifactEnvelope) -> bytes:
        return (
            json.dumps(
                envelope.model_dump(mode="json", by_alias=True),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")

    def _write_once(
        self, path: Path, envelope: _JsonObservationArtifactEnvelope
    ) -> None:
        if envelope.scope_fingerprint != self.scope_fingerprint:
            raise CheckpointScopeError(
                "observation artifact does not match repository scope partition"
            )
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise CheckpointPersistenceError(
                f"unsafe local observation artifact target: {path}"
            )
        canonical = self._canonical_bytes(envelope)
        temporary: Path | None = None
        try:
            descriptor, raw_path = tempfile.mkstemp(
                prefix=f".{path.stem}.", suffix=".tmp", dir=self.directory
            )
            temporary = Path(raw_path)
            if temporary.is_symlink():
                os.close(descriptor)
                raise CheckpointPersistenceError(
                    f"unsafe local observation artifact temporary: {temporary}"
                )
            try:
                os.chmod(temporary, 0o600)
            except OSError:
                pass
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(canonical)
                stream.flush()
                os.fsync(stream.fileno())
            if path.is_symlink() or (path.exists() and not path.is_file()):
                raise CheckpointPersistenceError(
                    f"unsafe local observation artifact target: {path}"
                )
            try:
                os.link(temporary, path)
            except FileExistsError:
                existing = path.read_bytes()
                if existing != canonical:
                    raise CheckpointConflictError(
                        "observation artifact ref was reused with different content"
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
                try:
                    temporary.unlink()
                except FileNotFoundError:
                    pass

    def _read(
        self, job_ref: str, *, suffix: Literal["context", "result"]
    ) -> _JsonObservationArtifactEnvelope | None:
        path = self._path(job_ref, suffix=suffix)
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise CheckpointPersistenceError(
                f"unsafe local observation artifact: {path}"
            )
        try:
            encoded = path.read_bytes()
        except FileNotFoundError:
            return None
        if len(encoded) > _MAX_OBSERVATION_OUTPUT_BYTES:
            raise ValueError("persisted observation artifact exceeds 65536 bytes")
        try:
            raw = json.loads(encoded)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(
                "persisted observation artifact is not canonical JSON"
            ) from exc
        envelope = _JsonObservationArtifactEnvelope.model_validate(raw)
        if envelope.scope_fingerprint != self.scope_fingerprint:
            raise CheckpointScopeError(
                "persisted observation artifact scope partition mismatch"
            )
        if envelope.job_ref != job_ref:
            raise ValueError("persisted observation artifact job_ref mismatch")
        if self._canonical_bytes(envelope) != encoded:
            raise ValueError("persisted observation artifact is not canonical")
        return envelope

    def put_context(self, job_ref: str, context: ObservationContext) -> None:
        stored = type(context).model_validate(context.model_dump(mode="python"))
        project_ref, scope_digest, artifact_kind = self._scope_fields(stored)
        payload = _privacy_safe_artifact_payload(
            stored.model_dump(mode="json", by_alias=True)
        )
        envelope = _JsonObservationArtifactEnvelope(
            artifact_kind=artifact_kind,
            job_ref=job_ref,
            scope_fingerprint=self.scope_fingerprint,
            project_ref=project_ref,
            exact_scope_digest=scope_digest,
            artifact_digest=_digest(payload),
            payload=payload,
        )
        self._write_once(self._path(job_ref, suffix="context"), envelope)

    def get_context(self, job_ref: str) -> ObservationContext | None:
        envelope = self._read(job_ref, suffix="context")
        if envelope is None:
            return None
        if envelope.artifact_kind == "gtm_context":
            context: ObservationContext = GtmObservationContext.model_validate(
                envelope.payload
            )
        elif envelope.artifact_kind == "storefront_context":
            context = StorefrontPhaseObservationContext.model_validate(envelope.payload)
        elif envelope.artifact_kind == "profit_context":
            context = ProfitObservationContext.model_validate(envelope.payload)
        else:
            raise ValueError("result artifact was stored in the context namespace")
        project_ref, scope_digest, artifact_kind = self._scope_fields(context)
        if (
            project_ref != envelope.project_ref
            or scope_digest != envelope.exact_scope_digest
            or artifact_kind != envelope.artifact_kind
        ):
            raise ValueError("persisted context scope binding is inconsistent")
        return context

    def put_result(self, result: ObservationRunResult) -> None:
        stored = ObservationRunResult.model_validate(result.model_dump(mode="python"))
        payload = _privacy_safe_artifact_payload(
            stored.model_dump(mode="json", by_alias=True)
        )
        envelope = _JsonObservationArtifactEnvelope(
            artifact_kind="result",
            job_ref=stored.job_ref,
            scope_fingerprint=self.scope_fingerprint,
            project_ref=stored.read_receipt.scope.project_ref,
            exact_scope_digest=stored.read_receipt.exact_scope_digest,
            artifact_digest=_digest(payload),
            payload=payload,
        )
        self._write_once(self._path(stored.job_ref, suffix="result"), envelope)

    def get_result(self, job_ref: str) -> ObservationRunResult | None:
        envelope = self._read(job_ref, suffix="result")
        if envelope is None:
            return None
        if envelope.artifact_kind != "result":
            raise ValueError("context artifact was stored in the result namespace")
        result = ObservationRunResult.model_validate(envelope.payload)
        if (
            result.job_ref != job_ref
            or result.read_receipt.scope.project_ref != envelope.project_ref
            or result.read_receipt.exact_scope_digest != envelope.exact_scope_digest
        ):
            raise ValueError("persisted result scope binding is inconsistent")
        return result


class ObservationRuntime:
    """Schedule, claim, normalize, attest, and evaluate post-action reads."""

    def __init__(
        self,
        *,
        checkpoint_store: WorkflowCheckpointStore,
        artifact_repository: ObservationArtifactRepository,
        connector_executor: ConnectorExecutor,
        scope_keyring: ObservationScopeKeyRing,
        host_observation_reader: HostObservationReader | None = None,
        normalizers: Iterable[ObservationNormalizer] = (),
    ) -> None:
        self.store = checkpoint_store
        self.repository = artifact_repository
        artifact_scope = getattr(artifact_repository, "scope_fingerprint", None)
        checkpoint_scope = getattr(checkpoint_store, "scope_fingerprint", None)
        if artifact_scope is not None and artifact_scope != checkpoint_scope:
            raise CheckpointScopeError(
                "checkpoint and observation artifact stores must share one scope partition"
            )
        self.executor = connector_executor
        self.host_reader = host_observation_reader
        self.scope_keyring = scope_keyring
        builtins: list[ObservationNormalizer] = [
            ShopifyAnalyticsNormalizer(),
            GoogleAnalyticsNormalizer(),
            CheckoutRecoverySnapshotNormalizer(),
        ]
        self.normalizers = {item.tool: item for item in builtins}
        for normalizer in normalizers:
            if normalizer.tool in self.normalizers:
                raise ValueError(
                    f"observation normalizer already registered: {normalizer.tool}"
                )
            if not callable(getattr(normalizer, "supports_metric", None)):
                raise ValueError(
                    "custom observation normalizer must declare supports_metric"
                )
            self.normalizers[normalizer.tool] = normalizer

    def schedule_gtm(
        self,
        plan_value: OmnichannelProductLaunchPlan | Mapping[str, Any],
        *,
        action_receipts: Iterable[ProductLaunchReceipt | Mapping[str, Any]],
        scope: DynamicWorkflowScope | Mapping[str, Any],
        project_id: UUID,
        tenant_connector_id: UUID,
        connector_account_ref: str,
        provider: Literal["shopify", "google_analytics"] = "shopify",
        source_capability: Literal[
            "shopify.analytics_query", "google_analytics.fetch_metrics"
        ]
        | None = None,
        query_arguments: Mapping[str, Any],
        expected_tool_version: int,
        expected_route_digest: str,
        run_ref: str,
        iteration: int = 1,
        previous_evaluation: ProductLaunchIterationEvaluation | None = None,
        max_attempts: int = 3,
    ) -> WorkflowCheckpoint:
        """Schedule one exact analytics source for one launch evaluation job.

        The runtime does not merge Shopify and GA into synthetic attribution. A
        job seals one provider receipt and evaluates the plan's primary metric.
        """

        workflow_scope = self._scope(scope)
        if query_arguments:
            raise ValueError(
                "governed Shopify analytics uses a fixed server-owned query; "
                "caller query arguments are not accepted"
            )
        plan = verify_product_launch_plan(
            plan_value, scope=workflow_scope, scope_keyring=self.scope_keyring
        )
        expected_capability = {
            "shopify": "shopify.analytics_query",
            "google_analytics": "google_analytics.fetch_metrics",
        }[provider]
        if source_capability is not None and source_capability != expected_capability:
            raise ValueError("GTM observation tool does not match its provider")
        source_capability = expected_capability
        normalizer = self.normalizers[source_capability]
        if normalizer.provider != provider or not normalizer.supports_metric(
            plan.evaluation_loop.primary_metric
        ):
            raise ValueError(
                f"{provider} cannot observe GTM primary metric "
                f"{plan.evaluation_loop.primary_metric!r}"
            )
        if provider == "shopify":
            bound = any(
                value.provider == "shopify"
                and value.connector_account_ref == connector_account_ref
                for value in plan.connector_account_bindings
            )
        else:
            bound = any(
                finding.provider == "google_analytics"
                and finding.scope_verified
                and finding.connector_account_ref == connector_account_ref
                and finding.source_capability == source_capability
                for finding in plan.analytics_findings
            )
        if not bound:
            raise ValueError(
                f"{provider} observation account is not scope-bound to the plan"
            )
        receipts = self._verified_gtm_action_receipts(
            plan,
            action_receipts,
            scope=workflow_scope,
            run_ref=run_ref,
            iteration=iteration,
        )
        latest = max(_timestamp(item.effective_at) for item in receipts)
        spec_seed = self._spec_values(
            kind="gtm",
            scope=workflow_scope,
            exact_scope_digest=plan.analytics_scope.exact_scope_digest,
            receipt_key_id=plan.analytics_scope.receipt_key_id,
            project_id=project_id,
            plan_digest=plan.plan_digest,
            run_ref=run_ref,
            iteration=iteration,
            provider=provider,
            source_capability=source_capability,
            connector_account_ref=connector_account_ref,
            tenant_connector_id=tenant_connector_id,
            expected_tool_version=expected_tool_version,
            expected_route_digest=expected_route_digest,
            query_arguments=query_arguments,
            latest=latest,
            measurement_window_hours=plan.evaluation_loop.measurement_window_hours,
            minimum_sample_size=plan.evaluation_loop.minimum_sample_size,
            max_observation_age_hours=plan.evaluation_loop.max_observation_age_hours,
            target_metric=plan.evaluation_loop.primary_metric,
            target_unit="ratio",
            currency=None,
            max_attempts=max_attempts,
        )
        resolved_query_arguments = spec_seed.pop("resolved_query_arguments")
        context = GtmObservationContext(
            spec_digest=spec_seed["pre_context_job_digest"],
            scope=workflow_scope,
            query_arguments=resolved_query_arguments,
            plan=plan,
            action_receipts=receipts,
            previous_evaluation=previous_evaluation,
        )
        return self._schedule(spec_seed, context)

    def schedule_storefront_phase(
        self,
        plan_value: OmnichannelProductLaunchPlan | Mapping[str, Any],
        *,
        storefront_receipts: Iterable[ProductLaunchReceipt | Mapping[str, Any]],
        scope: DynamicWorkflowScope | Mapping[str, Any],
        project_id: UUID,
        tenant_connector_id: UUID,
        connector_account_ref: str,
        provider: Literal["shopify", "google_analytics"] = "shopify",
        source_capability: Literal[
            "shopify.analytics_query", "google_analytics.fetch_metrics"
        ]
        | None = None,
        query_arguments: Mapping[str, Any],
        expected_tool_version: int,
        expected_route_digest: str,
        run_ref: str,
        iteration: int = 1,
        previous_evaluation: StorefrontPhaseEvaluation | None = None,
        max_attempts: int = 3,
    ) -> WorkflowCheckpoint:
        """Schedule a sealed storefront-phase evaluation from the four Shopify receipts."""

        workflow_scope = self._scope(scope)
        if query_arguments:
            raise ValueError(
                "governed storefront analytics uses a fixed server-owned query; "
                "caller query arguments are not accepted"
            )
        plan = verify_product_launch_plan(
            plan_value, scope=workflow_scope, scope_keyring=self.scope_keyring
        )
        expected_capability = {
            "shopify": "shopify.analytics_query",
            "google_analytics": "google_analytics.fetch_metrics",
        }[provider]
        if source_capability is not None and source_capability != expected_capability:
            raise ValueError("storefront observation tool does not match its provider")
        source_capability = expected_capability
        normalizer = self.normalizers[source_capability]
        if normalizer.provider != provider or not normalizer.supports_metric(
            plan.evaluation_loop.primary_metric
        ):
            raise ValueError(
                f"{provider} cannot observe storefront primary metric "
                f"{plan.evaluation_loop.primary_metric!r}"
            )
        if provider == "shopify":
            bound = any(
                value.provider == "shopify"
                and value.connector_account_ref == connector_account_ref
                for value in plan.connector_account_bindings
            )
        else:
            bound = any(
                finding.provider == "google_analytics"
                and finding.scope_verified
                and finding.connector_account_ref == connector_account_ref
                and finding.source_capability == source_capability
                for finding in plan.analytics_findings
            )
        if not bound:
            raise ValueError(
                f"{provider} storefront observation account is not scope-bound"
            )
        if not 1 <= iteration <= plan.evaluation_loop.max_iterations:
            raise ValueError("storefront iteration exceeds the plan limit")
        previous = None
        if previous_evaluation is not None:
            previous = self.verify_storefront_phase_evaluation(previous_evaluation)
        if iteration == 1 and previous is not None:
            raise ValueError("first storefront iteration cannot have a predecessor")
        if iteration > 1 and (
            previous is None
            or previous.plan_digest != plan.plan_digest
            or previous.exact_scope_digest != plan.analytics_scope.exact_scope_digest
            or previous.run_ref != run_ref
            or previous.decision != "revise_plan"
            or previous.next_iteration != iteration
        ):
            raise ValueError("storefront iteration does not continue a sealed revision")
        receipts = self._verified_storefront_receipts(
            plan,
            storefront_receipts,
            scope=workflow_scope,
            run_ref=run_ref,
            iteration=iteration,
        )
        latest = max(_timestamp(item.effective_at) for item in receipts)
        spec_seed = self._spec_values(
            kind="storefront_phase",
            scope=workflow_scope,
            exact_scope_digest=plan.analytics_scope.exact_scope_digest,
            receipt_key_id=plan.analytics_scope.receipt_key_id,
            project_id=project_id,
            plan_digest=plan.plan_digest,
            run_ref=run_ref,
            iteration=iteration,
            provider=provider,
            source_capability=source_capability,
            connector_account_ref=connector_account_ref,
            tenant_connector_id=tenant_connector_id,
            expected_tool_version=expected_tool_version,
            expected_route_digest=expected_route_digest,
            query_arguments={},
            latest=latest,
            measurement_window_hours=plan.evaluation_loop.measurement_window_hours,
            minimum_sample_size=plan.evaluation_loop.minimum_sample_size,
            max_observation_age_hours=plan.evaluation_loop.max_observation_age_hours,
            target_metric=plan.evaluation_loop.primary_metric,
            target_unit="ratio",
            currency=None,
            max_attempts=max_attempts,
        )
        resolved_query_arguments = spec_seed.pop("resolved_query_arguments")
        context = StorefrontPhaseObservationContext(
            spec_digest=spec_seed["pre_context_job_digest"],
            scope=workflow_scope,
            query_arguments=resolved_query_arguments,
            plan=plan,
            storefront_receipts=receipts,
            previous_evaluation=previous,
        )
        return self._schedule(spec_seed, context)

    def schedule_profit(
        self,
        plan_value: ProfitWorkflowPlan | Mapping[str, Any],
        *,
        action_receipts: Iterable[ProfitActionExecutionReceipt | Mapping[str, Any]],
        scope: DynamicWorkflowScope | Mapping[str, Any],
        project_id: UUID,
        provider: Literal["shopify", "google_analytics", "host"],
        tenant_connector_id: UUID | None = None,
        connector_account_ref: str | None = None,
        source_capability: str,
        query_arguments: Mapping[str, Any],
        expected_tool_version: int,
        expected_route_digest: str | None = None,
        run_ref: str,
        iteration: int = 1,
        previous_evaluation: ProfitWorkflowEvaluation | None = None,
        max_attempts: int = 3,
    ) -> WorkflowCheckpoint:
        workflow_scope = self._scope(scope)
        plan = verify_profit_workflow_plan(
            plan_value, scope=workflow_scope, scope_keyring=self.scope_keyring
        )
        normalizer = self.normalizers.get(source_capability)
        if normalizer is None or normalizer.provider != provider:
            raise ValueError(
                "source capability requires a registered provider-matched normalizer"
            )
        if not normalizer.supports_metric(plan.evaluation_loop.target_metric):
            raise ValueError(
                f"{source_capability} cannot normalize profit target metric "
                f"{plan.evaluation_loop.target_metric!r}"
            )
        definition = get_profit_workflow_definition(plan.workflow_id)
        if source_capability not in definition.evidence_capabilities:
            raise ValueError("observation capability is not allowed by this workflow")
        target_accounts = {
            item.target_account_ref for item in plan.actions if item.target_account_ref
        }
        declared_accounts = {
            item.connector_account_ref for item in plan.account_bindings
        }
        subject_account_refs: tuple[str, ...] = ()
        if provider == "host":
            if (
                connector_account_ref is not None
                or tenant_connector_id is not None
                or expected_route_digest is not None
            ):
                raise ValueError("host observations do not use connector custody")
            if not target_accounts or not target_accounts.issubset(declared_accounts):
                raise ValueError(
                    "host observation subjects must be exact plan target accounts"
                )
            subject_account_refs = tuple(sorted(target_accounts))
        else:
            if (
                connector_account_ref is None
                or tenant_connector_id is None
                or expected_route_digest is None
            ):
                raise ValueError(
                    "connector observations require account, tenant connector, and "
                    "route digest custody"
                )
            if not any(
                item.provider == provider
                and item.connector_account_ref == connector_account_ref
                for item in plan.account_bindings
            ):
                raise ValueError("observation account is not bound to the profit plan")
        receipts = tuple(
            verify_profit_action_execution_receipt(
                item, plan=plan, scope=workflow_scope, scope_keyring=self.scope_keyring
            )
            for item in action_receipts
        )
        if {item.operation_ref for item in receipts} != {
            item.operation_ref for item in plan.actions
        } or len(receipts) != len(plan.actions):
            raise ValueError("observation requires every planned action receipt")
        if any(
            item.run_ref != run_ref or item.iteration != iteration for item in receipts
        ):
            raise ValueError("action receipts do not match observation run/iteration")
        latest = max(_timestamp(item.completed_at) for item in receipts)
        resolved_input_arguments = dict(query_arguments)
        if (
            source_capability
            in {
                "shopify.analytics_query",
                "google_analytics.fetch_metrics",
            }
            and resolved_input_arguments
        ):
            raise ValueError(
                "governed analytics uses a fixed server-owned query; "
                "caller query arguments are not accepted"
            )
        if source_capability == "host.checkout_recovery_snapshot":
            resolved_input_arguments = _checkout_recovery_query_arguments(
                resolved_input_arguments,
                launch_ref=plan.launch_ref,
            )
        spec_seed = self._spec_values(
            kind="profit",
            scope=workflow_scope,
            exact_scope_digest=plan.exact_scope_digest,
            receipt_key_id=plan.receipt_key_id,
            project_id=project_id,
            plan_digest=plan.plan_digest,
            run_ref=run_ref,
            iteration=iteration,
            provider=provider,
            source_capability=source_capability,
            connector_account_ref=connector_account_ref,
            subject_account_refs=subject_account_refs,
            tenant_connector_id=tenant_connector_id,
            expected_tool_version=expected_tool_version,
            expected_route_digest=expected_route_digest,
            query_arguments=resolved_input_arguments,
            latest=latest,
            measurement_window_hours=plan.evaluation_loop.measurement_window_hours,
            minimum_sample_size=plan.evaluation_loop.minimum_sample_size,
            max_observation_age_hours=plan.evaluation_loop.max_observation_age_hours,
            target_metric=plan.evaluation_loop.target_metric,
            target_unit=plan.evaluation_loop.target_unit,
            currency=(
                plan.baseline.currency
                if plan.evaluation_loop.target_unit == "money"
                else None
            ),
            max_attempts=max_attempts,
        )
        resolved_query_arguments = spec_seed.pop("resolved_query_arguments")
        context = ProfitObservationContext(
            spec_digest=spec_seed["pre_context_job_digest"],
            scope=workflow_scope,
            query_arguments=resolved_query_arguments,
            plan=plan,
            action_receipts=receipts,
            previous_evaluation=previous_evaluation,
        )
        return self._schedule(spec_seed, context)

    def run_next(
        self,
        *,
        scope: DynamicWorkflowScope | Mapping[str, Any],
        worker_ref: str,
        now: datetime,
        lease_seconds: int = 60,
    ) -> ObservationRunResult | None:
        observed_now = _utc(now)
        workflow_scope = self._scope(scope)
        checkpoint = self.store.claim_next(
            _claim_partition_ref(workflow_scope),
            worker_ref=worker_ref,
            now=observed_now,
            lease_seconds=lease_seconds,
        )
        if checkpoint is None:
            return None
        if checkpoint.workflow_key != "post_action_observation":
            return self._fail(checkpoint, "unexpected_checkpoint_kind")
        try:
            spec = ObservationJobSpec.model_validate(
                checkpoint.workflow_inputs.get("observation_job")
            )
        except (TypeError, ValueError):
            return self._fail(checkpoint, "observation_checkpoint_invalid")
        if spec.project_ref != workflow_scope.project_ref:
            return self._fail(checkpoint, "checkpoint_scope_mismatch")
        try:
            context = self.repository.get_context(spec.job_ref)
        except (OSError, TypeError, ValueError, CheckpointPersistenceError):
            return self._fail(checkpoint, "observation_context_invalid")
        if context is None or context.context_digest != spec.context_digest:
            return self._fail(checkpoint, "observation_context_missing")
        if context.scope != workflow_scope:
            return self._fail(checkpoint, "observation_scope_mismatch")
        actual_scope_digest = self.scope_keyring.exact_scope_digest(
            key_id=spec.receipt_key_id,
            scope=workflow_scope,
        )
        if not hmac.compare_digest(actual_scope_digest, spec.exact_scope_digest):
            return self._fail(checkpoint, "observation_scope_digest_mismatch")
        try:
            prior_result = self.repository.get_result(spec.job_ref)
        except (OSError, TypeError, ValueError, CheckpointPersistenceError):
            return self._fail(checkpoint, "observation_result_invalid")
        if prior_result is not None:
            if prior_result.job_digest != spec.job_digest:
                return self._fail(checkpoint, "observation_result_mismatch")
            try:
                self.verify_read_receipt(prior_result.read_receipt)
                if spec.kind == "storefront_phase":
                    evaluation = prior_result.storefront_phase_evaluation
                    if (
                        evaluation is None
                        or self.verify_storefront_phase_evaluation(evaluation)
                        != evaluation
                        or evaluation.evidence_receipt_digest
                        != prior_result.read_receipt.receipt_digest
                    ):
                        raise ValueError("storefront result evidence is incomplete")
            except (TypeError, ValueError):
                return self._fail(checkpoint, "observation_result_untrusted")
            if prior_result.next_iteration_event is not None:
                self.store.record_event(prior_result.next_iteration_event)
            self._complete_checkpoint(checkpoint, prior_result)
            return prior_result
        normalizer = self.normalizers.get(spec.source_capability)
        if normalizer is None or normalizer.provider != spec.provider:
            return self._fail(checkpoint, "observation_normalizer_missing")
        if spec.provider == "host":
            if self.host_reader is None or not self.host_reader.supports(
                spec.source_capability
            ):
                return self._fail(checkpoint, "host_observation_reader_missing")
            host_request = HostObservationReadRequest(
                job_ref=spec.job_ref,
                job_digest=spec.job_digest,
                scope=workflow_scope,
                exact_scope_digest=spec.exact_scope_digest,
                receipt_key_id=spec.receipt_key_id,
                project_id=spec.project_id,
                source_capability=spec.source_capability,
                tool_version=spec.expected_tool_version,
                subject_account_refs=spec.subject_account_refs,
                query_arguments=context.query_arguments,
                query_digest=spec.query_digest,
                target_metric=spec.target_metric,
                target_unit=spec.target_unit,
                currency=spec.currency,
                window_start=spec.window_start,
                window_end=spec.window_end,
                idempotency_key=f"observation:{spec.job_digest}",
            )
            try:
                raw_host_result = self.host_reader.read(host_request)
            except Exception:
                return self._retry_or_fail(
                    checkpoint, spec, observed_now, "host_read_exception"
                )
            try:
                host_result = HostObservationReadResult.model_validate(
                    raw_host_result.model_dump(mode="python")
                    if isinstance(raw_host_result, HostObservationReadResult)
                    else raw_host_result
                )
            except (TypeError, ValueError):
                return self._fail(checkpoint, "host_read_result_invalid")
            if host_result.status != "completed":
                if host_result.retryable:
                    return self._retry_or_fail(
                        checkpoint, spec, observed_now, "host_read_retryable"
                    )
                return self._fail(checkpoint, "host_read_failed")
            try:
                read_receipt = self._normalize_host_and_seal(
                    spec,
                    workflow_scope,
                    host_request,
                    host_result,
                    normalizer,
                    observed_now,
                )
            except (TypeError, ValueError):
                return self._fail(checkpoint, "observation_evidence_rejected")
        else:
            if not self.executor.supports(spec.source_capability):
                return self._fail(checkpoint, "observation_tool_unsupported")
            request = ConnectorExecutionRequest(
                tool=spec.source_capability,
                arguments=context.query_arguments,
                scope=ExecutionScope(
                    tenant_ref=workflow_scope.tenant_id,
                    company_ref=workflow_scope.company_id,
                    project_ref=workflow_scope.project_ref,
                    project_id=spec.project_id,
                    actor_ref=workflow_scope.user_id,
                ),
                connector_account_ref=spec.connector_account_ref,
                effect=ConnectorEffect.READ,
                idempotency_key=f"observation:{spec.job_digest}",
                metadata={
                    "observation_job_ref": spec.job_ref,
                    "observation_job_digest": spec.job_digest,
                    "connector_account_ref": spec.connector_account_ref,
                    "tenant_connector_id": str(spec.tenant_connector_id),
                    "query_digest": spec.query_digest,
                    "window_start": spec.window_start,
                    "window_end": spec.window_end,
                    "expected_tool_version": spec.expected_tool_version,
                    "expected_route_digest": spec.expected_route_digest,
                },
            )
            try:
                connector_result = self.executor.execute(request)
            except Exception:
                return self._retry_or_fail(
                    checkpoint, spec, observed_now, "read_exception"
                )
            if connector_result.status != ConnectorExecutionStatus.COMPLETED:
                if connector_result.retryable:
                    return self._retry_or_fail(
                        checkpoint, spec, observed_now, "connector_read_retryable"
                    )
                return self._fail(checkpoint, "connector_read_failed")
            try:
                read_receipt = self._normalize_and_seal(
                    spec,
                    workflow_scope,
                    request,
                    connector_result,
                    normalizer,
                    observed_now,
                )
            except (TypeError, ValueError):
                return self._fail(checkpoint, "observation_evidence_rejected")
        try:
            result = self._evaluate(spec, workflow_scope, context, read_receipt)
        except (TypeError, ValueError):
            return self._fail(checkpoint, "observation_evidence_rejected")
        try:
            self.repository.put_result(result)
        except CheckpointConflictError:
            return self._fail(checkpoint, "observation_result_conflict")
        except (OSError, ValueError, CheckpointPersistenceError):
            return self._retry_or_fail(
                checkpoint, spec, observed_now, "observation_result_persistence"
            )
        if result.next_iteration_event is not None:
            self.store.record_event(result.next_iteration_event)
        self._complete_checkpoint(checkpoint, result)
        return result

    def verify_read_receipt(
        self, receipt_value: ObservationReadReceipt | Mapping[str, Any]
    ) -> ObservationReadReceipt:
        receipt = ObservationReadReceipt.model_validate(
            receipt_value.model_dump(mode="python", by_alias=True)
            if isinstance(receipt_value, ObservationReadReceipt)
            else receipt_value
        )
        actual_scope_digest = self.scope_keyring.exact_scope_digest(
            key_id=receipt.receipt_key_id, scope=receipt.scope
        )
        if not hmac.compare_digest(actual_scope_digest, receipt.exact_scope_digest):
            raise ValueError("observation receipt scope digest is invalid")
        expected = self.scope_keyring.sign(
            receipt.receipt_key_id,
            _OBSERVATION_RECEIPT_HMAC_DOMAIN,
            receipt.hmac_payload(),
        ).hex()
        if not hmac.compare_digest(expected, receipt.receipt_hmac):
            raise ValueError("observation receipt HMAC is invalid")
        return receipt

    def verify_storefront_phase_evaluation(
        self, value: StorefrontPhaseEvaluation | Mapping[str, Any]
    ) -> StorefrontPhaseEvaluation:
        evaluation = StorefrontPhaseEvaluation.model_validate(
            value.model_dump(mode="python", by_alias=True)
            if isinstance(value, StorefrontPhaseEvaluation)
            else value
        )
        expected = self.scope_keyring.sign(
            evaluation.receipt_key_id,
            _STOREFRONT_PHASE_EVALUATION_HMAC_DOMAIN,
            evaluation.hmac_payload(),
        ).hex()
        if not hmac.compare_digest(expected, evaluation.evaluation_hmac):
            raise ValueError("storefront phase evaluation HMAC is invalid")
        return evaluation

    @staticmethod
    def _scope(value: DynamicWorkflowScope | Mapping[str, Any]) -> DynamicWorkflowScope:
        return (
            value
            if isinstance(value, DynamicWorkflowScope)
            else DynamicWorkflowScope.model_validate(value)
        )

    def _spec_values(self, **values: Any) -> dict[str, Any]:
        query_arguments = _bounded_query_arguments(values.pop("query_arguments"))
        target_metric = str(values["target_metric"])
        if (
            "target_metric" in query_arguments
            and query_arguments["target_metric"] != target_metric
        ):
            raise ValueError("query target_metric does not match observation contract")
        query_arguments["target_metric"] = target_metric
        if values["provider"] == "shopify" and target_metric == "average_order_value":
            currency = values.get("currency")
            if currency is None:
                raise ValueError("Shopify average order value requires currency")
            if (
                "currency" in query_arguments
                and query_arguments["currency"] != currency
            ):
                raise ValueError("query currency does not match observation contract")
            query_arguments["currency"] = currency
        workflow_scope: DynamicWorkflowScope = values.pop("scope")
        latest: datetime = values.pop("latest")
        hours = int(values.pop("measurement_window_hours"))
        if values["provider"] in {"shopify", "google_analytics"} and (
            hours < 24 or hours % 24 != 0 or hours > 366 * 24
        ):
            raise ValueError("connector analytics windows must be 1-366 whole UTC days")
        start = datetime.combine(
            (latest + timedelta(days=1)).date(),
            datetime.min.time(),
            tzinfo=timezone.utc,
        )
        end = start + timedelta(hours=hours)
        due = end + timedelta(seconds=1)
        query_arguments.update(
            {
                "window_start": _iso(start),
                "window_end": _iso(end),
            }
        )
        query_arguments = _bounded_query_arguments(query_arguments)
        query_digest = _digest(query_arguments)
        seed = {
            **values,
            "project_ref": workflow_scope.project_ref,
            "query_digest": query_digest,
            "latest_action_completed_at": _iso(latest),
            "window_start": _iso(start),
            "window_end": _iso(end),
            "due_at": _iso(due),
        }
        pre_context_job_digest = _digest(seed)
        seed["pre_context_job_digest"] = pre_context_job_digest
        seed["resolved_query_arguments"] = query_arguments
        return seed

    def _schedule(
        self,
        seed: dict[str, Any],
        context: ObservationContext,
    ) -> WorkflowCheckpoint:
        expected_seed = seed.pop("pre_context_job_digest")
        if context.spec_digest != expected_seed:
            raise ValueError("observation context does not match its schedule seed")
        seed["context_digest"] = context.context_digest
        job_ref = f"obs-{_digest(seed)[:48]}"
        spec = ObservationJobSpec(job_ref=job_ref, **seed)
        self.repository.put_context(spec.job_ref, context)
        existing = self.store.get(spec.job_ref)
        if existing is not None:
            existing_spec = ObservationJobSpec.model_validate(
                existing.workflow_inputs.get("observation_job")
            )
            if existing_spec.job_digest != spec.job_digest:
                raise CheckpointConflictError("observation job_ref was reused")
            return existing
        created = datetime.now(timezone.utc)
        checkpoint = WorkflowCheckpoint(
            run_ref=spec.job_ref,
            project_ref=_claim_partition_ref(context.scope),
            scope_fingerprint=getattr(self.store, "scope_fingerprint", None),
            hosted_project_id=spec.project_id,
            project_version=OBSERVATION_RUNTIME_VERSION,
            workflow_key="post_action_observation",
            workflow_version=OBSERVATION_RUNTIME_VERSION,
            workflow_identity_sha256=spec.job_digest,
            primitive_versions={"observation.read": OBSERVATION_RUNTIME_VERSION},
            status=CheckpointStatus.SCHEDULED,
            workflow_inputs={
                "observation_job": spec.model_dump(mode="json", by_alias=True),
                "attempt": 1,
            },
            preview_only=False,
            current_step="observe",
            resume_at=_timestamp(spec.due_at),
            created_at=created,
            updated_at=created,
        )
        try:
            return self.store.save(checkpoint, expected_revision=None)
        except CheckpointConflictError:
            existing = self.store.get(spec.job_ref)
            if existing is None:
                raise
            return existing

    def _verified_storefront_receipts(
        self,
        plan: OmnichannelProductLaunchPlan,
        receipts: Iterable[ProductLaunchReceipt | Mapping[str, Any]],
        *,
        scope: DynamicWorkflowScope,
        run_ref: str,
        iteration: int,
    ) -> tuple[ProductLaunchReceipt, ...]:
        capabilities = {
            "ecommerce.create_product",
            "ecommerce.update_product",
            "shopify.publish_product",
            "gtm.verify_landing_readiness",
        }
        operations = {
            item.operation_id: item
            for item in plan.operations
            if item.capability in capabilities
        }
        if (
            len(operations) != 4
            or {item.capability for item in operations.values()} != capabilities
        ):
            raise ValueError("plan has no canonical four-stage storefront graph")
        requirements = {
            item.criterion_id: item
            for item in plan.required_receipts
            if item.operation_id in operations
        }
        if len(requirements) != 4:
            raise ValueError("plan has no canonical storefront receipt contract")
        parsed = tuple(
            ProductLaunchReceipt.model_validate(
                value.model_dump(mode="python", by_alias=True)
                if isinstance(value, ProductLaunchReceipt)
                else value
            )
            for value in receipts
        )
        if (
            len(parsed) != 4
            or {item.criterion_id for item in parsed} != set(requirements)
            or len({item.receipt_ref for item in parsed}) != 4
        ):
            raise ValueError(
                "storefront phase requires the exact four canonical Shopify receipts"
            )
        key_id = plan.analytics_scope.receipt_key_id
        scope_digest = plan.analytics_scope.exact_scope_digest
        if key_id is None or scope_digest is None:
            raise ValueError("storefront plan has no exact scope binding")
        if (
            self.scope_keyring.exact_scope_digest(key_id=key_id, scope=scope)
            != scope_digest
        ):
            raise ValueError("storefront receipt scope mismatch")
        for receipt in parsed:
            requirement = requirements[receipt.criterion_id]
            operation = operations[requirement.operation_id]
            if (
                receipt.plan_digest != plan.plan_digest
                or receipt.exact_scope_digest != scope_digest
                or receipt.receipt_key_id != key_id
                or receipt.run_ref != run_ref
                or receipt.iteration != iteration
                or receipt.receipt_kind != requirement.receipt_kind
                or receipt.evidence_kind != requirement.evidence_kind
                or receipt.operation_id != operation.operation_id
                or receipt.operation_digest != operation.operation_digest
                or receipt.approval_unit != requirement.approval_unit
                or (receipt.approval_receipt_digest is not None)
                != (requirement.approval_unit is not None)
            ):
                raise ValueError("storefront receipt does not match the signed plan")
            expected = self.scope_keyring.sign(
                key_id,
                "lightbulb.product_launch_receipt.v1",
                receipt.hmac_payload(),
            ).hex()
            if not hmac.compare_digest(expected, receipt.receipt_hmac):
                raise ValueError("storefront receipt HMAC is invalid")
        return tuple(
            sorted(parsed, key=lambda item: operations[item.operation_id].ordinal)
        )

    def _verified_gtm_action_receipts(
        self,
        plan: OmnichannelProductLaunchPlan,
        receipts: Iterable[ProductLaunchReceipt | Mapping[str, Any]],
        *,
        scope: DynamicWorkflowScope,
        run_ref: str,
        iteration: int,
    ) -> tuple[ProductLaunchReceipt, ...]:
        parsed = tuple(
            ProductLaunchReceipt.model_validate(
                value.model_dump(mode="python", by_alias=True)
                if isinstance(value, ProductLaunchReceipt)
                else value
            )
            for value in receipts
        )
        requirements = {
            item.criterion_id: item
            for item in plan.required_receipts
            if item.receipt_kind != "gtm_performance_snapshot"
        }
        if {item.criterion_id for item in parsed} != set(requirements):
            raise ValueError("schedule requires every non-performance launch receipt")
        if len(parsed) != len(requirements) or len(
            {item.receipt_ref for item in parsed}
        ) != len(parsed):
            raise ValueError("launch action receipts must be exact and unique")
        key_id = plan.analytics_scope.receipt_key_id
        scope_digest = plan.analytics_scope.exact_scope_digest
        if key_id is None or scope_digest is None:
            raise ValueError("launch plan has no exact scope binding")
        if (
            self.scope_keyring.exact_scope_digest(key_id=key_id, scope=scope)
            != scope_digest
        ):
            raise ValueError("launch receipt scope mismatch")
        for receipt in parsed:
            requirement = requirements[receipt.criterion_id]
            if (
                receipt.plan_digest != plan.plan_digest
                or receipt.exact_scope_digest != scope_digest
                or receipt.receipt_key_id != key_id
                or receipt.run_ref != run_ref
                or receipt.iteration != iteration
                or receipt.receipt_kind != requirement.receipt_kind
                or receipt.evidence_kind != requirement.evidence_kind
                or receipt.operation_id != requirement.operation_id
                or receipt.operation_digest != requirement.operation_digest
                or receipt.approval_unit != requirement.approval_unit
                or (receipt.approval_receipt_digest is not None)
                != (requirement.approval_unit is not None)
            ):
                raise ValueError("launch action receipt does not match the plan")
            expected = self.scope_keyring.sign(
                key_id,
                "lightbulb.product_launch_receipt.v1",
                receipt.hmac_payload(),
            ).hex()
            if not hmac.compare_digest(expected, receipt.receipt_hmac):
                raise ValueError("launch action receipt HMAC is invalid")
        return parsed

    def _normalize_host_and_seal(
        self,
        spec: ObservationJobSpec,
        scope: DynamicWorkflowScope,
        request: HostObservationReadRequest,
        result: HostObservationReadResult,
        normalizer: ObservationNormalizer,
        observed_now: datetime,
    ) -> ObservationReadReceipt:
        if result.status != "completed" or result.output is None:
            raise ValueError("host read did not complete with bounded output")
        provenance = result.provenance
        if provenance is None:
            raise ValueError("completed host observation has no provenance")
        if (
            provenance.source_capability != spec.source_capability
            or provenance.tool_version != spec.expected_tool_version
            or provenance.project_id != spec.project_id
            or provenance.exact_scope_digest != spec.exact_scope_digest
            or provenance.subject_account_refs != spec.subject_account_refs
            or provenance.query_digest != spec.query_digest
            or provenance.request_digest != request.request_digest
            or provenance.output_digest != _digest(result.output)
            or provenance.receipt_key_id != spec.receipt_key_id
        ):
            raise ValueError("host provenance does not match observation custody")
        expected_provenance_hmac = self.scope_keyring.sign(
            provenance.receipt_key_id,
            _HOST_OBSERVATION_PROVENANCE_HMAC_DOMAIN,
            provenance.hmac_payload(),
        ).hex()
        if not hmac.compare_digest(
            expected_provenance_hmac, provenance.provenance_hmac
        ):
            raise ValueError("host observation provenance HMAC is invalid")
        completed_at = _timestamp(provenance.completed_at)
        if completed_at < _timestamp(spec.window_end):
            raise ValueError("host observation completed before the window closed")
        if completed_at > observed_now + timedelta(minutes=5):
            raise ValueError("host observation completion is future-dated")
        if completed_at - _timestamp(spec.window_end) > timedelta(
            hours=spec.max_observation_age_hours
        ):
            raise ValueError("host observation is stale")
        normalized = normalizer.normalize(result.output, spec=spec)
        if (
            normalized.metric != spec.target_metric
            or normalized.unit != spec.target_unit
            or normalized.sample_size < spec.minimum_sample_size
            or normalized.currency != spec.currency
        ):
            raise ValueError("normalized host observation does not match the job")
        actual_scope_digest = self.scope_keyring.exact_scope_digest(
            key_id=spec.receipt_key_id,
            scope=scope,
        )
        if not hmac.compare_digest(actual_scope_digest, spec.exact_scope_digest):
            raise ValueError("host observation scope digest is invalid")
        draft = ObservationReadReceipt(
            receipt_ref=f"obsread:{spec.job_digest[:48]}",
            job_ref=spec.job_ref,
            job_digest=spec.job_digest,
            scope=scope,
            exact_scope_digest=spec.exact_scope_digest,
            project_id=spec.project_id,
            provider="host",
            source_capability=spec.source_capability,
            subject_account_refs=spec.subject_account_refs,
            tool_version=provenance.tool_version,
            query_digest=spec.query_digest,
            request_digest=provenance.request_digest,
            execution_receipt_digest=provenance.provenance_digest,
            journal_ref=provenance.journal_ref,
            raw_output_digest=provenance.output_digest,
            window_start=spec.window_start,
            window_end=spec.window_end,
            observed_at=provenance.completed_at,
            normalized=normalized,
            receipt_key_id=spec.receipt_key_id,
            receipt_hmac="0" * 64,
        )
        signature = self.scope_keyring.sign(
            spec.receipt_key_id,
            _OBSERVATION_RECEIPT_HMAC_DOMAIN,
            draft.hmac_payload(),
        ).hex()
        payload = draft.model_dump(mode="python", by_alias=True)
        payload["receipt_hmac"] = signature
        payload["receipt_digest"] = "0" * 64
        return ObservationReadReceipt.model_validate(payload)

    def _normalize_and_seal(
        self,
        spec: ObservationJobSpec,
        scope: DynamicWorkflowScope,
        request: ConnectorExecutionRequest,
        result: ConnectorExecutionResult,
        normalizer: ObservationNormalizer,
        observed_now: datetime,
    ) -> ObservationReadReceipt:
        provenance = result.provenance
        if provenance is None:
            raise ValueError("completed observation read has no server provenance")
        if (
            provenance.tool != spec.source_capability
            or provenance.tool_version != spec.expected_tool_version
            or provenance.server_effect != ConnectorEffect.READ
            or provenance.project_id != spec.project_id
            or provenance.connector_account_ref != spec.connector_account_ref
            or provenance.tenant_connector_id != spec.tenant_connector_id
            or provenance.route_digest != spec.expected_route_digest
            or provenance.request_digest != request.custody_fingerprint()
            or provenance.approval_ref is not None
            or provenance.approval_receipt_digest is not None
        ):
            raise ValueError("connector provenance does not match observation custody")
        completed_at = _timestamp(provenance.completed_at)
        if completed_at < _timestamp(spec.window_end):
            raise ValueError("connector observation completed before the window closed")
        if completed_at > observed_now + timedelta(minutes=5):
            raise ValueError(
                "connector observation completion is implausibly future-dated"
            )
        if completed_at - _timestamp(spec.window_end) > timedelta(
            hours=spec.max_observation_age_hours
        ):
            raise ValueError("connector observation is stale")
        normalized = normalizer.normalize(result.output, spec=spec)
        if (
            normalized.metric != spec.target_metric
            or normalized.unit != spec.target_unit
            or normalized.sample_size < spec.minimum_sample_size
            or normalized.currency != spec.currency
        ):
            raise ValueError("normalized observation does not match the job contract")
        key_id = spec.receipt_key_id
        actual_scope_digest = self.scope_keyring.exact_scope_digest(
            key_id=key_id, scope=scope
        )
        if not hmac.compare_digest(actual_scope_digest, spec.exact_scope_digest):
            raise ValueError("job scope digest does not match current host scope")
        draft = ObservationReadReceipt(
            receipt_ref=f"obsread:{spec.job_digest[:48]}",
            job_ref=spec.job_ref,
            job_digest=spec.job_digest,
            scope=scope,
            exact_scope_digest=spec.exact_scope_digest,
            project_id=spec.project_id,
            provider=spec.provider,
            source_capability=spec.source_capability,
            connector_account_ref=spec.connector_account_ref,
            subject_account_refs=spec.subject_account_refs,
            tenant_connector_id=spec.tenant_connector_id,
            tool_version=provenance.tool_version,
            query_digest=spec.query_digest,
            request_digest=provenance.request_digest,
            execution_receipt_digest=provenance.receipt_digest,
            journal_ref=provenance.journal_ref,
            raw_output_digest=_digest(result.output),
            window_start=spec.window_start,
            window_end=spec.window_end,
            observed_at=provenance.completed_at,
            normalized=normalized,
            receipt_key_id=key_id,
            receipt_hmac="0" * 64,
        )
        signature = self.scope_keyring.sign(
            key_id, _OBSERVATION_RECEIPT_HMAC_DOMAIN, draft.hmac_payload()
        ).hex()
        payload = draft.model_dump(mode="python", by_alias=True)
        payload["receipt_hmac"] = signature
        payload["receipt_digest"] = "0" * 64
        return ObservationReadReceipt.model_validate(payload)

    def _evaluate(
        self,
        spec: ObservationJobSpec,
        scope: DynamicWorkflowScope,
        context: ObservationContext,
        read_receipt: ObservationReadReceipt,
    ) -> ObservationRunResult:
        self.verify_read_receipt(read_receipt)
        evaluated_at = _timestamp(read_receipt.observed_at)
        if spec.kind == "storefront_phase":
            if not isinstance(context, StorefrontPhaseObservationContext):
                raise ValueError("storefront job loaded the wrong context kind")
            plan = context.plan
            observed_value = read_receipt.normalized.value
            target_value = plan.optimization_policy.target_value
            if observed_value >= target_value:
                decision = "target_met"
                next_iteration = None
            elif spec.iteration < plan.evaluation_loop.max_iterations:
                decision = "revise_plan"
                next_iteration = spec.iteration + 1
            else:
                decision = "iteration_limit_reached"
                next_iteration = None
            draft = StorefrontPhaseEvaluation(
                evaluation_ref=f"storefront-eval:{spec.job_digest[:40]}",
                plan_digest=plan.plan_digest,
                exact_scope_digest=spec.exact_scope_digest,
                receipt_key_id=spec.receipt_key_id,
                run_ref=spec.run_ref,
                iteration=spec.iteration,
                max_iterations=plan.evaluation_loop.max_iterations,
                provider=spec.provider,
                source_capability=spec.source_capability,
                connector_account_ref=spec.connector_account_ref,
                primary_metric=plan.evaluation_loop.primary_metric,
                observed_value=observed_value,
                target_value=target_value,
                sample_size=read_receipt.normalized.sample_size,
                window_start=spec.window_start,
                window_end=spec.window_end,
                evaluated_at=read_receipt.observed_at,
                evidence_receipt_digest=read_receipt.receipt_digest,
                storefront_receipt_digests=tuple(
                    item.receipt_digest for item in context.storefront_receipts
                ),
                previous_evaluation_digest=(
                    context.previous_evaluation.evaluation_digest
                    if context.previous_evaluation is not None
                    else None
                ),
                decision=decision,
                next_iteration=next_iteration,
                evaluation_hmac="0" * 64,
            )
            signature = self.scope_keyring.sign(
                spec.receipt_key_id,
                _STOREFRONT_PHASE_EVALUATION_HMAC_DOMAIN,
                draft.hmac_payload(),
            ).hex()
            payload = draft.model_dump(mode="python", by_alias=True)
            payload["evaluation_hmac"] = signature
            payload["evaluation_digest"] = "0" * 64
            evaluation = StorefrontPhaseEvaluation.model_validate(payload)
            event = self._revision_event(spec, evaluation)
            return ObservationRunResult(
                job_ref=spec.job_ref,
                job_digest=spec.job_digest,
                read_receipt=read_receipt,
                storefront_phase_evaluation=evaluation,
                next_iteration_event=event,
            )
        if spec.kind == "gtm":
            if not isinstance(context, GtmObservationContext):
                raise ValueError("GTM job loaded the wrong context kind")
            criterion = next(
                item
                for item in context.plan.required_receipts
                if item.receipt_kind == "gtm_performance_snapshot"
            )
            performance = mint_product_launch_receipt(
                context.plan,
                scope=scope,
                scope_keyring=self.scope_keyring,
                criterion_id=criterion.criterion_id,
                receipt_ref=f"gtmperf:{spec.job_digest[:48]}",
                issuer_ref="observation_runtime",
                evidence_digest=read_receipt.receipt_digest,
                issued_at=read_receipt.observed_at,
                effective_at=spec.window_end,
                window_start=spec.window_start,
                window_end=spec.window_end,
                run_ref=spec.run_ref,
                iteration=spec.iteration,
                sample_size=read_receipt.normalized.sample_size,
                primary_metric=context.plan.evaluation_loop.primary_metric,
                metric_value=read_receipt.normalized.value,
            )
            evaluation = evaluate_product_launch_iteration(
                context.plan,
                [*context.action_receipts, performance],
                scope=scope,
                scope_keyring=self.scope_keyring,
                evaluated_at=evaluated_at,
                iteration=spec.iteration,
                run_ref=spec.run_ref,
                previous_evaluation=context.previous_evaluation,
            )
            event = self._revision_event(spec, evaluation)
            return ObservationRunResult(
                job_ref=spec.job_ref,
                job_digest=spec.job_digest,
                read_receipt=read_receipt,
                gtm_performance_receipt=performance,
                gtm_evaluation=evaluation,
                next_iteration_event=event,
            )
        if not isinstance(context, ProfitObservationContext):
            raise ValueError("profit job loaded the wrong context kind")
        normalized = read_receipt.normalized
        evidence = mint_profit_metric_evidence(
            ProfitMetricEvidence(
                evidence_ref=f"obsmetric-{spec.job_digest[:48]}",
                provider=spec.provider,
                connector_account_ref=spec.connector_account_ref,
                subject_account_refs=spec.subject_account_refs,
                source_capability=spec.source_capability,
                metric=spec.target_metric,
                unit=spec.target_unit,
                value=normalized.value,
                currency=normalized.currency,
                exposure_count=normalized.exposure_count,
                sample_size=normalized.sample_size,
                observed_at=read_receipt.observed_at,
                window_start=spec.window_start,
                window_end=spec.window_end,
                ledger=normalized.ledger,
                evidence_digest=read_receipt.receipt_digest,
            ),
            scope=scope,
            scope_keyring=self.scope_keyring,
            scope_key_id=context.plan.receipt_key_id,
        )
        outcome = mint_profit_outcome_evidence(
            context.plan,
            evidence,
            action_receipts=context.action_receipts,
            run_ref=spec.run_ref,
            iteration=spec.iteration,
            scope=scope,
            scope_keyring=self.scope_keyring,
        )
        evaluation = evaluate_profit_workflow_iteration(
            context.plan,
            outcome,
            scope=scope,
            scope_keyring=self.scope_keyring,
            evaluated_at=evaluated_at,
            previous_evaluation=context.previous_evaluation,
        )
        event = self._revision_event(spec, evaluation)
        return ObservationRunResult(
            job_ref=spec.job_ref,
            job_digest=spec.job_digest,
            read_receipt=read_receipt,
            profit_metric_evidence=evidence,
            profit_outcome=outcome,
            profit_evaluation=evaluation,
            next_iteration_event=event,
        )

    @staticmethod
    def _revision_event(
        spec: ObservationJobSpec,
        evaluation: StorefrontPhaseEvaluation
        | ProductLaunchIterationEvaluation
        | ProfitWorkflowEvaluation,
    ) -> WorkflowEventEnvelope | None:
        if evaluation.decision != "revise_plan":
            return None
        evaluation_digest = evaluation.evaluation_digest
        return WorkflowEventEnvelope(
            event_id=f"obs-revise-{evaluation_digest[:48]}",
            project_ref=spec.project_ref,
            event_type=(
                "gtm.storefront_phase_revision_requested"
                if spec.kind == "storefront_phase"
                else (
                    "gtm.product_launch_revision_requested"
                    if spec.kind == "gtm"
                    else "profit.workflow_revision_requested"
                )
            ),
            payload={
                "job_ref": spec.job_ref,
                "job_digest": spec.job_digest,
                "plan_digest": spec.plan_digest,
                "run_ref": spec.run_ref,
                "completed_iteration": spec.iteration,
                "next_iteration": evaluation.next_iteration,
                "evaluation_digest": evaluation_digest,
            },
            occurred_at=_timestamp(evaluation.evaluated_at),
            source="lightbulb.observation_runtime",
        )

    def _retry_or_fail(
        self,
        checkpoint: WorkflowCheckpoint,
        spec: ObservationJobSpec,
        now: datetime,
        code: str,
    ) -> None:
        attempt = int(checkpoint.workflow_inputs.get("attempt", 1))
        if attempt >= spec.max_attempts:
            return self._fail(checkpoint, f"{code}_exhausted")
        delay_seconds = min(3_600, 30 * (2 ** (attempt - 1)))
        retry_at = now + timedelta(seconds=delay_seconds)
        self.store.save(
            checkpoint.model_copy(
                deep=True,
                update={
                    "status": CheckpointStatus.SCHEDULED,
                    "workflow_inputs": {
                        **checkpoint.workflow_inputs,
                        "attempt": attempt + 1,
                    },
                    "resume_at": retry_at,
                    "next_attempt_at": retry_at,
                    "lease_owner": None,
                    "lease_until": None,
                },
            ),
            expected_revision=checkpoint.revision,
        )
        return None

    def _fail(self, checkpoint: WorkflowCheckpoint, code: str) -> None:
        self.store.save(
            checkpoint.model_copy(
                deep=True,
                update={
                    "status": CheckpointStatus.FAILED,
                    "blockers": [
                        PrimitiveBlocker(
                            code=code,
                            message="Post-action evidence failed closed; no evaluator artifact was minted.",
                        )
                    ],
                    "resume_at": None,
                    "next_attempt_at": None,
                    "lease_owner": None,
                    "lease_until": None,
                },
            ),
            expected_revision=checkpoint.revision,
        )
        return None

    def _complete_checkpoint(
        self, checkpoint: WorkflowCheckpoint, result: ObservationRunResult
    ) -> None:
        self.store.save(
            checkpoint.model_copy(
                deep=True,
                update={
                    "status": CheckpointStatus.COMPLETED,
                    "workflow_inputs": {
                        "observation_job": checkpoint.workflow_inputs[
                            "observation_job"
                        ],
                        "attempt": checkpoint.workflow_inputs.get("attempt", 1),
                        "result_ref": result.job_ref,
                        "result_digest": result.result_digest,
                    },
                    "current_step": None,
                    "resume_at": None,
                    "next_attempt_at": None,
                    "lease_owner": None,
                    "lease_until": None,
                },
            ),
            expected_revision=checkpoint.revision,
        )


class ObservationWorker:
    """Bounded poller; the hosting process remains responsible for starting it."""

    def __init__(
        self,
        runtime: ObservationRuntime,
        *,
        scope_supplier: Callable[
            [], Iterable[DynamicWorkflowScope | Mapping[str, Any]]
        ],
        worker_ref: str,
        poll_interval_seconds: float = 5.0,
        max_scopes_per_poll: int = 100,
        max_jobs_per_scope: int = 10,
        max_jobs_per_poll: int = 500,
        clock: Callable[[], datetime] | None = None,
        wait: Callable[[float], None] | None = None,
    ) -> None:
        if re.fullmatch(_PORTABLE_REF_RE, worker_ref) is None:
            raise ValueError("worker_ref is not portable")
        if not 0.01 <= poll_interval_seconds <= 300:
            raise ValueError("poll interval must be between 0.01 and 300 seconds")
        if not 1 <= max_scopes_per_poll <= 10_000:
            raise ValueError("max_scopes_per_poll is outside the safe bound")
        if not 1 <= max_jobs_per_scope <= 100:
            raise ValueError("max_jobs_per_scope is outside the safe bound")
        if not 1 <= max_jobs_per_poll <= 10_000:
            raise ValueError("max_jobs_per_poll is outside the safe bound")
        self.runtime = runtime
        self.scope_supplier = scope_supplier
        self.worker_ref = worker_ref
        self.poll_interval_seconds = poll_interval_seconds
        self.max_scopes_per_poll = max_scopes_per_poll
        self.max_jobs_per_scope = max_jobs_per_scope
        self.max_jobs_per_poll = max_jobs_per_poll
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.wait = wait or time.sleep

    def _authenticated_scopes(self) -> tuple[DynamicWorkflowScope, ...]:
        scopes: list[DynamicWorkflowScope] = []
        seen_partitions: set[str] = set()
        for raw_scope in self.scope_supplier():
            if len(scopes) >= self.max_scopes_per_poll:
                raise ValueError("scope supplier exceeded max_scopes_per_poll")
            scope = ObservationRuntime._scope(raw_scope)
            partition = _claim_partition_ref(scope)
            if partition in seen_partitions:
                raise ValueError(
                    "scope supplier returned a duplicate authenticated scope"
                )
            seen_partitions.add(partition)
            scopes.append(scope)
        return tuple(scopes)

    def run_once(
        self, *, now: datetime | None = None
    ) -> tuple[ObservationRunResult, ...]:
        observed_now = _utc(now if now is not None else self.clock())
        results: list[ObservationRunResult] = []
        for scope in self._authenticated_scopes():
            for _ in range(self.max_jobs_per_scope):
                if len(results) >= self.max_jobs_per_poll:
                    return tuple(results)
                result = self.runtime.run_next(
                    scope=scope,
                    worker_ref=self.worker_ref,
                    now=observed_now,
                )
                if result is None:
                    break
                results.append(result)
        return tuple(results)

    def serve(
        self,
        *,
        stop_requested: Callable[[], bool],
        max_cycles: int | None = None,
    ) -> int:
        """Poll until the host requests shutdown; ``max_cycles`` bounds tests/jobs."""

        if max_cycles is not None and not 1 <= max_cycles <= 1_000_000:
            raise ValueError("max_cycles is outside the safe bound")
        cycles = 0
        while not stop_requested():
            self.run_once()
            cycles += 1
            if max_cycles is not None and cycles >= max_cycles:
                break
            if stop_requested():
                break
            self.wait(self.poll_interval_seconds)
        return cycles


__all__ = [
    "CHECKOUT_RECOVERY_SNAPSHOT_PAYLOAD_SCHEMA",
    "CheckoutRecoverySnapshotNormalizer",
    "CheckoutRecoverySnapshotPayload",
    "GOOGLE_ANALYTICS_PAYLOAD_SCHEMA",
    "GoogleAnalyticsNormalizer",
    "GoogleAnalyticsPayload",
    "GtmObservationContext",
    "HOST_OBSERVATION_PROVENANCE_SCHEMA",
    "HOST_OBSERVATION_READ_REQUEST_SCHEMA",
    "HostObservationReadProvenance",
    "HostObservationReadRequest",
    "HostObservationReadResult",
    "HostObservationReader",
    "InMemoryObservationArtifactRepository",
    "JsonFileObservationArtifactRepository",
    "NormalizedObservation",
    "OBSERVATION_JOB_SCHEMA",
    "OBSERVATION_READ_RECEIPT_SCHEMA",
    "OBSERVATION_RESULT_SCHEMA",
    "OBSERVATION_RUNTIME_VERSION",
    "ObservationArtifactRepository",
    "ObservationJobSpec",
    "ObservationNormalizer",
    "ObservationReadReceipt",
    "ObservationRunResult",
    "ObservationRuntime",
    "ObservationScopeKeyRing",
    "ObservationWorker",
    "ProfitObservationContext",
    "SHOPIFY_ANALYTICS_PAYLOAD_SCHEMA",
    "STOREFRONT_PHASE_EVALUATION_SCHEMA",
    "ShopifyAnalyticsNormalizer",
    "ShopifyAnalyticsPayload",
    "StorefrontPhaseEvaluation",
    "StorefrontPhaseObservationContext",
    "mint_host_observation_read_result",
]
