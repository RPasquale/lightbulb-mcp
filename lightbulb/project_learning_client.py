"""Typed public facade for governed Project learning-run lifecycle calls.

The facade can inspect Spring's last-observed receipt ledger, prepare a queued
durable run, and admit an existing run for worker claim.  It cannot call
internal execution routes, start Spark or AutoML, claim a worker, promote a
model/policy, or grant production-write authority.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Any, Literal, TypeVar
from uuid import UUID

import httpx
from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    FutureDatetime,
    StrictBool,
    StrictInt,
    ValidationError as PydanticValidationError,
    field_validator,
    model_validator,
)

from lightbulb.client import (
    LightbulbClient,
    _guard_request_body,
    _validate_idempotency_key,
)
from lightbulb.errors import (
    AuthenticationError,
    LightbulbError,
    NotFoundError,
    PermissionDenied,
    RateLimitedError,
    ServerError,
    ValidationError as LightbulbValidationError,
)
from lightbulb.project_learning_runs import (
    PROJECT_BILLABLE_LEARNING_RUNTIMES,
    PROJECT_CAPACITY_RUNTIMES,
    PROJECT_LEARNING_RUN_ADMISSION_CONFIRMATION,
    PROJECT_LEARNING_RUN_ADMISSION_RECEIPT_SCHEMA,
    PROJECT_LEARNING_RUN_EXECUTION_RECEIPT_SCHEMA,
    PROJECT_LEARNING_RUN_LEDGER_SCHEMA,
    PROJECT_LEARNING_RUN_PREPARE_CONFIRMATION,
    PROJECT_LEARNING_RUN_RECEIPT_SCHEMA,
    build_project_learning_run_admission_request,
    build_project_learning_run_prepare_request,
)


LearningRuntime = Literal[
    "automl",
    "spark_feature_matrix",
    "gepa_autoresearch",
    "pufferlib_v4",
    "prime_rl",
]
CapacityRuntime = Literal["automl", "spark", "prime", "puffer"]
MemoryRunStatus = Literal[
    "queued",
    "admitted",
    "running",
    "cancel_requested",
    "retry_scheduled",
    "held",
    "succeeded",
    "failed",
    "cancelled",
]
LedgerStatus = Literal[
    "awaiting_training_dataset",
    "durable_run_queued_awaiting_admission",
    "durable_run_admitted_awaiting_worker_claim",
    "memory_execution_receipt_observed",
]
ActorBindingAssurance = Literal[
    "verified_against_auth_strategy",
    "spring_enforced_not_locally_reverified",
]

_MONEY_QUANTUM = Decimal("0.000001")
_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{16,128}$")
_MEMORY_STATUSES = frozenset(
    {
        "queued",
        "admitted",
        "running",
        "cancel_requested",
        "retry_scheduled",
        "held",
        "succeeded",
        "failed",
        "cancelled",
    }
)
_EXECUTION_RECEIPT_STATUSES = frozenset(
    {
        "fenced_worker_claim_observed",
        "fenced_worker_checkpoint_observed",
        "training_result_observed",
    }
)
_FORBIDDEN_RESPONSE_KEYS = frozenset(
    {
        "access_token",
        "api_key",
        "authorization",
        "client_secret",
        "cookie",
        "credentials",
        "lease_token",
        "password",
        "private_key",
        "refresh_token",
        "secret",
        "set_cookie",
        "token_hash",
        "worker_id",
        "worker_identity",
    }
)
_FORBIDDEN_RESPONSE_KEY_SUFFIXES = (
    "_access_token",
    "_api_key",
    "_auth_token",
    "_authorization",
    "_bearer_token",
    "_client_secret",
    "_cookie",
    "_credential",
    "_credentials",
    "_lease_token",
    "_password",
    "_private_key",
    "_refresh_token",
    "_secret",
    "_token_hash",
    "_worker_id",
    "_worker_identity",
)
_NEGATIVE_SENSITIVE_ATTESTATIONS = frozenset(
    {
        "raw_lease_token_exposed",
        "raw_lease_tokens_exposed",
        "worker_identity_exposed",
    }
)
_INPUT_CONFIG = ConfigDict(
    extra="forbid",
    frozen=True,
    hide_input_in_errors=True,
    populate_by_name=True,
)
_REMOTE_CONFIG = ConfigDict(
    extra="allow",
    frozen=True,
    hide_input_in_errors=True,
    populate_by_name=True,
)


class ProjectLearningContractError(ValueError):
    """Sanitized local request/response contract failure."""


def _decimal6(value: Any, label: str) -> Decimal:
    try:
        parsed = Decimal(str(value))
        quantized = parsed.quantize(_MONEY_QUANTUM)
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be a finite decimal") from exc
    if not parsed.is_finite() or parsed < 0 or parsed != quantized:
        raise ValueError(f"{label} must be non-negative with at most six places")
    return parsed


class ProjectLearningRunPrepareInput(BaseModel):
    """Scope-free, secret-free input for one queued-run preparation."""

    model_config = _INPUT_CONFIG

    training_pack_receipt_id: UUID
    primary_metric: str = Field(min_length=1, max_length=256)
    runtime: LearningRuntime = "automl"
    request_id: UUID | None = None
    direction: Literal["maximize", "minimize"] = "maximize"
    minimum_improvement: Decimal = Decimal("0.010000")
    max_cost_usd: Decimal = Decimal("0.000000")
    max_platform_cost_usd: Decimal = Decimal("5.000000")
    max_gpu_seconds: StrictInt = Field(default=3600, ge=0, le=31_536_000)
    max_tokens: StrictInt = Field(default=100_000, ge=0, le=1_000_000_000_000)
    max_steps: StrictInt = Field(default=10_000, ge=0, le=1_000_000_000_000)
    provider_account_fingerprint: str | None = None
    provider_binding_expires_at: FutureDatetime | None = None
    max_attempts: StrictInt = Field(default=3, ge=1, le=10)
    lease_seconds: StrictInt = Field(default=300, ge=60, le=7200)
    preemptible: StrictBool = True
    confirmation: Literal["publish_dataset_and_create_queued_learning_run"]
    idempotency_key: str | None = None

    @field_validator(
        "minimum_improvement",
        "max_cost_usd",
        "max_platform_cost_usd",
        mode="before",
    )
    @classmethod
    def _money(cls, value: Any, info: Any) -> Decimal:
        return _decimal6(value, info.field_name)

    @field_validator("primary_metric")
    @classmethod
    def _metric(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized or any(ord(character) < 32 for character in normalized):
            raise ValueError("primary_metric must be printable non-blank text")
        return normalized

    @field_validator("provider_account_fingerprint")
    @classmethod
    def _fingerprint(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().lower()
        if _FINGERPRINT_RE.fullmatch(normalized) is None:
            raise ValueError("provider account fingerprint is invalid")
        return normalized

    @field_validator("idempotency_key")
    @classmethod
    def _retry_key(cls, value: str | None) -> str | None:
        return _validate_idempotency_key(value) if value is not None else None

    @model_validator(mode="after")
    def _funding(self) -> "ProjectLearningRunPrepareInput":
        billable = self.runtime in PROJECT_BILLABLE_LEARNING_RUNTIMES
        binding_complete = (
            self.provider_account_fingerprint is not None
            and self.provider_binding_expires_at is not None
        )
        binding_present = (
            self.provider_account_fingerprint is not None
            or self.provider_binding_expires_at is not None
        )
        if billable and (not binding_complete or self.max_cost_usd <= 0):
            raise ValueError(
                "billable runtimes require a verified binding and positive provider ceiling"
            )
        if not billable and binding_present:
            raise ValueError("platform runtimes must not include provider binding")
        if not billable and self.max_platform_cost_usd <= 0:
            raise ValueError("platform runtimes require a positive platform ceiling")
        return self


class LearningCapacityAdmission(BaseModel):
    """Fresh, exact, redacted capacity decision accepted by Spring."""

    model_config = _INPUT_CONFIG

    schema_id: Literal["lightbulb.learning-capacity-plan.v1"] = Field(alias="schema")
    decision_id: str = Field(min_length=1, max_length=128)
    runtime: CapacityRuntime
    admission: Literal["admit"]
    target_instances: StrictInt = Field(ge=1, le=10_000)
    expires_at: FutureDatetime
    secrets_redacted: Literal[True]

    @field_validator("decision_id")
    @classmethod
    def _decision_id(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized or any(ord(character) < 32 for character in normalized):
            raise ValueError("decision_id must be printable non-blank text")
        return normalized


class ProjectLearningRunAdmissionInput(BaseModel):
    """Scope-free, secret-free input for capacity/budget admission."""

    model_config = _INPUT_CONFIG

    runtime: LearningRuntime
    capacity_admission: LearningCapacityAdmission
    operator_approved: StrictBool = False
    confirmation: Literal["reserve_budget_and_admit_durable_learning_run"]
    idempotency_key: str | None = None

    @field_validator("idempotency_key")
    @classmethod
    def _retry_key(cls, value: str | None) -> str | None:
        return _validate_idempotency_key(value) if value is not None else None

    @model_validator(mode="after")
    def _admission(self) -> "ProjectLearningRunAdmissionInput":
        if self.capacity_admission.runtime != PROJECT_CAPACITY_RUNTIMES[self.runtime]:
            raise ValueError("capacity runtime does not match learning runtime")
        if (
            self.runtime in PROJECT_BILLABLE_LEARNING_RUNTIMES
            and not self.operator_approved
        ):
            raise ValueError("billable runtimes require operator approval")
        return self


class ProjectLearningRunPreparedReceipt(BaseModel):
    """Sanitized preparation summary, not a portable Spring authority receipt."""

    model_config = _INPUT_CONFIG

    schema_id: Literal["lightbulb.project_learning_run_receipt.v1"] = Field(
        alias="schema"
    )
    receipt_id: UUID
    receipt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    recorded_at: AwareDatetime
    request_id: UUID
    training_pack_receipt_id: UUID
    project_id: UUID
    learning_run_id: UUID
    runtime: LearningRuntime
    memory_status: MemoryRunStatus
    status: Literal[
        "durable_learning_run_queued",
        "durable_learning_run_created",
    ]
    idempotent: StrictBool
    actor_binding: ActorBindingAssurance = "spring_enforced_not_locally_reverified"
    dataset_custody_verified: Literal[True]
    worker_claim_completed: Literal[False]
    training_executed: Literal[False]
    production_promotion_authorized: Literal[False]


class ProjectLearningRunAdmittedReceipt(BaseModel):
    """Sanitized admission summary, not a portable Spring authority receipt."""

    model_config = _INPUT_CONFIG

    schema_id: Literal["lightbulb.project_learning_run_admission_receipt.v1"] = Field(
        alias="schema"
    )
    receipt_id: UUID
    receipt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    recorded_at: AwareDatetime
    project_id: UUID
    learning_run_id: UUID
    prepared_run_receipt_id: UUID
    runtime: LearningRuntime
    memory_status: Literal["admitted"]
    status: Literal["durable_learning_run_admitted"]
    idempotent: StrictBool
    actor_binding: ActorBindingAssurance = "spring_enforced_not_locally_reverified"
    capacity_decision_id: str
    operator_approval_required: StrictBool
    operator_approved: StrictBool
    memory_claim_candidate: Literal[True]
    worker_claim_completed: Literal[False]
    training_executed: Literal[False]
    production_promotion_authorized: Literal[False]


class ProjectLearningRunInspection(BaseModel):
    """One prepared run plus presence of later stored receipts."""

    model_config = _INPUT_CONFIG

    prepared_receipt_id: UUID
    project_id: UUID
    learning_run_id: UUID
    runtime: LearningRuntime
    prepared_status: Literal[
        "durable_learning_run_queued",
        "durable_learning_run_created",
    ]
    last_observed_memory_status: MemoryRunStatus
    admission_receipt_observed: StrictBool
    execution_receipt_observed: StrictBool
    terminal_result_receipt_observed: StrictBool


class ProjectLearningRunLedger(BaseModel):
    """Normalized last-observed ledger; never live worker telemetry."""

    model_config = _INPUT_CONFIG

    schema_id: Literal["lightbulb.project_learning_run_ledger.v1"] = Field(
        alias="schema"
    )
    project_id: UUID
    status: LedgerStatus
    run_count: StrictInt = Field(ge=0, le=50)
    admitted_count: StrictInt = Field(ge=0, le=50)
    execution_observation_count: StrictInt = Field(ge=0, le=50)
    terminal_result_count: StrictInt = Field(ge=0, le=50)
    runs: list[ProjectLearningRunInspection]
    latest_run_id: UUID | None
    actor_binding: ActorBindingAssurance = "spring_enforced_not_locally_reverified"
    statuses_are_last_observed_not_live_worker_telemetry: Literal[True]
    raw_lease_tokens_exposed: Literal[False]
    worker_claim_inferred: Literal[False]
    training_execution_inferred: Literal[False]
    production_promotion_authorized: Literal[False]


class _RemoteRun(BaseModel):
    model_config = _REMOTE_CONFIG

    schema_id: Literal["lightbulb.learning-run.v1"] = Field(alias="schema")
    id: UUID
    tenant_id: UUID
    company_id: UUID
    project_id: UUID
    user_id: UUID
    runtime: LearningRuntime
    status: MemoryRunStatus


class _RemoteReceipt(BaseModel):
    model_config = _REMOTE_CONFIG

    schema_id: str = Field(alias="schema")
    receipt_id: UUID
    receipt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    recorded_at: AwareDatetime
    tenant_id: UUID
    company_id: UUID
    project_id: UUID
    user_id: UUID
    learning_run: _RemoteRun
    status: str
    idempotent: StrictBool
    truth_boundary: dict[str, Any]


class _RemoteDatasetCustody(BaseModel):
    model_config = _INPUT_CONFIG

    schema_id: Literal["lightbulb.project_training_dataset_custody.v1"] = Field(
        alias="schema"
    )
    status: Literal["verified_immutable_artifact"]
    custody_verified: Literal[True]
    artifact_receipt_schema: Literal["lightbulb.immutable-artifact-receipt.v1"]
    artifact_receipt_status: Literal["created", "verified"]
    artifact_handle: str = Field(min_length=1, max_length=2048)
    artifact_uri: str = Field(min_length=1, max_length=2048)
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    artifact_size_bytes: StrictInt = Field(ge=1, le=100_000_000)
    training_pack_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    idempotent_artifact: StrictBool
    raw_dataset_exposed_in_receipt: Literal[False]


class _RemotePreparedReceipt(_RemoteReceipt):
    request_schema: Literal["lightbulb.project_learning_run_prepare_request.v1"]
    request_id: UUID
    request_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    training_pack_receipt_id: UUID
    dataset_custody: _RemoteDatasetCustody


class _RemoteAdmittedReceipt(_RemoteReceipt):
    request_schema: Literal["lightbulb.project_learning_run_admission_request.v1"]
    learning_run_id: UUID
    prepared_run_receipt_id: UUID
    admission_request_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    admission: dict[str, Any]


class _RemoteExecutionReceipt(_RemoteReceipt):
    request_schema: Literal["lightbulb.project_learning_run_execution_sync_request.v1"]
    learning_run_id: UUID
    prepared_run_receipt_id: UUID
    admission_receipt_id: UUID
    memory_snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    execution: dict[str, Any]


class _RemoteLedger(BaseModel):
    model_config = _REMOTE_CONFIG

    schema_id: Literal["lightbulb.project_learning_run_ledger.v1"] = Field(
        alias="schema"
    )
    tenant_id: UUID
    company_id: UUID
    project_id: UUID
    status: LedgerStatus
    run_count: StrictInt = Field(ge=0, le=50)
    admitted_count: StrictInt = Field(ge=0, le=50)
    execution_observation_count: StrictInt = Field(ge=0, le=50)
    terminal_result_count: StrictInt = Field(ge=0, le=50)
    latest_run: dict[str, Any] | None
    runs: list[dict[str, Any]]
    truth_boundary: dict[str, Any]


_ModelT = TypeVar("_ModelT", bound=BaseModel)


def _contract_model(
    model: type[_ModelT],
    value: Any,
    label: str,
) -> _ModelT:
    try:
        return model.model_validate(value)
    except (PydanticValidationError, TypeError, ValueError):
        raise ProjectLearningContractError(f"{label} contract is invalid") from None


def _input_model(
    model: type[_ModelT],
    value: _ModelT | Mapping[str, Any],
    label: str,
) -> _ModelT:
    if isinstance(value, model):
        return value
    try:
        return model.model_validate(value)
    except (PydanticValidationError, TypeError, ValueError):
        raise ProjectLearningContractError(
            f"{label} input contract is invalid"
        ) from None


def _uuid(value: Any, label: str) -> UUID:
    try:
        return UUID(str(value).strip())
    except (AttributeError, TypeError, ValueError):
        raise ProjectLearningContractError(f"{label} must be a UUID") from None


def _reject_sensitive(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            normalized = (
                re.sub(
                    r"(?<=[a-z0-9])(?=[A-Z])",
                    "_",
                    str(key).strip(),
                )
                .lower()
                .replace("-", "_")
            )
            negative_attestation = (
                normalized in _NEGATIVE_SENSITIVE_ATTESTATIONS and item is False
            )
            if not negative_attestation and (
                normalized in _FORBIDDEN_RESPONSE_KEYS
                or normalized.endswith(_FORBIDDEN_RESPONSE_KEY_SUFFIXES)
                or "lease_token" in normalized
                or "worker_identity" in normalized
            ):
                raise ProjectLearningContractError(
                    "response contains a forbidden sensitive field"
                )
            _reject_sensitive(item)
    elif isinstance(value, list):
        for item in value:
            _reject_sensitive(item)


def _payload(response: httpx.Response, label: str) -> Mapping[str, Any]:
    try:
        raw = response.json()
    except Exception:
        raise ProjectLearningContractError(f"{label} returned invalid JSON") from None
    if not isinstance(raw, Mapping):
        raise ProjectLearningContractError(f"{label} response contract is invalid")
    _reject_sensitive(raw)
    return raw


def _canonical_sha256(value: Mapping[str, Any]) -> str:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise ProjectLearningContractError(
            "response receipt cannot be canonically verified"
        ) from None
    return hashlib.sha256(encoded).hexdigest()


def _bool(mapping: Mapping[str, Any], key: str, expected: bool, label: str) -> bool:
    value = mapping.get(key)
    if not isinstance(value, bool) or value is not expected:
        raise ProjectLearningContractError(f"{label}.{key} contract is invalid")
    return value


def _text(mapping: Mapping[str, Any], key: str, label: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ProjectLearningContractError(f"{label}.{key} contract is invalid")
    return value.strip()


def _timestamp(value: Any, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError):
        raise ProjectLearningContractError(f"{label} timestamp is invalid") from None
    if parsed.tzinfo is None:
        raise ProjectLearningContractError(f"{label} timestamp is invalid")
    return parsed


def _no_authority(raw: Mapping[str, Any], label: str) -> None:
    authority = raw.get("authority")
    if not isinstance(authority, Mapping) or not authority:
        raise ProjectLearningContractError(f"{label} authority boundary is invalid")
    if any(value is not False for value in authority.values()):
        raise ProjectLearningContractError(f"{label} grants unsupported authority")


def _sanitized_http_error(status: int, operation: str, path: str) -> LightbulbError:
    kwargs = {"status_code": status, "path": path}
    message = f"Project learning {operation} request failed with HTTP {status}."
    if status in {400, 422}:
        return LightbulbValidationError(message, **kwargs)
    if status == 401:
        return AuthenticationError(message, **kwargs)
    if status == 403:
        return PermissionDenied(message, **kwargs)
    if status == 404:
        return NotFoundError(message, **kwargs)
    if status == 429:
        return RateLimitedError(message, **kwargs)
    if status >= 500:
        return ServerError(message, **kwargs)
    return LightbulbError(message, **kwargs)


def _status(
    response: httpx.Response,
    allowed: set[int],
    operation: str,
    path: str,
) -> int:
    status = getattr(response, "status_code", None)
    if isinstance(status, bool) or not isinstance(status, int):
        raise ProjectLearningContractError(f"{operation} response status is invalid")
    if status >= 400:
        raise _sanitized_http_error(status, operation, path)
    if status not in allowed:
        raise ProjectLearningContractError(
            f"{operation} returned unexpected HTTP status {status}"
        )
    return status


class ProjectLearningClient:
    """Typed facade over one authenticated selected-company client session."""

    def __init__(self, client: LightbulbClient) -> None:
        if not isinstance(client, LightbulbClient):
            raise TypeError("client must be a LightbulbClient")
        self._client = client

    def _scope(self, project_id: Any) -> tuple[UUID, UUID, UUID | None, UUID]:
        try:
            tenant = _uuid(self._client._auth.tenant_id, "authenticated tenant_id")
            company = _uuid(
                self._client._require_marketplace_company(),
                "selected company_id",
            )
            raw_user = self._client._auth.user_id
            user = _uuid(raw_user, "authenticated user_id") if raw_user else None
        except (AttributeError, TypeError, ValueError):
            raise ProjectLearningContractError(
                "authenticated tenant and selected-company scope are required"
            ) from None
        return tenant, company, user, _uuid(project_id, "project_id")

    def _headers(
        self,
        company_id: UUID,
        extra: Mapping[str, str] | None = None,
    ) -> dict[str, str]:
        headers = self._client._headers()
        headers.update(dict(extra or {}))
        headers["X-Company-Id"] = str(company_id)
        return headers

    @staticmethod
    def _bind_scope(
        receipt: _RemoteReceipt | _RemoteLedger,
        scope: tuple[UUID, UUID, UUID | None, UUID],
        *,
        require_current_user: bool,
    ) -> None:
        tenant, company, user, project = scope
        if (
            receipt.tenant_id != tenant
            or receipt.company_id != company
            or receipt.project_id != project
        ):
            raise ProjectLearningContractError("response scope binding does not match")
        if isinstance(receipt, _RemoteReceipt):
            if require_current_user and user is not None and receipt.user_id != user:
                raise ProjectLearningContractError(
                    "response actor binding does not match"
                )
            run = receipt.learning_run
            if (
                run.tenant_id != tenant
                or run.company_id != company
                or run.project_id != project
                or run.user_id != receipt.user_id
            ):
                raise ProjectLearningContractError(
                    "learning-run scope binding does not match"
                )

    @staticmethod
    def _bind_related(
        raw: Any,
        expected_schema: str,
        scope: tuple[UUID, UUID, UUID | None, UUID],
        run: _RemoteRun,
        label: str,
    ) -> _RemoteAdmittedReceipt | _RemoteExecutionReceipt:
        if not isinstance(raw, Mapping):
            raise ProjectLearningContractError(f"{label} contract is invalid")
        _no_authority(raw, label)
        if expected_schema == PROJECT_LEARNING_RUN_ADMISSION_RECEIPT_SCHEMA:
            related = _contract_model(_RemoteAdmittedReceipt, raw, label)
        elif expected_schema == PROJECT_LEARNING_RUN_EXECUTION_RECEIPT_SCHEMA:
            related = _contract_model(_RemoteExecutionReceipt, raw, label)
        else:
            raise ProjectLearningContractError(f"{label} schema is unsupported")
        if related.schema_id != expected_schema:
            raise ProjectLearningContractError(f"{label} schema is unsupported")
        ProjectLearningClient._bind_scope(
            related,
            scope,
            require_current_user=False,
        )
        if (
            related.learning_run_id != run.id
            or related.learning_run.id != run.id
            or related.learning_run.runtime != run.runtime
            or related.user_id != run.user_id
            or related.learning_run.user_id != run.user_id
        ):
            raise ProjectLearningContractError(
                f"{label} run/runtime/owner binding does not match"
            )
        if isinstance(related, _RemoteAdmittedReceipt):
            if (
                related.status != "durable_learning_run_admitted"
                or related.learning_run.status != "admitted"
                or related.admission.get("memory_status") != "admitted"
                or related.admission.get("capacity_admitted") is not True
                or related.admission.get("commercially_reserved") is not True
            ):
                raise ProjectLearningContractError(
                    "admission receipt lifecycle binding does not match"
                )
        else:
            execution = related.execution
            memory_status = _text(execution, "memory_status", label)
            checkpoint_count = execution.get("checkpoint_count")
            terminal_observed = execution.get("terminal_result_observed")
            if (
                related.status not in _EXECUTION_RECEIPT_STATUSES
                or related.learning_run.status
                not in _MEMORY_STATUSES - {"queued", "admitted", "held"}
                or memory_status != related.learning_run.status
                or isinstance(checkpoint_count, bool)
                or not isinstance(checkpoint_count, int)
                or not 0 <= checkpoint_count <= 100
                or not isinstance(terminal_observed, bool)
                or execution.get("worker_claim_observed") is not True
                or execution.get("raw_lease_token_exposed") is not False
                or execution.get("schema")
                != "lightbulb.project_learning_run_execution_snapshot.v1"
            ):
                raise ProjectLearningContractError(
                    "execution receipt lifecycle binding does not match"
                )
            expected_terminal = memory_status in {"succeeded", "failed", "cancelled"}
            expected_status = (
                "training_result_observed"
                if terminal_observed
                else (
                    "fenced_worker_checkpoint_observed"
                    if checkpoint_count > 0
                    else "fenced_worker_claim_observed"
                )
            )
            if (
                terminal_observed is not expected_terminal
                or related.status != expected_status
            ):
                raise ProjectLearningContractError(
                    "execution receipt lifecycle binding does not match"
                )
        return related

    def list(self, project_id: Any, *, limit: int = 25) -> ProjectLearningRunLedger:
        """Read last-observed Spring receipts without refreshing execution."""

        scope = self._scope(project_id)
        if isinstance(limit, bool):
            raise ProjectLearningContractError("limit must be an integer")
        try:
            bounded_limit = max(1, min(int(limit), 50))
        except (TypeError, ValueError):
            raise ProjectLearningContractError("limit must be an integer") from None
        path = f"/api/projects/{scope[3]}/learning-runs"
        response = self._client._get_session().get(
            f"{self._client._base_url}{path}",
            params={"limit": bounded_limit},
            headers=self._headers(scope[1]),
        )
        _status(response, {200}, "list", path)
        ledger = _contract_model(_RemoteLedger, _payload(response, "list"), "ledger")
        self._bind_scope(ledger, scope, require_current_user=False)
        if ledger.run_count > bounded_limit:
            raise ProjectLearningContractError(
                "ledger exceeds the requested bounded result limit"
            )

        runs: list[ProjectLearningRunInspection] = []
        seen_receipt_ids: set[UUID] = set()
        seen_run_ids: set[UUID] = set()
        prior_recorded_at: datetime | None = None
        latest_prepared_user_id: UUID | None = None
        current_actor_locally_verified = scope[2] is not None
        admitted = executed = terminal = 0
        for raw_run in ledger.runs:
            prepared = _contract_model(
                _RemotePreparedReceipt,
                raw_run,
                "prepared ledger receipt",
            )
            if prepared.schema_id != PROJECT_LEARNING_RUN_RECEIPT_SCHEMA:
                raise ProjectLearningContractError(
                    "prepared ledger receipt schema is unsupported"
                )
            self._bind_scope(
                prepared,
                scope,
                require_current_user=False,
            )
            if scope[2] is None or prepared.user_id != scope[2]:
                current_actor_locally_verified = False
            _no_authority(raw_run, "prepared ledger receipt")
            if prepared.status not in {
                "durable_learning_run_queued",
                "durable_learning_run_created",
            }:
                raise ProjectLearningContractError(
                    "prepared ledger receipt status is unsupported"
                )
            expected_prepared_status = (
                "durable_learning_run_queued"
                if prepared.learning_run.status == "queued"
                else "durable_learning_run_created"
            )
            if prepared.status != expected_prepared_status:
                raise ProjectLearningContractError(
                    "prepared ledger receipt lifecycle binding does not match"
                )
            if (
                prepared.receipt_id in seen_receipt_ids
                or prepared.learning_run.id in seen_run_ids
            ):
                raise ProjectLearningContractError(
                    "prepared ledger receipt identity is duplicated"
                )
            if (
                prior_recorded_at is not None
                and prepared.recorded_at > prior_recorded_at
            ):
                raise ProjectLearningContractError(
                    "prepared ledger receipts are not newest-first"
                )
            seen_receipt_ids.add(prepared.receipt_id)
            seen_run_ids.add(prepared.learning_run.id)
            prior_recorded_at = prepared.recorded_at
            if latest_prepared_user_id is None:
                latest_prepared_user_id = prepared.user_id
            latest_admission = raw_run.get("latest_admission")
            latest_execution = raw_run.get("latest_execution")
            admission = (
                self._bind_related(
                    latest_admission,
                    PROJECT_LEARNING_RUN_ADMISSION_RECEIPT_SCHEMA,
                    scope,
                    prepared.learning_run,
                    "admission receipt",
                )
                if latest_admission is not None
                else None
            )
            execution = (
                self._bind_related(
                    latest_execution,
                    PROJECT_LEARNING_RUN_EXECUTION_RECEIPT_SCHEMA,
                    scope,
                    prepared.learning_run,
                    "execution receipt",
                )
                if latest_execution is not None
                else None
            )
            if execution is not None and admission is None:
                raise ProjectLearningContractError(
                    "execution observation requires an admission receipt"
                )
            if admission is not None and (
                admission.prepared_run_receipt_id != prepared.receipt_id
            ):
                raise ProjectLearningContractError(
                    "admission receipt custody chain does not match"
                )
            if execution is not None and (
                execution.prepared_run_receipt_id != prepared.receipt_id
                or admission is None
                or execution.admission_receipt_id != admission.receipt_id
            ):
                raise ProjectLearningContractError(
                    "execution receipt custody chain does not match"
                )
            for related in (admission, execution):
                if related is None:
                    continue
                if related.receipt_id in seen_receipt_ids:
                    raise ProjectLearningContractError(
                        "learning-run receipt identity is duplicated"
                    )
                seen_receipt_ids.add(related.receipt_id)
            if admission is not None and admission.recorded_at < prepared.recorded_at:
                raise ProjectLearningContractError(
                    "admission receipt predates its prepared receipt"
                )
            if (
                execution is not None
                and admission is not None
                and execution.recorded_at < admission.recorded_at
            ):
                raise ProjectLearningContractError(
                    "execution receipt predates its admission receipt"
                )
            observed = _text(
                raw_run,
                "last_observed_memory_status",
                "prepared ledger receipt",
            )
            if observed not in _MEMORY_STATUSES:
                raise ProjectLearningContractError(
                    "last-observed run status is unsupported"
                )
            expected_observed = (
                execution.learning_run.status
                if execution is not None
                else admission.learning_run.status
                if admission is not None
                else prepared.learning_run.status
            )
            if observed != expected_observed:
                raise ProjectLearningContractError(
                    "last-observed run status binding does not match"
                )
            is_terminal = bool(
                execution
                and execution.learning_run.status
                in {"succeeded", "failed", "cancelled"}
            )
            admitted += admission is not None
            executed += execution is not None
            terminal += is_terminal
            runs.append(
                ProjectLearningRunInspection(
                    prepared_receipt_id=prepared.receipt_id,
                    project_id=scope[3],
                    learning_run_id=prepared.learning_run.id,
                    runtime=prepared.learning_run.runtime,
                    prepared_status=prepared.status,
                    last_observed_memory_status=observed,
                    admission_receipt_observed=admission is not None,
                    execution_receipt_observed=execution is not None,
                    terminal_result_receipt_observed=is_terminal,
                )
            )
        if (
            ledger.run_count != len(runs)
            or ledger.admitted_count != admitted
            or ledger.execution_observation_count != executed
            or ledger.terminal_result_count != terminal
        ):
            raise ProjectLearningContractError("ledger counts are inconsistent")
        # Spring derives status from its full bounded receipt maps, while `runs`
        # and the counts are limited to the caller-requested window. A later
        # lifecycle status may therefore be supported by an older run outside
        # this response. Selected receipts may never be ahead of that aggregate
        # status, and an empty prepared-run ledger must remain awaiting data.
        ledger_status_conflicts = (
            (not runs and ledger.status != "awaiting_training_dataset")
            or (bool(runs) and ledger.status == "awaiting_training_dataset")
            or (
                ledger.status == "durable_run_queued_awaiting_admission"
                and (admitted > 0 or executed > 0)
            )
            or (
                ledger.status == "durable_run_admitted_awaiting_worker_claim"
                and executed > 0
            )
        )
        if ledger_status_conflicts:
            raise ProjectLearningContractError(
                "ledger status does not match its receipt state"
            )
        latest_id = runs[0].learning_run_id if runs else None
        if bool(ledger.latest_run) != bool(runs):
            raise ProjectLearningContractError(
                "ledger latest-run binding is inconsistent"
            )
        if ledger.latest_run is not None:
            latest = _contract_model(
                _RemotePreparedReceipt,
                ledger.latest_run,
                "latest ledger receipt",
            )
            self._bind_scope(
                latest,
                scope,
                require_current_user=False,
            )
            if (
                latest.schema_id != PROJECT_LEARNING_RUN_RECEIPT_SCHEMA
                or latest.receipt_id != runs[0].prepared_receipt_id
                or latest.learning_run.id != latest_id
                or latest.learning_run.runtime != runs[0].runtime
                or latest.status != runs[0].prepared_status
                or latest.user_id != latest_prepared_user_id
                or latest.learning_run.user_id != latest_prepared_user_id
            ):
                raise ProjectLearningContractError(
                    "ledger latest-run binding does not match"
                )
        truth = ledger.truth_boundary
        return ProjectLearningRunLedger(
            schema=PROJECT_LEARNING_RUN_LEDGER_SCHEMA,
            project_id=scope[3],
            status=ledger.status,
            run_count=ledger.run_count,
            admitted_count=ledger.admitted_count,
            execution_observation_count=ledger.execution_observation_count,
            terminal_result_count=ledger.terminal_result_count,
            runs=runs,
            latest_run_id=latest_id,
            actor_binding=(
                "verified_against_auth_strategy"
                if current_actor_locally_verified and runs
                else "spring_enforced_not_locally_reverified"
            ),
            statuses_are_last_observed_not_live_worker_telemetry=_bool(
                truth,
                "statuses_are_last_observed_not_live_worker_telemetry",
                True,
                "ledger.truth_boundary",
            ),
            raw_lease_tokens_exposed=_bool(
                truth,
                "raw_lease_tokens_exposed",
                False,
                "ledger.truth_boundary",
            ),
            worker_claim_inferred=_bool(
                truth,
                "worker_claim_inferred",
                False,
                "ledger.truth_boundary",
            ),
            training_execution_inferred=_bool(
                truth,
                "training_execution_inferred",
                False,
                "ledger.truth_boundary",
            ),
            production_promotion_authorized=_bool(
                truth,
                "production_promotion_authorized",
                False,
                "ledger.truth_boundary",
            ),
        )

    def inspect(self, project_id: Any, *, limit: int = 25) -> ProjectLearningRunLedger:
        """Alias for :meth:`list`, emphasizing last-observed semantics."""

        return self.list(project_id, limit=limit)

    def prepare(
        self,
        project_id: Any,
        request: ProjectLearningRunPrepareInput | Mapping[str, Any],
    ) -> ProjectLearningRunPreparedReceipt:
        """Publish immutable custody and prepare a run without executing it."""

        scope = self._scope(project_id)
        parsed = _input_model(
            ProjectLearningRunPrepareInput,
            request,
            "preparation",
        )
        payload = build_project_learning_run_prepare_request(
            parsed.training_pack_receipt_id,
            parsed.primary_metric,
            runtime=parsed.runtime,
            request_id=parsed.request_id,
            direction=parsed.direction,
            minimum_improvement=parsed.minimum_improvement,
            max_cost_usd=parsed.max_cost_usd,
            max_platform_cost_usd=parsed.max_platform_cost_usd,
            max_gpu_seconds=parsed.max_gpu_seconds,
            max_tokens=parsed.max_tokens,
            max_steps=parsed.max_steps,
            provider_account_fingerprint=parsed.provider_account_fingerprint,
            provider_binding_expires_at=(
                parsed.provider_binding_expires_at.isoformat()
                if parsed.provider_binding_expires_at
                else None
            ),
            max_attempts=parsed.max_attempts,
            lease_seconds=parsed.lease_seconds,
            preemptible=parsed.preemptible,
            confirm_prepare=(
                parsed.confirmation == PROJECT_LEARNING_RUN_PREPARE_CONFIRMATION
            ),
        )
        retry_key = _validate_idempotency_key(
            parsed.idempotency_key or payload["request_id"]
        )
        if len(retry_key) < 8:
            raise ProjectLearningContractError(
                "idempotency_key must contain at least eight characters"
            )
        _guard_request_body(payload, endpoint="projects/learning-runs")
        path = f"/api/projects/{scope[3]}/learning-runs"
        response = self._client._get_session().post(
            f"{self._client._base_url}{path}",
            json=payload,
            headers=self._headers(scope[1], {"Idempotency-Key": retry_key}),
        )
        http_status = _status(response, {200, 201}, "prepare", path)
        raw_receipt = _payload(response, "prepare")
        _no_authority(raw_receipt, "prepared receipt")
        receipt = _contract_model(
            _RemotePreparedReceipt,
            raw_receipt,
            "prepared receipt",
        )
        if receipt.schema_id != PROJECT_LEARNING_RUN_RECEIPT_SCHEMA:
            raise ProjectLearningContractError("prepared receipt schema is unsupported")
        self._bind_scope(receipt, scope, require_current_user=True)
        if (
            receipt.request_id != UUID(payload["request_id"])
            or receipt.training_pack_receipt_id != parsed.training_pack_receipt_id
            or receipt.learning_run.runtime != parsed.runtime
        ):
            raise ProjectLearningContractError(
                "prepared receipt request/run/runtime binding does not match"
            )
        objective = payload["objective"]
        expected_request_sha256 = _canonical_sha256(
            {
                "request_id": payload["request_id"],
                "training_pack_receipt_id": payload["training_pack_receipt_id"],
                "runtime": payload["runtime"],
                "primary_metric": objective["primary_metric"],
                "direction": objective["direction"],
                "minimum_improvement": objective["minimum_improvement"],
                "budget": payload["budget"],
                "provider_account_binding": payload.get("provider_account_binding"),
                "max_attempts": payload["max_attempts"],
                "lease_seconds": payload["lease_seconds"],
                "preemptible": payload["preemptible"],
            }
        )
        if receipt.request_sha256 != expected_request_sha256:
            raise ProjectLearningContractError(
                "prepared receipt request digest does not match"
            )
        self._replay(http_status, receipt.idempotent, "prepared receipt")
        if receipt.status not in {
            "durable_learning_run_queued",
            "durable_learning_run_created",
        }:
            raise ProjectLearningContractError("prepared receipt status is unsupported")
        expected_status = (
            "durable_learning_run_queued"
            if receipt.learning_run.status == "queued"
            else "durable_learning_run_created"
        )
        if receipt.status != expected_status:
            raise ProjectLearningContractError(
                "prepared receipt lifecycle binding does not match"
            )
        truth = receipt.truth_boundary
        return ProjectLearningRunPreparedReceipt(
            schema=PROJECT_LEARNING_RUN_RECEIPT_SCHEMA,
            receipt_id=receipt.receipt_id,
            receipt_sha256=receipt.receipt_sha256,
            recorded_at=receipt.recorded_at,
            request_id=receipt.request_id,
            training_pack_receipt_id=receipt.training_pack_receipt_id,
            project_id=scope[3],
            learning_run_id=receipt.learning_run.id,
            runtime=receipt.learning_run.runtime,
            memory_status=receipt.learning_run.status,
            status=receipt.status,
            idempotent=receipt.idempotent,
            actor_binding=(
                "verified_against_auth_strategy"
                if scope[2] is not None
                else "spring_enforced_not_locally_reverified"
            ),
            dataset_custody_verified=_bool(
                truth,
                "dataset_custody_verified",
                True,
                "prepared receipt.truth_boundary",
            ),
            worker_claim_completed=_bool(
                truth,
                "worker_claim_completed",
                False,
                "prepared receipt.truth_boundary",
            ),
            training_executed=_bool(
                truth,
                "training_executed",
                False,
                "prepared receipt.truth_boundary",
            ),
            production_promotion_authorized=_bool(
                truth,
                "production_promotion_authorized",
                False,
                "prepared receipt.truth_boundary",
            ),
        )

    def admit(
        self,
        project_id: Any,
        learning_run_id: Any,
        request: ProjectLearningRunAdmissionInput | Mapping[str, Any],
    ) -> ProjectLearningRunAdmittedReceipt:
        """Reserve capacity/budget and make a run claimable without executing it."""

        scope = self._scope(project_id)
        run_id = _uuid(learning_run_id, "learning_run_id")
        parsed = _input_model(
            ProjectLearningRunAdmissionInput,
            request,
            "admission",
        )
        capacity = parsed.capacity_admission.model_dump(mode="python", by_alias=True)
        capacity["expires_at"] = parsed.capacity_admission.expires_at.isoformat()
        payload = build_project_learning_run_admission_request(
            parsed.runtime,
            capacity,
            operator_approved=parsed.operator_approved,
            confirm_admission=(
                parsed.confirmation == PROJECT_LEARNING_RUN_ADMISSION_CONFIRMATION
            ),
        )
        retry_key = _validate_idempotency_key(
            parsed.idempotency_key
            or f"project-learning-admission:{run_id}:"
            f"{parsed.capacity_admission.decision_id}"
        )
        if len(retry_key) < 8:
            raise ProjectLearningContractError(
                "idempotency_key must contain at least eight characters"
            )
        _guard_request_body(payload, endpoint="projects/learning-runs/admit")
        path = f"/api/projects/{scope[3]}/learning-runs/{run_id}/admit"
        response = self._client._get_session().post(
            f"{self._client._base_url}{path}",
            json=payload,
            headers=self._headers(scope[1], {"Idempotency-Key": retry_key}),
        )
        http_status = _status(response, {200, 201}, "admit", path)
        raw_receipt = _payload(response, "admit")
        _no_authority(raw_receipt, "admission receipt")
        receipt = _contract_model(
            _RemoteAdmittedReceipt,
            raw_receipt,
            "admission receipt",
        )
        if receipt.schema_id != PROJECT_LEARNING_RUN_ADMISSION_RECEIPT_SCHEMA:
            raise ProjectLearningContractError(
                "admission receipt schema is unsupported"
            )
        self._bind_scope(receipt, scope, require_current_user=True)
        if (
            receipt.learning_run_id != run_id
            or receipt.learning_run.id != run_id
            or receipt.learning_run.runtime != parsed.runtime
            or receipt.learning_run.status != "admitted"
        ):
            raise ProjectLearningContractError(
                "admission receipt run/runtime binding does not match"
            )
        self._replay(http_status, receipt.idempotent, "admission receipt")
        if receipt.status != "durable_learning_run_admitted":
            raise ProjectLearningContractError(
                "admission receipt status is unsupported"
            )
        admission = receipt.admission
        decision_id = _text(
            admission,
            "capacity_decision_id",
            "admission receipt",
        )
        expected_operator_required = (
            parsed.runtime in PROJECT_BILLABLE_LEARNING_RUNTIMES
        )
        if (
            decision_id != parsed.capacity_admission.decision_id
            or _timestamp(
                admission.get("capacity_expires_at"),
                "admission receipt capacity expiry",
            )
            != parsed.capacity_admission.expires_at
            or admission.get("memory_status") != "admitted"
            or admission.get("operator_approval_required")
            is not expected_operator_required
            or admission.get("operator_approved") is not parsed.operator_approved
        ):
            raise ProjectLearningContractError(
                "admission receipt capacity/approval binding does not match"
            )
        _bool(admission, "capacity_admitted", True, "admission receipt")
        _bool(admission, "commercially_reserved", True, "admission receipt")
        expected_admission_sha256 = _canonical_sha256(
            {
                "run_id": str(run_id),
                "operator_approved": parsed.operator_approved,
                "capacity_admission": payload["capacity_admission"],
                "commercial_request_hash": _text(
                    admission,
                    "commercial_request_hash",
                    "admission receipt",
                ),
            }
        )
        if receipt.admission_request_sha256 != expected_admission_sha256:
            raise ProjectLearningContractError(
                "admission receipt request digest does not match"
            )
        truth = receipt.truth_boundary
        return ProjectLearningRunAdmittedReceipt(
            schema=PROJECT_LEARNING_RUN_ADMISSION_RECEIPT_SCHEMA,
            receipt_id=receipt.receipt_id,
            receipt_sha256=receipt.receipt_sha256,
            recorded_at=receipt.recorded_at,
            project_id=scope[3],
            learning_run_id=run_id,
            prepared_run_receipt_id=receipt.prepared_run_receipt_id,
            runtime=receipt.learning_run.runtime,
            memory_status="admitted",
            status="durable_learning_run_admitted",
            idempotent=receipt.idempotent,
            actor_binding=(
                "verified_against_auth_strategy"
                if scope[2] is not None
                else "spring_enforced_not_locally_reverified"
            ),
            capacity_decision_id=decision_id,
            operator_approval_required=expected_operator_required,
            operator_approved=parsed.operator_approved,
            memory_claim_candidate=_bool(
                truth,
                "memory_claim_candidate",
                True,
                "admission receipt.truth_boundary",
            ),
            worker_claim_completed=_bool(
                truth,
                "worker_claim_completed",
                False,
                "admission receipt.truth_boundary",
            ),
            training_executed=_bool(
                truth,
                "training_executed",
                False,
                "admission receipt.truth_boundary",
            ),
            production_promotion_authorized=_bool(
                truth,
                "production_promotion_authorized",
                False,
                "admission receipt.truth_boundary",
            ),
        )

    @staticmethod
    def _replay(http_status: int, idempotent: bool, label: str) -> None:
        if (http_status == 200) != idempotent:
            expected = "idempotent replay" if http_status == 200 else "newly created"
            raise ProjectLearningContractError(f"{label} must be {expected}")


__all__ = [
    "ActorBindingAssurance",
    "CapacityRuntime",
    "LearningCapacityAdmission",
    "LearningRuntime",
    "LedgerStatus",
    "MemoryRunStatus",
    "ProjectLearningClient",
    "ProjectLearningContractError",
    "ProjectLearningRunAdmissionInput",
    "ProjectLearningRunAdmittedReceipt",
    "ProjectLearningRunInspection",
    "ProjectLearningRunLedger",
    "ProjectLearningRunPrepareInput",
    "ProjectLearningRunPreparedReceipt",
]
