"""Sanitized Project learning receipts for the durable SDK event runtime.

This module is deliberately transport-free. It accepts the complete, raw Spring
receipt contract and projects its allowlisted fields into the existing durable
workflow event envelope without exposing broker configuration, credentials, or
delivery guarantees.

The adapter validates receipt shape, nested scope, actor attestation, and lifecycle
consistency. It does not authenticate an arbitrary Python object or cryptographically
prove where a caller obtained a receipt. Callers must preserve the authenticated
Spring transport boundary and must not substitute an SDK-normalized projection.
"""

from __future__ import annotations

from datetime import datetime
from types import MappingProxyType
from typing import Annotated, Any, Literal, Mapping, TypeVar, cast
from uuid import UUID

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
)

from lightbulb.durable_runtime import WorkflowEventEnvelope
from lightbulb.project_learning_runs import (
    PROJECT_LEARNING_RUN_ADMISSION_RECEIPT_SCHEMA,
    PROJECT_LEARNING_RUN_EXECUTION_RECEIPT_SCHEMA,
    PROJECT_LEARNING_RUN_RECEIPT_SCHEMA,
)


# This is routing metadata for events projected from the complete raw Spring
# receipt contract. It is not a cryptographic provenance assertion.
PROJECT_LEARNING_RAW_RECEIPT_EVENT_SOURCE = "spring_project_learning_run_service"
# Compatibility alias retained for existing event consumers.
PROJECT_LEARNING_EVENT_SOURCE = PROJECT_LEARNING_RAW_RECEIPT_EVENT_SOURCE
PROJECT_LEARNING_EVENT_TYPE_BY_RECEIPT_SCHEMA: Mapping[str, str] = MappingProxyType(
    {
        PROJECT_LEARNING_RUN_RECEIPT_SCHEMA: "project.learning_run.requested",
        PROJECT_LEARNING_RUN_ADMISSION_RECEIPT_SCHEMA: "project.learning_run.admitted",
        PROJECT_LEARNING_RUN_EXECUTION_RECEIPT_SCHEMA: (
            "project.learning_run.execution_observed"
        ),
    }
)

_SENSITIVE_KEY_FRAGMENTS = frozenset(
    {
        "token",
        "secret",
        "password",
        "authorization",
        "cookie",
        "api_key",
        "apikey",
        "jwt",
    }
)
_PROJECT_REF_PATTERN = r"^[a-z0-9][a-z0-9._-]{0,127}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"


def _canonical_uuid(value: str) -> str:
    try:
        canonical = str(UUID(value))
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError("must be a canonical UUID string") from exc
    if value != canonical:
        raise ValueError("must be a canonical UUID string")
    return value


def _printable_text(value: str) -> str:
    if value != value.strip() or any(ord(character) < 32 for character in value):
        raise ValueError(
            "must be non-empty printable text without surrounding whitespace"
        )
    return value


def _aware_timestamp(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("must include a timezone offset")
    return value


CanonicalUuid = Annotated[str, AfterValidator(_canonical_uuid)]
Sha256 = Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)]
PrintableText = Annotated[
    str,
    StringConstraints(min_length=1, max_length=160),
    AfterValidator(_printable_text),
]
AwareTimestamp = Annotated[
    str,
    StringConstraints(min_length=1, max_length=128),
    AfterValidator(_aware_timestamp),
]
ProjectRef = Annotated[str, StringConstraints(pattern=_PROJECT_REF_PATTERN)]
LearningRuntime = Literal[
    "automl",
    "spark_feature_matrix",
    "gepa_autoresearch",
    "pufferlib_v4",
    "prime_rl",
]
ReceiptSchema = Literal[
    "lightbulb.project_learning_run_receipt.v1",
    "lightbulb.project_learning_run_admission_receipt.v1",
    "lightbulb.project_learning_run_execution_receipt.v1",
]


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=False,
        strict=True,
    )


class ProjectLearningReceiptValidationError(ValueError):
    """A source receipt cannot be safely projected into a workflow event."""


class _ProjectionScope(_StrictModel):
    project_ref: ProjectRef
    expected_project_id: CanonicalUuid


class _LearningRunIdentity(_StrictModel):
    schema_id: Literal["lightbulb.learning-run.v1"] = Field(alias="schema")
    id: CanonicalUuid
    tenant_id: CanonicalUuid
    company_id: CanonicalUuid
    project_id: CanonicalUuid
    user_id: CanonicalUuid
    runtime: LearningRuntime
    status: Literal[
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


class _AdmissionSummary(_StrictModel):
    memory_status: Literal["admitted"]


class _ExecutionSummary(_StrictModel):
    schema_id: Literal["lightbulb.project_learning_run_execution_snapshot.v1"] = Field(
        alias="schema"
    )
    memory_status: Literal[
        "running",
        "cancel_requested",
        "retry_scheduled",
        "succeeded",
        "failed",
        "cancelled",
    ]
    attempt: int = Field(ge=1, le=10)
    checkpoint_count: int = Field(ge=0, le=100)
    terminal_result_observed: bool


class _ReceiptBase(_StrictModel):
    tenant_id: CanonicalUuid
    company_id: CanonicalUuid
    project_id: CanonicalUuid
    user_id: CanonicalUuid
    actor: dict[str, Any]
    learning_run: dict[str, Any]
    quest: dict[str, Any]
    truth_boundary: dict[str, Any]
    authority: dict[str, Any]
    receipt_sha256: Sha256
    receipt_id: CanonicalUuid
    recorded_at: AwareTimestamp
    idempotent: bool


class _PrepareReceipt(_ReceiptBase):
    schema_id: Literal["lightbulb.project_learning_run_receipt.v1"] = Field(
        alias="schema"
    )
    request_schema: Literal["lightbulb.project_learning_run_prepare_request.v1"]
    request_id: CanonicalUuid
    request_sha256: Sha256
    training_pack_receipt_id: CanonicalUuid
    training_pack: dict[str, Any]
    dataset_custody: dict[str, Any]
    evaluation_plan: dict[str, Any]
    status: Literal[
        "durable_learning_run_queued",
        "durable_learning_run_created",
    ]


class _AdmissionReceipt(_ReceiptBase):
    schema_id: Literal["lightbulb.project_learning_run_admission_receipt.v1"] = Field(
        alias="schema"
    )
    request_schema: Literal["lightbulb.project_learning_run_admission_request.v1"]
    learning_run_id: CanonicalUuid
    prepared_run_receipt_id: CanonicalUuid
    admission_request_sha256: Sha256
    admission: dict[str, Any]
    status: Literal["durable_learning_run_admitted"]


class _ExecutionReceipt(_ReceiptBase):
    schema_id: Literal["lightbulb.project_learning_run_execution_receipt.v1"] = Field(
        alias="schema"
    )
    request_schema: Literal["lightbulb.project_learning_run_execution_sync_request.v1"]
    learning_run_id: CanonicalUuid
    prepared_run_receipt_id: CanonicalUuid
    admission_receipt_id: CanonicalUuid
    memory_snapshot_sha256: Sha256
    execution: dict[str, Any]
    status: Literal[
        "fenced_worker_claim_observed",
        "fenced_worker_checkpoint_observed",
        "training_result_observed",
    ]


class ProjectLearningWorkflowEventPayload(_StrictModel):
    """The complete allowlist permitted into a durable workflow event."""

    source_receipt_schema: ReceiptSchema
    source_receipt_id: CanonicalUuid
    source_receipt_sha256: Sha256
    project_id: CanonicalUuid
    learning_run_id: CanonicalUuid
    runtime: LearningRuntime
    status: PrintableText
    memory_status: PrintableText
    prepared_run_receipt_id: CanonicalUuid | None = None
    admission_receipt_id: CanonicalUuid | None = None
    memory_snapshot_sha256: Sha256 | None = None
    attempt: int | None = Field(default=None, ge=1, le=10)
    checkpoint_count: int | None = Field(default=None, ge=0, le=100)
    terminal_result_observed: bool | None = None


_Receipt = _PrepareReceipt | _AdmissionReceipt | _ExecutionReceipt
_RECEIPT_MODELS: Mapping[str, type[_ReceiptBase]] = MappingProxyType(
    {
        PROJECT_LEARNING_RUN_RECEIPT_SCHEMA: _PrepareReceipt,
        PROJECT_LEARNING_RUN_ADMISSION_RECEIPT_SCHEMA: _AdmissionReceipt,
        PROJECT_LEARNING_RUN_EXECUTION_RECEIPT_SCHEMA: _ExecutionReceipt,
    }
)
_ModelT = TypeVar("_ModelT", bound=BaseModel)


def _selected_fields(
    source: Mapping[str, Any], names: tuple[str, ...]
) -> dict[str, Any]:
    return {name: source[name] for name in names if name in source}


def _validate_receipt_model(model_type: type[_ModelT], value: Any) -> _ModelT:
    try:
        return model_type.model_validate(value)
    except ValidationError:
        raise ProjectLearningReceiptValidationError(
            "project learning receipt failed contract validation"
        ) from None


def _parse_receipt(receipt: Mapping[str, Any]) -> _Receipt:
    if not isinstance(receipt, Mapping):
        raise ProjectLearningReceiptValidationError(
            "project learning receipt failed contract validation"
        )
    raw = dict(receipt)
    schema = raw.get("schema")
    if not isinstance(schema, str) or schema not in _RECEIPT_MODELS:
        raise ProjectLearningReceiptValidationError(
            "project learning receipt schema is unsupported"
        )
    return cast(
        _Receipt,
        _validate_receipt_model(_RECEIPT_MODELS[schema], raw),
    )


def _learning_run_identity(receipt: _ReceiptBase) -> _LearningRunIdentity:
    return _validate_receipt_model(
        _LearningRunIdentity,
        _selected_fields(
            receipt.learning_run,
            (
                "schema",
                "id",
                "tenant_id",
                "company_id",
                "project_id",
                "user_id",
                "runtime",
                "status",
            ),
        ),
    )


def _reject_sensitive_keys(value: Any, path: str = "payload") -> None:
    if isinstance(value, Mapping):
        for raw_key, item in value.items():
            key = str(raw_key)
            normalized = key.lower()
            if any(fragment in normalized for fragment in _SENSITIVE_KEY_FRAGMENTS):
                raise ValueError(
                    f"{path} contains a prohibited credential field: {key}"
                )
            _reject_sensitive_keys(item, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _reject_sensitive_keys(item, f"{path}[{index}]")


def _timestamp(value: AwareTimestamp) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def project_learning_receipt_to_workflow_event(
    receipt: Mapping[str, Any],
    *,
    project_ref: str,
    expected_project_id: str,
) -> WorkflowEventEnvelope:
    """Project one complete raw Spring learning receipt into a sanitized event.

    A normalized SDK response model is intentionally rejected: it omits the actor
    and nested scope fields required to validate the receipt boundary and is freely
    constructible by callers. The source label records the expected receipt
    contract; it is not cryptographic proof of provenance. This adapter neither
    communicates with Kafka nor claims topic, partition, offset, or delivery
    semantics.
    """

    try:
        scope = _ProjectionScope.model_validate(
            {
                "project_ref": project_ref,
                "expected_project_id": expected_project_id,
            }
        )
    except ValidationError:
        raise ValueError("project learning event projection scope is invalid") from None
    if isinstance(receipt, BaseModel):
        raise ProjectLearningReceiptValidationError(
            "normalized SDK receipt projections are not authoritative Spring receipts"
        )
    parsed = _parse_receipt(receipt)
    if parsed.project_id != scope.expected_project_id:
        raise ProjectLearningReceiptValidationError(
            "project learning receipt project_id does not match expected scope"
        )

    run = _learning_run_identity(parsed)
    if (
        run.tenant_id != parsed.tenant_id
        or run.company_id != parsed.company_id
        or run.project_id != parsed.project_id
        or run.user_id != parsed.user_id
    ):
        raise ProjectLearningReceiptValidationError(
            "project learning receipt nested run scope does not match receipt scope"
        )
    actor = parsed.actor
    if (
        actor.get("authenticated") is not True
        or actor.get("scope_bound") is not True
        or not isinstance(actor.get("kind"), str)
        or not actor["kind"].strip()
    ):
        raise ProjectLearningReceiptValidationError(
            "project learning receipt actor scope attestation is invalid"
        )
    if isinstance(parsed, _ExecutionReceipt):
        if (
            actor.get("kind") != "memory_runtime"
            or actor.get("worker_identity_exposed") is not False
            or "user_id" in actor
        ):
            raise ProjectLearningReceiptValidationError(
                "execution receipt actor binding is invalid"
            )
    else:
        try:
            actor_user_id = _canonical_uuid(str(actor.get("user_id")))
        except ValueError:
            raise ProjectLearningReceiptValidationError(
                "project learning receipt actor binding is invalid"
            ) from None
        if (
            actor_user_id != parsed.user_id
            or actor.get("kind") not in {"human_user", "agent_worker"}
        ):
            raise ProjectLearningReceiptValidationError(
                "project learning receipt actor binding is invalid"
            )
    payload_values: dict[str, Any] = {
        "source_receipt_schema": parsed.schema_id,
        "source_receipt_id": parsed.receipt_id,
        "source_receipt_sha256": parsed.receipt_sha256,
        "project_id": parsed.project_id,
        "learning_run_id": run.id,
        "runtime": run.runtime,
        "status": parsed.status,
        "memory_status": run.status,
    }

    if isinstance(parsed, _PrepareReceipt):
        expected_status = (
            "durable_learning_run_queued"
            if run.status == "queued"
            else "durable_learning_run_created"
        )
        if parsed.status != expected_status:
            raise ProjectLearningReceiptValidationError(
                "prepare receipt status conflicts with its learning run status"
            )
    elif isinstance(parsed, _AdmissionReceipt):
        if parsed.learning_run_id != run.id:
            raise ProjectLearningReceiptValidationError(
                "admission receipt learning_run_id conflicts with learning_run.id"
            )
        admission = _validate_receipt_model(
            _AdmissionSummary,
            _selected_fields(parsed.admission, ("memory_status",)),
        )
        if admission.memory_status != run.status:
            raise ProjectLearningReceiptValidationError(
                "admission receipt memory status conflicts with learning_run.status"
            )
        payload_values["prepared_run_receipt_id"] = parsed.prepared_run_receipt_id
    else:
        if parsed.learning_run_id != run.id:
            raise ProjectLearningReceiptValidationError(
                "execution receipt learning_run_id conflicts with learning_run.id"
            )
        execution = _validate_receipt_model(
            _ExecutionSummary,
            _selected_fields(
                parsed.execution,
                (
                    "schema",
                    "memory_status",
                    "attempt",
                    "checkpoint_count",
                    "terminal_result_observed",
                ),
            ),
        )
        if execution.memory_status != run.status:
            raise ProjectLearningReceiptValidationError(
                "execution receipt memory status conflicts with learning_run.status"
            )
        terminal_status = execution.memory_status in {
            "succeeded",
            "failed",
            "cancelled",
        }
        if execution.terminal_result_observed is not terminal_status:
            raise ProjectLearningReceiptValidationError(
                "execution receipt terminal observation conflicts with memory status"
            )
        expected_status = (
            "training_result_observed"
            if execution.terminal_result_observed
            else (
                "fenced_worker_checkpoint_observed"
                if execution.checkpoint_count > 0
                else "fenced_worker_claim_observed"
            )
        )
        if parsed.status != expected_status:
            raise ProjectLearningReceiptValidationError(
                "execution receipt status conflicts with its execution summary"
            )
        payload_values.update(
            {
                "prepared_run_receipt_id": parsed.prepared_run_receipt_id,
                "admission_receipt_id": parsed.admission_receipt_id,
                "memory_snapshot_sha256": parsed.memory_snapshot_sha256,
                "attempt": execution.attempt,
                "checkpoint_count": execution.checkpoint_count,
                "terminal_result_observed": execution.terminal_result_observed,
            }
        )

    payload = _validate_receipt_model(
        ProjectLearningWorkflowEventPayload, payload_values
    ).model_dump(mode="json", exclude_none=True)
    _reject_sensitive_keys(payload)
    return WorkflowEventEnvelope(
        event_id=parsed.receipt_id,
        project_ref=scope.project_ref,
        event_type=PROJECT_LEARNING_EVENT_TYPE_BY_RECEIPT_SCHEMA[parsed.schema_id],
        payload=payload,
        occurred_at=_timestamp(parsed.recorded_at),
        source=PROJECT_LEARNING_RAW_RECEIPT_EVENT_SOURCE,
    )


__all__ = [
    "PROJECT_LEARNING_EVENT_SOURCE",
    "PROJECT_LEARNING_RAW_RECEIPT_EVENT_SOURCE",
    "PROJECT_LEARNING_EVENT_TYPE_BY_RECEIPT_SCHEMA",
    "ProjectLearningReceiptValidationError",
    "ProjectLearningWorkflowEventPayload",
    "project_learning_receipt_to_workflow_event",
]
