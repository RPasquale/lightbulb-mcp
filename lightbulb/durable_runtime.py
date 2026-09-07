"""Durable pause/resume, scheduling, events, and worker leasing for projects."""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Mapping, Protocol
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from lightbulb.errors import LightbulbError
from lightbulb.local_storage import local_scope_fingerprint

from lightbulb.primitive_runtime import (
    PrimitiveCall,
    PrimitiveBlocker,
    PrimitiveEvent,
    PrimitiveExecutionResult,
    PrimitiveExecutionStatus,
    PrimitiveOperationReceipt,
    PrimitiveRecoveryAttestation,
)
from lightbulb.project_runtime import (
    BindingResolutionError,
    ProjectRuntime,
    ProjectValidationSeverity,
    ProjectWorkflow,
    ProjectWorkflowRun,
    ProjectWorkflowRunStatus,
    ProjectWorkflowStepRun,
    _END,
    _authoritative_recovery_receipts,
    _step_inputs,
    _workflow_result_with_recovery_gate,
)


LEGACY_DURABLE_CHECKPOINT_SCHEMA = "lightbulb.project_workflow_checkpoint.v1"
PREVIOUS_DURABLE_CHECKPOINT_SCHEMA = "lightbulb.project_workflow_checkpoint.v2"
DURABLE_CHECKPOINT_SCHEMA = "lightbulb.project_workflow_checkpoint.v3"
WORKFLOW_EVENT_SCHEMA = "lightbulb.project_workflow_event.v1"
LOCAL_EVENT_LEDGER_SCHEMA = "lightbulb.local_workflow_event_ledger.v1"
_PORTABLE_PROJECT_REF_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_SCOPE_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{64}$")
_STEP_ATTEMPT_KEY_RE = re.compile(
    r"^[a-z][a-z0-9_-]{0,127}:[1-9][0-9]{0,2}$"
)
_CONNECTOR_ACCOUNT_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_INLINE_LEASE_SECONDS = 60
_MIN_LEASE_HEARTBEAT_INTERVAL_SECONDS = 0.25
_MAX_LEASE_HEARTBEAT_INTERVAL_SECONDS = 20.0


def _utc_now(value: datetime | None = None) -> datetime:
    now = value or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    return now.astimezone(timezone.utc)


def _normalized_connector_account_refs(
    value: Mapping[str, str] | None,
) -> Dict[str, str]:
    normalized: Dict[str, str] = {}
    for raw_key, raw_value in (value or {}).items():
        key = str(raw_key).strip().lower()
        account_ref = str(raw_value).strip()
        if not _CONNECTOR_ACCOUNT_KEY_RE.fullmatch(key):
            raise ValueError(
                "connector_account_refs keys must be portable operation, Tool, or provider names"
            )
        if (
            not account_ref
            or len(account_ref) > 200
            or any(ord(character) < 33 for character in account_ref)
        ):
            raise ValueError(
                "connector_account_refs values must be 1-200 visible characters"
            )
        if key in normalized:
            raise ValueError(
                "connector_account_refs keys must remain unique after normalization"
            )
        normalized[key] = account_ref
    return normalized


def _normalized_recovery_attestations(
    value: Mapping[str, PrimitiveRecoveryAttestation | Mapping[str, Any]] | None,
) -> Dict[str, PrimitiveRecoveryAttestation]:
    normalized: Dict[str, PrimitiveRecoveryAttestation] = {}
    for raw_digest, raw_attestation in (value or {}).items():
        digest = str(raw_digest).strip().lower()
        attestation = (
            raw_attestation
            if isinstance(raw_attestation, PrimitiveRecoveryAttestation)
            else PrimitiveRecoveryAttestation.model_validate(raw_attestation)
        )
        if digest != attestation.request_digest:
            raise ValueError(
                "recovery_attestations keys must match their request_digest"
            )
        if digest in normalized:
            raise ValueError("recovery_attestations request digests must be unique")
        normalized[digest] = attestation
    return normalized


def _workflow_identity_sha256(
    workflow: ProjectWorkflow,
    *,
    execution_policy: BaseModel,
) -> str:
    """Hash value-only workflow semantics without storing inputs or secrets."""
    material = json.dumps(
        {
            "workflow": workflow.model_dump(mode="json"),
            "execution_policy": execution_policy.model_dump(mode="json"),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def default_checkpoint_dir(
    project_ref: str,
    *,
    tenant_id: str | None = None,
    company_id: str | None = None,
) -> Path:
    """Return a local checkpoint directory isolated by authenticated scope.

    Callers with an authenticated scope must supply the tenant. Company-scoped
    runs receive a distinct namespace; tenant-wide runs use an explicit marker.
    The digest avoids exposing customer UUIDs in ordinary filesystem listings.
    """
    clean_project_ref = str(project_ref or "").strip().lower()
    if (
        not _PORTABLE_PROJECT_REF_RE.fullmatch(clean_project_ref)
        or ".." in clean_project_ref
    ):
        raise ValueError("project_ref has an invalid portable format")
    if company_id is not None and tenant_id is None:
        raise ValueError("company_id requires tenant_id for local checkpoint scope")
    root = os.getenv("LIGHTBULB_PROJECT_RUNTIME_DIR", "").strip()
    base = (
        Path(root).expanduser()
        if root
        else Path.cwd() / ".lightbulb" / "project-runtime"
    )
    if tenant_id is not None:
        scope_digest = local_scope_fingerprint(tenant_id, company_id)[:32]
        base = base / f"scope-{scope_digest}"
    return base / clean_project_ref


class CheckpointConflictError(RuntimeError):
    """The checkpoint changed after a worker read it."""


class CheckpointPersistenceError(RuntimeError):
    """A local checkpoint cannot be loaded or committed safely."""


class CheckpointScopeError(CheckpointPersistenceError):
    """A local checkpoint artifact is outside the exact authenticated scope."""


class CheckpointCompatibilityError(CheckpointPersistenceError):
    """A checkpoint was created for different executable project semantics."""


class CheckpointStatus(str, Enum):
    RUNNING = "running"
    SCHEDULED = "scheduled"
    DISPATCHED = "dispatched"
    COMPLETED = "completed"
    PREVIEW = "preview"
    PENDING_APPROVAL = "pending_approval"
    NEEDS_INPUT = "needs_input"
    WAITING_FOR_RECOVERY = "waiting_for_recovery"
    BLOCKED = "blocked"
    FAILED = "failed"


class WorkflowEventEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_id: str = Field(default=WORKFLOW_EVENT_SCHEMA, alias="schema")
    event_id: str = Field(
        default_factory=lambda: f"event-{uuid4()}", min_length=1, max_length=200
    )
    project_ref: str = Field(min_length=1, max_length=128)
    event_type: str = Field(min_length=1, max_length=160)
    payload: Dict[str, Any] = Field(default_factory=dict)
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = Field(default="sdk", max_length=120)

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True)

    def fingerprint(self) -> str:
        material = json.dumps(
            {
                "project_ref": self.project_ref,
                "event_type": self.event_type,
                "payload": self.payload,
            },
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
        return hashlib.sha256(material).hexdigest()


class WorkflowCheckpoint(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    schema_id: str = Field(default=DURABLE_CHECKPOINT_SCHEMA, alias="schema")
    run_ref: str = Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9._-]+$")
    project_ref: str = Field(min_length=1, max_length=128)
    scope_fingerprint: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    hosted_project_id: UUID | None = None
    project_version: str = Field(min_length=1, max_length=80)
    workflow_key: str = Field(min_length=1, max_length=128)
    workflow_version: str | None = Field(default=None, min_length=1, max_length=80)
    workflow_identity_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    primitive_versions: Dict[str, str] = Field(default_factory=dict)
    status: CheckpointStatus
    workflow_inputs: Dict[str, Any] = Field(default_factory=dict)
    preview_only: bool = True
    approval_refs: Dict[str, str] = Field(default_factory=dict)
    connector_account_refs: Dict[str, str] = Field(default_factory=dict)
    recovery_attestations: Dict[str, PrimitiveRecoveryAttestation] = Field(
        default_factory=dict
    )
    current_step: str | None = None
    step_runs: list[ProjectWorkflowStepRun] = Field(default_factory=list)
    events: list[PrimitiveEvent] = Field(default_factory=list)
    visits: Dict[str, int] = Field(default_factory=dict)
    saw_preview: bool = False
    last_event: PrimitiveEvent | None = None
    blockers: list[PrimitiveBlocker] = Field(default_factory=list)
    resume_at: datetime | None = None
    next_attempt_at: datetime | None = None
    step_attempts: Dict[str, int] = Field(default_factory=dict)
    step_invocations: Dict[str, int] = Field(default_factory=dict)
    active_step_id: str | None = Field(default=None, max_length=128)
    active_attempt_key: str | None = Field(default=None, max_length=132)
    legacy_step_idempotency_mode: bool = False
    trigger_event_id: str | None = Field(default=None, max_length=200)
    lease_owner: str | None = Field(default=None, max_length=200)
    lease_until: datetime | None = None
    revision: int = Field(default=0, ge=0)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @model_validator(mode="before")
    @classmethod
    def _migrate_checkpoint_schema(cls, value: Any) -> Any:
        if not isinstance(value, Mapping):
            return value
        payload = dict(value)
        alias_schema = payload.get("schema")
        name_schema = payload.get("schema_id")
        if (
            alias_schema is not None
            and name_schema is not None
            and alias_schema != name_schema
        ):
            raise ValueError("workflow checkpoint schema aliases disagree")
        schema = alias_schema if alias_schema is not None else name_schema
        if name_schema is not None:
            # Normalise the field name to its wire alias. Leaving both keys in
            # a migrated payload is rejected by Pydantic's extra=forbid.
            payload.pop("schema_id", None)
            payload["schema"] = schema
        if schema == LEGACY_DURABLE_CHECKPOINT_SCHEMA:
            payload["schema"] = DURABLE_CHECKPOINT_SCHEMA
            # Version 1 derived connector idempotency from step_id alone.
            # Preserve that identity for the remainder of an upgraded run so
            # exact approvals and crash-crossed writes cannot drift.
            payload["legacy_step_idempotency_mode"] = True
            payload.setdefault("connector_account_refs", {})
            payload.setdefault("recovery_attestations", {})
        elif schema == PREVIOUS_DURABLE_CHECKPOINT_SCHEMA:
            payload["schema"] = DURABLE_CHECKPOINT_SCHEMA
            payload.setdefault("connector_account_refs", {})
            payload.setdefault("recovery_attestations", {})
        elif schema is not None and schema != DURABLE_CHECKPOINT_SCHEMA:
            raise ValueError("workflow checkpoint schema is unsupported")
        return payload

    @field_validator("connector_account_refs")
    @classmethod
    def _normalize_connector_account_refs(
        cls, value: Mapping[str, str]
    ) -> Dict[str, str]:
        return _normalized_connector_account_refs(value)

    @field_validator("recovery_attestations")
    @classmethod
    def _normalize_recovery_attestations(
        cls,
        value: Mapping[
            str,
            PrimitiveRecoveryAttestation | Mapping[str, Any],
        ],
    ) -> Dict[str, PrimitiveRecoveryAttestation]:
        return _normalized_recovery_attestations(value)

    @field_validator("primitive_versions")
    @classmethod
    def _normalize_primitive_versions(
        cls, value: Mapping[str, str]
    ) -> Dict[str, str]:
        normalized: Dict[str, str] = {}
        for raw_ref, raw_version in value.items():
            primitive_ref = str(raw_ref).strip().lower()
            version = str(raw_version).strip()
            if not primitive_ref or "." not in primitive_ref:
                raise ValueError(
                    "primitive_versions keys must be dotted primitive references"
                )
            if not version or len(version) > 80:
                raise ValueError(
                    "primitive_versions values must contain 1 to 80 characters"
                )
            if primitive_ref in normalized:
                raise ValueError("primitive_versions keys must be unique")
            normalized[primitive_ref] = version
        return normalized

    @field_validator(
        "resume_at",
        "next_attempt_at",
        "lease_until",
        "created_at",
        "updated_at",
    )
    @classmethod
    def _normalize_datetime(cls, value: datetime | None) -> datetime | None:
        return _utc_now(value) if value is not None else None

    @field_validator("run_ref")
    @classmethod
    def _portable_run_ref(cls, value: str) -> str:
        if ".." in value:
            raise ValueError("run_ref must not contain '..'")
        return value

    @field_validator("step_attempts")
    @classmethod
    def _bounded_step_attempts(cls, value: Mapping[str, int]) -> Dict[str, int]:
        normalized: Dict[str, int] = {}
        for raw_key, raw_attempts in value.items():
            key = str(raw_key).strip().lower()
            if not _STEP_ATTEMPT_KEY_RE.fullmatch(key):
                raise ValueError("step_attempts keys must be step_id:visit_number")
            if (
                isinstance(raw_attempts, bool)
                or not isinstance(raw_attempts, int)
                or raw_attempts < 1
                or raw_attempts > 100
            ):
                raise ValueError("step_attempts values must be integers from 1 to 100")
            normalized[key] = raw_attempts
        return normalized

    @field_validator("step_invocations")
    @classmethod
    def _bounded_step_invocations(
        cls, value: Mapping[str, int]
    ) -> Dict[str, int]:
        normalized: Dict[str, int] = {}
        for raw_key, raw_invocations in value.items():
            key = str(raw_key).strip().lower()
            if not _STEP_ATTEMPT_KEY_RE.fullmatch(key):
                raise ValueError(
                    "step_invocations keys must be step_id:visit_number"
                )
            if (
                isinstance(raw_invocations, bool)
                or not isinstance(raw_invocations, int)
                or raw_invocations < 1
                or raw_invocations > 10_000
            ):
                raise ValueError(
                    "step_invocations values must be integers from 1 to 10000"
                )
            normalized[key] = raw_invocations
        return normalized

    @field_validator("active_step_id")
    @classmethod
    def _portable_active_step(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().lower()
        if not re.fullmatch(r"^[a-z][a-z0-9_-]{0,127}$", normalized):
            raise ValueError("active_step_id must be a lowercase project step key")
        return normalized

    @field_validator("active_attempt_key")
    @classmethod
    def _portable_attempt_key(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().lower()
        if not _STEP_ATTEMPT_KEY_RE.fullmatch(normalized):
            raise ValueError("active_attempt_key must be step_id:visit_number")
        return normalized

    @model_validator(mode="after")
    def _active_attempt_matches_step(self) -> "WorkflowCheckpoint":
        if (self.active_step_id is None) != (self.active_attempt_key is None):
            raise ValueError(
                "active_step_id and active_attempt_key must be set together"
            )
        if (
            self.active_step_id is not None
            and not self.active_attempt_key.startswith(
                f"{self.active_step_id}:"
            )
        ):
            raise ValueError("active_attempt_key must belong to active_step_id")
        if self.active_attempt_key is not None:
            step_id, raw_visit = self.active_attempt_key.rsplit(":", 1)
            if self.visits.get(step_id) != int(raw_visit):
                raise ValueError(
                    "active_attempt_key must match the active logical step visit"
                )
            attempts = self.step_attempts.get(self.active_attempt_key)
            invocations = self.step_invocations.get(self.active_attempt_key)
            if attempts is None or invocations is None:
                raise ValueError(
                    "active step counters must exist for active_attempt_key"
                )
            if invocations < attempts:
                raise ValueError(
                    "step_invocations cannot be lower than step_attempts"
                )
        if (
            self.next_attempt_at is not None
            and self.status != CheckpointStatus.SCHEDULED
        ):
            raise ValueError(
                "next_attempt_at is only valid for a scheduled checkpoint"
            )
        return self

    @model_validator(mode="after")
    def _surface_legacy_recovery_waits(self) -> "WorkflowCheckpoint":
        if self.status not in {CheckpointStatus.BLOCKED, CheckpointStatus.FAILED}:
            return self
        active_visit = (
            self.visits.get(self.active_step_id)
            if self.active_step_id is not None
            else None
        )
        for step_run in reversed(self.step_runs):
            if (
                self.active_step_id is not None
                and step_run.step_id != self.active_step_id
            ):
                continue
            if active_visit is not None and step_run.step_visit != active_visit:
                continue
            if _authoritative_recovery_receipts(step_run.result):
                self.status = CheckpointStatus.WAITING_FOR_RECOVERY
                self.resume_at = None
                self.next_attempt_at = None
                self.lease_owner = None
                self.lease_until = None
            break
        return self

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True)


class WorkflowCheckpointStore(Protocol):
    def save(
        self,
        checkpoint: WorkflowCheckpoint,
        *,
        expected_revision: int | None,
    ) -> WorkflowCheckpoint: ...

    def get(self, run_ref: str) -> WorkflowCheckpoint | None: ...

    def list_ready(
        self,
        project_ref: str,
        *,
        now: datetime,
        limit: int = 100,
    ) -> list[WorkflowCheckpoint]: ...

    def claim_next(
        self,
        project_ref: str,
        *,
        worker_ref: str,
        now: datetime,
        lease_seconds: int,
    ) -> WorkflowCheckpoint | None: ...

    def renew_lease(
        self,
        run_ref: str,
        *,
        worker_ref: str,
        expected_revision: int,
        now: datetime,
        lease_seconds: int,
    ) -> WorkflowCheckpoint: ...

    def record_event(self, event: WorkflowEventEnvelope) -> bool: ...


def _is_ready(checkpoint: WorkflowCheckpoint, now: datetime) -> bool:
    if checkpoint.status == CheckpointStatus.DISPATCHED:
        return True
    if checkpoint.status == CheckpointStatus.SCHEDULED:
        return checkpoint.resume_at is None or checkpoint.resume_at <= now
    return (
        checkpoint.status == CheckpointStatus.RUNNING
        and checkpoint.lease_until is not None
        and checkpoint.lease_until <= now
    )


class InMemoryCheckpointStore:
    """Revisioned checkpoint store and queue for tests and one-process workers."""

    def __init__(self) -> None:
        self._checkpoints: dict[str, WorkflowCheckpoint] = {}
        self._event_ids: dict[tuple[str, str], str] = {}
        self._lock = threading.RLock()

    def save(
        self,
        checkpoint: WorkflowCheckpoint,
        *,
        expected_revision: int | None,
    ) -> WorkflowCheckpoint:
        with self._lock:
            current = self._checkpoints.get(checkpoint.run_ref)
            actual_revision = current.revision if current is not None else 0
            if expected_revision is not None and expected_revision != actual_revision:
                raise CheckpointConflictError(
                    f"checkpoint {checkpoint.run_ref} revision is {actual_revision}, expected {expected_revision}"
                )
            if current is not None and expected_revision is None:
                raise CheckpointConflictError(
                    f"checkpoint already exists: {checkpoint.run_ref}"
                )
            stored = checkpoint.model_copy(
                deep=True,
                update={
                    "revision": actual_revision + 1,
                    "created_at": current.created_at
                    if current
                    else checkpoint.created_at,
                    "updated_at": _utc_now(),
                },
            )
            self._checkpoints[stored.run_ref] = stored
            return stored.model_copy(deep=True)

    def get(self, run_ref: str) -> WorkflowCheckpoint | None:
        with self._lock:
            value = self._checkpoints.get(str(run_ref).strip())
            return value.model_copy(deep=True) if value is not None else None

    def list_ready(
        self,
        project_ref: str,
        *,
        now: datetime,
        limit: int = 100,
    ) -> list[WorkflowCheckpoint]:
        timestamp = _utc_now(now)
        with self._lock:
            values = [
                value.model_copy(deep=True)
                for value in self._checkpoints.values()
                if value.project_ref == project_ref and _is_ready(value, timestamp)
            ]
        return sorted(
            values,
            key=lambda value: (value.resume_at or value.created_at, value.run_ref),
        )[:limit]

    def claim_next(
        self,
        project_ref: str,
        *,
        worker_ref: str,
        now: datetime,
        lease_seconds: int,
    ) -> WorkflowCheckpoint | None:
        if lease_seconds < 1:
            raise ValueError("lease_seconds must be positive")
        timestamp = _utc_now(now)
        with self._lock:
            ready = self.list_ready(project_ref, now=timestamp, limit=1)
            if not ready:
                return None
            current = self._checkpoints[ready[0].run_ref]
            claimed = current.model_copy(
                deep=True,
                update={
                    "status": CheckpointStatus.RUNNING,
                    "lease_owner": str(worker_ref).strip(),
                    "lease_until": timestamp + timedelta(seconds=lease_seconds),
                    "resume_at": None,
                    "next_attempt_at": None,
                    "revision": current.revision + 1,
                    "updated_at": timestamp,
                },
            )
            self._checkpoints[claimed.run_ref] = claimed
            return claimed.model_copy(deep=True)

    def renew_lease(
        self,
        run_ref: str,
        *,
        worker_ref: str,
        expected_revision: int,
        now: datetime,
        lease_seconds: int,
    ) -> WorkflowCheckpoint:
        if lease_seconds < 1:
            raise ValueError("lease_seconds must be positive")
        worker = str(worker_ref).strip()
        if not worker:
            raise ValueError("worker_ref is required")
        timestamp = _utc_now(now)
        clean_run_ref = str(run_ref).strip()
        with self._lock:
            current = self._checkpoints.get(clean_run_ref)
            if current is None:
                raise CheckpointConflictError(
                    f"checkpoint does not exist: {clean_run_ref}"
                )
            if current.revision != expected_revision:
                raise CheckpointConflictError(
                    f"checkpoint {clean_run_ref} revision is {current.revision}, "
                    f"expected {expected_revision}"
                )
            if (
                current.status != CheckpointStatus.RUNNING
                or current.lease_owner != worker
                or current.lease_until is None
            ):
                raise CheckpointConflictError(
                    f"checkpoint {clean_run_ref} lease is not owned by {worker}"
                )
            if current.lease_until <= timestamp:
                raise CheckpointConflictError(
                    f"checkpoint {clean_run_ref} lease has expired"
                )
            renewed = current.model_copy(
                deep=True,
                update={
                    "lease_until": timestamp + timedelta(seconds=lease_seconds),
                    "revision": current.revision + 1,
                    "updated_at": timestamp,
                },
            )
            self._checkpoints[clean_run_ref] = renewed
            return renewed.model_copy(deep=True)

    def record_event(self, event: WorkflowEventEnvelope) -> bool:
        key = (event.project_ref, event.event_id)
        fingerprint = event.fingerprint()
        with self._lock:
            prior = self._event_ids.get(key)
            if prior is not None and prior != fingerprint:
                raise CheckpointConflictError(
                    f"event_id was reused with a different payload: {event.event_id}"
                )
            if prior is not None:
                return False
            self._event_ids[key] = fingerprint
            return True


@contextmanager
def _exclusive_file_lock(path: Path):
    lock_path = path.with_suffix(path.suffix + ".lock")
    deadline = time.monotonic() + 5.0
    descriptor: int | None = None
    while descriptor is None:
        if lock_path.is_symlink():
            raise CheckpointPersistenceError(
                f"refusing symlinked lock file: {lock_path}"
            )
        try:
            descriptor = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            try:
                if time.time() - lock_path.stat().st_mtime > 30:
                    lock_path.unlink(missing_ok=True)
                    continue
            except OSError:
                pass
            if time.monotonic() >= deadline:
                raise CheckpointPersistenceError("local checkpoint store is busy")
            time.sleep(0.05)
    try:
        os.write(descriptor, str(os.getpid()).encode("ascii"))
        os.fsync(descriptor)
        yield
    finally:
        os.close(descriptor)
        lock_path.unlink(missing_ok=True)


def _atomic_write_private(path: Path, content: str) -> None:
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise CheckpointPersistenceError(f"unsafe local checkpoint target: {path}")
    temporary = path.with_name(
        f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp"
    )
    if temporary.is_symlink():
        raise CheckpointPersistenceError(
            f"unsafe local checkpoint temporary: {temporary}"
        )
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        if hasattr(os, "O_DIRECTORY"):
            directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)
        raise


class JsonFileCheckpointStore(InMemoryCheckpointStore):
    """Atomic local persistence for durable development and single-host workers."""

    def __init__(
        self,
        directory: str | Path,
        *,
        scope_fingerprint: str | None = None,
    ) -> None:
        super().__init__()
        requested = Path(directory).expanduser()
        if requested.is_symlink():
            raise CheckpointPersistenceError(
                f"refusing symlinked checkpoint directory: {requested}"
            )
        self.directory = requested.resolve()
        self.directory.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.directory, 0o700)
        except OSError:
            pass
        normalized_scope = str(scope_fingerprint or "").strip().lower() or None
        if normalized_scope is not None and not _SCOPE_FINGERPRINT_RE.fullmatch(
            normalized_scope
        ):
            raise ValueError("scope_fingerprint must be a lowercase SHA-256 value")
        self.scope_fingerprint = normalized_scope
        self._store_lock_path = self.directory / ".store"
        self._load()

    def _path(self, run_ref: str) -> Path:
        digest = hashlib.sha256(run_ref.encode("utf-8")).hexdigest()
        return self.directory / f"checkpoint-{digest}.json"

    @property
    def _events_path(self) -> Path:
        return self.directory / "events.json"

    def _validate_scope(self, checkpoint: WorkflowCheckpoint) -> None:
        if checkpoint.scope_fingerprint != self.scope_fingerprint:
            raise CheckpointScopeError(
                "local checkpoint scope does not match the authenticated tenant/company"
            )

    def _read_checkpoint(self, path: Path) -> WorkflowCheckpoint | None:
        if path.is_symlink():
            raise CheckpointPersistenceError(f"refusing symlinked checkpoint: {path}")
        try:
            checkpoint = WorkflowCheckpoint.model_validate_json(
                path.read_text(encoding="utf-8")
            )
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as exc:
            raise CheckpointPersistenceError(
                f"cannot load checkpoint: {path.name}"
            ) from exc
        self._validate_scope(checkpoint)
        return checkpoint

    def _load(self) -> None:
        self._checkpoints = {}
        for path in self.directory.glob("checkpoint-*.json"):
            checkpoint = self._read_checkpoint(path)
            if checkpoint is not None:
                self._checkpoints[checkpoint.run_ref] = checkpoint
        try:
            payload = json.loads(self._events_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            payload = None
        except (OSError, ValueError, TypeError) as exc:
            raise CheckpointPersistenceError(
                "cannot load local workflow event ledger"
            ) from exc
        if payload is None:
            rows = []
        elif isinstance(payload, list) and self.scope_fingerprint is None:
            rows = payload
        elif isinstance(payload, dict):
            if payload.get("scope_fingerprint") != self.scope_fingerprint:
                raise CheckpointScopeError("local event ledger scope does not match")
            rows = payload.get("events") or []
        else:
            raise CheckpointScopeError(
                "legacy unscoped event ledger is not accepted in scoped storage"
            )
        self._event_ids = {
            (str(row[0]), str(row[1])): str(row[2])
            for row in rows
            if isinstance(row, list) and len(row) == 3
        }

    def _write_checkpoint(self, checkpoint: WorkflowCheckpoint) -> None:
        path = self._path(checkpoint.run_ref)
        self._validate_scope(checkpoint)
        _atomic_write_private(
            path,
            json.dumps(checkpoint.to_dict(), indent=2, sort_keys=True) + "\n",
        )

    def save(
        self,
        checkpoint: WorkflowCheckpoint,
        *,
        expected_revision: int | None,
    ) -> WorkflowCheckpoint:
        with self._lock:
            with _exclusive_file_lock(self._store_lock_path):
                self._load()
                stored = super().save(checkpoint, expected_revision=expected_revision)
                self._write_checkpoint(stored)
                return stored

    def get(self, run_ref: str) -> WorkflowCheckpoint | None:
        with self._lock:
            checkpoint = self._read_checkpoint(self._path(str(run_ref).strip()))
            if checkpoint is None:
                self._checkpoints.pop(str(run_ref).strip(), None)
                return None
            self._checkpoints[checkpoint.run_ref] = checkpoint
            return checkpoint.model_copy(deep=True)

    def list_ready(
        self,
        project_ref: str,
        *,
        now: datetime,
        limit: int = 100,
    ) -> list[WorkflowCheckpoint]:
        with self._lock:
            self._load()
            return super().list_ready(project_ref, now=now, limit=limit)

    def claim_next(
        self,
        project_ref: str,
        *,
        worker_ref: str,
        now: datetime,
        lease_seconds: int,
    ) -> WorkflowCheckpoint | None:
        with self._lock:
            with _exclusive_file_lock(self._store_lock_path):
                self._load()
                claimed = super().claim_next(
                    project_ref,
                    worker_ref=worker_ref,
                    now=now,
                    lease_seconds=lease_seconds,
                )
                if claimed is not None:
                    self._write_checkpoint(claimed)
                return claimed

    def renew_lease(
        self,
        run_ref: str,
        *,
        worker_ref: str,
        expected_revision: int,
        now: datetime,
        lease_seconds: int,
    ) -> WorkflowCheckpoint:
        with self._lock:
            with _exclusive_file_lock(self._store_lock_path):
                self._load()
                renewed = super().renew_lease(
                    run_ref,
                    worker_ref=worker_ref,
                    expected_revision=expected_revision,
                    now=now,
                    lease_seconds=lease_seconds,
                )
                self._write_checkpoint(renewed)
                return renewed

    def record_event(self, event: WorkflowEventEnvelope) -> bool:
        with self._lock:
            with _exclusive_file_lock(self._store_lock_path):
                self._load()
                accepted = super().record_event(event)
                if not accepted:
                    return False
                payload = {
                    "schema": LOCAL_EVENT_LEDGER_SCHEMA,
                    "scope_fingerprint": self.scope_fingerprint,
                    "events": sorted(
                        [
                            list(key) + [fingerprint]
                            for key, fingerprint in self._event_ids.items()
                        ]
                    ),
                }
                _atomic_write_private(
                    self._events_path,
                    json.dumps(payload, indent=2, sort_keys=True) + "\n",
                )
                return True


class HostedCheckpointStore:
    """Checkpoint store backed by the authenticated Lightbulb control plane."""

    def __init__(
        self,
        client: Any,
        project_id: str | UUID,
        *,
        scope_fingerprint: str | None = None,
    ) -> None:
        self.client = client
        self.project_id = str(project_id)
        normalized_scope = str(scope_fingerprint or "").strip().lower() or None
        if normalized_scope is not None and not _SCOPE_FINGERPRINT_RE.fullmatch(
            normalized_scope
        ):
            raise ValueError("scope_fingerprint must be a lowercase SHA-256 value")
        self.scope_fingerprint = normalized_scope

    @staticmethod
    def _parse_checkpoint(value: Mapping[str, Any]) -> WorkflowCheckpoint:
        payload = dict(value)
        # Spring's atomic claim clears its indexed resume_at column but retains
        # the pre-claim JSON state. A claimed running row can therefore carry a
        # stale retry timestamp until the worker's next revision save.
        if (
            payload.get("status") == CheckpointStatus.RUNNING.value
            and payload.get("next_attempt_at") is not None
            and payload.get("lease_owner")
            and payload.get("lease_until")
        ):
            payload["next_attempt_at"] = None
        return WorkflowCheckpoint.model_validate(payload)

    def save(
        self,
        checkpoint: WorkflowCheckpoint,
        *,
        expected_revision: int | None,
    ) -> WorkflowCheckpoint:
        value = self.client.put_sdk_project_checkpoint(
            self.project_id,
            checkpoint.run_ref,
            checkpoint.to_dict(),
            expected_revision=expected_revision,
        )
        return self._parse_checkpoint(value)

    def get(self, run_ref: str) -> WorkflowCheckpoint | None:
        value = self.client.get_sdk_project_checkpoint(self.project_id, run_ref)
        return self._parse_checkpoint(value) if value else None

    def list_ready(
        self,
        project_ref: str,
        *,
        now: datetime,
        limit: int = 100,
    ) -> list[WorkflowCheckpoint]:
        values = self.client.list_ready_sdk_project_checkpoints(
            self.project_id,
            ready_at=_utc_now(now).isoformat(),
            limit=limit,
        )
        return [self._parse_checkpoint(value) for value in values]

    def claim_next(
        self,
        project_ref: str,
        *,
        worker_ref: str,
        now: datetime,
        lease_seconds: int,
    ) -> WorkflowCheckpoint | None:
        value = self.client.claim_sdk_project_checkpoint(
            self.project_id,
            worker_ref=worker_ref,
            ready_at=_utc_now(now).isoformat(),
            lease_seconds=lease_seconds,
        )
        if not value:
            return None
        return self._parse_checkpoint({**value, "next_attempt_at": None})

    def renew_lease(
        self,
        run_ref: str,
        *,
        worker_ref: str,
        expected_revision: int,
        now: datetime,
        lease_seconds: int,
    ) -> WorkflowCheckpoint:
        # The hosted service intentionally uses its own clock for the renewal.
        value = self.client.renew_sdk_project_checkpoint_lease(
            self.project_id,
            run_ref,
            worker_ref=worker_ref,
            expected_revision=expected_revision,
            lease_seconds=lease_seconds,
        )
        return self._parse_checkpoint(value)

    def record_event(self, event: WorkflowEventEnvelope) -> bool:
        value = self.client.ingest_sdk_project_event(self.project_id, event.to_dict())
        return bool(value.get("accepted"))


class _CheckpointLeaseHeartbeat:
    """Renew one running checkpoint while its synchronous primitive is active."""

    def __init__(
        self,
        store: WorkflowCheckpointStore,
        checkpoint: WorkflowCheckpoint,
        *,
        lease_seconds: int,
    ) -> None:
        if lease_seconds < 1:
            raise ValueError("lease_seconds must be positive")
        if (
            checkpoint.status != CheckpointStatus.RUNNING
            or not checkpoint.lease_owner
            or checkpoint.lease_until is None
        ):
            raise CheckpointConflictError(
                f"checkpoint {checkpoint.run_ref} has no renewable running lease"
            )
        self._store = store
        self._checkpoint = checkpoint
        self._lease_seconds = lease_seconds
        self._interval_seconds = min(
            _MAX_LEASE_HEARTBEAT_INTERVAL_SECONDS,
            max(
                _MIN_LEASE_HEARTBEAT_INTERVAL_SECONDS,
                lease_seconds / 3.0,
            ),
        )
        self._stop = threading.Event()
        self._state_lock = threading.Lock()
        self._failure: Exception | None = None
        self._thread = threading.Thread(
            target=self._run,
            name=f"lightbulb-lease-{checkpoint.run_ref[:40]}",
            daemon=True,
        )

    def start(self) -> None:
        self._thread.start()

    def finish(self) -> WorkflowCheckpoint:
        self._stop.set()
        self._thread.join()
        with self._state_lock:
            checkpoint = self._checkpoint
            failure = self._failure
        if failure is None:
            return checkpoint
        if isinstance(failure, CheckpointConflictError):
            raise failure
        raise CheckpointPersistenceError(
            f"checkpoint {checkpoint.run_ref} lease heartbeat failed"
        ) from failure

    def _run(self) -> None:
        while not self._stop.wait(self._interval_seconds):
            with self._state_lock:
                checkpoint = self._checkpoint
            try:
                renewed = self._store.renew_lease(
                    checkpoint.run_ref,
                    worker_ref=str(checkpoint.lease_owner),
                    expected_revision=checkpoint.revision,
                    now=_utc_now(),
                    lease_seconds=self._lease_seconds,
                )
            except Exception as exc:
                with self._state_lock:
                    self._failure = exc
                return
            with self._state_lock:
                self._checkpoint = renewed


class DurableProjectRuntime:
    """Execute a :class:`ProjectRuntime` with revisioned durable state."""

    def __init__(
        self,
        runtime: ProjectRuntime,
        checkpoint_store: WorkflowCheckpointStore,
    ) -> None:
        self.runtime = runtime
        self.store = checkpoint_store
        self.project = runtime.project
        self.scope_fingerprint = getattr(checkpoint_store, "scope_fingerprint", None)

    def get_checkpoint(self, run_ref: str) -> WorkflowCheckpoint | None:
        checkpoint = self.store.get(run_ref)
        if checkpoint is None:
            return None
        return self._validate_checkpoint_compatibility(checkpoint)

    def start_workflow(
        self,
        workflow_key: str,
        inputs: Mapping[str, Any],
        *,
        preview_only: bool | None = None,
        approval_refs: Mapping[str, str] | None = None,
        connector_account_refs: Mapping[str, str] | None = None,
        run_ref: str | None = None,
        tenant_ref: str = "authenticated",
        company_ref: str = "selected",
        actor_ref: str | None = None,
    ) -> ProjectWorkflowRun:
        checkpoint = self._create_checkpoint(
            workflow_key,
            inputs,
            status=CheckpointStatus.RUNNING,
            preview_only=preview_only,
            approval_refs=approval_refs,
            connector_account_refs=connector_account_refs,
            run_ref=run_ref,
        )
        return self._execute(
            checkpoint,
            tenant_ref=tenant_ref,
            company_ref=company_ref,
            actor_ref=actor_ref,
        )

    def schedule_workflow(
        self,
        workflow_key: str,
        inputs: Mapping[str, Any],
        *,
        resume_at: datetime,
        preview_only: bool | None = None,
        approval_refs: Mapping[str, str] | None = None,
        connector_account_refs: Mapping[str, str] | None = None,
        run_ref: str | None = None,
    ) -> WorkflowCheckpoint:
        when = _utc_now(resume_at)
        return self._create_checkpoint(
            workflow_key,
            inputs,
            status=CheckpointStatus.SCHEDULED,
            preview_only=preview_only,
            approval_refs=approval_refs,
            connector_account_refs=connector_account_refs,
            run_ref=run_ref,
            resume_at=when,
        )

    def dispatch_workflow(
        self,
        workflow_key: str,
        inputs: Mapping[str, Any],
        *,
        preview_only: bool | None = None,
        approval_refs: Mapping[str, str] | None = None,
        connector_account_refs: Mapping[str, str] | None = None,
        run_ref: str | None = None,
        trigger_event_id: str | None = None,
    ) -> WorkflowCheckpoint:
        return self._create_checkpoint(
            workflow_key,
            inputs,
            status=CheckpointStatus.DISPATCHED,
            preview_only=preview_only,
            approval_refs=approval_refs,
            connector_account_refs=connector_account_refs,
            run_ref=run_ref,
            trigger_event_id=trigger_event_id,
        )

    def resume_workflow(
        self,
        run_ref: str,
        *,
        input_updates: Mapping[str, Any] | None = None,
        approval_refs: Mapping[str, str] | None = None,
        connector_account_refs: Mapping[str, str] | None = None,
        recovery_attestations: Mapping[
            str,
            PrimitiveRecoveryAttestation | Mapping[str, Any],
        ]
        | None = None,
        tenant_ref: str = "authenticated",
        company_ref: str = "selected",
        actor_ref: str | None = None,
    ) -> ProjectWorkflowRun:
        checkpoint = self._require_checkpoint(run_ref)
        if checkpoint.status not in {
            CheckpointStatus.PENDING_APPROVAL,
            CheckpointStatus.NEEDS_INPUT,
            CheckpointStatus.WAITING_FOR_RECOVERY,
            CheckpointStatus.BLOCKED,
            CheckpointStatus.FAILED,
        }:
            raise ValueError(
                f"checkpoint {run_ref} is not resumable from {checkpoint.status.value}"
            )
        incoming_accounts = _normalized_connector_account_refs(connector_account_refs)
        for key, account_ref in incoming_accounts.items():
            existing_account_ref = checkpoint.connector_account_refs.get(key)
            if existing_account_ref is not None and existing_account_ref != account_ref:
                raise ValueError(
                    f"connector account binding {key!r} cannot be retargeted mid-run"
                )
        merged_accounts = {
            **checkpoint.connector_account_refs,
            **incoming_accounts,
        }

        incoming_attestations = _normalized_recovery_attestations(
            recovery_attestations
        )
        if incoming_attestations:
            raise ValueError(
                "caller-supplied recovery attestations cannot authorize replay; "
                "settle the ambiguous operation through the hosted connector authority"
            )
        unresolved_receipts = self._checkpoint_unresolved_receipts(checkpoint)
        if unresolved_receipts:
            raise ValueError(
                "the generic durable runtime never replays an unresolved external "
                "operation; settle it through the hosted connector journal and "
                "continue from its authoritative receipt"
            )

        reset_active_visit = bool(
            checkpoint.status == CheckpointStatus.FAILED
            and not unresolved_receipts
        )
        checkpoint = checkpoint.model_copy(
            deep=True,
            update={
                "workflow_inputs": {
                    **checkpoint.workflow_inputs,
                    **dict(input_updates or {}),
                },
                "approval_refs": {
                    **checkpoint.approval_refs,
                    **dict(approval_refs or {}),
                },
                "connector_account_refs": merged_accounts,
                "recovery_attestations": checkpoint.recovery_attestations,
                "status": CheckpointStatus.RUNNING,
                "blockers": [],
                "resume_at": None,
                "next_attempt_at": None,
                "active_step_id": (
                    None if reset_active_visit else checkpoint.active_step_id
                ),
                "active_attempt_key": (
                    None if reset_active_visit else checkpoint.active_attempt_key
                ),
                "lease_owner": None,
                "lease_until": None,
            },
        )
        return self._execute(
            checkpoint,
            tenant_ref=tenant_ref,
            company_ref=company_ref,
            actor_ref=actor_ref,
        )

    def ingest_event(
        self,
        event: WorkflowEventEnvelope | Mapping[str, Any],
        *,
        preview_only: bool | None = None,
        connector_account_refs: Mapping[str, str] | None = None,
    ) -> list[WorkflowCheckpoint]:
        envelope = (
            event
            if isinstance(event, WorkflowEventEnvelope)
            else WorkflowEventEnvelope.model_validate(event)
        )
        if envelope.project_ref != self.project.project_ref:
            raise ValueError("event project_ref does not match this runtime")
        self.store.record_event(envelope)
        matches = [
            workflow
            for workflow in self.project.workflows
            if workflow.trigger_event == envelope.event_type
        ]
        checkpoints: list[WorkflowCheckpoint] = []
        for workflow in matches:
            event_run_ref = self._event_run_ref(envelope.event_id, workflow.key)
            existing = self.store.get(event_run_ref)
            if existing is not None:
                checkpoints.append(
                    self._validate_checkpoint_compatibility(existing)
                )
                continue
            try:
                checkpoints.append(
                    self.dispatch_workflow(
                        workflow.key,
                        envelope.payload,
                        preview_only=preview_only,
                        connector_account_refs=connector_account_refs,
                        run_ref=event_run_ref,
                        trigger_event_id=envelope.event_id,
                    )
                )
            except CheckpointConflictError:
                existing = self.store.get(event_run_ref)
                if existing is None:
                    raise
                checkpoints.append(
                    self._validate_checkpoint_compatibility(existing)
                )
            except LightbulbError as exc:
                if exc.status_code != 409:
                    raise
                existing = self.store.get(event_run_ref)
                if existing is None:
                    raise
                checkpoints.append(
                    self._validate_checkpoint_compatibility(existing)
                )
        return checkpoints

    def run_next(
        self,
        *,
        worker_ref: str,
        now: datetime | None = None,
        lease_seconds: int = 60,
        tenant_ref: str = "authenticated",
        company_ref: str = "selected",
        actor_ref: str | None = None,
    ) -> ProjectWorkflowRun | None:
        ready_at = _utc_now(now)
        failure_time_override = ready_at if now is not None else None
        checkpoint = self.store.claim_next(
            self.project.project_ref,
            worker_ref=worker_ref,
            now=ready_at,
            lease_seconds=lease_seconds,
        )
        if checkpoint is None:
            return None
        return self._execute(
            checkpoint,
            tenant_ref=tenant_ref,
            company_ref=company_ref,
            actor_ref=actor_ref,
            save_running=False,
            execution_time=ready_at,
            failure_time_override=failure_time_override,
            lease_seconds=lease_seconds,
        )

    def run_ready(
        self,
        *,
        worker_ref: str,
        now: datetime | None = None,
        limit: int = 100,
        lease_seconds: int = 60,
    ) -> list[ProjectWorkflowRun]:
        runs: list[ProjectWorkflowRun] = []
        for _ in range(max(0, limit)):
            run = self.run_next(
                worker_ref=worker_ref,
                now=now,
                lease_seconds=lease_seconds,
            )
            if run is None:
                break
            runs.append(run)
        return runs

    def _create_checkpoint(
        self,
        workflow_key: str,
        inputs: Mapping[str, Any],
        *,
        status: CheckpointStatus,
        preview_only: bool | None,
        approval_refs: Mapping[str, str] | None,
        connector_account_refs: Mapping[str, str] | None,
        run_ref: str | None,
        resume_at: datetime | None = None,
        trigger_event_id: str | None = None,
    ) -> WorkflowCheckpoint:
        workflow = self._workflow(workflow_key)
        inline_execution = status == CheckpointStatus.RUNNING
        created_at = _utc_now()
        checkpoint = WorkflowCheckpoint(
            run_ref=str(run_ref or f"run-{uuid4()}").strip(),
            project_ref=self.project.project_ref,
            scope_fingerprint=self.scope_fingerprint,
            hosted_project_id=self.project.hosted_project_id,
            project_version=self.project.version,
            workflow_key=workflow.key,
            workflow_version=workflow.version,
            workflow_identity_sha256=_workflow_identity_sha256(
                workflow,
                execution_policy=self.project.policy,
            ),
            primitive_versions=self._primitive_versions(workflow),
            status=status,
            workflow_inputs=dict(inputs),
            preview_only=(
                self.project.policy.default_preview_only
                if preview_only is None
                else preview_only
            ),
            approval_refs=dict(approval_refs or {}),
            connector_account_refs=dict(connector_account_refs or {}),
            current_step=workflow.entry_step,
            resume_at=resume_at,
            trigger_event_id=trigger_event_id,
            lease_owner=f"inline-{uuid4()}" if inline_execution else None,
            lease_until=(
                created_at + timedelta(seconds=_INLINE_LEASE_SECONDS)
                if inline_execution
                else None
            ),
            created_at=created_at,
            updated_at=created_at,
        )
        return self.store.save(checkpoint, expected_revision=None)

    def _execute(
        self,
        checkpoint: WorkflowCheckpoint,
        *,
        tenant_ref: str,
        company_ref: str,
        actor_ref: str | None,
        save_running: bool = True,
        execution_time: datetime | None = None,
        failure_time_override: datetime | None = None,
        lease_seconds: int = _INLINE_LEASE_SECONDS,
    ) -> ProjectWorkflowRun:
        checkpoint = self._validate_checkpoint_compatibility(checkpoint)
        attempt_time = _utc_now(execution_time)
        validation = self.runtime.validate()
        if not validation.valid:
            blockers = [
                PrimitiveBlocker(code=issue.code, message=issue.message)
                for issue in validation.issues
                if issue.severity == ProjectValidationSeverity.ERROR
            ]
            return self._finish(
                checkpoint,
                CheckpointStatus.BLOCKED,
                blockers=blockers,
                preserve_active=checkpoint.active_step_id is not None,
            )
        workflow = self._workflow(checkpoint.workflow_key)
        if save_running:
            lease_owner = checkpoint.lease_owner or f"inline-{uuid4()}"
            lease_until = checkpoint.lease_until or (
                attempt_time + timedelta(seconds=_INLINE_LEASE_SECONDS)
            )
            checkpoint = self.store.save(
                checkpoint.model_copy(
                    deep=True,
                    update={
                        "status": CheckpointStatus.RUNNING,
                        "resume_at": None,
                        "next_attempt_at": None,
                        "lease_owner": lease_owner,
                        "lease_until": lease_until,
                    },
                ),
                expected_revision=checkpoint.revision,
            )
        step_by_id = {step.id: step for step in workflow.steps}
        event_log = list(checkpoint.events)
        step_runs = list(checkpoint.step_runs)
        visits = dict(checkpoint.visits)
        current_step = checkpoint.current_step or workflow.entry_step
        last_event = checkpoint.last_event
        saw_preview = checkpoint.saw_preview
        completed_results: Dict[str, PrimitiveExecutionResult[Any]] = {
            run.step_id: run.result
            for run in step_runs
            if run.status
            in {PrimitiveExecutionStatus.COMPLETED, PrimitiveExecutionStatus.PREVIEW}
            and not run.result.unresolved_operation_receipts()
        }
        session = self.runtime.open_primitive_run(
            run_ref=checkpoint.run_ref,
            preview_only=checkpoint.preview_only,
            approval_refs=checkpoint.approval_refs,
            connector_account_refs=checkpoint.connector_account_refs,
            tenant_ref=tenant_ref,
            company_ref=company_ref,
            actor_ref=actor_ref,
            workflow_key=workflow.key,
            source="lightbulb_durable_runtime",
        )

        while (
            sum(visits.values()) < self.project.policy.max_workflow_steps
            or checkpoint.active_step_id == current_step
        ):
            continuing_attempt = bool(
                checkpoint.active_step_id == current_step
                and checkpoint.active_attempt_key
            )
            if continuing_attempt:
                attempt_key = str(checkpoint.active_attempt_key)
            else:
                visits[current_step] = visits.get(current_step, 0) + 1
                attempt_key = f"{current_step}:{visits[current_step]}"
            if visits[current_step] > self.project.policy.max_step_visits:
                return self._finish(
                    checkpoint.model_copy(
                        deep=True,
                        update={
                            "step_runs": step_runs,
                            "events": event_log,
                            "visits": visits,
                            "current_step": current_step,
                            "last_event": last_event,
                            "saw_preview": saw_preview,
                        },
                    ),
                    CheckpointStatus.BLOCKED,
                    blockers=[
                        PrimitiveBlocker(
                            code="workflow_loop_limit",
                            message="A workflow step exceeded the project's visit limit.",
                        )
                    ],
                )
            step = step_by_id[current_step]
            try:
                step_input = _step_inputs(
                    step,
                    workflow_inputs=checkpoint.workflow_inputs,
                    step_results=completed_results,
                    last_event=last_event,
                )
            except BindingResolutionError as exc:
                return self._finish(
                    checkpoint.model_copy(
                        deep=True,
                        update={
                            "step_runs": step_runs,
                            "events": event_log,
                            "visits": visits,
                            "current_step": current_step,
                            "last_event": last_event,
                            "saw_preview": saw_preview,
                        },
                    ),
                    CheckpointStatus.NEEDS_INPUT,
                    blockers=[
                        PrimitiveBlocker(
                            code="binding_resolution_failed", message=str(exc)
                        )
                    ],
                    preserve_active=checkpoint.active_step_id is not None,
                )
            step_visit = visits[current_step]
            prior_attempts = checkpoint.step_attempts.get(attempt_key, 0)
            prior_invocations = checkpoint.step_invocations.get(attempt_key, 0)
            active_runs = [
                step_run
                for step_run in step_runs
                if step_run.step_id == step.id
                and step_run.step_visit == step_visit
            ]
            last_recorded_invocation = max(
                (step_run.invocation for step_run in active_runs),
                default=0,
            )
            interrupted_invocation = (
                continuing_attempt
                and prior_invocations > last_recorded_invocation
            )
            latest_active_run = active_runs[-1] if active_runs else None
            prior_retryable_failure = bool(
                latest_active_run is not None
                and self._is_retryable_failure(latest_active_run.result)
            )
            advance_attempt = bool(
                continuing_attempt
                and (interrupted_invocation or prior_retryable_failure)
            )
            if not continuing_attempt or prior_attempts == 0:
                attempt_number = 1
            elif advance_attempt:
                attempt_number = prior_attempts + 1
            else:
                # Approval and required-input resumptions remain the same
                # logical attempt and preserve connector idempotency.
                attempt_number = prior_attempts

            if attempt_number > self.project.policy.retry_policy.max_attempts:
                prior_result = next(
                    (
                        step_run.result
                        for step_run in reversed(step_runs)
                        if step_run.step_id == step.id
                        and step_run.step_visit == step_visit
                        and step_run.status == PrimitiveExecutionStatus.FAILED
                    ),
                    PrimitiveExecutionResult[Any](
                        status=PrimitiveExecutionStatus.FAILED,
                        primitive_ref=step.primitive_ref,
                        primitive_version=self.runtime.registry.get(
                            step.primitive_ref
                        ).version,
                        summary="Primitive attempt recovery exhausted its retry budget.",
                        blockers=[
                            PrimitiveBlocker(
                                code="primitive_attempt_interrupted",
                                message=(
                                    "A prior primitive attempt ended before a "
                                    "terminal checkpoint was committed."
                                ),
                                retryable=True,
                            )
                        ],
                        retryable=True,
                    ),
                )
                return self._schedule_or_exhaust_retry(
                    checkpoint.model_copy(
                        deep=True,
                        update={
                            "step_runs": step_runs,
                            "events": event_log,
                            "visits": visits,
                            "current_step": current_step,
                            "last_event": last_event,
                            "saw_preview": saw_preview,
                        },
                    ),
                    result=prior_result,
                    step_id=step.id,
                    attempt_key=attempt_key,
                    attempt_number=prior_attempts,
                    failure_time=_utc_now(failure_time_override),
                )

            step_attempts = dict(checkpoint.step_attempts)
            step_attempts[attempt_key] = attempt_number
            step_invocations = dict(checkpoint.step_invocations)
            invocation_number = prior_invocations + 1
            step_invocations[attempt_key] = invocation_number
            checkpoint = self.store.save(
                checkpoint.model_copy(
                    deep=True,
                    update={
                        "status": CheckpointStatus.RUNNING,
                        "step_runs": step_runs,
                        "events": event_log,
                        "visits": visits,
                        "current_step": current_step,
                        "last_event": last_event,
                        "saw_preview": saw_preview,
                        "blockers": [],
                        "resume_at": None,
                        "next_attempt_at": None,
                        "active_step_id": step.id,
                        "active_attempt_key": attempt_key,
                        "step_attempts": step_attempts,
                        "step_invocations": step_invocations,
                    },
                ),
                expected_revision=checkpoint.revision,
            )
            heartbeat = _CheckpointLeaseHeartbeat(
                self.store,
                checkpoint,
                lease_seconds=lease_seconds,
            )
            heartbeat.start()
            try:
                try:
                    result = session.execute(
                        PrimitiveCall(
                            primitive_ref=step.primitive_ref,
                            inputs=step_input,
                            step_id=step.id,
                            execution_ref=(
                                None
                                if checkpoint.legacy_step_idempotency_mode
                                else attempt_key
                            ),
                        )
                    )
                except Exception:
                    result = PrimitiveExecutionResult[Any](
                        status=PrimitiveExecutionStatus.FAILED,
                        primitive_ref=step.primitive_ref,
                        primitive_version=self.runtime.registry.get(
                            step.primitive_ref
                        ).version,
                        summary="Primitive execution was interrupted.",
                        blockers=[
                            PrimitiveBlocker(
                                code="primitive_exception",
                                message=(
                                    "Primitive execution was interrupted by an "
                                    "internal exception."
                                ),
                                retryable=True,
                            )
                        ],
                        retryable=True,
                    )
            finally:
                checkpoint = heartbeat.finish()
            result, unresolved_recovery = _workflow_result_with_recovery_gate(result)
            event_log.extend(result.events)
            step_runs.append(
                ProjectWorkflowStepRun(
                    step_id=step.id,
                    primitive_ref=step.primitive_ref,
                    step_visit=step_visit,
                    attempt=attempt_number,
                    invocation=invocation_number,
                    status=result.status,
                    result=result,
                )
            )
            if result.status == PrimitiveExecutionStatus.PREVIEW:
                saw_preview = True
            if result.status not in {
                PrimitiveExecutionStatus.COMPLETED,
                PrimitiveExecutionStatus.PREVIEW,
            }:
                recovery_required = bool(unresolved_recovery)
                retryable_failure = self._is_retryable_failure(result)
                paused_last_event = (
                    last_event
                    if retryable_failure
                    else result.events[-1]
                    if result.events
                    else last_event
                )
                paused_checkpoint = checkpoint.model_copy(
                    deep=True,
                    update={
                        "step_runs": step_runs,
                        "events": event_log,
                        "visits": visits,
                        "current_step": current_step,
                        "last_event": paused_last_event,
                        "saw_preview": saw_preview,
                    },
                )
                if retryable_failure:
                    return self._schedule_or_exhaust_retry(
                        paused_checkpoint,
                        result=result,
                        step_id=step.id,
                        attempt_key=attempt_key,
                        attempt_number=attempt_number,
                        failure_time=_utc_now(failure_time_override),
                    )
                return self._finish(
                    paused_checkpoint,
                    (
                        CheckpointStatus.WAITING_FOR_RECOVERY
                        if recovery_required
                        else CheckpointStatus(result.status.value)
                    ),
                    blockers=(
                        result.blockers
                        if not recovery_required
                        or any(
                            blocker.code == "operation_recovery_required"
                            for blocker in result.blockers
                        )
                        else [
                            *result.blockers,
                            PrimitiveBlocker(
                                code="operation_recovery_required",
                                message=(
                                    "Resolve every ambiguous operation receipt before "
                                    "continuing the workflow."
                                ),
                            ),
                        ]
                    ),
                    preserve_active=recovery_required
                    or result.status
                    in {
                        PrimitiveExecutionStatus.PENDING_APPROVAL,
                        PrimitiveExecutionStatus.NEEDS_INPUT,
                        PrimitiveExecutionStatus.BLOCKED,
                    },
                )
            if result.events:
                last_event = result.events[-1]
            completed_results[step.id] = result
            target = next(
                (
                    step.routes[event.type]
                    for event in result.events
                    if event.type in step.routes
                ),
                None,
            )
            target = target or step.next_step
            if not target or target == _END:
                return self._finish(
                    checkpoint.model_copy(
                        deep=True,
                        update={
                            "step_runs": step_runs,
                            "events": event_log,
                            "visits": visits,
                            "current_step": None,
                            "last_event": last_event,
                            "saw_preview": saw_preview,
                            "active_step_id": None,
                            "active_attempt_key": None,
                        },
                    ),
                    CheckpointStatus.PREVIEW
                    if saw_preview
                    else CheckpointStatus.COMPLETED,
                )
            current_step = target
            checkpoint = self.store.save(
                checkpoint.model_copy(
                    deep=True,
                    update={
                        "status": CheckpointStatus.RUNNING,
                        "step_runs": step_runs,
                        "events": event_log,
                        "visits": visits,
                        "current_step": current_step,
                        "last_event": last_event,
                        "saw_preview": saw_preview,
                        "blockers": [],
                        "active_step_id": None,
                        "active_attempt_key": None,
                        "next_attempt_at": None,
                    },
                ),
                expected_revision=checkpoint.revision,
            )

        return self._finish(
            checkpoint.model_copy(
                deep=True,
                update={
                    "step_runs": step_runs,
                    "events": event_log,
                    "visits": visits,
                    "current_step": current_step,
                    "last_event": last_event,
                    "saw_preview": saw_preview,
                },
            ),
            CheckpointStatus.BLOCKED,
            blockers=[
                PrimitiveBlocker(
                    code="workflow_step_limit",
                    message="Workflow exceeded the project's maximum step count.",
                )
            ],
        )

    @staticmethod
    def _checkpoint_unresolved_receipts(
        checkpoint: WorkflowCheckpoint,
    ) -> list[PrimitiveOperationReceipt]:
        active_step_id = checkpoint.active_step_id
        active_visit = (
            checkpoint.visits.get(active_step_id)
            if active_step_id is not None
            else None
        )
        for step_run in reversed(checkpoint.step_runs):
            if active_step_id is not None and step_run.step_id != active_step_id:
                continue
            if active_visit is not None and step_run.step_visit != active_visit:
                continue
            return _authoritative_recovery_receipts(step_run.result)
        return []

    @staticmethod
    def _is_retryable_failure(result: PrimitiveExecutionResult[Any]) -> bool:
        if _authoritative_recovery_receipts(result):
            # An unresolved provider operation must follow its typed recovery plan
            # before the durable workflow may schedule another invocation.
            return False
        return bool(
            result.status == PrimitiveExecutionStatus.FAILED
            and (
                result.retryable
                or any(blocker.retryable for blocker in result.blockers)
            )
        )

    def _schedule_or_exhaust_retry(
        self,
        checkpoint: WorkflowCheckpoint,
        *,
        result: PrimitiveExecutionResult[Any],
        step_id: str,
        attempt_key: str,
        attempt_number: int,
        failure_time: datetime,
    ) -> ProjectWorkflowRun:
        policy = self.project.policy.retry_policy
        step_visit = int(attempt_key.rsplit(":", 1)[1])
        event_payload = {
            "step_id": step_id,
            "primitive_ref": result.primitive_ref,
            "step_visit": step_visit,
            "failed_attempt": attempt_number,
            "max_attempts": policy.max_attempts,
        }
        if attempt_number < policy.max_attempts:
            delay_seconds = policy.delay_seconds(attempt_number)
            next_attempt_at = failure_time + timedelta(seconds=delay_seconds)
            retry_event = PrimitiveEvent(
                type="workflow.step_retry_scheduled",
                payload={
                    **event_payload,
                    "next_attempt": attempt_number + 1,
                    "delay_seconds": delay_seconds,
                    "resume_at": next_attempt_at.isoformat(),
                },
            )
            retry_blocker = PrimitiveBlocker(
                code="retry_scheduled",
                message=(
                    "A retryable primitive failure was scheduled with bounded "
                    "exponential backoff."
                ),
                retryable=True,
            )
            stored = self.store.save(
                checkpoint.model_copy(
                    deep=True,
                    update={
                        "status": CheckpointStatus.SCHEDULED,
                        "events": [*checkpoint.events, retry_event],
                        "blockers": [retry_blocker],
                        "resume_at": next_attempt_at,
                        "next_attempt_at": next_attempt_at,
                        "lease_owner": None,
                        "lease_until": None,
                    },
                ),
                expected_revision=checkpoint.revision,
            )
            return ProjectWorkflowRun(
                run_ref=stored.run_ref,
                project_ref=stored.project_ref,
                workflow_key=stored.workflow_key,
                status=ProjectWorkflowRunStatus.SCHEDULED,
                step_runs=stored.step_runs,
                events=stored.events,
                paused_step=stored.current_step,
                resume_at=stored.resume_at,
                blockers=stored.blockers,
            )

        exhausted_event = PrimitiveEvent(
            type="workflow.step_retry_exhausted",
            payload=event_payload,
        )
        exhausted_blocker = PrimitiveBlocker(
            code="retry_budget_exhausted",
            message=(
                "The primitive exhausted its bounded retry attempts and "
                "requires explicit review before any further execution."
            ),
        )
        return self._finish(
            checkpoint.model_copy(
                deep=True,
                update={"events": [*checkpoint.events, exhausted_event]},
            ),
            CheckpointStatus.FAILED,
            blockers=[*result.blockers, exhausted_blocker],
        )

    def _finish(
        self,
        checkpoint: WorkflowCheckpoint,
        status: CheckpointStatus,
        *,
        blockers: list[PrimitiveBlocker] | None = None,
        preserve_active: bool = False,
    ) -> ProjectWorkflowRun:
        stored = self.store.save(
            checkpoint.model_copy(
                deep=True,
                update={
                    "status": status,
                    "blockers": list(blockers or []),
                    "resume_at": None,
                    "next_attempt_at": None,
                    "active_step_id": (
                        checkpoint.active_step_id if preserve_active else None
                    ),
                    "active_attempt_key": (
                        checkpoint.active_attempt_key if preserve_active else None
                    ),
                    "lease_owner": None,
                    "lease_until": None,
                },
            ),
            expected_revision=checkpoint.revision,
        )
        return ProjectWorkflowRun(
            run_ref=stored.run_ref,
            project_ref=stored.project_ref,
            workflow_key=stored.workflow_key,
            status=ProjectWorkflowRunStatus(stored.status.value),
            step_runs=stored.step_runs,
            events=stored.events,
            paused_step=stored.current_step
            if stored.status
            in {
                CheckpointStatus.PENDING_APPROVAL,
                CheckpointStatus.NEEDS_INPUT,
                CheckpointStatus.WAITING_FOR_RECOVERY,
                CheckpointStatus.BLOCKED,
                CheckpointStatus.FAILED,
            }
            else None,
            resume_at=stored.resume_at,
            blockers=stored.blockers,
        )

    def _workflow(self, workflow_key: str) -> ProjectWorkflow:
        normalized = str(workflow_key).strip().lower()
        workflow = next(
            (value for value in self.project.workflows if value.key == normalized),
            None,
        )
        if workflow is None:
            raise KeyError(
                f"Workflow is not declared by this Lightbulb project: {normalized}"
            )
        return workflow

    def _primitive_versions(self, workflow: ProjectWorkflow) -> Dict[str, str]:
        versions: Dict[str, str] = {}
        for primitive_ref in sorted(
            {step.primitive_ref for step in workflow.steps}
        ):
            try:
                primitive = self.runtime.registry.get(primitive_ref)
            except KeyError as exc:
                raise CheckpointCompatibilityError(
                    "workflow checkpoint cannot bind an unregistered primitive: "
                    f"{primitive_ref}"
                ) from exc
            version = str(primitive.version).strip()
            if not version:
                raise CheckpointCompatibilityError(
                    f"registered primitive has no version: {primitive_ref}"
                )
            versions[primitive_ref] = version
        return versions

    def _validate_checkpoint_compatibility(
        self,
        checkpoint: WorkflowCheckpoint,
    ) -> WorkflowCheckpoint:
        """Fail closed before stale checkpoint state can execute new semantics."""
        if checkpoint.project_ref != self.project.project_ref:
            raise CheckpointCompatibilityError(
                "checkpoint project_ref does not match the active project"
            )
        if checkpoint.scope_fingerprint != self.scope_fingerprint:
            raise CheckpointScopeError(
                "checkpoint scope_fingerprint does not match the active "
                "tenant/company scope"
            )
        if checkpoint.hosted_project_id != self.project.hosted_project_id:
            raise CheckpointScopeError(
                "checkpoint hosted_project_id does not match the active project"
            )
        if checkpoint.project_version != self.project.version:
            raise CheckpointCompatibilityError(
                "checkpoint project_version does not match the active project"
            )

        try:
            workflow = self._workflow(checkpoint.workflow_key)
        except KeyError as exc:
            raise CheckpointCompatibilityError(
                "checkpoint workflow_key is not declared by the active project"
            ) from exc
        expected_workflow_identity = _workflow_identity_sha256(
            workflow,
            execution_policy=self.project.policy,
        )
        expected_primitive_versions = self._primitive_versions(workflow)
        legacy_checkpoint = checkpoint.legacy_step_idempotency_mode

        if checkpoint.workflow_version is None:
            if not legacy_checkpoint:
                raise CheckpointCompatibilityError(
                    "checkpoint workflow_version is missing"
                )
        elif checkpoint.workflow_version != workflow.version:
            raise CheckpointCompatibilityError(
                "checkpoint workflow_version does not match the active workflow"
            )

        if checkpoint.workflow_identity_sha256 is None:
            if not legacy_checkpoint:
                raise CheckpointCompatibilityError(
                    "checkpoint workflow identity is missing"
                )
        elif checkpoint.workflow_identity_sha256 != expected_workflow_identity:
            raise CheckpointCompatibilityError(
                "checkpoint workflow identity does not match the active workflow"
            )

        if not checkpoint.primitive_versions:
            if not legacy_checkpoint:
                raise CheckpointCompatibilityError(
                    "checkpoint primitive_versions are missing"
                )
        elif checkpoint.primitive_versions != expected_primitive_versions:
            raise CheckpointCompatibilityError(
                "checkpoint primitive versions do not match registered "
                "implementations"
            )

        steps_by_id = {step.id: step for step in workflow.steps}
        for step_run in checkpoint.step_runs:
            step = steps_by_id.get(step_run.step_id)
            if step is None or step.primitive_ref != step_run.primitive_ref:
                raise CheckpointCompatibilityError(
                    "checkpoint step history does not match the active workflow"
                )
            if step_run.result.primitive_ref != step.primitive_ref:
                raise CheckpointCompatibilityError(
                    "checkpoint primitive result does not match its workflow step"
                )
            if (
                step_run.result.primitive_version
                != expected_primitive_versions[step.primitive_ref]
            ):
                raise CheckpointCompatibilityError(
                    "checkpoint step result primitive version does not match "
                    "the registered implementation"
                )

        referenced_steps = {
            *checkpoint.visits,
            *(key.rsplit(":", 1)[0] for key in checkpoint.step_attempts),
            *(key.rsplit(":", 1)[0] for key in checkpoint.step_invocations),
        }
        if checkpoint.current_step is not None:
            referenced_steps.add(checkpoint.current_step)
        if checkpoint.active_step_id is not None:
            referenced_steps.add(checkpoint.active_step_id)
        if not referenced_steps.issubset(steps_by_id):
            raise CheckpointCompatibilityError(
                "checkpoint execution state references steps outside the "
                "active workflow"
            )

        if legacy_checkpoint and (
            checkpoint.workflow_version is None
            or checkpoint.workflow_identity_sha256 is None
            or not checkpoint.primitive_versions
        ):
            checkpoint = checkpoint.model_copy(
                deep=True,
                update={
                    "workflow_version": workflow.version,
                    "workflow_identity_sha256": expected_workflow_identity,
                    "primitive_versions": expected_primitive_versions,
                },
            )
        return checkpoint

    def _require_checkpoint(self, run_ref: str) -> WorkflowCheckpoint:
        checkpoint = self.store.get(str(run_ref).strip())
        if checkpoint is None:
            raise KeyError(f"Workflow checkpoint not found: {run_ref}")
        return self._validate_checkpoint_compatibility(checkpoint)

    def _event_run_ref(self, event_id: str, workflow_key: str) -> str:
        digest = hashlib.sha256(
            f"{self.project.project_ref}|{event_id}|{workflow_key}".encode("utf-8")
        ).hexdigest()[:24]
        return f"event-run-{digest}"


__all__ = [
    "DURABLE_CHECKPOINT_SCHEMA",
    "LEGACY_DURABLE_CHECKPOINT_SCHEMA",
    "PREVIOUS_DURABLE_CHECKPOINT_SCHEMA",
    "WORKFLOW_EVENT_SCHEMA",
    "CheckpointCompatibilityError",
    "CheckpointConflictError",
    "CheckpointPersistenceError",
    "CheckpointScopeError",
    "CheckpointStatus",
    "DurableProjectRuntime",
    "HostedCheckpointStore",
    "InMemoryCheckpointStore",
    "JsonFileCheckpointStore",
    "WorkflowCheckpoint",
    "WorkflowCheckpointStore",
    "WorkflowEventEnvelope",
    "default_checkpoint_dir",
    "local_scope_fingerprint",
]
