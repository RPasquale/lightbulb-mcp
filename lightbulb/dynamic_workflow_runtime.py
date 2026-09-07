"""Durable control for provider-neutral Dynamic Project Workflows.

The core state machine in :mod:`lightbulb.dynamic_workflows` is pure and
immutable.  This module adds optimistic persistence and idempotent mutation
receipts without making a model-provider or authorization decision.  Callers
must pass the exact scope established by the Spring Control Plane.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol
from typing_extensions import Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from lightbulb.dynamic_workflows import (
    BuilderAssignment,
    BuilderResult,
    DynamicWorkflowScope,
    DynamicWorkflowState,
    EvaluatorVerdict,
    PlannerPlan,
    WorkflowRunStatus,
)
from lightbulb.local_storage import local_scope_fingerprint


DYNAMIC_WORKFLOW_CHECKPOINT_SCHEMA = "lightbulb.dynamic_workflow_checkpoint.v1"
DYNAMIC_WORKFLOW_MUTATION_SCHEMA = "lightbulb.dynamic_workflow_mutation.v1"

_RUN_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$")
_IDEMPOTENCY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_MUTATION_RECORDS = 1_000


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamps must include a timezone")
    return value.astimezone(timezone.utc)


def _canonical_json(value: Any) -> bytes:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json", by_alias=True)

    def encode(item: Any) -> Any:
        if isinstance(item, BaseModel):
            return item.model_dump(mode="json", by_alias=True)
        if isinstance(item, Enum):
            return item.value
        if isinstance(item, datetime):
            return _utc(item).isoformat()
        if isinstance(item, (set, frozenset, tuple)):
            return list(item)
        raise TypeError(
            f"value is not canonically JSON serializable: {type(item).__name__}"
        )

    return json.dumps(
        value,
        default=encode,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def default_dynamic_workflow_dir(
    project_ref: str,
    *,
    tenant_id: str | None = None,
    company_id: str | None = None,
) -> Path:
    """Return the local checkpoint root for one validated public project ref."""

    clean = str(project_ref or "").strip().lower()
    if not _RUN_REF_RE.fullmatch(clean) or ".." in clean:
        raise ValueError("project_ref has an invalid portable format")
    configured = os.getenv("LIGHTBULB_DYNAMIC_WORKFLOW_DIR", "").strip()
    base = (
        Path(configured).expanduser()
        if configured
        else Path.cwd() / ".lightbulb" / "dynamic-workflows"
    )
    if company_id is not None and tenant_id is None:
        raise ValueError("company_id requires tenant_id for local workflow scope")
    if tenant_id is not None:
        base = base / f"scope-{local_scope_fingerprint(tenant_id, company_id)[:32]}"
    return base / clean


class DynamicWorkflowRuntimeError(RuntimeError):
    """Base error for durable dynamic-workflow control."""


class DynamicWorkflowCheckpointConflict(DynamicWorkflowRuntimeError):
    """A checkpoint revision or idempotency claim conflicts."""


class DynamicWorkflowCheckpointNotFound(DynamicWorkflowRuntimeError):
    """The requested durable run does not exist in the exact store scope."""


class DynamicWorkflowPersistenceError(DynamicWorkflowRuntimeError):
    """A durable checkpoint cannot be safely loaded or committed."""


class _FrozenModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        str_strip_whitespace=True,
    )


class DynamicWorkflowMutationRecord(_FrozenModel):
    """Bounded replay evidence for one committed state mutation."""

    schema_id: str = Field(default=DYNAMIC_WORKFLOW_MUTATION_SCHEMA, alias="schema")
    operation: str = Field(min_length=1, max_length=100)
    idempotency_key: str = Field(min_length=1, max_length=200)
    request_digest: str
    state_digest: str
    committed_revision: int = Field(ge=1)
    occurred_at: datetime

    @field_validator("idempotency_key")
    @classmethod
    def _valid_idempotency_key(cls, value: str) -> str:
        if not _IDEMPOTENCY_RE.fullmatch(value):
            raise ValueError("idempotency_key has an invalid format")
        return value

    @field_validator("operation")
    @classmethod
    def _valid_operation(cls, value: str) -> str:
        clean = value.strip().lower()
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,99}", clean):
            raise ValueError("operation has an invalid format")
        return clean

    @field_validator("request_digest", "state_digest")
    @classmethod
    def _valid_digest(cls, value: str) -> str:
        clean = value.strip().lower()
        if not _SHA256_RE.fullmatch(clean):
            raise ValueError("mutation digests must be lowercase SHA-256 values")
        return clean

    @field_validator("occurred_at")
    @classmethod
    def _valid_time(cls, value: datetime) -> datetime:
        return _utc(value)


class DynamicWorkflowCheckpoint(_FrozenModel):
    """Portable checkpoint envelope accepted by local and hosted stores."""

    schema_id: str = Field(default=DYNAMIC_WORKFLOW_CHECKPOINT_SCHEMA, alias="schema")
    run_ref: str = Field(min_length=1, max_length=200)
    hosted_project_id: str | None = Field(default=None, max_length=200)
    scope_fingerprint: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    status: WorkflowRunStatus
    workflow_state: DynamicWorkflowState
    mutation_records: tuple[DynamicWorkflowMutationRecord, ...] = Field(
        default_factory=tuple,
        max_length=_MAX_MUTATION_RECORDS,
    )
    revision: int = Field(ge=1)
    created_at: datetime
    updated_at: datetime
    resume_at: datetime | None = None
    lease_owner: str | None = Field(default=None, max_length=200)
    lease_until: datetime | None = None

    @field_validator("run_ref")
    @classmethod
    def _valid_run_ref(cls, value: str) -> str:
        if not _RUN_REF_RE.fullmatch(value) or ".." in value:
            raise ValueError("run_ref has an invalid portable format")
        return value

    @field_validator("created_at", "updated_at", "resume_at", "lease_until")
    @classmethod
    def _valid_time(cls, value: datetime | None) -> datetime | None:
        return _utc(value) if value is not None else None

    @model_validator(mode="after")
    def _consistent_envelope(self) -> Self:
        if self.workflow_state.run_ref != self.run_ref:
            raise ValueError("checkpoint run_ref must match workflow_state")
        if self.workflow_state.status != self.status:
            raise ValueError("checkpoint status must match workflow_state")
        if self.updated_at < self.created_at:
            raise ValueError("checkpoint updated_at must not precede created_at")
        if self.updated_at < self.workflow_state.updated_at:
            raise ValueError("checkpoint cannot predate its workflow_state")
        keys: set[str] = set()
        previous_revision = 0
        for record in self.mutation_records:
            if record.idempotency_key in keys:
                raise ValueError("checkpoint idempotency keys must be unique")
            if record.committed_revision <= previous_revision:
                raise ValueError("mutation committed revisions must increase")
            if record.committed_revision > self.revision:
                raise ValueError("mutation record cannot exceed checkpoint revision")
            keys.add(record.idempotency_key)
            previous_revision = record.committed_revision
        if self.mutation_records and self.mutation_records[-1].state_digest != _sha256(
            self.workflow_state
        ):
            raise ValueError("latest mutation record does not seal workflow_state")
        return self

    @property
    def scope(self) -> DynamicWorkflowScope:
        return self.workflow_state.scope

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True)

    def mutation_for(
        self, idempotency_key: str
    ) -> DynamicWorkflowMutationRecord | None:
        return next(
            (
                record
                for record in self.mutation_records
                if record.idempotency_key == idempotency_key
            ),
            None,
        )


class DynamicWorkflowCheckpointStore(Protocol):
    def get(self, run_ref: str) -> DynamicWorkflowCheckpoint | None: ...

    def save(
        self,
        checkpoint: DynamicWorkflowCheckpoint,
        *,
        expected_revision: int,
    ) -> DynamicWorkflowCheckpoint: ...


def _validate_save_revision(
    checkpoint: DynamicWorkflowCheckpoint,
    *,
    actual_revision: int,
    expected_revision: int,
) -> None:
    if actual_revision != expected_revision:
        raise DynamicWorkflowCheckpointConflict(
            f"checkpoint revision is {actual_revision}, expected {expected_revision}"
        )
    if checkpoint.revision != expected_revision + 1:
        raise DynamicWorkflowCheckpointConflict(
            "candidate checkpoint revision must increase by exactly one"
        )


class InMemoryDynamicWorkflowCheckpointStore:
    """Thread-safe optimistic store for tests and one-process harnesses."""

    def __init__(self) -> None:
        self._checkpoints: dict[str, DynamicWorkflowCheckpoint] = {}
        self._lock = threading.RLock()

    def get(self, run_ref: str) -> DynamicWorkflowCheckpoint | None:
        with self._lock:
            value = self._checkpoints.get(run_ref)
            return value.model_copy(deep=True) if value is not None else None

    def save(
        self,
        checkpoint: DynamicWorkflowCheckpoint,
        *,
        expected_revision: int,
    ) -> DynamicWorkflowCheckpoint:
        with self._lock:
            current = self._checkpoints.get(checkpoint.run_ref)
            actual = current.revision if current is not None else 0
            _validate_save_revision(
                checkpoint,
                actual_revision=actual,
                expected_revision=expected_revision,
            )
            stored = checkpoint.model_copy(deep=True)
            self._checkpoints[checkpoint.run_ref] = stored
            return stored.model_copy(deep=True)


@contextmanager
def _file_lock(path: Path):
    lock_path = path.with_suffix(path.suffix + ".lock")
    deadline = time.monotonic() + 3.0
    descriptor: int | None = None
    while descriptor is None:
        if lock_path.is_symlink():
            raise DynamicWorkflowPersistenceError("refusing symlinked workflow lock")
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
                raise DynamicWorkflowPersistenceError(
                    "dynamic workflow checkpoint is busy"
                )
            time.sleep(0.05)
    try:
        os.write(descriptor, str(os.getpid()).encode("ascii"))
        yield
    finally:
        os.close(descriptor)
        lock_path.unlink(missing_ok=True)


class JsonDynamicWorkflowCheckpointStore:
    """Atomic, process-locked JSON checkpoint store for a local harness."""

    def __init__(
        self,
        root: str | Path,
        *,
        scope_fingerprint: str | None = None,
    ) -> None:
        requested = Path(root).expanduser()
        if requested.is_symlink():
            raise DynamicWorkflowPersistenceError("refusing symlinked workflow root")
        self.root = requested.resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.root, 0o700)
        except OSError:
            pass
        normalized_scope = str(scope_fingerprint or "").strip().lower() or None
        if normalized_scope is not None and not _SHA256_RE.fullmatch(normalized_scope):
            raise ValueError("scope_fingerprint must be a lowercase SHA-256 value")
        self.scope_fingerprint = normalized_scope

    def _validate_scope(self, checkpoint: DynamicWorkflowCheckpoint) -> None:
        if checkpoint.scope_fingerprint != self.scope_fingerprint:
            raise DynamicWorkflowPersistenceError(
                "dynamic workflow checkpoint scope does not match the authenticated tenant/company"
            )

    def _path(self, run_ref: str) -> Path:
        if not _RUN_REF_RE.fullmatch(run_ref) or ".." in run_ref:
            raise ValueError("run_ref has an invalid portable format")
        # Lexical path: resolve() would follow a planted symlink, making every
        # later is_symlink() refusal examine the target instead of the link.
        target = self.root / f"{run_ref}.json"
        if target.is_symlink():
            raise DynamicWorkflowPersistenceError(
                "refusing symlinked workflow checkpoint"
            )
        if target.resolve().parent != self.root:
            raise ValueError("run_ref escapes the checkpoint root")
        return target

    def get(self, run_ref: str) -> DynamicWorkflowCheckpoint | None:
        path = self._path(run_ref)
        if path.is_symlink():
            raise DynamicWorkflowPersistenceError(
                "refusing symlinked workflow checkpoint"
            )
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        except (OSError, ValueError, TypeError) as exc:
            raise DynamicWorkflowPersistenceError(
                f"cannot load dynamic workflow checkpoint {run_ref}"
            ) from exc
        try:
            checkpoint = DynamicWorkflowCheckpoint.model_validate(payload)
        except ValueError as exc:
            raise DynamicWorkflowPersistenceError(
                f"dynamic workflow checkpoint {run_ref} failed validation"
            ) from exc
        self._validate_scope(checkpoint)
        return checkpoint

    def save(
        self,
        checkpoint: DynamicWorkflowCheckpoint,
        *,
        expected_revision: int,
    ) -> DynamicWorkflowCheckpoint:
        self._validate_scope(checkpoint)
        path = self._path(checkpoint.run_ref)
        with _file_lock(path):
            current = self.get(checkpoint.run_ref)
            actual = current.revision if current is not None else 0
            _validate_save_revision(
                checkpoint,
                actual_revision=actual,
                expected_revision=expected_revision,
            )
            temporary = path.with_suffix(
                path.suffix + f".{os.getpid()}.{threading.get_ident()}.tmp"
            )
            try:
                descriptor = os.open(
                    temporary,
                    os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                    0o600,
                )
                with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
                    handle.write(
                        json.dumps(
                            checkpoint.to_dict(),
                            sort_keys=True,
                            separators=(",", ":"),
                        )
                    )
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, path)
                try:
                    os.chmod(path, 0o600)
                except OSError:
                    pass
            except OSError as exc:
                temporary.unlink(missing_ok=True)
                raise DynamicWorkflowPersistenceError(
                    f"cannot save dynamic workflow checkpoint {checkpoint.run_ref}"
                ) from exc
            return checkpoint.model_copy(deep=True)


class HostedDynamicWorkflowCheckpointStore:
    """Non-authoritative adapter over the generic project checkpoint API.

    This can persist an inner state-machine checkpoint for trusted internal
    experiments. It is not a hosted Dynamic Workflow control plane: callers of
    the generic API can author its JSON, status, and envelope metadata.
    Production hosted workflows must use the dedicated command/query service.
    """

    def __init__(
        self,
        client: Any,
        hosted_project_id: str,
        *,
        company_id: str | None = None,
    ) -> None:
        clean = str(hosted_project_id or "").strip()
        if not clean:
            raise ValueError("hosted_project_id is required")
        clean_company = str(company_id or "").strip() or None
        self.client = client
        self.hosted_project_id = clean
        self.company_id = clean_company

    def get(self, run_ref: str) -> DynamicWorkflowCheckpoint | None:
        kwargs = {"company_id": self.company_id} if self.company_id is not None else {}
        payload = self.client.get_sdk_project_checkpoint(
            self.hosted_project_id,
            run_ref,
            **kwargs,
        )
        if payload is None:
            return None
        return DynamicWorkflowCheckpoint.model_validate(payload)

    def save(
        self,
        checkpoint: DynamicWorkflowCheckpoint,
        *,
        expected_revision: int,
    ) -> DynamicWorkflowCheckpoint:
        if checkpoint.hosted_project_id not in {None, self.hosted_project_id}:
            raise DynamicWorkflowCheckpointConflict(
                "checkpoint hosted_project_id does not match the store scope"
            )
        payload = checkpoint.model_copy(
            update={"hosted_project_id": self.hosted_project_id}
        ).to_dict()
        kwargs = {"company_id": self.company_id} if self.company_id is not None else {}
        saved = self.client.put_sdk_project_checkpoint(
            self.hosted_project_id,
            checkpoint.run_ref,
            payload,
            expected_revision=expected_revision,
            **kwargs,
        )
        resolved = DynamicWorkflowCheckpoint.model_validate(saved)
        if resolved.revision != checkpoint.revision:
            raise DynamicWorkflowPersistenceError(
                "hosted checkpoint returned an unexpected revision"
            )
        return resolved


class DynamicWorkflowMutationResult(_FrozenModel):
    checkpoint: DynamicWorkflowCheckpoint
    replayed: bool = False
    committed_revision: int = Field(ge=1)

    def to_dict(self) -> dict[str, Any]:
        payload = self.checkpoint.to_dict()
        payload["replayed"] = self.replayed
        payload["committed_revision"] = self.committed_revision
        return payload


class DynamicWorkflowRuntime:
    """Idempotent durable façade over :class:`DynamicWorkflowState`."""

    def __init__(self, store: DynamicWorkflowCheckpointStore) -> None:
        self.store = store

    def status(
        self,
        run_ref: str,
        *,
        scope: DynamicWorkflowScope | Mapping[str, Any],
    ) -> DynamicWorkflowCheckpoint:
        checkpoint = self.store.get(run_ref)
        if checkpoint is None:
            raise DynamicWorkflowCheckpointNotFound(
                f"dynamic workflow checkpoint not found: {run_ref}"
            )
        checkpoint.scope.require_exact(DynamicWorkflowScope.model_validate(scope))
        return checkpoint

    def start(
        self,
        *,
        scope: DynamicWorkflowScope | Mapping[str, Any],
        run_ref: str,
        objective: str,
        acceptance_criteria: Any,
        created_at: datetime,
        idempotency_key: str,
        limits: Any = None,
    ) -> DynamicWorkflowMutationResult:
        resolved_scope = DynamicWorkflowScope.model_validate(scope)
        state = DynamicWorkflowState.create(
            scope=resolved_scope,
            run_ref=run_ref,
            objective=objective,
            acceptance_criteria=acceptance_criteria,
            created_at=created_at,
            limits=limits,
        )
        request_digest = _sha256(state)
        existing = self.store.get(run_ref)
        if existing is not None:
            existing.scope.require_exact(resolved_scope)
            return self._replay_or_conflict(
                existing,
                operation="start",
                idempotency_key=idempotency_key,
                request_digest=request_digest,
            )
        checkpoint = self._checkpoint_with_record(
            previous=None,
            state=state,
            operation="start",
            idempotency_key=idempotency_key,
            request_digest=request_digest,
            occurred_at=state.created_at,
        )
        try:
            saved = self.store.save(checkpoint, expected_revision=0)
        except DynamicWorkflowCheckpointConflict:
            concurrent = self.store.get(run_ref)
            if concurrent is None:
                raise
            concurrent.scope.require_exact(resolved_scope)
            return self._replay_or_conflict(
                concurrent,
                operation="start",
                idempotency_key=idempotency_key,
                request_digest=request_digest,
            )
        return DynamicWorkflowMutationResult(
            checkpoint=saved,
            committed_revision=saved.revision,
        )

    def submit_plan(
        self,
        plan: PlannerPlan,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> DynamicWorkflowMutationResult:
        return self._mutate(
            run_ref=plan.run_ref,
            scope=plan.scope,
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
            operation="submit_plan",
            request=plan,
            transition=lambda state: state.submit_plan(plan),
        )

    def assign_builder(
        self,
        assignment: BuilderAssignment,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> DynamicWorkflowMutationResult:
        return self._mutate(
            run_ref=assignment.run_ref,
            scope=assignment.scope,
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
            operation="assign_builder",
            request=assignment,
            transition=lambda state: state.assign_builder(assignment),
        )

    def submit_builder_result(
        self,
        result: BuilderResult,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> DynamicWorkflowMutationResult:
        return self._mutate(
            run_ref=result.run_ref,
            scope=result.scope,
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
            operation="submit_builder_result",
            request=result,
            transition=lambda state: state.record_builder_result(result),
        )

    def submit_evaluator_verdict(
        self,
        verdict: EvaluatorVerdict,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> DynamicWorkflowMutationResult:
        return self._mutate(
            run_ref=verdict.run_ref,
            scope=verdict.scope,
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
            operation="submit_evaluator_verdict",
            request=verdict,
            transition=lambda state: state.record_evaluator_verdict(verdict),
        )

    def cancel(
        self,
        run_ref: str,
        *,
        scope: DynamicWorkflowScope | Mapping[str, Any],
        reason: str,
        occurred_at: datetime,
        expected_revision: int,
        idempotency_key: str,
    ) -> DynamicWorkflowMutationResult:
        resolved_scope = DynamicWorkflowScope.model_validate(scope)
        request = {
            "run_ref": run_ref,
            "scope": resolved_scope,
            "reason": reason,
            "occurred_at": occurred_at,
        }
        return self._mutate(
            run_ref=run_ref,
            scope=resolved_scope,
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
            operation="cancel",
            request=request,
            transition=lambda state: state.cancel(
                scope=resolved_scope,
                reason=reason,
                occurred_at=occurred_at,
            ),
        )

    def _mutate(
        self,
        *,
        run_ref: str,
        scope: DynamicWorkflowScope,
        expected_revision: int,
        idempotency_key: str,
        operation: str,
        request: Any,
        transition: Callable[[DynamicWorkflowState], DynamicWorkflowState],
    ) -> DynamicWorkflowMutationResult:
        checkpoint = self.status(run_ref, scope=scope)
        request_digest = _sha256(request)
        existing = checkpoint.mutation_for(idempotency_key)
        if existing is not None:
            return self._replay_or_conflict(
                checkpoint,
                operation=operation,
                idempotency_key=idempotency_key,
                request_digest=request_digest,
            )
        if checkpoint.revision != expected_revision:
            raise DynamicWorkflowCheckpointConflict(
                f"checkpoint revision is {checkpoint.revision}, expected {expected_revision}"
            )
        state = transition(checkpoint.workflow_state)
        candidate = self._checkpoint_with_record(
            previous=checkpoint,
            state=state,
            operation=operation,
            idempotency_key=idempotency_key,
            request_digest=request_digest,
            occurred_at=state.updated_at,
        )
        try:
            saved = self.store.save(candidate, expected_revision=expected_revision)
        except DynamicWorkflowCheckpointConflict:
            concurrent = self.status(run_ref, scope=scope)
            return self._replay_or_conflict(
                concurrent,
                operation=operation,
                idempotency_key=idempotency_key,
                request_digest=request_digest,
            )
        return DynamicWorkflowMutationResult(
            checkpoint=saved,
            committed_revision=saved.revision,
        )

    def _checkpoint_with_record(
        self,
        *,
        previous: DynamicWorkflowCheckpoint | None,
        state: DynamicWorkflowState,
        operation: str,
        idempotency_key: str,
        request_digest: str,
        occurred_at: datetime,
    ) -> DynamicWorkflowCheckpoint:
        prior_records = previous.mutation_records if previous is not None else ()
        if len(prior_records) >= _MAX_MUTATION_RECORDS:
            raise DynamicWorkflowPersistenceError(
                "dynamic workflow mutation ledger reached its bounded capacity"
            )
        revision = (previous.revision if previous is not None else 0) + 1
        record = DynamicWorkflowMutationRecord(
            operation=operation,
            idempotency_key=idempotency_key,
            request_digest=request_digest,
            state_digest=_sha256(state),
            committed_revision=revision,
            occurred_at=occurred_at,
        )
        return DynamicWorkflowCheckpoint(
            run_ref=state.run_ref,
            hosted_project_id=previous.hosted_project_id if previous else None,
            scope_fingerprint=(
                previous.scope_fingerprint
                if previous is not None
                else getattr(self.store, "scope_fingerprint", None)
            ),
            status=state.status,
            workflow_state=state,
            mutation_records=prior_records + (record,),
            revision=revision,
            created_at=previous.created_at if previous else state.created_at,
            updated_at=state.updated_at,
        )

    def _replay_or_conflict(
        self,
        checkpoint: DynamicWorkflowCheckpoint,
        *,
        operation: str,
        idempotency_key: str,
        request_digest: str,
    ) -> DynamicWorkflowMutationResult:
        record = checkpoint.mutation_for(idempotency_key)
        if record is None:
            raise DynamicWorkflowCheckpointConflict(
                f"dynamic workflow run already exists: {checkpoint.run_ref}"
            )
        if record.operation != operation or record.request_digest != request_digest:
            raise DynamicWorkflowCheckpointConflict(
                "idempotency_key was reused for a different dynamic workflow mutation"
            )
        return DynamicWorkflowMutationResult(
            checkpoint=checkpoint,
            replayed=True,
            committed_revision=record.committed_revision,
        )


__all__ = [
    "DYNAMIC_WORKFLOW_CHECKPOINT_SCHEMA",
    "DYNAMIC_WORKFLOW_MUTATION_SCHEMA",
    "DynamicWorkflowCheckpoint",
    "DynamicWorkflowCheckpointConflict",
    "DynamicWorkflowCheckpointNotFound",
    "DynamicWorkflowCheckpointStore",
    "DynamicWorkflowMutationRecord",
    "DynamicWorkflowMutationResult",
    "DynamicWorkflowPersistenceError",
    "DynamicWorkflowRuntime",
    "DynamicWorkflowRuntimeError",
    "HostedDynamicWorkflowCheckpointStore",
    "InMemoryDynamicWorkflowCheckpointStore",
    "JsonDynamicWorkflowCheckpointStore",
    "default_dynamic_workflow_dir",
]
