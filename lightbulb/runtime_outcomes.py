"""Sanitized runtime outcome telemetry for SDK business primitives.

Outcome records deliberately exclude primitive inputs, connector arguments, outputs,
and evidence payloads. They are safe to feed into the workflow-improvement evaluator
or persist in a tenant-scoped hosted ledger.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
from contextlib import contextmanager
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Protocol

from pydantic import BaseModel, ConfigDict, Field

from lightbulb.local_storage import local_scope_fingerprint, scoped_file_path


RUNTIME_OUTCOME_SCHEMA = "lightbulb.runtime_outcome.v1"
_SCOPE_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{64}$")


class RuntimeOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_id: str = Field(default=RUNTIME_OUTCOME_SCHEMA, alias="schema")
    primitive_ref: str = Field(min_length=3, max_length=200)
    status: str = Field(min_length=1, max_length=80)
    latency_ms: float = Field(ge=0)
    approval_state: str = Field(default="not_required", max_length=80)
    error_kind: str | None = Field(default=None, max_length=120)
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    harness: str = Field(default="lightbulb_sdk", max_length=120)
    project_ref: str | None = Field(default=None, max_length=128)
    workflow_key: str | None = Field(default=None, max_length=128)
    run_ref: str | None = Field(default=None, max_length=200)
    step_id: str | None = Field(default=None, max_length=128)
    scope_fingerprint: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True)

    def to_improvement_dict(self) -> dict[str, Any]:
        """Return only fields accepted by the proposal-only improvement loop."""
        return {
            key: value
            for key, value in self.to_dict().items()
            if key
            in {
                "primitive_ref",
                "status",
                "error_kind",
                "latency_ms",
                "approval_state",
                "occurred_at",
                "harness",
            }
            and value is not None
        }


class RuntimeOutcomeRecorder(Protocol):
    def record(self, outcome: RuntimeOutcome) -> None: ...

    def snapshot(self) -> list[RuntimeOutcome]: ...

    def drain(self) -> list[RuntimeOutcome]: ...


class InMemoryOutcomeRecorder:
    """Thread-safe bounded recorder suitable for one SDK or worker process."""

    def __init__(self, *, max_outcomes: int = 10_000) -> None:
        if max_outcomes < 1:
            raise ValueError("max_outcomes must be positive")
        self._outcomes: deque[RuntimeOutcome] = deque(maxlen=max_outcomes)
        self._lock = threading.Lock()

    def record(self, outcome: RuntimeOutcome) -> None:
        parsed = RuntimeOutcome.model_validate(outcome)
        with self._lock:
            self._outcomes.append(parsed)

    def snapshot(self) -> list[RuntimeOutcome]:
        with self._lock:
            return list(self._outcomes)

    def drain(self) -> list[RuntimeOutcome]:
        with self._lock:
            values = list(self._outcomes)
            self._outcomes.clear()
            return values


class RuntimeOutcomeScopeError(RuntimeError):
    """A local outcome artifact is outside the authenticated tenant/company."""


@contextmanager
def _outcome_file_lock(path: Path):
    lock_path = path.with_suffix(path.suffix + ".lock")
    deadline = time.monotonic() + 5.0
    descriptor: int | None = None
    while descriptor is None:
        if lock_path.is_symlink():
            raise RuntimeError(f"refusing symlinked outcome lock: {lock_path}")
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
                raise RuntimeError("local runtime outcome store is busy")
            time.sleep(0.05)
    try:
        os.write(descriptor, str(os.getpid()).encode("ascii"))
        os.fsync(descriptor)
        yield
    finally:
        os.close(descriptor)
        lock_path.unlink(missing_ok=True)


def _atomic_replace_private(path: Path, content: str) -> None:
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise RuntimeError(f"unsafe local runtime outcome target: {path}")
    temporary = path.with_name(
        f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp"
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
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)
        raise


class JsonlOutcomeRecorder:
    """Process-local durable recorder using replace-on-drain JSON Lines storage."""

    def __init__(
        self,
        path: str | Path,
        *,
        max_outcomes: int = 100_000,
        scope_fingerprint: str | None = None,
    ) -> None:
        requested = Path(path).expanduser()
        if requested.is_symlink():
            raise RuntimeError(f"refusing symlinked runtime outcomes file: {requested}")
        self.path = requested.resolve()
        if max_outcomes < 1:
            raise ValueError("max_outcomes must be positive")
        self.max_outcomes = max_outcomes
        normalized_scope = str(scope_fingerprint or "").strip().lower() or None
        if normalized_scope is not None and not _SCOPE_FINGERPRINT_RE.fullmatch(
            normalized_scope
        ):
            raise ValueError("scope_fingerprint must be a lowercase SHA-256 value")
        self.scope_fingerprint = normalized_scope
        self._lock = threading.Lock()

    def _scoped(self, outcome: RuntimeOutcome) -> RuntimeOutcome:
        if self.scope_fingerprint is None:
            if outcome.scope_fingerprint is not None:
                raise RuntimeOutcomeScopeError(
                    "scoped outcome cannot enter an unscoped store"
                )
            return outcome
        if outcome.scope_fingerprint not in {None, self.scope_fingerprint}:
            raise RuntimeOutcomeScopeError("runtime outcome scope does not match")
        if outcome.scope_fingerprint is None:
            return outcome.model_copy(
                update={"scope_fingerprint": self.scope_fingerprint}
            )
        return outcome

    def record(self, outcome: RuntimeOutcome) -> None:
        parsed = self._scoped(RuntimeOutcome.model_validate(outcome))
        line = json.dumps(parsed.to_dict(), sort_keys=True, separators=(",", ":"))
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(self.path.parent, 0o700)
            except OSError:
                pass
            with _outcome_file_lock(self.path):
                if self.path.is_symlink():
                    raise RuntimeError(
                        f"refusing symlinked runtime outcomes file: {self.path}"
                    )
                descriptor = os.open(
                    self.path,
                    os.O_CREAT | os.O_APPEND | os.O_WRONLY,
                    0o600,
                )
                try:
                    os.write(descriptor, (line + "\n").encode("utf-8"))
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                self._trim_unlocked()

    def snapshot(self) -> list[RuntimeOutcome]:
        with self._lock:
            with _outcome_file_lock(self.path):
                return self._read_unlocked()

    def drain(self) -> list[RuntimeOutcome]:
        with self._lock:
            with _outcome_file_lock(self.path):
                outcomes = self._read_unlocked()
                try:
                    self.path.unlink()
                except FileNotFoundError:
                    pass
                return outcomes

    def _read_unlocked(self) -> list[RuntimeOutcome]:
        if self.path.is_symlink():
            raise RuntimeError(f"refusing symlinked runtime outcomes file: {self.path}")
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            return []
        outcomes: list[RuntimeOutcome] = []
        for line in lines[-self.max_outcomes :]:
            try:
                outcomes.append(self._scoped(RuntimeOutcome.model_validate_json(line)))
            except (ValueError, TypeError):
                raise RuntimeOutcomeScopeError(
                    "runtime outcome ledger contains invalid or unscoped data"
                )
        return outcomes

    def _trim_unlocked(self) -> None:
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            return
        if len(lines) <= self.max_outcomes:
            return
        _atomic_replace_private(
            self.path,
            "\n".join(lines[-self.max_outcomes :]) + "\n",
        )


class CompositeOutcomeRecorder:
    """Fan out records while exposing the first recorder as the local queue."""

    def __init__(self, *recorders: RuntimeOutcomeRecorder) -> None:
        if not recorders:
            raise ValueError("at least one outcome recorder is required")
        self._recorders = recorders

    def record(self, outcome: RuntimeOutcome) -> None:
        errors: list[Exception] = []
        for recorder in self._recorders:
            try:
                recorder.record(outcome)
            except Exception as exc:  # recorder failures must not skip later sinks
                errors.append(exc)
        if errors:
            raise RuntimeError(
                f"{len(errors)} runtime outcome recorder(s) failed"
            ) from errors[0]

    def snapshot(self) -> list[RuntimeOutcome]:
        return self._recorders[0].snapshot()

    def drain(self) -> list[RuntimeOutcome]:
        return self._recorders[0].drain()


def improvement_outcomes(values: Iterable[RuntimeOutcome]) -> list[dict[str, Any]]:
    return [
        RuntimeOutcome.model_validate(value).to_improvement_dict() for value in values
    ]


def outcome_recorder_from_env(
    *,
    tenant_id: str | None = None,
    company_id: str | None = None,
) -> RuntimeOutcomeRecorder:
    """Use durable JSONL telemetry when explicitly configured, else bounded memory."""
    configured = os.getenv("LIGHTBULB_RUNTIME_OUTCOMES_FILE", "").strip()
    if not configured:
        return InMemoryOutcomeRecorder()
    if tenant_id is None:
        return JsonlOutcomeRecorder(configured)
    fingerprint = local_scope_fingerprint(tenant_id, company_id)
    return JsonlOutcomeRecorder(
        scoped_file_path(configured, fingerprint),
        scope_fingerprint=fingerprint,
    )


__all__ = [
    "RUNTIME_OUTCOME_SCHEMA",
    "CompositeOutcomeRecorder",
    "InMemoryOutcomeRecorder",
    "JsonlOutcomeRecorder",
    "RuntimeOutcome",
    "RuntimeOutcomeRecorder",
    "RuntimeOutcomeScopeError",
    "improvement_outcomes",
    "outcome_recorder_from_env",
]
