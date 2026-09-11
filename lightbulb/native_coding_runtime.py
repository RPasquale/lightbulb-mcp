"""Crash-conscious integration seam for the forthcoming local runtime.

Drivers implement native execution; this module never spawns a vendor process.
All three adapters require the same idempotent start, inspection, cancellation,
lease enforcement and exact-question decision capabilities.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
import secrets
import sqlite3
from typing import Any, Literal, Protocol
from uuid import uuid4

from pydantic import SecretStr
from lightbulb.local_secret_store import protect_secret, unprotect_secret
from lightbulb.native_coding import NativeCodingClient, NativeCodingReport, NativeCodingTask, RuntimeConnection


@dataclass(frozen=True)
class RuntimeSnapshot:
    status: Literal["unknown", "running", "question", "completed", "failed", "cancelled"]
    session_ref: str = ""
    summary: str = ""
    question_ref: str = ""
    changed_files: list[str] = field(default_factory=list)
    test_results: list[str] = field(default_factory=list)
    pull_request_url: str | None = None
    commit_sha: str | None = None


class NativeRuntimeDriver(Protocol):
    """Required driver contract; each call must return promptly.

    start_once durably binds task_id before launching and never creates a second
    execution for that ID. inspect returns unknown when absence cannot be proven.
    The driver must pause execution itself at lease expiry, even if this client dies.
    answer_once must bind question_ref and ignore identical replayed decisions.
    """
    def start_once(self, task_id: str, packet: dict[str, Any], lease_expires_at: str) -> RuntimeSnapshot: ...
    def inspect(self, task_id: str) -> RuntimeSnapshot: ...
    def renew_lease(self, task_id: str, lease_expires_at: str) -> None: ...
    def pause(self, task_id: str) -> None: ...
    def cancel(self, task_id: str) -> RuntimeSnapshot: ...
    def answer_once(self, task_id: str, question_ref: str, approved: bool) -> RuntimeSnapshot: ...


class NativeRuntimeAdapter:
    harness: str
    def __init__(self, driver: NativeRuntimeDriver):
        for name in ("start_once", "inspect", "renew_lease", "pause", "cancel", "answer_once"):
            if not callable(getattr(driver, name, None)):
                raise TypeError(f"Native driver must implement {name}")
        self.driver = driver


class CodexRuntimeAdapter(NativeRuntimeAdapter):
    harness = "codex"


class ClaudeCodeRuntimeAdapter(NativeRuntimeAdapter):
    harness = "claude_code"


class CursorRuntimeAdapter(NativeRuntimeAdapter):
    harness = "cursor"


class NativeCodingBusyError(RuntimeError):
    """Another local process currently owns this task's observation step."""


class NativeCodingJournal:
    """SQLite delivery journal with OS-backed protection for custody and packet material.

    The namespace must identify the authenticated Project and connection. Do not
    share a journal between independently installed runtime instances.
    """
    def __init__(self, path: str | Path, namespace: str):
        self.namespace = namespace
        self.lock_directory = Path(str(path) + ".locks")
        self.lock_directory.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, timeout=5)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("CREATE TABLE IF NOT EXISTS native_tasks (namespace TEXT, task TEXT, phase TEXT NOT NULL, protected TEXT NOT NULL, PRIMARY KEY(namespace,task))")
        self.db.execute("CREATE TABLE IF NOT EXISTS native_cursor (namespace TEXT PRIMARY KEY, last_task TEXT NOT NULL)")
        self.db.commit()

    @contextmanager
    def task_lock(self, task: str):
        # Separate SQLite lock files allow durable journal commits while holding
        # cross-process task ownership. Process exit releases the OS lock.
        key = hashlib.sha256(f"{self.namespace}:{task}".encode()).hexdigest()
        lock = sqlite3.connect(self.lock_directory / (key + ".db"), timeout=0)
        try:
            try:
                lock.execute("BEGIN IMMEDIATE")
            except sqlite3.OperationalError as error:
                if getattr(error, "sqlite_errorcode", 0) & 255 in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}:
                    raise NativeCodingBusyError("Another worker owns this task") from error
                raise
            yield
        finally:
            lock.rollback()
            lock.close()

    def select_fairly(self, tasks: list[str], limit: int) -> list[str]:
        ordered = sorted(set(tasks))
        row = self.db.execute("SELECT last_task FROM native_cursor WHERE namespace=?", (self.namespace,)).fetchone()
        last = row[0] if row else ""
        selected = ([task for task in ordered if task > last] + [task for task in ordered if task <= last])[:limit]
        if selected:
            with self.db:
                self.db.execute("INSERT INTO native_cursor VALUES (?,?) ON CONFLICT(namespace) DO UPDATE SET last_task=excluded.last_task", (self.namespace, selected[-1]))
        return selected

    def unfinished(self) -> list[str]:
        return [row[0] for row in self.db.execute("SELECT task FROM native_tasks WHERE namespace=? AND phase!='finished'", (self.namespace,))]

    def close(self) -> None:
        self.db.close()

    def _protect(self, task: str, value: dict[str, Any]) -> str:
        return json.dumps(protect_secret(json.dumps(value).encode(), purpose="native-coding-journal", context=f"{self.namespace}:{task}"))

    def load(self, task: str) -> dict[str, Any] | None:
        row = self.db.execute("SELECT protected FROM native_tasks WHERE namespace=? AND task=?", (self.namespace, task)).fetchone()
        if row is None:
            return None
        return json.loads(unprotect_secret(json.loads(row[0]), purpose="native-coding-journal", context=f"{self.namespace}:{task}"))

    def reserve(self, task: str, digest: str) -> dict[str, Any]:
        value = {"claim_token": secrets.token_urlsafe(32), "digest": digest, "phase": "new", "pending": None}
        with self.db:
            self.db.execute("INSERT OR IGNORE INTO native_tasks VALUES (?,?,?,?)", (self.namespace, task, "new", self._protect(task, value)))
        result = self.load(task)
        if result is None or result["digest"] != digest:
            raise ValueError("Local task identity changed its approved packet")
        return result

    def save(self, task: str, value: dict[str, Any]) -> None:
        with self.db:
            self.db.execute("UPDATE native_tasks SET phase=?,protected=? WHERE namespace=? AND task=?", (value["phase"], self._protect(task, value), self.namespace, task))

    def begin_start(self, task: str, value: dict[str, Any]) -> bool:
        value["phase"] = "start_intent"
        with self.db:
            cursor = self.db.execute("UPDATE native_tasks SET phase=?,protected=? WHERE namespace=? AND task=? AND phase='new'", (value["phase"], self._protect(task, value), self.namespace, task))
        return cursor.rowcount == 1


class NativeCodingWorker:
    """One bounded observation/execution step; scheduling belongs to the local runtime."""
    def __init__(self, channel: NativeCodingClient, connection: RuntimeConnection,
                 adapter: NativeRuntimeAdapter, journal: NativeCodingJournal):
        if adapter.harness != connection.harness or channel.project_id != connection.project_id:
            raise ValueError("Runtime adapter does not match the connected Project harness")
        if connection.connection_secret is None:
            raise ValueError("Protected connection custody is required")
        if journal.namespace != f"{connection.project_id}:{connection.id}":
            raise ValueError("Journal belongs to a different Project connection")
        self.channel, self.connection, self.adapter, self.journal = channel, connection, adapter, journal

    def _custody(self, task: str, record: dict[str, Any], operation: str):
        return self.channel.custody(self.connection.id, self.connection.connection_secret, task,
                                    SecretStr(record["claim_token"]), operation)

    def _emit(self, state: NativeCodingTask, record: dict[str, Any], kind: str, snapshot: RuntimeSnapshot) -> NativeCodingTask:
        task = str(state.id)
        if record["pending"] is None:
            report = NativeCodingReport(event_id=uuid4(), expected_revision=state.revision,
                claim_token=SecretStr(record["claim_token"]), kind=kind,
                summary=snapshot.summary or kind, runtime_session_ref=snapshot.session_ref or None,
                changed_files=snapshot.changed_files, test_results=snapshot.test_results,
                pull_request_url=snapshot.pull_request_url, commit_sha=snapshot.commit_sha)
            record["pending"] = report.wire()
            self.journal.save(task, record)
        # Retry the exact same event after uncertainty. Never manufacture a new result ID.
        result = self.channel.report(self.connection.id, self.connection.connection_secret, task,
                                     NativeCodingReport.model_validate(record["pending"]))
        if record["pending"]["kind"] in {"started", "progress"}:
            record["last_progress"] = record["pending"]["summary"]
        record["pending"] = None
        self.journal.save(task, record)
        return result

    def poll_once(self, limit: int = 20) -> list[NativeCodingTask]:
        if not 1 <= limit <= 100:
            raise ValueError("Poll limit must be between 1 and 100")
        tasks = {str(task.id): task for task in self.channel.poll(self.connection.id, self.connection.connection_secret)}
        # Retain completion acknowledgements even after the server removes terminal tasks from its inbox.
        for task_id in self.journal.unfinished():
            if task_id not in tasks:
                tasks[task_id] = self.channel.get(task_id)
        results = []
        for task_id in self.journal.select_fairly(list(tasks), limit):
            try:
                results.append(self.tick(tasks[task_id]))
            except NativeCodingBusyError:
                continue
        return results

    def tick(self, task: NativeCodingTask) -> NativeCodingTask:
        if task.connection_id != self.connection.id or task.harness != self.adapter.harness or task.project_id != self.connection.project_id:
            raise ValueError("Task is outside the connected runtime scope")
        task_id = str(task.id)
        with self.journal.task_lock(task_id):
            record = self.journal.reserve(task_id, task.proposal_digest)
            try:
                return self._tick(task, record)
            except Exception:
                # Stop execution on lost control-plane contact; results remain retryable.
                self.adapter.driver.pause(task_id)
                raise

    def _tick(self, task: NativeCodingTask, record: dict[str, Any]) -> NativeCodingTask:
        task_id = str(task.id)
        if task.status in {"cancelled", "failed", "result_review"} and record["phase"] == "new" and record["pending"] is None:
            record["phase"] = "finished"
            self.journal.save(task_id, record)
            return task
        state = self._custody(task_id, record, "claim" if task.status == "queued" else "heartbeat")
        if state.reconciliation_required:
            self.adapter.driver.pause(task_id)
            snapshot = self.adapter.driver.inspect(task_id)
            if snapshot.status == "unknown" and record["phase"] != "new":
                return state  # A lost start acknowledgement must never trigger a fresh process.
            state = self._custody(task_id, record, "reconcile")
        if state.status in {"result_review", "failed", "cancelled"}:
            if record["pending"] is not None:
                state = self._emit(state, record, record["pending"]["kind"], RuntimeSnapshot("unknown"))
            record["phase"] = "finished"
            self.journal.save(task_id, record)
            return state
        if state.cancel_requested:
            snapshot = self.adapter.driver.cancel(task_id)
            if snapshot.status in {"cancelled", "completed", "failed"}:
                # A pending progress report cannot override a later user cancellation.
                record["pending"] = None
                return self._emit(state, record, snapshot.status, snapshot)
            return state
        if record["pending"] is not None:
            state = self._emit(state, record, record["pending"]["kind"], RuntimeSnapshot("unknown"))
        if state.status == "waiting_for_user":
            decision = self._custody(task_id, record, "decision")["decision"]
            if decision == "pending":
                return state
            snapshot = self.adapter.driver.answer_once(task_id, record.get("question_ref", ""), decision == "approved")
            if decision == "rejected":
                snapshot = self.adapter.driver.cancel(task_id)
                if snapshot.status in {"cancelled", "failed"}:
                    return self._emit(state, record, snapshot.status, snapshot)
                if snapshot.status == "completed":
                    return self._emit(state, record, "failed", RuntimeSnapshot("failed", snapshot.session_ref,
                        "Execution completed after a rejected request; independent review is required."))
                return state
            state = self._emit(state, record, "progress", snapshot)
        if not state.lease_expires_at:
            raise ValueError("Native execution requires a server-issued lease deadline")
        snapshot = self.adapter.driver.inspect(task_id)
        if record["phase"] == "new" and state.status == "claimed":
            if not state.packet:
                raise ValueError("Approved execution packet missing")
            if self.journal.begin_start(task_id, record):
                snapshot = self.adapter.driver.start_once(task_id, state.packet, state.lease_expires_at)
        elif snapshot.status == "unknown":
            return state  # Inspection uncertainty is a hold, never a restart instruction.
        self.adapter.driver.renew_lease(task_id, state.lease_expires_at)
        if snapshot.status != "unknown" and state.status == "claimed":
            if not snapshot.session_ref:
                raise ValueError("Native runtime must return its durable session reference")
            state = self._emit(state, record, "started", snapshot)
        if snapshot.status == "question":
            if state.revision >= 10000:
                stopped = self.adapter.driver.cancel(task_id)
                if stopped.status in {"cancelled", "failed"}:
                    return self._emit(state, record, "failed", RuntimeSnapshot("failed", stopped.session_ref,
                        "Task progress budget exhausted before this question could be approved."))
                return state
            if not snapshot.question_ref:
                raise ValueError("Runtime question needs a stable identity")
            record["question_ref"] = snapshot.question_ref
            return self._emit(state, record, "question", snapshot)
        if snapshot.status in {"completed", "failed", "cancelled"}:
            return self._emit(state, record, snapshot.status, snapshot)
        if state.revision < 10000 and snapshot.status == "running" and snapshot.summary and snapshot.summary != record.get("last_progress"):
            return self._emit(state, record, "progress", snapshot)
        return state
