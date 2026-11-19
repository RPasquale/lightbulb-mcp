"""Durable resume for engine-transition approvals.

An engine that stops on ``*_APPROVAL_REQUIRED`` asks the platform for a decision and keeps the exact sealed command it
wants to re-issue.  Before this module that command lived only in ``EngineRuntime.pending_commands``: the platform
task carries just the binding digests, so once the process that asked was gone nothing could rebuild the command and
an approval made in the web inbox advanced nothing.

Now the runtime writes an :class:`EngineApprovalCheckpoint` into the project's checkpoint store (the same Spring
``sdk_project_workflow_checkpoints`` rows the cadence scheduler uses, through any ``CheckpointGateway``) before it
asks the platform, and marks it when the engine resumes.  The checkpoint is sealed with its own digest and carries the
sealed request and command, so the task's binding digests verify it on the way back.  Its platform status is
``pending_approval`` with no ``resume_at``, so the cadence worker's claim scan never picks it up; resumes write at the
read revision instead of taking a lease.

Two resumers share :func:`resume_approved_task`: the worker tick (:class:`ApprovalResumeStep`, under the cadence
lease) and the MCP ``decide_engine_approval`` tool.  Both are idempotent on the approval id and both work in a fresh
process.  Neither advances a company the owner has stopped.

Trust: ``checkpoint_digest`` is a keyless content hash, so the store never acts on a document it cannot verify (a
journal-signed document read through a plain gateway is refused), and the resumer re-validates the sealed command
through the engine's own ``Command`` model before anything is re-issued: its ``request_digest`` guard binds the
command's content to the digest the platform task carries, so an edited-and-resealed checkpoint cannot ride a real
approval.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, BoundedText, OpaqueRef, Sha256Digest, ShortText, StrictModel, detached, seal, sealed_digest, skip_digests, timestamp

APPROVAL_CHECKPOINT_SCHEMA = "lightbulb.engine_approval_checkpoint.v1"
APPROVAL_INDEX_SCHEMA = "lightbulb.engine_approval_index.v1"
RESUME_REPORT_SCHEMA = "lightbulb.engine_approval_resume_report.v1"
TRACE_PREFIX = "sdk-engine-approval:"
OPEN_PHASES: tuple[str, ...] = ("awaiting_request", "awaiting_decision")
TERMINAL_PHASES: tuple[str, ...] = ("resumed", "rejected", "expired", "superseded", "unresumable")
Phase = Literal["awaiting_request", "awaiting_decision", "resumed", "rejected", "expired", "superseded", "unresumable"]
INDEX_LIMIT = 500
_SCOPE_KEYS = ("tenant_ref", "company_ref", "project_ref", "project_id")
# Platform-added and journal-wrapper fields stripped before the sealed document is validated.
_PLATFORM_KEYS = {"revision", "lease_owner", "lease_until", "updated_at", "created_at", "hosted_project_id", "status", "resume_at", "host_document", "host_receipt"}
_DECIDED_AGAINST = {"REJECTED": "rejected", "EXPIRED": "expired", "CANCELLED": "expired"}


class ApprovalCheckpointError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _short(value: str) -> str:
    # a letter leads each segment so no digest can read as a 13+ digit run, which the payload screen refuses
    return "h" + hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:15]


def approval_run_ref(approval_engine: str, entity_ref: str, transition_ref: str) -> str:
    """The checkpoint run ref, keyed on the engine name the platform task binds (``approval_engine``).

    The run-ref charset excludes ``:``/``@``, which refs use, so the refs are shortened digests; the full refs live
    inside the document. A chain whose approvals are requested under another module's name (``compliance_obligation``
    binds as ``compliance_calendar``) is found by that bound name from the task, the inbox and the MCP tool alike.
    """

    return f"engine-approval.{approval_engine}.{_short(entity_ref)}.{_short(transition_ref)}"


def approval_index_ref(company_ref: str) -> str:
    return f"engine-approvals.{_short(company_ref)}"


class EngineApprovalCheckpoint(StrictModel):
    """One engine transition parked on a platform decision: the exact request and command, sealed."""

    schema_id: str = Field(default=APPROVAL_CHECKPOINT_SCHEMA, alias="schema")
    kind: Literal["engine_approval"] = "engine_approval"
    run_ref: OpaqueRef
    engine: ShortText
    approval_engine: ShortText
    entity_ref: OpaqueRef
    transition_ref: OpaqueRef
    event: ShortText
    request_schema: ShortText
    request: dict[str, Any]
    command: dict[str, Any]
    request_digest: Sha256Digest
    approval_request_digest: Sha256Digest | None = None
    expected_version: int = Field(ge=0)
    expected_state_digest: Sha256Digest
    plan_digest: Sha256Digest
    bundle_digest: Sha256Digest | None = None
    scope: dict[str, Any]
    trace_id: OpaqueRef | None = None
    task_id: OpaqueRef | None = None
    phase: Phase = "awaiting_request"
    approval_ref: OpaqueRef | None = None
    resumed_version: int | None = Field(default=None, ge=1)
    requested_at: str
    decided_at: str | None = None
    resumed_at: str | None = None
    note: BoundedText | None = None
    checkpoint_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("requested_at", "decided_at", "resumed_at")
    @classmethod
    def _stamps(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> EngineApprovalCheckpoint:
        if str(self.command.get("transition_ref")) != self.transition_ref or str(self.command.get("request_digest")) != self.request_digest:
            raise ValueError("the checkpoint's command must be the one its request binds")
        if str(self.request.get("request_digest", self.request_digest)) != self.request_digest:
            raise ValueError("the checkpoint's request must bind its command")
        if self.phase == "resumed" and (self.approval_ref is None or self.resumed_version is None):
            raise ValueError("a resumed checkpoint names the approval and the version it resumed to")
        if not skip_digests(info) and self.checkpoint_digest != sealed_digest(EngineApprovalCheckpoint, self, "checkpoint_digest"):
            raise ValueError("checkpoint_digest must commit the exact checkpoint")
        return self

    @property
    def open(self) -> bool:
        return self.phase in OPEN_PHASES


class EngineApprovalIndex(StrictModel):
    """The company's open approval checkpoints by run ref; a projection, the checkpoints are the truth."""

    schema_id: str = Field(default=APPROVAL_INDEX_SCHEMA, alias="schema")
    kind: Literal["engine_approval_index"] = "engine_approval_index"
    run_ref: OpaqueRef
    company_ref: OpaqueRef
    entries: dict[str, dict[str, str]] = Field(default_factory=dict)
    indexed_at: str


def checkpoint_from_request(*, runtime: Any, entity_ref: str, request: Any, command: Mapping[str, Any], state: Any, now: str, task_id: str | None = None) -> EngineApprovalCheckpoint:
    """Build the sealed checkpoint for a request the runtime just made (or is about to make)."""

    raw_request = dict(detached(request))
    raw_command = dict(detached(command))
    raw_state = dict(detached(state))
    scope = {key: value for key, value in dict(raw_state.get("scope") or {}).items() if key in _SCOPE_KEYS}
    approval_request_digest = raw_request.get("approval_request_digest") or raw_request.get("gate_request_digest")
    engine = str(runtime.engine)
    approval_engine = str(getattr(runtime, "approval_engine", None) or engine)
    transition_ref = str(raw_command["transition_ref"])
    return seal(EngineApprovalCheckpoint, {
        "run_ref": approval_run_ref(approval_engine, entity_ref, transition_ref),
        "engine": engine,
        "approval_engine": approval_engine,
        "entity_ref": entity_ref,
        "transition_ref": transition_ref,
        "event": str(raw_command["event"]),
        "request_schema": str(raw_request.get("schema") or type(request).__name__),
        "request": raw_request,
        "command": raw_command,
        "request_digest": str(raw_command["request_digest"]),
        "approval_request_digest": approval_request_digest if isinstance(approval_request_digest, str) and len(approval_request_digest) == 64 else None,
        "expected_version": int(raw_command.get("expected_version", raw_state.get("version", 0))),
        "expected_state_digest": str(raw_command.get("expected_state_digest") or raw_state["state_digest"]),
        "plan_digest": str(raw_state["plan_digest"]),
        "bundle_digest": getattr(runtime, "bundle_digest", None),
        "scope": scope,
        "trace_id": f"{TRACE_PREFIX}{approval_request_digest}" if isinstance(approval_request_digest, str) and len(approval_request_digest) == 64 else None,
        "task_id": task_id,
        "phase": "awaiting_decision" if task_id else "awaiting_request",
        "requested_at": now,
    }, "checkpoint_digest")


def request_from_checkpoint(lane: Any, checkpoint: EngineApprovalCheckpoint) -> Any:
    """The typed request the lane binds decisions to, rebuilt from the checkpoint; its own digest guard re-verifies it."""

    parse = getattr(lane, "parse", None)
    if callable(parse):
        return parse(dict(checkpoint.request))
    from lightbulb.company_execution_bridge import EngineApprovalRequest

    return EngineApprovalRequest.model_validate(dict(checkpoint.request))


def _task_id(task: Mapping[str, Any]) -> str:
    return str(task.get("id") or task.get("approvalRef") or task.get("approval_ref") or "")


def state_carries_approval(state: Mapping[str, Any], approval_ref: str) -> bool:
    """Whether a persisted state already consumed this platform decision (the crash-mid-resume check)."""

    if not approval_ref:
        return False
    ledger = state.get("ledger")
    if isinstance(ledger, Mapping) and str(ledger.get("approval_ref") or "") == approval_ref:
        return True
    for item in state.get("transition_history") or ():
        if not isinstance(item, Mapping):
            continue
        receipt = dict((item.get("command") or {}).get("receipt") or {})
        proof = receipt.get("authorization_proof") or {}
        if str(receipt.get("approval_ref") or receipt.get("gate_task_ref") or "") == approval_ref:
            return True
        if isinstance(proof, Mapping) and approval_ref in {str(proof.get("approval_task_id") or ""), str(proof.get("second_approval_task_id") or "")}:
            return True
    return False


@dataclass
class ApprovalCheckpointStore:
    """Approval checkpoints and the company's index of open ones, through any ``put``/``get`` checkpoint gateway.

    The worker writes through its authenticated host journal, which verifies the signature on every read and hands
    back the plain document. A plain gateway hands back the signed wrapper instead; this store refuses it
    (``CHECKPOINT_UNVERIFIED``) rather than trusting a keyless content hash, so the keyring-less MCP tool defers such
    checkpoints to the worker's next tick.
    """

    gateway: Any
    company_ref: str
    index_limit: int = INDEX_LIMIT
    #: A reader that must never write (the keyring-less MCP tool): in production every checkpoint is journal-signed
    #: by the hosted worker, so two writers never share these refs; ``write`` refuses with ``CHECKPOINT_READ_ONLY``.
    read_only: bool = False

    # -- reading ----------------------------------------------------------- #

    def _read(self, ref: str) -> tuple[dict[str, Any] | None, int | None]:
        stored = self.gateway.get(ref)
        if stored is None:
            return None, None
        raw = dict(stored)
        if "host_document" in raw or "host_receipt" in raw:
            raise ApprovalCheckpointError("CHECKPOINT_UNVERIFIED", f"{ref} is signed by the hosted worker's journal and this gateway cannot verify it; the worker's next tick acts on it")
        revision = raw.get("revision")
        return {key: value for key, value in raw.items() if key not in _PLATFORM_KEYS}, (int(revision) if revision is not None else None)

    def get_ref(self, ref: str) -> tuple[EngineApprovalCheckpoint | None, int | None]:
        document, revision = self._read(ref)
        if document is None:
            return None, None
        return EngineApprovalCheckpoint.model_validate(document), revision

    def get(self, approval_engine: str, entity_ref: str, transition_ref: str) -> EngineApprovalCheckpoint | None:
        """By the identity the platform task binds: the bound engine name, the entity and the transition."""
        return self.get_ref(approval_run_ref(approval_engine, entity_ref, transition_ref))[0]

    def index(self) -> EngineApprovalIndex | None:
        document, _ = self._read(approval_index_ref(self.company_ref))
        return None if document is None else EngineApprovalIndex.model_validate(document)

    def open_entries(self, *, engine: str | None = None) -> dict[str, dict[str, str]]:
        index = self.index()
        if index is None:
            return {}
        return {ref: dict(entry) for ref, entry in index.entries.items() if entry.get("phase") in OPEN_PHASES and (engine is None or entry.get("engine") == engine)}

    # -- writing ----------------------------------------------------------- #

    def write(self, checkpoint: EngineApprovalCheckpoint, *, expected_revision: int | None, now: str) -> int:
        """Reserve the index entry behind its revision fence first, then write the document.

        Two requesters racing at the cap both read the same index revision; the second put loses the fence, re-lists
        and retries, so the cap is decided by one fenced write. A document write failing after the reservation leaves
        an entry without a document: readers skip it and the next cap check prunes it.
        """
        if self.read_only:
            raise ApprovalCheckpointError("CHECKPOINT_READ_ONLY", f"this store only reads {self.company_ref}'s approval checkpoints; the hosted worker writes them")
        self._index(checkpoint, now=now, admit=checkpoint.open)
        document = {"status": "pending_approval" if checkpoint.open else "completed", "resume_at": None, **checkpoint.to_dict()}
        stored = dict(self.gateway.put(checkpoint.run_ref, document, expected_revision=expected_revision))
        return int(stored.get("revision") or 0)

    def record(self, checkpoint: EngineApprovalCheckpoint, *, now: str) -> int:
        """Write a request's checkpoint at whatever revision the ref holds (a re-request after a crash lands on the same ref)."""

        _, revision = self._read(checkpoint.run_ref)
        return self.write(checkpoint, expected_revision=revision or 0, now=now)

    def update(self, checkpoint: EngineApprovalCheckpoint, *, now: str, **changes: Any) -> EngineApprovalCheckpoint:
        """Re-seal the checkpoint with ``changes`` and write it at the revision currently held."""

        _, revision = self._read(checkpoint.run_ref)
        if revision is None:
            raise ApprovalCheckpointError("CHECKPOINT_MISSING", f"{checkpoint.run_ref} is not persisted")
        payload = {key: value for key, value in checkpoint.to_dict().items() if key != "checkpoint_digest"}
        payload.update(changes)
        updated = seal(EngineApprovalCheckpoint, payload, "checkpoint_digest")
        self.write(updated, expected_revision=revision, now=now)
        return updated

    def _index(self, checkpoint: EngineApprovalCheckpoint, *, now: str, admit: bool = False, attempts: int = 3) -> None:
        """Upsert the checkpoint's index entry behind the index's revision fence; resolved entries are pruned on every write."""
        from lightbulb.company_hosted_scheduler import CheckpointConflict

        ref = approval_index_ref(self.company_ref)
        for attempt in range(attempts):
            document, revision = self._read(ref)
            index = None if document is None else EngineApprovalIndex.model_validate(document)
            entries = {} if index is None else {key: dict(entry) for key, entry in index.entries.items() if entry.get("phase") in OPEN_PHASES and key != checkpoint.run_ref}
            if admit and len(entries) >= self.index_limit:
                # at the cap, entries whose documents never landed are dropped before refusing
                entries = {key: entry for key, entry in entries.items() if self._read(key)[0] is not None}
                if len(entries) >= self.index_limit:
                    raise ApprovalCheckpointError("APPROVAL_INDEX_FULL", f"{self.company_ref} already has {len(entries)} approvals awaiting decisions; decide or expire some before asking for more")
            if checkpoint.open:
                entries[checkpoint.run_ref] = {"engine": checkpoint.engine, "approval_engine": checkpoint.approval_engine, "entity_ref": checkpoint.entity_ref, "transition_ref": checkpoint.transition_ref, "phase": checkpoint.phase, "task_id": checkpoint.task_id or ""}
            updated = EngineApprovalIndex(run_ref=ref, company_ref=self.company_ref, entries=entries, indexed_at=timestamp(now, field_name="now"))
            try:
                self.gateway.put(ref, {"status": "completed", "resume_at": None, **updated.to_dict()}, expected_revision=revision or 0)
                return
            except CheckpointConflict:
                if attempt == attempts - 1:
                    raise


# --------------------------------------------------------------------------- #
# Resuming
# --------------------------------------------------------------------------- #


def runtime_for_checkpoint(runner: Any, engine: str, entity_ref: str, checkpoints: ApprovalCheckpointStore | None = None) -> Any:
    """The runtime a checkpointed transition runs under, opened the way the cadence runner opens it.

    Engines the runner already holds run under the bundle's plan; the console-plan engines (compliance obligations,
    exception cases) and chains the runner does not hold are opened through ``chain_runtime`` with the entity, so a
    state advances under the plan it was opened under, never a sibling's.
    """
    from lightbulb.company_chain_catalog import CONSOLE_PLAN_ENGINES, chain_runtime

    runtime = runner.runtimes.get(engine)
    if runtime is not None and engine not in CONSOLE_PLAN_ENGINES:
        return runtime
    try:
        runtime = chain_runtime(runner.bundle, engine, runner.store, approval_requester=runner.approval_requester, entity_ref=entity_ref)
    except (LookupError, ValueError, KeyError):
        return None
    runtime.checkpoints = checkpoints if checkpoints is not None else getattr(runner, "checkpoints", None)
    runtime.bundle_digest = getattr(runner.bundle, "bundle_digest", None)
    return runtime


def _autonomy_hold(autonomy_reader: Callable[[], Mapping[str, Any]] | None) -> str | None:
    """Why an APPROVED task must not advance the company now: the owner's stop, or a stop that cannot be read."""

    if autonomy_reader is None:
        return None
    try:
        view = dict(autonomy_reader())
    except Exception as exc:  # noqa: BLE001 - an unreadable stop holds the resume
        return f"the owner's autonomy stop could not be read ({type(exc).__name__}); not resuming"
    if str(view.get("status") or "").lower() == "stopped":
        return f"the owner stopped the company ({view.get('halted_by') or 'autonomy stop'}); not resuming"
    return None


def _item(checkpoint: EngineApprovalCheckpoint, outcome: str, **extra: Any) -> dict[str, Any]:
    return {"run_ref": checkpoint.run_ref, "engine": checkpoint.engine, "entity_ref": checkpoint.entity_ref, "transition_ref": checkpoint.transition_ref, "task_id": checkpoint.task_id, "outcome": outcome, **extra}


def resume_approved_task(*, task: Mapping[str, Any], checkpoint: EngineApprovalCheckpoint, runtime: Any, checkpoints: ApprovalCheckpointStore | None, now: str, autonomy_reader: Callable[[], Mapping[str, Any]] | None = None, asserted_company_id: str | None = None) -> dict[str, Any]:
    """Resume one checkpointed transition from its platform task, idempotently.

    Outcomes: ``resumed``, ``already_resumed``, ``pending``, ``rejected``/``expired``, ``superseded``, ``held`` (the
    owner's stop), ``refused`` (scope or binding mismatch), ``awaiting_authority`` (approved, but the engine needs an
    authority proof the resumer cannot mint), ``unresumable``.
    """

    from lightbulb.company_engine_store import EngineStateConflictError

    stamp = timestamp(now, field_name="now")
    raw_task = dict(detached(task))
    task_id = _task_id(raw_task)
    status = str(raw_task.get("status") or "PENDING").upper()

    def mark(**changes: Any) -> None:
        if checkpoints is None:
            return
        try:
            checkpoints.update(checkpoint, now=stamp, **changes)
        except ApprovalCheckpointError as exc:
            # a read-only store (the MCP tool) leaves marking to the hosted worker's next pass
            if exc.code != "CHECKPOINT_READ_ONLY":
                raise

    if not checkpoint.open:
        return _item(checkpoint, "already_resumed" if checkpoint.phase == "resumed" else checkpoint.phase, approval_ref=checkpoint.approval_ref)
    if checkpoint.task_id and task_id and task_id != checkpoint.task_id:
        return _item(checkpoint, "refused", code="APPROVAL_TASK_MISMATCH", detail=f"task {task_id} is not the task this transition asked for ({checkpoint.task_id})")
    if status == "PENDING":
        return _item(checkpoint, "pending")
    if status in _DECIDED_AGAINST:
        phase = _DECIDED_AGAINST[status]
        runtime.pending.pop(checkpoint.transition_ref, None)
        runtime.pending_commands.pop(checkpoint.transition_ref, None)
        getattr(runtime, "requested", {}).pop(checkpoint.transition_ref, None)
        mark(phase=phase, task_id=task_id or checkpoint.task_id, decided_at=raw_task.get("decidedAt") or stamp, note=f"the platform task is {status}; the entity stays where it is")
        return _item(checkpoint, phase)
    if status != "APPROVED":
        return _item(checkpoint, "refused", code="APPROVAL_TASK_INVALID", detail=f"unknown approval status {status!r}")
    hold = _autonomy_hold(autonomy_reader)
    if hold is not None:
        return _item(checkpoint, "held", detail=hold)
    if asserted_company_id and raw_task.get("companyId") and str(raw_task.get("companyId")) != str(asserted_company_id):
        return _item(checkpoint, "refused", code="SCOPE_MISMATCH", detail="the task belongs to another company than the one this caller asserts")
    record = runtime.store.get(checkpoint.engine, checkpoint.entity_ref)
    if record is None:
        mark(phase="unresumable", note="the entity is no longer persisted")
        return _item(checkpoint, "unresumable", code="STATE_MISSING")
    current = dict(record)
    if state_carries_approval(dict(current.get("state") or {}), task_id):
        runtime.pending.pop(checkpoint.transition_ref, None)
        runtime.pending_commands.pop(checkpoint.transition_ref, None)
        mark(phase="resumed", task_id=task_id, approval_ref=task_id, resumed_version=int(current["version"]), resumed_at=stamp, decided_at=raw_task.get("decidedAt") or stamp, note="the state already carried this decision (resumed before the checkpoint was marked)")
        return _item(checkpoint, "already_resumed", approval_ref=task_id, version=int(current["version"]))
    if str(current.get("state_digest")) != checkpoint.expected_state_digest or int(current.get("version", 0)) != checkpoint.expected_version:
        runtime.pending.pop(checkpoint.transition_ref, None)
        runtime.pending_commands.pop(checkpoint.transition_ref, None)
        mark(phase="superseded", task_id=task_id, decided_at=raw_task.get("decidedAt") or stamp, note=f"the entity moved on to v{current.get('version')} since the request; the decision does not resume it")
        return _item(checkpoint, "superseded", code="STATE_MOVED_ON", version=int(current.get("version", 0)))
    try:
        # the engine's own sealed Command model re-derives request_digest from the content: an edited command (even
        # with the checkpoint re-sealed around it) fails here, and a recomputed digest fails the task binding below
        command = runtime.spec.Command.model_validate(dict(checkpoint.command)).to_dict()
    except Exception as exc:  # noqa: BLE001 - never re-issue what the engine does not recognise as its own command
        return _item(checkpoint, "refused", code="COMMAND_TAMPERED", detail=str(exc)[:600])
    try:
        request = request_from_checkpoint(runtime.approval_lane, checkpoint)
        runtime.approval_lane.bind(raw_task, request)
    except Exception as exc:  # noqa: BLE001 - a binding that does not hold is reported, never acted on
        return _item(checkpoint, "refused", code=str(getattr(exc, "code", "") or "APPROVAL_BINDING_MISMATCH"), detail=str(exc)[:600])
    runtime.pending.setdefault(checkpoint.transition_ref, request)
    runtime.pending_commands.setdefault(checkpoint.transition_ref, dict(command))
    try:
        outcome = runtime.resume_with_approval(checkpoint.entity_ref, dict(command), raw_task, occurred_at=stamp)
    except EngineStateConflictError as exc:
        latest = runtime.store.get(checkpoint.engine, checkpoint.entity_ref) or {}
        if state_carries_approval(dict(latest.get("state") or {}), task_id):
            runtime.pending.pop(checkpoint.transition_ref, None)
            runtime.pending_commands.pop(checkpoint.transition_ref, None)
            mark(phase="resumed", task_id=task_id, approval_ref=task_id, resumed_version=int(latest["version"]), resumed_at=stamp, decided_at=raw_task.get("decidedAt") or stamp, note="another resumer persisted this decision first")
            return _item(checkpoint, "already_resumed", approval_ref=task_id, version=int(latest["version"]))
        return _item(checkpoint, "refused", code="STATE_CONFLICT", detail=str(exc)[:600])
    except (LookupError, ValueError) as exc:
        return _item(checkpoint, "refused", code=str(getattr(exc, "code", "") or "RESUME_REFUSED"), detail=str(exc)[:600])
    if outcome.persisted and outcome.record is not None:
        latest, _ = (checkpoints.get_ref(checkpoint.run_ref) if checkpoints is not None else (None, None))
        if latest is None or latest.open:
            mark(phase="resumed", task_id=task_id, approval_ref=task_id, resumed_version=int(outcome.record["version"]), resumed_at=stamp, decided_at=raw_task.get("decidedAt") or stamp, note=None)
        return _item(checkpoint, "resumed", approval_ref=task_id, version=int(outcome.record["version"]), status=str(outcome.record.get("status")))
    code = str(getattr(getattr(outcome.result, "receipt", None), "rejection_code", "") or "RESUME_REJECTED")
    mark(task_id=task_id, note=f"approved on the platform; the engine refused the re-issued command with {code} (it needs an authority proof or a fresh request)")
    return _item(checkpoint, "awaiting_authority", code=code)


def resume_open_approvals(*, checkpoints: ApprovalCheckpointStore, runtime_for: Callable[[str, str], Any], client: Any, now: str, autonomy_reader: Callable[[], Mapping[str, Any]] | None = None, asserted_company_id: str | None = None, fence: Callable[[], Any] | None = None) -> dict[str, Any]:
    """Walk the company's open checkpoints, read each platform task, and resume what was approved.

    ``runtime_for(engine, entity_ref)`` opens the runtime for one checkpoint. Anything one item raises (a checkpoint
    that no longer verifies, a conflicting write, a journal the host cannot authenticate) holds that item and is
    reported; only the caller's ``fence`` is allowed to stop the walk.
    """

    from lightbulb.company_host_journal import HostAuthorityError

    stamp = timestamp(now, field_name="now")
    items: list[dict[str, Any]] = []
    for ref, entry in sorted(checkpoints.open_entries().items()):
        if fence is not None:
            fence()
        placeholder = {"run_ref": ref, "engine": entry.get("engine"), "entity_ref": entry.get("entity_ref"), "transition_ref": entry.get("transition_ref"), "task_id": entry.get("task_id") or None}
        try:
            checkpoint, _ = checkpoints.get_ref(ref)
        except ApprovalCheckpointError as exc:
            items.append({**placeholder, "outcome": "held", "code": exc.code, "detail": str(exc)[:300]})
            continue
        except HostAuthorityError as exc:
            # a journal this host cannot authenticate (foreign bundle, bad signature) holds the item; it is a ValueError
            items.append({**placeholder, "outcome": "held", "code": str(getattr(exc, "code", "") or "HOST_JOURNAL_UNAUTHENTICATED"), "detail": str(exc)[:300]})
            continue
        except ValueError as exc:
            # a stored document that no longer verifies (tampered, or another schema) is reported and never acted on
            items.append({**placeholder, "outcome": "refused", "code": "CHECKPOINT_INVALID", "detail": str(exc)[:300]})
            continue
        except Exception as exc:  # noqa: BLE001 - the gateway failing on one ref holds that item, not the tick
            items.append({**placeholder, "outcome": "held", "code": type(exc).__name__, "detail": str(exc)[:300]})
            continue
        if checkpoint is None or not checkpoint.open:
            continue
        if not checkpoint.task_id:
            items.append(_item(checkpoint, "awaiting_request", detail="no platform task is recorded yet; the engine re-requests on its next advance"))
            continue
        try:
            task = dict(client.get_approval(checkpoint.task_id) or {})
        except Exception as exc:  # noqa: BLE001 - the platform read failing holds this item, not the tick
            items.append(_item(checkpoint, "unreadable", detail=f"{type(exc).__name__}: {exc}"[:300]))
            continue
        try:
            runtime = runtime_for(checkpoint.engine, checkpoint.entity_ref)
            if runtime is None:
                items.append(_item(checkpoint, "unresumable", code="NO_RUNTIME", detail=f"this worker runs no {checkpoint.engine} runtime"))
                continue
            items.append(resume_approved_task(task=task, checkpoint=checkpoint, runtime=runtime, checkpoints=checkpoints, now=stamp, autonomy_reader=autonomy_reader, asserted_company_id=asserted_company_id))
        except Exception as exc:  # noqa: BLE001 - a conflicting or unauthenticated write holds this item, not the tick
            items.append(_item(checkpoint, "held", code=type(exc).__name__, detail=str(exc)[:300]))
    counts: dict[str, int] = {}
    for item in items:
        counts[item["outcome"]] = counts.get(item["outcome"], 0) + 1
    detail = ", ".join(f"{count} {outcome}" for outcome, count in sorted(counts.items()))
    return {"schema": RESUME_REPORT_SCHEMA, "now": stamp, "items": items, "counts": counts, "detail": f"Engine approvals: {detail}" if items else None}


@dataclass
class ApprovalResumeStep:
    """The worker tick's step: resume the company's approved engine transitions under the cadence lease."""

    runner: Any
    checkpoints: ApprovalCheckpointStore
    client: Any
    autonomy_reader: Callable[[], Mapping[str, Any]] | None = None
    asserted_company_id: str | None = None

    def runtime_for(self, engine: str, entity_ref: str) -> Any:
        return runtime_for_checkpoint(self.runner, engine, entity_ref, self.checkpoints)

    def run(self, *, now: str, fence: Callable[[], Any] | None = None) -> dict[str, Any]:
        return resume_open_approvals(checkpoints=self.checkpoints, runtime_for=self.runtime_for, client=self.client, now=now, autonomy_reader=self.autonomy_reader, asserted_company_id=self.asserted_company_id, fence=fence)


__all__ = [
    "APPROVAL_CHECKPOINT_SCHEMA",
    "APPROVAL_INDEX_SCHEMA",
    "INDEX_LIMIT",
    "OPEN_PHASES",
    "RESUME_REPORT_SCHEMA",
    "TERMINAL_PHASES",
    "TRACE_PREFIX",
    "ApprovalCheckpointError",
    "ApprovalCheckpointStore",
    "ApprovalResumeStep",
    "EngineApprovalCheckpoint",
    "EngineApprovalIndex",
    "approval_index_ref",
    "approval_run_ref",
    "checkpoint_from_request",
    "request_from_checkpoint",
    "resume_approved_task",
    "resume_open_approvals",
    "runtime_for_checkpoint",
    "state_carries_approval",
]
