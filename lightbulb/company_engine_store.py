"""Durable engine state: persist and advance company-engine lifecycles behind Spring's fences.

Every engine state the SDK seals (campaign, prospect, release, operating
period, period close, service case, worker) can now live in Spring under the
project the company operates in.  A store keeps one document per
``(engine, entity_ref)``; a write must present the prior version and prior
state digest, and Spring refuses stale, replayed, skipped, or out-of-scope
writes with a conflict.

:class:`EngineRuntime` is the small loop a harness or agent uses to run an
engine durably: load the state, seal a command against it, advance through
the engine, persist the new state, and, when the engine asks for a human
decision, open the platform approval bound to that exact command.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

from lightbulb.company_engine_core import LifecycleSpec, detached
from lightbulb.company_execution_bridge import ApprovalBinding, EngineApprovalRequest, bind_approval, command_with_approval, engine_approval_request

ENGINE_STATE_RECORD_SCHEMA = "lightbulb.sdk_engine_state_record.v1"


class EngineStateConflictError(RuntimeError):
    """The store refused the write: the caller's expected version or digest is stale, or the transition was already applied."""


class ApprovalLane(Protocol):
    """How one engine turns an ``*_APPROVAL_REQUIRED`` rejection into a platform decision and back into a command.

    ``bind_approval`` refuses any task whose ``approvalType`` is not
    ``sdk_engine_transition``, so an engine whose gate is a different approval
    type (``company_launch``'s human-only ``sdk_launch_gate``) supplies its own
    lane instead of forking the runtime.
    """

    def request(self, result: Any, command: Mapping[str, Any], *, engine: str, entity_ref: str, plan_digest: str, summary: str, description: str, risk_level: int) -> Any: ...

    def bind(self, task: Mapping[str, Any], request: Any) -> Any: ...

    def reissue(self, binding: Any, command: Mapping[str, Any], *, state: Any, occurred_at: str) -> dict[str, Any]: ...


class EngineTransitionLane:
    """The default lane: ``sdk_engine_transition`` approvals through the execution bridge."""

    def request(self, result: Any, command: Mapping[str, Any], *, engine: str, entity_ref: str, plan_digest: str, summary: str, description: str, risk_level: int) -> EngineApprovalRequest:
        return engine_approval_request(result, command, engine=engine, entity_ref=entity_ref, plan_digest=plan_digest, summary=summary, description=description, risk_level=risk_level)

    def bind(self, task: Mapping[str, Any], request: Any) -> ApprovalBinding:
        return bind_approval(task, request)

    def reissue(self, binding: Any, command: Mapping[str, Any], *, state: Any, occurred_at: str) -> dict[str, Any]:
        return command_with_approval(binding, command, state=state, occurred_at=occurred_at)


class EngineStateStore(Protocol):
    def get(self, engine: str, entity_ref: str) -> Mapping[str, Any] | None: ...

    def put(self, engine: str, entity_ref: str, state: Mapping[str, Any], *, expected_version: int | None, expected_state_digest: str | None) -> Mapping[str, Any]: ...

    def list(self, *, engine: str | None = None, status: str | None = None, limit: int = 50) -> list[Mapping[str, Any]]: ...

    def list_all(self, *, engine: str | None = None, status: str | None = None) -> list[Mapping[str, Any]]: ...

    def migrate(self, engine: str, entity_ref: str, state: Mapping[str, Any], *, migration: Mapping[str, Any]) -> Mapping[str, Any]: ...


def _record(engine: str, entity_ref: str, state: Mapping[str, Any]) -> dict[str, Any]:
    return {"schema": ENGINE_STATE_RECORD_SCHEMA, "engine": engine, "entity_ref": entity_ref, "status": state["status"], "plan_digest": state["plan_digest"], "version": int(state["version"]), "state_digest": state["state_digest"], "state": dict(state)}


class InMemoryEngineStateStore:
    """The Spring fences, in memory: for tests, simulations, and local runs."""

    def __init__(self) -> None:
        self._records: dict[tuple[str, str], dict[str, Any]] = {}

    def get(self, engine: str, entity_ref: str) -> Mapping[str, Any] | None:
        record = self._records.get((engine, entity_ref))
        return dict(record) if record is not None else None

    def put(self, engine: str, entity_ref: str, state: Mapping[str, Any], *, expected_version: int | None, expected_state_digest: str | None) -> Mapping[str, Any]:
        document = dict(detached(state))
        scope = document.get("scope") or {}
        if str(scope.get("entity_ref")) != entity_ref:
            raise ValueError("state.scope.entity_ref must match the entity ref")
        existing = self._records.get((engine, entity_ref))
        # Inspect only approvals consumed by this entity's own commands. Nested
        # source artifacts legitimately retain approvals consumed upstream.
        def consumptions(kind: str, ref: str, candidate: Mapping[str, Any]) -> dict[str, tuple[str, ...]]:
            uses: dict[str, tuple[str, ...]] = {}
            for item in candidate.get("transition_history", ()):
                command = item.get("command", {})
                proof = command.get("receipt", {}).get("authorization_proof") or {}
                if not proof:
                    continue
                identity = (kind, ref, str(command.get("event")), str(command.get("transition_ref")), str(command.get("idempotency_key")))
                for key in ("approval_task_id", "second_approval_task_id"):
                    task_id = proof.get(key)
                    if task_id:
                        if str(task_id) in uses and uses[str(task_id)] != identity:
                            raise EngineStateConflictError("APPROVAL_REUSED: one approval task cannot authorize two transitions; do_not_replay")
                        uses[str(task_id)] = identity
            return uses

        used = consumptions(engine, entity_ref, document)
        if used:
            company_scope = {key: scope.get(key) for key in ("tenant_ref", "company_ref", "project_ref", "project_id")}
            for (kind, other_ref), other in self._records.items():
                other_state = other["state"]
                if company_scope != {key: other_state.get("scope", {}).get(key) for key in company_scope}:
                    continue
                for task_id, identity in consumptions(kind, other_ref, other_state).items():
                    if task_id in used and used[task_id] != identity:
                        raise EngineStateConflictError("APPROVAL_REUSED: this task already authorized another persisted transition; do_not_replay")
        if engine == "pipeline_engine":
            ledger = document.get("ledger") or {}
            counts = dict(ledger.get("sends_by_day") or {})
            company_scope = {key: scope.get(key) for key in ("tenant_ref", "company_ref", "project_ref", "project_id")}
            for (kind, other_ref), other in self._records.items():
                if kind != engine or other_ref == entity_ref:
                    continue
                other_state = other["state"]
                if company_scope != {key: other_state.get("scope", {}).get(key) for key in company_scope}:
                    continue
                for key, count in other_state.get("ledger", {}).get("sends_by_day", {}).items():
                    counts[key] = counts.get(key, 0) + count
            for key, count in counts.items():
                cap = ledger.get("channel_daily_caps", {}).get(key.split(":")[0])
                if cap is not None and count > cap:
                    raise EngineStateConflictError("DAILY_CAP_EXCEEDED: the scoped channel's daily cap covers all prospects")
        if engine == "company_operating_system":
            sources = set((document.get("ledger") or {}).get("evidence_source_digests", ()))
            company_scope = {key: scope.get(key) for key in ("tenant_ref", "company_ref", "project_ref", "project_id")}
            for (kind, other_ref), other in self._records.items():
                if kind != engine or other_ref == entity_ref:
                    continue
                other_state = other["state"]
                other_scope = {key: other_state.get("scope", {}).get(key) for key in company_scope}
                if company_scope == other_scope and sources.intersection(other_state.get("ledger", {}).get("evidence_source_digests", ())):
                    raise EngineStateConflictError("EVIDENCE_ALREADY_RECORDED: a source digest already funds another operating period; do_not_replay")
        if existing is None:
            if expected_version not in (None, 0):
                raise EngineStateConflictError(f"engine state does not exist at expected version {expected_version}")
        else:
            if expected_version != existing["version"]:
                raise EngineStateConflictError(f"engine state version is {existing['version']}, expected {expected_version}")
            if expected_state_digest != existing["state_digest"]:
                raise EngineStateConflictError("engine state digest does not match the expected prior state")
            if document["state_digest"] == existing["state_digest"]:
                raise EngineStateConflictError("engine state digest did not change; the transition was already applied")
            if int(document["version"]) != existing["version"] + 1:
                raise EngineStateConflictError(f"engine state must advance exactly one version from {existing['version']}; got {document['version']}")
            if document["plan_digest"] != existing["plan_digest"]:
                raise EngineStateConflictError("engine state belongs to a different loop plan")
        record = _record(engine, entity_ref, document)
        self._records[(engine, entity_ref)] = record
        return dict(record)

    def list(self, *, engine: str | None = None, status: str | None = None, limit: int = 50) -> list[Mapping[str, Any]]:
        rows = [dict(record) for (kind, _), record in self._records.items() if (engine is None or kind == engine) and (status is None or record["status"] == status)]
        return rows[: max(1, min(200, limit))]

    def list_all(self, *, engine: str | None = None, status: str | None = None) -> list[Mapping[str, Any]]:
        from lightbulb._engine_inventory import MAX_ENGINE_SNAPSHOT_ROWS
        # Capture the membership before detaching rows. Writes replace records,
        # so later local writes cannot alter this snapshot's versions.
        captured = tuple(self._records.items())
        rows = [detached(record) for (kind, _), record in captured
                if (engine is None or kind == engine) and (status is None or record["status"] == status)]
        if len(rows) > MAX_ENGINE_SNAPSHOT_ROWS:
            raise ValueError("ENGINE_SNAPSHOT_ROW_LIMIT: narrow the scope; partial snapshots are not issued")
        return sorted(rows, key=lambda row: (row["engine"], row["entity_ref"]))

    def migrate(self, engine: str, entity_ref: str, state: Mapping[str, Any], *, migration: Mapping[str, Any]) -> Mapping[str, Any]:
        """Same-version write under a new plan digest, admitted only by a proof that names the persisted state."""

        document = dict(detached(state))
        proof = dict(detached(migration))
        existing = self._records.get((engine, entity_ref))
        if existing is None:
            raise EngineStateConflictError("engine state does not exist; nothing to migrate")
        if str((document.get("scope") or {}).get("entity_ref")) != entity_ref or str(proof.get("entity_ref")) != entity_ref:
            raise ValueError("state and migration must name the persisted entity ref")
        if proof.get("from_state_digest") != existing["state_digest"] or proof.get("from_plan_digest") != existing["plan_digest"]:
            raise EngineStateConflictError("migration proof does not start from the persisted state")
        if int(proof.get("version", -1)) != existing["version"] or int(document["version"]) != existing["version"]:
            raise EngineStateConflictError("a migration keeps the persisted version")
        if proof.get("to_plan_digest") != document["plan_digest"] or proof.get("to_state_digest") != document["state_digest"]:
            raise EngineStateConflictError("migration proof does not end at the supplied state")
        if document["plan_digest"] == existing["plan_digest"]:
            raise EngineStateConflictError("a migration changes the plan digest")
        record = _record(engine, entity_ref, document)
        record["migrated_from"] = {"plan_digest": existing["plan_digest"], "state_digest": existing["state_digest"], "migration_digest": proof.get("migration_digest")}
        self._records[(engine, entity_ref)] = record
        return dict(record)


class HostedEngineStateStore:
    """Spring-backed store through ``LightbulbClient`` engine-state methods, scoped to one project."""

    def __init__(self, client: Any, *, project_id: str, company_id: str | None = None) -> None:
        self._client = client
        self._project_id = project_id
        self._company_id = company_id

    def get(self, engine: str, entity_ref: str) -> Mapping[str, Any] | None:
        return self._client.get_engine_state(self._project_id, engine, entity_ref, company_id=self._company_id)

    def put(self, engine: str, entity_ref: str, state: Mapping[str, Any], *, expected_version: int | None, expected_state_digest: str | None) -> Mapping[str, Any]:
        from lightbulb.errors import LightbulbError

        try:
            return self._client.put_engine_state(self._project_id, engine, entity_ref, state, expected_version=expected_version, expected_state_digest=expected_state_digest, company_id=self._company_id)
        except LightbulbError as exc:
            if getattr(exc, "status_code", None) == 409:
                raise EngineStateConflictError(str(exc)) from exc
            raise

    def list(self, *, engine: str | None = None, status: str | None = None, limit: int = 50) -> list[Mapping[str, Any]]:
        return self._client.list_engine_states(self._project_id, engine=engine, status=status, limit=limit, company_id=self._company_id)

    def list_all(self, *, engine: str | None = None, status: str | None = None) -> list[Mapping[str, Any]]:
        return self._client.list_all_engine_states(self._project_id, engine=engine, status=status, company_id=self._company_id)

    def migrate(self, engine: str, entity_ref: str, state: Mapping[str, Any], *, migration: Mapping[str, Any]) -> Mapping[str, Any]:
        from lightbulb.errors import LightbulbError

        try:
            return self._client.migrate_engine_state(self._project_id, engine, entity_ref, state, migration=migration, company_id=self._company_id)
        except LightbulbError as exc:
            if getattr(exc, "status_code", None) == 409:
                raise EngineStateConflictError(str(exc)) from exc
            raise


@dataclass(frozen=True)
class EngineAdvanceOutcome:
    """What one durable advance produced: the transition result, the persisted record, or the approval to wait on."""

    result: Any
    record: Mapping[str, Any] | None = None
    approval_request: EngineApprovalRequest | None = None
    persisted: bool = False
    platform_task: Mapping[str, Any] | None = None

    @property
    def awaiting_approval(self) -> bool:
        return self.approval_request is not None


@dataclass(frozen=True)
class EngineMigrationOutcome:
    """A persisted plan migration: the proof, the migrated state, and the store record."""

    migration: Any
    state: Any
    record: Mapping[str, Any]


@dataclass
class EngineRuntime:
    """Run one engine durably: load, seal, advance, persist, and route approvals."""

    spec: LifecycleSpec
    engine: str
    plan: Any
    store: EngineStateStore
    advance: Callable[[Any, Any, Any], Any]
    approval_requester: Callable[..., Mapping[str, Any]] | None = None
    approval_reader: Callable[[str], Mapping[str, Any]] | None = None
    risk_level: int = 6
    approval_engine: str | None = None
    pending: dict[str, Any] = field(default_factory=dict)
    pending_commands: dict[str, dict[str, Any]] = field(default_factory=dict)
    #: Applied to ``(request, command)`` before the requester sees it: an operator
    #: stamps the authority category and money on the request here.
    request_decorator: Callable[[EngineApprovalRequest, Mapping[str, Any]], Any] | None = None
    #: What the requester returned, by transition ref: the platform task, so a
    #: caller can see an auto-accepted decision that ``advance_and_persist``
    #: would otherwise discard.
    requested: dict[str, Any] = field(default_factory=dict)
    approval_lane: ApprovalLane = field(default_factory=EngineTransitionLane)

    def open(self, entity_ref: str, state: Any) -> Mapping[str, Any]:
        """Persist a freshly opened state (version 1)."""

        document = detached(state)
        if int(document["version"]) != 1:
            raise ValueError("open persists a version-1 state; use advance for later versions")
        return self.store.put(self.engine, entity_ref, document, expected_version=0, expected_state_digest=None)

    def load(self, entity_ref: str) -> Any:
        record = self.store.get(self.engine, entity_ref)
        if record is None:
            raise LookupError(f"{self.engine} state {entity_ref} is not persisted")
        return self.spec.State.model_validate(dict(record["state"]), context={self.spec.plan_context_key: self.plan})

    def command(self, state: Any, *, event: str, transition_ref: str, idempotency_key: str, occurred_at: str, actor_ref: str, receipt: Mapping[str, Any] | None = None, reason: str | None = None) -> dict[str, Any]:
        return self.spec.seal_command({"event": event, "transition_ref": transition_ref, "idempotency_key": idempotency_key, "expected_version": state.version, "expected_state_digest": state.state_digest, "occurred_at": occurred_at, "actor_ref": actor_ref, "receipt": dict(receipt or {}), "reason": reason})

    def advance_and_persist(self, entity_ref: str, command: Mapping[str, Any], *, summary: str | None = None, description: str | None = None) -> EngineAdvanceOutcome:
        state = self.load(entity_ref)
        result = self.advance(self.plan, state, command)
        if result.candidate_validated:
            record = self.store.put(self.engine, entity_ref, detached(result.state), expected_version=state.version, expected_state_digest=state.state_digest)
            return EngineAdvanceOutcome(result=result, record=record, persisted=True)
        receipt = result.receipt
        if receipt.rejection_code and (receipt.recovery.disposition == "await_approval" or receipt.rejection_code == "APPROVAL_NOT_BOUND"):
            pending = self.pending.get(str(command["transition_ref"]))
            if pending is not None:
                # An incomplete resumption must not replace the exact request
                # the human already reviewed. Changed intent needs a new ref.
                return EngineAdvanceOutcome(result=result, approval_request=pending)
            request = self.approval_lane.request(result, command, engine=self.approval_engine or self.engine, entity_ref=entity_ref, plan_digest=self.plan.plan_digest, summary=summary or f"Approve {self.engine}.{command['event']} on {entity_ref}", description=description or str(receipt.recovery.instructions or "The engine requires a human decision for this transition."), risk_level=self.risk_level)
            self.pending[str(command["transition_ref"])] = request
            self.pending_commands[str(command["transition_ref"])] = dict(detached(command))
            task = None
            if self.approval_requester is not None:
                payload = self.request_decorator(request, dict(detached(command))) if self.request_decorator is not None else request
                task = self.approval_requester(payload)
                if task is not None:
                    self.requested[str(command["transition_ref"])] = task
            return EngineAdvanceOutcome(result=result, approval_request=request, platform_task=task)
        return EngineAdvanceOutcome(result=result)

    def resume_with_approval(self, entity_ref: str, command: Mapping[str, Any], task: Mapping[str, Any], *, occurred_at: str, authorization_proof: Any = None) -> EngineAdvanceOutcome:
        """Bind a platform decision to the pending request for this command and re-issue it."""

        request = self.pending.get(str(command["transition_ref"]))
        if request is None:
            raise LookupError(f"no pending approval request for transition {command['transition_ref']}")
        binding = self.approval_lane.bind(task, request)
        state = self.load(entity_ref)
        payload = self.approval_lane.reissue(binding, command, state=state, occurred_at=occurred_at)
        if authorization_proof is not None:
            from lightbulb.authority_matrix import AuthorizationProof
            proof = AuthorizationProof.model_validate(detached(authorization_proof))
            if proof.source_binding != binding:
                raise ValueError("APPROVAL_BINDING_MISMATCH: the authority proof must retain this exact platform decision")
            payload["receipt"] = {**payload["receipt"], "authorization_proof": proof.to_dict()}
        reissued = self.spec.seal_command(payload)
        outcome = self.advance_and_persist(entity_ref, reissued)
        if outcome.persisted:
            self.pending.pop(str(command["transition_ref"]), None)
            self.pending_commands.pop(str(command["transition_ref"]), None)
            self.requested.pop(str(command["transition_ref"]), None)
        return outcome

    def resume_with_authorization(self, entity_ref: str, proof: Any, *, occurred_at: str) -> EngineAdvanceOutcome:
        """Consume an authority proof retaining the pending platform ApprovalBinding."""
        from lightbulb.authority_matrix import AuthorizationProof
        from lightbulb.company_engine_core import timestamp

        authorized = AuthorizationProof.model_validate(detached(proof))
        request = self.pending.get(authorized.transition_ref)
        command = self.pending_commands.get(authorized.transition_ref)
        if request is None or command is None:
            raise LookupError(f"no pending approval request for transition {authorized.transition_ref}")
        binding = authorized.source_binding
        for key in ("engine", "entity_ref", "event", "transition_ref", "idempotency_key", "request_digest", "plan_digest", "actor_ref"):
            if getattr(binding, key) != getattr(request, key):
                raise ValueError(f"APPROVAL_BINDING_MISMATCH: proof does not bind pending {key}")
        if entity_ref != request.entity_ref:
            raise ValueError("APPROVAL_BINDING_MISMATCH: proof names another entity")
        payload = {**command, "occurred_at": timestamp(occurred_at, field_name="occurred_at"),
                   "receipt": {**command["receipt"], "authorization_proof": authorized.to_dict()}}
        outcome = self.advance_and_persist(entity_ref, self.spec.seal_command(payload))
        if outcome.persisted:
            self.pending.pop(authorized.transition_ref, None)
            self.pending_commands.pop(authorized.transition_ref, None)
        return outcome

    def migrate(self, entity_ref: str, to_plan: Any, *, migrated_at: str, actor_ref: str, reason: str) -> Any:
        """Replay the persisted entity under ``to_plan``, persist behind the migration fence, and run under the new plan from here on."""

        from lightbulb.company_plan_migration import migrate_state

        record = self.store.get(self.engine, entity_ref)
        if record is None:
            raise LookupError(f"{self.engine} state {entity_ref} is not persisted")
        result = migrate_state(self.spec, state=dict(record["state"]), from_plan=self.plan, to_plan=to_plan, migrated_at=migrated_at, actor_ref=actor_ref, reason=reason)
        persisted = self.store.migrate(self.engine, entity_ref, detached(result.state), migration=result.migration.to_dict())
        self.plan = result.plan
        return EngineMigrationOutcome(migration=result.migration, state=result.state, record=persisted)

    def resume_pending(self, transition_ref: str, task: Mapping[str, Any], *, occurred_at: str, authorization_proof: Any = None) -> EngineAdvanceOutcome:
        """Resume the command this runtime asked approval for, by its transition ref."""

        command = self.pending_commands.get(transition_ref)
        if command is None:
            raise LookupError(f"no pending command for transition {transition_ref}")
        request = self.pending[transition_ref]
        return self.resume_with_approval(str(request.entity_ref), command, task, occurred_at=occurred_at, authorization_proof=authorization_proof)


__all__ = [
    "ENGINE_STATE_RECORD_SCHEMA",
    "ApprovalLane",
    "EngineAdvanceOutcome",
    "EngineTransitionLane",
    "EngineMigrationOutcome",
    "EngineRuntime",
    "EngineStateConflictError",
    "EngineStateStore",
    "HostedEngineStateStore",
    "InMemoryEngineStateStore",
]


def complete_engine_states(store: Any, *, engine: str | None = None, status: str | None = None) -> list[Mapping[str, Any]]:
    """Use snapshot-aware stores; a full legacy page is ambiguous and must fail closed."""
    if callable(getattr(store, "list_all", None)):
        return list(store.list_all(engine=engine, status=status))
    rows = list(store.list(engine=engine, status=status, limit=200))
    if len(rows) >= 200:
        raise ValueError("ENGINE_SNAPSHOT_REQUIRED: this store cannot prove a full listing; implement list_all")
    return rows
