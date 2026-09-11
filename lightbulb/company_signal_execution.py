"""Durable materialization of company signal intents on the existing host.

Signals request internal review work; they are not provider observations or
proof of retained revenue. The host freezes each original signal before any
case write and drains its bounded queue under the ordinary cadence lease.
Only ``open_retention_case`` and churn-triggered prospect suppression execute
here. Other intents and commands remain explicitly deferred in the report.

Case execution reuses the service lifecycle and scoped engine store. The
authenticated checkpoint gateway owns journal custody; no separate database,
approval authority, messaging path, or retention lifecycle is introduced.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import json
from typing import Any, Literal

from pydantic import Field

from lightbulb.company_engine_core import (
    OpaqueRef, StrictModel, detached, parsed, stable_digest, timestamp,
)
from lightbulb.company_engine_store import EngineStateConflictError
from lightbulb.company_hosted_scheduler import CheckpointConflict
from lightbulb.company_operating_system import CompanySignal
from lightbulb.company_signal_consumers import consume_signal
from lightbulb.company_signal_commands import execute_signal_command, prepare_signal_commands
from lightbulb.service_delivery_engine import CASE_LIFECYCLE, open_case

SIGNAL_EXECUTION_SCHEMA = "lightbulb.company_signal_execution.v1"
SIGNAL_QUEUE_SCHEMA = "lightbulb.company_signal_queue.v1"
MAX_PENDING_SIGNALS = 128
MAX_SIGNALS_PER_TICK = 32
MAX_JOURNAL_BYTES = 512 * 1024
# Completion adds bounded case/command reports plus status and host metadata.
# Refuse insufficient headroom before accepting work or writing engine state.
RESULT_RESERVE_BYTES = 4096
ORIGIN_PREFIX = "signal-intent-origin:"


class SignalIntentExecutionError(ValueError):
    """A signal cannot be materialized without explicit reconciliation."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class IntentExecutionResult(StrictModel):
    intent_index: int = Field(ge=0)
    kind: Literal["open_retention_case"] = "open_retention_case"
    entity_ref: OpaqueRef
    outcome: Literal["applied", "existing", "blocked"]
    state_digest: str | None = None
    case_status: str | None = None
    blocker: str | None = None
    provider_effect_executed: Literal[False] = False
    revenue_verified: Literal[False] = False


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise SignalIntentExecutionError(code)


@dataclass
class CompanySignalIntentExecutor:
    """Use with the runner and authenticated journal returned by build_worker.

    ``fence`` is the current cadence lease-renewal callback and is required at
    every mutation. Tests may use the same in-memory stores and a local fence.
    The original signal identity, not consumption time, owns deduplication.
    """

    runner: Any
    gateway: Any
    capability_waits: Any = None

    @property
    def queue_ref(self) -> str:
        return "signal-intents-" + stable_digest({
            "scope": self.runner.bundle.scope, "bundle_digest": self.runner.bundle.plan_digest,
        })[:40]

    def _identity(self, signal: CompanySignal) -> str:
        return "signal-" + stable_digest({
            "bundle_digest": self.runner.bundle.plan_digest,
            "scope": self.runner.bundle.scope,
            "signal": signal.to_dict(),
        })

    def _write(self, ref: str, document: Mapping[str, Any], old: Any, fence: Callable[[], None], *, reserve_bytes: int = 0) -> dict[str, Any]:
        _require(len(json.dumps(detached(document), ensure_ascii=True).encode()) + reserve_bytes <= MAX_JOURNAL_BYTES,
                 "SIGNAL_JOURNAL_TOO_LARGE")
        fence()
        return dict(self.gateway.put(ref, document, expected_revision=int(old["revision"]) if old else 0))

    def _queue(self) -> dict[str, Any] | None:
        queue = self.gateway.get(self.queue_ref)
        if queue is not None:
            _require(queue.get("schema") == SIGNAL_QUEUE_SCHEMA
                     and queue.get("bundle_digest") == self.runner.bundle.plan_digest
                     and queue.get("scope") == self.runner.bundle.scope,
                     "SIGNAL_QUEUE_SCOPE_MISMATCH")
            refs = queue.get("pending")
            _require(isinstance(refs, list) and len(refs) <= MAX_PENDING_SIGNALS
                     and len(refs) == len(set(refs)), "SIGNAL_QUEUE_INVALID")
        return queue

    def _journal(self, ref: str) -> dict[str, Any] | None:
        journal = self.gateway.get(ref)
        if journal is not None:
            _require(journal.get("schema") == SIGNAL_EXECUTION_SCHEMA
                     and journal.get("bundle_digest") == self.runner.bundle.plan_digest
                     and journal.get("scope") == self.runner.bundle.scope,
                     "SIGNAL_JOURNAL_SCOPE_MISMATCH")
            signal = CompanySignal.model_validate(journal["signal"])
            _require(self._identity(signal) == ref and journal.get("signal_ref") == ref,
                     "SIGNAL_JOURNAL_IDENTITY_MISMATCH")
        return journal

    def _queue_add(self, ref: str, fence: Callable[[], None]) -> None:
        for _ in range(3):
            old = self._queue()
            refs = list(old["pending"]) if old else []
            if ref in refs:
                return
            _require(len(refs) < MAX_PENDING_SIGNALS, "SIGNAL_QUEUE_FULL")
            try:
                self._write(self.queue_ref, {
                    "schema": SIGNAL_QUEUE_SCHEMA, "status": "RUNNING",
                    "scope": dict(self.runner.bundle.scope),
                    "bundle_digest": self.runner.bundle.plan_digest,
                    "pending": [*refs, ref],
                }, old, fence)
                return
            except CheckpointConflict:
                continue
        raise CheckpointConflict("signal queue changed during enqueue; retry the original signal")

    def enqueue(self, signal: CompanySignal | Mapping[str, Any], *, now: str, fence: Callable[[], None]) -> dict[str, Any]:
        """Retain a signal for the next leased tick; this does not create a case."""
        source = CompanySignal.model_validate(detached(signal))
        at = timestamp(now, field_name="now")
        _require(parsed(source.emitted_at) <= parsed(at), "SIGNAL_FROM_FUTURE")
        ref = self._identity(source)
        journal = self._journal(ref)
        if journal is None:
            bundle = self.runner.bundle
            states = detached(self.runner.states())
            consumption = consume_signal(bundle.operating_plan, source, states=states, now=at)
            command_plans, deferred_commands = prepare_signal_commands(self.runner, source, consumption, states,
                signal_ref=ref, now=at)
            plans, deferred = self._prepare_intents(consumption, ref=ref, at=at)
            journal = {
                "schema": SIGNAL_EXECUTION_SCHEMA, "status": "RUNNING",
                "signal_ref": ref, "signal": source.to_dict(), "scope": dict(bundle.scope),
                "bundle_digest": bundle.plan_digest, "enqueued_at": at,
                "consumption": consumption.to_dict(), "plans": plans,
                "results": [], "deferred_intents": deferred,
                "command_plans": command_plans, "command_results": [], "deferred_commands": deferred_commands,
                "execution_status": "queued", "provider_effect_executed": False,
                "revenue_verified": False,
            }
            try:
                journal = self._write(ref, journal, None, fence,
                    reserve_bytes=1024 + RESULT_RESERVE_BYTES * (len(plans) + len(command_plans)))
            except CheckpointConflict:
                journal = self._journal(ref)
                if journal is None:
                    raise
        if journal["execution_status"] in {"queued", "blocked"}:
            self._queue_add(ref, fence)
        return self._report(journal)

    def _prepare_intents(self, consumption, *, ref, at):
        bundle = self.runner.bundle
        plans = []
        deferred = []
        for index, intent in enumerate(consumption.intents):
            if intent.kind != "open_retention_case" or intent.engine != "service_delivery":
                deferred.append(intent.to_dict())
                continue
            account = intent.payload["customer_ref"]
            entity_ref = "retention-" + stable_digest({"scope": bundle.scope, "account": account})[:40]
            candidate = None
            if bundle.service_delivery_plan is not None:
                candidate = open_case(
                    bundle.service_delivery_plan, bundle.engine_scope(entity_ref),
                    case_ref=entity_ref, customer_ref=account,
                    channel=intent.payload["channel"], subject=intent.payload["subject"],
                    opened_at=at, actor_ref=bundle.actor_ref,
                    evidence_refs=(ORIGIN_PREFIX + ref,),
                ).to_dict()
            plans.append({"intent_index": index, "entity_ref": entity_ref,
                          "intent": intent.to_dict(), "opening_state": candidate})
        return plans, deferred

    def _resume_deferred(self, journal, fence):
        """Recompile only never-admitted work; retained commands never rebase."""
        from lightbulb.company_signal_consumers import SignalConsumption
        consumption = SignalConsumption.model_validate(journal["consumption"])
        plans, deferred = self._prepare_intents(consumption, ref=journal["signal_ref"], at=journal["enqueued_at"])
        commands, deferred_commands = prepare_signal_commands(self.runner, consumption.signal, consumption,
            detached(self.runner.states()), signal_ref=journal["signal_ref"], now=journal["enqueued_at"])
        existing_intents = {p["intent_index"]: p for p in journal["plans"]}
        existing_commands = {p["command_index"]: p for p in journal["command_plans"]}
        # Previous admitted plans win even if current planning would change their CAS source.
        merged_plans = {p["intent_index"]: p for p in plans}
        merged_plans.update(existing_intents)
        merged_commands = {p["command_index"]: p for p in commands}
        merged_commands.update(existing_commands)
        deferred = [r for r in deferred if r not in [p["intent"] for p in existing_intents.values()]]
        deferred_commands = [r for r in deferred_commands if r not in [p["consumer_command"] for p in existing_commands.values()]]
        return self._write(journal["signal_ref"], {**journal, "plans": list(merged_plans.values()),
            "command_plans": list(merged_commands.values()), "deferred_intents": deferred,
            "deferred_commands": deferred_commands, "execution_status": "queued", "status": "RUNNING"}, journal, fence)

    def _state(self, runtime: Any, entity_ref: str) -> Any:
        state = runtime.load(entity_ref)
        expected = self.runner.bundle.engine_scope(entity_ref)
        _require(state.scope.to_dict() == expected, "SIGNAL_CASE_SCOPE_MISMATCH")
        return state

    def _origin(self, state: Any, target: str) -> tuple[dict[str, Any], dict[str, Any]]:
        receipt = state.transition_history[0].command.receipt
        origins = [value[len(ORIGIN_PREFIX):] for value in receipt.evidence_refs if value.startswith(ORIGIN_PREFIX)]
        _require(len(origins) == 1, "SIGNAL_CASE_ORIGIN_MISSING")
        source = self._journal(origins[0])
        _require(source is not None, "SIGNAL_CASE_ORIGIN_MISSING")
        matches = [plan for plan in source["plans"] if plan["entity_ref"] == target]
        _require(len(matches) == 1 and matches[0]["opening_state"] is not None, "SIGNAL_CASE_ORIGIN_MISMATCH")
        intended = CASE_LIFECYCLE.State.model_validate(matches[0]["opening_state"],
                    context={CASE_LIFECYCLE.plan_context_key: self.runner.bundle.service_delivery_plan})
        _require(detached(state.transition_history[0]) == detached(intended.transition_history[0]),
                 "SIGNAL_CASE_ORIGIN_MISMATCH")
        return source, matches[0]

    def _materialize(self, journal: Mapping[str, Any], plan: Mapping[str, Any], fence: Callable[[], None]) -> IntentExecutionResult:
        ref = plan["entity_ref"]
        runtime = self.runner.runtimes.get("service_delivery")
        _require(runtime is not None and plan["opening_state"] is not None, "SIGNAL_SERVICE_RUNTIME_MISSING")
        record = runtime.store.get("service_delivery", ref)
        created = record is None
        if record is None:
            intended = CASE_LIFECYCLE.State.model_validate(plan["opening_state"],
                        context={CASE_LIFECYCLE.plan_context_key: runtime.plan})
            fence()
            try:
                runtime.open(ref, intended)
            except EngineStateConflictError:
                # A competing creation is admissible only after exact origin verification.
                if runtime.store.get("service_delivery", ref) is None:
                    raise
                created = False
        state = self._state(runtime, ref)
        origin, original_plan = self._origin(state, ref)
        _require(state.ledger.customer_ref == plan["intent"]["payload"]["customer_ref"],
                 "SIGNAL_CASE_CUSTOMER_MISMATCH")
        _require(state.status != "closed" or origin["signal_ref"] == journal["signal_ref"],
                 "SIGNAL_RETENTION_EPISODE_CLOSED")
        if state.status == "intaken":
            original = original_plan["intent"]["payload"]
            key = "classify:" + origin["signal_ref"]
            command = runtime.command(state, event="classify", transition_ref=key, idempotency_key=key,
                occurred_at=origin["enqueued_at"], actor_ref=self.runner.bundle.actor_ref,
                receipt={"severity": original["severity"], "classification_ref": key})
            fence()
            outcome = runtime.advance_and_persist(ref, command)
            _require(outcome.persisted, "SIGNAL_CASE_CLASSIFICATION_REFUSED")
            state = self._state(runtime, ref)
        return IntentExecutionResult(intent_index=plan["intent_index"], entity_ref=ref,
            outcome="applied" if created else "existing", state_digest=state.state_digest, case_status=state.status)

    def _execute(self, journal: dict[str, Any], fence: Callable[[], None]) -> dict[str, Any]:
        if journal["execution_status"] in {"completed", "partial"}:
            return journal
        command_results = [execute_signal_command(self.runner, journal, plan, fence).to_dict()
                           for plan in journal.get("command_plans", ())]
        results = []
        for plan in journal["plans"]:
            try:
                result = self._materialize(journal, plan, fence)
            except SignalIntentExecutionError as exc:
                result = IntentExecutionResult(intent_index=plan["intent_index"], entity_ref=plan["entity_ref"],
                    outcome="blocked", blocker=exc.code)
            results.append(result.to_dict())
        blocked = any(result["outcome"] == "blocked" for result in (*results, *command_results))
        deferred = bool(journal["deferred_intents"] or journal["deferred_commands"])
        status = "blocked" if blocked else "partial" if deferred else "completed"
        return self._write(journal["signal_ref"], {**journal, "results": results, "command_results": command_results,
            "execution_status": status, "status": "RUNNING" if blocked else "COMPLETED"}, journal, fence)

    def _report(self, journal: Mapping[str, Any]) -> dict[str, Any]:
        report = {key: detached(journal[key]) for key in (
            "schema", "signal_ref", "execution_status", "results", "deferred_intents",
            "deferred_commands", "provider_effect_executed", "revenue_verified",
        )}
        return {**report, "command_results": detached(journal.get("command_results", []))}

    def report(self, signal_ref: str) -> dict[str, Any]:
        journal = self._journal(signal_ref)
        if journal is None:
            raise LookupError(signal_ref)
        return self._report(journal)

    def drain(self, *, now: str, fence: Callable[[], None]) -> dict[str, Any]:
        """Execute a bounded batch under the host lease, retaining every refusal."""
        timestamp(now, field_name="now")
        queue = self._queue()
        if queue is None or not queue["pending"]:
            return {"reports": [], "pending": 0, "applied": 0, "deferred": 0}
        refs = list(queue["pending"][:MAX_SIGNALS_PER_TICK])
        reports, finished = [], set()
        for ref in refs:
            journal = self._journal(ref)
            _require(journal is not None, "SIGNAL_QUEUE_JOURNAL_MISSING")
            if self.capability_waits and not self.capability_waits.begin("operations", ref, stable_digest(journal["signal"]), now=now, fence=fence):
                reports.append({**self._report(journal), "capability_waiting": True})
                continue
            if self.capability_waits and journal["execution_status"] == "partial":
                wait = (self.capability_waits._read() or {}).get("entries", {}).get(self.capability_waits._key("operations", ref))
                if wait and wait["phase"] == "resuming":
                    journal = self._resume_deferred(journal, self.capability_waits.owner_fence("operations", ref, now=now, fence=fence))
            journal = self._execute(journal, self.capability_waits.owner_fence("operations", ref, now=now, fence=fence) if self.capability_waits else fence)
            reports.append(self._report(journal))
            if self.capability_waits and journal["execution_status"] != "completed":
                from lightbulb.sdk_capability_assessment import diagnose_owner_blocker
                diagnose_owner_blocker(self.capability_waits, "operations", ref, self._report(journal), now=now, fence=fence)
            if self.capability_waits:
                self.capability_waits.finish("operations", ref, complete=journal["execution_status"] == "completed",
                    terminal=journal["execution_status"] == "partial", reason="deferred_intents_need_review" if journal["execution_status"] == "partial" else None, fence=fence)
            waiting = self.capability_waits and self.capability_waits.development.blocks("operations", ref)
            if journal["execution_status"] in {"completed", "partial"} and not waiting:
                finished.add(ref)
        # Reload and CAS so concurrent enqueue never disappears. Rotate blocked
        # entries behind untouched work so one missing prerequisite cannot starve it.
        for _ in range(3):
            current = self._queue()
            pending = [ref for ref in current["pending"] if ref not in finished]
            pending = [ref for ref in pending if ref not in refs] + [ref for ref in pending if ref in refs]
            try:
                self._write(self.queue_ref, {**current, "pending": pending}, current, fence)
                break
            except CheckpointConflict:
                continue
        else:
            raise CheckpointConflict("signal queue changed during drain; retained journals can be replayed")
        return {"reports": reports, "pending": len(pending),
                "applied": sum(result["outcome"] in {"applied", "existing"} for report in reports
                               for result in (*report["results"], *report["command_results"])),
                "deferred": sum(len(report["deferred_intents"]) + len(report["deferred_commands"]) for report in reports)}


__all__ = ["CompanySignalIntentExecutor", "IntentExecutionResult", "SignalIntentExecutionError"]
