"""Freeze and execute churn-triggered prospect suppression without rebasing.

The authenticated signal journal owns custody. These helpers reuse the prospect
lifecycle and scoped engine runtime; they never write a provider suppression list.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any, Literal

from pydantic import Field

from lightbulb.company_engine_core import OpaqueRef, StrictModel, detached, stable_digest
from lightbulb.company_engine_store import EngineStateConflictError
from lightbulb.pipeline_engine_loop import PROSPECT_LIFECYCLE


class SignalCommandExecutionResult(StrictModel):
    command_index: int = Field(ge=0)
    engine: Literal["pipeline_engine"] = "pipeline_engine"
    entity_ref: OpaqueRef
    event: Literal["suppress"] = "suppress"
    outcome: Literal["applied", "existing", "blocked"]
    state_digest: str | None = None
    prospect_status: str | None = None
    blocker: str | None = None
    provider_effect_executed: Literal[False] = False
    revenue_verified: Literal[False] = False


class _CommandBlocked(ValueError):
    pass


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise _CommandBlocked(code)


def _sealed_command(source: Any, consumer: Mapping[str, Any], *, signal_ref: str,
                    index: int, now: str, actor_ref: str) -> dict[str, Any]:
    key = "signal-suppress:" + stable_digest({"signal_ref": signal_ref, "command_index": index})
    return PROSPECT_LIFECYCLE.seal_command({
        "event": "suppress", "transition_ref": key, "idempotency_key": key,
        "expected_version": source.version, "expected_state_digest": source.state_digest,
        "occurred_at": now, "actor_ref": actor_ref,
        "receipt": consumer.get("receipt", {}), "reason": consumer.get("reason"),
    })


def prepare_signal_commands(runner: Any, signal: Any, consumption: Any, states: Mapping[str, Any],
                            *, signal_ref: str, now: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Use the same immutable snapshot as consumption; never reload during planning."""
    plans, deferred = [], []
    for index, consumer in enumerate(consumption.commands):
        if (signal.name, consumer.engine, consumer.event) != ("signals.churn_risk", "pipeline_engine", "suppress"):
            deferred.append(consumer.to_dict())
            continue
        matches = [record.get("state", record) for record in states.get("pipeline_engine", ())
                   if record.get("state", record).get("scope", {}).get("entity_ref") == consumer.entity_ref]
        source = PROSPECT_LIFECYCLE.State.model_validate(matches[0]) if len(matches) == 1 else None
        plans.append({
            "command_index": index, "engine": "pipeline_engine", "event": "suppress",
            "entity_ref": consumer.entity_ref, "signal_ref": signal_ref,
            "account_ref": str(signal.payload["account_ref"]),
            "scope": runner.bundle.engine_scope(consumer.entity_ref),
            "consumer_command": consumer.to_dict(),
            "source_state": source.to_dict() if source is not None else None,
            "command": _sealed_command(source, consumer.to_dict(), signal_ref=signal_ref,
                index=index, now=now, actor_ref=runner.bundle.actor_ref) if source is not None else None,
        })
    return plans, deferred


def _bound_plan(runner: Any, journal: Mapping[str, Any], plan: Mapping[str, Any]) -> tuple[Any, Any, dict[str, Any]]:
    ref = plan["entity_ref"]
    _require((journal["signal"]["name"], plan["engine"], plan["event"]) ==
             ("signals.churn_risk", "pipeline_engine", "suppress"), "SIGNAL_COMMAND_NOT_SUPPORTED")
    _require(plan["signal_ref"] == journal["signal_ref"] and
             plan["account_ref"] == str(journal["signal"]["payload"]["account_ref"]), "SIGNAL_COMMAND_IDENTITY_MISMATCH")
    _require(plan["scope"] == runner.bundle.engine_scope(ref), "SIGNAL_COMMAND_SCOPE_MISMATCH")
    consumer = journal["consumption"]["commands"][plan["command_index"]]
    _require(consumer == plan["consumer_command"] and
             (consumer["engine"], consumer["entity_ref"], consumer["event"]) ==
             ("pipeline_engine", ref, "suppress"), "SIGNAL_COMMAND_IDENTITY_MISMATCH")
    runtime = runner.runtimes.get("pipeline_engine")
    _require(runtime is not None, "SIGNAL_COMMAND_RUNTIME_MISSING")
    _require(plan["source_state"] is not None and plan["command"] is not None, "SIGNAL_COMMAND_SOURCE_MISSING")
    _require(plan["source_state"]["plan_digest"] == runtime.plan.plan_digest, "SIGNAL_COMMAND_PLAN_MISMATCH")
    source = PROSPECT_LIFECYCLE.State.model_validate(plan["source_state"],
        context={PROSPECT_LIFECYCLE.plan_context_key: runtime.plan})
    _require(source.scope.to_dict() == plan["scope"], "SIGNAL_COMMAND_SCOPE_MISMATCH")
    _require(source.ledger.account_ref == plan["account_ref"], "SIGNAL_COMMAND_ACCOUNT_MISMATCH")
    command = _sealed_command(source, consumer, signal_ref=journal["signal_ref"], index=plan["command_index"],
        now=journal["enqueued_at"], actor_ref=runner.bundle.actor_ref)
    _require(command == plan["command"], "SIGNAL_COMMAND_IDENTITY_MISMATCH")
    return runtime, source, command


def _current(runtime: Any, plan: Mapping[str, Any]) -> Any:
    record = runtime.store.get("pipeline_engine", plan["entity_ref"])
    _require(record is not None, "SIGNAL_COMMAND_SOURCE_MISSING")
    _require(record["state"]["plan_digest"] == runtime.plan.plan_digest, "SIGNAL_COMMAND_PLAN_MISMATCH")
    state = PROSPECT_LIFECYCLE.State.model_validate(record["state"],
        context={PROSPECT_LIFECYCLE.plan_context_key: runtime.plan})
    _require(state.scope.to_dict() == plan["scope"], "SIGNAL_COMMAND_SCOPE_MISMATCH")
    _require(state.ledger.account_ref == plan["account_ref"], "SIGNAL_COMMAND_ACCOUNT_MISMATCH")
    return state


def _retained(state: Any, command: Mapping[str, Any]) -> bool:
    for transition in state.transition_history:
        prior = detached(transition.command)
        if prior == command:
            return True
        _require(prior["transition_ref"] != command["transition_ref"] and
                 prior["idempotency_key"] != command["idempotency_key"], "SIGNAL_COMMAND_IDEMPOTENCY_CONFLICT")
    return False


def execute_signal_command(runner: Any, journal: Mapping[str, Any], plan: Mapping[str, Any],
                           fence: Callable[[], None]) -> SignalCommandExecutionResult:
    """Only the retained command may be applied; CAS races never authorize a rebase."""
    identity = {"command_index": plan["command_index"], "entity_ref": plan["entity_ref"]}
    try:
        runtime, source, command = _bound_plan(runner, journal, plan)
        state = _current(runtime, plan)
        existing = _retained(state, command)
        if not existing:
            _require((state.version, state.state_digest) == (source.version, source.state_digest), "SIGNAL_COMMAND_SOURCE_CHANGED")
            fence()
            try:
                outcome = runtime.advance_and_persist(plan["entity_ref"], command)
            except EngineStateConflictError:
                state = _current(runtime, plan)
                _require(_retained(state, command), "SIGNAL_COMMAND_SOURCE_CHANGED")
                existing = True
            else:
                if not outcome.persisted:
                    state = _current(runtime, plan)
                    existing = _retained(state, command)
                    if not existing:
                        _require((state.version, state.state_digest) == (source.version, source.state_digest), "SIGNAL_COMMAND_SOURCE_CHANGED")
                        raise _CommandBlocked(outcome.result.receipt.rejection_code or "SIGNAL_COMMAND_REFUSED")
                state = _current(runtime, plan)
                _require(_retained(state, command), "SIGNAL_COMMAND_NOT_RETAINED")
        return SignalCommandExecutionResult(**identity, outcome="existing" if existing else "applied",
            state_digest=state.state_digest, prospect_status=state.status)
    except _CommandBlocked as exc:
        return SignalCommandExecutionResult(**identity, outcome="blocked", blocker=str(exc))


__all__ = ["SignalCommandExecutionResult", "prepare_signal_commands", "execute_signal_command"]
