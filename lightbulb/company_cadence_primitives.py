"""Executable primitives for the operating cadence runner.

``company.plan_cadence_tick`` is the pure planner: from a cadence bundle,
the persisted engine state records, and a clock it returns the next legal
moves (automatic actions) and the typed work items whose inputs are missing.
``company.advance_cadence`` materializes one replay-fenced cadence
transition (start, tick, pause, resume, stop).  Read-only; the runner never
invents an input and Spring authorizes every effect the work items ask for.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import Field, field_validator

from lightbulb.company_cadence_runner import (
    CADENCE_GOLDEN_LOOP,
    CADENCE_KIND,
    CADENCE_MANIFEST,
    CadenceBundle,
    CadenceCommand,
    CadenceState,
    CadenceTickPlan,
    CadenceTransitionResult,
    advance_cadence,
    build_bundle,
    plan_cadence_tick,
    seal_cadence_command,
    start_cadence,
)
from lightbulb.company_engine_core import OpaqueRef, StrictModel, timestamp
from lightbulb.company_engine_primitives_base import EXAMPLE_ACTOR, EXAMPLE_SCOPE, EnginePrimitive, LazyExample, RequestScope, read_spec, request_digest, scope_matches
from lightbulb.company_operating_system import compile_company_operating_blueprint, open_period
from lightbulb.finance_close_engine import compile_finance_close_blueprint
from lightbulb.primitive_runtime import BusinessProcessPrimitive, PrimitiveExecutionContext, PrimitiveExecutionResult


class PlanCadenceTickInput(StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    bundle: CadenceBundle
    states: dict[str, tuple[dict[str, Any], ...]] = Field(default_factory=dict)
    now: str

    @field_validator("states", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        if isinstance(value, dict):
            return {str(key): tuple(item) if isinstance(item, (list, tuple)) else item for key, item in value.items()}
        if isinstance(value, list):
            return tuple(value)
        return value

    @field_validator("now")
    @classmethod
    def _now(cls, value: str) -> str:
        return timestamp(value, field_name="now")


class AdvanceCadenceInput(StrictModel):
    bundle: CadenceBundle
    state: CadenceState  # type: ignore[valid-type]
    command: CadenceCommand  # type: ignore[valid-type]


class _Examples:
    def __init__(self) -> None:
        self._built: dict[str, Any] | None = None

    def get(self) -> dict[str, Any]:
        if self._built is not None:
            return self._built
        plan = compile_company_operating_blueprint("b2b_saas")
        bundle = build_bundle({"company_ref": "company-example", "scope": {key: value for key, value in EXAMPLE_SCOPE.items() if key in ("tenant_ref", "company_ref", "project_ref", "project_id")}, "actor_ref": EXAMPLE_ACTOR, "operating_plan": plan.to_dict(), "finance_close_plan": compile_finance_close_blueprint("weekly_close").to_dict(), "ledger_ref": "ledger-example", "preparer_ref": "preparer-example", "start_at": "2026-10-05T00:00:00Z"})
        period = open_period(plan, bundle.engine_scope("company-example:period:0001"), period_start="2026-10-05T00:00:00Z", opened_at="2026-10-05T00:00:00Z", actor_ref=EXAMPLE_ACTOR)
        record = {"schema": "lightbulb.sdk_engine_state_record.v1", "engine": "company_operating_system", "entity_ref": "company-example:period:0001", "status": period.status, "plan_digest": plan.plan_digest, "version": period.version, "state_digest": period.state_digest, "state": period.to_dict()}
        cadence = start_cadence(bundle, started_at="2026-10-05T00:00:00Z")
        command = seal_cadence_command({"event": "pause", "transition_ref": "pause:company-example", "idempotency_key": "company-example:pause", "expected_version": cadence.version, "expected_state_digest": cadence.state_digest, "occurred_at": "2026-10-05T01:00:00Z", "actor_ref": EXAMPLE_ACTOR, "receipt": {}, "reason": "Operator review"})
        self._built = {
            "plan": {"scope": EXAMPLE_SCOPE, "requested_by_ref": EXAMPLE_ACTOR, "bundle": bundle.to_dict(), "states": {"company_operating_system": [record]}, "now": "2026-10-06T00:00:00Z"},
            "advance": {"bundle": bundle.to_dict(), "state": cadence.to_dict(), "command": command},
        }
        return self._built


_EXAMPLES = _Examples()


def example_cadence_inputs() -> dict[str, Any]:
    return {key: dict(value) for key, value in _EXAMPLES.get().items()}


class _CadencePrimitive(EnginePrimitive[Any, Any]):
    golden_loop = CADENCE_GOLDEN_LOOP
    engine = CADENCE_KIND
    loop_stages = tuple(CADENCE_MANIFEST["stages"])
    profiles = ("b2b_saas", "dtc_commerce", "services_firm", "marketplace")
    hard_rules = {"never_invents_an_input": True, "automatic_actions_only_from_held_inputs": True, "replans_above_threshold_wait_for_bound_approval": True, "every_tick_is_a_fenced_transition": True, "no_dispatch_send_post_or_spend_here": True}
    authority_boundary = {"agent": "supplies receipts and observations for work items", "sdk": "plans ticks, applies legal moves, raises work items, records ticks", "spring": "persists engine states, authorizes dispatches, decides approvals", "connectors": "produce the sealed reads and executions the work items need", "mcp": "projects these primitives"}


class PlanCadenceTickPrimitive(_CadencePrimitive):
    primitive_ref = "company.plan_cadence_tick"
    version = "0.1.0"
    title = "Plan the next cadence tick for a company"
    description = "From the cadence bundle, the persisted engine state records, and a clock: the automatic actions the runner may apply now (open a period, open the close, reconcile on a verified-books proof, replan inside the threshold, close) and the typed work items whose inputs are missing (dispatch receipts, sealed observations, close steps, approvals, overdue cases)."
    input_model = PlanCadenceTickInput
    output_model = CadenceTickPlan
    risk_level = "low"
    operation_spec = read_spec("company_plan_cadence_tick", "sdk.company.plan_cadence_tick")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "plan")

    def _execute(self, context: PrimitiveExecutionContext, inputs: PlanCadenceTickInput) -> PrimitiveExecutionResult[CadenceTickPlan]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            tick = plan_cadence_tick(inputs.bundle, {engine: list(records) for engine, records in inputs.states.items()}, now=inputs.now)
        except ValueError as exc:
            return self.blocked(digest=digest, code="STATES_INVALID", message=str(exc))
        return self.preview(output=tick, digest=digest, external_refs={"tick_plan_digest": tick.plan_digest, "bundle_digest": tick.bundle_digest}, event_type="company.cadence_tick_planned", event_payload={"period_ref": tick.period_ref, "period_status": tick.period_status, "automatic": len(tick.automatic), "work_items": len(tick.work_items)}, evidence_kind="company_cadence_tick_plan", evidence_summary="Tick plan; nothing applied.", summary=f"{len(tick.automatic)} automatic action(s), {len(tick.work_items)} work item(s)" + (f" for {tick.period_ref} ({tick.period_status})" if tick.period_ref else "") + ".")


class AdvanceCadencePrimitive(_CadencePrimitive):
    primitive_ref = "company.advance_cadence"
    version = "0.1.0"
    title = "Advance the cadence lifecycle by one transition"
    description = "Materialize one replay-fenced cadence transition: start against the exact bundle, record a tick (its plan and result digests and counts, clock advancing), pause, resume, stop."
    input_model = AdvanceCadenceInput
    output_model = CadenceTransitionResult
    risk_level = "low"
    operation_spec = read_spec("company_advance_cadence", "sdk.company.advance_cadence")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "advance")

    def _execute(self, context: PrimitiveExecutionContext, inputs: AdvanceCadenceInput) -> PrimitiveExecutionResult[CadenceTransitionResult]:
        digest = request_digest(inputs.to_dict())
        scope = inputs.state.scope
        if not scope_matches(RequestScope.from_engine_scope(scope), inputs.command.actor_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and acting actor must exactly match the cadence scope and the command.")
        try:
            result = advance_cadence(inputs.bundle, inputs.state, inputs.command)
        except ValueError as exc:
            return self.blocked(digest=digest, code="STATE_NOT_BOUND", message=str(exc))
        return self.transition_preview(result=result, digest=digest, entity_ref=scope.entity_ref, event_prefix="company_cadence")


CADENCE_EXECUTABLE_PRIMITIVES: tuple[BusinessProcessPrimitive[Any, Any], ...] = (
    PlanCadenceTickPrimitive(),
    AdvanceCadencePrimitive(),
)

CADENCE_INTEGRATION_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.capability_pack_integration_manifest.v1",
    "capability_pack": "company_cadence_runner",
    "golden_loop": CADENCE_GOLDEN_LOOP,
    "engine": CADENCE_MANIFEST,
    "modules": {"domain": "lightbulb.company_cadence_runner", "primitives": "lightbulb.company_cadence_primitives", "store": "lightbulb.company_engine_store", "core": "lightbulb.company_engine_core"},
    "reuses": ["company_operating_system period lifecycle", "finance_close verify_books", "company_workforce plan_dispatch", "service_delivery case states", "company_execution_bridge approvals", "sdk_engine_states persistence"],
    "required_connectors": CADENCE_MANIFEST["required_connectors"],
    "primitive_refs": [item.primitive_ref for item in CADENCE_EXECUTABLE_PRIMITIVES],
    "non_goals": ["no input invented; no dispatch, send, post, or spend here", "no certification or production-readiness claim"],
}

__all__ = [
    "CADENCE_EXECUTABLE_PRIMITIVES",
    "CADENCE_INTEGRATION_MANIFEST",
    "AdvanceCadenceInput",
    "AdvanceCadencePrimitive",
    "PlanCadenceTickInput",
    "PlanCadenceTickPrimitive",
    "example_cadence_inputs",
]
