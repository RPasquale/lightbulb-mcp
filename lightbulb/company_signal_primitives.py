"""Executable primitive for signal consumption: ``company.consume_signal``.

Routes one typed cross-loop signal through the operating plan and returns
the sealed consumption: exact engine commands the signal justifies (applied
through the engines' own fences) and typed intents for the plans and
primitives that follow.  Read-only; nothing here pauses, suppresses, opens,
or spends.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import Field, field_validator

from lightbulb.company_engine_core import OpaqueRef, StrictModel, timestamp
from lightbulb.company_engine_primitives_base import EXAMPLE_ACTOR, EXAMPLE_SCOPE, EnginePrimitive, LazyExample, RequestScope, read_spec, request_digest, scope_matches
from lightbulb.company_operating_system import COMPANY_OS_GOLDEN_LOOP, CompanyOperatingPlan, CompanySignal, compile_company_operating_blueprint
from lightbulb.company_signal_consumers import SignalConsumption, consume_signal
from lightbulb.primitive_runtime import BusinessProcessPrimitive, PrimitiveExecutionContext, PrimitiveExecutionResult

SIGNAL_CONSUMER_STAGES: tuple[str, ...] = ("route", "consume", "apply", "learn")


class ConsumeSignalInput(StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    plan: CompanyOperatingPlan
    signal: CompanySignal
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


class _Examples:
    def __init__(self) -> None:
        self._built: dict[str, Any] | None = None

    def get(self) -> dict[str, Any]:
        if self._built is not None:
            return self._built
        plan = compile_company_operating_blueprint("b2b_saas")
        self._built = {"consume": {"scope": EXAMPLE_SCOPE, "requested_by_ref": EXAMPLE_ACTOR, "plan": plan.to_dict(), "signal": {"name": "signals.churn_risk", "producer": "saas_operating_engine", "emitted_at": "2026-10-06T00:00:00Z", "payload": {"account_ref": "account-example-1", "mrr_at_risk": "199.00", "inactive_days": 30}}, "states": {}, "now": "2026-10-06T00:00:00Z"}}
        return self._built


_EXAMPLES = _Examples()


def example_signal_consumer_inputs() -> dict[str, Any]:
    return {key: dict(value) for key, value in _EXAMPLES.get().items()}


class ConsumeSignalPrimitive(EnginePrimitive[Any, Any]):
    primitive_ref = "company.consume_signal"
    version = "0.1.0"
    title = "Consume a cross-loop signal into engine commands and intents"
    description = "Route one typed signal (churn risk, rolled-back release, exhausted envelope, qualified pipeline, expansion candidate, verified books, resolved case, company formed, attributed revenue) and return the exact engine transitions it justifies from the persisted states plus typed intents for the plans and primitives that follow; never over-acts without the payload naming what is affected."
    input_model = ConsumeSignalInput
    output_model = SignalConsumption
    risk_level = "medium"
    operation_spec = read_spec("company_consume_signal", "sdk.company.consume_signal")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "consume")
    golden_loop = COMPANY_OS_GOLDEN_LOOP
    engine = "company_operating_system"
    loop_stages = SIGNAL_CONSUMER_STAGES
    profiles = ("b2b_saas", "dtc_commerce", "services_firm", "marketplace")
    hard_rules = {"commands_only_for_entities_the_signal_names": True, "review_intent_instead_of_blanket_action": True, "consent_before_expansion_outreach": True, "no_pause_suppress_open_or_spend_here": True}
    authority_boundary = {"agent": "raises and relays signals", "sdk": "routes, derives commands and intents", "spring": "authorizes the effects behind commands and intents", "connectors": "none", "mcp": "projects this primitive"}

    def _execute(self, context: PrimitiveExecutionContext, inputs: ConsumeSignalInput) -> PrimitiveExecutionResult[SignalConsumption]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            consumption = consume_signal(inputs.plan, inputs.signal, states={engine: list(records) for engine, records in inputs.states.items()}, now=inputs.now)
        except ValueError as exc:
            return self.blocked(digest=digest, code="SIGNAL_INVALID", message=str(exc))
        return self.preview(output=consumption, digest=digest, external_refs={"consumption_digest": consumption.consumption_digest, "routing_digest": consumption.routing_digest}, event_type="company.signal_consumed", event_payload={"signal": consumption.signal.name, "commands": len(consumption.commands), "intents": [item.kind for item in consumption.intents]}, evidence_kind="company_signal_consumption", evidence_summary="Commands and intents; nothing applied.", summary=f"{consumption.signal.name}: {len(consumption.commands)} command(s), {len(consumption.intents)} intent(s) across {', '.join(consumption.consumers)}.")


SIGNAL_CONSUMER_EXECUTABLE_PRIMITIVES: tuple[BusinessProcessPrimitive[Any, Any], ...] = (ConsumeSignalPrimitive(),)

SIGNAL_CONSUMER_INTEGRATION_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.capability_pack_integration_manifest.v1",
    "capability_pack": "company_signal_consumers",
    "golden_loop": COMPANY_OS_GOLDEN_LOOP,
    "engine": {"schema": "lightbulb.company_engine_manifest.v1", "engine": "company_signal_consumers", "golden_loop": COMPANY_OS_GOLDEN_LOOP, "stages": list(SIGNAL_CONSUMER_STAGES), "required_connectors": [], "hard_rules": ["commands only for the entities the signal names", "review intents instead of blanket action", "consent before expansion outreach", "nothing paused, suppressed, opened, or spent here"]},
    "modules": {"domain": "lightbulb.company_signal_consumers", "primitives": "lightbulb.company_signal_primitives", "core": "lightbulb.company_engine_core"},
    "reuses": ["company_operating_system route_signal", "growth_engine campaign lifecycle", "pipeline_engine prospect lifecycle", "service_delivery cases", "company_engine_store runtimes"],
    "required_connectors": [],
    "primitive_refs": [item.primitive_ref for item in SIGNAL_CONSUMER_EXECUTABLE_PRIMITIVES],
    "non_goals": ["no effect executed here", "no certification or production-readiness claim"],
}

__all__ = ["SIGNAL_CONSUMER_EXECUTABLE_PRIMITIVES", "SIGNAL_CONSUMER_INTEGRATION_MANIFEST", "ConsumeSignalInput", "ConsumeSignalPrimitive", "example_signal_consumer_inputs"]
