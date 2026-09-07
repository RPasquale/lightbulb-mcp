"""Scoped executable entry points for people, marketplace and engagement engines.

These registry entries delegate to the existing compilers and lifecycles.
An advance returns a candidate; persistence and provider effects remain with
the platform. Advance examples retain synthetic source histories and sealed
commands validated by the real lifecycles; they grant no hosted authority.
"""
from __future__ import annotations

from typing import Any, Literal
from pydantic import Field

from lightbulb.company_engine_core import OpaqueRef, StrictModel, detached, stable_digest
from lightbulb.company_engine_primitives_base import (
    EXAMPLE_ACTOR, EXAMPLE_SCOPE, EnginePrimitive, LazyExample, RequestScope,
    read_spec, request_digest, scope_matches,
)
from lightbulb.primitive_runtime import PrimitiveBlocker


class CompileRound5EngineInput(StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    company_ref: OpaqueRef
    operating_plan: dict[str, Any]
    profile: str = Field(min_length=1, max_length=80)
    overrides: dict[str, Any] = Field(default_factory=dict)


class Round5EngineInput(StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    plan: dict[str, Any]
    entity_kind: Literal["people_period", "seller", "listing", "transaction", "engagement"]
    states: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=500)
    command: dict[str, Any] | None = None


class Round5EngineOutput(StrictModel):
    engine: str
    operation: Literal["compile", "advance", "assess"]
    result: dict[str, Any]
    source_digests: tuple[str, ...] = ()
    effects_executed: Literal[False] = False


def _engine(engine: str) -> tuple[Any, Any, str]:
    if engine == "people_engine":
        from lightbulb import people_engine as module
        return module, module.compile_people_engine, "small_team"
    if engine == "marketplace_supply_engine":
        from lightbulb import marketplace_supply_engine as module
        return module, module.compile_marketplace_supply_engine, "two_sided_marketplace"
    from lightbulb import engagement_engine as module
    return module, module.compile_engagement_engine, "professional_services"


def _lifecycle(engine: str, kind: str) -> tuple[Any, Any]:
    module, _, _ = _engine(engine)
    choices = {
        "people_engine": {"people_period": ("PEOPLE_LIFECYCLE", "advance_people")},
        "marketplace_supply_engine": {key: (key.upper() + "_LIFECYCLE", "advance_" + key) for key in ("seller", "listing", "transaction")},
        "engagement_engine": {"engagement": ("ENGAGEMENT_LIFECYCLE", "advance_engagement")},
    }
    if kind not in choices[engine]:
        raise ValueError("ENTITY_KIND_MISMATCH: choose a lifecycle belonging to this engine")
    spec, advance = choices[engine][kind]
    return getattr(module, spec), getattr(module, advance)


class _Examples:
    def __init__(self, engine: str) -> None:
        self.engine = engine

    def get(self) -> dict[str, Any]:
        from copy import deepcopy
        from lightbulb._round5_example_sources import ROUND5_ADVANCE_EXAMPLES
        from lightbulb.company_operating_system import compile_company_operating_blueprint
        _, compile_engine, profile = _engine(self.engine)
        archetype = {"people_engine": "b2b_saas", "marketplace_supply_engine": "two_sided_marketplace", "engagement_engine": "services_firm"}[self.engine]
        operating = compile_company_operating_blueprint(archetype)
        plan = compile_engine("company-example", operating_plan=operating, profile=profile)
        scope = {"scope": EXAMPLE_SCOPE, "requested_by_ref": EXAMPLE_ACTOR}
        kind = {"people_engine": "people_period", "marketplace_supply_engine": "seller", "engagement_engine": "engagement"}[self.engine]
        return {
            "compile": {**scope, "company_ref": "company-example", "operating_plan": operating.to_dict(), "profile": profile},
            "advance": deepcopy(ROUND5_ADVANCE_EXAMPLES[self.engine]),
            "assess": {**scope, "plan": plan.to_dict(), "entity_kind": kind, "states": []},
        }


class Round5EnginePrimitive(EnginePrimitive[Any, Round5EngineOutput]):
    version = "0.1.0"
    output_model = Round5EngineOutput
    hard_rules = {"exact_authenticated_scope": True, "source_states_replayed": True, "provider_effects_executed": False}

    def __init__(self, engine: str, operation: str, primitive_ref: str) -> None:
        self.engine, self.operation, self.primitive_ref = engine, operation, primitive_ref
        self.input_model = CompileRound5EngineInput if operation == "compile" else Round5EngineInput
        self.title = f"{operation.capitalize()} {engine.replace('_', ' ')}"
        self.description = "Replay and delegate to the engine's own rules within the authenticated scope; returns an SDK candidate without persistence or provider effects."
        self.operation_spec = read_spec(primitive_ref.replace(".", "_"), "sdk." + primitive_ref)
        self.example_inputs = LazyExample(_Examples(engine), operation)

    def _execute(self, context: Any, inputs: Any) -> Any:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="The authenticated execution scope and requesting actor must match.")
        try:
            module, compile_engine, _ = _engine(self.engine)
            if self.operation == "compile":
                plan = compile_engine(inputs.company_ref, operating_plan=inputs.operating_plan, profile=inputs.profile, overrides=inputs.overrides)
                payload, sources, blocker = plan.to_dict(), (plan.plan_digest,), None
            else:
                spec, advance = _lifecycle(self.engine, inputs.entity_kind)
                plan = spec.plan_model.model_validate(inputs.plan)
                states = [spec.bind(plan, state)[1] for state in inputs.states]
                for state in states:
                    if not scope_matches(RequestScope.from_engine_scope(state.scope), inputs.requested_by_ref, context):
                        return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Every source must belong to the authenticated execution scope.")
                if len({state.scope.entity_ref for state in states}) != len(states):
                    raise ValueError("SOURCE_DUPLICATED: supply each entity once")
                sources = tuple(state.state_digest for state in states)
                blocker = None
                if self.operation == "advance":
                    if len(states) != 1 or inputs.command is None:
                        return self.blocked(digest=digest, code="SOURCE_COMMAND_REQUIRED", message="Supply one real source state and its exact sealed command.")
                    command = spec.Command.model_validate(inputs.command)
                    if command.actor_ref != inputs.requested_by_ref:
                        return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="The command actor must be the requesting actor.")
                    result = advance(plan, states[0], command)
                    payload = result.to_dict()
                    if not result.candidate_validated:
                        blocker = PrimitiveBlocker(code=result.receipt.rejection_code, message=result.receipt.recovery.instructions[:500], retryable=False)
                else:
                    if inputs.command is not None:
                        raise ValueError("COMMAND_NOT_ALLOWED: an assessment does not consume a transition")
                    if self.engine == "people_engine":
                        rows = [module.assess_capacity(state, plan=plan) for state in states]
                    elif self.engine == "marketplace_supply_engine":
                        rows = [module.marketplace_summary(state, source_plan=plan, kind=inputs.entity_kind) for state in states]
                    else:
                        rows = [module.engagements(state, source_plan=plan) for state in states]
                    payload = {"plan_digest": plan.plan_digest, "entities": rows, "count": len(rows)}
        except ValueError as exc:
            return self.blocked(digest=digest, code=getattr(exc, "code", "ENGINE_INPUT_INVALID"), message=str(exc))
        output = Round5EngineOutput(engine=self.engine, operation=self.operation, result=detached(payload), source_digests=sources)
        return self.preview(output=output, digest=digest, external_refs={"result_digest": stable_digest(output.to_dict())}, event_type=self.primitive_ref + ".candidate", event_payload={"engine": self.engine, "operation": self.operation}, evidence_kind="company_engine_candidate", evidence_summary="Derived from the existing compiler or replayed lifecycle.", summary=f"{self.title}: candidate only.", blocker=blocker)


ROUND5_ENGINE_EXECUTABLE_PRIMITIVES = tuple(
    Round5EnginePrimitive(engine, operation, ref)
    for engine, refs in (
        ("people_engine", ("people.compile_people_engine", "people.advance_people", "people.assess_capacity")),
        ("marketplace_supply_engine", ("marketplace.compile_supply_engine", "marketplace.advance_supply", "marketplace.assess_supply")),
        ("engagement_engine", ("engagement.compile_engagement", "engagement.advance_engagement", "engagement.assess_engagement")),
    )
    for operation, ref in zip(("compile", "advance", "assess"), refs)
)

__all__ = ["CompileRound5EngineInput", "Round5EngineInput", "Round5EngineOutput", "Round5EnginePrimitive", "ROUND5_ENGINE_EXECUTABLE_PRIMITIVES"]
