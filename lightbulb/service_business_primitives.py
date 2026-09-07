"""Executable primitives for the Service Business Golden Operating Loop.

``blueprint.compile_service_business`` turns a ready-made profile (consulting,
trades, software delivery, agency) or a custom blueprint into a loop plan.
``service.advance_business_cycle`` materializes one replay-fenced cycle
transition.  ``service.assess_business_cycle`` produces the learn-stage
assessment.  All three are read-only mechanics; Spring authorizes every
effect the bound primitives would execute.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

from pydantic import Field, field_validator

from lightbulb.connector_execution import ConnectorEffect
from lightbulb.primitive_runtime import (
    BusinessProcessPrimitive,
    PrimitiveBlocker,
    PrimitiveExecutionContext,
    PrimitiveExecutionResult,
    PrimitiveOperationFreshnessClass,
    PrimitiveOperationRecoveryPolicy,
    PrimitiveOperationReplayClass,
    PrimitiveOperationSpec,
)
from lightbulb.service_business_loop import (
    SERVICE_BUSINESS_ARCHETYPE_MANIFEST,
    SERVICE_BUSINESS_GOLDEN_LOOP,
    SERVICE_BUSINESS_PROFILES,
    STAGE_ORDER,
    CycleTransitionResult,
    OpaqueRef,
    ServiceBusinessBlueprint,
    ServiceBusinessCycleAssessment,
    ServiceBusinessCycleCommand,
    ServiceBusinessCycleState,
    ServiceBusinessLoopPlan,
    _StrictModel,
    _timestamp,
    advance_service_business_cycle,
    assess_service_business_cycle,
    compile_service_business_blueprint,
    open_service_business_cycle,
    seal_cycle_command,
)
from lightbulb.service_operations_primitives import _scope_matches, _ServiceOpsPrimitive


COMPILE_OPERATION = PrimitiveOperationSpec(
    operation_ref="service_business_compile_blueprint",
    tool="sdk.blueprint.compile_service_business",
    effect=ConnectorEffect.READ,
    approval_required=False,
    replay_class=PrimitiveOperationReplayClass.SAFE,
    freshness_class=PrimitiveOperationFreshnessClass.CURRENT,
    recovery_policy=PrimitiveOperationRecoveryPolicy.NONE,
)
ADVANCE_OPERATION = PrimitiveOperationSpec(
    operation_ref="service_business_advance_cycle",
    tool="sdk.service.advance_business_cycle",
    effect=ConnectorEffect.READ,
    approval_required=False,
    replay_class=PrimitiveOperationReplayClass.SAFE,
    freshness_class=PrimitiveOperationFreshnessClass.CURRENT,
    recovery_policy=PrimitiveOperationRecoveryPolicy.NONE,
)
ASSESS_OPERATION = PrimitiveOperationSpec(
    operation_ref="service_business_assess_cycle",
    tool="sdk.service.assess_business_cycle",
    effect=ConnectorEffect.READ,
    approval_required=False,
    replay_class=PrimitiveOperationReplayClass.SAFE,
    freshness_class=PrimitiveOperationFreshnessClass.CURRENT,
    recovery_policy=PrimitiveOperationRecoveryPolicy.NONE,
)

_EXAMPLE_PROJECT_ID = "40100000-0000-4000-8000-000000000001"
_EXAMPLE_ACTOR = "actor-requester-example"
_EXAMPLE_SCOPE = {"tenant_ref": "authenticated", "company_ref": "selected", "project_ref": "workflow-improvement", "project_id": _EXAMPLE_PROJECT_ID}


class RequestScope(_StrictModel):
    tenant_ref: OpaqueRef
    company_ref: OpaqueRef
    project_ref: OpaqueRef
    project_id: str


class CompileServiceBusinessInput(_StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    profile: str = Field(min_length=1, max_length=40)
    blueprint: ServiceBusinessBlueprint | None = None
    overrides: dict[str, Any] = Field(default_factory=dict)


class AdvanceBusinessCycleInput(_StrictModel):
    plan: ServiceBusinessLoopPlan
    state: ServiceBusinessCycleState
    command: ServiceBusinessCycleCommand


class AssessBusinessCycleInput(_StrictModel):
    plan: ServiceBusinessLoopPlan
    state: ServiceBusinessCycleState
    requested_by_ref: OpaqueRef
    assessed_at: str

    @field_validator("assessed_at")
    @classmethod
    def _assessed(cls, value: str) -> str:
        return _timestamp(value, field_name="assessed_at")


def _request_digest(payload: Mapping[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class _ExampleBundle:
    def __init__(self) -> None:
        self._built: dict[str, Any] | None = None

    def get(self) -> dict[str, Any]:
        if self._built is not None:
            return self._built
        plan = compile_service_business_blueprint("consulting")
        scope = {**_EXAMPLE_SCOPE, "cycle_ref": "cycle-example", "customer_ref": "customer-example", "currency": "USD"}
        state = open_service_business_cycle(plan, scope, opened_at="2026-09-01T00:00:00Z", actor_ref=_EXAMPLE_ACTOR, campaign_refs=["campaign-content-q3"], lead_refs=["lead-example"])
        command = seal_cycle_command({"event": "complete_stage", "stage": "qualify", "transition_ref": "qualify:cycle-example", "idempotency_key": "cycle-example:qualify", "expected_version": state.version, "expected_state_digest": state.state_digest, "occurred_at": "2026-09-02T00:00:00Z", "actor_ref": _EXAMPLE_ACTOR, "receipt": {"lead_refs": ["lead-example"], "lead_score": 78, "qualification": "qualified", "evidence_refs": ["crm-qualification-1"]}})
        self._built = {
            "compile": {"scope": _EXAMPLE_SCOPE, "requested_by_ref": _EXAMPLE_ACTOR, "profile": "consulting", "overrides": {"target_gross_margin_percent": "60"}},
            "advance": {"plan": plan.to_dict(), "state": state.to_dict(), "command": command},
            "assess": {"plan": plan.to_dict(), "state": state.to_dict(), "requested_by_ref": _EXAMPLE_ACTOR, "assessed_at": "2026-09-02T01:00:00Z"},
        }
        return self._built


_EXAMPLES = _ExampleBundle()


class _LazyExample(Mapping[str, Any]):
    def __init__(self, key: str) -> None:
        self._key = key

    def _payload(self) -> dict[str, Any]:
        return _EXAMPLES.get()[self._key]

    def __getitem__(self, key: str) -> Any:
        return self._payload()[key]

    def __iter__(self):  # type: ignore[no-untyped-def]
        return iter(self._payload())

    def __len__(self) -> int:
        return len(self._payload())

    def keys(self):  # type: ignore[no-untyped-def]
        return self._payload().keys()

    def items(self):  # type: ignore[no-untyped-def]
        return self._payload().items()

    def values(self):  # type: ignore[no-untyped-def]
        return self._payload().values()


def example_service_business_inputs() -> dict[str, Any]:
    return {key: dict(value) for key, value in _EXAMPLES.get().items()}


class _ServiceBusinessPrimitive(_ServiceOpsPrimitive[Any, Any]):
    golden_loop = SERVICE_BUSINESS_GOLDEN_LOOP

    def implementation_contract(self) -> dict[str, Any]:
        contract = super().implementation_contract()
        contract["archetype"] = SERVICE_BUSINESS_ARCHETYPE_MANIFEST["archetype"]
        contract["loop_stages"] = list(STAGE_ORDER)
        contract["profiles"] = sorted(SERVICE_BUSINESS_PROFILES)
        contract["hard_rules"] = {
            "delivery_mode_from_blueprint": True,
            "builder_cannot_accept_own_work": True,
            "software_acceptance_requires_production_verified_run": True,
            "invoices_follow_schedule_and_never_exceed_accepted_value": True,
            "renewal_follows_policy": True,
            "no_invoice_or_payment_effect_here": True,
        }
        return contract


class CompileServiceBusinessPrimitive(_ServiceBusinessPrimitive):
    primitive_ref = "blueprint.compile_service_business"
    version = "0.1.0"
    title = "Compile a service-business Company Blueprint into a loop plan"
    description = (
        "Turn a ready-made service profile (consulting, trades, software_delivery, agency) or a custom blueprint into the "
        "market → qualify → quote → agreement → deliver → verify acceptance → invoice → collect → support/renew → learn plan, "
        "binding every stage to existing primitives with the delivery mode, acceptance policy, invoice schedule, and renewal policy."
    )
    input_model = CompileServiceBusinessInput
    output_model = ServiceBusinessLoopPlan
    risk_level = "low"
    operation_spec = COMPILE_OPERATION
    example_inputs: Mapping[str, Any] = _LazyExample("compile")

    def _execute(self, context: PrimitiveExecutionContext, inputs: CompileServiceBusinessInput) -> PrimitiveExecutionResult[ServiceBusinessLoopPlan]:
        request_digest = _request_digest(inputs.to_dict())
        scope = inputs.scope
        if not _scope_matches(scope.tenant_ref, scope.company_ref, scope.project_ref, scope.project_id, inputs.requested_by_ref, context):
            return self._blocked(request_digest=request_digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            plan = compile_service_business_blueprint(inputs.blueprint.to_dict() if inputs.profile == "custom" and inputs.blueprint is not None else inputs.profile, inputs.overrides)
        except ValueError as exc:
            return self._blocked(request_digest=request_digest, code="BLUEPRINT_INVALID", message=str(exc)[:500])
        return self._preview(
            output=plan, request_digest=request_digest,
            external_refs={"plan_digest": plan.plan_digest, "blueprint_digest": plan.blueprint.blueprint_digest},
            event_type="blueprint.service_business_compiled",
            event_payload={"profile": plan.blueprint.profile, "delivery_mode": plan.blueprint.delivery_mode, "acceptance_policy": plan.blueprint.acceptance_policy, "invoice_schedule": plan.blueprint.invoice_schedule.kind, "renewal_policy": plan.blueprint.renewal_policy, "composed_golden_loops": list(plan.composed_golden_loops)},
            evidence_kind="service_business_loop_plan", evidence_summary="Loop plan with per-stage primitive bindings; nothing executed.",
            summary=f"Compiled {plan.blueprint.profile} service-business plan ({plan.blueprint.delivery_mode}, {plan.blueprint.acceptance_policy}).",
        )


class AdvanceBusinessCyclePrimitive(_ServiceBusinessPrimitive):
    primitive_ref = "service.advance_business_cycle"
    version = "0.1.0"
    title = "Advance a service-business cycle by one stage"
    description = (
        "Materialize one replay-fenced transition of a service-business cycle from a sealed command that links the stage's evidence "
        "(campaigns, qualification, quote, executed agreement custody, work packets or software-production run, acceptance, invoices, "
        "payments, renewal, learning inputs). Duplicates, stale revisions, and policy violations are rejected with a typed disposition."
    )
    input_model = AdvanceBusinessCycleInput
    output_model = CycleTransitionResult
    risk_level = "medium"
    operation_spec = ADVANCE_OPERATION
    example_inputs: Mapping[str, Any] = _LazyExample("advance")

    def _execute(self, context: PrimitiveExecutionContext, inputs: AdvanceBusinessCycleInput) -> PrimitiveExecutionResult[CycleTransitionResult]:
        request_digest = _request_digest(inputs.to_dict())
        scope = inputs.state.scope
        if not _scope_matches(scope.tenant_ref, scope.company_ref, scope.project_ref, scope.project_id, inputs.command.actor_ref, context):
            return self._blocked(request_digest=request_digest, code="SCOPE_MISMATCH", message="Runtime scope and acting actor must exactly match the cycle scope and command.")
        try:
            result = advance_service_business_cycle(inputs.plan, inputs.state, inputs.command)
        except ValueError as exc:
            return self._blocked(request_digest=request_digest, code="STATE_NOT_BOUND", message=str(exc)[:500])
        receipt = result.receipt
        blocker = None if result.candidate_validated else PrimitiveBlocker(code=str(receipt.rejection_code), message=str(receipt.recovery.instructions)[:500], retryable=receipt.recovery.disposition == "refresh_state")
        return self._preview(
            output=result, request_digest=request_digest,
            external_refs={"cycle_ref": scope.cycle_ref, "transition_ref": receipt.transition_ref, "to_state_digest": receipt.to_state_digest},
            event_type="service.business_cycle_advanced",
            event_payload={"event": receipt.event, "stage": receipt.stage, "transition_status": receipt.status, "from_status": receipt.from_status, "to_status": receipt.to_status, "rejection_code": receipt.rejection_code, "recovery": receipt.recovery.disposition},
            evidence_kind="service_business_cycle_transition", evidence_summary="Replay-fenced cycle transition; the state is a candidate until Spring retains it.",
            summary=(f"{receipt.stage or receipt.event}: {receipt.from_status} -> {receipt.to_status} (v{receipt.to_version})." if result.candidate_validated else f"{receipt.stage or receipt.event} rejected: {receipt.rejection_code} ({receipt.recovery.disposition})."),
            blocker=blocker,
        )


class AssessBusinessCyclePrimitive(_ServiceBusinessPrimitive):
    primitive_ref = "service.assess_business_cycle"
    version = "0.1.0"
    title = "Assess a service-business cycle (learn stage)"
    description = (
        "Effect-dark assessment of a cycle: stages completed, next stage, quote/accepted/invoiced/collected totals, outstanding receivable, "
        "gross margin against the blueprint target, delivery quality, renewal outcome, learnings, and next-cycle recommendations."
    )
    input_model = AssessBusinessCycleInput
    output_model = ServiceBusinessCycleAssessment
    risk_level = "low"
    operation_spec = ASSESS_OPERATION
    example_inputs: Mapping[str, Any] = _LazyExample("assess")

    def _execute(self, context: PrimitiveExecutionContext, inputs: AssessBusinessCycleInput) -> PrimitiveExecutionResult[ServiceBusinessCycleAssessment]:
        request_digest = _request_digest(inputs.to_dict())
        scope = inputs.state.scope
        if not _scope_matches(scope.tenant_ref, scope.company_ref, scope.project_ref, scope.project_id, inputs.requested_by_ref, context):
            return self._blocked(request_digest=request_digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the cycle scope.")
        try:
            assessment = assess_service_business_cycle(inputs.plan, inputs.state, assessed_at=inputs.assessed_at)
        except ValueError as exc:
            return self._blocked(request_digest=request_digest, code="STATE_NOT_BOUND", message=str(exc)[:500])
        # A cycle in flight assesses as a preview of where it stands; nothing to block on.
        blocker = None
        return self._preview(
            output=assessment, request_digest=request_digest,
            external_refs={"cycle_ref": assessment.cycle_ref, "assessment_digest": assessment.assessment_digest},
            event_type="service.business_cycle_assessed",
            event_payload={"status": assessment.status, "next_stage": assessment.next_stage, "gross_margin_percent": None if assessment.gross_margin_percent is None else str(assessment.gross_margin_percent), "renewal_decision": assessment.renewal_decision, "learnings": list(assessment.learnings)},
            evidence_kind="service_business_cycle_assessment", evidence_summary="Learn-stage assessment and next-cycle candidates; no effect.",
            summary=(f"Cycle {assessment.status}: {assessment.learnings[0]}" if assessment.learnings else f"Cycle at {assessment.status}; next stage {assessment.next_stage}."),
            blocker=blocker,
        )


SERVICE_BUSINESS_EXECUTABLE_PRIMITIVES: tuple[BusinessProcessPrimitive[Any, Any], ...] = (
    CompileServiceBusinessPrimitive(),
    AdvanceBusinessCyclePrimitive(),
    AssessBusinessCyclePrimitive(),
)

SERVICE_BUSINESS_INTEGRATION_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.capability_pack_integration_manifest.v1",
    "capability_pack": "service_business_golden_loop",
    "golden_loop": SERVICE_BUSINESS_GOLDEN_LOOP,
    "archetype": SERVICE_BUSINESS_ARCHETYPE_MANIFEST,
    "stacked_on": "fable/service-business-operations-core (PR #475) -> #474 -> #473 -> #472",
    "modules": {"domain": "lightbulb.service_business_loop", "primitives": "lightbulb.service_business_primitives"},
    "primitive_refs": [item.primitive_ref for item in SERVICE_BUSINESS_EXECUTABLE_PRIMITIVES],
    "executable_registry": {"file": "lightbulb/executable_primitives.py", "import": "from lightbulb.service_business_primitives import SERVICE_BUSINESS_EXECUTABLE_PRIMITIVES", "splice": "*SERVICE_BUSINESS_EXECUTABLE_PRIMITIVES in BUILTIN_EXECUTABLE_PRIMITIVES"},
    "golden_loop_registry": {"note": "register service.market_to_renewal_business@0.1.0 with STAGE_ORDER and the composed loops from SERVICE_BUSINESS_ARCHETYPE_MANIFEST"},
    "company_blueprints": {"note": "register the service_business archetype with SERVICE_BUSINESS_PROFILES; composable with product_commerce"},
    "public_exports": {"file": "lightbulb/__init__.py", "names": ["SERVICE_BUSINESS_EXECUTABLE_PRIMITIVES", "SERVICE_BUSINESS_INTEGRATION_MANIFEST", "SERVICE_BUSINESS_PROFILES", "SERVICE_BUSINESS_ARCHETYPE_MANIFEST", "ServiceBusinessBlueprint", "ServiceBusinessLoopPlan", "ServiceBusinessCycleState", "compile_service_business_blueprint", "open_service_business_cycle", "advance_service_business_cycle", "assess_service_business_cycle"]},
    "software_delivery_binding": {"golden_loop": "software.approved_change_to_verified_production@0.1.0", "primitives": ["project.request_software_production", "project.assess_software_production_result"], "branch": "fable/software-production-contract (#476) and stacked #477/#478", "binding": "by reference only until integration"},
    "mcp": {"note": "project the three primitives through the generated primitive tools; the loop plan and stage table are resources"},
    "non_goals": ["no new invoice, payment, CRM, or marketing connector calls", "no replacement of the ServiceEngagement or contract-delivery mechanics", "no certification or production-readiness claim"],
}

__all__ = [
    "ADVANCE_OPERATION",
    "ASSESS_OPERATION",
    "COMPILE_OPERATION",
    "SERVICE_BUSINESS_EXECUTABLE_PRIMITIVES",
    "SERVICE_BUSINESS_INTEGRATION_MANIFEST",
    "AdvanceBusinessCycleInput",
    "AdvanceBusinessCyclePrimitive",
    "AssessBusinessCycleInput",
    "AssessBusinessCyclePrimitive",
    "CompileServiceBusinessInput",
    "CompileServiceBusinessPrimitive",
    "RequestScope",
    "example_service_business_inputs",
]
