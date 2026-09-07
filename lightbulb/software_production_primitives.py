"""Executable primitives for the canonical software-production request contract.

``project.request_software_production`` compiles a typed request onto the
existing Project Work Packet and Dynamic Workflow acceptance contracts and
returns the composition seam an originating workflow waits on.
``project.assess_software_production_result`` turns a run handle and receipt
set into a typed terminal result.  Neither calls a provider, a coding
harness, CI, or a deployment platform; Spring resolves the harness and
authorizes every effect.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any, Generic, TypeVar

from pydantic import BaseModel

from lightbulb.connector_execution import ConnectorEffect
from lightbulb.primitive_runtime import (
    BusinessProcessPrimitive,
    PrimitiveBlocker,
    PrimitiveEvent,
    PrimitiveEvidence,
    PrimitiveExecutionContext,
    PrimitiveExecutionResult,
    PrimitiveExecutionStatus,
    PrimitiveOperationFreshnessClass,
    PrimitiveOperationReceipt,
    PrimitiveOperationRecoveryPolicy,
    PrimitiveOperationReplayClass,
    PrimitiveOperationSpec,
    PrimitiveOperationStatus,
)
from lightbulb.software_production import (
    MILESTONE_ORDER,
    SOFTWARE_PRODUCTION_GOLDEN_LOOP,
    TERMINAL_STATUSES,
    SoftwareProductionAssessment,
    SoftwareProductionCompilation,
    SoftwareProductionRequest,
    SoftwareProductionResultInput,
    SoftwareProductionScope,
    assess_software_production_result,
    compile_software_production_request,
    seal_software_production_request,
)


InputT = TypeVar("InputT", bound=BaseModel)
OutputT = TypeVar("OutputT", bound=BaseModel)

REQUEST_OPERATION = PrimitiveOperationSpec(
    operation_ref="software_production_compile_request",
    tool="sdk.project.request_software_production",
    effect=ConnectorEffect.READ,
    approval_required=False,
    replay_class=PrimitiveOperationReplayClass.SAFE,
    freshness_class=PrimitiveOperationFreshnessClass.CURRENT,
    recovery_policy=PrimitiveOperationRecoveryPolicy.NONE,
)
ASSESS_OPERATION = PrimitiveOperationSpec(
    operation_ref="software_production_assess_result",
    tool="sdk.project.assess_software_production_result",
    effect=ConnectorEffect.READ,
    approval_required=False,
    replay_class=PrimitiveOperationReplayClass.SAFE,
    freshness_class=PrimitiveOperationFreshnessClass.CURRENT,
    recovery_policy=PrimitiveOperationRecoveryPolicy.NONE,
)

_ROLE_SEPARATION = {
    "originating_workflow": "states the business need and consumes the terminal result; never picks credentials or bypasses Project scope",
    "project_consulting_agent": "clarifies, scopes, compiles, coordinates; never implements and independently accepts the same work",
    "coding_harness": "builds in the exact workspace under the exact one-use grant; never selects release authority or claims production success",
    "independent_evaluator": "judges against the immutable Acceptance Contract; never modifies the artifact it evaluates",
    "spring": "resolves scope, policy, and harness; authorizes effects; persists and audits the lifecycle",
    "release_connector": "executes the exact authorized effect; never broadens scope or reinterprets acceptance",
    "production_observer": "verifies health and business outcome; a deployment receipt alone is never success",
}


def _request_digest(payload: Mapping[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _scope_matches(scope: SoftwareProductionScope, requesting_ref: str, context: PrimitiveExecutionContext, *, idempotency_key: str | None) -> bool:
    runtime = context.scope
    # Tenant, company, project ref, and project id must always match. The actor and
    # idempotency key are checked whenever the runtime asserts them (Spring always
    # does); a runtime that asserts neither cannot be contradicted by the request.
    matched = (
        scope.tenant_ref == runtime.tenant_ref
        and scope.company_ref == runtime.company_ref
        and scope.project_ref == runtime.project_ref
        and runtime.project_id is not None
        and scope.project_id == str(runtime.project_id)
    )
    if runtime.actor_ref is not None:
        matched = matched and requesting_ref == runtime.actor_ref
    if idempotency_key is not None and context.idempotency_key is not None:
        matched = matched and idempotency_key == context.idempotency_key
    return matched


class _SoftwareProductionPrimitive(BusinessProcessPrimitive[InputT, OutputT], Generic[InputT, OutputT]):
    connector_tools = ()
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    operation_spec: PrimitiveOperationSpec

    def implementation_contract(self) -> dict[str, Any]:
        contract = super().implementation_contract()
        contract["operation_contract"] = self.operation_spec.to_dict()
        contract["golden_loop"] = SOFTWARE_PRODUCTION_GOLDEN_LOOP
        contract["lifecycle"] = {"milestones": list(MILESTONE_ORDER), "terminal_statuses": sorted(TERMINAL_STATUSES), "success": "production_verified"}
        contract["role_separation"] = dict(_ROLE_SEPARATION)
        contract["hard_rules"] = {
            "no_tenant_company_override": True,
            "no_credentials_or_raw_sessions": True,
            "harness_resolved_by_spring_policy": True,
            "work_packet_and_acceptance_immutable_after_authorization": True,
            "builder_cannot_evaluate_itself": True,
            "effects_separately_classified_and_fail_closed": True,
            "production_success_requires_independent_health_and_outcome": True,
        }
        return contract

    def _blocked(self, *, request_digest: str, code: str, message: str) -> PrimitiveExecutionResult[OutputT]:
        blocker = PrimitiveBlocker(code=code, message=message, field="scope" if code == "SCOPE_MISMATCH" else None, retryable=False)
        return PrimitiveExecutionResult[OutputT](
            status=PrimitiveExecutionStatus.BLOCKED, primitive_ref=self.primitive_ref, primitive_version=self.version,
            summary=f"{self.title} blocked: {code}.", blockers=[blocker],
            operation_receipts=[PrimitiveOperationReceipt(spec=self.operation_spec, status=PrimitiveOperationStatus.BLOCKED, request_digest=request_digest, error=blocker)],
        )

    def _preview(self, *, output: OutputT, request_digest: str, external_refs: Mapping[str, str], event_type: str, event_payload: Mapping[str, Any], evidence_kind: str, evidence_summary: str, summary: str, blocker: PrimitiveBlocker | None = None) -> PrimitiveExecutionResult[OutputT]:
        status = PrimitiveExecutionStatus.BLOCKED if blocker else PrimitiveExecutionStatus.PREVIEW
        return PrimitiveExecutionResult[OutputT](
            status=status, primitive_ref=self.primitive_ref, primitive_version=self.version, summary=summary, output=output,
            events=[PrimitiveEvent(type=event_type, payload={**dict(event_payload), "request_digest": request_digest, "provider_called": False, "deployment_executed": False, "connector_effect_executed": False})],
            evidence=[PrimitiveEvidence(kind=evidence_kind, summary=evidence_summary, refs={"request_digest": request_digest, **dict(external_refs)})],
            operation_receipts=[PrimitiveOperationReceipt(spec=self.operation_spec, status=PrimitiveOperationStatus.BLOCKED if blocker else PrimitiveOperationStatus.PREVIEW, request_digest=request_digest, external_refs=dict(external_refs), error=blocker)],
            blockers=[blocker] if blocker else [],
        )


_EXAMPLE_PROJECT_ID = "40100000-0000-4000-8000-000000000001"
_EXAMPLE_ACTOR = "agent-product-example"


def example_software_production_request(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "scope": {"tenant_ref": "authenticated", "company_ref": "selected", "project_ref": "workflow-improvement", "project_id": _EXAMPLE_PROJECT_ID},
        "origin": {"originating_workflow_ref": "workflow-campaign-example", "originating_run_ref": "run-campaign-example", "originating_step_ref": "step-landing-page", "requesting_agent_ref": _EXAMPLE_ACTOR, "idempotency_key": "idem-software-production-example"},
        "objective": {"business_objective": "Add a landing page for the autumn campaign", "expected_outcome": "Campaign traffic lands on a page that converts", "urgency": "high", "change_type": "feature"},
        "change_scope": {"repository_binding_refs": ["repository-binding-web-example"], "workspace_binding_ref": "workspace-binding-web-example", "included_areas": ["marketing site"], "excluded_areas": ["checkout"], "source_context_refs": ["campaign-brief-example"]},
        "work": {"title": "Autumn campaign landing page", "summary": "Build the landing page from the approved campaign brief", "deliverables": ["landing page route", "analytics event on the call to action"], "dependencies": ["design-approval-example"], "constraints": ["no checkout changes"]},
        "acceptance": {
            "criteria": [
                {"criterion_id": "page-renders", "description": "Landing page renders with the approved copy", "required_evidence": ["test_report", "screenshot"]},
                {"criterion_id": "event-fires", "description": "Analytics event fires on the call to action", "required_evidence": ["test_report"]},
            ],
            "evaluator_policy": "distinct_binding",
        },
        "harness_policy": {"allowed_harness_families": ["claude_code", "codex"], "preferred_family": "claude_code"},
        "risk": {"change_risk": "low", "data_classification": "public", "blast_radius": "single_component"},
        "release": {"automation_level": "staging_automation", "allowed_environments": ["preview", "staging"], "production_approval": "not_applicable", "rollout": "canary", "rollback": "manual", "rollback_verification_required": False},
        "budget": {"max_elapsed_seconds": 7200, "max_tokens": 2_000_000, "max_cost_microusd": 20_000_000},
        "requested_at": "2026-09-10T00:00:00Z",
    }
    payload.update(overrides)
    return seal_software_production_request(payload)


class _ExampleBundle:
    def __init__(self) -> None:
        self._built: dict[str, Any] | None = None

    def get(self) -> dict[str, Any]:
        if self._built is not None:
            return self._built
        request = example_software_production_request()
        compilation = compile_software_production_request(request)
        from lightbulb.software_production import SoftwareProductionRunHandle, _sealed_digest

        handle = {"request_digest": compilation.request_digest, "compilation_digest": compilation.compilation_digest, "dynamic_workflow_run_ref": "dwr_example", "execution_run_ref": "execution-run-example", "status": "staging_verified", "updated_at": "2026-09-11T00:00:00Z"}
        handle["handle_digest"] = _sealed_digest(SoftwareProductionRunHandle, handle, "handle_digest")
        receipt_set = {
            "request_digest": compilation.request_digest,
            "compilation_digest": compilation.compilation_digest,
            "acceptance_contract_digest": compilation.acceptance_contract_digest,
            "selected_harness_family": "claude_code",
            "evaluator_accepted": True,
            "receipts": [{"kind": kind, "ref": f"{kind}-example", "issuer_ref": "spring-example", "observed_at": "2026-09-11T00:00:00Z", "independent_of_builder": kind != "builder_result"} for kind in ("builder_result", "evaluator_verdict", "branch", "commit", "pull_request", "ci", "review", "staging", "deployment")],
        }
        self._built = {"request": request, "assess_input": {"compilation": compilation.to_dict(), "handle": handle, "receipt_set": receipt_set, "assessed_at": "2026-09-11T01:00:00Z"}}
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


class RequestSoftwareProductionPrimitive(_SoftwareProductionPrimitive[SoftwareProductionRequest, SoftwareProductionCompilation]):
    primitive_ref = "project.request_software_production"
    version = "0.1.0"
    title = "Request governed software production"
    description = (
        "Compile a typed software-production request (origin, objective, scope, work, acceptance, "
        "harness policy, risk, release, budget, evidence) onto the existing Project Work Packet and "
        "immutable Dynamic Workflow acceptance contract, with finite limits and separately classified "
        "effects. Returns the composition seam; Spring resolves the harness and authorizes every effect."
    )
    input_model = SoftwareProductionRequest
    output_model = SoftwareProductionCompilation
    risk_level = "high"
    operation_spec = REQUEST_OPERATION
    example_inputs: Mapping[str, Any] = _LazyExample("request")

    def _execute(self, context: PrimitiveExecutionContext, inputs: SoftwareProductionRequest) -> PrimitiveExecutionResult[SoftwareProductionCompilation]:
        if not _scope_matches(inputs.scope, inputs.origin.requesting_agent_ref, context, idempotency_key=inputs.origin.idempotency_key):
            return self._blocked(request_digest=inputs.request_digest, code="SCOPE_MISMATCH", message="Runtime scope, requesting agent, and idempotency key must exactly match the request origin.")
        compilation = compile_software_production_request(inputs)
        return self._preview(
            output=compilation, request_digest=inputs.request_digest,
            external_refs={"compilation_digest": compilation.compilation_digest, "work_packet_digest": compilation.work_packet_digest, "acceptance_contract_digest": compilation.acceptance_contract_digest},
            event_type="project.software_production_requested",
            event_payload={"originating_workflow_ref": inputs.origin.originating_workflow_ref, "change_type": inputs.objective.change_type, "effective_risk": compilation.effective_risk, "automation_level": inputs.release.automation_level, "allowed_hosts": list(compilation.dynamic_workflow_start.allowed_hosts), "harness_selected": False},
            evidence_kind="software_production_compilation", evidence_summary="Compiled Work Packet, acceptance contract, workflow start payload, limits, and effect classification; no run started.",
            summary=f"Compiled software-production request {inputs.request_digest[:12]} ({compilation.effective_risk} risk, {inputs.release.automation_level}).",
        )


class AssessSoftwareProductionResultPrimitive(_SoftwareProductionPrimitive[SoftwareProductionResultInput, SoftwareProductionAssessment]):
    primitive_ref = "project.assess_software_production_result"
    version = "0.1.0"
    title = "Assess a software-production run into a typed terminal result"
    description = (
        "Turn a run handle and receipt set into a typed terminal result. production_verified requires an "
        "accepting independent evaluator plus deployment, production-health, and business-outcome evidence "
        "and every policy-required evidence kind; milestones and deployment receipts alone are never success."
    )
    input_model = SoftwareProductionResultInput
    output_model = SoftwareProductionAssessment
    risk_level = "medium"
    operation_spec = ASSESS_OPERATION
    example_inputs: Mapping[str, Any] = _LazyExample("assess_input")

    def _execute(self, context: PrimitiveExecutionContext, inputs: SoftwareProductionResultInput) -> PrimitiveExecutionResult[SoftwareProductionAssessment]:
        request_digest = _request_digest(inputs.to_dict())
        if not _scope_matches(inputs.compilation.scope, inputs.compilation.origin.requesting_agent_ref, context, idempotency_key=None):
            return self._blocked(request_digest=request_digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting agent must exactly match the compiled request.")
        assessment = assess_software_production_result(inputs)
        # A non-terminal run assesses as a preview of where it stands; only a terminal run with
        # missing evidence is a blocker.
        blocker = PrimitiveBlocker(code="RESULT_INCOMPLETE", message=assessment.blockers[0][:500], retryable=False) if assessment.blockers and inputs.handle.status in TERMINAL_STATUSES else None
        return self._preview(
            output=assessment, request_digest=request_digest,
            external_refs={"status": inputs.handle.status, **({"result_digest": assessment.result.result_digest} if assessment.result else {})},
            event_type="project.software_production_result_assessed",
            event_payload={"status": inputs.handle.status, "production_verified": bool(assessment.result and assessment.result.production_verified), "blockers": list(assessment.blockers)},
            evidence_kind="software_production_result", evidence_summary="Typed terminal result or blockers; never a claim of production success from a receipt alone.",
            summary=(f"Run {inputs.handle.status}: typed result sealed." if assessment.result else f"Run {inputs.handle.status}: {assessment.blockers[0]}"),
            blocker=blocker,
        )


SOFTWARE_PRODUCTION_EXECUTABLE_PRIMITIVES: tuple[BusinessProcessPrimitive[Any, Any], ...] = (
    RequestSoftwareProductionPrimitive(),
    AssessSoftwareProductionResultPrimitive(),
)

SOFTWARE_PRODUCTION_INTEGRATION_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.capability_pack_integration_manifest.v1",
    "capability_pack": "software_production_contract",
    "work_package": "1A",
    "golden_loop": SOFTWARE_PRODUCTION_GOLDEN_LOOP,
    "modules": {"domain": "lightbulb.software_production", "primitives": "lightbulb.software_production_primitives"},
    "base": "origin/main d6528edc87ee79ad5fb2c2d39339901a99517b21",
    "reuses": ["lightbulb.dynamic_workflows.AcceptanceCriterion", "lightbulb.dynamic_workflows.WorkflowLimits", "lightbulb.growth_primitives.CreateWorkPacketInput (project.create_work_packet)", "LightbulbClient.dynamic_workflow_start / AsyncLightbulbClient.dynamic_workflow_start"],
    "primitive_refs": [item.primitive_ref for item in SOFTWARE_PRODUCTION_EXECUTABLE_PRIMITIVES],
    "executable_registry": {"file": "lightbulb/executable_primitives.py", "import": "from lightbulb.software_production_primitives import SOFTWARE_PRODUCTION_EXECUTABLE_PRIMITIVES", "splice": "*SOFTWARE_PRODUCTION_EXECUTABLE_PRIMITIVES in BUILTIN_EXECUTABLE_PRIMITIVES"},
    "public_exports": {"file": "lightbulb/__init__.py", "names": ["SOFTWARE_PRODUCTION_EXECUTABLE_PRIMITIVES", "SOFTWARE_PRODUCTION_INTEGRATION_MANIFEST", "RequestSoftwareProductionPrimitive", "AssessSoftwareProductionResultPrimitive", "SoftwareProductionRequest", "SoftwareProductionCompilation", "SoftwareProductionRunHandle", "SoftwareProductionReceiptSet", "SoftwareProductionResult", "SoftwareProductionComposer", "AsyncSoftwareProductionComposer", "compile_software_production_request", "assess_software_production_result", "seal_software_production_request"]},
    "mcp": {"note": "Work Package 1C generates the lifecycle projection from these schemas; no hand-written tool here."},
    "spring": {"note": "Work Package 1B binds compilation to Spring Execution Runs, harness resolution, one-use grants, CI/staging/deployment connectors, production observation, and rollback."},
    "non_goals": ["no direct OpenAI, Anthropic, Cursor, GitHub, CI, or cloud deployment client", "no hand-written MCP tool", "no automatic production authority", "no replacement Dynamic Workflow engine", "no rename of LightbulbSoftwareFactoryRuntime"],
}

__all__ = [
    "ASSESS_OPERATION",
    "REQUEST_OPERATION",
    "SOFTWARE_PRODUCTION_EXECUTABLE_PRIMITIVES",
    "SOFTWARE_PRODUCTION_INTEGRATION_MANIFEST",
    "AssessSoftwareProductionResultPrimitive",
    "RequestSoftwareProductionPrimitive",
    "example_software_production_request",
]
