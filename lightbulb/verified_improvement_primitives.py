"""Effect-dark SDK seams for the quarantined Verified Improvement design.

These primitives make the 1.0.0 manifest steps compilable and introspectable in
custom companies.  They intentionally do not manufacture trusted harness,
evaluator, or canary evidence in-process. The source authority is unavailable,
so execution returns a typed, non-retryable blocker and advertises no hosted
continuation.
"""

from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from lightbulb.primitive_runtime import (
    BusinessProcessPrimitive,
    PrimitiveBlocker,
    PrimitiveEvent,
    PrimitiveEvidence,
    PrimitiveExecutionContext,
    PrimitiveExecutionResult,
    PrimitiveExecutionStatus,
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ExecuteApprovedWorkPacketInput(_StrictModel):
    project_work_packet_binding_id: UUID


class ExecuteApprovedWorkPacketOutput(_StrictModel):
    project_work_packet_binding_id: UUID
    status: Literal["source_authority_unavailable"] = "source_authority_unavailable"
    blocker_code: Literal[
        "golden_loop.verified_improvement.source_authority_quarantined"
    ] = (
        "golden_loop.verified_improvement.source_authority_quarantined"
    )
    reviewed_harness_binding_required: Literal[True] = True
    merge_authorized: Literal[False] = False
    deploy_authorized: Literal[False] = False
    external_publish_authorized: Literal[False] = False


class ExecuteApprovedWorkPacketPrimitive(
    BusinessProcessPrimitive[
        ExecuteApprovedWorkPacketInput, ExecuteApprovedWorkPacketOutput
    ]
):
    primitive_ref = "project.execute_approved_work_packet"
    version = "1.0.0"
    title = "Execute approved work packet"
    description = (
        "Validate an opaque approved Project work-packet binding while the "
        "Verified Improvement source authority remains quarantined."
    )
    input_model = ExecuteApprovedWorkPacketInput
    output_model = ExecuteApprovedWorkPacketOutput
    connector_tools = ()
    risk_level = "high"
    approval_required = True
    mcp_read_only = False
    mcp_destructive = True
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs = {
        "project_work_packet_binding_id": "00000000-0000-0000-0000-000000000001"
    }

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: ExecuteApprovedWorkPacketInput,
    ) -> PrimitiveExecutionResult[ExecuteApprovedWorkPacketOutput]:
        return _host_authority_handoff(
            self,
            ExecuteApprovedWorkPacketOutput(
                project_work_packet_binding_id=inputs.project_work_packet_binding_id
            ),
            event_type="project.approved_work_packet_host_authority_required",
            summary=(
                "The approved packet is validly typed; signed harness execution must "
                "continue through the hosted ID-only authority."
            ),
        )


class EvaluateWorkPacketArtifactInput(_StrictModel):
    project_work_packet_binding_id: UUID


class EvaluateWorkPacketArtifactOutput(_StrictModel):
    project_work_packet_binding_id: UUID
    status: Literal["source_authority_unavailable"] = "source_authority_unavailable"
    blocker_code: Literal[
        "golden_loop.verified_improvement.source_authority_quarantined"
    ] = (
        "golden_loop.verified_improvement.source_authority_quarantined"
    )
    independent_evaluator_required: Literal[True] = True
    caller_verdict_accepted: Literal[False] = False


class EvaluateWorkPacketArtifactPrimitive(
    BusinessProcessPrimitive[
        EvaluateWorkPacketArtifactInput, EvaluateWorkPacketArtifactOutput
    ]
):
    primitive_ref = "project.evaluate_work_packet_artifact"
    version = "1.0.0"
    title = "Independently evaluate work packet artifact"
    description = (
        "Validate an opaque Project Harness Binding without accepting a "
        "caller-authored verdict while source authority is unavailable."
    )
    input_model = EvaluateWorkPacketArtifactInput
    output_model = EvaluateWorkPacketArtifactOutput
    connector_tools = ()
    risk_level = "medium"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs = {
        "project_work_packet_binding_id": "00000000-0000-0000-0000-000000000001"
    }

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: EvaluateWorkPacketArtifactInput,
    ) -> PrimitiveExecutionResult[EvaluateWorkPacketArtifactOutput]:
        return _host_authority_handoff(
            self,
            EvaluateWorkPacketArtifactOutput(
                project_work_packet_binding_id=inputs.project_work_packet_binding_id
            ),
            event_type="project.artifact_evaluator_host_authority_required",
            summary=(
                "Independent acceptance must be derived from the current signed "
                "Project Harness Binding and a separate reviewer identity."
            ),
        )


class EvaluateStagingCanaryInput(_StrictModel):
    workflow_improvement_delivery_id: UUID


class EvaluateStagingCanaryOutput(_StrictModel):
    workflow_improvement_delivery_id: UUID
    status: Literal["source_authority_unavailable"] = "source_authority_unavailable"
    blocker_code: Literal[
        "golden_loop.verified_improvement.source_authority_quarantined"
    ] = (
        "golden_loop.verified_improvement.source_authority_quarantined"
    )
    source_bound_comparison_required: Literal[True] = True
    production_deployment: Literal[False] = False
    external_publish_authorized: Literal[False] = False


class EvaluateStagingCanaryPrimitive(
    BusinessProcessPrimitive[EvaluateStagingCanaryInput, EvaluateStagingCanaryOutput]
):
    primitive_ref = "workflow.evaluate_staging_canary"
    version = "1.0.0"
    title = "Evaluate source-bound staging canary"
    description = (
        "Validate one opaque staging delivery while the comparison source "
        "authority is unavailable; this primitive cannot deploy or publish."
    )
    input_model = EvaluateStagingCanaryInput
    output_model = EvaluateStagingCanaryOutput
    connector_tools = ()
    risk_level = "medium"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs = {
        "workflow_improvement_delivery_id": (
            "00000000-0000-0000-0000-000000000002"
        )
    }

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: EvaluateStagingCanaryInput,
    ) -> PrimitiveExecutionResult[EvaluateStagingCanaryOutput]:
        return _host_authority_handoff(
            self,
            EvaluateStagingCanaryOutput(
                workflow_improvement_delivery_id=(
                    inputs.workflow_improvement_delivery_id
                )
            ),
            event_type="workflow.staging_canary_host_authority_required",
            summary=(
                "The canary comparison must be derived from server-retained staging, "
                "journal, cost, and outcome custody."
            ),
        )


def _host_authority_handoff(
    primitive: BusinessProcessPrimitive,
    output: BaseModel,
    *,
    event_type: str,
    summary: str,
) -> PrimitiveExecutionResult:
    return PrimitiveExecutionResult(
        status=PrimitiveExecutionStatus.BLOCKED,
        primitive_ref=primitive.primitive_ref,
        primitive_version=primitive.version,
        summary=summary,
        output=output,
        events=[PrimitiveEvent(type=event_type)],
        evidence=[
            PrimitiveEvidence(
                kind="authority_boundary",
                summary=(
                    "No caller-authored evidence, harness receipt, evaluator verdict, "
                    "canary result, merge, deployment, or publication was accepted."
                ),
            )
        ],
        blockers=[
            PrimitiveBlocker(
                code="golden_loop.verified_improvement.source_authority_quarantined",
                message=(
                    "The reviewed Verified Improvement source authority is quarantined; "
                    "there is no SDK, Agent, MCP, ChatGPT, or hosted continuation."
                ),
                retryable=False,
            )
        ],
        retryable=False,
    )


VERIFIED_IMPROVEMENT_EXECUTABLE_PRIMITIVES = (
    ExecuteApprovedWorkPacketPrimitive(),
    EvaluateWorkPacketArtifactPrimitive(),
    EvaluateStagingCanaryPrimitive(),
)


__all__ = [
    "EvaluateStagingCanaryInput",
    "EvaluateStagingCanaryOutput",
    "EvaluateStagingCanaryPrimitive",
    "EvaluateWorkPacketArtifactInput",
    "EvaluateWorkPacketArtifactOutput",
    "EvaluateWorkPacketArtifactPrimitive",
    "ExecuteApprovedWorkPacketInput",
    "ExecuteApprovedWorkPacketOutput",
    "ExecuteApprovedWorkPacketPrimitive",
    "VERIFIED_IMPROVEMENT_EXECUTABLE_PRIMITIVES",
]
