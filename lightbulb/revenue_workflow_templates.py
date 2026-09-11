"""Portable workflow structure, with source step evidence and fresh destination binding."""
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field
from lightbulb.company_engine_core import stable_digest
from lightbulb.revenue_workflows import RevenueGoal, RevenueWorkflowPackage, RevenueWorkflowStage, prepare_revenue_workflow


class RevenueWorkflowTemplate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_id: Literal["lightbulb.revenue_workflow_template.v1"] = "lightbulb.revenue_workflow_template.v1"
    goal: RevenueGoal
    golden_loop: str
    stages: tuple[RevenueWorkflowStage, ...] = Field(min_length=1, max_length=20)
    required_evidence: tuple[str, ...] = Field(max_length=20)
    source_evidence_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    evidence_basis: Literal["completed_owner_step_not_causal_goal_uplift"] = "completed_owner_step_not_causal_goal_uplift"
    destination_revalidation_required: Literal[True] = True
    execution_authorized: Literal[False] = False
    template_digest: str = Field(pattern=r"^[a-f0-9]{64}$")


def export_revenue_workflow_template(waits, package, *, domain, target_ref):
    """Export a candidate recipe only from a scoped, completed original owner step.

    This does not certify conversion uplift or export customer inputs, scope,
    connector identities, message copy, task IDs, or approvals.
    """
    from lightbulb.company_capability_waits import CompanyCapabilityWaits
    if not isinstance(waits, CompanyCapabilityWaits):
        raise ValueError("AUTHENTICATED_CAPABILITY_WORKER_REQUIRED")
    package = RevenueWorkflowPackage.model_validate(package)
    body = package.model_dump(mode="json", exclude={"package_digest"})
    if stable_digest(body) != package.package_digest or package.bundle_digest != waits.runner.bundle.plan_digest or not package.configuration_ready:
        raise ValueError("WORKFLOW_TEMPLATE_SOURCE_MISMATCH")
    # Rebuild the canonical stage projection; a digest alone does not establish provenance.
    plan = waits.runner.bundle.pipeline_plan if package.goal == "lead_to_meeting" else waits.runner.bundle.saas_plan
    canonical = tuple(RevenueWorkflowStage(stage=s.stage, primitive_refs=s.primitive_refs, connector_tools=s.connector_tools, gate=s.gate) for s in plan.stages) if plan else ()
    expected_evidence = prepare_revenue_workflow(package.goal, waits.runner.bundle).required_evidence
    if package.required_evidence != expected_evidence:
        raise ValueError("WORKFLOW_TEMPLATE_EVIDENCE_MISMATCH")
    if package.stages != canonical or not plan or package.golden_loop != plan.golden_loop:
        raise ValueError("WORKFLOW_TEMPLATE_PLAN_MISMATCH")
    if (package.goal == "lead_to_meeting" and domain != "sales") or (package.goal != "lead_to_meeting" and domain != "operations"):
        raise ValueError("WORKFLOW_TEMPLATE_OWNER_MISMATCH")
    doc = waits._read() or {}
    row = doc.get("entries", {}).get(waits._key(domain, target_ref))
    if not row or row["phase"] != "resumed":
        raise ValueError("WORKFLOW_TEMPLATE_COMPLETED_SOURCE_REQUIRED")
    # The caller reviews the association; source proof certifies a step, never the whole goal.
    body = dict(schema_id="lightbulb.revenue_workflow_template.v1", goal=package.goal,
        golden_loop=package.golden_loop, stages=[s.model_dump(mode="json") for s in package.stages],
        required_evidence=package.required_evidence, source_evidence_digest=stable_digest(row),
        evidence_basis="completed_owner_step_not_causal_goal_uplift", destination_revalidation_required=True, execution_authorized=False)
    return RevenueWorkflowTemplate(**body, template_digest=stable_digest(body))


def instantiate_revenue_workflow_template(template, bundle, sources=(), **configuration):
    template = RevenueWorkflowTemplate.model_validate(template)
    if stable_digest(template.model_dump(mode="json", exclude={"template_digest"})) != template.template_digest:
        raise ValueError("WORKFLOW_TEMPLATE_DIGEST_MISMATCH")
    # Imported text cannot replace code, gates, bindings or policy in the destination.
    package = prepare_revenue_workflow(template.goal, bundle, sources, **configuration)
    if package.golden_loop != template.golden_loop or package.stages != template.stages or package.required_evidence != template.required_evidence:
        raise ValueError("WORKFLOW_TEMPLATE_RECOMPILE_REQUIRED")
    return package
