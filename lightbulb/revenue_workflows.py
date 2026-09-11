"""Goal-oriented entry points over canonical company plans and the existing worker."""
from __future__ import annotations
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field
from lightbulb.company_engine_core import stable_digest
from lightbulb.company_cadence_runner import build_bundle
from lightbulb.company_preflight import worker_preflight

RevenueGoal = Literal["lead_to_meeting", "customer_activation", "renewal_recovery"]


class RevenueWorkflowStage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    stage: str = Field(min_length=1, max_length=100)
    primitive_refs: tuple[str, ...] = Field(max_length=20)
    connector_tools: tuple[str, ...] = Field(max_length=40)
    gate: str = Field(max_length=60)


class RevenueWorkflowPackage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_id: Literal["lightbulb.revenue_workflow_package.v1"] = "lightbulb.revenue_workflow_package.v1"
    goal: RevenueGoal
    bundle_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    configuration_digest: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    golden_loop: str | None
    stages: tuple[RevenueWorkflowStage, ...] = Field(max_length=20)
    blockers: tuple[str, ...] = Field(max_length=40)
    required_evidence: tuple[str, ...] = Field(max_length=20)
    configuration_ready: bool
    execution_authorized: Literal[False] = False
    package_digest: str = Field(pattern=r"^[a-f0-9]{64}$")


def prepare_revenue_workflow(goal: RevenueGoal, bundle, sources=(), **configuration):
    """Compile a reviewable package. No connector, approval, or scheduling effects."""
    if goal not in {"lead_to_meeting", "customer_activation", "renewal_recovery"}:
        raise ValueError("REVENUE_GOAL_INVALID")
    bundle = build_bundle(bundle)
    report = worker_preflight(bundle, sources, **configuration)
    blockers = [c["code"] for c in report["checks"] if c["status"] == "failed"]
    plan = bundle.pipeline_plan if goal == "lead_to_meeting" else bundle.saas_plan
    if plan is None:
        blockers.append("PIPELINE_PLAN_REQUIRED" if goal == "lead_to_meeting" else "SAAS_PLAN_REQUIRED")
    if goal == "lead_to_meeting":
        evidence = ("scoped_prospect_and_existing_thread", "current_contact_eligibility", "approved_communication_effect", "verified_meeting_receipt")
        from lightbulb.company_sales_configuration import CompanySalesConfiguration
        try:
            sales = CompanySalesConfiguration.model_validate(configuration.get("sales_config") or {})
            books = {p.spec.playbook_ref: p for p in sales.playbooks}
            if not any(books[b.playbook_ref].spec.goals.objective == "meeting" for b in sales.all_bindings() if b.playbook_ref in books):
                blockers.append("MEETING_PLAYBOOK_BINDING_REQUIRED")
        except ValueError:
            blockers.append("SALES_CONFIGURATION_INVALID")
    elif goal == "customer_activation":
        evidence = ("scoped_account_usage_snapshot", "activation_event_definition", "verified_support_or_onboarding_effect", "subsequent_activation_observation")
    else:
        evidence = ("scoped_usage_and_renewal_due", "renewal_risk_assessment", "current_contact_eligibility", "verified_renewal_provider_receipt")
        from lightbulb.company_chain_catalog import plan_for_chain
        try:
            plan_for_chain(bundle, "retention_chain")
        except (ValueError, LookupError):
            blockers.append("RETENTION_SUPPORTING_PLAN_REQUIRED")
    stages = [RevenueWorkflowStage(stage=s.stage, primitive_refs=s.primitive_refs, connector_tools=s.connector_tools, gate=s.gate).model_dump(mode="json") for s in plan.stages] if plan else []
    body = dict(schema_id="lightbulb.revenue_workflow_package.v1", goal=goal, bundle_digest=bundle.plan_digest,
        configuration_digest=report.get("configuration_digest"), golden_loop=plan.golden_loop if plan else None,
        stages=stages, blockers=sorted(set(blockers)), required_evidence=evidence,
        configuration_ready=not blockers, execution_authorized=False)
    return RevenueWorkflowPackage(**body, package_digest=stable_digest(body))


def build_revenue_worker(client, package, bundle, *, company_id, sources, worker_ref, keyring, clock=None, **configuration):
    """Revalidate the exact package, then use the authenticated production worker.

    Call the returned worker's existing start/register methods to begin its cadence.
    SaaS evidence enters through existing cadence inputs; a package is not an analytics poller.
    """
    expected = RevenueWorkflowPackage.model_validate(package)
    actual = prepare_revenue_workflow(expected.goal, bundle, sources, company_id=company_id, **configuration)
    if actual != expected:
        raise ValueError("REVENUE_WORKFLOW_CONFIGURATION_CHANGED")
    if not actual.configuration_ready:
        raise ValueError("REVENUE_WORKFLOW_CONFIGURATION_BLOCKED")
    from lightbulb.company_worker import build_worker
    return build_worker(client, bundle, company_id=company_id, sources=sources, worker_ref=worker_ref,
        keyring=keyring, **({"clock": clock} if clock is not None else {}), **configuration)
