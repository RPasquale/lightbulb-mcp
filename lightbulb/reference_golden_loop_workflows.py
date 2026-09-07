"""Canonical workflow registry for the initial GTM Golden Loops.

The entries identify one versioned workflow adapter and one exact entrypoint on
each product surface.  They remain declarative SDK data; they do not certify a
deployment, authorize execution, or promote any loop out of quarantine.
"""

from lightbulb.golden_loop_workflow_registry import (
    GoldenLoopWorkflowRegistry,
    GoldenLoopWorkflowRegistryEntry,
    GoldenLoopWorkflowSurfaceEntrypoint,
)
from lightbulb.golden_loops import LoopSurface
from lightbulb.golden_loop_projections import GoldenLoopProjectionParticipation


_PROCUREMENT_DERIVED_MATCH_BLOCKER = (
    "golden_loop.procurement.derived_match_authority_not_bound"
)


def assert_reference_golden_loop_sdk_entrypoints(
    sync_client_type: type[object],
    async_client_type: type[object],
) -> None:
    """Fail closed when a declared SDK entrypoint is absent from either client."""

    prefix = "lightbulb.client.LightbulbClient."
    failures: list[str] = []
    for entry in REFERENCE_GOLDEN_LOOP_WORKFLOW_REGISTRY.entries:
        sdk_surface = next(
            surface
            for surface in entry.surface_entrypoints
            if surface.surface is LoopSurface.SDK
        )
        if sdk_surface.participation is not GoldenLoopProjectionParticipation.CALLABLE:
            continue
        if not sdk_surface.entrypoint_ref.startswith(prefix):
            failures.append(f"{entry.loop_ref}: SDK entrypoint prefix is invalid")
            continue
        method_name = sdk_surface.entrypoint_ref.removeprefix(prefix)
        if "." in method_name or not method_name:
            failures.append(f"{entry.loop_ref}: SDK method name is invalid")
            continue
        if not callable(getattr(sync_client_type, method_name, None)):
            failures.append(f"{entry.loop_ref}: sync SDK method {method_name} is absent")
        if not callable(getattr(async_client_type, method_name, None)):
            failures.append(f"{entry.loop_ref}: async SDK method {method_name} is absent")
    if failures:
        raise RuntimeError("Golden Loop SDK entrypoint drift: " + "; ".join(failures))


def _candidate_surface(
    surface: LoopSurface, entrypoint_ref: str, blocker_code: str
) -> GoldenLoopWorkflowSurfaceEntrypoint:
    return GoldenLoopWorkflowSurfaceEntrypoint(
        surface=surface,
        entrypoint_ref=entrypoint_ref,
        participation=GoldenLoopProjectionParticipation.CANDIDATE_ONLY,
        blocker_code=blocker_code,
    )


def _blocked_surface(
    surface: LoopSurface, blocker_code: str
) -> GoldenLoopWorkflowSurfaceEntrypoint:
    return GoldenLoopWorkflowSurfaceEntrypoint(
        surface=surface,
        entrypoint_ref=f"blocked:{blocker_code}",
        participation=GoldenLoopProjectionParticipation.BLOCKED,
        blocker_code=blocker_code,
    )


CONTROL_SPEND_WORKFLOW = GoldenLoopWorkflowRegistryEntry(
    loop_ref="procurement.approved_commitment_to_matched_close",
    loop_version="0.3.0",
    execution_loop_version="0.1.0",
    workflow_ref="procurement.procure_to_pay_controlled_commitment",
    workflow_version="1.0.0",
    runtime_owner="spring_hosted_lifecycle",
    runtime_adapter_ref="spring.procurement_matched_close.unavailable",
    runtime_adapter_source_refs=(
        "lightbulb-sdk/lightbulb/procure_to_pay_lifecycle.py",
        "lightbulb-sdk/lightbulb/procurement_golden_loop.py",
        "springboot-server/src/main/java/com/project401/service/procurement/ProcurementGoldenLoopSourceAuthority.java",
        "springboot-server/src/main/java/com/project401/service/procurement/ProcurementGoldenLoopSourceStore.java",
        "springboot-server/src/main/java/com/project401/service/procurement/ProcurementThreeWayMatchCalculator.java",
        "springboot-server/src/main/java/com/project401/service/procurement/ProcurementGoldenLoopAuthority.java",
        "springboot-server/src/main/java/com/project401/service/procurement/ProcurementGoldenLoopScopeService.java",
        "springboot-server/src/main/java/com/project401/controller/ProcurementGoldenLoopController.java",
        "springboot-server/src/main/java/com/project401/service/procurement/ProcurementGoldenLoopMcpToolAdapter.java",
        "springboot-server/src/main/java/com/project401/service/economicspine/EconomicSpineRunAuthority.java",
        "springboot-server/src/main/resources/db/migration/V1976__procurement_matched_close_source_authority.sql",
        "lightbulb-sdk/lightbulb/client.py",
        "lightbulb-sdk/lightbulb/async_client.py",
        "agent-workers/agents/procurement_golden_loop_agent_projection.py",
        "agent-workers/agents/golden_loop_admission.py",
        "lightbulb-sdk/lightbulb/golden_loop_mcp.py",
        "springboot-server/src/main/java/com/project401/controller/ChatGptMcpController.java",
    ),
    surface_entrypoints=tuple(
        _blocked_surface(surface, _PROCUREMENT_DERIVED_MATCH_BLOCKER)
        for surface in LoopSurface
    ),
)


PERIOD_RECONCILIATION_WORKFLOW_V0_3 = GoldenLoopWorkflowRegistryEntry(
    loop_ref="finance.period_reconciliation_approved_close_candidate",
    loop_version="0.3.0",
    execution_loop_version="0.1.0",
    workflow_ref="finance.period_close_evidence_lifecycle",
    workflow_version="1.1.0",
    runtime_owner="spring_hosted_lifecycle",
    runtime_adapter_ref="spring.period_reconciliation",
    runtime_adapter_source_refs=(
        "lightbulb-sdk/lightbulb/finance_close_lifecycle.py",
        "lightbulb-sdk/lightbulb/finance_accounting.py",
        "lightbulb-sdk/lightbulb/period_reconciliation.py",
        "lightbulb-sdk/lightbulb/period_reconciliation_control.py",
        "springboot-server/src/main/java/com/project401/service/finance/periodclose/PeriodReconciliationAuthority.java",
        "springboot-server/src/main/java/com/project401/service/finance/periodclose/PeriodReconciliationStore.java",
        "springboot-server/src/main/java/com/project401/service/finance/periodclose/PeriodReconciliationCalculator.java",
        "springboot-server/src/main/java/com/project401/service/finance/periodclose/PeriodReconciliationOrchestrationService.java",
        "springboot-server/src/main/java/com/project401/controller/PeriodReconciliationController.java",
        "springboot-server/src/main/java/com/project401/service/finance/periodclose/PeriodReconciliationMcpToolAdapter.java",
        "springboot-server/src/main/java/com/project401/service/economicspine/EconomicSpineRunAuthority.java",
        "lightbulb-sdk/lightbulb/client.py",
        "lightbulb-sdk/lightbulb/async_client.py",
        "agent-workers/agents/period_reconciliation_agent_projection.py",
        "agent-workers/agents/golden_loop_admission.py",
        "lightbulb-sdk/lightbulb/golden_loop_mcp.py",
        "springboot-server/src/main/java/com/project401/controller/ChatGptMcpController.java",
    ),
    surface_entrypoints=(
        GoldenLoopWorkflowSurfaceEntrypoint(
            surface=LoopSurface.AGENTS,
            entrypoint_ref="blocked:golden_loop.finance.canonical_runtime_not_bound",
            participation=GoldenLoopProjectionParticipation.BLOCKED,
            blocker_code="golden_loop.finance.canonical_runtime_not_bound",
        ),
        GoldenLoopWorkflowSurfaceEntrypoint(
            surface=LoopSurface.SDK,
            entrypoint_ref="blocked:golden_loop.finance.canonical_runtime_not_bound",
            participation=GoldenLoopProjectionParticipation.BLOCKED,
            blocker_code="golden_loop.finance.canonical_runtime_not_bound",
        ),
        GoldenLoopWorkflowSurfaceEntrypoint(
            surface=LoopSurface.MCP,
            entrypoint_ref="blocked:golden_loop.finance.canonical_runtime_not_bound",
            participation=GoldenLoopProjectionParticipation.BLOCKED,
            blocker_code="golden_loop.finance.canonical_runtime_not_bound",
        ),
        GoldenLoopWorkflowSurfaceEntrypoint(
            surface=LoopSurface.CHATGPT,
            entrypoint_ref="blocked:golden_loop.finance.canonical_runtime_not_bound",
            participation=GoldenLoopProjectionParticipation.BLOCKED,
            blocker_code="golden_loop.finance.canonical_runtime_not_bound",
        ),
    ),
)

_period_reconciliation_workflow_v0_4_payload = (
    PERIOD_RECONCILIATION_WORKFLOW_V0_3.model_dump(
        mode="python",
        exclude={"workflow_binding_digest"},
    )
)
_period_reconciliation_workflow_v0_4_payload.update(
    loop_version="0.4.0",
    execution_loop_version="0.2.0",
)
PERIOD_RECONCILIATION_WORKFLOW = GoldenLoopWorkflowRegistryEntry.model_validate(
    _period_reconciliation_workflow_v0_4_payload
)
del _period_reconciliation_workflow_v0_4_payload


VERIFIED_IMPROVEMENT_WORKFLOW = GoldenLoopWorkflowRegistryEntry(
    loop_ref="workflow.verified_evidence_to_publish_approval",
    loop_version="0.3.0",
    execution_loop_version="0.1.0",
    workflow_ref="workflow.verified_improvement_delivery",
    workflow_version="0.1.0",
    runtime_owner="spring_hosted_lifecycle",
    runtime_adapter_ref="spring.economic_spine_run.verified_improvement.unavailable",
    runtime_adapter_source_refs=(
        "lightbulb-sdk/lightbulb/verified_improvement.py",
        "lightbulb-sdk/lightbulb/verified_improvement_primitives.py",
        "lightbulb-sdk/lightbulb/golden_loop_lifecycle_contracts.py",
        "springboot-server/src/main/java/com/project401/service/economicspine/EconomicSpineRunAuthority.java",
        "springboot-server/src/main/resources/db/migration/V1973__source_bound_economic_spine_v2.sql",
    ),
    surface_entrypoints=tuple(
        _blocked_surface(
            surface,
            "golden_loop.verified_improvement.source_authority_quarantined",
        )
        for surface in LoopSurface
    ),
)

CONTRACT_TO_CASH_WORKFLOW = GoldenLoopWorkflowRegistryEntry(
    loop_ref="finance.contract_to_cash_collected_cash",
    loop_version="0.2.0",
    execution_loop_version="0.1.0",
    workflow_ref="finance.contract_to_cash_continuation",
    workflow_version="0.3.0",
    runtime_owner="spring_hosted_lifecycle",
    runtime_adapter_ref="finance.contract_to_cash_continuation.adapter",
    runtime_adapter_source_refs=(
        "springboot-server/src/main/java/com/project401/service/commercial/ExecutedCommercialAgreementCustodyService.java",
        "springboot-server/src/main/java/com/project401/service/finance/contracttocash/ContractToCashInvoiceAdmissionService.java",
        "springboot-server/src/main/java/com/project401/service/finance/contracttocash/ContractToCashInvoiceIssuedService.java",
        "springboot-server/src/main/java/com/project401/service/finance/contracttocash/ContractToCashCashCollectionService.java",
        "springboot-server/src/main/java/com/project401/service/finance/contracttocash/ContractToCashRunAuthority.java",
        "springboot-server/src/main/java/com/project401/service/finance/contracttocash/ContractToCashRunStore.java",
        "lightbulb-sdk/lightbulb/contract_to_cash.py",
        "lightbulb-sdk/lightbulb/golden_loop_mcp.py",
        "springboot-server/src/main/java/com/project401/controller/ChatGptMcpController.java",
        "agent-workers/agents/contract_to_cash_agent_projection.py",
        "agent-workers/agents/golden_loop_admission.py",
    ),
    surface_entrypoints=(
        GoldenLoopWorkflowSurfaceEntrypoint(
            surface=LoopSurface.AGENTS,
            entrypoint_ref=(
                "agent-workers.agents.golden_loop_admission."
                "ManagedGoldenLoopAdmissionClient.start_contract_to_cash"
            ),
        ),
        GoldenLoopWorkflowSurfaceEntrypoint(
            surface=LoopSurface.SDK,
            entrypoint_ref=(
                "lightbulb.client.LightbulbClient."
                "start_contract_to_cash_run"
            ),
        ),
        GoldenLoopWorkflowSurfaceEntrypoint(
            surface=LoopSurface.MCP,
            entrypoint_ref="start_contract_to_cash_run",
        ),
        GoldenLoopWorkflowSurfaceEntrypoint(
            surface=LoopSurface.CHATGPT,
            entrypoint_ref="start_contract_to_cash_run",
        ),
    ),
)

FINANCE_JOURNAL_WORKFLOW = GoldenLoopWorkflowRegistryEntry(
    loop_ref="finance.journal_post_readback_settlement",
    loop_version="0.3.0",
    execution_loop_version="0.2.0",
    workflow_ref="finance.journal_post_readback_settlement",
    workflow_version="0.2.0",
    runtime_owner="spring_hosted_lifecycle",
    runtime_adapter_ref="spring.governed_finance_canary",
    runtime_adapter_source_refs=(
        "springboot-server/src/main/java/com/project401/service/tools/GovernedFinanceCanaryService.java",
        "springboot-server/src/main/java/com/project401/service/tools/GovernedFinanceCanaryStore.java",
        "springboot-server/src/main/java/com/project401/controller/internal/GovernedFinanceCanaryExecutionController.java",
    ),
    surface_entrypoints=(
        GoldenLoopWorkflowSurfaceEntrypoint(
            surface=LoopSurface.AGENTS,
            entrypoint_ref=(
                "blocked:golden_loop.finance.canonical_runtime_not_bound"
            ),
            participation=GoldenLoopProjectionParticipation.BLOCKED,
            blocker_code="golden_loop.finance.canonical_runtime_not_bound",
        ),
        GoldenLoopWorkflowSurfaceEntrypoint(
            surface=LoopSurface.SDK,
            entrypoint_ref=(
                "blocked:golden_loop.finance.canonical_runtime_not_bound"
            ),
            participation=GoldenLoopProjectionParticipation.BLOCKED,
            blocker_code="golden_loop.finance.canonical_runtime_not_bound",
        ),
        GoldenLoopWorkflowSurfaceEntrypoint(
            surface=LoopSurface.MCP,
            entrypoint_ref=(
                "blocked:golden_loop.finance.canonical_runtime_not_bound"
            ),
            participation=GoldenLoopProjectionParticipation.BLOCKED,
            blocker_code="golden_loop.finance.canonical_runtime_not_bound",
        ),
        GoldenLoopWorkflowSurfaceEntrypoint(
            surface=LoopSurface.CHATGPT,
            entrypoint_ref=(
                "blocked:golden_loop.finance.canonical_runtime_not_bound"
            ),
            participation=GoldenLoopProjectionParticipation.BLOCKED,
            blocker_code="golden_loop.finance.canonical_runtime_not_bound",
        ),
    ),
)


PROJECT_WORK_PACKET_WORKFLOW = GoldenLoopWorkflowRegistryEntry(
    loop_ref="project.work_packet_independent_acceptance",
    loop_version="0.2.0",
    execution_loop_version="0.1.0",
    workflow_ref="dynamic_workflow.project_work_packet_acceptance",
    workflow_version="0.1.0",
    runtime_owner="spring_dynamic_workflow",
    runtime_adapter_ref="dynamic_workflow.project_work_packet_acceptance.adapter",
    runtime_adapter_source_refs=(
        "springboot-server/src/main/java/com/project401/service/dynamicworkflow/SpringDynamicWorkflowAuthority.java",
        "springboot-server/src/main/java/com/project401/service/project/ProjectWorkPacketDynamicWorkflowService.java",
        "springboot-server/src/main/java/com/project401/service/project/ProjectWorkPacketGoldenLoopMcpToolAdapter.java",
        "springboot-server/src/main/java/com/project401/service/dynamicworkflow/ProjectCodingHarnessAdapterAuthority.java",
        "springboot-server/src/main/java/com/project401/service/dynamicworkflow/DynamicWorkflowMcpToolAdapter.java",
        "lightbulb-sdk/lightbulb/dynamic_workflow_control.py",
        "lightbulb-sdk/lightbulb/golden_loop_projections.py",
        "agent-workers/agents/golden_loop_admission.py",
    ),
    surface_entrypoints=(
        GoldenLoopWorkflowSurfaceEntrypoint(
            surface=LoopSurface.AGENTS,
            entrypoint_ref=(
                "agent-workers.agents.golden_loop_admission."
                "ManagedGoldenLoopAdmissionClient.start_project"
            ),
        ),
        GoldenLoopWorkflowSurfaceEntrypoint(
            surface=LoopSurface.SDK,
            entrypoint_ref="lightbulb.client.LightbulbClient.start_project_work_packet",
        ),
        GoldenLoopWorkflowSurfaceEntrypoint(
            surface=LoopSurface.MCP,
            entrypoint_ref="start_project_work_packet",
        ),
        GoldenLoopWorkflowSurfaceEntrypoint(
            surface=LoopSurface.CHATGPT,
            entrypoint_ref="start_project_work_packet",
        ),
    ),
)


REVENUE_VERIFIED_REPLY_WORKFLOW = GoldenLoopWorkflowRegistryEntry(
    loop_ref="revenue.governed_crm_turn_verified_reply",
    loop_version="0.2.0",
    execution_loop_version="0.1.0",
    workflow_ref="communication.private_dispatch_observe_reply",
    workflow_version="0.1.0",
    runtime_owner="spring_hosted_lifecycle",
    runtime_adapter_ref="communication.private_dispatch_observe_reply.adapter",
    runtime_adapter_source_refs=(
        "springboot-server/src/main/java/com/project401/service/communication/GovernedCommunicationRunService.java",
        "springboot-server/src/main/java/com/project401/controller/GovernedCommunicationRunController.java",
        "springboot-server/src/main/java/com/project401/controller/InternalGovernedCommunicationRunProjectionController.java",
        "communication-worker/communication_worker/client.py",
        "communication-worker/communication_worker/worker.py",
        "lightbulb-sdk/lightbulb/golden_loop_projections.py",
        "lightbulb-sdk/lightbulb/golden_loop_mcp.py",
        "springboot-server/src/main/java/com/project401/service/communication/GovernedCommunicationMcpToolAdapter.java",
        "agent-workers/agents/golden_loop_admission.py",
    ),
    surface_entrypoints=(
        GoldenLoopWorkflowSurfaceEntrypoint(
            surface=LoopSurface.AGENTS,
            entrypoint_ref=(
                "agent-workers.agents.golden_loop_admission."
                "ManagedGoldenLoopAdmissionClient.start_revenue"
            ),
        ),
        GoldenLoopWorkflowSurfaceEntrypoint(
            surface=LoopSurface.SDK,
            entrypoint_ref=(
                "lightbulb.client.LightbulbClient." "start_governed_communication_run"
            ),
        ),
        GoldenLoopWorkflowSurfaceEntrypoint(
            surface=LoopSurface.MCP,
            entrypoint_ref="start_governed_communication_run",
        ),
        GoldenLoopWorkflowSurfaceEntrypoint(
            surface=LoopSurface.CHATGPT,
            entrypoint_ref="start_governed_communication_run",
        ),
    ),
)


SERVICE_VERIFIED_RESOLUTION_WORKFLOW = GoldenLoopWorkflowRegistryEntry(
    loop_ref="service.case_customer_verified_resolution",
    loop_version="0.3.0",
    execution_loop_version="0.2.0",
    workflow_ref="service.case_customer_verified_resolution",
    workflow_version="0.2.0",
    runtime_owner="spring_hosted_lifecycle",
    runtime_adapter_ref="service.case_customer_verified_resolution.adapter",
    runtime_adapter_source_refs=(
        "springboot-server/src/main/java/com/project401/service/servicecase/ServiceCaseResolutionAuthority.java",
        "springboot-server/src/main/java/com/project401/controller/ServiceCaseResolutionController.java",
        "springboot-server/src/main/java/com/project401/service/servicecase/ServiceCaseGoldenLoopMcpToolAdapter.java",
        "springboot-server/src/main/java/com/project401/service/servicecase/SpringFreshserviceCaseExecutionPort.java",
        "springboot-server/src/main/java/com/project401/config/GovernedFreshserviceConfiguration.java",
        "springboot-server/src/main/java/com/project401/service/tools/connectors/GovernedFreshserviceTransport.java",
        "springboot-server/src/main/java/com/project401/service/tools/connectors/GovernedFreshserviceHttpTransport.java",
        "springboot-server/src/main/java/com/project401/service/tools/connectors/adapters/GovernedFreshserviceAdapter.java",
        "lightbulb-sdk/lightbulb/golden_loop_projections.py",
        "lightbulb-sdk/lightbulb/golden_loop_mcp.py",
        "agent-workers/agents/golden_loop_admission.py",
    ),
    surface_entrypoints=(
        GoldenLoopWorkflowSurfaceEntrypoint(
            surface=LoopSurface.AGENTS,
            entrypoint_ref=(
                "agent-workers.agents.golden_loop_admission."
                "ManagedGoldenLoopAdmissionClient.start_service"
            ),
        ),
        GoldenLoopWorkflowSurfaceEntrypoint(
            surface=LoopSurface.SDK,
            entrypoint_ref=(
                "lightbulb.client.LightbulbClient." "start_service_case_resolution"
            ),
        ),
        GoldenLoopWorkflowSurfaceEntrypoint(
            surface=LoopSurface.MCP,
            entrypoint_ref="start_service_case_resolution",
        ),
        GoldenLoopWorkflowSurfaceEntrypoint(
            surface=LoopSurface.CHATGPT,
            entrypoint_ref="start_service_case_resolution",
        ),
    ),
)


REFERENCE_GOLDEN_LOOP_WORKFLOW_REGISTRY = GoldenLoopWorkflowRegistry(
    entries=(
        CONTRACT_TO_CASH_WORKFLOW,
        FINANCE_JOURNAL_WORKFLOW,
        PERIOD_RECONCILIATION_WORKFLOW,
        CONTROL_SPEND_WORKFLOW,
        PROJECT_WORK_PACKET_WORKFLOW,
        REVENUE_VERIFIED_REPLY_WORKFLOW,
        SERVICE_VERIFIED_RESOLUTION_WORKFLOW,
        VERIFIED_IMPROVEMENT_WORKFLOW,
    )
)


__all__ = [
    "CONTRACT_TO_CASH_WORKFLOW",
    "CONTROL_SPEND_WORKFLOW",
    "FINANCE_JOURNAL_WORKFLOW",
    "PROJECT_WORK_PACKET_WORKFLOW",
    "PERIOD_RECONCILIATION_WORKFLOW",
    "PERIOD_RECONCILIATION_WORKFLOW_V0_3",
    "REFERENCE_GOLDEN_LOOP_WORKFLOW_REGISTRY",
    "REVENUE_VERIFIED_REPLY_WORKFLOW",
    "SERVICE_VERIFIED_RESOLUTION_WORKFLOW",
    "VERIFIED_IMPROVEMENT_WORKFLOW",
    "assert_reference_golden_loop_sdk_entrypoints",
]
