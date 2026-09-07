"""Host-neutral MCP projections for canonical Golden Operating Loops.

The adapter deliberately contains no workflow authority, connector custody, or
actor identity.  It resolves public company/project handles through the local
authenticated MCP session, calls the exact typed SDK lifecycle method, and
returns a bounded public projection while Spring retains private runtime identities.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from functools import wraps
from typing import Annotated, Any, Literal, Protocol, Sequence
from uuid import UUID

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import BaseModel, ConfigDict, Field

from lightbulb.contract_to_cash import (
    ContractToCashCashCollectionRecord,
    ContractToCashCashCollectionRegistration,
    ContractToCashInvoiceExecutionRequest,
    ContractToCashInvoiceIssuedRecord,
    ContractToCashInvoiceIssuedRegistration,
    ContractToCashInvoiceProposalReceipt,
    ContractToCashInvoiceProposalRequest,
    ContractToCashInvoiceWriteReceipt,
    ContractToCashRun,
    ContractToCashRunCancellation,
    ContractToCashRunRecordBinding,
    ContractToCashRunStart,
)
from lightbulb.golden_loop_certification_control import (
    GoldenLoopCertificationCandidateStatus,
    GoldenLoopCertificationProposalRequest,
    GoldenLoopCertificationSpringRecord,
)
from lightbulb.golden_loop_catalog_control import (
    GoldenLoopCatalogRegistrationRequest,
    GoldenLoopCatalogVersion,
    GoldenLoopDeclarationVersion,
)
from lightbulb.company_blueprint_control import (
    CompanyBlueprintCertificationCandidate,
    CompanyBlueprintCertificationSpringRecord,
    CompanyBlueprintCertificationStatus,
    CompanyBlueprintDeploymentCandidate,
    CompanyBlueprintDeploymentHead,
    CompanyBlueprintDeploymentStatus,
)
from lightbulb.executed_commercial_agreement_custody import (
    ExecutedCommercialAgreementCustodyCandidate,
    ExecutedCommercialAgreementRecord,
)
from lightbulb.economic_spine_runs import (
    EconomicSpineRun,
    EconomicSpineRunStart,
    EconomicSpineRunTransition,
)
from lightbulb.procurement_golden_loop import (
    ProcurementAmbiguity,
    ProcurementApprovalBinding,
    ProcurementCancellation,
    ProcurementCommandReceipt,
    ProcurementCustodyReceipt,
    ProcurementFailure,
    ProcurementGoodsReceipt,
    ProcurementMatchedClose,
    ProcurementOutcomeReceipt,
    ProcurementPurchaseOrderJournalBinding,
    ProcurementRequisitionLine,
    ProcurementReconciliation,
    ProcurementStart,
    ProcurementSupplierInvoice,
    ProcurementThreeWayMatch,
)
from lightbulb.period_reconciliation_control import (
    PeriodReconciliationCampaignFact,
    PeriodReconciliationEvaluationReceipt,
    PeriodReconciliationEvaluationRequest,
    PeriodReconciliationOutcomeFact,
    PeriodReconciliationQuickBooksReadSetRequest,
    PeriodReconciliationReadSetReceipt,
    PeriodReconciliationRestartRequest,
    PeriodReconciliationReviewReceipt,
    PeriodReconciliationReviewRequest,
    PeriodReconciliationRun,
    PeriodReconciliationRunReceipt,
    PeriodReconciliationScopeReceipt,
    PeriodReconciliationScopeRequest,
    PeriodReconciliationStageRequest,
    PeriodReconciliationStartRequest,
    PeriodReconciliationTerminalRequest,
)
from lightbulb.golden_loop_projections import (
    GoldenLoopEconomicClosureProjection,
    GoldenLoopOperation,
    GoldenLoopOperationAvailability,
    GoldenLoopProjectionParticipation,
    GoldenLoopRef,
    GoldenLoopRunProjection,
    GovernedCommunicationAdmission,
    GovernedCommunicationSourcePage,
    ProjectWorkPacketRunRead,
    ProjectWorkPacketStartResult,
    REFERENCE_GOLDEN_LOOP_PROJECTIONS,
    ServiceCaseResolutionStart,
)
from lightbulb.golden_loop_lifecycle_contracts import (
    GOLDEN_LOOP_LIFECYCLE_REGISTRY_CURRENT,
)
from lightbulb.golden_loops import LoopSurface
from lightbulb.reference_golden_loop_workflows import (
    REFERENCE_GOLDEN_LOOP_WORKFLOW_REGISTRY,
)
from lightbulb.reference_company_onboarding import (
    REFERENCE_COMPANY_CONNECTOR_PROVIDERS,
    ReferenceCompanyOnboardingPreview,
    ReferenceCompanyOnboardingReadiness,
)


OPERATING_LOOP_MCP_PROTOCOL_SCHEMA = "lightbulb.operating_loop_mcp_protocol.v1"
OPERATING_LOOP_MCP_PRIMARY_TOOL_NAMES = (
    "find_operating_loops",
    "describe_operating_loop",
    "start_operating_loop",
    "get_operating_loop_status",
    "get_operating_loop_next_action",
    "cancel_operating_loop",
    "get_operating_loop_evidence",
)

_OPERATING_LOOP_DESCRIPTORS = {
    descriptor.loop_ref.value: descriptor
    for descriptor in REFERENCE_GOLDEN_LOOP_PROJECTIONS
}


class _PublicMcpStartRequest(BaseModel):
    model_config = ConfigDict(
        extra="forbid", frozen=True, populate_by_name=True, serialize_by_alias=True
    )


_BLUEPRINT_VERSION_PUBLIC_REF = Annotated[
    str, Field(pattern=r"^blueprint-version:[0-9a-f]{32}$")
]
_TENANT_CONNECTOR_PUBLIC_REF = Annotated[
    str, Field(pattern=r"^tenant-connector:[0-9a-f]{32}$")
]


class _ReferenceCompanyConnectorSelections(_PublicMcpStartRequest):
    docusign_agreements: _TENANT_CONNECTOR_PUBLIC_REF = Field(
        alias="connector.docusign_agreements"
    )
    freshservice_customer_support: _TENANT_CONNECTOR_PUBLIC_REF = Field(
        alias="connector.freshservice_customer_support"
    )
    gmail_customer_communications: _TENANT_CONNECTOR_PUBLIC_REF = Field(
        alias="connector.gmail_customer_communications"
    )
    quickbooks_accounting: _TENANT_CONNECTOR_PUBLIC_REF = Field(
        alias="connector.quickbooks_accounting"
    )
    stripe_cash_settlement: _TENANT_CONNECTOR_PUBLIC_REF = Field(
        alias="connector.stripe_cash_settlement"
    )
    xero_procurement: _TENANT_CONNECTOR_PUBLIC_REF = Field(
        alias="connector.xero_procurement"
    )

    def exact_dict(self) -> dict[str, str]:
        return self.model_dump(mode="json", by_alias=True)


class _PublicContractToCashRunStart(_PublicMcpStartRequest):
    agreement_record_id: UUID
    idempotency_key: str = Field(min_length=1, max_length=500)


class _PublicEconomicSpineRunStart(_PublicMcpStartRequest):
    source_observation_id: UUID
    command_id: UUID


class _PublicProcurementStart(_PublicMcpStartRequest):
    command_id: UUID
    idempotency_key: str = Field(
        min_length=1,
        max_length=256,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9:/._#@~-]{0,255}$",
    )
    supplier_ref: str = Field(
        min_length=1,
        max_length=256,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9:/._#@~-]{0,255}$",
    )
    cost_center_ref: str = Field(
        min_length=1,
        max_length=256,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9:/._#@~-]{0,255}$",
    )
    budget_policy_ref: str = Field(
        min_length=1,
        max_length=256,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9:/._#@~-]{0,255}$",
    )
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    requested_total: Decimal = Field(ge=0, max_digits=18, decimal_places=9)
    lines: tuple[ProcurementRequisitionLine, ...] = Field(min_length=1, max_length=250)


class _PublicPeriodReconciliationStart(_PublicMcpStartRequest):
    source_record_id: UUID
    command_id: UUID


class _PublicPeriodReconciliationRestart(_PublicMcpStartRequest):
    scope_record_id: UUID
    terminal_run_ref: str = Field(pattern=r"^pcr_[0-9a-f]{32}$")
    command_id: UUID


class _PublicGovernedCommunicationStart(_PublicMcpStartRequest):
    source_ref: str = Field(pattern=r"^gcs_v1_[0-9a-f]{64}$")
    idempotency_key: str = Field(
        min_length=1,
        max_length=100,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,99}$",
    )


class _PublicServiceCaseResolutionStart(_PublicMcpStartRequest):
    schema_id: Literal["lightbulb.service_case_resolution_candidate.v1"] = Field(
        alias="schema"
    )
    candidate_ref: str = Field(min_length=1, max_length=200)
    candidate_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    connector_account_ref: str = Field(min_length=1, max_length=200)
    ticket_ref: str = Field(pattern=r"^[1-9][0-9]{0,18}$")
    requester_ref: str = Field(pattern=r"^[1-9][0-9]{0,18}$")
    classification_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    routing_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    resolution_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    contact_policy_decision_ref: str = Field(min_length=1, max_length=200)
    contact_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    contact_policy_expires_at: str
    reply_body: str = Field(min_length=1, max_length=7_000)
    idempotency_key: str = Field(min_length=1, max_length=240)


class _PublicCancellationRequest(_PublicMcpStartRequest):
    reason: str = Field(min_length=1, max_length=500)


def _internal_start_request(value: BaseModel, model_type: type[Any]) -> Any:
    return model_type.model_validate(
        value.model_dump(mode="python", by_alias=True, exclude_none=True)
    )


class _GoldenLoopClient(Protocol):
    def register_golden_loop_catalog(
        self,
        project_id: str,
        request: GoldenLoopCatalogRegistrationRequest,
        *,
        company_id: str,
    ) -> GoldenLoopCatalogVersion: ...

    def get_golden_loop_catalog_version(
        self,
        project_id: str,
        catalog_version_id: str,
        *,
        company_id: str,
    ) -> GoldenLoopCatalogVersion: ...

    def get_golden_loop_declaration_version(
        self,
        project_id: str,
        catalog_version_id: str,
        declaration_version_id: str,
        *,
        company_id: str,
    ) -> GoldenLoopDeclarationVersion: ...

    def propose_golden_loop_certification(
        self,
        project_id: str,
        request: GoldenLoopCertificationProposalRequest,
        *,
        company_id: str,
    ) -> GoldenLoopCertificationCandidateStatus: ...

    def get_company_blueprint_certification_candidate(
        self,
        project_id: str,
        candidate_id: str,
        *,
        company_id: str,
    ) -> CompanyBlueprintCertificationStatus: ...

    def propose_company_blueprint_certification(
        self,
        project_id: str,
        candidate: CompanyBlueprintCertificationCandidate | Mapping[str, Any],
        *,
        evidence_target_id: str,
        idempotency_key: str,
        company_id: str,
    ) -> CompanyBlueprintCertificationStatus: ...

    def prepare_company_blueprint_native_proof(
        self,
        project_id: str,
        blueprint_version_id: str,
        golden_loop_certification_record_ids: Sequence[str],
        rollback_shadow_intent_id: str,
        *,
        company_id: str,
    ) -> Mapping[str, Any]: ...

    def finalize_company_blueprint_certification(
        self,
        project_id: str,
        candidate_id: str,
        *,
        company_id: str,
    ) -> CompanyBlueprintCertificationStatus: ...

    def cancel_company_blueprint_certification(
        self,
        project_id: str,
        candidate_id: str,
        *,
        company_id: str,
    ) -> CompanyBlueprintCertificationStatus: ...

    def get_current_company_blueprint_certification(
        self,
        project_id: str,
        *,
        blueprint_version_id: str,
        environment_ref: str,
        company_id: str,
    ) -> CompanyBlueprintCertificationSpringRecord | None: ...

    def get_company_blueprint_deployment(
        self,
        project_id: str,
        deployment_id: str,
        *,
        company_id: str,
    ) -> CompanyBlueprintDeploymentStatus: ...

    def get_company_blueprint_deployment_head(
        self,
        project_id: str,
        *,
        company_id: str,
    ) -> CompanyBlueprintDeploymentHead | None: ...

    def get_reference_company_onboarding_readiness(
        self,
        project_id: str,
        *,
        company_id: str,
    ) -> ReferenceCompanyOnboardingReadiness: ...

    def preview_reference_company_onboarding(
        self,
        project_id: str,
        blueprint_version_ref: str,
        *,
        connector_selections: Mapping[str, str],
        coding_harness: str | None,
        company_id: str,
    ) -> ReferenceCompanyOnboardingPreview: ...

    def propose_company_blueprint_deployment(
        self,
        project_id: str,
        candidate: CompanyBlueprintDeploymentCandidate | Mapping[str, Any],
        *,
        idempotency_key: str,
        company_id: str,
    ) -> CompanyBlueprintDeploymentStatus: ...

    def transition_company_blueprint_deployment(
        self,
        project_id: str,
        deployment_id: str,
        *,
        action: str,
        company_id: str,
    ) -> CompanyBlueprintDeploymentStatus: ...

    def register_executed_commercial_agreement(
        self,
        project_id: str,
        candidate: ExecutedCommercialAgreementCustodyCandidate,
        *,
        company_id: str,
    ) -> ExecutedCommercialAgreementRecord: ...

    def get_executed_commercial_agreement(
        self,
        project_id: str,
        record_id: str,
        *,
        company_id: str,
    ) -> ExecutedCommercialAgreementRecord: ...

    def resolve_executed_commercial_agreement(
        self,
        project_id: str,
        agreement_ref: str,
        *,
        company_id: str,
    ) -> ExecutedCommercialAgreementRecord: ...

    def get_golden_loop_certification_candidate(
        self,
        project_id: str,
        candidate_id: str,
        *,
        company_id: str,
    ) -> GoldenLoopCertificationCandidateStatus: ...

    def get_current_golden_loop_certification(
        self,
        project_id: str,
        *,
        loop_ref: str,
        loop_version: str,
        environment_ref: str,
        company_id: str,
    ) -> GoldenLoopCertificationSpringRecord | None: ...

    def get_golden_loop_economic_closure(
        self,
        project_id: str,
        run_ref: str,
        *,
        company_id: str,
    ) -> GoldenLoopEconomicClosureProjection: ...

    def start_project_work_packet(
        self,
        project_id: str,
        *,
        company_id: str,
    ) -> ProjectWorkPacketStartResult: ...

    def get_project_work_packet_run(
        self,
        project_id: str,
        run_ref: str,
        *,
        company_id: str,
    ) -> ProjectWorkPacketRunRead: ...

    def propose_contract_to_cash_invoice(
        self,
        project_id: str,
        request: ContractToCashInvoiceProposalRequest,
        *,
        company_id: str,
    ) -> Any: ...

    def execute_contract_to_cash_invoice(
        self,
        project_id: str,
        request: ContractToCashInvoiceExecutionRequest,
        *,
        company_id: str,
    ) -> Any: ...

    def register_contract_to_cash_invoice_issued(
        self,
        project_id: str,
        request: ContractToCashInvoiceIssuedRegistration,
        *,
        company_id: str,
    ) -> ContractToCashInvoiceIssuedRecord: ...

    def get_contract_to_cash_invoice_issued(
        self,
        project_id: str,
        record_id: str,
        *,
        company_id: str,
    ) -> ContractToCashInvoiceIssuedRecord: ...

    def register_contract_to_cash_cash_collection(
        self,
        project_id: str,
        request: ContractToCashCashCollectionRegistration,
        *,
        company_id: str,
    ) -> ContractToCashCashCollectionRecord: ...

    def get_contract_to_cash_cash_collection(
        self,
        project_id: str,
        record_id: str,
        *,
        company_id: str,
    ) -> ContractToCashCashCollectionRecord: ...

    def start_contract_to_cash_run(
        self, project_id: str, request: ContractToCashRunStart, *, company_id: str
    ) -> ContractToCashRun: ...

    def get_contract_to_cash_run(
        self, project_id: str, run_ref: str, *, company_id: str
    ) -> ContractToCashRun: ...

    def attach_contract_to_cash_invoice_issued(
        self,
        project_id: str,
        run_ref: str,
        request: ContractToCashRunRecordBinding,
        *,
        company_id: str,
    ) -> ContractToCashRun: ...

    def attach_contract_to_cash_cash_collected(
        self,
        project_id: str,
        run_ref: str,
        request: ContractToCashRunRecordBinding,
        *,
        company_id: str,
    ) -> ContractToCashRun: ...

    def cancel_contract_to_cash_before_invoice(
        self,
        project_id: str,
        run_ref: str,
        request: ContractToCashRunCancellation,
        *,
        company_id: str,
    ) -> ContractToCashRun: ...

    def start_economic_spine_run(
        self, project_id: str, request: EconomicSpineRunStart, *, company_id: str
    ) -> EconomicSpineRun: ...

    def get_economic_spine_run(
        self, project_id: str, run_ref: str, *, company_id: str
    ) -> EconomicSpineRun: ...

    def advance_economic_spine_run(
        self,
        project_id: str,
        run_ref: str,
        request: EconomicSpineRunTransition,
        *,
        company_id: str,
    ) -> EconomicSpineRun: ...

    def fail_economic_spine_run(
        self,
        project_id: str,
        run_ref: str,
        request: EconomicSpineRunTransition,
        *,
        company_id: str,
    ) -> EconomicSpineRun: ...

    def cancel_economic_spine_run(
        self,
        project_id: str,
        run_ref: str,
        request: EconomicSpineRunTransition,
        *,
        company_id: str,
    ) -> EconomicSpineRun: ...

    def mark_economic_spine_effect_ambiguous(
        self,
        project_id: str,
        run_ref: str,
        request: EconomicSpineRunTransition,
        *,
        company_id: str,
    ) -> EconomicSpineRun: ...

    def reconcile_economic_spine_run(
        self,
        project_id: str,
        run_ref: str,
        request: EconomicSpineRunTransition,
        *,
        company_id: str,
    ) -> EconomicSpineRun: ...

    def start_procurement_matched_close_run(
        self, project_id: str, request: ProcurementStart, *, company_id: str
    ) -> ProcurementCommandReceipt: ...

    def submit_procurement_requisition(
        self,
        project_id: str,
        run_ref: str,
        request: ProcurementApprovalBinding,
        *,
        company_id: str,
    ) -> ProcurementCommandReceipt: ...

    def approve_procurement_spend_commitment(
        self,
        project_id: str,
        run_ref: str,
        request: ProcurementApprovalBinding,
        *,
        company_id: str,
    ) -> ProcurementCommandReceipt: ...

    def bind_procurement_xero_purchase_order_readback(
        self,
        project_id: str,
        run_ref: str,
        request: ProcurementPurchaseOrderJournalBinding,
        *,
        company_id: str,
    ) -> ProcurementCommandReceipt: ...

    def record_procurement_goods_receipt(
        self,
        project_id: str,
        run_ref: str,
        request: ProcurementGoodsReceipt,
        *,
        company_id: str,
    ) -> ProcurementCommandReceipt: ...

    def record_procurement_supplier_invoice(
        self,
        project_id: str,
        run_ref: str,
        request: ProcurementSupplierInvoice,
        *,
        company_id: str,
    ) -> ProcurementCustodyReceipt: ...

    def derive_procurement_three_way_match(
        self,
        project_id: str,
        run_ref: str,
        request: ProcurementThreeWayMatch,
        *,
        company_id: str,
    ) -> ProcurementCustodyReceipt: ...

    def approve_procurement_matched_close(
        self,
        project_id: str,
        run_ref: str,
        request: ProcurementMatchedClose,
        *,
        company_id: str,
    ) -> ProcurementCommandReceipt: ...

    def get_procurement_matched_close_run(
        self, project_id: str, run_ref: str, *, company_id: str
    ) -> ProcurementCommandReceipt: ...

    def get_procurement_matched_close_outcomes(
        self, project_id: str, run_ref: str, *, company_id: str
    ) -> ProcurementOutcomeReceipt: ...

    def fail_procurement_matched_close_run(
        self,
        project_id: str,
        run_ref: str,
        request: ProcurementFailure,
        *,
        company_id: str,
    ) -> ProcurementCommandReceipt: ...

    def cancel_procurement_matched_close_run(
        self,
        project_id: str,
        run_ref: str,
        request: ProcurementCancellation,
        *,
        company_id: str,
    ) -> ProcurementCommandReceipt: ...

    def mark_procurement_purchase_order_ambiguous(
        self,
        project_id: str,
        run_ref: str,
        request: ProcurementAmbiguity,
        *,
        company_id: str,
    ) -> ProcurementCommandReceipt: ...

    def reconcile_procurement_purchase_order(
        self,
        project_id: str,
        run_ref: str,
        request: ProcurementReconciliation,
        *,
        company_id: str,
    ) -> ProcurementCommandReceipt: ...

    def retain_period_reconciliation_scope(
        self,
        project_id: str,
        request: PeriodReconciliationScopeRequest,
        *,
        company_id: str,
    ) -> PeriodReconciliationScopeReceipt: ...

    def start_period_reconciliation_run(
        self,
        project_id: str,
        request: PeriodReconciliationStartRequest,
        *,
        company_id: str,
    ) -> PeriodReconciliationRunReceipt: ...

    def restart_period_reconciliation_run(
        self,
        project_id: str,
        request: PeriodReconciliationRestartRequest,
        *,
        company_id: str,
    ) -> PeriodReconciliationRunReceipt: ...

    def retain_period_reconciliation_quickbooks_reads(
        self,
        project_id: str,
        run_ref: str,
        request: PeriodReconciliationQuickBooksReadSetRequest,
        *,
        company_id: str,
    ) -> PeriodReconciliationReadSetReceipt: ...

    def evaluate_period_reconciliation_run(
        self,
        project_id: str,
        run_ref: str,
        request: PeriodReconciliationEvaluationRequest,
        *,
        company_id: str,
    ) -> PeriodReconciliationEvaluationReceipt: ...

    def retain_period_reconciliation_review(
        self,
        project_id: str,
        run_ref: str,
        request: PeriodReconciliationReviewRequest,
        *,
        company_id: str,
    ) -> PeriodReconciliationReviewReceipt: ...

    def advance_period_reconciliation_stage(
        self,
        project_id: str,
        run_ref: str,
        request: PeriodReconciliationStageRequest,
        *,
        company_id: str,
    ) -> PeriodReconciliationRunReceipt: ...

    def get_period_reconciliation_run(
        self, project_id: str, run_ref: str, *, company_id: str
    ) -> PeriodReconciliationRun: ...

    def get_period_reconciliation_outcomes(
        self, project_id: str, run_ref: str, *, company_id: str
    ) -> tuple[PeriodReconciliationOutcomeFact, ...]: ...

    def get_period_reconciliation_campaign_facts(
        self, project_id: str, run_ref: str, *, company_id: str
    ) -> tuple[PeriodReconciliationCampaignFact, ...]: ...

    def fail_period_reconciliation_run(
        self,
        project_id: str,
        run_ref: str,
        request: PeriodReconciliationTerminalRequest,
        *,
        company_id: str,
    ) -> PeriodReconciliationRunReceipt: ...

    def cancel_period_reconciliation_run(
        self,
        project_id: str,
        run_ref: str,
        request: PeriodReconciliationTerminalRequest,
        *,
        company_id: str,
    ) -> PeriodReconciliationRunReceipt: ...

    def start_service_case_resolution(
        self,
        project_id: str,
        request: ServiceCaseResolutionStart,
        *,
        company_id: str,
    ) -> Any: ...

    def get_service_case_resolution(
        self,
        project_id: str,
        run_ref: str,
        *,
        company_id: str,
    ) -> Any: ...

    def advance_service_case_resolution(
        self,
        project_id: str,
        run_ref: str,
        *,
        company_id: str,
    ) -> Any: ...

    def cancel_service_case_resolution(
        self,
        project_id: str,
        run_ref: str,
        *,
        reason: str,
        company_id: str,
    ) -> Any: ...

    def get_governed_communication_run(
        self,
        project_id: str,
        run_ref: str,
        *,
        company_id: str,
    ) -> Any: ...

    def list_governed_communication_sources(
        self,
        project_id: str,
        *,
        limit: int,
        cursor: str | None,
        company_id: str,
    ) -> GovernedCommunicationSourcePage: ...

    def start_governed_communication_run(
        self,
        project_id: str,
        request: GovernedCommunicationAdmission,
        *,
        idempotency_key: str,
        company_id: str,
    ) -> Any: ...

    def cancel_governed_communication_run(
        self,
        project_id: str,
        run_ref: str,
        *,
        company_id: str,
    ) -> Any: ...


ScopeResolver = Callable[[str, str], tuple[_GoldenLoopClient, Mapping[str, str]]]
JsonResult = Callable[..., str]
GOLDEN_LOOP_MCP_CORE_OPERATIONS_SCHEMA = "lightbulb.golden_loop_mcp_core_operations.v1"

McpAnnotationProfile = Literal[
    "read_only",
    "role_status",
    "internal_start",
    "internal_non_idempotent",
    "revenue_start",
    "external_idempotent_start",
    "external_non_retryable_effect",
    "coding_harness_non_retryable",
    "cancel",
    "non_idempotent_terminal",
]

MCP_ANNOTATION_PROFILE_VALUES: dict[
    McpAnnotationProfile, tuple[bool, bool, bool, bool]
] = {
    "read_only": (True, False, True, False),
    "role_status": (True, False, False, False),
    "internal_start": (False, False, True, False),
    "internal_non_idempotent": (False, False, False, False),
    "revenue_start": (False, False, True, True),
    "external_idempotent_start": (False, False, True, True),
    "external_non_retryable_effect": (False, True, False, True),
    "coding_harness_non_retryable": (False, True, False, False),
    "cancel": (False, True, True, False),
    "non_idempotent_terminal": (False, True, False, False),
}

_MCP_TOOL_ANNOTATION_PROFILES: dict[str, McpAnnotationProfile] = {
    "register_executed_commercial_agreement": "internal_start",
    "get_executed_commercial_agreement": "read_only",
    "resolve_executed_commercial_agreement": "read_only",
    "propose_contract_to_cash_invoice": "internal_start",
    "execute_contract_to_cash_invoice": "external_non_retryable_effect",
    "register_contract_to_cash_invoice_issued": "internal_start",
    "get_contract_to_cash_invoice_issued": "read_only",
    "register_contract_to_cash_cash_collection": "internal_start",
    "get_contract_to_cash_cash_collection": "read_only",
    "start_contract_to_cash_run": "internal_start",
    "get_contract_to_cash_run": "read_only",
    "attach_contract_to_cash_invoice_issued": "internal_start",
    "attach_contract_to_cash_cash_collected": "internal_start",
    "cancel_contract_to_cash_before_invoice": "cancel",
    "start_project_work_packet": "coding_harness_non_retryable",
    "get_project_work_packet_run": "read_only",
    "dynamic_workflow_status": "role_status",
    "dynamic_workflow_next_assignment": "internal_start",
    "dynamic_workflow_cancel": "cancel",
    "start_governed_communication_run": "revenue_start",
    "get_governed_communication_run": "read_only",
    "cancel_governed_communication_run": "cancel",
    "start_service_case_resolution": "external_idempotent_start",
    "get_service_case_resolution": "read_only",
    "advance_service_case_resolution": "external_non_retryable_effect",
    "cancel_service_case_resolution": "cancel",
    "start_procurement_matched_close_run": "internal_start",
    "submit_procurement_requisition": "internal_start",
    "approve_procurement_spend_commitment": "internal_start",
    "bind_procurement_xero_purchase_order_readback": "internal_start",
    "record_procurement_goods_receipt": "internal_start",
    "record_procurement_supplier_invoice": "internal_start",
    "derive_procurement_three_way_match": "internal_start",
    "approve_procurement_matched_close": "internal_start",
    "get_procurement_matched_close_run": "read_only",
    "get_procurement_matched_close_outcomes": "read_only",
    "fail_procurement_matched_close_run": "cancel",
    "cancel_procurement_matched_close_run": "cancel",
    "mark_procurement_purchase_order_ambiguous": "internal_start",
    "reconcile_procurement_purchase_order": "internal_start",
    "retain_period_reconciliation_scope": "internal_non_idempotent",
    "start_period_reconciliation_run": "internal_start",
    "restart_period_reconciliation_run": "internal_non_idempotent",
    "retain_period_reconciliation_quickbooks_reads": "internal_non_idempotent",
    "evaluate_period_reconciliation_run": "internal_non_idempotent",
    "retain_period_reconciliation_review": "internal_non_idempotent",
    "get_period_reconciliation_run": "read_only",
    "advance_period_reconciliation_stage": "internal_non_idempotent",
    "get_period_reconciliation_outcomes": "read_only",
    "get_period_reconciliation_campaign_facts": "read_only",
    "fail_period_reconciliation_run": "non_idempotent_terminal",
    "cancel_period_reconciliation_run": "non_idempotent_terminal",
}


@dataclass(frozen=True, slots=True)
class McpInputObjectShape:
    """Exact closed object at one path in a public MCP input schema."""

    path: str
    properties: tuple[str, ...]
    required: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.path.startswith(".") or self.path.endswith("."):
            raise ValueError("MCP input object paths must be canonical")
        if self.properties != tuple(sorted(set(self.properties))):
            raise ValueError("MCP input object properties must be unique and sorted")
        if self.required != tuple(sorted(set(self.required))):
            raise ValueError("MCP input required fields must be unique and sorted")
        if not set(self.required).issubset(self.properties):
            raise ValueError("MCP input required fields must be declared properties")


@dataclass(frozen=True, slots=True)
class McpInputShape:
    """All reviewed closed objects for one canonical public MCP input."""

    objects: tuple[McpInputObjectShape, ...]

    def __post_init__(self) -> None:
        paths = tuple(item.path for item in self.objects)
        if not paths or paths[0] != "":
            raise ValueError("MCP input shape must begin with the root object")
        if len(paths) != len(set(paths)):
            raise ValueError("MCP input object paths must be unique")


def _input_object(
    path: str,
    properties: Sequence[str],
    required: Sequence[str] | None = None,
) -> McpInputObjectShape:
    exact_properties = tuple(sorted(properties))
    return McpInputObjectShape(
        path=path,
        properties=exact_properties,
        required=tuple(sorted(required if required is not None else properties)),
    )


def _input_shape(
    root_properties: Sequence[str],
    *,
    root_required: Sequence[str] | None = None,
    request_properties: Sequence[str] | None = None,
    request_required: Sequence[str] | None = None,
    nested_objects: Sequence[McpInputObjectShape] = (),
) -> McpInputShape:
    objects = [
        _input_object("", root_properties, root_required),
    ]
    if request_properties is not None:
        objects.append(_input_object("request", request_properties, request_required))
    objects.extend(nested_objects)
    return McpInputShape(tuple(objects))


_SCOPED_READ = _input_shape(("company_ref", "project_ref", "run_ref"))
_SCOPED_START = ("company_ref", "project_ref", "request")
_SCOPED_MUTATION = ("company_ref", "project_ref", "request", "run_ref")
_CANCEL_REQUEST = ("reason",)

GOLDEN_LOOP_MCP_PUBLIC_FORBIDDEN_SCHEMA_FIELDS = (
    "approval_task_id",
    "close_approval_task_id",
    "model_execution_run_id",
)

GOLDEN_LOOP_MCP_PRIVATE_SCOPE_SCHEMA_FIELDS = (
    "tenant_id",
    "company_id",
    "project_id",
    "user_id",
    "actor_user_id",
    "original_user_id",
    "managed_admission_ref",
    "admission_ref",
)

_MCP_TOOL_INPUT_SHAPES: dict[str, McpInputShape] = {
    "start_contract_to_cash_run": _input_shape(
        _SCOPED_START,
        request_properties=("agreement_record_id", "idempotency_key"),
    ),
    "get_contract_to_cash_run": _SCOPED_READ,
    "cancel_contract_to_cash_before_invoice": _input_shape(
        _SCOPED_MUTATION,
        request_properties=_CANCEL_REQUEST,
    ),
    "start_project_work_packet": _input_shape(("company_ref", "project_ref")),
    "get_project_work_packet_run": _SCOPED_READ,
    "dynamic_workflow_next_assignment": _input_shape(
        (
            "company_ref",
            "expected_revision",
            "host_binding_ref",
            "host_role",
            "idempotency_key",
            "project_ref",
            "run_ref",
            "session_receipt",
        )
    ),
    "dynamic_workflow_cancel": _input_shape(
        (
            "company_ref",
            "expected_revision",
            "host_binding_ref",
            "host_role",
            "idempotency_key",
            "project_ref",
            "reason",
            "run_ref",
            "session_receipt",
        )
    ),
    "start_governed_communication_run": _input_shape(
        _SCOPED_START,
        request_properties=("idempotency_key", "source_ref"),
    ),
    "get_governed_communication_run": _SCOPED_READ,
    "cancel_governed_communication_run": _SCOPED_READ,
    "start_service_case_resolution": _input_shape(
        _SCOPED_START,
        request_properties=(
            "candidate_ref",
            "candidate_sha256",
            "classification_sha256",
            "connector_account_ref",
            "contact_policy_decision_ref",
            "contact_policy_expires_at",
            "contact_policy_sha256",
            "idempotency_key",
            "reply_body",
            "requester_ref",
            "resolution_sha256",
            "routing_sha256",
            "schema",
            "ticket_ref",
        ),
    ),
    "get_service_case_resolution": _SCOPED_READ,
    "advance_service_case_resolution": _SCOPED_READ,
    "cancel_service_case_resolution": _input_shape(
        _SCOPED_MUTATION,
        request_properties=_CANCEL_REQUEST,
    ),
}


@dataclass(frozen=True, slots=True)
class GoldenLoopMcpToolContract:
    """One reviewed mapping from a loop operation to an exact MCP tool."""

    loop_ref: GoldenLoopRef
    operation: GoldenLoopOperation
    participation: GoldenLoopProjectionParticipation
    tool_name: str | None = None
    blocker_code: str | None = None
    forbidden_tool_name: str | None = None
    annotation_profile: McpAnnotationProfile | None = None
    input_shape: McpInputShape | None = None

    def __post_init__(self) -> None:
        callable_projection = (
            self.participation is GoldenLoopProjectionParticipation.CALLABLE
        )
        if callable_projection != (self.tool_name is not None):
            raise ValueError("callable MCP projections require one exact tool_name")
        if callable_projection != (self.blocker_code is None):
            raise ValueError(
                "non-callable MCP projections require an exact blocker_code"
            )
        if callable_projection != (self.forbidden_tool_name is None):
            raise ValueError(
                "non-callable MCP projections require an exact forbidden_tool_name"
            )
        if callable_projection != (self.annotation_profile is not None):
            raise ValueError(
                "callable MCP projections require an exact annotation_profile"
            )
        if callable_projection != (self.input_shape is not None):
            raise ValueError(
                "callable MCP projections require one exact closed input shape"
            )

    def annotation_values(self) -> tuple[bool, bool, bool, bool] | None:
        if self.annotation_profile is None:
            return None
        return MCP_ANNOTATION_PROFILE_VALUES[self.annotation_profile]


def _contract(
    loop_ref: GoldenLoopRef,
    operation: GoldenLoopOperation,
    *,
    tool_name: str | None = None,
    blocker_code: str | None = None,
    forbidden_tool_name: str | None = None,
) -> GoldenLoopMcpToolContract:
    annotation_profile = (
        _MCP_TOOL_ANNOTATION_PROFILES.get(tool_name) if tool_name is not None else None
    )
    if tool_name is not None and annotation_profile is None:
        raise ValueError(f"MCP tool lacks an annotation profile: {tool_name}")
    input_shape = (
        _MCP_TOOL_INPUT_SHAPES.get(tool_name) if tool_name is not None else None
    )
    if tool_name is not None and input_shape is None:
        raise ValueError(f"MCP tool lacks an exact input shape: {tool_name}")
    return GoldenLoopMcpToolContract(
        loop_ref=loop_ref,
        operation=operation,
        participation=(
            GoldenLoopProjectionParticipation.CALLABLE
            if tool_name is not None
            else GoldenLoopProjectionParticipation.BLOCKED
        ),
        tool_name=tool_name,
        blocker_code=blocker_code,
        forbidden_tool_name=forbidden_tool_name,
        annotation_profile=annotation_profile,
        input_shape=input_shape,
    )


GOLDEN_LOOP_MCP_TOOL_CONTRACTS = (
    _contract(
        GoldenLoopRef.CONTRACT_TO_CASH,
        GoldenLoopOperation.START,
        tool_name="start_contract_to_cash_run",
    ),
    _contract(
        GoldenLoopRef.CONTRACT_TO_CASH,
        GoldenLoopOperation.GET,
        tool_name="get_contract_to_cash_run",
    ),
    _contract(
        GoldenLoopRef.CONTRACT_TO_CASH,
        GoldenLoopOperation.ADVANCE,
        blocker_code="golden_loop.contract_to_cash.advance_transition_specific",
        forbidden_tool_name="advance_contract_to_cash_run",
    ),
    _contract(
        GoldenLoopRef.CONTRACT_TO_CASH,
        GoldenLoopOperation.CANCEL,
        tool_name="cancel_contract_to_cash_before_invoice",
    ),
    _contract(
        GoldenLoopRef.FINANCE_JOURNAL,
        GoldenLoopOperation.START,
        blocker_code="golden_loop.finance.canonical_runtime_not_bound",
        forbidden_tool_name="start_finance_journal_settlement",
    ),
    _contract(
        GoldenLoopRef.FINANCE_JOURNAL,
        GoldenLoopOperation.GET,
        blocker_code="golden_loop.finance.canonical_runtime_not_bound",
        forbidden_tool_name="get_finance_journal_settlement",
    ),
    _contract(
        GoldenLoopRef.FINANCE_JOURNAL,
        GoldenLoopOperation.ADVANCE,
        blocker_code="golden_loop.finance.canonical_runtime_not_bound",
        forbidden_tool_name="advance_finance_journal_settlement",
    ),
    _contract(
        GoldenLoopRef.FINANCE_JOURNAL,
        GoldenLoopOperation.CANCEL,
        blocker_code="golden_loop.finance.canonical_runtime_not_bound",
        forbidden_tool_name="cancel_finance_journal_settlement",
    ),
    _contract(
        GoldenLoopRef.FINANCE_JOURNAL,
        GoldenLoopOperation.STEP,
        blocker_code="golden_loop.finance.canonical_runtime_not_bound",
        forbidden_tool_name="step_finance_journal_settlement",
    ),
    _contract(
        GoldenLoopRef.PROJECT_WORK_PACKET,
        GoldenLoopOperation.START,
        tool_name="start_project_work_packet",
    ),
    _contract(
        GoldenLoopRef.PROJECT_WORK_PACKET,
        GoldenLoopOperation.GET,
        tool_name="get_project_work_packet_run",
    ),
    _contract(
        GoldenLoopRef.PROJECT_WORK_PACKET,
        GoldenLoopOperation.ADVANCE,
        tool_name="dynamic_workflow_next_assignment",
    ),
    _contract(
        GoldenLoopRef.PROJECT_WORK_PACKET,
        GoldenLoopOperation.CANCEL,
        tool_name="dynamic_workflow_cancel",
    ),
    _contract(
        GoldenLoopRef.REVENUE_VERIFIED_REPLY,
        GoldenLoopOperation.START,
        tool_name="start_governed_communication_run",
    ),
    _contract(
        GoldenLoopRef.REVENUE_VERIFIED_REPLY,
        GoldenLoopOperation.GET,
        tool_name="get_governed_communication_run",
    ),
    _contract(
        GoldenLoopRef.REVENUE_VERIFIED_REPLY,
        GoldenLoopOperation.ADVANCE,
        blocker_code="golden_loop.revenue.advance_worker_only",
        forbidden_tool_name="advance_governed_communication_run",
    ),
    _contract(
        GoldenLoopRef.REVENUE_VERIFIED_REPLY,
        GoldenLoopOperation.CANCEL,
        tool_name="cancel_governed_communication_run",
    ),
    _contract(
        GoldenLoopRef.SERVICE_VERIFIED_RESOLUTION,
        GoldenLoopOperation.START,
        tool_name="start_service_case_resolution",
    ),
    _contract(
        GoldenLoopRef.SERVICE_VERIFIED_RESOLUTION,
        GoldenLoopOperation.GET,
        tool_name="get_service_case_resolution",
    ),
    _contract(
        GoldenLoopRef.SERVICE_VERIFIED_RESOLUTION,
        GoldenLoopOperation.ADVANCE,
        tool_name="advance_service_case_resolution",
    ),
    _contract(
        GoldenLoopRef.SERVICE_VERIFIED_RESOLUTION,
        GoldenLoopOperation.CANCEL,
        tool_name="cancel_service_case_resolution",
    ),
    _contract(
        GoldenLoopRef.PROCUREMENT_MATCHED_CLOSE,
        GoldenLoopOperation.START,
        blocker_code="golden_loop.procurement.derived_match_authority_not_bound",
        forbidden_tool_name="start_procurement_matched_close_run",
    ),
    _contract(
        GoldenLoopRef.PROCUREMENT_MATCHED_CLOSE,
        GoldenLoopOperation.GET,
        blocker_code="golden_loop.procurement.derived_match_authority_not_bound",
        forbidden_tool_name="get_procurement_matched_close_run",
    ),
    _contract(
        GoldenLoopRef.PROCUREMENT_MATCHED_CLOSE,
        GoldenLoopOperation.ADVANCE,
        blocker_code="golden_loop.procurement.derived_match_authority_not_bound",
        forbidden_tool_name="advance_procurement_matched_close_run",
    ),
    _contract(
        GoldenLoopRef.PROCUREMENT_MATCHED_CLOSE,
        GoldenLoopOperation.CANCEL,
        blocker_code="golden_loop.procurement.derived_match_authority_not_bound",
        forbidden_tool_name="cancel_procurement_matched_close_run",
    ),
    _contract(
        GoldenLoopRef.PERIOD_RECONCILIATION,
        GoldenLoopOperation.START,
        blocker_code="golden_loop.finance.canonical_runtime_not_bound",
        forbidden_tool_name="start_period_reconciliation_run",
    ),
    _contract(
        GoldenLoopRef.PERIOD_RECONCILIATION,
        GoldenLoopOperation.GET,
        blocker_code="golden_loop.finance.canonical_runtime_not_bound",
        forbidden_tool_name="get_period_reconciliation_run",
    ),
    _contract(
        GoldenLoopRef.PERIOD_RECONCILIATION,
        GoldenLoopOperation.ADVANCE,
        blocker_code="golden_loop.finance.canonical_runtime_not_bound",
        forbidden_tool_name="advance_period_reconciliation_stage",
    ),
    _contract(
        GoldenLoopRef.PERIOD_RECONCILIATION,
        GoldenLoopOperation.CANCEL,
        blocker_code="golden_loop.finance.canonical_runtime_not_bound",
        forbidden_tool_name="cancel_period_reconciliation_run",
    ),
    _contract(
        GoldenLoopRef.VERIFIED_IMPROVEMENT,
        GoldenLoopOperation.START,
        blocker_code="golden_loop.verified_improvement.source_authority_quarantined",
        forbidden_tool_name="start_verified_improvement_run",
    ),
    _contract(
        GoldenLoopRef.VERIFIED_IMPROVEMENT,
        GoldenLoopOperation.GET,
        blocker_code="golden_loop.verified_improvement.source_authority_quarantined",
        forbidden_tool_name="get_verified_improvement_run",
    ),
    _contract(
        GoldenLoopRef.VERIFIED_IMPROVEMENT,
        GoldenLoopOperation.ADVANCE,
        blocker_code="golden_loop.verified_improvement.source_authority_quarantined",
        forbidden_tool_name="advance_verified_improvement_run",
    ),
    _contract(
        GoldenLoopRef.VERIFIED_IMPROVEMENT,
        GoldenLoopOperation.CANCEL,
        blocker_code="golden_loop.verified_improvement.source_authority_quarantined",
        forbidden_tool_name="cancel_verified_improvement_run",
    ),
)


@dataclass(frozen=True, slots=True)
class GoldenLoopMcpLifecycleToolContract:
    """Current typed lifecycle projection consumed by every MCP host."""

    loop_ref: GoldenLoopRef
    operation_ref: str
    participation: GoldenLoopProjectionParticipation
    tool_name: str | None
    blocker_code: str | None
    forbidden_tool_name: str | None
    annotation_profile: McpAnnotationProfile | None
    operation_kind: str
    effect: str
    retry_class: str
    response_schema: str | None

    def annotation_values(self) -> tuple[bool, bool, bool, bool] | None:
        if self.annotation_profile is None:
            return None
        return MCP_ANNOTATION_PROFILE_VALUES[self.annotation_profile]


def _current_lifecycle_mcp_contracts() -> tuple[
    GoldenLoopMcpLifecycleToolContract, ...
]:
    contracts: list[GoldenLoopMcpLifecycleToolContract] = []
    for loop in GOLDEN_LOOP_LIFECYCLE_REGISTRY_CURRENT.loops:
        for operation in loop.operations:
            callable_projection = (
                operation.surface_participation
                is GoldenLoopProjectionParticipation.CALLABLE
            )
            tool_name = operation.mcp_tool_name if callable_projection else None
            annotation_profile = (
                _MCP_TOOL_ANNOTATION_PROFILES.get(str(tool_name))
                if tool_name is not None
                else None
            )
            if tool_name is not None and annotation_profile is None:
                raise RuntimeError(
                    f"Current Golden Loop MCP tool lacks a safety profile: {tool_name}"
                )
            contracts.append(
                GoldenLoopMcpLifecycleToolContract(
                    loop_ref=loop.loop_ref,
                    operation_ref=operation.operation_ref,
                    participation=operation.surface_participation,
                    tool_name=tool_name,
                    blocker_code=operation.blocker_code,
                    forbidden_tool_name=(
                        operation.forbidden_entrypoint_ref
                        if not callable_projection
                        else None
                    ),
                    annotation_profile=annotation_profile,
                    operation_kind=operation.kind.value,
                    effect=operation.effect.value,
                    retry_class=operation.retry_class.value,
                    response_schema=operation.response_schema,
                )
            )
    return tuple(contracts)


GOLDEN_LOOP_MCP_LIFECYCLE_TOOL_CONTRACTS = _current_lifecycle_mcp_contracts()
GOLDEN_LOOP_MCP_LIFECYCLE_FORBIDDEN_ALIASES = tuple(
    (alias.alias_ref, alias.blocker_code)
    for loop in GOLDEN_LOOP_LIFECYCLE_REGISTRY_CURRENT.loops
    for alias in loop.forbidden_aliases
)


def _assert_current_lifecycle_mcp_contract_parity() -> None:
    contracts = GOLDEN_LOOP_MCP_LIFECYCLE_TOOL_CONTRACTS
    callable_contracts = tuple(
        contract
        for contract in contracts
        if contract.participation is GoldenLoopProjectionParticipation.CALLABLE
    )
    blocked_contracts = tuple(
        contract
        for contract in contracts
        if contract.participation is GoldenLoopProjectionParticipation.BLOCKED
    )
    tool_names = tuple(contract.tool_name for contract in callable_contracts)
    if len(contracts) != 64 or len(callable_contracts) != 25:
        raise RuntimeError(
            "Current Golden Loop MCP lifecycle must contain 64 logical and "
            "25 callable operations"
        )
    if len(tool_names) != len(set(tool_names)):
        raise RuntimeError("Current Golden Loop MCP tool names must be unique")
    if len(blocked_contracts) != 39:
        raise RuntimeError(
            "Current Golden Loop MCP lifecycle must have 39 blocked operations"
        )
    if set(GOLDEN_LOOP_MCP_LIFECYCLE_FORBIDDEN_ALIASES) != {
        (
            "advance_contract_to_cash_run",
            "golden_loop.contract_to_cash.advance_transition_specific",
        ),
        (
            "advance_procurement_matched_close_run",
            "golden_loop.procurement.advance_transition_specific",
        ),
    }:
        raise RuntimeError("Current Golden Loop MCP forbidden aliases drifted")

    for contract in callable_contracts:
        expected = contract.annotation_values()
        if expected is None:
            raise RuntimeError(
                f"Current Golden Loop MCP safety profile is absent: {contract.operation_ref}"
            )
        read_only, destructive, idempotent, _open_world = expected
        if read_only != (contract.operation_kind == "READ"):
            raise RuntimeError(
                "Current Golden Loop MCP read-only semantics drifted: "
                f"{contract.operation_ref}"
            )
        expected_idempotent = contract.retry_class in {
            "SAFE_READ",
            "IDEMPOTENT_REPLAY",
        }
        if idempotent != expected_idempotent:
            raise RuntimeError(
                "Current Golden Loop MCP retry annotation drifted: "
                f"{contract.operation_ref}"
            )
        if contract.effect in {"EXTERNAL_WRITE", "CODING_HARNESS"} and not destructive:
            raise RuntimeError(
                "Current Golden Loop MCP dangerous effect is not destructive: "
                f"{contract.operation_ref}"
            )
        if contract.response_schema is None:
            raise RuntimeError(
                f"Current Golden Loop MCP response schema is absent: {contract.operation_ref}"
            )


_assert_current_lifecycle_mcp_contract_parity()


def _assert_reference_projection_contract_parity() -> None:
    """Fail import when the eight-loop SDK and MCP lifecycle matrices drift."""

    core_operations = {
        GoldenLoopOperation.START,
        GoldenLoopOperation.GET,
        GoldenLoopOperation.ADVANCE,
        GoldenLoopOperation.CANCEL,
    }
    contracts: dict[
        tuple[GoldenLoopRef, GoldenLoopOperation], GoldenLoopMcpToolContract
    ] = {}
    for contract in GOLDEN_LOOP_MCP_TOOL_CONTRACTS:
        key = (contract.loop_ref, contract.operation)
        if key in contracts:
            raise RuntimeError(
                "Duplicate Golden Loop MCP operation contract: "
                f"{contract.loop_ref.value}.{contract.operation.value}"
            )
        contracts[key] = contract

    expected_core = {
        (descriptor.loop_ref, operation)
        for descriptor in REFERENCE_GOLDEN_LOOP_PROJECTIONS
        for operation in core_operations
    }
    actual_core = {key for key in contracts if key[1] in core_operations}
    if actual_core != expected_core:
        missing = sorted(
            f"{loop_ref.value}.{operation.value}"
            for loop_ref, operation in expected_core.difference(actual_core)
        )
        unexpected = sorted(
            f"{loop_ref.value}.{operation.value}"
            for loop_ref, operation in actual_core.difference(expected_core)
        )
        raise RuntimeError(
            "Golden Loop MCP core operation matrix drifted from the reference "
            f"projections; missing={missing}, unexpected={unexpected}"
        )

    callable_availability = {
        GoldenLoopOperationAvailability.PUBLIC,
        GoldenLoopOperationAvailability.ROLE_PROTOCOL_ONLY,
    }
    for descriptor in REFERENCE_GOLDEN_LOOP_PROJECTIONS:
        for operation in core_operations:
            projected = descriptor.operation(operation)
            contract = contracts[(descriptor.loop_ref, operation)]
            if (projected.availability in callable_availability) != (
                contract.participation is GoldenLoopProjectionParticipation.CALLABLE
            ):
                raise RuntimeError(
                    "Golden Loop MCP availability drifted from the SDK projection: "
                    f"{descriptor.loop_ref.value}.{operation.value}"
                )

    callable_names = {
        contract.tool_name
        for contract in GOLDEN_LOOP_MCP_TOOL_CONTRACTS
        if contract.participation is GoldenLoopProjectionParticipation.CALLABLE
    }
    if callable_names != set(_MCP_TOOL_INPUT_SHAPES):
        missing = sorted(callable_names.difference(_MCP_TOOL_INPUT_SHAPES))
        unexpected = sorted(set(_MCP_TOOL_INPUT_SHAPES).difference(callable_names))
        raise RuntimeError(
            "Golden Loop MCP input-shape registry drifted from callable operations; "
            f"missing={missing}, unexpected={unexpected}"
        )


_assert_reference_projection_contract_parity()


def _resolved_schema_node(
    schema: Mapping[str, Any], root: Mapping[str, Any]
) -> Mapping[str, Any]:
    current = schema
    visited: set[str] = set()
    while "$ref" in current:
        reference = current.get("$ref")
        if not isinstance(reference, str) or not reference.startswith("#/"):
            raise RuntimeError(f"unsupported MCP schema reference: {reference}")
        if reference in visited:
            raise RuntimeError(f"cyclic MCP schema reference: {reference}")
        visited.add(reference)
        resolved: Any = root
        for part in reference[2:].split("/"):
            key = part.replace("~1", "/").replace("~0", "~")
            if not isinstance(resolved, Mapping) or key not in resolved:
                raise RuntimeError(f"unresolved MCP schema reference: {reference}")
            resolved = resolved[key]
        if not isinstance(resolved, Mapping):
            raise RuntimeError(f"MCP schema reference is not an object: {reference}")
        current = resolved
    alternatives = current.get("anyOf", current.get("oneOf"))
    if isinstance(alternatives, list):
        object_candidates = [
            _resolved_schema_node(candidate, root)
            for candidate in alternatives
            if isinstance(candidate, Mapping) and candidate.get("type") != "null"
        ]
        if len(object_candidates) == 1:
            current = object_candidates[0]
    return current


def _schema_at_object_path(root: Mapping[str, Any], path: str) -> Mapping[str, Any]:
    current = _resolved_schema_node(root, root)
    if not path:
        return current
    for raw_segment in path.split("."):
        array_item = raw_segment.endswith("[]")
        segment = raw_segment[:-2] if array_item else raw_segment
        properties = current.get("properties")
        if not isinstance(properties, Mapping) or not isinstance(
            properties.get(segment), Mapping
        ):
            raise RuntimeError(f"MCP input schema is missing object path: {path}")
        current = _resolved_schema_node(properties[segment], root)
        if array_item:
            items = current.get("items")
            if not isinstance(items, Mapping):
                raise RuntimeError(f"MCP input schema path is not an array: {path}")
            current = _resolved_schema_node(items, root)
    return current


def _assert_schema_has_no_public_forbidden_fields(
    value: Any, *, tool_name: str
) -> None:
    forbidden = set(GOLDEN_LOOP_MCP_PUBLIC_FORBIDDEN_SCHEMA_FIELDS).union(
        GOLDEN_LOOP_MCP_PRIVATE_SCOPE_SCHEMA_FIELDS
    )
    if isinstance(value, Mapping):
        properties = value.get("properties")
        if isinstance(properties, Mapping):
            leaked = forbidden.intersection(str(key) for key in properties)
            if leaked:
                raise RuntimeError(
                    "Golden Loop public MCP schema exposes private fields for "
                    f"{tool_name}: {sorted(leaked)}"
                )
        required = value.get("required")
        if isinstance(required, list):
            leaked = forbidden.intersection(str(item) for item in required)
            if leaked:
                raise RuntimeError(
                    "Golden Loop public MCP schema requires private fields for "
                    f"{tool_name}: {sorted(leaked)}"
                )
        for child in value.values():
            _assert_schema_has_no_public_forbidden_fields(child, tool_name=tool_name)
    elif isinstance(value, list):
        for child in value:
            _assert_schema_has_no_public_forbidden_fields(child, tool_name=tool_name)


def _assert_closed_public_lifecycle_input(
    parameters: Mapping[str, Any], *, tool_name: str
) -> None:
    """Fail closed for every object and every server-owned scope identity."""

    _assert_schema_has_no_public_forbidden_fields(parameters, tool_name=tool_name)

    def visit(value: Any, path: str) -> None:
        if isinstance(value, Mapping):
            if value.get("type") == "object" or "properties" in value:
                if not isinstance(value.get("properties"), Mapping):
                    raise RuntimeError(
                        "Golden Loop MCP object schema has no properties for "
                        f"{tool_name}.{path}"
                    )
                if value.get("additionalProperties") is not False:
                    raise RuntimeError(
                        f"Golden Loop MCP object schema is open for {tool_name}.{path}"
                    )
            for key, child in value.items():
                visit(child, f"{path}.{key}" if path else str(key))
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, f"{path}[{index}]")

    visit(parameters, "")
    root = _resolved_schema_node(parameters, parameters)
    properties = root.get("properties")
    if not isinstance(properties, Mapping):
        raise RuntimeError(
            f"Golden Loop MCP lifecycle input schema is absent: {tool_name}"
        )
    if not {"company_ref", "project_ref"}.issubset(properties):
        raise RuntimeError(
            f"Golden Loop MCP lifecycle input is not public-scope bound: {tool_name}"
        )
    required = root.get("required")
    if not isinstance(required, list) or not {
        "company_ref",
        "project_ref",
    }.issubset(str(item) for item in required):
        raise RuntimeError(
            "Golden Loop MCP lifecycle input does not require public scope: "
            f"{tool_name}"
        )


def _assert_exact_input_shape(
    parameters: Mapping[str, Any],
    expected: McpInputShape,
    *,
    tool_name: str,
) -> None:
    _assert_schema_has_no_public_forbidden_fields(parameters, tool_name=tool_name)
    for object_shape in expected.objects:
        schema = _schema_at_object_path(parameters, object_shape.path)
        properties = schema.get("properties")
        required = schema.get("required")
        label = object_shape.path or "<root>"
        if not isinstance(properties, Mapping):
            raise RuntimeError(
                f"Golden Loop MCP input object is absent for {tool_name}.{label}"
            )
        actual_properties = set(str(key) for key in properties)
        if actual_properties != set(object_shape.properties):
            raise RuntimeError(
                "Golden Loop MCP input properties drifted for "
                f"{tool_name}.{label}: expected={list(object_shape.properties)}, "
                f"actual={sorted(actual_properties)}"
            )
        actual_required = (
            set(str(item) for item in required) if isinstance(required, list) else set()
        )
        if actual_required != set(object_shape.required):
            raise RuntimeError(
                "Golden Loop MCP required fields drifted for "
                f"{tool_name}.{label}: expected={list(object_shape.required)}, "
                f"actual={sorted(actual_required)}"
            )
        if schema.get("additionalProperties") is not False:
            raise RuntimeError(
                f"Golden Loop MCP input object is open for {tool_name}.{label}"
            )


def assert_golden_loop_mcp_tool_contracts(
    mcp: FastMCP,
    *,
    require_all_callable: bool,
) -> None:
    """Validate the current 64/25 lifecycle plus the frozen exact core shapes."""

    tools = mcp._tool_manager._tools
    annotation_fields = (
        "readOnlyHint",
        "destructiveHint",
        "idempotentHint",
        "openWorldHint",
    )
    for contract in GOLDEN_LOOP_MCP_LIFECYCLE_TOOL_CONTRACTS:
        if contract.participation is GoldenLoopProjectionParticipation.BLOCKED:
            if contract.forbidden_tool_name in tools:
                raise RuntimeError(
                    "Blocked Golden Loop MCP lifecycle operation was registered: "
                    f"{contract.forbidden_tool_name}"
                )
            continue
        tool = tools.get(contract.tool_name)
        if tool is None:
            if require_all_callable:
                raise RuntimeError(
                    "Callable Golden Loop MCP lifecycle operation is not registered: "
                    f"{contract.tool_name}"
                )
            continue
        expected = contract.annotation_values()
        annotations = getattr(tool, "annotations", None)
        actual = tuple(getattr(annotations, field, None) for field in annotation_fields)
        if actual != expected:
            raise RuntimeError(
                "Golden Loop MCP lifecycle safety annotations drifted for "
                f"{contract.tool_name}: expected={expected}, actual={actual}"
            )
        parameters = getattr(tool, "parameters", None)
        if not isinstance(parameters, Mapping):
            raise RuntimeError(
                "Golden Loop MCP lifecycle input schema is absent: "
                f"{contract.tool_name}"
            )
        _assert_closed_public_lifecycle_input(
            parameters,
            tool_name=str(contract.tool_name),
        )

    for alias_ref, blocker_code in GOLDEN_LOOP_MCP_LIFECYCLE_FORBIDDEN_ALIASES:
        if not blocker_code:
            raise RuntimeError(
                f"Golden Loop MCP forbidden alias lacks a blocker: {alias_ref}"
            )
        if alias_ref in tools:
            raise RuntimeError(
                f"Blocked Golden Loop MCP alias was registered: {alias_ref}"
            )

    # The predecessor 33-operation matrix remains an additional exact-field
    # compatibility fence. The current lifecycle above is the coverage source.
    for contract in GOLDEN_LOOP_MCP_TOOL_CONTRACTS:
        if contract.participation is GoldenLoopProjectionParticipation.BLOCKED:
            if contract.forbidden_tool_name in tools:
                raise RuntimeError(
                    "Blocked Golden Loop MCP operation was registered: "
                    f"{contract.forbidden_tool_name}"
                )
            continue
        tool = tools.get(contract.tool_name)
        if tool is None:
            if require_all_callable:
                raise RuntimeError(
                    "Callable Golden Loop MCP operation is not registered: "
                    f"{contract.tool_name}"
                )
            continue
        expected = contract.annotation_values()
        annotations = getattr(tool, "annotations", None)
        actual = tuple(getattr(annotations, field, None) for field in annotation_fields)
        if actual != expected:
            raise RuntimeError(
                "Golden Loop MCP safety annotations drifted for "
                f"{contract.tool_name}: expected={expected}, actual={actual}"
            )
        parameters = getattr(tool, "parameters", None)
        if not isinstance(parameters, Mapping) or contract.input_shape is None:
            raise RuntimeError(
                f"Golden Loop MCP input schema is absent: {contract.tool_name}"
            )
        _assert_exact_input_shape(
            parameters,
            contract.input_shape,
            tool_name=contract.tool_name,
        )


def _reference_golden_loop_mcp_entrypoint_tool_names() -> tuple[str, ...]:
    """Derive callable MCP START names from all eight workflow declarations."""

    tool_names: list[str] = []
    for entry in REFERENCE_GOLDEN_LOOP_WORKFLOW_REGISTRY.entries:
        projections = tuple(
            projection
            for projection in entry.surface_entrypoints
            if projection.surface is LoopSurface.MCP
        )
        if len(projections) != 1:
            raise RuntimeError(
                "Each reference Golden Loop must declare exactly one MCP "
                f"entrypoint: {entry.loop_ref}@{entry.loop_version}"
            )
        projection = projections[0]
        if projection.participation is GoldenLoopProjectionParticipation.BLOCKED:
            continue
        if projection.participation is not GoldenLoopProjectionParticipation.CALLABLE:
            raise RuntimeError(
                "Reference Golden Loop MCP entrypoint is neither callable nor blocked: "
                f"{entry.loop_ref}@{entry.loop_version}"
            )
        tool_names.append(str(projection.entrypoint_ref))
    if len(tool_names) != len(set(tool_names)):
        raise RuntimeError(
            "Reference Golden Loop MCP entrypoint names must be globally unique"
        )
    return tuple(tool_names)


REFERENCE_GOLDEN_LOOP_MCP_ENTRYPOINT_TOOL_NAMES = (
    _reference_golden_loop_mcp_entrypoint_tool_names()
)


_READ_ONLY = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)
_INTERNAL_START = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)
_INTERNAL_NON_IDEMPOTENT = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=False,
    openWorldHint=False,
)
_REVENUE_START = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=True,
)
_EXTERNAL_IDEMPOTENT_START = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=True,
)
_EXTERNAL_NON_RETRYABLE_EFFECT = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=True,
    idempotentHint=False,
    openWorldHint=True,
)
_CODING_HARNESS_NON_RETRYABLE = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=True,
    idempotentHint=False,
    openWorldHint=False,
)
_CANCEL = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=True,
    idempotentHint=True,
    openWorldHint=False,
)
_NON_IDEMPOTENT_TERMINAL = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=True,
    idempotentHint=False,
    openWorldHint=False,
)
_REVENUE_SOURCE_LIST_TOOL = "list_governed_communication_sources"
_SOURCE_REF = Annotated[str, Field(pattern=r"^gcs_v1_[0-9a-f]{64}$")]
_SOURCE_CURSOR = Annotated[
    str | None,
    Field(pattern=r"^gcs_v1_[0-9a-f]{64}$"),
]
_SOURCE_PAGE_LIMIT = Annotated[int, Field(ge=1, le=50)]
_COMPANY_PUBLIC_REF_PATTERN = r"^company:[0-9a-f]{32}$"
_PROJECT_PUBLIC_REF_PATTERN = r"^project:[0-9a-f]{32}$"
_CANONICAL_COMPANY_REF = Annotated[str, Field(pattern=_COMPANY_PUBLIC_REF_PATTERN)]
_CANONICAL_PROJECT_REF = Annotated[str, Field(pattern=_PROJECT_PUBLIC_REF_PATTERN)]
_PROCUREMENT_RUN_REF = Annotated[str, Field(pattern=r"^ppr_[0-9a-f]{32}$")]
_PROCUREMENT_RECEIPT_OPERATIONS = {
    "start_procurement_matched_close_run": "START_REQUISITION",
    "submit_procurement_requisition": "REQUISITION_SUBMISSION",
    "approve_procurement_spend_commitment": "APPROVED_COMMITMENT",
    "bind_procurement_xero_purchase_order_readback": "PURCHASE_ORDER_ISSUED",
    "record_procurement_goods_receipt": "RECORD_GOODS_RECEIPT",
    "record_procurement_supplier_invoice": "RECORD_SUPPLIER_INVOICE",
    "derive_procurement_three_way_match": "DERIVE_THREE_WAY_MATCH",
    "approve_procurement_matched_close": "MATCHED_CLOSE",
    "get_procurement_matched_close_run": "GET",
    "fail_procurement_matched_close_run": "FAILED",
    "cancel_procurement_matched_close_run": "CANCELLED",
    "mark_procurement_purchase_order_ambiguous": "EFFECT_AMBIGUOUS",
    "reconcile_procurement_purchase_order": "RECONCILE",
}
_PERIOD_RECONCILIATION_RUN_REF = Annotated[str, Field(pattern=r"^pcr_[0-9a-f]{32}$")]
_IDEMPOTENCY_KEY = Annotated[
    str,
    Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,99}$"),
]
_APPROVAL_REF = Annotated[
    UUID,
    Field(description="Opaque approval reference resolved by the authenticated MCP host."),
]
_PROCUREMENT_REASON_CODE = Annotated[
    str,
    Field(
        min_length=1,
        max_length=256,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9:/._#@~-]{0,255}$",
    ),
]


class _PublicProcurementApprovalBinding(_PublicMcpStartRequest):
    requisition_source_id: UUID
    approval_ref: _APPROVAL_REF
    command_id: UUID
    idempotency_key: _IDEMPOTENCY_KEY


class _PublicProcurementMatchedClose(_PublicMcpStartRequest):
    approved_commitment_source_id: UUID
    supplier_invoice_id: UUID
    three_way_match_id: UUID
    close_approval_ref: _APPROVAL_REF
    command_id: UUID
    idempotency_key: _IDEMPOTENCY_KEY


class _PublicProcurementFailure(_PublicMcpStartRequest):
    reason_code: _PROCUREMENT_REASON_CODE
    command_id: UUID
    idempotency_key: _IDEMPOTENCY_KEY
    approved_commitment_source_id: UUID | None = None
    approval_ref: _APPROVAL_REF | None = None
    write_journal_id: UUID | None = None


class _PublicProcurementCancellation(_PublicMcpStartRequest):
    reason_code: _PROCUREMENT_REASON_CODE
    command_id: UUID
    idempotency_key: _IDEMPOTENCY_KEY
    approval_ref: _APPROVAL_REF | None = None


class _PublicProcurementReconciliation(_PublicMcpStartRequest):
    write_journal_id: UUID
    readback_journal_id: UUID
    approval_ref: _APPROVAL_REF
    reconciled_at: datetime
    command_id: UUID
    idempotency_key: _IDEMPOTENCY_KEY


class _PublicPeriodReconciliationReview(_PublicMcpStartRequest):
    evaluation_id: UUID
    approval_ref: _APPROVAL_REF


def _internal_procurement_approval(
    request: _PublicProcurementApprovalBinding,
) -> ProcurementApprovalBinding:
    return ProcurementApprovalBinding(
        requisition_source_id=request.requisition_source_id,
        approval_task_id=request.approval_ref,
        command_id=request.command_id,
        idempotency_key=request.idempotency_key,
    )


def _internal_procurement_matched_close(
    request: _PublicProcurementMatchedClose,
) -> ProcurementMatchedClose:
    return ProcurementMatchedClose(
        approved_commitment_source_id=request.approved_commitment_source_id,
        supplier_invoice_id=request.supplier_invoice_id,
        three_way_match_id=request.three_way_match_id,
        close_approval_task_id=request.close_approval_ref,
        command_id=request.command_id,
        idempotency_key=request.idempotency_key,
    )


def _internal_procurement_failure(
    request: _PublicProcurementFailure,
) -> ProcurementFailure:
    return ProcurementFailure(
        reason_code=request.reason_code,
        command_id=request.command_id,
        idempotency_key=request.idempotency_key,
        approved_commitment_source_id=request.approved_commitment_source_id,
        approval_task_id=request.approval_ref,
        write_journal_id=request.write_journal_id,
    )


def _internal_procurement_cancellation(
    request: _PublicProcurementCancellation,
) -> ProcurementCancellation:
    return ProcurementCancellation(
        reason_code=request.reason_code,
        command_id=request.command_id,
        idempotency_key=request.idempotency_key,
        approval_task_id=request.approval_ref,
    )


def _internal_procurement_reconciliation(
    request: _PublicProcurementReconciliation,
) -> ProcurementReconciliation:
    return ProcurementReconciliation(
        write_journal_id=request.write_journal_id,
        readback_journal_id=request.readback_journal_id,
        approval_task_id=request.approval_ref,
        reconciled_at=request.reconciled_at,
        command_id=request.command_id,
        idempotency_key=request.idempotency_key,
    )


def _internal_period_review(
    request: _PublicPeriodReconciliationReview,
) -> PeriodReconciliationReviewRequest:
    return PeriodReconciliationReviewRequest(
        evaluation_id=request.evaluation_id,
        approval_task_id=request.approval_ref,
    )
_BLUEPRINT_CERTIFICATION_CANDIDATE_JSON = Annotated[
    str,
    Field(
        min_length=2,
        max_length=2_000_000,
        description=(
            "Canonical CompanyBlueprintCertificationCandidate JSON emitted by "
            "the Lightbulb SDK; it is parsed into the typed contract before IO."
        ),
    ),
]
_BLUEPRINT_DEPLOYMENT_CANDIDATE_JSON = Annotated[
    str,
    Field(
        min_length=2,
        max_length=4_000_000,
        description=(
            "Canonical CompanyBlueprintDeploymentCandidate JSON emitted by the "
            "Lightbulb SDK; it is parsed into the typed contract before IO."
        ),
    ),
]


def _resolved_scope(
    resolve_scope: ScopeResolver,
    company_ref: str,
    project_ref: str,
) -> tuple[_GoldenLoopClient, str, str]:
    if not isinstance(company_ref, str) or not company_ref.strip():
        raise ValueError("company_ref must be a nonblank public handle")
    if not isinstance(project_ref, str) or not project_ref.strip():
        raise ValueError("project_ref must be a nonblank public handle")
    client, scope = resolve_scope(company_ref.strip(), project_ref.strip())
    company_id = scope.get("company_id")
    project_id = scope.get("project_id")
    if not company_id or not project_id:
        raise ValueError(
            "public company_ref/project_ref did not resolve an exact scope"
        )
    return client, company_id, project_id


def _strictly_resolved_scope(
    resolve_scope: ScopeResolver,
    company_ref: str,
    project_ref: str,
) -> tuple[_GoldenLoopClient, str, str]:
    if (
        not isinstance(company_ref, str)
        or re.fullmatch(_COMPANY_PUBLIC_REF_PATTERN, company_ref) is None
    ):
        raise ValueError(
            f"company_ref must match {_COMPANY_PUBLIC_REF_PATTERN} exactly"
        )
    if (
        not isinstance(project_ref, str)
        or re.fullmatch(_PROJECT_PUBLIC_REF_PATTERN, project_ref) is None
    ):
        raise ValueError(
            f"project_ref must match {_PROJECT_PUBLIC_REF_PATTERN} exactly"
        )
    client, scope = resolve_scope(company_ref, project_ref)
    company_id = scope.get("company_id")
    project_id = scope.get("project_id")
    if not company_id or not project_id:
        raise ValueError(
            "public company_ref/project_ref did not resolve an exact scope"
        )
    return client, company_id, project_id


def _projection(value: Any) -> GoldenLoopRunProjection:
    projected = getattr(value, "projection", value)
    if not isinstance(projected, GoldenLoopRunProjection):
        raise ValueError("Golden Loop client returned a non-projection result")
    return projected


def _public_mcp_projection(value: Any) -> Any:
    """Remove private execution and approval-task identities from public MCP values."""

    if isinstance(value, Mapping):
        projected: dict[str, Any] = {}
        for key, item in value.items():
            field = str(key)
            if field == "approval_task_id":
                field = "approval_ref"
            elif field == "close_approval_task_id":
                field = "close_approval_ref"
            elif field == "model_execution_run_id":
                continue
            projected[field] = _public_mcp_projection(item)
        return projected
    if isinstance(value, (list, tuple)):
        return [_public_mcp_projection(item) for item in value]
    return value


def _result(
    value: Any,
    *,
    operation: str,
    bounded_json_result: JsonResult,
) -> str:
    return bounded_json_result(
        _projection(value).to_dict(),
        operation=operation,
        max_chars=16_000,
        compact=True,
    )


def _project_start_result(
    value: Any,
    *,
    bounded_json_result: JsonResult,
) -> str:
    if not isinstance(value, ProjectWorkPacketStartResult):
        raise ValueError("Golden Loop client returned a non-Project-START result")
    return bounded_json_result(
        _public_mcp_projection(value.to_dict()),
        operation="start_project_work_packet",
        max_chars=16_000,
        compact=True,
    )


def _project_run_result(
    value: Any,
    *,
    bounded_json_result: JsonResult,
) -> str:
    if not isinstance(value, ProjectWorkPacketRunRead):
        raise ValueError("Golden Loop client returned a non-Project-run result")
    return bounded_json_result(
        _public_mcp_projection(value.to_dict()),
        operation="get_project_work_packet_run",
        max_chars=16_000,
        compact=True,
    )


def _contract_to_cash_result(
    value: Any,
    *,
    expected_type: type[
        ContractToCashInvoiceProposalReceipt | ContractToCashInvoiceWriteReceipt
    ],
    operation: str,
    bounded_json_result: JsonResult,
) -> str:
    if not isinstance(value, expected_type):
        raise ValueError(f"Golden Loop client returned an invalid {operation} receipt")
    return bounded_json_result(
        _public_mcp_projection(value.to_dict()),
        operation=operation,
        max_chars=16_000,
        compact=True,
    )


def _economic_spine_result(
    value: Any,
    *,
    operation: str,
    bounded_json_result: JsonResult,
) -> str:
    if not isinstance(value, EconomicSpineRun):
        raise ValueError("Golden Loop client returned an invalid economic-spine run")
    return bounded_json_result(
        _public_mcp_projection(value.to_dict()),
        operation=operation,
        max_chars=16_000,
        compact=True,
    )


def _procurement_result(
    value: Any,
    *,
    expected_type: type[Any],
    operation: str,
    bounded_json_result: JsonResult,
) -> str:
    if not isinstance(value, expected_type):
        raise ValueError(f"Golden Loop client returned an invalid {operation} receipt")
    receipt = expected_type.model_validate(value.to_dict())
    expected_operation = _PROCUREMENT_RECEIPT_OPERATIONS.get(operation)
    if expected_operation is not None and (
        getattr(receipt, "operation", None) != expected_operation
    ):
        raise ValueError(f"Golden Loop client returned the wrong {operation} receipt")
    return bounded_json_result(
        _public_mcp_projection(receipt.to_dict()),
        operation=operation,
        max_chars=16_000,
        compact=True,
    )


def _period_reconciliation_result(
    value: Any,
    *,
    expected_type: type[Any],
    operation: str,
    bounded_json_result: JsonResult,
) -> str:
    if not isinstance(value, expected_type):
        raise ValueError(
            f"Period Reconciliation client returned an invalid {operation} result"
        )
    return bounded_json_result(
        _public_mcp_projection(value.to_dict()),
        operation=operation,
        max_chars=16_000,
        compact=True,
    )


def _period_reconciliation_facts_result(
    value: Any,
    *,
    expected_type: type[Any],
    expected_count: int,
    response_key: str,
    operation: str,
    bounded_json_result: JsonResult,
) -> str:
    if (
        not isinstance(value, tuple)
        or len(value) != expected_count
        or any(not isinstance(item, expected_type) for item in value)
    ):
        raise ValueError(
            f"Period Reconciliation client returned an invalid {operation} fact set"
        )
    return bounded_json_result(
        {response_key: [item.to_dict() for item in value]},
        operation=operation,
        max_chars=64_000,
        compact=True,
    )


def _invoice_issued_result(
    value: Any,
    *,
    operation: str,
    bounded_json_result: JsonResult,
) -> str:
    if not isinstance(value, ContractToCashInvoiceIssuedRecord):
        raise ValueError("Golden Loop client returned an invalid invoice-issued record")
    return bounded_json_result(
        value.to_dict(),
        operation=operation,
        max_chars=16_000,
        compact=True,
    )


def _cash_collection_result(
    value: Any,
    *,
    operation: str,
    bounded_json_result: JsonResult,
) -> str:
    if not isinstance(value, ContractToCashCashCollectionRecord):
        raise ValueError("Golden Loop client returned an invalid collected-cash record")
    return bounded_json_result(
        value.to_dict(), operation=operation, max_chars=16_000, compact=True
    )


def _economic_closure_result(
    value: Any,
    *,
    bounded_json_result: JsonResult,
) -> str:
    if not isinstance(value, GoldenLoopEconomicClosureProjection):
        raise ValueError("Golden Loop client returned a non-closure result")
    return bounded_json_result(
        value.to_exact_dict(),
        operation="get_golden_loop_economic_closure",
        max_chars=16_000,
        compact=True,
    )


def _certification_result(
    value: Any,
    *,
    operation: str,
    bounded_json_result: JsonResult,
) -> str:
    if value is None:
        return bounded_json_result(
            {
                "schema": "lightbulb.golden_loop_certification_absent.v1",
                "current": False,
                "deployment_authorized": False,
                "external_effect_authorized": False,
            },
            operation=operation,
            max_chars=16_000,
            compact=True,
        )
    if not isinstance(
        value,
        (
            GoldenLoopCatalogVersion,
            GoldenLoopDeclarationVersion,
            GoldenLoopCertificationCandidateStatus,
            GoldenLoopCertificationSpringRecord,
        ),
    ):
        raise ValueError("Golden Loop client returned an invalid certification result")
    return bounded_json_result(
        value.model_dump(mode="json", by_alias=True),
        operation=operation,
        max_chars=32_000,
        compact=True,
    )


def _company_blueprint_result(
    value: Any,
    *,
    operation: str,
    bounded_json_result: JsonResult,
) -> str:
    certification_status_operations = {
        "get_company_blueprint_certification_candidate",
        "propose_company_blueprint_certification",
        "finalize_company_blueprint_certification",
        "cancel_company_blueprint_certification",
    }
    deployment_status_operations = {
        "get_company_blueprint_deployment",
        "propose_company_blueprint_deployment",
        "finalize_company_blueprint_deployment",
        "finalize_company_blueprint_activation",
        "request_company_blueprint_rollback",
        "finalize_company_blueprint_rollback",
        "cancel_company_blueprint_deployment",
    }
    if operation in certification_status_operations:
        expected_type: type[BaseModel] = CompanyBlueprintCertificationStatus
    elif operation == "get_current_company_blueprint_certification":
        expected_type = CompanyBlueprintCertificationSpringRecord
    elif operation in deployment_status_operations:
        expected_type = CompanyBlueprintDeploymentStatus
    elif operation == "get_company_blueprint_deployment_head":
        expected_type = CompanyBlueprintDeploymentHead
    else:
        raise ValueError("Lightbulb client returned an unexpected Blueprint operation")
    if value is None:
        if operation == "get_current_company_blueprint_certification":
            payload = {
                "schema": "lightbulb.company_blueprint_certification_absent.v1",
                "current": False,
                "deployment_authorized": False,
                "external_effect_authorized": False,
            }
        elif operation == "get_company_blueprint_deployment_head":
            payload = {
                "schema": "lightbulb.company_blueprint_deployment_head_absent.v1",
                "current": False,
                "external_effect_authorized": False,
            }
        else:
            raise ValueError("Company Blueprint client returned an unexpected absence")
        return bounded_json_result(
            payload,
            operation=operation,
            max_chars=16_000,
            compact=True,
        )
    if not isinstance(value, expected_type):
        raise ValueError(
            "Lightbulb client returned an invalid Company Blueprint result"
        )
    return bounded_json_result(
        value.model_dump(mode="json", by_alias=True),
        operation=operation,
        max_chars=64_000,
        compact=True,
    )


def _canonical_internal_uuid(value: str, *, label: str) -> str:
    try:
        parsed = UUID(str(value))
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError(f"resolved {label} is not a canonical UUID") from exc
    canonical = str(parsed)
    if canonical != str(value).lower():
        raise ValueError(f"resolved {label} is not a canonical UUID")
    return canonical


def _require_reference_onboarding_scope(
    value: ReferenceCompanyOnboardingReadiness | ReferenceCompanyOnboardingPreview,
    *,
    company_id: str,
    project_id: str,
) -> None:
    _canonical_internal_uuid(company_id, label="company_id")
    _canonical_internal_uuid(project_id, label="project_id")
    if not value.company_ref.startswith("company:") or not value.project_ref.startswith(
        "project:"
    ):
        raise ValueError("reference onboarding response has invalid public scope")


def _reference_onboarding_readiness_projection(
    value: ReferenceCompanyOnboardingReadiness,
) -> dict[str, Any]:
    if (
        not value.effect_dark
        or value.certification_claimed
        or value.deployment_authorized
        or value.external_effects_authorized
    ):
        raise ValueError("reference onboarding readiness must remain default-dark")
    return value.model_dump(mode="json", by_alias=True)


def _reference_onboarding_preview_projection(
    value: ReferenceCompanyOnboardingPreview,
) -> dict[str, Any]:
    authority = value.authority
    harness = value.coding_harness
    if (
        authority.connector_setup_performed
        or authority.credential_material_accepted
        or authority.schedules_enabled
        or authority.external_effects_enabled
        or authority.host_binding_created
        or authority.deployment_authorized
        or authority.certification_claimed
        or authority.gtm_visible
        or harness.host_binding_created
        or harness.live_session_identifier_accepted
    ):
        raise ValueError("reference onboarding preview must remain default-dark")
    return value.model_dump(mode="json", by_alias=True)


def _reference_company_onboarding_result(
    value: Any,
    *,
    operation: str,
    bounded_json_result: JsonResult,
    company_id: str,
    project_id: str,
) -> str:
    if not isinstance(
        value,
        (ReferenceCompanyOnboardingReadiness, ReferenceCompanyOnboardingPreview),
    ):
        raise ValueError("Lightbulb client returned invalid reference onboarding data")
    _require_reference_onboarding_scope(
        value,
        company_id=company_id,
        project_id=project_id,
    )
    if isinstance(value, ReferenceCompanyOnboardingReadiness):
        projection = _reference_onboarding_readiness_projection(value)
    else:
        projection = _reference_onboarding_preview_projection(value)
    return bounded_json_result(
        projection,
        operation=operation,
        max_chars=64_000,
        compact=True,
    )


def _resolve_reference_onboarding_preview_inputs(
    readiness: ReferenceCompanyOnboardingReadiness,
    *,
    blueprint_version_ref: str,
    connector_selection_refs: Mapping[str, str],
) -> tuple[str, dict[str, str]]:
    if blueprint_version_ref != readiness.blueprint.blueprint_version_ref:
        raise ValueError(
            "blueprint_version_ref is not the current authorized readiness selection"
        )
    if set(connector_selection_refs) != set(REFERENCE_COMPANY_CONNECTOR_PROVIDERS):
        raise ValueError(
            "connector_selections must exactly cover the six reference requirements"
        )

    resolved: dict[str, str] = {}
    for requirement in readiness.connector_requirements:
        supplied_ref = connector_selection_refs[requirement.requirement_ref]
        matches = [
            candidate
            for candidate in requirement.candidates
            if candidate.tenant_connector_ref == supplied_ref
        ]
        if len(matches) != 1:
            raise ValueError(
                "connector selection is not a current authorized readiness candidate: "
                + requirement.requirement_ref
            )
        resolved[requirement.requirement_ref] = matches[0].tenant_connector_ref
    return readiness.blueprint.blueprint_version_ref, resolved


def _require_preview_matches_fresh_readiness(
    preview: ReferenceCompanyOnboardingPreview,
    *,
    readiness: ReferenceCompanyOnboardingReadiness,
    connector_selections: Mapping[str, str],
) -> None:
    if (
        preview.company_ref != readiness.company_ref
        or preview.project_ref != readiness.project_ref
    ):
        raise ValueError("onboarding preview does not match the fresh readiness scope")
    if preview.blueprint.blueprint_version_ref != (
        readiness.blueprint.blueprint_version_ref
    ):
        raise ValueError("onboarding preview does not match the fresh Blueprint choice")
    projected_selections = {
        selection.requirement_ref: selection.tenant_connector_ref
        for selection in preview.connector_selections
    }
    if projected_selections != dict(connector_selections):
        raise ValueError(
            "onboarding preview does not match the fresh connector choices"
        )


def _executed_agreement_result(
    value: Any,
    *,
    operation: str,
    bounded_json_result: JsonResult,
) -> str:
    if not isinstance(value, ExecutedCommercialAgreementRecord):
        raise ValueError("Lightbulb client returned an invalid executed agreement")
    return bounded_json_result(
        value.model_dump(mode="json", by_alias=True),
        operation=operation,
        max_chars=16_000,
        compact=True,
    )


def _close_object_schemas(value: Any) -> None:
    """Make every object in these bounded input contracts fail closed."""

    if isinstance(value, dict):
        if value.get("type") == "object" or "properties" in value:
            additional = value.get("additionalProperties")
            if additional not in (None, False):
                raise RuntimeError(
                    "Golden Loop MCP inputs may not contain open object schemas"
                )
            value["additionalProperties"] = False
        for child in value.values():
            _close_object_schemas(child)
    elif isinstance(value, list):
        for child in value:
            _close_object_schemas(child)


def _operating_loop_descriptor(loop_ref: str) -> Any:
    descriptor = _OPERATING_LOOP_DESCRIPTORS.get(str(loop_ref).strip())
    if descriptor is None:
        raise ValueError("loop_ref must name one canonical Golden Operating Loop")
    return descriptor


def _operating_loop_public_value(value: Any) -> Any:
    """Project authority values without private identity or provider payloads."""

    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json", by_alias=True, exclude_none=True)
    elif not isinstance(value, (Mapping, list, tuple)) and callable(
        getattr(value, "to_dict", None)
    ):
        value = value.to_dict()
    if isinstance(value, Mapping):
        projected: dict[str, Any] = {}
        for key, item in value.items():
            field = str(key)
            normalized = re.sub(r"[^a-z0-9]+", "_", field.lower()).strip("_")
            if field == "approval_task_id":
                field = "approval_ref"
            elif field == "close_approval_task_id":
                field = "close_approval_ref"
            elif normalized == "id" or normalized.endswith("_id"):
                continue
            elif any(
                sensitive in normalized
                for sensitive in (
                    "access_token",
                    "api_key",
                    "authorization",
                    "client_secret",
                    "credential",
                    "password",
                    "private_key",
                    "provider_payload",
                    "raw_payload",
                    "refresh_token",
                    "secret",
                    "session_receipt",
                    "signing_key",
                )
            ):
                continue
            projected[field] = _operating_loop_public_value(item)
        return projected
    if isinstance(value, (list, tuple)):
        return [_operating_loop_public_value(item) for item in value]
    return value


def _operating_loop_read(
    *,
    client: _GoldenLoopClient,
    company_id: str,
    project_id: str,
    loop_ref: str,
    run_ref: str,
) -> Any:
    descriptor = _operating_loop_descriptor(loop_ref)
    if re.fullmatch(descriptor.canonical_run_ref_pattern, run_ref) is None:
        raise ValueError("run_ref does not belong to the selected Golden Operating Loop")
    if descriptor.loop_ref in {
        GoldenLoopRef.FINANCE_JOURNAL,
        GoldenLoopRef.PERIOD_RECONCILIATION,
    }:
        return _operating_loop_blocked(
            loop_ref=descriptor.loop_ref.value,
            run_ref=run_ref,
            blocker_code="golden_loop.finance.canonical_runtime_not_bound",
            message=(
                "The canonical finance source authority is effect-dark and has no "
                "model-callable runtime."
            ),
        )
    if descriptor.loop_ref is GoldenLoopRef.PROCUREMENT_MATCHED_CLOSE:
        return _operating_loop_blocked(
            loop_ref=descriptor.loop_ref.value,
            run_ref=run_ref,
            blocker_code=(
                "golden_loop.procurement.derived_match_authority_not_bound"
            ),
            message=(
                "Procurement match truth lacks DB-owned source authority; no "
                "hosted run can be read or advanced."
            ),
        )
    if descriptor.loop_ref is GoldenLoopRef.VERIFIED_IMPROVEMENT:
        return _operating_loop_blocked(
            loop_ref=descriptor.loop_ref.value,
            run_ref=run_ref,
            blocker_code=(
                "golden_loop.verified_improvement.source_authority_quarantined"
            ),
            message=(
                "Verified Improvement source custody is quarantined; no hosted "
                "run can be read or advanced."
            ),
        )
    readers = {
        GoldenLoopRef.CONTRACT_TO_CASH.value: "get_contract_to_cash_run",
        GoldenLoopRef.PROJECT_WORK_PACKET.value: "get_project_work_packet_run",
        GoldenLoopRef.REVENUE_VERIFIED_REPLY.value: (
            "get_governed_communication_run"
        ),
        GoldenLoopRef.SERVICE_VERIFIED_RESOLUTION.value: (
            "get_service_case_resolution"
        ),
    }
    method = getattr(client, readers[loop_ref])
    return method(project_id, run_ref, company_id=company_id)


def _operating_loop_blocked(
    *,
    loop_ref: str,
    blocker_code: str,
    message: str,
    run_ref: str | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema": OPERATING_LOOP_MCP_PROTOCOL_SCHEMA,
        "loop_ref": loop_ref,
        "state": "BLOCKED",
        "external_effect_authorized": False,
        "blockers": [{"code": blocker_code, "message": message}],
    }
    if run_ref is not None:
        payload["run_ref"] = run_ref
    return payload


_MODEL_FACING_CONTROL_BLOCKERS: dict[str, tuple[str, str]] = {
    "register_golden_loop_catalog": (
        "golden_loop.catalog.authority_not_bound",
        "Golden Loop catalog custody is not bound to this hosted control plane.",
    ),
    "get_golden_loop_catalog_version": (
        "golden_loop.catalog.authority_not_bound",
        "Golden Loop catalog custody is not bound to this hosted control plane.",
    ),
    "get_golden_loop_declaration_version": (
        "golden_loop.catalog.authority_not_bound",
        "Golden Loop catalog custody is not bound to this hosted control plane.",
    ),
    "propose_golden_loop_certification": (
        "golden_loop.certification.operator_only",
        "Golden Loop certification remains outside model-facing MCP.",
    ),
    "get_golden_loop_certification_candidate": (
        "golden_loop.certification.operator_only",
        "Golden Loop certification remains outside model-facing MCP.",
    ),
    "get_current_golden_loop_certification": (
        "golden_loop.certification.operator_only",
        "Golden Loop certification remains outside model-facing MCP.",
    ),
    "get_reference_company_onboarding_readiness": (
        "reference_company.onboarding.source_authority_quarantined",
        "Reference-company onboarding depends on quarantined source authority.",
    ),
    "preview_reference_company_onboarding": (
        "reference_company.onboarding.source_authority_quarantined",
        "Reference-company onboarding depends on quarantined source authority.",
    ),
    "get_company_blueprint_certification_candidate": (
        "company_blueprint.certification.operator_only",
        "Company Blueprint certification remains outside model-facing MCP.",
    ),
    "prepare_company_blueprint_native_proof": (
        "company_blueprint.certification.operator_only",
        "Company Blueprint certification remains outside model-facing MCP.",
    ),
    "propose_company_blueprint_certification": (
        "company_blueprint.certification.operator_only",
        "Company Blueprint certification remains outside model-facing MCP.",
    ),
    "finalize_company_blueprint_certification": (
        "company_blueprint.certification.operator_only",
        "Company Blueprint certification remains outside model-facing MCP.",
    ),
    "cancel_company_blueprint_certification": (
        "company_blueprint.certification.operator_only",
        "Company Blueprint certification remains outside model-facing MCP.",
    ),
    "get_current_company_blueprint_certification": (
        "company_blueprint.certification.operator_only",
        "Company Blueprint certification remains outside model-facing MCP.",
    ),
    "get_company_blueprint_deployment": (
        "company_blueprint.deployment.authority_quarantined",
        "Company Blueprint deployment authority remains quarantined.",
    ),
    "propose_company_blueprint_deployment": (
        "company_blueprint.deployment.authority_quarantined",
        "Company Blueprint deployment authority remains quarantined.",
    ),
    "finalize_company_blueprint_deployment": (
        "company_blueprint.deployment.authority_quarantined",
        "Company Blueprint deployment authority remains quarantined.",
    ),
    "finalize_company_blueprint_activation": (
        "company_blueprint.deployment.authority_quarantined",
        "Company Blueprint deployment authority remains quarantined.",
    ),
    "request_company_blueprint_rollback": (
        "company_blueprint.deployment.authority_quarantined",
        "Company Blueprint deployment authority remains quarantined.",
    ),
    "finalize_company_blueprint_rollback": (
        "company_blueprint.deployment.authority_quarantined",
        "Company Blueprint deployment authority remains quarantined.",
    ),
    "cancel_company_blueprint_deployment": (
        "company_blueprint.deployment.authority_quarantined",
        "Company Blueprint deployment authority remains quarantined.",
    ),
    "get_company_blueprint_deployment_head": (
        "company_blueprint.deployment.authority_quarantined",
        "Company Blueprint deployment authority remains quarantined.",
    ),
}


def register_golden_loop_mcp_tools(
    mcp: FastMCP,
    *,
    resolve_scope: ScopeResolver,
    bounded_json_result: JsonResult,
) -> tuple[str, ...]:
    """Register lifecycle tools and return the verified FastMCP registry delta.

    The returned membership is derived from the tools actually installed, then
    checked against callable contracts and callable reference workflow START
    entrypoints. It is safe for compact MCP profiles to consume directly.
    """

    tools = getattr(getattr(mcp, "_tool_manager", None), "_tools", None)
    if not isinstance(tools, dict):
        raise RuntimeError("FastMCP tool registry shape changed")
    registered_before = dict(tools)

    def fail_closed_model_control(function: Callable[..., str]) -> Callable[..., str]:
        """Preserve a typed private schema while withholding unavailable authority."""

        blocker_code, message = _MODEL_FACING_CONTROL_BLOCKERS[function.__name__]

        @wraps(function)
        def blocked(
            company_ref: str,
            project_ref: str,
            *args: Any,
            **kwargs: Any,
        ) -> str:
            del args, kwargs
            _resolved_scope(resolve_scope, company_ref, project_ref)
            return bounded_json_result(
                {
                    "schema": "lightbulb.model_control_unavailable.v1",
                    "operation": function.__name__,
                    "state": "BLOCKED",
                    "external_effect_authorized": False,
                    "blockers": [{"code": blocker_code, "message": message}],
                },
                operation=function.__name__,
                max_chars=8_000,
                compact=True,
            )

        return blocked

    @mcp.tool(annotations=_READ_ONLY)
    def find_operating_loops(
        query: str = "",
        limit: Annotated[int, Field(ge=1, le=8)] = 8,
    ) -> str:
        """Find canonical Golden Operating Loops; discovery grants no authority."""

        needle = query.strip().lower()
        matches = []
        for descriptor in REFERENCE_GOLDEN_LOOP_PROJECTIONS:
            searchable = " ".join(
                (
                    descriptor.loop_ref.value,
                    descriptor.loop_version,
                    descriptor.lifecycle,
                )
            ).lower()
            if needle and needle not in searchable:
                continue
            matches.append(
                {
                    "loop_ref": descriptor.loop_ref.value,
                    "loop_version": descriptor.loop_version,
                    "lifecycle": descriptor.lifecycle,
                    "run_ref_pattern": descriptor.canonical_run_ref_pattern,
                    "external_effect_authorized": False,
                }
            )
        return bounded_json_result(
            {
                "schema": OPERATING_LOOP_MCP_PROTOCOL_SCHEMA,
                "count": min(len(matches), limit),
                "loops": matches[:limit],
            },
            operation="find_operating_loops",
            max_chars=16_000,
            compact=True,
        )

    @mcp.tool(annotations=_READ_ONLY)
    def describe_operating_loop(loop_ref: str) -> str:
        """Describe one versioned loop and its honest quarantined availability."""

        descriptor = _operating_loop_descriptor(loop_ref)
        return bounded_json_result(
            {
                "schema": OPERATING_LOOP_MCP_PROTOCOL_SCHEMA,
                "loop": descriptor.to_dict(),
                "primary_protocol": list(OPERATING_LOOP_MCP_PRIMARY_TOOL_NAMES),
                "raw_lifecycle_operations": "advanced_private",
                "certification_activation_model_callable": False,
                "operator_countersign_model_callable": False,
                "external_effect_authorized": False,
            },
            operation="describe_operating_loop",
            max_chars=32_000,
            compact=True,
        )

    @mcp.tool(annotations=_INTERNAL_START)
    def start_operating_loop(
        company_ref: str,
        project_ref: str,
        loop_ref: str,
    ) -> str:
        """Request loop admission; quarantined catalog entries fail closed."""

        descriptor = _operating_loop_descriptor(loop_ref)
        _resolved_scope(resolve_scope, company_ref, project_ref)
        return bounded_json_result(
            _operating_loop_blocked(
                loop_ref=descriptor.loop_ref.value,
                blocker_code="operating_loop.quarantined",
                message=(
                    "This loop is quarantined. A model cannot activate certification, "
                    "invent provider authority, or bypass its typed advanced admission."
                ),
            ),
            operation="start_operating_loop",
            max_chars=8_000,
            compact=True,
        )

    @mcp.tool(annotations=_READ_ONLY)
    def get_operating_loop_status(
        company_ref: str,
        project_ref: str,
        loop_ref: str,
        run_ref: str,
    ) -> str:
        """Read one exact loop run through its Spring-scoped SDK authority."""

        descriptor = _operating_loop_descriptor(loop_ref)
        client, company_id, project_id = _resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        status = _operating_loop_read(
            client=client,
            company_id=company_id,
            project_id=project_id,
            loop_ref=descriptor.loop_ref.value,
            run_ref=run_ref,
        )
        return bounded_json_result(
            {
                "schema": OPERATING_LOOP_MCP_PROTOCOL_SCHEMA,
                "loop_ref": descriptor.loop_ref.value,
                "loop_version": descriptor.loop_version,
                "run_ref": run_ref,
                "status": _operating_loop_public_value(status),
            },
            operation="get_operating_loop_status",
            max_chars=32_000,
            compact=True,
        )

    @mcp.tool(annotations=_READ_ONLY)
    def get_operating_loop_next_action(
        company_ref: str,
        project_ref: str,
        loop_ref: str,
        run_ref: str,
    ) -> str:
        """Read the next governed action without advancing or dispatching a write."""

        descriptor = _operating_loop_descriptor(loop_ref)
        if re.fullmatch(descriptor.canonical_run_ref_pattern, run_ref) is None:
            raise ValueError(
                "run_ref does not belong to the selected Golden Operating Loop"
            )
        client, company_id, project_id = _resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        if descriptor.loop_ref is GoldenLoopRef.PERIOD_RECONCILIATION:
            return bounded_json_result(
                {
                    **_operating_loop_blocked(
                        loop_ref=descriptor.loop_ref.value,
                        run_ref=run_ref,
                        blocker_code="golden_loop.finance.canonical_runtime_not_bound",
                        message=(
                            "Period Reconciliation source authority is quarantined; "
                            "there is no model-callable next action."
                        ),
                    ),
                    "loop_version": descriptor.loop_version,
                    "terminal": False,
                    "next_action": None,
                    "automatic_advance_performed": False,
                },
                operation="get_operating_loop_next_action",
                max_chars=8_000,
                compact=True,
            )
        if descriptor.loop_ref is GoldenLoopRef.PROCUREMENT_MATCHED_CLOSE:
            return bounded_json_result(
                {
                    **_operating_loop_blocked(
                        loop_ref=descriptor.loop_ref.value,
                        run_ref=run_ref,
                        blocker_code=(
                            "golden_loop.procurement."
                            "derived_match_authority_not_bound"
                        ),
                        message=(
                            "Procurement match truth lacks DB-owned source authority; "
                            "there is no model-callable next action."
                        ),
                    ),
                    "loop_version": descriptor.loop_version,
                    "terminal": False,
                    "next_action": None,
                    "automatic_advance_performed": False,
                },
                operation="get_operating_loop_next_action",
                max_chars=8_000,
                compact=True,
            )
        if descriptor.loop_ref is GoldenLoopRef.VERIFIED_IMPROVEMENT:
            return bounded_json_result(
                {
                    **_operating_loop_blocked(
                        loop_ref=descriptor.loop_ref.value,
                        run_ref=run_ref,
                        blocker_code=(
                            "golden_loop.verified_improvement."
                            "source_authority_quarantined"
                        ),
                        message=(
                            "Verified Improvement source custody is quarantined; "
                            "there is no model-callable next action."
                        ),
                    ),
                    "loop_version": descriptor.loop_version,
                    "terminal": False,
                    "next_action": None,
                    "automatic_advance_performed": False,
                },
                operation="get_operating_loop_next_action",
                max_chars=8_000,
                compact=True,
            )
        public_status = _operating_loop_public_value(
            _operating_loop_read(
                client=client,
                company_id=company_id,
                project_id=project_id,
                loop_ref=descriptor.loop_ref.value,
                run_ref=run_ref,
            )
        )

        def find_next(value: Any) -> str | None:
            if isinstance(value, Mapping):
                for key in ("next_action", "next_step"):
                    candidate = value.get(key)
                    if isinstance(candidate, str) and candidate.strip():
                        return candidate
                for child in value.values():
                    candidate = find_next(child)
                    if candidate is not None:
                        return candidate
            elif isinstance(value, list):
                for child in value:
                    candidate = find_next(child)
                    if candidate is not None:
                        return candidate
            return None

        next_action = find_next(public_status)
        terminal = bool(
            isinstance(public_status, Mapping) and public_status.get("terminal") is True
        )
        return bounded_json_result(
            {
                "schema": OPERATING_LOOP_MCP_PROTOCOL_SCHEMA,
                "loop_ref": descriptor.loop_ref.value,
                "loop_version": descriptor.loop_version,
                "run_ref": run_ref,
                "terminal": terminal,
                "next_action": (
                    None
                    if terminal
                    else next_action
                    or "inspect_advanced_governed_lifecycle_protocol"
                ),
                "automatic_advance_performed": False,
                "external_effect_authorized": False,
            },
            operation="get_operating_loop_next_action",
            max_chars=8_000,
            compact=True,
        )

    @mcp.tool(annotations=_CANCEL)
    def cancel_operating_loop(
        company_ref: str,
        project_ref: str,
        loop_ref: str,
        run_ref: str,
        reason: Annotated[str, Field(min_length=1, max_length=500)],
    ) -> str:
        """Cancel only loops whose public authority needs no hidden source custody."""

        descriptor = _operating_loop_descriptor(loop_ref)
        if re.fullmatch(descriptor.canonical_run_ref_pattern, run_ref) is None:
            raise ValueError(
                "run_ref does not belong to the selected Golden Operating Loop"
            )
        client, company_id, project_id = _resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        if descriptor.loop_ref in {
            GoldenLoopRef.FINANCE_JOURNAL,
            GoldenLoopRef.PERIOD_RECONCILIATION,
        }:
            return bounded_json_result(
                _operating_loop_blocked(
                    loop_ref=descriptor.loop_ref.value,
                    run_ref=run_ref,
                    blocker_code="golden_loop.finance.canonical_runtime_not_bound",
                    message=(
                        "The canonical finance source authority is effect-dark and "
                        "has no model-callable cancellation route."
                    ),
                ),
                operation="cancel_operating_loop",
                max_chars=8_000,
                compact=True,
            )
        if descriptor.loop_ref is GoldenLoopRef.PROCUREMENT_MATCHED_CLOSE:
            return bounded_json_result(
                _operating_loop_blocked(
                    loop_ref=descriptor.loop_ref.value,
                    run_ref=run_ref,
                    blocker_code=(
                        "golden_loop.procurement.derived_match_authority_not_bound"
                    ),
                    message=(
                        "Procurement match truth lacks DB-owned source authority; no "
                        "model-callable cancellation route exists."
                    ),
                ),
                operation="cancel_operating_loop",
                max_chars=8_000,
                compact=True,
            )
        if descriptor.loop_ref is GoldenLoopRef.VERIFIED_IMPROVEMENT:
            return bounded_json_result(
                _operating_loop_blocked(
                    loop_ref=descriptor.loop_ref.value,
                    run_ref=run_ref,
                    blocker_code=(
                        "golden_loop.verified_improvement.source_authority_quarantined"
                    ),
                    message=(
                        "Verified Improvement source custody is quarantined; no "
                        "model-callable cancellation route exists."
                    ),
                ),
                operation="cancel_operating_loop",
                max_chars=8_000,
                compact=True,
            )
        cancellation_methods: dict[str, tuple[str, tuple[Any, ...], dict[str, Any]]] = {
            GoldenLoopRef.CONTRACT_TO_CASH.value: (
                "cancel_contract_to_cash_before_invoice",
                (ContractToCashRunCancellation(reason=reason),),
                {},
            ),
            GoldenLoopRef.REVENUE_VERIFIED_REPLY.value: (
                "cancel_governed_communication_run",
                (),
                {},
            ),
            GoldenLoopRef.SERVICE_VERIFIED_RESOLUTION.value: (
                "cancel_service_case_resolution",
                (),
                {"reason": reason},
            ),
        }
        cancellation = cancellation_methods.get(descriptor.loop_ref.value)
        if cancellation is None:
            return bounded_json_result(
                _operating_loop_blocked(
                    loop_ref=descriptor.loop_ref.value,
                    run_ref=run_ref,
                    blocker_code="operating_loop.cancellation_custody_required",
                    message=(
                        "This loop requires an exact role, source, or approval-bound "
                        "cancellation contract available only on the advanced governed surface."
                    ),
                ),
                operation="cancel_operating_loop",
                max_chars=8_000,
                compact=True,
            )
        method_name, positional, keyword = cancellation
        result = getattr(client, method_name)(
            project_id,
            run_ref,
            *positional,
            company_id=company_id,
            **keyword,
        )
        return bounded_json_result(
            {
                "schema": OPERATING_LOOP_MCP_PROTOCOL_SCHEMA,
                "loop_ref": descriptor.loop_ref.value,
                "loop_version": descriptor.loop_version,
                "run_ref": run_ref,
                "status": _operating_loop_public_value(result),
            },
            operation="cancel_operating_loop",
            max_chars=32_000,
            compact=True,
        )

    @mcp.tool(annotations=_READ_ONLY)
    def get_operating_loop_evidence(
        company_ref: str,
        project_ref: str,
        loop_ref: str,
        run_ref: str,
    ) -> str:
        """Read the source-bound economic-closure evidence for one exact loop run."""

        descriptor = _operating_loop_descriptor(loop_ref)
        if re.fullmatch(descriptor.canonical_run_ref_pattern, run_ref) is None:
            raise ValueError(
                "run_ref does not belong to the selected Golden Operating Loop"
            )
        client, company_id, project_id = _resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        if descriptor.loop_ref is GoldenLoopRef.PERIOD_RECONCILIATION:
            return bounded_json_result(
                _operating_loop_blocked(
                    loop_ref=descriptor.loop_ref.value,
                    run_ref=run_ref,
                    blocker_code="golden_loop.finance.canonical_runtime_not_bound",
                    message=(
                        "Period Reconciliation source authority is quarantined; no "
                        "source-bound economic-closure evidence can be projected."
                    ),
                ),
                operation="get_operating_loop_evidence",
                max_chars=8_000,
                compact=True,
            )
        if descriptor.loop_ref is GoldenLoopRef.PROCUREMENT_MATCHED_CLOSE:
            return bounded_json_result(
                _operating_loop_blocked(
                    loop_ref=descriptor.loop_ref.value,
                    run_ref=run_ref,
                    blocker_code=(
                        "golden_loop.procurement.derived_match_authority_not_bound"
                    ),
                    message=(
                        "Procurement match truth lacks DB-owned source authority; no "
                        "source-bound economic-closure evidence can be projected."
                    ),
                ),
                operation="get_operating_loop_evidence",
                max_chars=8_000,
                compact=True,
            )
        if descriptor.loop_ref is GoldenLoopRef.VERIFIED_IMPROVEMENT:
            return bounded_json_result(
                _operating_loop_blocked(
                    loop_ref=descriptor.loop_ref.value,
                    run_ref=run_ref,
                    blocker_code=(
                        "golden_loop.verified_improvement.source_authority_quarantined"
                    ),
                    message=(
                        "Verified Improvement source custody is quarantined; no "
                        "source-bound economic-closure evidence can be projected."
                    ),
                ),
                operation="get_operating_loop_evidence",
                max_chars=8_000,
                compact=True,
            )
        evidence = client.get_golden_loop_economic_closure(
            project_id, run_ref, company_id=company_id
        )
        if not isinstance(evidence, GoldenLoopEconomicClosureProjection):
            raise ValueError("Golden Loop client returned a non-closure result")
        if evidence.loop_ref != descriptor.loop_ref.value:
            raise ValueError("economic-closure evidence belongs to a different loop")
        return bounded_json_result(
            {
                "schema": OPERATING_LOOP_MCP_PROTOCOL_SCHEMA,
                "loop_ref": descriptor.loop_ref.value,
                "loop_version": descriptor.loop_version,
                "run_ref": run_ref,
                "evidence": _operating_loop_public_value(evidence.to_exact_dict()),
            },
            operation="get_operating_loop_evidence",
            max_chars=32_000,
            compact=True,
        )

    @mcp.tool(annotations=_INTERNAL_START)
    def register_executed_commercial_agreement(
        company_ref: str,
        project_ref: str,
        candidate: ExecutedCommercialAgreementCustodyCandidate,
    ) -> str:
        """Seal existing governed DocuSign READ evidence; performs no provider call."""

        client, company_id, project_id = _resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _executed_agreement_result(
            client.register_executed_commercial_agreement(
                project_id, candidate, company_id=company_id
            ),
            operation="register_executed_commercial_agreement",
            bounded_json_result=bounded_json_result,
        )

    @mcp.tool(annotations=_READ_ONLY)
    def get_executed_commercial_agreement(
        company_ref: str,
        project_ref: str,
        record_id: str,
    ) -> str:
        """Read one exact immutable executed-agreement custody record."""

        client, company_id, project_id = _resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _executed_agreement_result(
            client.get_executed_commercial_agreement(
                project_id, record_id, company_id=company_id
            ),
            operation="get_executed_commercial_agreement",
            bounded_json_result=bounded_json_result,
        )

    @mcp.tool(annotations=_READ_ONLY)
    def resolve_executed_commercial_agreement(
        company_ref: str,
        project_ref: str,
        agreement_ref: str,
    ) -> str:
        """Resolve immutable custody by its portable provider-derived agreement ref."""

        client, company_id, project_id = _resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _executed_agreement_result(
            client.resolve_executed_commercial_agreement(
                project_id, agreement_ref, company_id=company_id
            ),
            operation="resolve_executed_commercial_agreement",
            bounded_json_result=bounded_json_result,
        )

    @mcp.tool(annotations=_INTERNAL_START)
    @fail_closed_model_control
    def register_golden_loop_catalog(
        company_ref: str,
        project_ref: str,
        request: GoldenLoopCatalogRegistrationRequest,
    ) -> str:
        """Register or replay exact QUARANTINED loop declarations; never certify or deploy."""

        client, company_id, project_id = _resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _certification_result(
            client.register_golden_loop_catalog(
                project_id, request, company_id=company_id
            ),
            operation="register_golden_loop_catalog",
            bounded_json_result=bounded_json_result,
        )

    @mcp.tool(annotations=_READ_ONLY)
    @fail_closed_model_control
    def get_golden_loop_catalog_version(
        company_ref: str,
        project_ref: str,
        catalog_version_id: str,
    ) -> str:
        """Read one exact immutable Spring catalog and its declaration IDs."""

        client, company_id, project_id = _resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _certification_result(
            client.get_golden_loop_catalog_version(
                project_id, catalog_version_id, company_id=company_id
            ),
            operation="get_golden_loop_catalog_version",
            bounded_json_result=bounded_json_result,
        )

    @mcp.tool(annotations=_READ_ONLY)
    @fail_closed_model_control
    def get_golden_loop_declaration_version(
        company_ref: str,
        project_ref: str,
        catalog_version_id: str,
        declaration_version_id: str,
    ) -> str:
        """Read one exact immutable declaration through its containing catalog."""

        client, company_id, project_id = _resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _certification_result(
            client.get_golden_loop_declaration_version(
                project_id,
                catalog_version_id,
                declaration_version_id,
                company_id=company_id,
            ),
            operation="get_golden_loop_declaration_version",
            bounded_json_result=bounded_json_result,
        )

    @mcp.tool(annotations=_INTERNAL_START)
    @fail_closed_model_control
    def propose_golden_loop_certification(
        company_ref: str,
        project_ref: str,
        request: GoldenLoopCertificationProposalRequest,
    ) -> str:
        """Propose one registry-bound candidate for independent Spring/operator review."""

        client, company_id, project_id = _resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _certification_result(
            client.propose_golden_loop_certification(
                project_id, request, company_id=company_id
            ),
            operation="propose_golden_loop_certification",
            bounded_json_result=bounded_json_result,
        )

    @mcp.tool(annotations=_READ_ONLY)
    @fail_closed_model_control
    def get_golden_loop_certification_candidate(
        company_ref: str,
        project_ref: str,
        candidate_id: str,
    ) -> str:
        """Read one exact operator-review candidate without retained raw evidence."""

        client, company_id, project_id = _resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _certification_result(
            client.get_golden_loop_certification_candidate(
                project_id,
                candidate_id,
                company_id=company_id,
            ),
            operation="get_golden_loop_certification_candidate",
            bounded_json_result=bounded_json_result,
        )

    @mcp.tool(annotations=_READ_ONLY)
    @fail_closed_model_control
    def get_reference_company_onboarding_readiness(
        company_ref: str,
        project_ref: str,
    ) -> str:
        """List secret-free choices for the exact quarantined reference company."""

        client, company_id, project_id = _resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _reference_company_onboarding_result(
            client.get_reference_company_onboarding_readiness(
                project_id,
                company_id=company_id,
            ),
            operation="get_reference_company_onboarding_readiness",
            bounded_json_result=bounded_json_result,
            company_id=company_id,
            project_id=project_id,
        )

    @mcp.tool(annotations=_READ_ONLY)
    @fail_closed_model_control
    def preview_reference_company_onboarding(
        company_ref: str,
        project_ref: str,
        blueprint_version_ref: _BLUEPRINT_VERSION_PUBLIC_REF,
        connector_selections: _ReferenceCompanyConnectorSelections,
        coding_harness: Literal["codex", "claude_code", "cursor"] | None = None,
    ) -> str:
        """Validate exact connector and harness choices without granting authority."""

        client, company_id, project_id = _resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        readiness = client.get_reference_company_onboarding_readiness(
            project_id,
            company_id=company_id,
        )
        if not isinstance(readiness, ReferenceCompanyOnboardingReadiness):
            raise ValueError(
                "Lightbulb client returned invalid reference onboarding data"
            )
        _require_reference_onboarding_scope(
            readiness,
            company_id=company_id,
            project_id=project_id,
        )
        resolved_blueprint_ref, resolved_connectors = (
            _resolve_reference_onboarding_preview_inputs(
                readiness,
                blueprint_version_ref=blueprint_version_ref,
                connector_selection_refs=connector_selections.exact_dict(),
            )
        )
        preview = client.preview_reference_company_onboarding(
            project_id,
            resolved_blueprint_ref,
            connector_selections=resolved_connectors,
            coding_harness=coding_harness,
            company_id=company_id,
        )
        if not isinstance(preview, ReferenceCompanyOnboardingPreview):
            raise ValueError(
                "Lightbulb client returned invalid reference onboarding data"
            )
        _require_preview_matches_fresh_readiness(
            preview,
            readiness=readiness,
            connector_selections=resolved_connectors,
        )
        return _reference_company_onboarding_result(
            preview,
            operation="preview_reference_company_onboarding",
            bounded_json_result=bounded_json_result,
            company_id=company_id,
            project_id=project_id,
        )

    @mcp.tool(annotations=_READ_ONLY)
    @fail_closed_model_control
    def get_company_blueprint_certification_candidate(
        company_ref: str,
        project_ref: str,
        candidate_id: str,
    ) -> str:
        """Read one exact whole-company certification review candidate."""
        client, company_id, project_id = _resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _company_blueprint_result(
            client.get_company_blueprint_certification_candidate(
                project_id, candidate_id, company_id=company_id
            ),
            operation="get_company_blueprint_certification_candidate",
            bounded_json_result=bounded_json_result,
        )

    @mcp.tool(annotations=_INTERNAL_START)
    @fail_closed_model_control
    def prepare_company_blueprint_native_proof(
        company_ref: str,
        project_ref: str,
        blueprint_version_id: str,
        golden_loop_certification_record_ids: list[str],
        rollback_shadow_intent_id: str,
    ) -> str:
        """Derive stage, metric, Loop, runtime, and rollback proof from Spring custody."""
        client, company_id, project_id = _resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return bounded_json_result(
            client.prepare_company_blueprint_native_proof(
                project_id,
                blueprint_version_id,
                golden_loop_certification_record_ids,
                rollback_shadow_intent_id,
                company_id=company_id,
            ),
            operation="prepare_company_blueprint_native_proof",
            max_chars=32_000,
            compact=True,
        )

    @mcp.tool(annotations=_INTERNAL_START)
    @fail_closed_model_control
    def propose_company_blueprint_certification(
        company_ref: str,
        project_ref: str,
        candidate: _BLUEPRINT_CERTIFICATION_CANDIDATE_JSON,
        evidence_target_id: str,
        idempotency_key: _IDEMPOTENCY_KEY,
    ) -> str:
        """Submit SDK-sealed Blueprint JSON for independent Spring/operator review."""
        client, company_id, project_id = _resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        typed_candidate = CompanyBlueprintCertificationCandidate.model_validate_json(
            candidate
        )
        return _company_blueprint_result(
            client.propose_company_blueprint_certification(
                project_id,
                typed_candidate,
                evidence_target_id=evidence_target_id,
                idempotency_key=idempotency_key,
                company_id=company_id,
            ),
            operation="propose_company_blueprint_certification",
            bounded_json_result=bounded_json_result,
        )

    @mcp.tool(annotations=_INTERNAL_NON_IDEMPOTENT)
    @fail_closed_model_control
    def finalize_company_blueprint_certification(
        company_ref: str,
        project_ref: str,
        candidate_id: str,
    ) -> str:
        """Request independent finalization of one exact Blueprint candidate."""
        client, company_id, project_id = _resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _company_blueprint_result(
            client.finalize_company_blueprint_certification(
                project_id, candidate_id, company_id=company_id
            ),
            operation="finalize_company_blueprint_certification",
            bounded_json_result=bounded_json_result,
        )

    @mcp.tool(annotations=_CANCEL)
    @fail_closed_model_control
    def cancel_company_blueprint_certification(
        company_ref: str,
        project_ref: str,
        candidate_id: str,
    ) -> str:
        """Cancel an unfinalized Blueprint certification candidate."""
        client, company_id, project_id = _resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _company_blueprint_result(
            client.cancel_company_blueprint_certification(
                project_id, candidate_id, company_id=company_id
            ),
            operation="cancel_company_blueprint_certification",
            bounded_json_result=bounded_json_result,
        )

    @mcp.tool(annotations=_READ_ONLY)
    @fail_closed_model_control
    def get_current_company_blueprint_certification(
        company_ref: str,
        project_ref: str,
        blueprint_version_id: str,
        environment_ref: str,
    ) -> str:
        """Read the current exact whole-company certificate or explicit absence."""
        client, company_id, project_id = _resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _company_blueprint_result(
            client.get_current_company_blueprint_certification(
                project_id,
                blueprint_version_id=blueprint_version_id,
                environment_ref=environment_ref,
                company_id=company_id,
            ),
            operation="get_current_company_blueprint_certification",
            bounded_json_result=bounded_json_result,
        )

    @mcp.tool(annotations=_READ_ONLY)
    @fail_closed_model_control
    def get_company_blueprint_deployment(
        company_ref: str,
        project_ref: str,
        deployment_id: str,
    ) -> str:
        """Read one receipt-bearing Blueprint deployment lifecycle."""
        client, company_id, project_id = _resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _company_blueprint_result(
            client.get_company_blueprint_deployment(
                project_id, deployment_id, company_id=company_id
            ),
            operation="get_company_blueprint_deployment",
            bounded_json_result=bounded_json_result,
        )

    @mcp.tool(annotations=_INTERNAL_START)
    @fail_closed_model_control
    def propose_company_blueprint_deployment(
        company_ref: str,
        project_ref: str,
        candidate: _BLUEPRINT_DEPLOYMENT_CANDIDATE_JSON,
        idempotency_key: _IDEMPOTENCY_KEY,
    ) -> str:
        """Propose an SDK-sealed deployment; this does not activate it."""
        client, company_id, project_id = _resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        typed_candidate = CompanyBlueprintDeploymentCandidate.model_validate_json(
            candidate
        )
        return _company_blueprint_result(
            client.propose_company_blueprint_deployment(
                project_id,
                typed_candidate,
                idempotency_key=idempotency_key,
                company_id=company_id,
            ),
            operation="propose_company_blueprint_deployment",
            bounded_json_result=bounded_json_result,
        )

    def _transition_company_blueprint_deployment(
        company_ref: str,
        project_ref: str,
        deployment_id: str,
        *,
        action: str,
        operation: str,
    ) -> str:
        client, company_id, project_id = _resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _company_blueprint_result(
            client.transition_company_blueprint_deployment(
                project_id,
                deployment_id,
                action=action,
                company_id=company_id,
            ),
            operation=operation,
            bounded_json_result=bounded_json_result,
        )

    @mcp.tool(annotations=_INTERNAL_NON_IDEMPOTENT)
    @fail_closed_model_control
    def finalize_company_blueprint_deployment(
        company_ref: str,
        project_ref: str,
        deployment_id: str,
    ) -> str:
        """Finalize the deployment receipt without activating the company head."""
        return _transition_company_blueprint_deployment(
            company_ref,
            project_ref,
            deployment_id,
            action="finalize-deployment",
            operation="finalize_company_blueprint_deployment",
        )

    @mcp.tool(annotations=_INTERNAL_NON_IDEMPOTENT)
    @fail_closed_model_control
    def finalize_company_blueprint_activation(
        company_ref: str,
        project_ref: str,
        deployment_id: str,
    ) -> str:
        """Activate only a deployment whose independent gates already passed."""
        return _transition_company_blueprint_deployment(
            company_ref,
            project_ref,
            deployment_id,
            action="finalize-activation",
            operation="finalize_company_blueprint_activation",
        )

    @mcp.tool(annotations=_INTERNAL_NON_IDEMPOTENT)
    @fail_closed_model_control
    def request_company_blueprint_rollback(
        company_ref: str,
        project_ref: str,
        deployment_id: str,
    ) -> str:
        """Request rollback for an exact active deployment; this does not finalize it."""
        return _transition_company_blueprint_deployment(
            company_ref,
            project_ref,
            deployment_id,
            action="request-rollback",
            operation="request_company_blueprint_rollback",
        )

    @mcp.tool(annotations=_INTERNAL_NON_IDEMPOTENT)
    @fail_closed_model_control
    def finalize_company_blueprint_rollback(
        company_ref: str,
        project_ref: str,
        deployment_id: str,
    ) -> str:
        """Finalize a separately requested and authorized Blueprint rollback."""
        return _transition_company_blueprint_deployment(
            company_ref,
            project_ref,
            deployment_id,
            action="finalize-rollback",
            operation="finalize_company_blueprint_rollback",
        )

    @mcp.tool(annotations=_CANCEL)
    @fail_closed_model_control
    def cancel_company_blueprint_deployment(
        company_ref: str,
        project_ref: str,
        deployment_id: str,
    ) -> str:
        """Cancel a deployment that has not reached an active terminal."""
        return _transition_company_blueprint_deployment(
            company_ref,
            project_ref,
            deployment_id,
            action="cancel",
            operation="cancel_company_blueprint_deployment",
        )

    @mcp.tool(annotations=_READ_ONLY)
    @fail_closed_model_control
    def get_company_blueprint_deployment_head(
        company_ref: str,
        project_ref: str,
    ) -> str:
        """Read the exact active AI-native company head or explicit absence."""
        client, company_id, project_id = _resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _company_blueprint_result(
            client.get_company_blueprint_deployment_head(
                project_id, company_id=company_id
            ),
            operation="get_company_blueprint_deployment_head",
            bounded_json_result=bounded_json_result,
        )

    @mcp.tool(annotations=_READ_ONLY)
    @fail_closed_model_control
    def get_current_golden_loop_certification(
        company_ref: str,
        project_ref: str,
        loop_ref: str,
        loop_version: str,
        environment_ref: str,
    ) -> str:
        """Read the current exact-scope certificate, or an explicit absent projection."""

        client, company_id, project_id = _resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _certification_result(
            client.get_current_golden_loop_certification(
                project_id,
                loop_ref=loop_ref,
                loop_version=loop_version,
                environment_ref=environment_ref,
                company_id=company_id,
            ),
            operation="get_current_golden_loop_certification",
            bounded_json_result=bounded_json_result,
        )

    @mcp.tool(annotations=_READ_ONLY)
    def get_golden_loop_economic_closure(
        company_ref: str,
        project_ref: str,
        run_ref: str,
    ) -> str:
        """Read Spring's canonical cost completeness and settlement state for any Golden Loop."""

        client, company_id, project_id = _resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _economic_closure_result(
            client.get_golden_loop_economic_closure(
                project_id,
                run_ref,
                company_id=company_id,
            ),
            bounded_json_result=bounded_json_result,
        )

    @mcp.tool(annotations=_INTERNAL_START)
    def propose_contract_to_cash_invoice(
        company_ref: str,
        project_ref: str,
        request: ContractToCashInvoiceProposalRequest,
    ) -> str:
        """Create or replay an exact invoice approval; this performs no provider write."""

        client, company_id, project_id = _resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _contract_to_cash_result(
            client.propose_contract_to_cash_invoice(
                project_id, request, company_id=company_id
            ),
            expected_type=ContractToCashInvoiceProposalReceipt,
            operation="propose_contract_to_cash_invoice",
            bounded_json_result=bounded_json_result,
        )

    @mcp.tool(annotations=_EXTERNAL_NON_RETRYABLE_EFFECT)
    def execute_contract_to_cash_invoice(
        company_ref: str,
        project_ref: str,
        request: ContractToCashInvoiceExecutionRequest,
    ) -> str:
        """Consume one exact approval; readback is still required before issuance."""

        client, company_id, project_id = _resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _contract_to_cash_result(
            client.execute_contract_to_cash_invoice(
                project_id, request, company_id=company_id
            ),
            expected_type=ContractToCashInvoiceWriteReceipt,
            operation="execute_contract_to_cash_invoice",
            bounded_json_result=bounded_json_result,
        )

    @mcp.tool(annotations=_INTERNAL_START)
    def register_contract_to_cash_invoice_issued(
        company_ref: str,
        project_ref: str,
        request: ContractToCashInvoiceIssuedRegistration,
    ) -> str:
        """Seal exact reconciled QuickBooks issuance evidence into Spring custody."""

        client, company_id, project_id = _resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _invoice_issued_result(
            client.register_contract_to_cash_invoice_issued(
                project_id, request, company_id=company_id
            ),
            operation="register_contract_to_cash_invoice_issued",
            bounded_json_result=bounded_json_result,
        )

    @mcp.tool(annotations=_READ_ONLY)
    def get_contract_to_cash_invoice_issued(
        company_ref: str,
        project_ref: str,
        record_id: str,
    ) -> str:
        """Read one exact provider-observed invoice issuance custody record."""

        client, company_id, project_id = _resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _invoice_issued_result(
            client.get_contract_to_cash_invoice_issued(
                project_id, record_id, company_id=company_id
            ),
            operation="get_contract_to_cash_invoice_issued",
            bounded_json_result=bounded_json_result,
        )

    @mcp.tool(annotations=_INTERNAL_START)
    def register_contract_to_cash_cash_collection(
        company_ref: str,
        project_ref: str,
        request: ContractToCashCashCollectionRegistration,
    ) -> str:
        """Seal independent accounting and payout evidence as collected cash."""

        client, company_id, project_id = _resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _cash_collection_result(
            client.register_contract_to_cash_cash_collection(
                project_id, request, company_id=company_id
            ),
            operation="register_contract_to_cash_cash_collection",
            bounded_json_result=bounded_json_result,
        )

    @mcp.tool(annotations=_READ_ONLY)
    def get_contract_to_cash_cash_collection(
        company_ref: str,
        project_ref: str,
        record_id: str,
    ) -> str:
        """Read exact immutable collected-cash custody."""

        client, company_id, project_id = _resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _cash_collection_result(
            client.get_contract_to_cash_cash_collection(
                project_id, record_id, company_id=company_id
            ),
            operation="get_contract_to_cash_cash_collection",
            bounded_json_result=bounded_json_result,
        )

    @mcp.tool(annotations=_INTERNAL_START)
    def start_contract_to_cash_run(
        company_ref: str,
        project_ref: str,
        request: _PublicContractToCashRunStart,
    ) -> str:
        """Start the Spring-owned loop from exact executed-agreement custody."""
        client, company_id, project_id = _resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _contract_to_cash_result(
            client.start_contract_to_cash_run(
                project_id,
                _internal_start_request(request, ContractToCashRunStart),
                company_id=company_id,
            ),
            expected_type=ContractToCashRun,
            operation="start_contract_to_cash_run",
            bounded_json_result=bounded_json_result,
        )

    @mcp.tool(annotations=_READ_ONLY)
    def get_contract_to_cash_run(
        company_ref: str, project_ref: str, run_ref: str
    ) -> str:
        """Read the exact Spring-owned Contract-to-Cash lifecycle projection."""
        client, company_id, project_id = _resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _contract_to_cash_result(
            client.get_contract_to_cash_run(project_id, run_ref, company_id=company_id),
            expected_type=ContractToCashRun,
            operation="get_contract_to_cash_run",
            bounded_json_result=bounded_json_result,
        )

    @mcp.tool(annotations=_INTERNAL_START)
    def attach_contract_to_cash_invoice_issued(
        company_ref: str,
        project_ref: str,
        run_ref: str,
        request: ContractToCashRunRecordBinding,
    ) -> str:
        """Advance only from exact reconciled invoice-issued custody."""
        client, company_id, project_id = _resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _contract_to_cash_result(
            client.attach_contract_to_cash_invoice_issued(
                project_id, run_ref, request, company_id=company_id
            ),
            expected_type=ContractToCashRun,
            operation="attach_contract_to_cash_invoice_issued",
            bounded_json_result=bounded_json_result,
        )

    @mcp.tool(annotations=_INTERNAL_START)
    def attach_contract_to_cash_cash_collected(
        company_ref: str,
        project_ref: str,
        run_ref: str,
        request: ContractToCashRunRecordBinding,
    ) -> str:
        """Terminalize only from independent accounting and settlement evidence."""
        client, company_id, project_id = _resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _contract_to_cash_result(
            client.attach_contract_to_cash_cash_collected(
                project_id, run_ref, request, company_id=company_id
            ),
            expected_type=ContractToCashRun,
            operation="attach_contract_to_cash_cash_collected",
            bounded_json_result=bounded_json_result,
        )

    @mcp.tool(annotations=_CANCEL)
    def cancel_contract_to_cash_before_invoice(
        company_ref: str,
        project_ref: str,
        run_ref: str,
        request: ContractToCashRunCancellation,
    ) -> str:
        """Cancel only while no invoice effect has authoritative custody."""
        client, company_id, project_id = _resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _contract_to_cash_result(
            client.cancel_contract_to_cash_before_invoice(
                project_id, run_ref, request, company_id=company_id
            ),
            expected_type=ContractToCashRun,
            operation="cancel_contract_to_cash_before_invoice",
            bounded_json_result=bounded_json_result,
        )

    def _blocked_economic_spine_lifecycle_tool(
        function: Callable[..., str],
    ) -> Callable[..., str]:
        """Keep the generic Period/Procurement bridge out of every MCP registry."""

        return function

    @_blocked_economic_spine_lifecycle_tool
    def start_economic_spine_run(
        company_ref: str,
        project_ref: str,
        request: _PublicEconomicSpineRunStart,
    ) -> str:
        """Start exact procurement, period-close, or improvement evidence custody."""
        client, company_id, project_id = _resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _economic_spine_result(
            client.start_economic_spine_run(
                project_id,
                _internal_start_request(request, EconomicSpineRunStart),
                company_id=company_id,
            ),
            operation="start_economic_spine_run",
            bounded_json_result=bounded_json_result,
        )

    @_blocked_economic_spine_lifecycle_tool
    def get_economic_spine_run(company_ref: str, project_ref: str, run_ref: str) -> str:
        client, company_id, project_id = _resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _economic_spine_result(
            client.get_economic_spine_run(project_id, run_ref, company_id=company_id),
            operation="get_economic_spine_run",
            bounded_json_result=bounded_json_result,
        )

    @_blocked_economic_spine_lifecycle_tool
    def advance_economic_spine_run(
        company_ref: str,
        project_ref: str,
        run_ref: str,
        request: EconomicSpineRunTransition,
    ) -> str:
        """Attach the exact next evidence transition to Spring's authority."""
        client, company_id, project_id = _resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _economic_spine_result(
            client.advance_economic_spine_run(
                project_id, run_ref, request, company_id=company_id
            ),
            operation="advance_economic_spine_run",
            bounded_json_result=bounded_json_result,
        )

    def _economic_spine_command(
        operation: str,
        company_ref: str,
        project_ref: str,
        run_ref: str,
        request: EconomicSpineRunTransition,
    ) -> str:
        client, company_id, project_id = _resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        method = getattr(client, operation)
        return _economic_spine_result(
            method(project_id, run_ref, request, company_id=company_id),
            operation=operation,
            bounded_json_result=bounded_json_result,
        )

    @_blocked_economic_spine_lifecycle_tool
    def fail_economic_spine_run(
        company_ref: str,
        project_ref: str,
        run_ref: str,
        request: EconomicSpineRunTransition,
    ) -> str:
        """Fail with one immutable trusted observation; ambiguity remains blocked."""
        return _economic_spine_command(
            "fail_economic_spine_run", company_ref, project_ref, run_ref, request
        )

    @_blocked_economic_spine_lifecycle_tool
    def cancel_economic_spine_run(
        company_ref: str,
        project_ref: str,
        run_ref: str,
        request: EconomicSpineRunTransition,
    ) -> str:
        """Fence and cancel only when retained effect custody proves it is safe."""
        return _economic_spine_command(
            "cancel_economic_spine_run", company_ref, project_ref, run_ref, request
        )

    @_blocked_economic_spine_lifecycle_tool
    def mark_economic_spine_effect_ambiguous(
        company_ref: str,
        project_ref: str,
        run_ref: str,
        request: EconomicSpineRunTransition,
    ) -> str:
        """Block automatic replay after a trusted ambiguous-effect observation."""
        return _economic_spine_command(
            "mark_economic_spine_effect_ambiguous",
            company_ref,
            project_ref,
            run_ref,
            _internal_procurement_approval(request),
        )

    @_blocked_economic_spine_lifecycle_tool
    def reconcile_economic_spine_run(
        company_ref: str,
        project_ref: str,
        run_ref: str,
        request: EconomicSpineRunTransition,
    ) -> str:
        """Append trusted human reconciliation without rewriting terminal history."""
        return _economic_spine_command(
            "reconcile_economic_spine_run", company_ref, project_ref, run_ref, request
        )

    def _blocked_procurement_lifecycle_tool(
        function: Callable[..., str],
    ) -> Callable[..., str]:
        """Keep candidate implementations unreachable until DB-owned match truth exists."""

        return function

    def _procurement_command(
        operation: str,
        company_ref: str,
        project_ref: str,
        run_ref: str,
        request: Any,
        expected_type: type[Any],
    ) -> str:
        client, company_id, project_id = _strictly_resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        method = getattr(client, operation)
        return _procurement_result(
            method(project_id, run_ref, request, company_id=company_id),
            expected_type=expected_type,
            operation=operation,
            bounded_json_result=bounded_json_result,
        )

    @_blocked_procurement_lifecycle_tool
    def start_procurement_matched_close_run(
        company_ref: _CANONICAL_COMPANY_REF,
        project_ref: _CANONICAL_PROJECT_REF,
        request: _PublicProcurementStart,
    ) -> str:
        """Start one typed requisition; Spring derives scope and evidence custody."""

        client, company_id, project_id = _strictly_resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _procurement_result(
            client.start_procurement_matched_close_run(
                project_id,
                _internal_start_request(request, ProcurementStart),
                company_id=company_id,
            ),
            expected_type=ProcurementCommandReceipt,
            operation="start_procurement_matched_close_run",
            bounded_json_result=bounded_json_result,
        )

    @_blocked_procurement_lifecycle_tool
    def submit_procurement_requisition(
        company_ref: _CANONICAL_COMPANY_REF,
        project_ref: _CANONICAL_PROJECT_REF,
        run_ref: _PROCUREMENT_RUN_REF,
        request: _PublicProcurementApprovalBinding,
    ) -> str:
        """Bind the exact requisition source and Spring approval task for review."""

        return _procurement_command(
            "submit_procurement_requisition",
            company_ref,
            project_ref,
            run_ref,
            _internal_procurement_approval(request),
            ProcurementCommandReceipt,
        )

    @_blocked_procurement_lifecycle_tool
    def approve_procurement_spend_commitment(
        company_ref: _CANONICAL_COMPANY_REF,
        project_ref: _CANONICAL_PROJECT_REF,
        run_ref: _PROCUREMENT_RUN_REF,
        request: _PublicProcurementApprovalBinding,
    ) -> str:
        """Consume Spring's independently approved commitment custody."""

        return _procurement_command(
            "approve_procurement_spend_commitment",
            company_ref,
            project_ref,
            run_ref,
            _internal_procurement_approval(request),
            ProcurementCommandReceipt,
        )

    @_blocked_procurement_lifecycle_tool
    def bind_procurement_xero_purchase_order_readback(
        company_ref: _CANONICAL_COMPANY_REF,
        project_ref: _CANONICAL_PROJECT_REF,
        run_ref: _PROCUREMENT_RUN_REF,
        request: ProcurementPurchaseOrderJournalBinding,
    ) -> str:
        """Bind governed Xero write and independent readback journals; call no provider."""

        return _procurement_command(
            "bind_procurement_xero_purchase_order_readback",
            company_ref,
            project_ref,
            run_ref,
            request,
            ProcurementCommandReceipt,
        )

    @_blocked_procurement_lifecycle_tool
    def record_procurement_goods_receipt(
        company_ref: _CANONICAL_COMPANY_REF,
        project_ref: _CANONICAL_PROJECT_REF,
        run_ref: _PROCUREMENT_RUN_REF,
        request: ProcurementGoodsReceipt,
    ) -> str:
        """Retain typed goods-receipt facts under the exact Procurement run."""

        return _procurement_command(
            "record_procurement_goods_receipt",
            company_ref,
            project_ref,
            run_ref,
            request,
            ProcurementCommandReceipt,
        )

    @_blocked_procurement_lifecycle_tool
    def record_procurement_supplier_invoice(
        company_ref: _CANONICAL_COMPANY_REF,
        project_ref: _CANONICAL_PROJECT_REF,
        run_ref: _PROCUREMENT_RUN_REF,
        request: ProcurementSupplierInvoice,
    ) -> str:
        """Retain a typed supplier invoice without accepting an outcome claim."""

        return _procurement_command(
            "record_procurement_supplier_invoice",
            company_ref,
            project_ref,
            run_ref,
            request,
            ProcurementCustodyReceipt,
        )

    @_blocked_procurement_lifecycle_tool
    def derive_procurement_three_way_match(
        company_ref: _CANONICAL_COMPANY_REF,
        project_ref: _CANONICAL_PROJECT_REF,
        run_ref: _PROCUREMENT_RUN_REF,
        request: ProcurementThreeWayMatch,
    ) -> str:
        """Ask Spring to deterministically derive the three-way match."""

        return _procurement_command(
            "derive_procurement_three_way_match",
            company_ref,
            project_ref,
            run_ref,
            request,
            ProcurementCustodyReceipt,
        )

    @_blocked_procurement_lifecycle_tool
    def approve_procurement_matched_close(
        company_ref: _CANONICAL_COMPANY_REF,
        project_ref: _CANONICAL_PROJECT_REF,
        run_ref: _PROCUREMENT_RUN_REF,
        request: _PublicProcurementMatchedClose,
    ) -> str:
        """Consume independent close approval over an exact matched custody set."""

        return _procurement_command(
            "approve_procurement_matched_close",
            company_ref,
            project_ref,
            run_ref,
            _internal_procurement_matched_close(request),
            ProcurementCommandReceipt,
        )

    @_blocked_procurement_lifecycle_tool
    def get_procurement_matched_close_run(
        company_ref: _CANONICAL_COMPANY_REF,
        project_ref: _CANONICAL_PROJECT_REF,
        run_ref: _PROCUREMENT_RUN_REF,
    ) -> str:
        """Read Spring's exact Procurement 0.3 run receipt."""

        client, company_id, project_id = _strictly_resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _procurement_result(
            client.get_procurement_matched_close_run(
                project_id, run_ref, company_id=company_id
            ),
            expected_type=ProcurementCommandReceipt,
            operation="get_procurement_matched_close_run",
            bounded_json_result=bounded_json_result,
        )

    @_blocked_procurement_lifecycle_tool
    def get_procurement_matched_close_outcomes(
        company_ref: _CANONICAL_COMPANY_REF,
        project_ref: _CANONICAL_PROJECT_REF,
        run_ref: _PROCUREMENT_RUN_REF,
    ) -> str:
        """Read the three Spring-derived source-bound Procurement outcomes."""

        client, company_id, project_id = _strictly_resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _procurement_result(
            client.get_procurement_matched_close_outcomes(
                project_id, run_ref, company_id=company_id
            ),
            expected_type=ProcurementOutcomeReceipt,
            operation="get_procurement_matched_close_outcomes",
            bounded_json_result=bounded_json_result,
        )

    @_blocked_procurement_lifecycle_tool
    def fail_procurement_matched_close_run(
        company_ref: _CANONICAL_COMPANY_REF,
        project_ref: _CANONICAL_PROJECT_REF,
        run_ref: _PROCUREMENT_RUN_REF,
        request: _PublicProcurementFailure,
    ) -> str:
        """Fail with bounded evidence bindings; never conceal an ambiguous effect."""

        return _procurement_command(
            "fail_procurement_matched_close_run",
            company_ref,
            project_ref,
            run_ref,
            _internal_procurement_failure(request),
            ProcurementCommandReceipt,
        )

    @_blocked_procurement_lifecycle_tool
    def cancel_procurement_matched_close_run(
        company_ref: _CANONICAL_COMPANY_REF,
        project_ref: _CANONICAL_PROJECT_REF,
        run_ref: _PROCUREMENT_RUN_REF,
        request: _PublicProcurementCancellation,
    ) -> str:
        """Fence and cancel only through Spring's safe terminal transition."""

        return _procurement_command(
            "cancel_procurement_matched_close_run",
            company_ref,
            project_ref,
            run_ref,
            _internal_procurement_cancellation(request),
            ProcurementCommandReceipt,
        )

    @_blocked_procurement_lifecycle_tool
    def mark_procurement_purchase_order_ambiguous(
        company_ref: _CANONICAL_COMPANY_REF,
        project_ref: _CANONICAL_PROJECT_REF,
        run_ref: _PROCUREMENT_RUN_REF,
        request: ProcurementAmbiguity,
    ) -> str:
        """Quarantine an unresolved governed Xero write without blind replay."""

        return _procurement_command(
            "mark_procurement_purchase_order_ambiguous",
            company_ref,
            project_ref,
            run_ref,
            request,
            ProcurementCommandReceipt,
        )

    @_blocked_procurement_lifecycle_tool
    def reconcile_procurement_purchase_order(
        company_ref: _CANONICAL_COMPANY_REF,
        project_ref: _CANONICAL_PROJECT_REF,
        run_ref: _PROCUREMENT_RUN_REF,
        request: _PublicProcurementReconciliation,
    ) -> str:
        """Submit opaque journals and approval for Spring-owned reconciliation."""

        return _procurement_command(
            "reconcile_procurement_purchase_order",
            company_ref,
            project_ref,
            run_ref,
            _internal_procurement_reconciliation(request),
            ProcurementCommandReceipt,
        )

    def _blocked_period_lifecycle_tool(function: Callable[..., str]) -> Callable[..., str]:
        """Keep stale implementations unreachable while their source authority is absent."""

        return function

    @_blocked_period_lifecycle_tool
    def retain_period_reconciliation_scope(
        company_ref: _CANONICAL_COMPANY_REF,
        project_ref: _CANONICAL_PROJECT_REF,
        request: PeriodReconciliationScopeRequest,
    ) -> str:
        """Retain typed fiscal scope; Spring mints the only valid START source."""
        client, company_id, project_id = _strictly_resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _period_reconciliation_result(
            client.retain_period_reconciliation_scope(
                project_id, request, company_id=company_id
            ),
            expected_type=PeriodReconciliationScopeReceipt,
            operation="retain_period_reconciliation_scope",
            bounded_json_result=bounded_json_result,
        )

    @_blocked_period_lifecycle_tool
    def start_period_reconciliation_run(
        company_ref: _CANONICAL_COMPANY_REF,
        project_ref: _CANONICAL_PROJECT_REF,
        request: _PublicPeriodReconciliationStart,
    ) -> str:
        """Start from one opaque Spring-owned Period source and command identity."""
        client, company_id, project_id = _strictly_resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _period_reconciliation_result(
            client.start_period_reconciliation_run(
                project_id,
                _internal_start_request(request, PeriodReconciliationStartRequest),
                company_id=company_id,
            ),
            expected_type=PeriodReconciliationRunReceipt,
            operation="start_period_reconciliation_run",
            bounded_json_result=bounded_json_result,
        )

    @_blocked_period_lifecycle_tool
    def restart_period_reconciliation_run(
        company_ref: _CANONICAL_COMPANY_REF,
        project_ref: _CANONICAL_PROJECT_REF,
        request: _PublicPeriodReconciliationRestart,
    ) -> str:
        """Bind exact terminal authority into a new server-owned restart source."""
        client, company_id, project_id = _strictly_resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _period_reconciliation_result(
            client.restart_period_reconciliation_run(
                project_id,
                _internal_start_request(request, PeriodReconciliationRestartRequest),
                company_id=company_id,
            ),
            expected_type=PeriodReconciliationRunReceipt,
            operation="restart_period_reconciliation_run",
            bounded_json_result=bounded_json_result,
        )

    @_blocked_period_lifecycle_tool
    def retain_period_reconciliation_quickbooks_reads(
        company_ref: _CANONICAL_COMPANY_REF,
        project_ref: _CANONICAL_PROJECT_REF,
        run_ref: _PERIOD_RECONCILIATION_RUN_REF,
        request: PeriodReconciliationQuickBooksReadSetRequest,
    ) -> str:
        """Bind five governed QuickBooks READ invocation IDs; accept no report body."""
        client, company_id, project_id = _strictly_resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _period_reconciliation_result(
            client.retain_period_reconciliation_quickbooks_reads(
                project_id, run_ref, request, company_id=company_id
            ),
            expected_type=PeriodReconciliationReadSetReceipt,
            operation="retain_period_reconciliation_quickbooks_reads",
            bounded_json_result=bounded_json_result,
        )

    @_blocked_period_lifecycle_tool
    def evaluate_period_reconciliation_run(
        company_ref: _CANONICAL_COMPANY_REF,
        project_ref: _CANONICAL_PROJECT_REF,
        run_ref: _PERIOD_RECONCILIATION_RUN_REF,
        request: PeriodReconciliationEvaluationRequest,
    ) -> str:
        """Ask Spring to derive reconciliation from retained reads and journals."""
        client, company_id, project_id = _strictly_resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _period_reconciliation_result(
            client.evaluate_period_reconciliation_run(
                project_id, run_ref, request, company_id=company_id
            ),
            expected_type=PeriodReconciliationEvaluationReceipt,
            operation="evaluate_period_reconciliation_run",
            bounded_json_result=bounded_json_result,
        )

    @_blocked_period_lifecycle_tool
    def retain_period_reconciliation_review(
        company_ref: _CANONICAL_COMPANY_REF,
        project_ref: _CANONICAL_PROJECT_REF,
        run_ref: _PERIOD_RECONCILIATION_RUN_REF,
        request: _PublicPeriodReconciliationReview,
    ) -> str:
        """Bind an already-decided independent approval without closing the ledger."""
        client, company_id, project_id = _strictly_resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _period_reconciliation_result(
            client.retain_period_reconciliation_review(
                project_id,
                run_ref,
                _internal_period_review(request),
                company_id=company_id,
            ),
            expected_type=PeriodReconciliationReviewReceipt,
            operation="retain_period_reconciliation_review",
            bounded_json_result=bounded_json_result,
        )

    @_blocked_period_lifecycle_tool
    def advance_period_reconciliation_stage(
        company_ref: _CANONICAL_COMPANY_REF,
        project_ref: _CANONICAL_PROJECT_REF,
        run_ref: _PERIOD_RECONCILIATION_RUN_REF,
        request: PeriodReconciliationStageRequest,
    ) -> str:
        """Mint and consume one exact source-custody stage through Spring."""
        client, company_id, project_id = _strictly_resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _period_reconciliation_result(
            client.advance_period_reconciliation_stage(
                project_id, run_ref, request, company_id=company_id
            ),
            expected_type=PeriodReconciliationRunReceipt,
            operation="advance_period_reconciliation_stage",
            bounded_json_result=bounded_json_result,
        )

    @_blocked_period_lifecycle_tool
    def get_period_reconciliation_run(
        company_ref: _CANONICAL_COMPANY_REF,
        project_ref: _CANONICAL_PROJECT_REF,
        run_ref: _PERIOD_RECONCILIATION_RUN_REF,
    ) -> str:
        """Read the exact Spring-owned Period Economic Spine run."""
        client, company_id, project_id = _strictly_resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _period_reconciliation_result(
            client.get_period_reconciliation_run(
                project_id, run_ref, company_id=company_id
            ),
            expected_type=PeriodReconciliationRun,
            operation="get_period_reconciliation_run",
            bounded_json_result=bounded_json_result,
        )

    @_blocked_period_lifecycle_tool
    def get_period_reconciliation_outcomes(
        company_ref: _CANONICAL_COMPANY_REF,
        project_ref: _CANONICAL_PROJECT_REF,
        run_ref: _PERIOD_RECONCILIATION_RUN_REF,
    ) -> str:
        """Read the exact three source-bound, uncertified outcome facts."""
        client, company_id, project_id = _strictly_resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _period_reconciliation_facts_result(
            client.get_period_reconciliation_outcomes(
                project_id, run_ref, company_id=company_id
            ),
            expected_type=PeriodReconciliationOutcomeFact,
            expected_count=3,
            response_key="outcomes",
            operation="get_period_reconciliation_outcomes",
            bounded_json_result=bounded_json_result,
        )

    @_blocked_period_lifecycle_tool
    def get_period_reconciliation_campaign_facts(
        company_ref: _CANONICAL_COMPANY_REF,
        project_ref: _CANONICAL_PROJECT_REF,
        run_ref: _PERIOD_RECONCILIATION_RUN_REF,
    ) -> str:
        """Read the exact ten source-bound campaign facts without certification."""
        client, company_id, project_id = _strictly_resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _period_reconciliation_facts_result(
            client.get_period_reconciliation_campaign_facts(
                project_id, run_ref, company_id=company_id
            ),
            expected_type=PeriodReconciliationCampaignFact,
            expected_count=10,
            response_key="campaign_facts",
            operation="get_period_reconciliation_campaign_facts",
            bounded_json_result=bounded_json_result,
        )

    def _period_reconciliation_terminal(
        operation: str,
        company_ref: str,
        project_ref: str,
        run_ref: str,
        request: PeriodReconciliationTerminalRequest,
    ) -> str:
        client, company_id, project_id = _strictly_resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        method = getattr(client, operation)
        return _period_reconciliation_result(
            method(project_id, run_ref, request, company_id=company_id),
            expected_type=PeriodReconciliationRunReceipt,
            operation=operation,
            bounded_json_result=bounded_json_result,
        )

    @_blocked_period_lifecycle_tool
    def fail_period_reconciliation_run(
        company_ref: _CANONICAL_COMPANY_REF,
        project_ref: _CANONICAL_PROJECT_REF,
        run_ref: _PERIOD_RECONCILIATION_RUN_REF,
        request: PeriodReconciliationTerminalRequest,
    ) -> str:
        """Retain exact failure evidence and terminalize without a provider write."""
        return _period_reconciliation_terminal(
            "fail_period_reconciliation_run",
            company_ref,
            project_ref,
            run_ref,
            request,
        )

    @_blocked_period_lifecycle_tool
    def cancel_period_reconciliation_run(
        company_ref: _CANONICAL_COMPANY_REF,
        project_ref: _CANONICAL_PROJECT_REF,
        run_ref: _PERIOD_RECONCILIATION_RUN_REF,
        request: PeriodReconciliationTerminalRequest,
    ) -> str:
        """Retain exact cancellation evidence before any provider write."""
        return _period_reconciliation_terminal(
            "cancel_period_reconciliation_run",
            company_ref,
            project_ref,
            run_ref,
            request,
        )

    @mcp.tool(annotations=_CODING_HARNESS_NON_RETRYABLE)
    def start_project_work_packet(
        company_ref: str,
        project_ref: str,
    ) -> str:
        """Propose or start Spring's exact approved Project work packet."""

        client, company_id, project_id = _resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _project_start_result(
            client.start_project_work_packet(
                project_id,
                company_id=company_id,
            ),
            bounded_json_result=bounded_json_result,
        )

    @mcp.tool(annotations=_READ_ONLY)
    def get_project_work_packet_run(
        company_ref: str,
        project_ref: str,
        run_ref: str,
    ) -> str:
        """Read one exact Project work-packet run without harness custody."""

        client, company_id, project_id = _resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _project_run_result(
            client.get_project_work_packet_run(
                project_id,
                run_ref,
                company_id=company_id,
            ),
            bounded_json_result=bounded_json_result,
        )

    @mcp.tool(annotations=_EXTERNAL_IDEMPOTENT_START)
    def start_service_case_resolution(
        company_ref: str,
        project_ref: str,
        request: _PublicServiceCaseResolutionStart,
    ) -> str:
        """Start one quarantined Service loop from an exact typed candidate."""

        client, company_id, project_id = _resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _result(
            client.start_service_case_resolution(
                project_id,
                _internal_start_request(request, ServiceCaseResolutionStart),
                company_id=company_id,
            ),
            operation="start_service_case_resolution",
            bounded_json_result=bounded_json_result,
        )

    @mcp.tool(annotations=_READ_ONLY)
    def get_service_case_resolution(
        company_ref: str,
        project_ref: str,
        run_ref: str,
    ) -> str:
        """Read the canonical state/evidence projection for one ``scr_`` run."""

        client, company_id, project_id = _resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _result(
            client.get_service_case_resolution(
                project_id,
                run_ref,
                company_id=company_id,
            ),
            operation="get_service_case_resolution",
            bounded_json_result=bounded_json_result,
        )

    @mcp.tool(annotations=_EXTERNAL_NON_RETRYABLE_EFFECT)
    def advance_service_case_resolution(
        company_ref: str,
        project_ref: str,
        run_ref: str,
    ) -> str:
        """Ask Spring to advance at most one approval/effect/observation phase."""

        client, company_id, project_id = _resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _result(
            client.advance_service_case_resolution(
                project_id,
                run_ref,
                company_id=company_id,
            ),
            operation="advance_service_case_resolution",
            bounded_json_result=bounded_json_result,
        )

    @mcp.tool(annotations=_CANCEL)
    def cancel_service_case_resolution(
        company_ref: str,
        project_ref: str,
        run_ref: str,
        request: _PublicCancellationRequest,
    ) -> str:
        """Cancel only the exact undecided pre-reply Service run."""

        client, company_id, project_id = _resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _result(
            client.cancel_service_case_resolution(
                project_id,
                run_ref,
                reason=request.reason,
                company_id=company_id,
            ),
            operation="cancel_service_case_resolution",
            bounded_json_result=bounded_json_result,
        )

    @mcp.tool(annotations=_READ_ONLY)
    def list_governed_communication_sources(
        company_ref: str,
        project_ref: str,
        limit: _SOURCE_PAGE_LIMIT = 20,
        cursor: _SOURCE_CURSOR = None,
    ) -> str:
        """List bounded opaque Gmail approval sources; no content or UUID is returned."""

        client, company_id, project_id = _resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        page = client.list_governed_communication_sources(
            project_id,
            limit=limit,
            cursor=cursor,
            company_id=company_id,
        )
        if not isinstance(page, GovernedCommunicationSourcePage):
            raise ValueError("Golden Loop client returned a non-source-page result")
        return bounded_json_result(
            page.to_dict(),
            operation=_REVENUE_SOURCE_LIST_TOOL,
            max_chars=16_000,
            compact=True,
        )

    @mcp.tool(annotations=_REVENUE_START)
    def start_governed_communication_run(
        company_ref: str,
        project_ref: str,
        request: _PublicGovernedCommunicationStart,
    ) -> str:
        """Admit one approved source; Gmail may follow asynchronously, never inline."""

        client, company_id, project_id = _resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _result(
            client.start_governed_communication_run(
                project_id,
                GovernedCommunicationAdmission(
                    source_ref=request.source_ref,
                    source_surface="mcp",
                ),
                idempotency_key=request.idempotency_key,
                company_id=company_id,
            ),
            operation="start_governed_communication_run",
            bounded_json_result=bounded_json_result,
        )

    @mcp.tool(annotations=_READ_ONLY)
    def get_governed_communication_run(
        company_ref: str,
        project_ref: str,
        run_ref: str,
    ) -> str:
        """Read one canonical worker-owned Revenue ``gcr_`` run projection."""

        client, company_id, project_id = _resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _result(
            client.get_governed_communication_run(
                project_id, run_ref, company_id=company_id
            ),
            operation="get_governed_communication_run",
            bounded_json_result=bounded_json_result,
        )

    @mcp.tool(annotations=_CANCEL)
    def cancel_governed_communication_run(
        company_ref: str,
        project_ref: str,
        run_ref: str,
    ) -> str:
        """Cancel a cancellable Revenue run; worker execution remains separate."""

        client, company_id, project_id = _resolved_scope(
            resolve_scope, company_ref, project_ref
        )
        return _result(
            client.cancel_governed_communication_run(
                project_id, run_ref, company_id=company_id
            ),
            operation="cancel_governed_communication_run",
            bounded_json_result=bounded_json_result,
        )

    collisions = sorted(
        name
        for name, original in registered_before.items()
        if tools.get(name) is not original
    )
    if collisions:
        raise RuntimeError(
            "Golden Loop MCP tool registration replaced existing tools: "
            + ", ".join(collisions)
        )
    registered = tuple(name for name in tools if name not in registered_before)
    locally_registered_contract_names = {
        contract.tool_name
        for contract in GOLDEN_LOOP_MCP_LIFECYCLE_TOOL_CONTRACTS
        if contract.participation is GoldenLoopProjectionParticipation.CALLABLE
        and contract.tool_name
        not in {
            "dynamic_workflow_next_assignment",
            "dynamic_workflow_cancel",
        }
    }
    missing_declared_tools = sorted(
        locally_registered_contract_names.difference(registered)
    )
    missing_reference_entrypoints = sorted(
        set(REFERENCE_GOLDEN_LOOP_MCP_ENTRYPOINT_TOOL_NAMES).difference(registered)
    )
    if missing_declared_tools or missing_reference_entrypoints:
        missing = sorted(
            set(missing_declared_tools).union(missing_reference_entrypoints)
        )
        raise RuntimeError(
            "Golden Loop MCP declarations did not register exact tools: "
            + ", ".join(missing)
        )
    # Some canonical Golden Loop operations (currently the hosted Dynamic
    # Workflow advance/cancel protocol) are registered by the root MCP server
    # before this projection installs its local tools. Close those reviewed
    # schemas too: being pre-existing must not let a canonical input bypass the
    # same fail-closed object contract applied to this registration delta.
    callable_contract_tool_names = {
        contract.tool_name
        for contract in GOLDEN_LOOP_MCP_LIFECYCLE_TOOL_CONTRACTS
        if contract.participation is GoldenLoopProjectionParticipation.CALLABLE
        and contract.tool_name is not None
    }
    for tool_name in sorted(set(registered).union(callable_contract_tool_names)):
        tool = tools.get(tool_name)
        if tool is None:
            continue
        parameters = getattr(tool, "parameters", None)
        if not isinstance(parameters, dict):
            raise RuntimeError(f"Golden Loop MCP tool did not register: {tool_name}")
        _close_object_schemas(parameters)
    assert_golden_loop_mcp_tool_contracts(mcp, require_all_callable=False)
    return registered


__all__ = [
    "GOLDEN_LOOP_MCP_CORE_OPERATIONS_SCHEMA",
    "GOLDEN_LOOP_MCP_LIFECYCLE_FORBIDDEN_ALIASES",
    "GOLDEN_LOOP_MCP_LIFECYCLE_TOOL_CONTRACTS",
    "GOLDEN_LOOP_MCP_PRIVATE_SCOPE_SCHEMA_FIELDS",
    "GOLDEN_LOOP_MCP_PUBLIC_FORBIDDEN_SCHEMA_FIELDS",
    "GOLDEN_LOOP_MCP_TOOL_CONTRACTS",
    "MCP_ANNOTATION_PROFILE_VALUES",
    "OPERATING_LOOP_MCP_PRIMARY_TOOL_NAMES",
    "OPERATING_LOOP_MCP_PROTOCOL_SCHEMA",
    "REFERENCE_GOLDEN_LOOP_MCP_ENTRYPOINT_TOOL_NAMES",
    "GoldenLoopMcpToolContract",
    "GoldenLoopMcpLifecycleToolContract",
    "McpAnnotationProfile",
    "McpInputObjectShape",
    "McpInputShape",
    "assert_golden_loop_mcp_tool_contracts",
    "register_golden_loop_mcp_tools",
]
