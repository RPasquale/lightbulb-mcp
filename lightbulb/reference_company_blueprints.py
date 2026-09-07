"""Reference Company Blueprints that compose the initial Golden Loop portfolio."""

from __future__ import annotations

from lightbulb.company_blueprints import (
    AgentRoleBinding,
    BudgetCapacityPolicy,
    CompanyBlueprint,
    CompanyObjective,
    CompanyOutcomeMetricBinding,
    CompanyProjectSpecification,
    ConnectorRequirement,
    DepartmentBinding,
    DeploymentUpgradePolicy,
    EconomicSpineContract,
    EconomicSpineStage,
    EconomicSpineStageBinding,
    ExecutionHostPolicy,
    GoldenLoopBinding,
    HumanAuthorityPolicy,
    KnowledgeEvidencePolicy,
    ProjectBinding,
    ScheduleBinding,
    SecretRequirement,
)
from lightbulb.golden_loops import CapabilityLifecycleState
from lightbulb.primitive_runtime import PrimitiveEvidenceVerificationGrade
from lightbulb.reference_golden_loops import (
    CONTRACT_TO_CASH_COLLECTED_CASH,
    CONTROLLED_SPEND_MATCHED_CLOSE,
    FINANCE_JOURNAL_READBACK_SETTLEMENT,
    GOVERNED_CRM_VERIFIED_REPLY,
    PERIOD_RECONCILIATION_APPROVED_CLOSE_CANDIDATE,
    PERIOD_RECONCILIATION_APPROVED_CLOSE_CANDIDATE_V0_3,
    PROJECT_INDEPENDENT_ACCEPTANCE,
    SERVICE_CASE_VERIFIED_RESOLUTION,
    VERIFIED_EVIDENCE_TO_PUBLISH_APPROVAL,
    initial_gtm_golden_loops,
    referenced_primitive_refs,
)


def _loop_binding(manifest: object, department_ref: str) -> GoldenLoopBinding:
    return GoldenLoopBinding(
        loop_ref=manifest.loop_ref,  # type: ignore[attr-defined]
        version=manifest.version,  # type: ignore[attr-defined]
        declaration_digest=manifest.declaration_digest,  # type: ignore[attr-defined]
        declared_lifecycle=manifest.lifecycle,  # type: ignore[attr-defined]
        department_ref=department_ref,
    )


SERVICES_STUDIO_DELIVERY_PROJECT_SPEC = CompanyProjectSpecification(
    project_ref="services_studio_delivery",
    version="0.2.0",
    title="Services studio delivery and verified improvement",
    purpose=(
        "Run approved Project work packets and verified improvements through a "
        "user-selected coding harness to independently accepted artifacts and a "
        "separately approved publication candidate, without claiming merge, "
        "deployment, or publication authority."
    ),
    department_ref="department.delivery",
    objective_refs=(
        "objective.deliver_accepted_work",
        "objective.improve_from_verified_evidence",
    ),
    agent_role_refs=(
        "project_agent",
        "planner",
        "builder",
        "independent_evaluator",
        "improvement_operator",
        "implementation_approver",
        "canary_evaluator",
        "publish_approver",
    ),
    workflow_refs=(
        "dynamic_workflow.project_work_packet_acceptance",
        "workflow.verified_improvement_delivery",
    ),
    loop_refs=(
        PROJECT_INDEPENDENT_ACCEPTANCE.loop_ref,
        VERIFIED_EVIDENCE_TO_PUBLISH_APPROVAL.loop_ref,
    ),
    allowed_primitive_refs=(
        "project.create_work_packet",
        "learning.plan_optimization_sweep",
        "approval.request_decision",
        "project.execute_approved_work_packet",
        "project.evaluate_work_packet_artifact",
        "workflow.evaluate_staging_canary",
    ),
    approval_policy_refs=(
        "project_work_packet_dynamic_workflow_start",
        "improvement_implementation",
        "capability_publication_candidate",
        "code_merge_and_deployment",
    ),
    allowed_harnesses=("claude_code", "codex", "cursor"),
)


AI_NATIVE_SERVICES_STUDIO_BLUEPRINT_V0_6 = CompanyBlueprint(
    blueprint_ref="company.ai_native_services_studio",
    version="0.6.0",
    name="AI-native services studio candidate",
    company_archetype="ai_native_services_studio",
    lifecycle=CapabilityLifecycleState.QUARANTINED,
    objectives=(
        CompanyObjective(
            objective_ref="objective.acquire_verified_demand",
            description="Create governed customer conversations with verified reply evidence.",
            metric_refs=("verified_reply_rate", "time_to_verified_reply_seconds"),
        ),
        CompanyObjective(
            objective_ref="objective.agree_and_monetize_work",
            description=(
                "Turn qualified demand into an accepted agreement, issued invoice, "
                "and verified cash receipt."
            ),
            metric_refs=(
                "agreement_to_collected_cash_rate",
                "time_to_collected_cash_seconds",
                "duplicate_invoice_or_payment_effect_rate",
            ),
        ),
        CompanyObjective(
            objective_ref="objective.deliver_accepted_work",
            description="Produce bounded work artifacts accepted by an independent evaluator.",
            metric_refs=(
                "independent_acceptance_rate",
                "accepted_work_packet_mean_time_to_independent_acceptance_seconds",
            ),
        ),
        CompanyObjective(
            objective_ref="objective.control_accounting_effects",
            description="Post and read back journal effects without automatic duplication.",
            metric_refs=(
                "journal_applied_settlement_rate",
                "duplicate_journal_effect_rate",
            ),
        ),
        CompanyObjective(
            objective_ref="objective.verify_service_resolution",
            description=(
                "Reach customer-confirmed, independently approved, provider-read-back "
                "Freshservice closure without unsafe effect replay."
            ),
            metric_refs=(
                "customer_confirmed_provider_closed_rate",
                "time_to_customer_confirmed_provider_close_seconds",
                "case_reopen_rate",
                "service_manual_reconciliation_rate",
            ),
        ),
        CompanyObjective(
            objective_ref="objective.control_company_spend",
            description=(
                "Approve a content-bound commitment, issue and read back one purchase "
                "order, and independently close only a verified three-way match."
            ),
            metric_refs=(
                "spend_policy_compliance_rate",
                "matched_procurement_close_rate",
                "duplicate_purchase_order_effect_rate",
            ),
        ),
        CompanyObjective(
            objective_ref="objective.reconcile_company_books",
            description=(
                "Reconcile the exact scoped period books and surface every unresolved "
                "balance without claiming that the provider ledger period is closed."
            ),
            metric_refs=(
                "period_reconciliation_completion_rate",
                "unreconciled_balance_rate",
                "time_to_approved_close_candidate_seconds",
            ),
        ),
        CompanyObjective(
            objective_ref="objective.improve_from_verified_evidence",
            description=(
                "Produce an independently approved publication candidate from verified "
                "outcome evidence without merging, deploying, or publishing it."
            ),
            metric_refs=(
                "verified_improvement_adoption_rate",
                "artifact_correction_rate",
                "time_to_publish_approval_seconds",
            ),
        ),
    ),
    departments=(
        DepartmentBinding(
            department_ref="department.revenue",
            title="Revenue",
            objective_refs=("objective.acquire_verified_demand",),
            agent_role_refs=("revenue_operator", "communication_specialist"),
            loop_refs=(GOVERNED_CRM_VERIFIED_REPLY.loop_ref,),
        ),
        DepartmentBinding(
            department_ref="department.delivery",
            title="Delivery",
            objective_refs=(
                "objective.deliver_accepted_work",
                "objective.improve_from_verified_evidence",
            ),
            agent_role_refs=(
                "project_agent",
                "planner",
                "improvement_operator",
                "implementation_approver",
                "builder",
                "independent_evaluator",
                "canary_evaluator",
                "publish_approver",
            ),
            loop_refs=(
                PROJECT_INDEPENDENT_ACCEPTANCE.loop_ref,
                VERIFIED_EVIDENCE_TO_PUBLISH_APPROVAL.loop_ref,
            ),
        ),
        DepartmentBinding(
            department_ref="department.finance",
            title="Finance",
            objective_refs=(
                "objective.agree_and_monetize_work",
                "objective.control_accounting_effects",
                "objective.control_company_spend",
                "objective.reconcile_company_books",
            ),
            agent_role_refs=(
                "accountant",
                "independent_finance_reviewer",
                "procurement_operator",
                "independent_spend_approver",
                "independent_procurement_close_reviewer",
            ),
            loop_refs=(
                CONTRACT_TO_CASH_COLLECTED_CASH.loop_ref,
                FINANCE_JOURNAL_READBACK_SETTLEMENT.loop_ref,
                PERIOD_RECONCILIATION_APPROVED_CLOSE_CANDIDATE.loop_ref,
                CONTROLLED_SPEND_MATCHED_CLOSE.loop_ref,
            ),
        ),
        DepartmentBinding(
            department_ref="department.service",
            title="Customer service",
            objective_refs=("objective.verify_service_resolution",),
            agent_role_refs=("service_agent", "customer_outcome_verifier"),
            loop_refs=(SERVICE_CASE_VERIFIED_RESOLUTION.loop_ref,),
        ),
    ),
    agent_roles=(
        AgentRoleBinding(
            role_ref="revenue_operator",
            title="Revenue operator",
            responsibilities=(
                "Select the exact scoped contact and business objective.",
                "Interpret verified replies without asserting downstream conversion.",
            ),
            allowed_primitive_refs=(
                "communication.plan_crm_conversation_turn",
                "communication.classify_reply",
            ),
            allowed_tool_refs=(
                "gmail.get_thread",
                "signing.get_envelope",
                "signing.download_document",
            ),
        ),
        AgentRoleBinding(
            role_ref="communication_specialist",
            title="Communication specialist",
            responsibilities=(
                "Apply channel policy and identity resolution.",
                "Materialize only approval-bound external communication.",
            ),
            allowed_primitive_refs=(
                "communication.evaluate_jurisdiction_channel_policy",
                "communication.resolve_cross_channel_identity",
                "communication.write_email",
            ),
            allowed_tool_refs=("gmail.send_email",),
        ),
        AgentRoleBinding(
            role_ref="project_agent",
            title="Project Agent",
            responsibilities=(
                "Bind the approved work packet and immutable acceptance contract.",
                "Coordinate but never self-accept implementation work.",
            ),
            allowed_primitive_refs=("project.create_work_packet",),
        ),
        AgentRoleBinding(
            role_ref="planner",
            title="Delivery planner",
            responsibilities=(
                "Decompose the immutable acceptance contract into bounded assignments.",
            ),
        ),
        AgentRoleBinding(
            role_ref="builder",
            title="Selected coding harness builder",
            responsibilities=(
                "Return content-addressed artifacts inside the leased assignment scope.",
                "Never widen scope, self-approve, merge, deploy, publish, or declare Project completion.",
            ),
            allowed_primitive_refs=("project.execute_approved_work_packet",),
        ),
        AgentRoleBinding(
            role_ref="independent_evaluator",
            title="Independent delivery evaluator",
            responsibilities=(
                "Evaluate every acceptance criterion with fresh, distinct custody.",
                "Remain separate from the builder and never infer publication or deployment authority.",
            ),
            allowed_primitive_refs=("project.evaluate_work_packet_artifact",),
        ),
        AgentRoleBinding(
            role_ref="improvement_operator",
            title="Verified improvement operator",
            responsibilities=(
                "Select only retained outcome evidence and a bounded measurable gap.",
                "Propose improvement work without approving implementation, publication, or deployment.",
            ),
            allowed_primitive_refs=("learning.plan_optimization_sweep",),
        ),
        AgentRoleBinding(
            role_ref="implementation_approver",
            title="Independent implementation approver",
            responsibilities=(
                "Approve only the exact content-bound improvement work packet.",
                "Remain separate from the improvement operator, builder, evaluator, and publication approver.",
            ),
            allowed_primitive_refs=("approval.request_decision",),
        ),
        AgentRoleBinding(
            role_ref="canary_evaluator",
            title="Independent staging canary evaluator",
            responsibilities=(
                "Compare server-retained baseline and staging evidence without deploying production.",
                "Return a source-bound canary result independently of the builder.",
            ),
            allowed_primitive_refs=("workflow.evaluate_staging_canary",),
        ),
        AgentRoleBinding(
            role_ref="publish_approver",
            title="Independent publication-candidate approver",
            responsibilities=(
                "Approve only the exact independently accepted, passing-canary candidate.",
                "Never treat publication approval as merge, deployment, or external-publish authority.",
            ),
            allowed_primitive_refs=("approval.request_decision",),
        ),
        AgentRoleBinding(
            role_ref="accountant",
            title="Accountant",
            responsibilities=(
                "Prepare and submit only approved, balanced journal candidates.",
            ),
            allowed_primitive_refs=(
                "finance.discover_ledger_accounts",
                "finance.prepare_journal_entry",
                "finance.post_journal_entry",
                "finance.create_invoice",
                "finance.propose_period_close_transition",
                "finance.evaluate_period_reconciliation",
            ),
            allowed_tool_refs=(
                "quickbooks.list_accounts",
                "quickbooks.create_journal_entry",
                "quickbooks.create_invoice",
                "quickbooks.trial_balance_report",
                "quickbooks.balance_sheet_report",
                "quickbooks.cash_flow_report",
                "quickbooks.aged_receivable_report",
                "quickbooks.aged_payable_report",
            ),
        ),
        AgentRoleBinding(
            role_ref="independent_finance_reviewer",
            title="Independent finance reviewer",
            responsibilities=(
                "Evaluate journal controls and exact readback evidence.",
            ),
            allowed_primitive_refs=(
                "finance.evaluate_journal_entry_controls",
                "finance.reconcile_journal_post",
                "finance.observe_invoice_issued",
                "finance.observe_invoice_payment_applied",
                "finance.observe_cash_settlement",
                "finance.propose_period_close_transition",
                "finance.evaluate_period_close_readiness",
            ),
            allowed_tool_refs=(
                "quickbooks.get_journal_entry",
                "quickbooks.observe_invoice_issued",
                "quickbooks.observe_invoice_payment_applied",
                "stripe.observe_cash_settlement",
            ),
        ),
        AgentRoleBinding(
            role_ref="procurement_operator",
            title="Procurement operator",
            responsibilities=(
                "Prepare exact requisition, purchase-order, receipt, and supplier-invoice evidence.",
                "Never approve its own spend commitment or match exception.",
            ),
            allowed_primitive_refs=(
                "procurement.plan_approved_commitment_to_matched_close",
            ),
            allowed_tool_refs=(
                "xero.create_purchase_order",
                "xero.get_purchase_order",
            ),
        ),
        AgentRoleBinding(
            role_ref="independent_spend_approver",
            title="Independent spend approver",
            responsibilities=(
                "Approve a content-bound spend commitment within policy and budget.",
                "Remain separate from purchase-order dispatch, matching, and close approval.",
            ),
            allowed_primitive_refs=(
                "procurement.plan_approved_commitment_to_matched_close",
            ),
        ),
        AgentRoleBinding(
            role_ref="independent_procurement_close_reviewer",
            title="Independent procurement close reviewer",
            responsibilities=(
                "Review the retained purchase order, provider readback, receipt, invoice, and deterministic match.",
                "Approve matched close independently of the operator, spend approver, and match evaluator.",
            ),
            allowed_primitive_refs=(
                "procurement.plan_approved_commitment_to_matched_close",
            ),
            allowed_tool_refs=("xero.get_purchase_order",),
        ),
        AgentRoleBinding(
            role_ref="service_agent",
            title="Service agent",
            responsibilities=(
                "Classify, route, and content-bind the exact resolution candidate.",
                "Request governed reply and closure effects without approving its own work.",
            ),
            allowed_primitive_refs=(
                "service.intake_and_classify_case",
                "service.route_and_escalate_case",
                "service.submit_resolution_for_verification",
                "service.propose_remedy_authorization",
            ),
            allowed_tool_refs=(
                "freshservice.get_ticket",
                "freshservice.reply_ticket_public",
                "freshservice.close_ticket",
            ),
        ),
        AgentRoleBinding(
            role_ref="customer_outcome_verifier",
            title="Customer outcome verifier",
            responsibilities=(
                "Verify the unique customer confirmation bound to the public reply.",
                "Accept closure only after an exact same-ticket provider readback.",
            ),
            allowed_primitive_refs=(
                "service.evaluate_case_resolution_controls",
                "service.verify_case_resolution",
            ),
            allowed_tool_refs=(
                "freshservice.observe_customer_confirmation",
                "freshservice.get_ticket_status",
            ),
        ),
    ),
    golden_loops=(
        _loop_binding(CONTRACT_TO_CASH_COLLECTED_CASH, "department.finance"),
        _loop_binding(FINANCE_JOURNAL_READBACK_SETTLEMENT, "department.finance"),
        _loop_binding(
            PERIOD_RECONCILIATION_APPROVED_CLOSE_CANDIDATE_V0_3,
            "department.finance",
        ),
        _loop_binding(CONTROLLED_SPEND_MATCHED_CLOSE, "department.finance"),
        _loop_binding(PROJECT_INDEPENDENT_ACCEPTANCE, "department.delivery"),
        _loop_binding(GOVERNED_CRM_VERIFIED_REPLY, "department.revenue"),
        _loop_binding(SERVICE_CASE_VERIFIED_RESOLUTION, "department.service"),
        _loop_binding(VERIFIED_EVIDENCE_TO_PUBLISH_APPROVAL, "department.delivery"),
    ),
    allowed_primitive_refs=referenced_primitive_refs(),
    allowed_tool_refs=(
        "gmail.get_thread",
        "gmail.send_email",
        "quickbooks.create_journal_entry",
        "quickbooks.get_journal_entry",
        "quickbooks.list_accounts",
        "quickbooks.create_invoice",
        "quickbooks.observe_invoice_issued",
        "quickbooks.observe_invoice_payment_applied",
        "quickbooks.trial_balance_report",
        "quickbooks.balance_sheet_report",
        "quickbooks.cash_flow_report",
        "quickbooks.aged_receivable_report",
        "quickbooks.aged_payable_report",
        "stripe.observe_cash_settlement",
        "signing.get_envelope",
        "signing.download_document",
        "freshservice.get_ticket",
        "freshservice.reply_ticket_public",
        "freshservice.observe_customer_confirmation",
        "freshservice.close_ticket",
        "freshservice.get_ticket_status",
        "xero.create_purchase_order",
        "xero.get_purchase_order",
    ),
    connector_requirements=(
        ConnectorRequirement(
            requirement_ref="connector.gmail_customer_communications",
            provider="gmail",
            required_tool_refs=("gmail.get_thread", "gmail.send_email"),
        ),
        ConnectorRequirement(
            requirement_ref="connector.quickbooks_accounting",
            provider="quickbooks",
            required_tool_refs=(
                "quickbooks.create_journal_entry",
                "quickbooks.get_journal_entry",
                "quickbooks.list_accounts",
                "quickbooks.create_invoice",
                "quickbooks.observe_invoice_issued",
                "quickbooks.observe_invoice_payment_applied",
                "quickbooks.trial_balance_report",
                "quickbooks.balance_sheet_report",
                "quickbooks.cash_flow_report",
                "quickbooks.aged_receivable_report",
                "quickbooks.aged_payable_report",
            ),
        ),
        ConnectorRequirement(
            requirement_ref="connector.stripe_cash_settlement",
            provider="stripe",
            required_tool_refs=("stripe.observe_cash_settlement",),
        ),
        ConnectorRequirement(
            requirement_ref="connector.docusign_agreements",
            provider="signing",
            required_tool_refs=("signing.get_envelope", "signing.download_document"),
        ),
        ConnectorRequirement(
            requirement_ref="connector.freshservice_customer_support",
            provider="freshservice",
            required_tool_refs=(
                "freshservice.get_ticket",
                "freshservice.reply_ticket_public",
                "freshservice.observe_customer_confirmation",
                "freshservice.close_ticket",
                "freshservice.get_ticket_status",
            ),
        ),
        ConnectorRequirement(
            requirement_ref="connector.xero_procurement",
            provider="xero",
            required_tool_refs=(
                "xero.create_purchase_order",
                "xero.get_purchase_order",
            ),
        ),
    ),
    secret_requirements=(
        SecretRequirement(
            secret_ref="secret.gmail_customer_communications",
            connector_requirement_ref="connector.gmail_customer_communications",
            purpose="Resolve a Spring-custodied Gmail connector account at deployment time.",
            rotation_max_age_days=90,
        ),
        SecretRequirement(
            secret_ref="secret.quickbooks_accounting",
            connector_requirement_ref="connector.quickbooks_accounting",
            purpose="Resolve a Spring-custodied QuickBooks connector account at deployment time.",
            rotation_max_age_days=90,
        ),
        SecretRequirement(
            secret_ref="secret.stripe_cash_settlement",
            connector_requirement_ref="connector.stripe_cash_settlement",
            purpose="Resolve a Spring-custodied Stripe account for independent settlement readback.",
            rotation_max_age_days=90,
        ),
        SecretRequirement(
            secret_ref="secret.docusign_agreements",
            connector_requirement_ref="connector.docusign_agreements",
            purpose="Resolve Spring-custodied DocuSign agreement evidence at deployment time.",
            rotation_max_age_days=90,
        ),
        SecretRequirement(
            secret_ref="secret.freshservice_customer_support",
            connector_requirement_ref="connector.freshservice_customer_support",
            purpose=(
                "Resolve a Spring-custodied Freshservice connector account at "
                "deployment time."
            ),
            rotation_max_age_days=90,
        ),
        SecretRequirement(
            secret_ref="secret.xero_procurement",
            connector_requirement_ref="connector.xero_procurement",
            purpose=(
                "Resolve the Spring-custodied Xero procurement account used by the "
                "approval-bound purchase-order write and independent exact readback."
            ),
            rotation_max_age_days=90,
        ),
    ),
    projects=(
        ProjectBinding(
            project_ref=SERVICES_STUDIO_DELIVERY_PROJECT_SPEC.project_ref,
            project_version=SERVICES_STUDIO_DELIVERY_PROJECT_SPEC.version,
            project_spec_digest=SERVICES_STUDIO_DELIVERY_PROJECT_SPEC.spec_digest,
            workflow_refs=SERVICES_STUDIO_DELIVERY_PROJECT_SPEC.workflow_refs,
            loop_refs=SERVICES_STUDIO_DELIVERY_PROJECT_SPEC.loop_refs,
            project_spec=SERVICES_STUDIO_DELIVERY_PROJECT_SPEC,
        ),
    ),
    schedules=(
        ScheduleBinding(
            schedule_ref="schedule.finance_journal_review",
            loop_ref=FINANCE_JOURNAL_READBACK_SETTLEMENT.loop_ref,
            trigger_ref="finance.journal_post_requested",
            schedule_expression="event:finance.journal_post_requested",
            timezone="UTC",
        ),
        ScheduleBinding(
            schedule_ref="schedule.service_case_intake",
            loop_ref=SERVICE_CASE_VERIFIED_RESOLUTION.loop_ref,
            trigger_ref="service.case_received",
            schedule_expression="event:service.case_received",
            timezone="UTC",
        ),
        ScheduleBinding(
            schedule_ref="schedule.period_reconciliation_review",
            loop_ref=PERIOD_RECONCILIATION_APPROVED_CLOSE_CANDIDATE.loop_ref,
            trigger_ref="finance.period_close_requested",
            schedule_expression="event:finance.period_close_requested",
            timezone="UTC",
        ),
        ScheduleBinding(
            schedule_ref="schedule.procurement_requisition_review",
            loop_ref=CONTROLLED_SPEND_MATCHED_CLOSE.loop_ref,
            trigger_ref="procurement.requisition_requested",
            schedule_expression="event:procurement.requisition_requested",
            timezone="UTC",
        ),
        ScheduleBinding(
            schedule_ref="schedule.verified_improvement_review",
            loop_ref=VERIFIED_EVIDENCE_TO_PUBLISH_APPROVAL.loop_ref,
            trigger_ref="workflow.verified_outcome_gap_detected",
            schedule_expression="event:workflow.verified_outcome_gap_detected",
            timezone="UTC",
        ),
    ),
    economic_spine=EconomicSpineContract(
        version="0.3.0",
        stages=(
            EconomicSpineStageBinding(
                stage=EconomicSpineStage.ACQUIRE_DEMAND,
                objective_ref="objective.acquire_verified_demand",
                loop_refs=(GOVERNED_CRM_VERIFIED_REPLY.loop_ref,),
                required_artifact_refs=("verified_inbound_reply",),
                terminal_outcome_ref="verified_reply_recorded",
                required_evidence_kind="verified_reply_trace",
                lifecycle=CapabilityLifecycleState.QUARANTINED,
                known_blockers=(
                    "The governed CRM loop has no retained production/customer certification.",
                ),
            ),
            EconomicSpineStageBinding(
                stage=EconomicSpineStage.AGREE_WORK,
                objective_ref="objective.agree_and_monetize_work",
                loop_refs=(CONTRACT_TO_CASH_COLLECTED_CASH.loop_ref,),
                required_artifact_refs=("executed_customer_agreement",),
                terminal_outcome_ref="customer_agreement_effective",
                required_evidence_kind="executed_customer_agreement",
                lifecycle=CapabilityLifecycleState.QUARANTINED,
                known_blockers=(
                    "Immutable Spring executed-agreement custody exists locally, but no retained provider-conformance and customer certification permits release promotion.",
                ),
            ),
            EconomicSpineStageBinding(
                stage=EconomicSpineStage.DELIVER_VALUE,
                objective_ref="objective.deliver_accepted_work",
                loop_refs=(PROJECT_INDEPENDENT_ACCEPTANCE.loop_ref,),
                required_artifact_refs=("builder_artifact_package",),
                terminal_outcome_ref="builder_artifact_package_retained",
                required_evidence_kind="builder_artifact_evidence",
                lifecycle=CapabilityLifecycleState.QUARANTINED,
                known_blockers=(
                    "The Project loop has no retained production/customer certification.",
                ),
            ),
            EconomicSpineStageBinding(
                stage=EconomicSpineStage.ACCEPT_VALUE,
                objective_ref="objective.deliver_accepted_work",
                loop_refs=(PROJECT_INDEPENDENT_ACCEPTANCE.loop_ref,),
                required_artifact_refs=("evaluator_verdict",),
                terminal_outcome_ref="work_packet_independently_accepted",
                required_evidence_kind="independent_evaluator_verdict",
                lifecycle=CapabilityLifecycleState.QUARANTINED,
                known_blockers=(
                    "Independent acceptance has not been certified with design-partner evidence.",
                ),
            ),
            EconomicSpineStageBinding(
                stage=EconomicSpineStage.INVOICE_CUSTOMER,
                objective_ref="objective.agree_and_monetize_work",
                loop_refs=(CONTRACT_TO_CASH_COLLECTED_CASH.loop_ref,),
                required_artifact_refs=("issued_customer_invoice",),
                terminal_outcome_ref="customer_invoice_issued",
                required_evidence_kind="issued_customer_invoice",
                lifecycle=CapabilityLifecycleState.QUARANTINED,
                known_blockers=(
                    "The v0.3 continuation and immutable Spring invoice-issued custody are locally implemented; production provider-pair and customer-outcome certification remain missing.",
                ),
            ),
            EconomicSpineStageBinding(
                stage=EconomicSpineStage.COLLECT_CASH,
                objective_ref="objective.agree_and_monetize_work",
                loop_refs=(CONTRACT_TO_CASH_COLLECTED_CASH.loop_ref,),
                required_artifact_refs=("settled_cash_receipt",),
                terminal_outcome_ref="customer_cash_collected",
                required_evidence_kind="settled_cash_receipt",
                lifecycle=CapabilityLifecycleState.QUARANTINED,
                known_blockers=(
                    "Independent QuickBooks payment-application and Stripe paid-payout custody are locally implemented; production settlement and customer-outcome certification remain missing.",
                ),
            ),
            EconomicSpineStageBinding(
                stage=EconomicSpineStage.SUPPORT_CUSTOMER,
                objective_ref="objective.verify_service_resolution",
                loop_refs=(SERVICE_CASE_VERIFIED_RESOLUTION.loop_ref,),
                required_artifact_refs=("service_resolution_receipt",),
                terminal_outcome_ref="customer_confirmed_provider_closed",
                required_evidence_kind="service_case_resolution_receipt",
                lifecycle=CapabilityLifecycleState.QUARANTINED,
                known_blockers=(
                    "The service loop has no retained customer-outcome certification.",
                ),
            ),
            EconomicSpineStageBinding(
                stage=EconomicSpineStage.CONTROL_SPEND,
                objective_ref="objective.control_company_spend",
                loop_refs=(CONTROLLED_SPEND_MATCHED_CLOSE.loop_ref,),
                required_artifact_refs=("procurement_close_receipt",),
                terminal_outcome_ref="matched_procurement_closed",
                required_evidence_kind="procurement_close_receipt",
                lifecycle=CapabilityLifecycleState.QUARANTINED,
                known_blockers=(
                    "Spring now owns the content-addressed transition chain, but certification and production promotion remain blocked.",
                ),
            ),
            EconomicSpineStageBinding(
                stage=EconomicSpineStage.RECONCILE_BOOKS,
                objective_ref="objective.reconcile_company_books",
                loop_refs=(
                    PERIOD_RECONCILIATION_APPROVED_CLOSE_CANDIDATE.loop_ref,
                ),
                required_artifact_refs=("journal_subledger_cash_ar_ap_package",),
                terminal_outcome_ref="approved_close_candidate",
                required_evidence_kind="reconciled_period_books",
                lifecycle=CapabilityLifecycleState.QUARANTINED,
                known_blockers=(
                    "Spring owns the content-addressed period-reconciliation transition chain, but production close evidence and certification remain missing.",
                ),
            ),
            EconomicSpineStageBinding(
                stage=EconomicSpineStage.IMPROVE_FROM_EVIDENCE,
                objective_ref="objective.improve_from_verified_evidence",
                loop_refs=(VERIFIED_EVIDENCE_TO_PUBLISH_APPROVAL.loop_ref,),
                required_artifact_refs=("approved_publication_candidate",),
                terminal_outcome_ref="approved_publication_candidate",
                required_evidence_kind="approved_publication_candidate",
                lifecycle=CapabilityLifecycleState.QUARANTINED,
                known_blockers=(
                    "Spring owns immutable project-scoped improvement terminal custody, but adopted-change outcome evidence and certification remain missing.",
                ),
            ),
        ),
    ),
    knowledge_evidence_policy=KnowledgeEvidencePolicy(
        context_space_refs=("company", "project", "customer_account"),
        minimum_evidence_grade=PrimitiveEvidenceVerificationGrade.ATTESTED,
        required_retention_policy_ref="company_evidence_two_years",
    ),
    human_authority_policy=HumanAuthorityPolicy(
        approval_policy_refs=(
            "project_work_packet_dynamic_workflow_start",
            "external_communications",
            "financial_posting",
            "procurement_spend_commitment",
            "procurement_matched_close",
            "period_close_candidate",
            "customer_service_reply",
            "customer_service_closure",
            "improvement_implementation",
            "capability_publication_candidate",
            "code_merge_and_deployment",
        ),
    ),
    budget_capacity_policy=BudgetCapacityPolicy(
        monthly_budget_microusd=2_000_000_000,
        max_loop_cost_microusd=100_000_000,
        max_concurrent_company_runs=20,
        max_concurrent_background_runs=12,
        interactive_capacity_reserve=4,
    ),
    execution_host_policy=ExecutionHostPolicy(
        allowed_harnesses=("claude_code", "codex", "cursor"),
        preferred_harnesses=("codex", "claude_code", "cursor"),
    ),
    outcome_metrics=(
        *tuple(
            CompanyOutcomeMetricBinding(
                metric_ref=metric.metric_ref,
                loop_refs=(manifest.loop_ref,),
                direction=metric.direction,
                unit=metric.unit,
                source_system_ref=metric.source_system_ref,
                required_sample_count=metric.required_sample_count,
                measurement_window_seconds=metric.measurement_window_seconds,
                certification_target=metric.certification_target,
                certification_comparison=metric.certification_comparison,
            )
            for manifest in initial_gtm_golden_loops()
            for metric in manifest.outcome_metrics
        ),
    ),
    deployment_upgrade_policy=DeploymentUpgradePolicy(
        deployment_mode="manual_approval",
    ),
    known_blockers=(
        "All eight bound Golden Loops remain QUARANTINED and are not production-deployable.",
        "The managed-Agent and coding-harness authorities lack retained multi-replica production-topology evidence.",
        "Spring can activate and roll back an effect-dark QUARANTINED shadow head, but production materialization, migration, provisioning, and promotion remain unavailable.",
        "All ten economic-spine stages now bind exact named loops and artifacts; the three newest loops have Spring authorities but remain quarantined pending certification evidence.",
        "No design-partner outcome, live-provider canary, or production migration evidence is attached.",
    ),
)

_ai_native_services_studio_v0_7_payload = (
    AI_NATIVE_SERVICES_STUDIO_BLUEPRINT_V0_6.model_dump(
        mode="python",
        exclude={"blueprint_digest"},
    )
)
_ai_native_services_studio_v0_7_payload.update(
    version="0.7.0",
    golden_loops=tuple(
        _loop_binding(
            PERIOD_RECONCILIATION_APPROVED_CLOSE_CANDIDATE,
            binding.department_ref,
        )
        if binding.loop_ref
        == PERIOD_RECONCILIATION_APPROVED_CLOSE_CANDIDATE.loop_ref
        else binding
        for binding in AI_NATIVE_SERVICES_STUDIO_BLUEPRINT_V0_6.golden_loops
    ),
)
AI_NATIVE_SERVICES_STUDIO_BLUEPRINT = CompanyBlueprint.model_validate(
    _ai_native_services_studio_v0_7_payload
)
del _ai_native_services_studio_v0_7_payload


REFERENCE_COMPANY_BLUEPRINTS = (AI_NATIVE_SERVICES_STUDIO_BLUEPRINT,)


__all__ = [
    "AI_NATIVE_SERVICES_STUDIO_BLUEPRINT",
    "AI_NATIVE_SERVICES_STUDIO_BLUEPRINT_V0_6",
    "REFERENCE_COMPANY_BLUEPRINTS",
    "SERVICES_STUDIO_DELIVERY_PROJECT_SPEC",
]
