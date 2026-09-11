"""Built-in executable business process primitives shipped by the SDK."""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any, Dict, Iterable, Literal, Mapping

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from lightbulb.cash_collection import CASH_COLLECTION_EXECUTABLE_PRIMITIVES
from lightbulb.communication_primitives import PlanCrmConversationTurnPrimitive
from lightbulb.communication_omnichannel import (
    EvaluateJurisdictionChannelPolicyPrimitive,
    NormalizeProviderOutcomePrimitive,
    PlanGovernedVoiceCallPrimitive,
    ResolveCrossChannelIdentityPrimitive,
)
from lightbulb.commercial_controls import EvaluateQuoteOrderContractControlsPrimitive
from lightbulb.commercial_operations_lifecycle import (
    COMMERCIAL_OPERATIONS_LIFECYCLE_EXECUTABLE_PRIMITIVES,
    ProposeCommercialOperationsTransitionPrimitive,
)
from lightbulb.customer_service_lifecycle import (
    CUSTOMER_SERVICE_LIFECYCLE_EXECUTABLE_PRIMITIVES,
    IntakeAndClassifyServiceCasePrimitive,
    ProposeServiceRemedyAuthorizationPrimitive,
    RouteAndEscalateServiceCasePrimitive,
    SubmitServiceResolutionPrimitive,
    VerifyServiceResolutionPrimitive,
)
from lightbulb.compliance_controls import EvaluateRegulatedControlsPrimitive
from lightbulb.compliance_risk_lifecycle import (
    COMPLIANCE_RISK_LIFECYCLE_EXECUTABLE_PRIMITIVES,
    ProposeComplianceRiskTransitionPrimitive,
)
from lightbulb.connector_bindings import resolve_connector_tool
from lightbulb.connector_execution import (
    ConnectorEffect,
    ConnectorExecutionResult,
    ConnectorExecutionStatus,
)
from lightbulb.domain_primitives import (
    ContractRiskFinding,
    DraftContractInput,
    DraftContractOutput,
    DraftContractPrimitive,
    IngestSupplierInvoicePrimitive,
    LeadQualificationRules,
    OnboardEmployeeInput,
    OnboardEmployeeOutput,
    OnboardEmployeePrimitive,
    OnboardingTask,
    QualifyLeadInput,
    QualifyLeadOutput,
    QualifyLeadPrimitive,
    ReviewContractInput,
    ReviewContractOutput,
    ReviewContractPrimitive,
    SupplierInvoiceInput,
    SupplierInvoiceOutput,
)
from lightbulb.finance_accounting import (
    FINANCE_ACCOUNTING_EXECUTABLE_PRIMITIVES,
    EvaluateJournalEntryControlsPrimitive,
    EvaluatePeriodCloseReadinessPrimitive,
)
from lightbulb.finance_adjusting_entries_package import (
    FINANCE_ADJUSTING_ENTRIES_PACKAGE_EXECUTABLE_PRIMITIVES,
    PrepareAdjustingEntriesPackagePrimitive,
)
from lightbulb.finance_adjusting_entries_transition import (
    FINANCE_ADJUSTING_ENTRIES_TRANSITION_EXECUTABLE_PRIMITIVES,
    PrepareAdjustingEntriesTransitionCommandPrimitive,
)
from lightbulb.finance_close_lifecycle import (
    FINANCE_CLOSE_LIFECYCLE_EXECUTABLE_PRIMITIVES,
    ProposePeriodCloseTransitionPrimitive,
)
from lightbulb.finance_close_approval_package import (
    FINANCE_CLOSE_APPROVAL_PACKAGE_EXECUTABLE_PRIMITIVES,
    PrepareCloseApprovalPackagePrimitive,
)
from lightbulb.finance_close_audit_packet import (
    FINANCE_CLOSE_AUDIT_PACKET_EXECUTABLE_PRIMITIVES,
    BuildFinanceCloseAuditPacketPrimitive,
)
from lightbulb.finance_close_approval_transition import (
    FINANCE_CLOSE_APPROVAL_TRANSITION_EXECUTABLE_PRIMITIVES,
    PrepareCloseApprovalTransitionCommandPrimitive,
)
from lightbulb.finance_close_period_package import (
    FINANCE_CLOSE_PERIOD_PACKAGE_EXECUTABLE_PRIMITIVES,
    PrepareClosePeriodPackagePrimitive,
)
from lightbulb.finance_close_period_transition import (
    FINANCE_CLOSE_PERIOD_TRANSITION_EXECUTABLE_PRIMITIVES,
    PrepareClosePeriodTransitionCommandPrimitive,
)
from lightbulb.finance_close_reconciliation_readiness import (
    FINANCE_CLOSE_RECONCILIATION_READINESS_EXECUTABLE_PRIMITIVES,
    EvaluateCloseReconciliationReadinessPrimitive,
)
from lightbulb.finance_close_evidence_bundle import (
    FINANCE_CLOSE_EVIDENCE_BUNDLE_EXECUTABLE_PRIMITIVES,
    PrepareCloseEvidenceBundlePrimitive,
)
from lightbulb.finance_close_workspace import (
    FINANCE_CLOSE_WORKSPACE_EXECUTABLE_PRIMITIVES,
    PrepareCloseWorkspacePrimitive,
)
from lightbulb.finance_close_source_transactions import (
    FINANCE_CLOSE_SOURCE_TRANSACTION_EXECUTABLE_PRIMITIVES,
    DiscoverCloseSourceTransactionsPrimitive,
)
from lightbulb.finance_xero_close_source_transactions import (
    FINANCE_XERO_CLOSE_SOURCE_TRANSACTION_EXECUTABLE_PRIMITIVES,
)
from lightbulb.finance_provider_period_status import (
    FINANCE_PROVIDER_PERIOD_STATUS_EXECUTABLE_PRIMITIVES,
    DiscoverProviderPeriodStatusPrimitive,
)
from lightbulb.finance_consolidation_package import (
    FINANCE_CONSOLIDATION_PACKAGE_EXECUTABLE_PRIMITIVES,
    PrepareConsolidationPackagePrimitive,
)
from lightbulb.finance_consolidation_transition import (
    FINANCE_CONSOLIDATION_TRANSITION_EXECUTABLE_PRIMITIVES,
    PrepareConsolidationTransitionCommandPrimitive,
)
from lightbulb.finance_general_ledger import (
    FINANCE_GENERAL_LEDGER_EXECUTABLE_PRIMITIVES,
    DiscoverGeneralLedgerActivityPrimitive,
)
from lightbulb.finance_journal_lifecycle import (
    FINANCE_JOURNAL_LIFECYCLE_EXECUTABLE_PRIMITIVES,
    DiscoverLedgerAccountsPrimitive,
    DiscoverTrialBalancePrimitive,
    PostJournalEntryPrimitive,
    PrepareJournalEntryPrimitive,
    ReconcileJournalPostPrimitive,
)
from lightbulb.finance_ledger_materialization import (
    FINANCE_LEDGER_MATERIALIZATION_EXECUTABLE_PRIMITIVES,
    MaterializeLedgerSnapshotPrimitive,
)
from lightbulb.finance_operating_controls import (
    FINANCE_OPERATING_EXECUTABLE_PRIMITIVES,
    EvaluateFinanceOperatingControlsPrimitive,
)
from lightbulb.finance_reconciliation_package import (
    FINANCE_RECONCILIATION_PACKAGE_EXECUTABLE_PRIMITIVES,
    PrepareReconciliationPackagePrimitive,
)
from lightbulb.finance_reconciliation_transition import (
    FINANCE_RECONCILIATION_TRANSITION_EXECUTABLE_PRIMITIVES,
    PrepareReconciliationTransitionCommandPrimitive,
)
from lightbulb.finance_settlement_reconciliation import (
    FINANCE_SETTLEMENT_RECONCILIATION_EXECUTABLE_PRIMITIVES,
    ReconcileStripeSettlementsPrimitive,
)
from lightbulb.finance_stripe_settlements import (
    FINANCE_STRIPE_SETTLEMENT_EXECUTABLE_PRIMITIVES,
    DiscoverStripeSettlementMovementsPrimitive,
)
from lightbulb.finance_subledger_lock_package import (
    FINANCE_SUBLEDGER_LOCK_PACKAGE_EXECUTABLE_PRIMITIVES,
    PrepareSubledgerLockPackagePrimitive,
)
from lightbulb.finance_subledger_lock_transition import (
    FINANCE_SUBLEDGER_LOCK_TRANSITION_EXECUTABLE_PRIMITIVES,
    PrepareSubledgerLockTransitionCommandPrimitive,
)
from lightbulb.growth_primitives import (
    CollectPaymentInput,
    CollectPaymentOutput,
    CollectPaymentPrimitive,
    CreateWorkPacketInput,
    CreateWorkPacketOutput,
    CreateWorkPacketPrimitive,
    GenerateBusinessArtifactInput,
    GenerateBusinessArtifactOutput,
    GenerateBusinessArtifactPrimitive,
    RequestDecisionInput,
    RequestDecisionOutput,
    RequestDecisionPrimitive,
)
from lightbulb.gtm_primitives import PlanOmnichannelProductLaunchPrimitive
from lightbulb.invoice_issuance import INVOICE_ISSUANCE_EXECUTABLE_PRIMITIVES
from lightbulb.manufacturing_controls import VerifyBomInventoryTraceabilityPrimitive
from lightbulb.manufacturing_execution_lifecycle import (
    MANUFACTURING_EXECUTION_LIFECYCLE_EXECUTABLE_PRIMITIVES,
    AdvanceManufacturingExecutionLifecyclePrimitive,
)
from lightbulb.manufacturing_field_quality import (
    FIELD_QUALITY_EXECUTABLE_PRIMITIVES,
    EvaluateFieldQualityControlsPrimitive,
)
from lightbulb.maintenance_work_order_lifecycle import (
    MAINTENANCE_WORK_ORDER_LIFECYCLE_EXECUTABLE_PRIMITIVES,
    ProposeMaintenanceWorkOrderTransitionPrimitive,
)
from lightbulb.operational_readiness import (
    OPERATIONAL_READINESS_EXECUTABLE_PRIMITIVES,
    EvaluateOperationalReadinessPrimitive,
)
from lightbulb.people_controls import EvaluateWorkerLifecycleControlsPrimitive
from lightbulb.people_operations_lifecycle import (
    PEOPLE_OPERATIONS_LIFECYCLE_EXECUTABLE_PRIMITIVES,
    ProposePeopleOperationsTransitionPrimitive,
)
from lightbulb.period_reconciliation import PERIOD_RECONCILIATION_EXECUTABLE_PRIMITIVES
from lightbulb.learning_primitives import (
    LearningDataProfile,
    LearningEventStreamContract,
    LearningRunPreparationPlan,
    OptimizationSweepBudgetLedger,
    OptimizationSweepBudget,
    OptimizationSweepOutput,
    OptimizationSweepResourceTotals,
    OptimizationSweepSafety,
    OptimizationSweepStage,
    PlanOptimizationSweepInput,
    PlanOptimizationSweepPrimitive,
    compile_optimization_sweep,
)
from lightbulb.primitive_runtime import (
    BusinessProcessPrimitive,
    PrimitiveBlocker,
    PrimitiveEvent,
    PrimitiveEvidence,
    PrimitiveExecutionContext,
    PrimitiveExecutionResult,
    PrimitiveExecutionStatus,
    PrimitiveRegistry,
)
from lightbulb.growth_cockpit import (
    BuildGrowthFunnelSnapshotPrimitive,
    DiagnoseGrowthPrimitive,
    PlanAudienceGrowthPrimitive,
    PlanContentCalendarPrimitive,
)
from lightbulb.growth_customers import (
    BuildCustomerValuePrimitive,
    ReviewCustomerValuePrimitive,
)
from lightbulb.accountant_loop import RunAccountantCyclePrimitive
from lightbulb.business_allocation import GateObjectiveFundingPrimitive
from lightbulb.fundraise_readiness import (
    AssessDefaultAlivePrimitive,
    ComputeBurnMultiplePrimitive,
)
from lightbulb.tax_provision import EstimateTaxSetAsidePrimitive
from lightbulb.cash_forecast import BuildCashFlowForecastPrimitive
from lightbulb.cash_payables import AssessPayablesPrimitive
from lightbulb.cash_receivables import AssessReceivablesPrimitive
from lightbulb.cash_runway import (
    AssessRunwayPrimitive,
    BuildRunwaySnapshotPrimitive,
    DeriveBudgetEnvelopePrimitive,
)
from lightbulb.grant_discovery import MatchGrantsPrimitive, SearchGrantsPrimitive
from lightbulb.growth_briefing import CompileBriefingPrimitive
from lightbulb.growth_mandate import PreflightActionPrimitive
from lightbulb.growth_objectives import AssessObjectivePrimitive
from lightbulb.growth_operating import (
    CompareFunnelSnapshotsPrimitive,
    CompileGrowthAgendaPrimitive,
)
from lightbulb.growth_profit import (
    BuildUnitEconomicsPrimitive,
    PlanPriceMovePrimitive,
    ReviewProfitPrimitive,
)
from lightbulb.profit_primitives import (
    PROFIT_EXECUTABLE_PRIMITIVES,
    ProfitWorkflowPrimitive,
)
from lightbulb.procurement_controls import EvaluatePurchaseToPayControlsPrimitive
from lightbulb.procure_to_pay_lifecycle import (
    PROCURE_TO_PAY_LIFECYCLE_EXECUTABLE_PRIMITIVES,
    ProposeProcureToPayTransitionPrimitive,
)
from lightbulb.vendor_onboarding_lifecycle import (
    VENDOR_ONBOARDING_LIFECYCLE_EXECUTABLE_PRIMITIVES,
    ProposeVendorOnboardingTransitionPrimitive,
)
from lightbulb.verified_improvement_primitives import (
    VERIFIED_IMPROVEMENT_EXECUTABLE_PRIMITIVES,
)
from lightbulb.product_governance import EvaluateReleaseGovernanceControlsPrimitive
from lightbulb.product_engineering_lifecycle import (
    PRODUCT_ENGINEERING_LIFECYCLE_EXECUTABLE_PRIMITIVES,
    ProposeProductEngineeringTransitionPrimitive,
)
from lightbulb.production_connector_conformance import (
    PRODUCTION_CONNECTOR_CONFORMANCE_EXECUTABLE_PRIMITIVES,
    EvaluateProductionConnectorConformancePrimitive,
)
from lightbulb.production_connector_read_conformance import (
    PRODUCTION_CONNECTOR_READ_CONFORMANCE_EXECUTABLE_PRIMITIVES,
    EvaluateProductionConnectorReadConformancePrimitive,
)
from lightbulb.service_controls import EvaluateCaseResolutionControlsPrimitive
from lightbulb.service_asset_remedy_lifecycle import (
    SERVICE_ASSET_REMEDY_LIFECYCLE_EXECUTABLE_PRIMITIVES,
    ProposeServiceAssetRemedyTransitionPrimitive,
)
from lightbulb.shopify_primitives import PlanShopifyStorefrontPrimitive
from lightbulb.supply_chain_controls import SUPPLY_CHAIN_EXECUTABLE_PRIMITIVES
from lightbulb.supply_chain_execution_lifecycle import (
    SUPPLY_CHAIN_EXECUTION_LIFECYCLE_EXECUTABLE_PRIMITIVES,
    ProposeSupplyChainExecutionTransitionPrimitive,
)
from lightbulb.fable_capability_packs import FABLE_EXECUTABLE_PRIMITIVES
from lightbulb.company_round5_primitives import ROUND5_ENGINE_EXECUTABLE_PRIMITIVES
from lightbulb.productised_assessment_primitives import PRODUCTISED_ASSESSMENT_EXECUTABLE_PRIMITIVES

EXECUTABLE_PRIMITIVE_CATALOG_SCHEMA = "lightbulb.executable_primitive_catalog.v1"
_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def _external_ref(output: Mapping[str, Any]) -> str | None:
    for key in (
        "id",
        "externalId",
        "external_id",
        "messageId",
        "message_id",
        "eventId",
        "event_id",
        "invoiceId",
        "invoice_id",
    ):
        value = output.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return None


def _connector_blocker(result: ConnectorExecutionResult) -> PrimitiveBlocker:
    return PrimitiveBlocker(
        code=result.error_code
        or (
            result.error_kind.value
            if result.error_kind is not None
            else "connector_blocked"
        ),
        message=result.message or "Connector Execution did not complete.",
        retryable=result.retryable,
    )


def _primitive_status(result: ConnectorExecutionResult) -> PrimitiveExecutionStatus:
    return {
        ConnectorExecutionStatus.COMPLETED: PrimitiveExecutionStatus.COMPLETED,
        ConnectorExecutionStatus.PREVIEW: PrimitiveExecutionStatus.PREVIEW,
        ConnectorExecutionStatus.PENDING_APPROVAL: PrimitiveExecutionStatus.PENDING_APPROVAL,
        ConnectorExecutionStatus.BLOCKED: PrimitiveExecutionStatus.BLOCKED,
        ConnectorExecutionStatus.FAILED: PrimitiveExecutionStatus.FAILED,
    }[result.status]


class ReplyClassificationInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reply_text: str = Field(min_length=1, max_length=100_000)
    thread_context: Dict[str, Any] = Field(default_factory=dict)
    taxonomy: list[str] = Field(default_factory=list, max_length=100)
    confidence_threshold: float = Field(default=0.75, ge=0, le=1)
    channel: str = Field(default="email", min_length=1, max_length=40)


class ReplyClassificationOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    intent: str
    confidence: float = Field(ge=0, le=1)
    route_event: str
    needs_human_review: bool
    evidence_labels: list[str]
    channel: str


class ClassifyReplyPrimitive(
    BusinessProcessPrimitive[ReplyClassificationInput, ReplyClassificationOutput]
):
    primitive_ref = "communication.classify_reply"
    version = "1.0.0"
    title = "Classify inbound reply"
    description = "Classify normalized replies without retaining raw text in evidence."
    input_model = ReplyClassificationInput
    output_model = ReplyClassificationOutput
    connector_tools = ("gmail.get_thread",)
    risk_level = "low"
    approval_required = False
    example_inputs = {"reply_text": "Can we schedule a call next week?"}

    _RULES: tuple[tuple[str, tuple[str, ...], float, str, tuple[str, ...]], ...] = (
        (
            "legal_or_security",
            (
                "lawyer",
                "legal action",
                "sue",
                "breach",
                "security incident",
                "data leak",
            ),
            0.98,
            "reply.needs_human_review",
            ("sensitive_content", "human_review_required"),
        ),
        (
            "payment_dispute",
            ("chargeback", "unauthorized charge", "payment dispute", "refund dispute"),
            0.97,
            "reply.needs_human_review",
            ("payment_dispute", "human_review_required"),
        ),
        (
            "unsubscribe",
            ("unsubscribe", "remove me", "opt out", "do not contact", "stop emailing"),
            0.99,
            "unsubscribe.requested",
            ("explicit_opt_out",),
        ),
        (
            "meeting_request",
            (
                "schedule a call",
                "book a call",
                "meet next",
                "set up a meeting",
                "calendar invite",
                "availability",
            ),
            0.92,
            "meeting.requested",
            ("meeting_language",),
        ),
        ("negative", ("not interested", "no thanks", "decline", "not a fit"), 0.90,
         "crm.intent_detected", ("negative_language",)),
        ("wrong_person", ("wrong person", "not my responsibility", "wrong department"), 0.85,
         "reply.needs_human_review", ("recipient_routing",)),
        ("not_now", ("not now", "contact me later", "next quarter", "reach out later"), 0.80,
         "reply.needs_human_review", ("deferred_interest",)),
        ("objection", ("too expensive", "already use", "already have a provider"), 0.80,
         "reply.needs_human_review", ("objection_language",)),
        (
            "positive_interest",
            ("interested", "sounds good", "move forward", "next steps", "tell me more"),
            0.86,
            "crm.intent_detected",
            ("positive_language",),
        ),
    )

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: ReplyClassificationInput,
    ) -> PrimitiveExecutionResult[ReplyClassificationOutput]:
        normalized = " ".join(inputs.reply_text.lower().split())
        intent = "general_reply"
        confidence = 0.55
        route_event = "email.reply_classified"
        labels = ["no_high_confidence_rule"]
        for candidate, phrases, score, event, evidence_labels in self._RULES:
            if any(phrase in normalized for phrase in phrases):
                intent = candidate
                confidence = score
                route_event = event
                labels = list(evidence_labels)
                break

        taxonomy = {label.strip().lower() for label in inputs.taxonomy if label.strip()}
        taxonomy_mismatch = bool(taxonomy and intent not in taxonomy)
        sensitive = intent in {"legal_or_security", "payment_dispute"}
        needs_review = (
            sensitive or route_event == "reply.needs_human_review"
            or taxonomy_mismatch or confidence < inputs.confidence_threshold
        )
        if taxonomy_mismatch:
            labels.append("tenant_taxonomy_mismatch")
        if confidence < inputs.confidence_threshold:
            labels.append("below_confidence_threshold")
        if needs_review:
            route_event = "reply.needs_human_review"

        output = ReplyClassificationOutput(
            intent=intent,
            confidence=confidence,
            route_event=route_event,
            needs_human_review=needs_review,
            evidence_labels=labels,
            channel=inputs.channel,
        )
        event = PrimitiveEvent(
            type=route_event,
            payload={
                "intent": intent,
                "confidence": confidence,
                "needs_human_review": needs_review,
                "channel": inputs.channel,
            },
        )
        return PrimitiveExecutionResult[ReplyClassificationOutput](
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                "Reply classified and routed to human review."
                if needs_review
                else f"Reply classified as {intent}."
            ),
            output=output,
            events=[event],
            evidence=[
                PrimitiveEvidence(
                    kind="classification",
                    summary="Classification used normalized text and emitted no raw reply content.",
                    labels=labels,
                )
            ],
        )


class WriteEmailInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    to: list[str] = Field(default_factory=list, max_length=100)
    subject: str = Field(default="", max_length=998)
    body: str = Field(default="", max_length=500_000)
    intent: str = Field(default="", max_length=120)
    tone: str = Field(default="professional", max_length=80)
    send: bool = False
    provider: Literal["gmail", "microsoft", "notifications", "ses"] = "gmail"
    thread_id: str | None = Field(default=None, min_length=1, max_length=512)
    parent_message_id: str | None = Field(default=None, min_length=3, max_length=998)

    @field_validator("to", mode="before")
    @classmethod
    def _normalize_recipients(cls, value: Any) -> list[str]:
        if isinstance(value, str):
            return [part.strip() for part in value.split(",") if part.strip()]
        return list(value or [])

    @field_validator("to")
    @classmethod
    def _validate_recipients(cls, value: list[str]) -> list[str]:
        invalid = [address for address in value if not _EMAIL_RE.fullmatch(address)]
        if invalid:
            raise ValueError("recipient addresses must be valid email addresses")
        return value

    @model_validator(mode="after")
    def _requires_draft_material(self) -> "WriteEmailInput":
        if not self.body.strip() and not self.intent.strip():
            raise ValueError("body or intent is required")
        if self.send and not self.to:
            raise ValueError("to is required when send is true")
        if self.send and len(self.to) != 1:
            raise ValueError(
                "governed email dispatch requires exactly one recipient per action"
            )
        if self.thread_id is not None:
            clean_thread_id = self.thread_id.strip()
            if not clean_thread_id:
                raise ValueError("thread_id must not be blank")
            object.__setattr__(self, "thread_id", clean_thread_id)
        if self.parent_message_id is not None:
            clean_parent = self.parent_message_id.strip()
            if (
                clean_parent != self.parent_message_id
                or not clean_parent.startswith("<")
                or not clean_parent.endswith(">")
                or "@" not in clean_parent[1:-1]
                or any(character.isspace() for character in clean_parent)
            ):
                raise ValueError(
                    "parent_message_id must be one canonical RFC Message-ID"
                )
            object.__setattr__(self, "parent_message_id", clean_parent)
        if (self.thread_id is None) != (self.parent_message_id is None):
            raise ValueError(
                "thread_id and parent_message_id must be supplied together"
            )
        if self.thread_id is not None and self.provider != "gmail":
            raise ValueError(
                "threaded communication.write_email currently supports Gmail only"
            )
        return self


class WriteEmailOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    recipients: list[str]
    subject: str
    body: str
    tone: str
    provider: str
    state: Literal["draft", "preview", "pending_approval", "sent", "blocked", "failed"]
    message_ref: str | None = None


class WriteEmailPrimitive(BusinessProcessPrimitive[WriteEmailInput, WriteEmailOutput]):
    primitive_ref = "communication.write_email"
    version = "1.2.0"
    title = "Write email"
    description = (
        "Create a typed draft and send only through governed Connector Execution."
    )
    input_model = WriteEmailInput
    output_model = WriteEmailOutput
    connector_tools = (
        "gmail.send_email",
        "microsoft.send_email",
        "notifications.send_email",
        "ses.send_email",
    )
    risk_level = "high"
    approval_required = True
    example_inputs = {
        "to": ["customer@example.test"],
        "subject": "Project update",
        "body": "The requested update is ready.",
        "send": False,
    }

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: WriteEmailInput,
    ) -> PrimitiveExecutionResult[WriteEmailOutput]:
        subject = (
            inputs.subject.strip() or inputs.intent.replace("_", " ").strip().title()
        )
        body = inputs.body.strip()
        if not body:
            body = f"Hello,\n\n{inputs.intent.replace('_', ' ').strip().capitalize()}.\n\nBest,"
        draft = WriteEmailOutput(
            recipients=inputs.to,
            subject=subject,
            body=body,
            tone=inputs.tone,
            provider=inputs.provider,
            state="draft",
        )
        if not inputs.send:
            return PrimitiveExecutionResult[WriteEmailOutput](
                status=PrimitiveExecutionStatus.COMPLETED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary="Email draft created; no connector write requested.",
                output=draft,
                events=[PrimitiveEvent(type="email.draft_created")],
                evidence=[
                    PrimitiveEvidence(
                        kind="draft", summary="Email draft prepared in the SDK runtime."
                    )
                ],
            )

        tool = resolve_connector_tool(self.primitive_ref, inputs.provider)
        connector_result = context.connectors.execute(
            context.connector_request(
                primitive_ref=self.primitive_ref,
                tool=tool,
                arguments={
                    "to": inputs.to[0],
                    "subject": subject,
                    "body": body,
                    **(
                        {
                            "thread_id": inputs.thread_id,
                            "parent_message_id": inputs.parent_message_id,
                        }
                        if inputs.thread_id is not None
                        else {}
                    ),
                },
                effect=ConnectorEffect.WRITE,
                approval_required=True,
            )
        )
        state = {
            ConnectorExecutionStatus.COMPLETED: "sent",
            ConnectorExecutionStatus.PREVIEW: "preview",
            ConnectorExecutionStatus.PENDING_APPROVAL: "pending_approval",
            ConnectorExecutionStatus.BLOCKED: "blocked",
            ConnectorExecutionStatus.FAILED: "failed",
        }[connector_result.status]
        event_type = {
            "sent": "email.sent",
            "preview": "email.draft_created",
            "pending_approval": "email.pending_approval",
            "blocked": "email.blocked",
            "failed": "email.failed",
            "draft": "email.draft_created",
        }[state]
        output = draft.model_copy(
            update={
                "state": state,
                "message_ref": _external_ref(connector_result.output),
            }
        )
        blockers = []
        if connector_result.status in {
            ConnectorExecutionStatus.BLOCKED,
            ConnectorExecutionStatus.FAILED,
        }:
            blockers.append(_connector_blocker(connector_result))
        return PrimitiveExecutionResult[WriteEmailOutput](
            status=_primitive_status(connector_result),
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=connector_result.message or f"Email state: {state}.",
            output=output,
            events=[
                PrimitiveEvent(type=event_type, payload={"provider": inputs.provider})
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="connector_execution", summary=f"Email routed through {tool}."
                )
            ],
            blockers=blockers,
            approval_ref=connector_result.approval_ref,
            connector_tool=tool,
            retryable=connector_result.retryable,
        )


class InvoiceLineItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    description: str = Field(min_length=1, max_length=500)
    quantity: Decimal = Field(default=Decimal("1"), gt=0)
    unit_amount: Decimal = Field(gt=0)
    account_code: str | None = Field(default=None, max_length=80)


class CreateInvoiceInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: Literal["xero", "quickbooks", "stripe", "square"] = "xero"
    customer_name: str = Field(default="", max_length=300)
    customer_id: str = Field(default="", max_length=200)
    line_items: list[InvoiceLineItem] = Field(default_factory=list, max_length=500)
    amount: Decimal | None = Field(default=None, gt=0)
    currency: str = Field(default="USD", min_length=3, max_length=3)
    due_date: str = Field(default="", max_length=20)
    reference: str = Field(default="", max_length=200)
    memo: str = Field(default="", max_length=5000)
    commit: bool = False

    @field_validator("currency")
    @classmethod
    def _normalize_currency(cls, value: str) -> str:
        clean = value.strip().upper()
        if not clean.isalpha():
            raise ValueError("currency must be a three-letter code")
        return clean

    @model_validator(mode="after")
    def _requires_customer_and_amount(self) -> "CreateInvoiceInput":
        if not self.customer_name.strip() and not self.customer_id.strip():
            raise ValueError("customer_name or customer_id is required")
        if not self.line_items and self.amount is None:
            raise ValueError("line_items or amount is required")
        return self


class CreateInvoiceOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: str
    customer_name: str
    customer_id: str
    currency: str
    subtotal: Decimal
    total: Decimal
    state: Literal[
        "draft", "preview", "pending_approval", "created", "blocked", "failed"
    ]
    invoice_ref: str | None = None


class CreateInvoicePrimitive(
    BusinessProcessPrimitive[CreateInvoiceInput, CreateInvoiceOutput]
):
    primitive_ref = "finance.create_invoice"
    version = "1.0.0"
    title = "Create invoice"
    description = "Validate and total an invoice before any governed provider write."
    input_model = CreateInvoiceInput
    output_model = CreateInvoiceOutput
    connector_tools = (
        "xero.create_invoice",
        "quickbooks.create_invoice",
        "stripe.create_invoice",
        "square.create_invoice",
    )
    risk_level = "high"
    approval_required = True
    example_inputs = {
        "customer_name": "Example Customer",
        "amount": "100.00",
        "currency": "USD",
        "commit": False,
    }

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: CreateInvoiceInput,
    ) -> PrimitiveExecutionResult[CreateInvoiceOutput]:
        subtotal = inputs.amount or sum(
            (item.quantity * item.unit_amount for item in inputs.line_items),
            Decimal("0"),
        )
        output = CreateInvoiceOutput(
            provider=inputs.provider,
            customer_name=inputs.customer_name,
            customer_id=inputs.customer_id,
            currency=inputs.currency,
            subtotal=subtotal,
            total=subtotal,
            state="draft",
        )
        if not inputs.commit:
            return PrimitiveExecutionResult[CreateInvoiceOutput](
                status=PrimitiveExecutionStatus.COMPLETED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary="Validated invoice draft created; no provider write requested.",
                output=output,
                events=[PrimitiveEvent(type="invoice.draft_created")],
                evidence=[
                    PrimitiveEvidence(
                        kind="invoice_totals",
                        summary="Invoice totals were calculated locally.",
                    )
                ],
            )

        tool = resolve_connector_tool(self.primitive_ref, inputs.provider)
        connector_result = context.connectors.execute(
            context.connector_request(
                primitive_ref=self.primitive_ref,
                tool=tool,
                arguments={
                    "customer_name": inputs.customer_name,
                    "customer_id": inputs.customer_id,
                    "line_items": [
                        item.model_dump(mode="json") for item in inputs.line_items
                    ],
                    "amount": str(subtotal),
                    "currency": inputs.currency,
                    "due_date": inputs.due_date,
                    "reference": inputs.reference,
                    "memo": inputs.memo,
                },
                effect=ConnectorEffect.WRITE,
                approval_required=True,
            )
        )
        state = {
            ConnectorExecutionStatus.COMPLETED: "created",
            ConnectorExecutionStatus.PREVIEW: "preview",
            ConnectorExecutionStatus.PENDING_APPROVAL: "pending_approval",
            ConnectorExecutionStatus.BLOCKED: "blocked",
            ConnectorExecutionStatus.FAILED: "failed",
        }[connector_result.status]
        event_type = {
            "created": "invoice.created",
            "preview": "invoice.draft_created",
            "pending_approval": "invoice.pending_approval",
            "blocked": "invoice.blocked",
            "failed": "invoice.failed",
            "draft": "invoice.draft_created",
        }[state]
        final_output = output.model_copy(
            update={
                "state": state,
                "invoice_ref": _external_ref(connector_result.output),
            }
        )
        blockers = []
        if connector_result.status in {
            ConnectorExecutionStatus.BLOCKED,
            ConnectorExecutionStatus.FAILED,
        }:
            blockers.append(_connector_blocker(connector_result))
        return PrimitiveExecutionResult[CreateInvoiceOutput](
            status=_primitive_status(connector_result),
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=connector_result.message or f"Invoice state: {state}.",
            output=final_output,
            events=[
                PrimitiveEvent(type=event_type, payload={"provider": inputs.provider})
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="connector_execution",
                    summary=f"Invoice routed through {tool}.",
                )
            ],
            blockers=blockers,
            approval_ref=connector_result.approval_ref,
            connector_tool=tool,
            retryable=connector_result.retryable,
        )


class ScheduleMeetingInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attendees: list[str] = Field(min_length=1, max_length=100)
    title: str = Field(min_length=1, max_length=500)
    time_window: str = Field(default="", max_length=500)
    start_time: str = Field(default="", max_length=80)
    duration_minutes: int = Field(default=30, ge=5, le=1440)
    agenda: str = Field(default="", max_length=20_000)
    provider: Literal["calendar", "microsoft"] = "calendar"
    create_invite: bool = False

    @field_validator("attendees", mode="before")
    @classmethod
    def _normalize_attendees(cls, value: Any) -> list[str]:
        if isinstance(value, str):
            return [part.strip() for part in value.split(",") if part.strip()]
        return list(value or [])

    @field_validator("attendees")
    @classmethod
    def _validate_attendees(cls, value: list[str]) -> list[str]:
        if any(not _EMAIL_RE.fullmatch(address) for address in value):
            raise ValueError("attendees must contain valid email addresses")
        return value

    @model_validator(mode="after")
    def _invite_requires_start_time(self) -> "ScheduleMeetingInput":
        if self.create_invite and not self.start_time.strip():
            raise ValueError("start_time is required when create_invite is true")
        if self.create_invite:
            start = datetime.fromisoformat(self.start_time.replace("Z", "+00:00"))
            if start.tzinfo is None or start.utcoffset() is None:
                raise ValueError("start_time requires an explicit timezone")
            start + timedelta(minutes=self.duration_minutes)
        return self


class ScheduleMeetingOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attendees: list[str]
    title: str
    proposed_slots: list[str]
    duration_minutes: int
    provider: str
    state: Literal[
        "proposed", "preview", "pending_approval", "scheduled", "blocked", "failed"
    ]
    event_ref: str | None = None


class ScheduleMeetingPrimitive(
    BusinessProcessPrimitive[ScheduleMeetingInput, ScheduleMeetingOutput]
):
    primitive_ref = "calendar.schedule_meeting"
    version = "1.0.0"
    title = "Schedule meeting"
    description = (
        "Propose a meeting first and create invites only through governed writes."
    )
    input_model = ScheduleMeetingInput
    output_model = ScheduleMeetingOutput
    connector_tools = (
        "calendar.get_availability",
        "calendar.create_event",
        "microsoft.create_event",
    )
    risk_level = "medium"
    approval_required = True
    example_inputs = {
        "attendees": ["customer@example.test"],
        "title": "Project follow-up",
        "time_window": "next week",
        "create_invite": False,
    }

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: ScheduleMeetingInput,
    ) -> PrimitiveExecutionResult[ScheduleMeetingOutput]:
        proposed = [slot for slot in (inputs.start_time, inputs.time_window) if slot]
        output = ScheduleMeetingOutput(
            attendees=inputs.attendees,
            title=inputs.title,
            proposed_slots=proposed,
            duration_minutes=inputs.duration_minutes,
            provider=inputs.provider,
            state="proposed",
        )
        if not inputs.create_invite:
            return PrimitiveExecutionResult[ScheduleMeetingOutput](
                status=PrimitiveExecutionStatus.COMPLETED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary="Meeting proposal created; no calendar write requested.",
                output=output,
                events=[PrimitiveEvent(type="meeting.slots_proposed")],
                evidence=[
                    PrimitiveEvidence(
                        kind="meeting_proposal",
                        summary="Meeting details were validated locally.",
                    )
                ],
            )

        tool = resolve_connector_tool(self.primitive_ref, inputs.provider)
        connector_result = context.connectors.execute(
            context.connector_request(
                primitive_ref=self.primitive_ref,
                tool=tool,
                arguments={
                    "attendees": [{"email": address} for address in inputs.attendees],
                    "title": inputs.title,
                    "start": inputs.start_time,
                    "end": (datetime.fromisoformat(inputs.start_time.replace("Z", "+00:00"))
                            + timedelta(minutes=inputs.duration_minutes)).isoformat(),
                    "description": inputs.agenda,
                },
                effect=ConnectorEffect.WRITE,
                approval_required=True,
            )
        )
        state = {
            ConnectorExecutionStatus.COMPLETED: "scheduled",
            ConnectorExecutionStatus.PREVIEW: "preview",
            ConnectorExecutionStatus.PENDING_APPROVAL: "pending_approval",
            ConnectorExecutionStatus.BLOCKED: "blocked",
            ConnectorExecutionStatus.FAILED: "failed",
        }[connector_result.status]
        event_type = {
            "scheduled": "meeting.invite_sent",
            "preview": "meeting.slots_proposed",
            "pending_approval": "meeting.invite_pending_approval",
            "blocked": "meeting.blocked",
            "failed": "meeting.failed",
            "proposed": "meeting.slots_proposed",
        }[state]
        final_output = output.model_copy(
            update={"state": state, "event_ref": _external_ref(connector_result.output)}
        )
        blockers = []
        if connector_result.status in {
            ConnectorExecutionStatus.BLOCKED,
            ConnectorExecutionStatus.FAILED,
        }:
            blockers.append(_connector_blocker(connector_result))
        return PrimitiveExecutionResult[ScheduleMeetingOutput](
            status=_primitive_status(connector_result),
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=connector_result.message or f"Meeting state: {state}.",
            output=final_output,
            events=[
                PrimitiveEvent(type=event_type, payload={"provider": inputs.provider})
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="connector_execution",
                    summary=f"Meeting routed through {tool}.",
                )
            ],
            blockers=blockers,
            approval_ref=connector_result.approval_ref,
            connector_tool=tool,
            retryable=connector_result.retryable,
        )


BUILTIN_EXECUTABLE_PRIMITIVES: tuple[BusinessProcessPrimitive[Any, Any], ...] = (
    PlanCrmConversationTurnPrimitive(),
    ClassifyReplyPrimitive(),
    WriteEmailPrimitive(),
    CreateInvoicePrimitive(),
    IngestSupplierInvoicePrimitive(),
    DraftContractPrimitive(),
    ReviewContractPrimitive(),
    ScheduleMeetingPrimitive(),
    QualifyLeadPrimitive(),
    OnboardEmployeePrimitive(),
    CollectPaymentPrimitive(),
    RequestDecisionPrimitive(),
    GenerateBusinessArtifactPrimitive(),
    CreateWorkPacketPrimitive(),
    PlanOptimizationSweepPrimitive(),
    PlanShopifyStorefrontPrimitive(),
    PlanOmnichannelProductLaunchPrimitive(),
    ResolveCrossChannelIdentityPrimitive(),
    EvaluateJurisdictionChannelPolicyPrimitive(),
    PlanGovernedVoiceCallPrimitive(),
    NormalizeProviderOutcomePrimitive(),
    *PROFIT_EXECUTABLE_PRIMITIVES,
    *INVOICE_ISSUANCE_EXECUTABLE_PRIMITIVES,
    *CASH_COLLECTION_EXECUTABLE_PRIMITIVES,
    *FINANCE_ACCOUNTING_EXECUTABLE_PRIMITIVES,
    *FINANCE_ADJUSTING_ENTRIES_PACKAGE_EXECUTABLE_PRIMITIVES,
    *FINANCE_ADJUSTING_ENTRIES_TRANSITION_EXECUTABLE_PRIMITIVES,
    *FINANCE_CONSOLIDATION_PACKAGE_EXECUTABLE_PRIMITIVES,
    *FINANCE_CONSOLIDATION_TRANSITION_EXECUTABLE_PRIMITIVES,
    *FINANCE_CLOSE_APPROVAL_PACKAGE_EXECUTABLE_PRIMITIVES,
    *FINANCE_CLOSE_APPROVAL_TRANSITION_EXECUTABLE_PRIMITIVES,
    *FINANCE_CLOSE_PERIOD_PACKAGE_EXECUTABLE_PRIMITIVES,
    *FINANCE_CLOSE_PERIOD_TRANSITION_EXECUTABLE_PRIMITIVES,
    *FINANCE_CLOSE_AUDIT_PACKET_EXECUTABLE_PRIMITIVES,
    *FINANCE_CLOSE_SOURCE_TRANSACTION_EXECUTABLE_PRIMITIVES,
    *FINANCE_XERO_CLOSE_SOURCE_TRANSACTION_EXECUTABLE_PRIMITIVES,
    *FINANCE_PROVIDER_PERIOD_STATUS_EXECUTABLE_PRIMITIVES,
    *FINANCE_GENERAL_LEDGER_EXECUTABLE_PRIMITIVES,
    *FINANCE_JOURNAL_LIFECYCLE_EXECUTABLE_PRIMITIVES,
    *FINANCE_LEDGER_MATERIALIZATION_EXECUTABLE_PRIMITIVES,
    *FINANCE_RECONCILIATION_PACKAGE_EXECUTABLE_PRIMITIVES,
    *FINANCE_RECONCILIATION_TRANSITION_EXECUTABLE_PRIMITIVES,
    *FINANCE_SETTLEMENT_RECONCILIATION_EXECUTABLE_PRIMITIVES,
    *FINANCE_STRIPE_SETTLEMENT_EXECUTABLE_PRIMITIVES,
    *FINANCE_SUBLEDGER_LOCK_PACKAGE_EXECUTABLE_PRIMITIVES,
    *FINANCE_SUBLEDGER_LOCK_TRANSITION_EXECUTABLE_PRIMITIVES,
    *FINANCE_OPERATING_EXECUTABLE_PRIMITIVES,
    *FINANCE_CLOSE_LIFECYCLE_EXECUTABLE_PRIMITIVES,
    *FINANCE_CLOSE_RECONCILIATION_READINESS_EXECUTABLE_PRIMITIVES,
    *FINANCE_CLOSE_EVIDENCE_BUNDLE_EXECUTABLE_PRIMITIVES,
    *FINANCE_CLOSE_WORKSPACE_EXECUTABLE_PRIMITIVES,
    *PERIOD_RECONCILIATION_EXECUTABLE_PRIMITIVES,
    EvaluatePurchaseToPayControlsPrimitive(),
    *PROCURE_TO_PAY_LIFECYCLE_EXECUTABLE_PRIMITIVES,
    *VENDOR_ONBOARDING_LIFECYCLE_EXECUTABLE_PRIMITIVES,
    *SUPPLY_CHAIN_EXECUTABLE_PRIMITIVES,
    *SUPPLY_CHAIN_EXECUTION_LIFECYCLE_EXECUTABLE_PRIMITIVES,
    VerifyBomInventoryTraceabilityPrimitive(),
    *MANUFACTURING_EXECUTION_LIFECYCLE_EXECUTABLE_PRIMITIVES,
    *FIELD_QUALITY_EXECUTABLE_PRIMITIVES,
    *MAINTENANCE_WORK_ORDER_LIFECYCLE_EXECUTABLE_PRIMITIVES,
    EvaluateQuoteOrderContractControlsPrimitive(),
    *COMMERCIAL_OPERATIONS_LIFECYCLE_EXECUTABLE_PRIMITIVES,
    EvaluateCaseResolutionControlsPrimitive(),
    *CUSTOMER_SERVICE_LIFECYCLE_EXECUTABLE_PRIMITIVES,
    *SERVICE_ASSET_REMEDY_LIFECYCLE_EXECUTABLE_PRIMITIVES,
    EvaluateWorkerLifecycleControlsPrimitive(),
    *PEOPLE_OPERATIONS_LIFECYCLE_EXECUTABLE_PRIMITIVES,
    EvaluateReleaseGovernanceControlsPrimitive(),
    *PRODUCT_ENGINEERING_LIFECYCLE_EXECUTABLE_PRIMITIVES,
    *VERIFIED_IMPROVEMENT_EXECUTABLE_PRIMITIVES,
    EvaluateRegulatedControlsPrimitive(),
    *COMPLIANCE_RISK_LIFECYCLE_EXECUTABLE_PRIMITIVES,
    *OPERATIONAL_READINESS_EXECUTABLE_PRIMITIVES,
    *PRODUCTION_CONNECTOR_CONFORMANCE_EXECUTABLE_PRIMITIVES,
    *PRODUCTION_CONNECTOR_READ_CONFORMANCE_EXECUTABLE_PRIMITIVES,
    BuildGrowthFunnelSnapshotPrimitive(),
    DiagnoseGrowthPrimitive(),
    PlanContentCalendarPrimitive(),
    PlanAudienceGrowthPrimitive(),
    BuildUnitEconomicsPrimitive(),
    ReviewProfitPrimitive(),
    PlanPriceMovePrimitive(),
    CompileGrowthAgendaPrimitive(),
    CompareFunnelSnapshotsPrimitive(),
    BuildCustomerValuePrimitive(),
    ReviewCustomerValuePrimitive(),
    AssessObjectivePrimitive(),
    PreflightActionPrimitive(),
    CompileBriefingPrimitive(),
    BuildRunwaySnapshotPrimitive(),
    DeriveBudgetEnvelopePrimitive(),
    AssessRunwayPrimitive(),
    BuildCashFlowForecastPrimitive(),
    GateObjectiveFundingPrimitive(),
    MatchGrantsPrimitive(),
    SearchGrantsPrimitive(),
    RunAccountantCyclePrimitive(),
    EstimateTaxSetAsidePrimitive(),
    AssessDefaultAlivePrimitive(),
    ComputeBurnMultiplePrimitive(),
    AssessReceivablesPrimitive(),
    AssessPayablesPrimitive(),
    *FABLE_EXECUTABLE_PRIMITIVES,
    *ROUND5_ENGINE_EXECUTABLE_PRIMITIVES,
    *PRODUCTISED_ASSESSMENT_EXECUTABLE_PRIMITIVES,
)


def default_primitive_registry(
    extra_primitives: Iterable[BusinessProcessPrimitive[Any, Any]] = (),
) -> PrimitiveRegistry:
    registry = PrimitiveRegistry(BUILTIN_EXECUTABLE_PRIMITIVES)
    for primitive in extra_primitives:
        registry.register(primitive)
    return registry


def executable_business_primitive_catalog(
    *,
    query: str = "",
    include_schemas: bool = True,
    offset: int = 0,
    limit: int | None = None,
) -> Dict[str, Any]:
    """Return a filterable, optionally paged executable primitive catalog.

    Direct SDK callers retain the original full-schema default. MCP discovery
    uses bounded summary pages and asks for one filtered schema only when it is
    ready to invoke a primitive.
    """

    if offset < 0:
        raise ValueError("offset must be non-negative")
    if limit is not None and (limit < 1 or limit > 100):
        raise ValueError("limit must be between 1 and 100")
    if include_schemas and limit is not None and limit > 10:
        raise ValueError("full-schema pages are limited to 10 primitives")
    clean_query = query.strip().lower()
    implementations = default_primitive_registry().catalog()
    if clean_query:
        exact_matches = [
            item
            for item in implementations
            if str(item.get("primitive_ref") or "").lower() == clean_query
        ]
        implementations = exact_matches or [
            item
            for item in implementations
            if clean_query
            in " ".join(
                [
                    str(item.get("primitive_ref") or ""),
                    str(item.get("title") or ""),
                    str(item.get("description") or ""),
                    " ".join(item.get("connector_tools") or []),
                    " ".join(item.get("capability_hints") or []),
                ]
            ).lower()
        ]
    total_count = len(implementations)
    end = None if limit is None else offset + limit
    implementations = implementations[offset:end]
    if not include_schemas:
        implementations = [
            {
                "primitive_ref": item["primitive_ref"],
                "version": item["version"],
                "title": item["title"],
                "description": item["description"],
                "risk_level": item["risk_level"],
                "approval_required": item["approval_required"],
                "connector_tools": item["connector_tools"],
                "capability_hints": item.get("capability_hints", []),
                "required_inputs": list(item["input_schema"].get("required") or []),
                "mcp_annotations": item["mcp_annotations"],
            }
            for item in implementations
        ]
    next_offset = offset + len(implementations)
    return {
        "schema": EXECUTABLE_PRIMITIVE_CATALOG_SCHEMA,
        "count": len(implementations),
        "total_count": total_count,
        "offset": offset,
        "has_more": next_offset < total_count,
        "next_offset": next_offset if next_offset < total_count else None,
        "include_schemas": include_schemas,
        "implementations": implementations,
    }


__all__ = [
    "BUILTIN_EXECUTABLE_PRIMITIVES",
    "EXECUTABLE_PRIMITIVE_CATALOG_SCHEMA",
    "EvaluateJurisdictionChannelPolicyPrimitive",
    "NormalizeProviderOutcomePrimitive",
    "PlanGovernedVoiceCallPrimitive",
    "ResolveCrossChannelIdentityPrimitive",
    "EvaluateJournalEntryControlsPrimitive",
    "EvaluatePeriodCloseReadinessPrimitive",
    "EvaluateCloseReconciliationReadinessPrimitive",
    "ProposePeriodCloseTransitionPrimitive",
    "PrepareAdjustingEntriesPackagePrimitive",
    "PrepareAdjustingEntriesTransitionCommandPrimitive",
    "PrepareConsolidationPackagePrimitive",
    "PrepareConsolidationTransitionCommandPrimitive",
    "PrepareCloseWorkspacePrimitive",
    "PrepareCloseEvidenceBundlePrimitive",
    "PrepareCloseApprovalPackagePrimitive",
    "PrepareCloseApprovalTransitionCommandPrimitive",
    "PrepareClosePeriodPackagePrimitive",
    "PrepareClosePeriodTransitionCommandPrimitive",
    "BuildFinanceCloseAuditPacketPrimitive",
    "DiscoverCloseSourceTransactionsPrimitive",
    "DiscoverProviderPeriodStatusPrimitive",
    "DiscoverGeneralLedgerActivityPrimitive",
    "DiscoverLedgerAccountsPrimitive",
    "DiscoverStripeSettlementMovementsPrimitive",
    "DiscoverTrialBalancePrimitive",
    "MaterializeLedgerSnapshotPrimitive",
    "PostJournalEntryPrimitive",
    "PrepareJournalEntryPrimitive",
    "PrepareReconciliationPackagePrimitive",
    "PrepareReconciliationTransitionCommandPrimitive",
    "PrepareSubledgerLockPackagePrimitive",
    "PrepareSubledgerLockTransitionCommandPrimitive",
    "ReconcileJournalPostPrimitive",
    "ReconcileStripeSettlementsPrimitive",
    "EvaluatePurchaseToPayControlsPrimitive",
    "ProposeProcureToPayTransitionPrimitive",
    "ProposeVendorOnboardingTransitionPrimitive",
    "ProposeSupplyChainExecutionTransitionPrimitive",
    "EvaluateFinanceOperatingControlsPrimitive",
    "EvaluateFieldQualityControlsPrimitive",
    "EvaluateOperationalReadinessPrimitive",
    "EvaluateProductionConnectorConformancePrimitive",
    "EvaluateProductionConnectorReadConformancePrimitive",
    "EvaluateQuoteOrderContractControlsPrimitive",
    "ProposeCommercialOperationsTransitionPrimitive",
    "EvaluateCaseResolutionControlsPrimitive",
    "ProposeServiceAssetRemedyTransitionPrimitive",
    "IntakeAndClassifyServiceCasePrimitive",
    "ProposeServiceRemedyAuthorizationPrimitive",
    "RouteAndEscalateServiceCasePrimitive",
    "SubmitServiceResolutionPrimitive",
    "VerifyServiceResolutionPrimitive",
    "EvaluateWorkerLifecycleControlsPrimitive",
    "ProposePeopleOperationsTransitionPrimitive",
    "EvaluateReleaseGovernanceControlsPrimitive",
    "ProposeProductEngineeringTransitionPrimitive",
    "EvaluateRegulatedControlsPrimitive",
    "ProposeComplianceRiskTransitionPrimitive",
    "VerifyBomInventoryTraceabilityPrimitive",
    "AdvanceManufacturingExecutionLifecyclePrimitive",
    "ProposeMaintenanceWorkOrderTransitionPrimitive",
    "CASH_COLLECTION_EXECUTABLE_PRIMITIVES",
    "COMMERCIAL_OPERATIONS_LIFECYCLE_EXECUTABLE_PRIMITIVES",
    "FIELD_QUALITY_EXECUTABLE_PRIMITIVES",
    "FINANCE_ACCOUNTING_EXECUTABLE_PRIMITIVES",
    "FINANCE_ADJUSTING_ENTRIES_PACKAGE_EXECUTABLE_PRIMITIVES",
    "FINANCE_ADJUSTING_ENTRIES_TRANSITION_EXECUTABLE_PRIMITIVES",
    "FINANCE_CONSOLIDATION_PACKAGE_EXECUTABLE_PRIMITIVES",
    "FINANCE_CONSOLIDATION_TRANSITION_EXECUTABLE_PRIMITIVES",
    "FINANCE_CLOSE_LIFECYCLE_EXECUTABLE_PRIMITIVES",
    "FINANCE_CLOSE_APPROVAL_PACKAGE_EXECUTABLE_PRIMITIVES",
    "FINANCE_CLOSE_APPROVAL_TRANSITION_EXECUTABLE_PRIMITIVES",
    "FINANCE_CLOSE_PERIOD_PACKAGE_EXECUTABLE_PRIMITIVES",
    "FINANCE_CLOSE_PERIOD_TRANSITION_EXECUTABLE_PRIMITIVES",
    "FINANCE_CLOSE_AUDIT_PACKET_EXECUTABLE_PRIMITIVES",
    "FINANCE_CLOSE_RECONCILIATION_READINESS_EXECUTABLE_PRIMITIVES",
    "FINANCE_CLOSE_EVIDENCE_BUNDLE_EXECUTABLE_PRIMITIVES",
    "FINANCE_CLOSE_SOURCE_TRANSACTION_EXECUTABLE_PRIMITIVES",
    "FINANCE_XERO_CLOSE_SOURCE_TRANSACTION_EXECUTABLE_PRIMITIVES",
    "FINANCE_PROVIDER_PERIOD_STATUS_EXECUTABLE_PRIMITIVES",
    "FINANCE_CLOSE_WORKSPACE_EXECUTABLE_PRIMITIVES",
    "FINANCE_GENERAL_LEDGER_EXECUTABLE_PRIMITIVES",
    "FINANCE_JOURNAL_LIFECYCLE_EXECUTABLE_PRIMITIVES",
    "FINANCE_LEDGER_MATERIALIZATION_EXECUTABLE_PRIMITIVES",
    "FINANCE_RECONCILIATION_PACKAGE_EXECUTABLE_PRIMITIVES",
    "FINANCE_RECONCILIATION_TRANSITION_EXECUTABLE_PRIMITIVES",
    "FINANCE_SETTLEMENT_RECONCILIATION_EXECUTABLE_PRIMITIVES",
    "FINANCE_STRIPE_SETTLEMENT_EXECUTABLE_PRIMITIVES",
    "FINANCE_SUBLEDGER_LOCK_PACKAGE_EXECUTABLE_PRIMITIVES",
    "FINANCE_SUBLEDGER_LOCK_TRANSITION_EXECUTABLE_PRIMITIVES",
    "FINANCE_OPERATING_EXECUTABLE_PRIMITIVES",
    "INVOICE_ISSUANCE_EXECUTABLE_PRIMITIVES",
    "CUSTOMER_SERVICE_LIFECYCLE_EXECUTABLE_PRIMITIVES",
    "SERVICE_ASSET_REMEDY_LIFECYCLE_EXECUTABLE_PRIMITIVES",
    "MANUFACTURING_EXECUTION_LIFECYCLE_EXECUTABLE_PRIMITIVES",
    "MAINTENANCE_WORK_ORDER_LIFECYCLE_EXECUTABLE_PRIMITIVES",
    "PEOPLE_OPERATIONS_LIFECYCLE_EXECUTABLE_PRIMITIVES",
    "PRODUCT_ENGINEERING_LIFECYCLE_EXECUTABLE_PRIMITIVES",
    "COMPLIANCE_RISK_LIFECYCLE_EXECUTABLE_PRIMITIVES",
    "OPERATIONAL_READINESS_EXECUTABLE_PRIMITIVES",
    "PERIOD_RECONCILIATION_EXECUTABLE_PRIMITIVES",
    "PRODUCTION_CONNECTOR_CONFORMANCE_EXECUTABLE_PRIMITIVES",
    "PRODUCTION_CONNECTOR_READ_CONFORMANCE_EXECUTABLE_PRIMITIVES",
    "PROCURE_TO_PAY_LIFECYCLE_EXECUTABLE_PRIMITIVES",
    "VENDOR_ONBOARDING_LIFECYCLE_EXECUTABLE_PRIMITIVES",
    "VERIFIED_IMPROVEMENT_EXECUTABLE_PRIMITIVES",
    "SUPPLY_CHAIN_EXECUTABLE_PRIMITIVES",
    "SUPPLY_CHAIN_EXECUTION_LIFECYCLE_EXECUTABLE_PRIMITIVES",
    "AssessObjectivePrimitive",
    "AssessPayablesPrimitive",
    "AssessReceivablesPrimitive",
    "AssessRunwayPrimitive",
    "BuildCashFlowForecastPrimitive",
    "BuildCustomerValuePrimitive",
    "BuildRunwaySnapshotPrimitive",
    "DeriveBudgetEnvelopePrimitive",
    "GateObjectiveFundingPrimitive",
    "MatchGrantsPrimitive",
    "SearchGrantsPrimitive",
    "RunAccountantCyclePrimitive",
    "EstimateTaxSetAsidePrimitive",
    "AssessDefaultAlivePrimitive",
    "ComputeBurnMultiplePrimitive",
    "BuildGrowthFunnelSnapshotPrimitive",
    "BuildUnitEconomicsPrimitive",
    "ClassifyReplyPrimitive",
    "CompareFunnelSnapshotsPrimitive",
    "CompileBriefingPrimitive",
    "CompileGrowthAgendaPrimitive",
    "ReviewCustomerValuePrimitive",
    "DiagnoseGrowthPrimitive",
    "PlanAudienceGrowthPrimitive",
    "PlanContentCalendarPrimitive",
    "PreflightActionPrimitive",
    "PlanPriceMovePrimitive",
    "ReviewProfitPrimitive",
    "CollectPaymentInput",
    "CollectPaymentOutput",
    "CollectPaymentPrimitive",
    "ContractRiskFinding",
    "CreateInvoiceInput",
    "CreateInvoiceOutput",
    "CreateInvoicePrimitive",
    "CreateWorkPacketInput",
    "CreateWorkPacketOutput",
    "CreateWorkPacketPrimitive",
    "DraftContractInput",
    "DraftContractOutput",
    "DraftContractPrimitive",
    "IngestSupplierInvoicePrimitive",
    "InvoiceLineItem",
    "LeadQualificationRules",
    "GenerateBusinessArtifactInput",
    "GenerateBusinessArtifactOutput",
    "GenerateBusinessArtifactPrimitive",
    "OnboardEmployeeInput",
    "OnboardEmployeeOutput",
    "OnboardEmployeePrimitive",
    "OnboardingTask",
    "LearningDataProfile",
    "LearningEventStreamContract",
    "LearningRunPreparationPlan",
    "OptimizationSweepBudgetLedger",
    "OptimizationSweepBudget",
    "OptimizationSweepOutput",
    "OptimizationSweepResourceTotals",
    "OptimizationSweepSafety",
    "OptimizationSweepStage",
    "PlanOptimizationSweepInput",
    "PlanOptimizationSweepPrimitive",
    "PlanOmnichannelProductLaunchPrimitive",
    "PlanCrmConversationTurnPrimitive",
    "PlanShopifyStorefrontPrimitive",
    "PROFIT_EXECUTABLE_PRIMITIVES",
    "ProfitWorkflowPrimitive",
    "QualifyLeadInput",
    "QualifyLeadOutput",
    "QualifyLeadPrimitive",
    "ReplyClassificationInput",
    "ReplyClassificationOutput",
    "RequestDecisionInput",
    "RequestDecisionOutput",
    "RequestDecisionPrimitive",
    "ReviewContractInput",
    "ReviewContractOutput",
    "ReviewContractPrimitive",
    "ScheduleMeetingInput",
    "ScheduleMeetingOutput",
    "ScheduleMeetingPrimitive",
    "SupplierInvoiceInput",
    "SupplierInvoiceOutput",
    "WriteEmailInput",
    "WriteEmailOutput",
    "WriteEmailPrimitive",
    "default_primitive_registry",
    "compile_optimization_sweep",
    "executable_business_primitive_catalog",
]
