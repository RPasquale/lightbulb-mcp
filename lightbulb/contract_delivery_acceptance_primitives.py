"""Executable primitives for contract-bound delivery and independent acceptance.

Five read-only primitives expose ``lightbulb.contract_delivery_acceptance``
behind ``BusinessProcessPrimitive``.  They extend the
``project.work_packet_independent_acceptance`` loop with contract binding and
customer acceptance; none of them creates a project runtime, accepts work,
records customer acceptance, authorizes an invoice, mutates scope, or invokes
a connector.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any, Generic, TypeVar

from pydantic import BaseModel

from lightbulb.commercial_legal_handoff import reconcile_executed_agreement
from lightbulb.commercial_legal_handoff_primitives import (
    ReconcileExecutedAgreementPrimitive as _ReconcileExecutedAgreementPrimitive,
)
from lightbulb.connector_execution import ConnectorEffect
from lightbulb.contract_delivery_acceptance import (
    CONTRACT_DELIVERY_GOLDEN_LOOP,
    CONTRACT_DELIVERY_LOOP_EXTENSION,
    ContractChangeOrderInput,
    ContractChangeOrderProposal,
    ContractDeliverableBindingInput,
    ContractDeliverableBindingResult,
    ContractDeliveryEffectBoundary,
    ContractDeliveryPlanInput,
    ContractDeliveryPlanResult,
    ContractDeliveryScope,
    ContractualDeliveryEvidenceAssessment,
    ContractualDeliveryEvidenceInput,
    CustomerAcceptanceCandidateInput,
    CustomerAcceptanceCandidateResult,
    bind_contract_deliverable_to_work_packet,
    compile_contract_delivery_plan,
    compile_customer_acceptance_candidate,
    evaluate_contractual_delivery_evidence,
    propose_contract_change_order,
)
from lightbulb.contract_obligation_intake import (
    build_contract_obligation_normalization_input,
    route_contract_obligation_register,
)
from lightbulb.contract_obligation_primitives import (
    IntakeContractObligationsFromCustodyPrimitive as _IntakePrimitive,
)
from lightbulb.contract_obligations import normalize_contract_obligation_candidates
from lightbulb.dynamic_workflows import BuilderResult
from lightbulb.primitive_runtime import (
    BusinessProcessPrimitive,
    PrimitiveBlocker,
    PrimitiveEvent,
    PrimitiveEvidence,
    PrimitiveEvidenceRef,
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


InputT = TypeVar("InputT", bound=BaseModel)
OutputT = TypeVar("OutputT", bound=BaseModel)


def _read_operation(operation_ref: str, tool: str) -> PrimitiveOperationSpec:
    return PrimitiveOperationSpec(
        operation_ref=operation_ref,
        tool=tool,
        effect=ConnectorEffect.READ,
        approval_required=False,
        replay_class=PrimitiveOperationReplayClass.SAFE,
        freshness_class=PrimitiveOperationFreshnessClass.CURRENT,
        recovery_policy=PrimitiveOperationRecoveryPolicy.NONE,
    )


DELIVERY_PLAN_OPERATION = _read_operation(
    "contract_delivery_compile_plan", "sdk.project.compile_contract_delivery_plan"
)
DELIVERABLE_BINDING_OPERATION = _read_operation(
    "contract_delivery_bind_work_packet", "sdk.project.bind_contract_deliverable_to_work_packet"
)
DELIVERY_EVIDENCE_OPERATION = _read_operation(
    "contract_delivery_evaluate_evidence", "sdk.project.evaluate_contractual_delivery_evidence"
)
ACCEPTANCE_CANDIDATE_OPERATION = _read_operation(
    "contract_delivery_compile_acceptance", "sdk.project.compile_customer_acceptance_candidate"
)
CHANGE_ORDER_OPERATION = _read_operation(
    "contract_change_order_propose", "sdk.commercial.propose_contract_change_order"
)

_AUTHORITY_BOUNDARY = {
    "project_agent": "plans deliverables, assigns roles, and decides when to bind and submit work",
    "builder": "produces work and retained evidence; can never accept its own work",
    "independent_evaluator_or_customer": "decides acceptance in a fresh context or by verified sign-off",
    "sdk": (
        "binds deliverables to exact agreements and immutable criteria, checks evidence "
        "coverage, and computes the contractually allocated accepted value; never accepts, "
        "never authorizes invoices, never mutates scope"
    ),
    "spring": "records authoritative customer acceptance, authorizes invoice continuation, persists, audits",
    "workflow": "observes builder results, verdicts, sign-offs, invoices, and collections",
    "mcp": "thin projection of the same five operations",
}


def _request_digest(payload: Mapping[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _scope_matches_context(
    scope: ContractDeliveryScope, requested_by_ref: str, context: PrimitiveExecutionContext
) -> bool:
    runtime = context.scope
    return (
        scope.tenant_ref == runtime.tenant_ref
        and scope.company_ref == runtime.company_ref
        and scope.project_ref == runtime.project_ref
        and runtime.project_id is not None
        and scope.project_id == str(runtime.project_id)
        and runtime.actor_ref is not None
        and requested_by_ref == runtime.actor_ref
    )


class _DeliveryPrimitive(BusinessProcessPrimitive[InputT, OutputT], Generic[InputT, OutputT]):
    connector_tools = ()
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    operation_spec: PrimitiveOperationSpec
    golden_loop = CONTRACT_DELIVERY_GOLDEN_LOOP

    def implementation_contract(self) -> dict[str, Any]:
        contract = super().implementation_contract()
        contract["operation_contract"] = self.operation_spec.to_dict()
        contract["effect_boundary"] = ContractDeliveryEffectBoundary().to_dict()
        contract["authority_boundary"] = dict(_AUTHORITY_BOUNDARY)
        contract["golden_loop"] = self.golden_loop
        contract["golden_loop_extension"] = CONTRACT_DELIVERY_LOOP_EXTENSION
        contract["invariants"] = {
            "deliverable_bound_to_exact_agreement_obligation_order_line_and_criteria": True,
            "builder_cannot_accept_own_work": True,
            "project_completion_is_not_acceptance": True,
            "provider_upload_is_not_acceptance": True,
            "criteria_immutable_after_binding_without_change_order": True,
            "partial_acceptance_yields_only_allocated_amount": True,
            "rejected_work_never_invoice_eligible": True,
            "expired_or_superseded_agreement_generates_no_work": True,
            "change_order_never_rewrites_prior_work_evidence_acceptance_or_invoices": True,
            "only_spring_persists_acceptance_or_authorizes_invoicing": True,
        }
        return contract

    def _scope_blocked(self, *, request_digest: str, evidence_refs: list[PrimitiveEvidenceRef]) -> PrimitiveExecutionResult[OutputT]:
        blocker = PrimitiveBlocker(
            code="SCOPE_MISMATCH",
            message=(
                "Runtime tenant/company/project UUID and authenticated actor must be present "
                "and exactly match the delivery input."
            ),
            field="scope",
            retryable=False,
        )
        return PrimitiveExecutionResult[OutputT](
            status=PrimitiveExecutionStatus.BLOCKED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=f"{self.title} rejected at the scope boundary.",
            blockers=[blocker],
            evidence_refs=evidence_refs,
            operation_receipts=[
                PrimitiveOperationReceipt(
                    spec=self.operation_spec,
                    status=PrimitiveOperationStatus.BLOCKED,
                    request_digest=request_digest,
                    evidence_refs=evidence_refs,
                    error=blocker,
                )
            ],
        )

    def _result(
        self,
        *,
        output: OutputT,
        request_digest: str,
        evidence_refs: list[PrimitiveEvidenceRef],
        external_refs: Mapping[str, str],
        event_type: str,
        event_payload: Mapping[str, Any],
        evidence_kind: str,
        evidence_summary: str,
        summary: str,
        blocker: PrimitiveBlocker | None = None,
    ) -> PrimitiveExecutionResult[OutputT]:
        status = PrimitiveExecutionStatus.BLOCKED if blocker is not None else PrimitiveExecutionStatus.PREVIEW
        receipt = PrimitiveOperationReceipt(
            spec=self.operation_spec,
            status=PrimitiveOperationStatus.BLOCKED if blocker is not None else PrimitiveOperationStatus.PREVIEW,
            request_digest=request_digest,
            evidence_refs=evidence_refs,
            external_refs=dict(external_refs),
            error=blocker,
        )
        return PrimitiveExecutionResult[OutputT](
            status=status,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=summary,
            output=output,
            events=[
                PrimitiveEvent(
                    type=event_type,
                    payload={
                        **dict(event_payload),
                        "request_digest": request_digest,
                        "customer_acceptance_recorded": False,
                        "invoice_authorized": False,
                        "scope_mutated": False,
                        "connector_effect_executed": False,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind=evidence_kind,
                    summary=evidence_summary,
                    refs={"request_digest": request_digest, **dict(external_refs)},
                )
            ],
            evidence_refs=evidence_refs,
            operation_receipts=[receipt],
            blockers=[blocker] if blocker is not None else [],
        )


def _first_blocker(blockers: Any, fallback_code: str) -> PrimitiveBlocker | None:
    if not blockers:
        return None
    first = blockers[0]
    return PrimitiveBlocker(code=first.code, message=first.detail, retryable=False)


# --------------------------------------------------------------------------- #
# Deterministic example bundle chained from the handoff and obligation examples
# --------------------------------------------------------------------------- #

_EXAMPLE_ACTOR = "actor-requester-example"
_WORKFLOW_SCOPE = {
    "tenant_id": "tenant-workflow-example",
    "company_id": "company-workflow-example",
    "user_id": "user-workflow-example",
    "project_ref": "project:workflow-improvement",
}


def _digest_of(seed: str) -> str:
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


class _ExampleBundle:
    def __init__(self) -> None:
        self._built: dict[str, Any] | None = None

    def get(self) -> dict[str, Any]:
        if self._built is not None:
            return self._built
        reconciliation = reconcile_executed_agreement(dict(_ReconcileExecutedAgreementPrimitive.example_inputs))
        assert reconciliation.custody_candidate is not None
        assert reconciliation.service_delivery is not None
        assert reconciliation.contract_to_cash is not None
        custody = reconciliation.custody_candidate
        normalization = build_contract_obligation_normalization_input(dict(_IntakePrimitive.example_inputs))
        register = normalize_contract_obligation_candidates(normalization)
        routing = route_contract_obligation_register(
            {
                "scope": register.scope.to_dict(),
                "obligation_register": register.to_dict(),
                "counterparty_role": "customer",
                "requested_by_ref": _EXAMPLE_ACTOR,
            }
        )
        scope = {
            "tenant_ref": "authenticated",
            "company_ref": "selected",
            "project_ref": "workflow-improvement",
            "project_id": "40100000-0000-4000-8000-000000000001",
            "agreement_ref": custody.contract_ref,
            "custody_candidate_digest": custody.custody_candidate_digest,
            "workflow_scope": dict(_WORKFLOW_SCOPE),
            "evidence_custody_ref": "custody-example",
            "authorized_evidence_issuer_refs": ["customer-portal-example", "spring-example"],
        }
        criteria = [
            {
                "criterion_id": "report-delivered",
                "description": "Usage report delivered to the counterparty portal",
                "required_evidence": ["portal_receipt"],
            },
            {
                "criterion_id": "report-format",
                "description": "Usage report follows the agreed template",
                "required_evidence": ["template_check"],
            },
        ]
        plan_input = {
            "scope": scope,
            "custody_candidate": custody.to_dict(),
            "service_delivery": reconciliation.service_delivery.to_dict(),
            "contract_to_cash": reconciliation.contract_to_cash.to_dict(),
            "obligation_register": register.to_dict(),
            "routing_plan": routing.to_dict(),
            "assignments": [
                {
                    "obligation_ref": "obligation-monthly-report-example",
                    "milestone_ref": "milestone-go-live-example",
                    "accountable_role_ref": "role-delivery-lead-example",
                    "deadline_at": "2026-10-15T00:00:00Z",
                    "order_line_refs": ["order-line-example"],
                    "acceptance_criteria": criteria,
                    "criterion_allocations": [
                        {"criterion_id": "report-delivered", "amount": "120.000000"},
                        {"criterion_id": "report-format", "amount": "60.000000"},
                    ],
                    "allocated_amount": "180.000000",
                }
            ],
            "as_of": "2026-09-10T00:00:00Z",
            "requested_by_ref": _EXAMPLE_ACTOR,
        }
        plan_result = compile_contract_delivery_plan(plan_input)
        assert plan_result.plan is not None
        plan = plan_result.plan
        deliverable = plan.deliverables[0]
        planner_plan_digest = _digest_of("planner-plan-example")
        binding_input = {
            "scope": scope,
            "plan": plan.to_dict(),
            "obligation_ref": deliverable.obligation_ref,
            "work_packet": {
                "packet_ref": "work-packet-report-example",
                "title": "Deliver the monthly usage report",
                "objective": "Produce and deliver the September usage report",
                "scope": ["report generation", "portal delivery"],
                "acceptance_criteria": [item["description"] for item in criteria],
                "target_files": [],
                "dependencies": [],
                "risk_level": "medium",
                "state": "approved",
            },
            "workflow_run_ref": "dwr_report_example",
            "planner_plan_digest": planner_plan_digest,
            "retained_acceptance_criteria": [item.model_dump(mode="json") for item in deliverable.acceptance_criteria],
            "bound_at": "2026-09-11T00:00:00Z",
            "requested_by_ref": _EXAMPLE_ACTOR,
        }
        binding_result = bind_contract_deliverable_to_work_packet(binding_input)
        assert binding_result.binding is not None
        binding = binding_result.binding
        builder_result = {
            "scope": dict(_WORKFLOW_SCOPE),
            "run_ref": "dwr_report_example",
            "assignment_id": "dwa_report_example",
            "plan_digest": planner_plan_digest,
            "iteration": 1,
            "builder_context_id": "dwh_" + "b" * 64,
            "builder_session_id": "dwh_" + "c" * 64,
            "outcome": "completed",
            "summary": "Report generated and delivered to the portal.",
            "evidence_refs": [
                {"ref": "dwe_portal_receipt_example", "sha256": _digest_of("portal-receipt"), "kind": "portal_receipt"},
                {"ref": "dwe_template_check_example", "sha256": _digest_of("template-check"), "kind": "template_check"},
            ],
            "progress_digest": _digest_of("progress"),
            "occurred_at": "2026-09-20T00:00:00Z",
        }
        evidence_input = {
            "scope": scope,
            "binding": binding.to_dict(),
            "builder_result": builder_result,
            "evaluated_at": "2026-09-20T01:00:00Z",
            "requested_by_ref": _EXAMPLE_ACTOR,
        }
        assessment = evaluate_contractual_delivery_evidence(evidence_input)
        builder_digest = BuilderResult.model_validate(builder_result).digest
        verdict = {
            "scope": dict(_WORKFLOW_SCOPE),
            "run_ref": "dwr_report_example",
            "verdict_id": "dwv_report_example",
            "plan_digest": planner_plan_digest,
            "builder_result_digest": builder_digest,
            "evaluator_context_id": "dwh_" + "d" * 64,
            "evaluator_session_id": "dwh_" + "e" * 64,
            "decision": "accept",
            "accepted": True,
            "summary": "Both contractual criteria are met.",
            "criterion_results": [
                {
                    "criterion_id": "report-delivered",
                    "accepted": True,
                    "reason": "Portal receipt retained",
                    "evidence_refs": [{"ref": "dwe_portal_receipt_example", "sha256": _digest_of("portal-receipt"), "kind": "portal_receipt"}],
                },
                {
                    "criterion_id": "report-format",
                    "accepted": True,
                    "reason": "Template check retained",
                    "evidence_refs": [{"ref": "dwe_template_check_example", "sha256": _digest_of("template-check"), "kind": "template_check"}],
                },
            ],
            "occurred_at": "2026-09-21T00:00:00Z",
        }
        acceptance_input = {
            "scope": scope,
            "binding": binding.to_dict(),
            "evidence_assessment": assessment.to_dict(),
            "evaluator_verdict": verdict,
            "accepted_at": "2026-09-21T01:00:00Z",
            "requested_by_ref": _EXAMPLE_ACTOR,
        }
        change_order_input = {
            "scope": scope,
            "plan": plan.to_dict(),
            "variance": {
                "variance_ref": "variance-weekly-reports-example",
                "discovered_at": "2026-09-22T00:00:00Z",
                "discovered_by_ref": "role-delivery-lead-example",
                "classification": "scope_change",
                "description": "Customer asked for weekly instead of monthly reports",
                "affected_obligation_refs": [deliverable.obligation_ref],
                "evidence_refs": ["customer-email-thread-example"],
            },
            "impact": {
                "schedule_days_delta": 0,
                "price_delta": "40.000000",
                "currency": plan.currency,
                "scope_delta": "Weekly reporting cadence replaces monthly cadence",
                "assumption_changes": ["Reporting effort quadruples"],
            },
            "requested_by_ref": _EXAMPLE_ACTOR,
        }
        self._built = {
            "plan_input": plan_input,
            "binding_input": binding_input,
            "evidence_input": evidence_input,
            "acceptance_input": acceptance_input,
            "change_order_input": change_order_input,
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


# --------------------------------------------------------------------------- #
# Primitives
# --------------------------------------------------------------------------- #


class CompileContractDeliveryPlanPrimitive(_DeliveryPrimitive[ContractDeliveryPlanInput, ContractDeliveryPlanResult]):
    primitive_ref = "project.compile_contract_delivery_plan"
    version = "0.1.0"
    title = "Compile a contract delivery plan from executed-agreement obligations"
    description = (
        "Map the delivery-routed obligations of an executed agreement into deliverables with "
        "milestones, dependencies, deadlines, accountable roles, immutable acceptance criteria, "
        "evidence requirements, and invoice allocation that equals the contracted total. Expired "
        "or superseded agreements produce blockers, never work."
    )
    input_model = ContractDeliveryPlanInput
    output_model = ContractDeliveryPlanResult
    risk_level = "medium"
    operation_spec = DELIVERY_PLAN_OPERATION
    example_inputs: Mapping[str, Any] = _LazyExample("plan_input")

    def _execute(self, context: PrimitiveExecutionContext, inputs: ContractDeliveryPlanInput) -> PrimitiveExecutionResult[ContractDeliveryPlanResult]:
        request_digest = _request_digest(inputs.to_dict())
        if not _scope_matches_context(inputs.scope, inputs.requested_by_ref, context):
            return self._scope_blocked(request_digest=request_digest, evidence_refs=[])
        result = compile_contract_delivery_plan(inputs)
        return self._result(
            output=result,
            request_digest=request_digest,
            evidence_refs=[],
            external_refs={"plan_digest": result.plan.plan_digest} if result.plan else {"result_digest": result.result_digest},
            event_type="project.contract_delivery_plan_compiled",
            event_payload={
                "agreement_ref": inputs.scope.agreement_ref,
                "deliverables": len(result.plan.deliverables) if result.plan else 0,
                "blockers": [item.code for item in result.blockers],
            },
            evidence_kind="contract_delivery_plan",
            evidence_summary="Portable delivery plan candidate; Spring and the project runtime admit work.",
            summary=(
                f"Planned {len(result.plan.deliverables)} contractual deliverable(s) totalling {result.plan.total_allocated} {result.plan.currency}."
                if result.plan
                else f"Delivery plan blocked: {[item.code for item in result.blockers]}."
            ),
            blocker=_first_blocker(result.blockers, "PLAN_BLOCKED"),
        )


class BindContractDeliverableToWorkPacketPrimitive(
    _DeliveryPrimitive[ContractDeliverableBindingInput, ContractDeliverableBindingResult]
):
    primitive_ref = "project.bind_contract_deliverable_to_work_packet"
    version = "0.1.0"
    title = "Bind a contractual deliverable to a work packet and immutable acceptance contract"
    description = (
        "Bind one planned deliverable to an existing project.create_work_packet record and the "
        "acceptance criteria retained by the Dynamic Workflow run. Criteria that differ from the "
        "contract block the binding and require a change order; expired or superseded agreements "
        "cannot bind new work."
    )
    input_model = ContractDeliverableBindingInput
    output_model = ContractDeliverableBindingResult
    risk_level = "medium"
    operation_spec = DELIVERABLE_BINDING_OPERATION
    example_inputs: Mapping[str, Any] = _LazyExample("binding_input")

    def _execute(self, context: PrimitiveExecutionContext, inputs: ContractDeliverableBindingInput) -> PrimitiveExecutionResult[ContractDeliverableBindingResult]:
        request_digest = _request_digest(inputs.to_dict())
        if not _scope_matches_context(inputs.scope, inputs.requested_by_ref, context):
            return self._scope_blocked(request_digest=request_digest, evidence_refs=[])
        result = bind_contract_deliverable_to_work_packet(inputs)
        return self._result(
            output=result,
            request_digest=request_digest,
            evidence_refs=[],
            external_refs=(
                {"binding_digest": result.binding.binding_digest, "packet_ref": result.binding.packet_ref}
                if result.binding
                else {"result_digest": result.result_digest}
            ),
            event_type="project.contract_deliverable_bound",
            event_payload={
                "obligation_ref": inputs.obligation_ref,
                "packet_ref": inputs.work_packet.packet_ref,
                "bound": result.binding is not None,
                "change_order_required": result.change_order_required,
                "blockers": [item.code for item in result.blockers],
            },
            evidence_kind="contract_deliverable_binding",
            evidence_summary="Portable binding candidate; acceptance criteria are immutable once bound.",
            summary=(
                f"Bound {inputs.obligation_ref} to {inputs.work_packet.packet_ref}."
                if result.binding
                else f"Binding blocked: {[item.code for item in result.blockers]}."
            ),
            blocker=_first_blocker(result.blockers, "BINDING_BLOCKED"),
        )


class EvaluateContractualDeliveryEvidencePrimitive(
    _DeliveryPrimitive[ContractualDeliveryEvidenceInput, ContractualDeliveryEvidenceAssessment]
):
    primitive_ref = "project.evaluate_contractual_delivery_evidence"
    version = "0.1.0"
    title = "Assess whether retained builder evidence addresses the contractual acceptance criteria"
    description = (
        "Check a Dynamic Workflow builder result against the bound deliverable's immutable "
        "criteria and report evidence coverage per criterion. The assessment is "
        "non-authoritative and cannot accept: project completion and provider upload are not "
        "customer acceptance."
    )
    input_model = ContractualDeliveryEvidenceInput
    output_model = ContractualDeliveryEvidenceAssessment
    risk_level = "low"
    operation_spec = DELIVERY_EVIDENCE_OPERATION
    example_inputs: Mapping[str, Any] = _LazyExample("evidence_input")

    def _execute(self, context: PrimitiveExecutionContext, inputs: ContractualDeliveryEvidenceInput) -> PrimitiveExecutionResult[ContractualDeliveryEvidenceAssessment]:
        request_digest = _request_digest(inputs.to_dict())
        if not _scope_matches_context(inputs.scope, inputs.requested_by_ref, context):
            return self._scope_blocked(request_digest=request_digest, evidence_refs=[])
        assessment = evaluate_contractual_delivery_evidence(inputs)
        return self._result(
            output=assessment,
            request_digest=request_digest,
            evidence_refs=[],
            external_refs={
                "assessment_digest": assessment.assessment_digest,
                "builder_result_digest": assessment.builder_result_digest,
                "coverage": assessment.coverage_summary,
            },
            event_type="project.contractual_delivery_evidence_assessed",
            event_payload={
                "obligation_ref": assessment.obligation_ref,
                "coverage_summary": assessment.coverage_summary,
                "acceptance_status": assessment.acceptance_status,
                "blockers": [item.code for item in assessment.blockers],
            },
            evidence_kind="contractual_delivery_evidence_assessment",
            evidence_summary="Evidence coverage only; not acceptance.",
            summary=f"Builder evidence coverage for {assessment.obligation_ref}: {assessment.coverage_summary}; acceptance pending independent evaluation.",
            blocker=_first_blocker(assessment.blockers, "EVIDENCE_BLOCKED"),
        )


class CompileCustomerAcceptanceCandidatePrimitive(
    _DeliveryPrimitive[CustomerAcceptanceCandidateInput, CustomerAcceptanceCandidateResult]
):
    primitive_ref = "project.compile_customer_acceptance_candidate"
    version = "0.1.0"
    title = "Compile an AcceptedValueBinding candidate from independent acceptance"
    description = (
        "Convert a fresh-context evaluator verdict or verified customer sign-off into an "
        "AcceptedValueBinding candidate for contract-to-cash: full or partial acceptance yields "
        "only the contractually allocated amount, rejected work is never invoice-eligible, and "
        "the builder cannot accept its own work. Spring records the authoritative acceptance."
    )
    input_model = CustomerAcceptanceCandidateInput
    output_model = CustomerAcceptanceCandidateResult
    risk_level = "high"
    operation_spec = ACCEPTANCE_CANDIDATE_OPERATION
    example_inputs: Mapping[str, Any] = _LazyExample("acceptance_input")

    def _execute(self, context: PrimitiveExecutionContext, inputs: CustomerAcceptanceCandidateInput) -> PrimitiveExecutionResult[CustomerAcceptanceCandidateResult]:
        request_digest = _request_digest(inputs.to_dict())
        evidence_refs = [inputs.customer_signoff.evidence] if inputs.customer_signoff else []
        if not _scope_matches_context(inputs.scope, inputs.requested_by_ref, context):
            return self._scope_blocked(request_digest=request_digest, evidence_refs=evidence_refs)
        result = compile_customer_acceptance_candidate(inputs)
        candidate = result.candidate
        return self._result(
            output=result,
            request_digest=request_digest,
            evidence_refs=evidence_refs,
            external_refs=(
                {
                    "accepted_value_digest": candidate.accepted_value_digest,
                    "acceptance_state": candidate.acceptance_state,
                    "accepted_amount": str(candidate.accepted_amount),
                }
                if candidate
                else {"result_digest": result.result_digest}
            ),
            event_type="project.customer_acceptance_candidate_compiled",
            event_payload={
                "obligation_ref": inputs.binding.deliverable.obligation_ref,
                "acceptance_state": candidate.acceptance_state if candidate else None,
                "invoice_eligible": candidate.invoice_eligible if candidate else False,
                "builder_self_acceptance": False,
                "blockers": [item.code for item in result.blockers],
            },
            evidence_kind="accepted_value_binding_candidate",
            evidence_summary="Candidate accepted value; Spring records acceptance and authorizes invoicing.",
            summary=(
                f"{candidate.acceptance_state}: {candidate.accepted_amount} of {candidate.allocated_amount} {candidate.currency} accepted."
                if candidate
                else f"Acceptance candidate blocked: {[item.code for item in result.blockers]}."
            ),
            blocker=_first_blocker(result.blockers, "ACCEPTANCE_BLOCKED"),
        )


class ProposeContractChangeOrderPrimitive(_DeliveryPrimitive[ContractChangeOrderInput, ContractChangeOrderProposal]):
    primitive_ref = "commercial.propose_contract_change_order"
    version = "0.1.0"
    title = "Propose a contract change order from a delivery variance"
    description = (
        "Classify a delivery variance (clarification, internal correction, schedule, scope, "
        "price, acceptance criteria, regulatory, cancellation, supplier) against its stated "
        "impact and route contractual changes back through commercial and legal review. Prior "
        "work, evidence, acceptance, and invoices are never rewritten."
    )
    input_model = ContractChangeOrderInput
    output_model = ContractChangeOrderProposal
    risk_level = "medium"
    operation_spec = CHANGE_ORDER_OPERATION
    example_inputs: Mapping[str, Any] = _LazyExample("change_order_input")

    def _execute(self, context: PrimitiveExecutionContext, inputs: ContractChangeOrderInput) -> PrimitiveExecutionResult[ContractChangeOrderProposal]:
        request_digest = _request_digest(inputs.to_dict())
        if not _scope_matches_context(inputs.scope, inputs.requested_by_ref, context):
            return self._scope_blocked(request_digest=request_digest, evidence_refs=[])
        proposal = propose_contract_change_order(inputs)
        return self._result(
            output=proposal,
            request_digest=request_digest,
            evidence_refs=[],
            external_refs={
                "proposal_digest": proposal.proposal_digest,
                "disposition": proposal.disposition,
                "required_path": proposal.required_path,
            },
            event_type="commercial.contract_change_order_proposed",
            event_payload={
                "variance_ref": proposal.variance.variance_ref,
                "classification": proposal.variance.classification,
                "disposition": proposal.disposition,
                "required_path": proposal.required_path,
                "prior_work_rewritten": False,
                "blockers": [item.code for item in proposal.blockers],
            },
            evidence_kind="contract_change_order_proposal",
            evidence_summary="Change-order proposal; commercial and legal approval remain required.",
            summary=f"Variance {proposal.variance.variance_ref}: {proposal.disposition} via {proposal.required_path}.",
            blocker=_first_blocker(proposal.blockers, "CHANGE_ORDER_BLOCKED"),
        )


CONTRACT_DELIVERY_EXECUTABLE_PRIMITIVES: tuple[BusinessProcessPrimitive[Any, Any], ...] = (
    CompileContractDeliveryPlanPrimitive(),
    BindContractDeliverableToWorkPacketPrimitive(),
    EvaluateContractualDeliveryEvidencePrimitive(),
    CompileCustomerAcceptanceCandidatePrimitive(),
    ProposeContractChangeOrderPrimitive(),
)


CONTRACT_DELIVERY_INTEGRATION_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.capability_pack_integration_manifest.v1",
    "capability_pack": "contract_delivery_acceptance",
    "golden_loop": CONTRACT_DELIVERY_GOLDEN_LOOP,
    "golden_loop_extension": CONTRACT_DELIVERY_LOOP_EXTENSION,
    "golden_loop_lifecycle": [
        "executed agreement custody candidate + obligation register + routing",
        "contract delivery plan (deliverables, milestones, criteria, allocation)",
        "deliverable bound to project.create_work_packet and immutable acceptance contract",
        "builder result → contractual evidence assessment (non-authoritative)",
        "independent evaluator verdict or verified customer sign-off → AcceptedValueBinding candidate",
        "Spring records acceptance and authorizes invoice continuation → contract-to-cash",
        "delivery variance → change-order proposal → commercial/legal amendment lifecycle",
    ],
    "modules": {
        "domain": "lightbulb.contract_delivery_acceptance",
        "primitives": "lightbulb.contract_delivery_acceptance_primitives",
    },
    "stacked_on": {
        "branch": "fable/contract-obligations-core",
        "consumes": [
            "lightbulb.commercial_legal_handoff.ExecutedCommercialAgreementCustodyCandidate",
            "lightbulb.commercial_legal_handoff.ServiceDeliveryProjection",
            "lightbulb.commercial_legal_handoff.ContractToCashProjection",
            "lightbulb.contract_obligations.ObligationRegister",
            "lightbulb.contract_obligation_intake.ObligationRoutingPlan",
        ],
    },
    "reuses": [
        "lightbulb.dynamic_workflows.AcceptanceCriterion",
        "lightbulb.dynamic_workflows.BuilderResult",
        "lightbulb.dynamic_workflows.EvaluatorVerdict",
        "lightbulb.dynamic_workflows.DynamicWorkflowScope",
        "lightbulb.growth_primitives.CreateWorkPacketOutput (project.create_work_packet)",
        "lightbulb.primitive_runtime.PrimitiveEvidenceRef",
    ],
    "primitive_refs": [item.primitive_ref for item in CONTRACT_DELIVERY_EXECUTABLE_PRIMITIVES],
    "executable_registry": {
        "file": "lightbulb/executable_primitives.py",
        "import": "from lightbulb.contract_delivery_acceptance_primitives import CONTRACT_DELIVERY_EXECUTABLE_PRIMITIVES",
        "splice": "*CONTRACT_DELIVERY_EXECUTABLE_PRIMITIVES in BUILTIN_EXECUTABLE_PRIMITIVES",
        "placement_hint": "after *CONTRACT_OBLIGATION_EXECUTABLE_PRIMITIVES",
    },
    "public_exports": {
        "file": "lightbulb/__init__.py",
        "names": [
            "CONTRACT_DELIVERY_EXECUTABLE_PRIMITIVES",
            "CONTRACT_DELIVERY_GOLDEN_LOOP",
            "CONTRACT_DELIVERY_INTEGRATION_MANIFEST",
            "CompileContractDeliveryPlanPrimitive",
            "BindContractDeliverableToWorkPacketPrimitive",
            "EvaluateContractualDeliveryEvidencePrimitive",
            "CompileCustomerAcceptanceCandidatePrimitive",
            "ProposeContractChangeOrderPrimitive",
            "ContractDeliveryScope",
            "ContractDeliveryPlan",
            "ContractDeliverableBinding",
            "ContractualDeliveryEvidenceAssessment",
            "AcceptedValueBinding",
            "ContractChangeOrderProposal",
            "compile_contract_delivery_plan",
            "bind_contract_deliverable_to_work_packet",
            "evaluate_contractual_delivery_evidence",
            "compile_customer_acceptance_candidate",
            "propose_contract_change_order",
        ],
    },
    "catalog": {"file": "lightbulb/business_primitives.py", "note": "No Backbone catalog entry required; registry membership suffices."},
    "mcp": {"file": "lightbulb/mcp_server.py", "note": "No hand-written MCP tool; run_sdk_business_primitive applies."},
    "assumption": (
        "The brief cited lightbulb/contract_to_cash.py, AcceptedValueBinding, and the "
        "project.work_packet_independent_acceptance Golden Loop as existing. None exists on any "
        "reachable ref; AcceptedValueBinding is defined here under that exact name and the loop "
        "identifier is used as the extension target. Reconcile if canonical modules land first."
    ),
    "not_claimed": [
        "hosted execution",
        "Spring acceptance persistence or invoice authorization",
        "project runtime or work-packet execution",
        "certification or production readiness",
    ],
}


__all__ = [
    "ACCEPTANCE_CANDIDATE_OPERATION",
    "CHANGE_ORDER_OPERATION",
    "CONTRACT_DELIVERY_EXECUTABLE_PRIMITIVES",
    "CONTRACT_DELIVERY_INTEGRATION_MANIFEST",
    "DELIVERABLE_BINDING_OPERATION",
    "DELIVERY_EVIDENCE_OPERATION",
    "DELIVERY_PLAN_OPERATION",
    "BindContractDeliverableToWorkPacketPrimitive",
    "CompileContractDeliveryPlanPrimitive",
    "CompileCustomerAcceptanceCandidatePrimitive",
    "EvaluateContractualDeliveryEvidencePrimitive",
    "ProposeContractChangeOrderPrimitive",
]
