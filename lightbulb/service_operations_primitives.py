"""Executable primitives for Service Business Operations and Artifact Production.

Read-only, preview-only primitives over ``lightbulb.business_artifact_production``
and ``lightbulb.service_engagement``.  The artifact primitives keep the
model-powered generation step behind the SDK executor interface: preparing a
request yields a host ticket for the connected model host; validating a
submission binds provenance, version, approvals, and engagement linkage.  The
engagement primitives propose transitions, invoice candidates, and
assessments.  None of them writes a file, issues an invoice, moves money, or
invokes a connector; ``documents.generate_business_artifact`` and
``finance.create_invoice`` remain the governed effect paths.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any, Generic, TypeVar

from pydantic import BaseModel

from lightbulb.business_artifact_production import (
    BUSINESS_ARTIFACT_GOLDEN_LOOP,
    ArtifactGenerationInput,
    ArtifactGenerationRequest,
    ArtifactValidationInput,
    GeneratedBusinessArtifact,
    TemplateArtifactGenerationExecutor,
    prepare_business_artifact_generation,
    validate_generated_business_artifact,
)
from lightbulb.connector_execution import ConnectorEffect
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
    PrimitiveRecoveryDisposition,
    PrimitiveRecoveryPlan,
)
from lightbulb.service_engagement import (
    SERVICE_ENGAGEMENT_GOLDEN_LOOP,
    ServiceEngagementAssessment,
    ServiceEngagementAssessmentInput,
    ServiceEngagementInvoiceCandidate,
    ServiceEngagementInvoiceInput,
    ServiceEngagementTransitionInput,
    ServiceEngagementTransitionResult,
    assess_service_engagement,
    genesis_engagement_state_digest,
    materialize_service_engagement_transition,
    propose_service_engagement_invoice,
    seal_service_engagement_command,
)


InputT = TypeVar("InputT", bound=BaseModel)
OutputT = TypeVar("OutputT", bound=BaseModel)


def _read_operation(operation_ref: str, tool: str, *, replay: PrimitiveOperationReplayClass = PrimitiveOperationReplayClass.SAFE) -> PrimitiveOperationSpec:
    return PrimitiveOperationSpec(
        operation_ref=operation_ref,
        tool=tool,
        effect=ConnectorEffect.READ,
        approval_required=False,
        replay_class=replay,
        freshness_class=PrimitiveOperationFreshnessClass.CURRENT,
        recovery_policy=(
            PrimitiveOperationRecoveryPolicy.MANUAL_RECONCILIATION
            if replay == PrimitiveOperationReplayClass.NEVER
            else PrimitiveOperationRecoveryPolicy.NONE
        ),
    )


ARTIFACT_PREPARE_OPERATION = _read_operation("business_artifact_prepare_generation", "sdk.documents.prepare_business_artifact_generation")
ARTIFACT_VALIDATE_OPERATION = _read_operation("business_artifact_validate_generated", "sdk.documents.validate_generated_business_artifact")
ENGAGEMENT_TRANSITION_OPERATION = _read_operation("service_engagement_propose_transition", "sdk.service.propose_engagement_transition", replay=PrimitiveOperationReplayClass.NEVER)
ENGAGEMENT_INVOICE_OPERATION = _read_operation("service_engagement_propose_invoice", "sdk.service.propose_engagement_invoice")
ENGAGEMENT_ASSESS_OPERATION = _read_operation("service_engagement_assess", "sdk.service.assess_engagement")


def _request_digest(payload: Mapping[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _scope_matches(tenant_ref: str, company_ref: str, project_ref: str, project_id: str, requested_by_ref: str, context: PrimitiveExecutionContext, *, idempotency_key: str | None = None) -> bool:
    runtime = context.scope
    matched = (
        tenant_ref == runtime.tenant_ref
        and company_ref == runtime.company_ref
        and project_ref == runtime.project_ref
        and runtime.project_id is not None
        and project_id == str(runtime.project_id)
        and runtime.actor_ref is not None
        and requested_by_ref == runtime.actor_ref
    )
    if idempotency_key is not None:
        matched = matched and context.idempotency_key is not None and idempotency_key == context.idempotency_key
    return matched


class _ServiceOpsPrimitive(BusinessProcessPrimitive[InputT, OutputT], Generic[InputT, OutputT]):
    connector_tools = ()
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    operation_spec: PrimitiveOperationSpec
    golden_loop: str

    def implementation_contract(self) -> dict[str, Any]:
        contract = super().implementation_contract()
        contract["operation_contract"] = self.operation_spec.to_dict()
        contract["golden_loop"] = self.golden_loop
        contract["authority_boundary"] = {
            "agent": "decides what to produce, for whom, and when to advance the engagement",
            "model_host": "produces artifact content on request through the SDK executor interface",
            "sdk": "assembles context, applies policy, validates output, proposes transitions and invoices",
            "spring": "approvals, artifact persistence and file writes, engagement of record, invoicing, settlement",
            "mcp": "thin projection of these primitives plus the host-model delegation adapter",
        }
        return contract

    def _blocked(self, *, request_digest: str, code: str, message: str, evidence_refs: list[PrimitiveEvidenceRef] | None = None) -> PrimitiveExecutionResult[OutputT]:
        blocker = PrimitiveBlocker(code=code, message=message, field="scope" if code == "SCOPE_MISMATCH" else None, retryable=False)
        return PrimitiveExecutionResult[OutputT](
            status=PrimitiveExecutionStatus.BLOCKED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=f"{self.title} blocked: {code}.",
            blockers=[blocker],
            evidence_refs=evidence_refs or [],
            operation_receipts=[PrimitiveOperationReceipt(spec=self.operation_spec, status=PrimitiveOperationStatus.BLOCKED, request_digest=request_digest, evidence_refs=evidence_refs or [], error=blocker)],
        )

    def _preview(self, *, output: OutputT, request_digest: str, external_refs: Mapping[str, str], event_type: str, event_payload: Mapping[str, Any], evidence_kind: str, evidence_summary: str, summary: str, blocker: PrimitiveBlocker | None = None) -> PrimitiveExecutionResult[OutputT]:
        status = PrimitiveExecutionStatus.BLOCKED if blocker is not None else PrimitiveExecutionStatus.PREVIEW
        receipt = PrimitiveOperationReceipt(spec=self.operation_spec, status=PrimitiveOperationStatus.BLOCKED if blocker is not None else PrimitiveOperationStatus.PREVIEW, request_digest=request_digest, external_refs=dict(external_refs), error=blocker)
        return PrimitiveExecutionResult[OutputT](
            status=status,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=summary,
            output=output,
            events=[PrimitiveEvent(type=event_type, payload={**dict(event_payload), "request_digest": request_digest, "external_write_performed": False, "connector_effect_executed": False})],
            evidence=[PrimitiveEvidence(kind=evidence_kind, summary=evidence_summary, refs={"request_digest": request_digest, **dict(external_refs)})],
            operation_receipts=[receipt],
            blockers=[blocker] if blocker is not None else [],
        )


# --------------------------------------------------------------------------- #
# Examples
# --------------------------------------------------------------------------- #

_EXAMPLE_ACTOR = "actor-requester-example"
_EXAMPLE_PROJECT_ID = "40100000-0000-4000-8000-000000000001"


def _digest_of(seed: str) -> str:
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def _artifact_scope() -> dict[str, Any]:
    return {"tenant_ref": "authenticated", "company_ref": "selected", "project_ref": "workflow-improvement", "project_id": _EXAMPLE_PROJECT_ID, "engagement_ref": "engagement-example", "customer_ref": "customer-example"}


def _engagement_scope() -> dict[str, Any]:
    return {"tenant_ref": "authenticated", "company_ref": "selected", "project_ref": "workflow-improvement", "project_id": _EXAMPLE_PROJECT_ID, "engagement_ref": "engagement-example", "customer_ref": "customer-example", "currency": "USD"}


def example_artifact_generation_input(*, kind: str = "proposal", artifact_format: str = "docx", mode: str = "host_model") -> dict[str, Any]:
    payload: dict[str, Any] = {
        "scope": _artifact_scope(),
        "artifact_kind": kind,
        "artifact_format": artifact_format,
        "title": "Seat expansion proposal for the example customer",
        "purpose": "Win the seat expansion described in the approved quote",
        "generation_mode": mode,
        "brand": {"brand_ref": "brand-example", "brand_name": "Lightbulb Partners", "tone": ["confident", "plain"], "forbidden_claims": ["guaranteed results"], "brand_approver_role_ref": "role-brand-example"},
        "commercial": {"quote_ref": "quote-example", "quote_revision": 2, "currency": "USD", "total": "180.000000", "lines": [{"line_ref": "quote-line-example", "description": "Platform seats", "quantity": "2.000000", "unit_price": "90.000000", "line_total": "180.000000"}], "payment_terms_days": 30, "valid_until": "2026-09-25T00:00:00Z"},
        "customer": {"customer_ref": "customer-example", "customer_display_name": "Example Customer", "industry": "Logistics"},
        "engagement": {"engagement_ref": "engagement-example", "stage": "quote_approved"},
        "requested_at": "2026-09-10T00:00:00Z",
        "requested_by_ref": _EXAMPLE_ACTOR,
    }
    if kind in {"contract", "statement_of_work"}:
        payload["legal"] = {
            "policy": {
                "policy_ref": "legal-policy-example",
                "approved_templates": [{"template_ref": "template-msa-example", "template_digest": _digest_of("template-msa"), "document_kind": "contract", "jurisdiction_refs": ["US-DE"], "required_clause_markers": ["liability_cap", "termination_notice"], "risk_class": "standard", "version": 3}],
                "approved_jurisdiction_refs": ["US-DE", "US-NY"],
                "legal_reviewer_role_ref": "role-legal-example",
                "contract_value_review_threshold": "100000.000000",
                "currency": "USD",
            },
            "template_ref": "template-msa-example",
            "template_version": 3,
            "jurisdiction_ref": "US-DE",
            "counterparty_ref": "customer-example",
        }
    return payload


class _ExampleBundle:
    def __init__(self) -> None:
        self._built: dict[str, Any] | None = None

    def get(self) -> dict[str, Any]:
        if self._built is not None:
            return self._built
        prepare_input = example_artifact_generation_input(mode="template")
        request = prepare_business_artifact_generation(prepare_input)
        submission = TemplateArtifactGenerationExecutor().generate(request)
        validate_input = {"request": request.to_dict(), "submission": submission.to_dict(), "artifact_ref": "artifact-proposal-example", "validated_at": "2026-09-10T01:00:00Z", "requested_by_ref": _EXAMPLE_ACTOR}
        scope = _engagement_scope()
        command = seal_service_engagement_command({
            "kind": "link_quote", "scope": scope, "transition_ref": "transition-link-quote-example", "idempotency_key": "idem-engagement-example",
            "expected_version": 0, "expected_state_digest": genesis_engagement_state_digest(scope), "occurred_at": "2026-09-01T00:00:00Z",
            "requested_by_ref": _EXAMPLE_ACTOR, "package": {"kind": "link_quote", "quote_ref": "quote-example", "quote_revision": 1, "commercial_snapshot_digest": _digest_of("commercial-snapshot"), "total": "180.000000"},
        })
        transition_input = {"scope": scope, "command": command}
        first = materialize_service_engagement_transition(transition_input)
        assert first.snapshot is not None
        assess_input = {"scope": scope, "snapshot": first.snapshot.to_dict(), "requested_by_ref": _EXAMPLE_ACTOR}
        # Invoice example: build an engagement with linked accepted value.
        snapshot = first.snapshot
        steps = [
            ("approve_quote", {"quote_ref": "quote-example", "quote_revision": 1, "approved_by_ref": "actor-sales-manager-example", "approval_evidence_ref": "evidence-quote-approval-example"}, "2026-09-02T00:00:00Z"),
            ("link_legal_review_packet", {"packet_digest": _digest_of("packet"), "quote_ref": "quote-example", "quote_revision": 1}, "2026-09-03T00:00:00Z"),
            ("link_executed_agreement", {"custody_candidate_digest": _digest_of("custody"), "contract_ref": "contract-example", "agreement_version": 1, "executed_agreement_digest": _digest_of("executed"), "packet_digest": _digest_of("packet"), "custody_record_ref": "custody-record-example"}, "2026-09-04T00:00:00Z"),
            ("link_delivery_plan", {"plan_digest": _digest_of("plan"), "custody_candidate_digest": _digest_of("custody"), "total_allocated": "180.000000", "deliverable_refs": ["obligation-monthly-report-example"]}, "2026-09-05T00:00:00Z"),
            ("link_deliverable_binding", {"binding_digest": _digest_of("binding"), "plan_digest": _digest_of("plan"), "obligation_ref": "obligation-monthly-report-example", "packet_ref": "work-packet-report-example"}, "2026-09-06T00:00:00Z"),
            ("link_accepted_value", {"accepted_value_digest": _digest_of("accepted"), "binding_digest": _digest_of("binding"), "obligation_ref": "obligation-monthly-report-example", "acceptance_state": "accepted_full", "accepted_amount": "180.000000", "invoice_eligible": True, "spring_acceptance_record_ref": "acceptance-record-example"}, "2026-09-07T00:00:00Z"),
        ]
        for kind, package, occurred_at in steps:
            command = seal_service_engagement_command({
                "kind": kind, "scope": scope, "transition_ref": f"transition-{kind}-example", "idempotency_key": f"idem-{kind}-example",
                "expected_version": snapshot.version, "expected_state_digest": snapshot.state_digest, "occurred_at": occurred_at,
                "requested_by_ref": _EXAMPLE_ACTOR, "package": {"kind": kind, **package},
            })
            result = materialize_service_engagement_transition({"scope": scope, "command": command, "current_snapshot": snapshot.to_dict()})
            assert result.snapshot is not None, result.transition_receipt.to_dict()
            snapshot = result.snapshot
        invoice_input = {
            "scope": scope,
            "snapshot": snapshot.to_dict(),
            "invoice_candidate_ref": "invoice-candidate-example",
            "accepted_values": [{"accepted_value_digest": _digest_of("accepted"), "obligation_ref": "obligation-monthly-report-example", "description": "Monthly usage report (accepted)", "accepted_amount": "180.000000"}],
            "due_days": 30,
            "requested_by_ref": _EXAMPLE_ACTOR,
        }
        self._built = {"prepare_input": prepare_input, "validate_input": validate_input, "transition_input": transition_input, "invoice_input": invoice_input, "assess_input": assess_input}
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
# Artifact primitives
# --------------------------------------------------------------------------- #


class PrepareBusinessArtifactGenerationPrimitive(_ServiceOpsPrimitive[ArtifactGenerationInput, ArtifactGenerationRequest]):
    primitive_ref = "documents.prepare_business_artifact_generation"
    version = "0.1.0"
    title = "Prepare governed business artifact generation"
    description = (
        "Assemble brand, commercial, legal-template, customer, and engagement context into a sealed "
        "generation brief, classify legal risk and mandatory review, derive approvals, and issue a "
        "host generation ticket for the connected model host (or mark the request for template "
        "rendering). Blocked legal policy yields no ticket."
    )
    input_model = ArtifactGenerationInput
    output_model = ArtifactGenerationRequest
    risk_level = "medium"
    operation_spec = ARTIFACT_PREPARE_OPERATION
    golden_loop = BUSINESS_ARTIFACT_GOLDEN_LOOP
    example_inputs: Mapping[str, Any] = _LazyExample("prepare_input")

    def _execute(self, context: PrimitiveExecutionContext, inputs: ArtifactGenerationInput) -> PrimitiveExecutionResult[ArtifactGenerationRequest]:
        request_digest = _request_digest(inputs.to_dict())
        scope = inputs.scope
        if not _scope_matches(scope.tenant_ref, scope.company_ref, scope.project_ref, scope.project_id, inputs.requested_by_ref, context):
            return self._blocked(request_digest=request_digest, code="SCOPE_MISMATCH", message="Runtime scope and actor must exactly match the artifact request.")
        request = prepare_business_artifact_generation(inputs)
        blocker = None
        if request.blocked_reasons:
            blocker = PrimitiveBlocker(code="LEGAL_POLICY_BLOCKED", message="; ".join(request.blocked_reasons), field="legal", retryable=False)
        return self._preview(
            output=request,
            request_digest=request_digest,
            external_refs={"brief_digest": request.brief.brief_digest, "request_digest_sealed": request.request_digest, **({"ticket_ref": request.host_ticket.ticket_ref} if request.host_ticket else {})},
            event_type="documents.business_artifact_generation_prepared",
            event_payload={"artifact_kind": inputs.artifact_kind, "generation_mode": inputs.generation_mode, "risk_class": request.brief.legal_assessment.risk_class, "mandatory_legal_review": request.brief.legal_assessment.mandatory_legal_review, "required_approvals": [item.approval_kind for item in request.brief.required_approvals], "blocked": bool(request.blocked_reasons)},
            evidence_kind="business_artifact_generation_request",
            evidence_summary="Sealed brief and host ticket; generation happens through the SDK executor interface.",
            summary=(f"Prepared {inputs.artifact_kind} generation ({inputs.generation_mode}); risk {request.brief.legal_assessment.risk_class}." if not request.blocked_reasons else f"Artifact generation blocked by legal policy: {request.blocked_reasons[0]}"),
            blocker=blocker,
        )


class ValidateGeneratedBusinessArtifactPrimitive(_ServiceOpsPrimitive[ArtifactValidationInput, GeneratedBusinessArtifact]):
    primitive_ref = "documents.validate_generated_business_artifact"
    version = "0.1.0"
    title = "Validate a generated business artifact"
    description = (
        "Validate host- or template-produced sections against the sealed brief (required and "
        "forbidden sections, credentials, amounts outside the commercial context, brand claims, "
        "retained template clauses, ticket provenance) and bind provenance, version, approvals, and "
        "engagement linkage into an artifact candidate. The file write still goes through "
        "documents.generate_business_artifact and Spring approval."
    )
    input_model = ArtifactValidationInput
    output_model = GeneratedBusinessArtifact
    risk_level = "medium"
    operation_spec = ARTIFACT_VALIDATE_OPERATION
    golden_loop = BUSINESS_ARTIFACT_GOLDEN_LOOP
    example_inputs: Mapping[str, Any] = _LazyExample("validate_input")

    def _execute(self, context: PrimitiveExecutionContext, inputs: ArtifactValidationInput) -> PrimitiveExecutionResult[GeneratedBusinessArtifact]:
        request_digest = _request_digest(inputs.to_dict())
        scope = inputs.request.brief.scope
        if not _scope_matches(scope.tenant_ref, scope.company_ref, scope.project_ref, scope.project_id, inputs.requested_by_ref, context):
            return self._blocked(request_digest=request_digest, code="SCOPE_MISMATCH", message="Runtime scope and actor must exactly match the artifact request.")
        artifact = validate_generated_business_artifact(inputs)
        blocker = None
        if artifact.state == "blocked":
            blocker = PrimitiveBlocker(code=artifact.findings[0].code, message=artifact.findings[0].detail, field=artifact.findings[0].section, retryable=False)
        return self._preview(
            output=artifact,
            request_digest=request_digest,
            external_refs={"artifact_ref": artifact.artifact_ref, "artifact_version": str(artifact.version), "artifact_digest": artifact.artifact_digest, "state": artifact.state},
            event_type="documents.business_artifact_validated",
            event_payload={"artifact_kind": artifact.artifact_kind, "state": artifact.state, "findings": [item.code for item in artifact.findings], "required_approvals": [item.approval_kind for item in artifact.required_approvals], "generator_kind": artifact.provenance.generator_kind, "engagement_ref": artifact.engagement_ref},
            evidence_kind="generated_business_artifact",
            evidence_summary="Validated artifact candidate with provenance and version; not yet written or approved.",
            summary=f"Artifact {artifact.artifact_ref} v{artifact.version}: {artifact.state} ({artifact.word_count} words).",
            blocker=blocker,
        )


# --------------------------------------------------------------------------- #
# Engagement primitives
# --------------------------------------------------------------------------- #


class ProposeServiceEngagementTransitionPrimitive(_ServiceOpsPrimitive[ServiceEngagementTransitionInput, ServiceEngagementTransitionResult]):
    primitive_ref = "service.propose_engagement_transition"
    version = "0.1.0"
    title = "Propose a bounded service engagement transition"
    description = (
        "Link quote, approval, legal review packet, executed agreement, delivery plan, deliverable "
        "bindings, accepted value, invoice candidates, issued invoices, and payments into one "
        "replay-fenced engagement history, or close/cancel it. Proposal only; Spring owns the "
        "engagement of record."
    )
    input_model = ServiceEngagementTransitionInput
    output_model = ServiceEngagementTransitionResult
    risk_level = "medium"
    mcp_idempotent = False
    operation_spec = ENGAGEMENT_TRANSITION_OPERATION
    golden_loop = SERVICE_ENGAGEMENT_GOLDEN_LOOP
    example_inputs: Mapping[str, Any] = _LazyExample("transition_input")

    def _execute(self, context: PrimitiveExecutionContext, inputs: ServiceEngagementTransitionInput) -> PrimitiveExecutionResult[ServiceEngagementTransitionResult]:
        command = inputs.command
        scope = inputs.scope
        if not _scope_matches(scope.tenant_ref, scope.company_ref, scope.project_ref, scope.project_id, command.requested_by_ref, context, idempotency_key=command.idempotency_key):
            return self._blocked(request_digest=command.request_digest, code="SCOPE_MISMATCH", message="Runtime scope, actor, and idempotency key must exactly match the engagement command.")
        output = materialize_service_engagement_transition(inputs)
        receipt = output.transition_receipt
        blocker: PrimitiveBlocker | None = None
        recovery_plan: PrimitiveRecoveryPlan | None = None
        if output.candidate_validated:
            status, receipt_status, disposition = PrimitiveExecutionStatus.PREVIEW, PrimitiveOperationStatus.PREVIEW, PrimitiveRecoveryDisposition.NOT_REQUIRED
        elif receipt.status == "in_doubt":
            status, receipt_status, disposition = PrimitiveExecutionStatus.BLOCKED, PrimitiveOperationStatus.IN_DOUBT, PrimitiveRecoveryDisposition.MANUAL_RECONCILIATION_REQUIRED
            recovery_plan = PrimitiveRecoveryPlan(policy=PrimitiveOperationRecoveryPolicy.MANUAL_RECONCILIATION, disposition=disposition, instructions=receipt.recovery.instructions)
            blocker = PrimitiveBlocker(code=receipt.rejection_code or "OUTCOME_IN_DOUBT", message=receipt.recovery.instructions or "Manual reconciliation is required.", retryable=False)
        else:
            status, receipt_status, disposition = PrimitiveExecutionStatus.BLOCKED, PrimitiveOperationStatus.BLOCKED, PrimitiveRecoveryDisposition.NOT_REQUIRED
            blocker = PrimitiveBlocker(code=receipt.rejection_code or "TRANSITION_REJECTED", message=receipt.recovery.instructions or "Engagement transition was rejected.", retryable=False)
        operation_receipt = PrimitiveOperationReceipt(
            spec=self.operation_spec, status=receipt_status, request_digest=command.request_digest,
            external_refs=({"state_digest": output.snapshot.state_digest, "stage": output.snapshot.stage, "transition_ref": command.transition_ref} if output.snapshot else {}),
            recovery_disposition=disposition, recovery_plan=recovery_plan, error=blocker,
        )
        return PrimitiveExecutionResult[ServiceEngagementTransitionResult](
            status=status, primitive_ref=self.primitive_ref, primitive_version=self.version,
            summary=(f"Engagement advanced to {output.snapshot.stage}." if output.snapshot else f"Engagement transition rejected: {receipt.rejection_code}."),
            output=output,
            events=[PrimitiveEvent(type="service.engagement_transition_candidate_evaluated", payload={"engagement_ref": scope.engagement_ref, "command_kind": command.kind, "candidate_validated": output.candidate_validated, "to_stage": receipt.to_stage, "request_digest": command.request_digest, "invoice_issued": False, "payment_moved": False, "connector_effect_executed": False})],
            evidence=[PrimitiveEvidence(kind="service_engagement_transition_receipt", summary="Portable engagement transition candidate; not the engagement of record.", refs={"transition_ref": command.transition_ref, "request_digest": command.request_digest})],
            operation_receipts=[operation_receipt], recovery_plan=recovery_plan, blockers=[blocker] if blocker else [],
        )


class ProposeServiceEngagementInvoicePrimitive(_ServiceOpsPrimitive[ServiceEngagementInvoiceInput, ServiceEngagementInvoiceCandidate]):
    primitive_ref = "service.propose_engagement_invoice"
    version = "0.1.0"
    title = "Propose an invoice from accepted engagement value"
    description = (
        "Shape uninvoiced, invoice-eligible accepted value linked to the engagement into an invoice "
        "candidate compatible with finance.create_invoice. Issuing the invoice remains a governed "
        "finance write."
    )
    input_model = ServiceEngagementInvoiceInput
    output_model = ServiceEngagementInvoiceCandidate
    risk_level = "medium"
    operation_spec = ENGAGEMENT_INVOICE_OPERATION
    golden_loop = SERVICE_ENGAGEMENT_GOLDEN_LOOP
    example_inputs: Mapping[str, Any] = _LazyExample("invoice_input")

    def _execute(self, context: PrimitiveExecutionContext, inputs: ServiceEngagementInvoiceInput) -> PrimitiveExecutionResult[ServiceEngagementInvoiceCandidate]:
        request_digest = _request_digest(inputs.to_dict())
        scope = inputs.scope
        if not _scope_matches(scope.tenant_ref, scope.company_ref, scope.project_ref, scope.project_id, inputs.requested_by_ref, context):
            return self._blocked(request_digest=request_digest, code="SCOPE_MISMATCH", message="Runtime scope and actor must exactly match the engagement input.")
        try:
            candidate = propose_service_engagement_invoice(inputs)
        except ValueError as exc:
            return self._blocked(request_digest=request_digest, code="INVOICE_NOT_ELIGIBLE", message=str(exc)[:500])
        return self._preview(
            output=candidate, request_digest=request_digest,
            external_refs={"candidate_digest": candidate.candidate_digest, "invoice_candidate_ref": candidate.invoice_candidate_ref, "total": str(candidate.total)},
            event_type="service.engagement_invoice_proposed",
            event_payload={"engagement_ref": scope.engagement_ref, "total": str(candidate.total), "currency": candidate.currency, "lines": len(candidate.lines), "invoice_issued": False},
            evidence_kind="service_engagement_invoice_candidate", evidence_summary="Invoice candidate for finance.create_invoice; not an issued invoice.",
            summary=f"Proposed invoice {candidate.invoice_candidate_ref} for {candidate.total} {candidate.currency}.",
        )


class AssessServiceEngagementPrimitive(_ServiceOpsPrimitive[ServiceEngagementAssessmentInput, ServiceEngagementAssessment]):
    primitive_ref = "service.assess_engagement"
    version = "0.1.0"
    title = "Assess a service engagement"
    description = "Report stage, linked value totals, uninvoiced accepted value, outstanding receivable, unbound deliverables, and the next governed action. Effect-dark."
    input_model = ServiceEngagementAssessmentInput
    output_model = ServiceEngagementAssessment
    risk_level = "low"
    operation_spec = ENGAGEMENT_ASSESS_OPERATION
    golden_loop = SERVICE_ENGAGEMENT_GOLDEN_LOOP
    example_inputs: Mapping[str, Any] = _LazyExample("assess_input")

    def _execute(self, context: PrimitiveExecutionContext, inputs: ServiceEngagementAssessmentInput) -> PrimitiveExecutionResult[ServiceEngagementAssessment]:
        request_digest = _request_digest(inputs.to_dict())
        scope = inputs.scope
        if not _scope_matches(scope.tenant_ref, scope.company_ref, scope.project_ref, scope.project_id, inputs.requested_by_ref, context):
            return self._blocked(request_digest=request_digest, code="SCOPE_MISMATCH", message="Runtime scope and actor must exactly match the engagement input.")
        assessment = assess_service_engagement(inputs)
        return self._preview(
            output=assessment, request_digest=request_digest,
            external_refs={"assessment_digest": assessment.assessment_digest, "stage": assessment.stage},
            event_type="service.engagement_assessed",
            event_payload={"engagement_ref": scope.engagement_ref, "stage": assessment.stage, "uninvoiced_accepted_value": str(assessment.uninvoiced_accepted_value), "outstanding_receivable": str(assessment.outstanding_receivable)},
            evidence_kind="service_engagement_assessment", evidence_summary="Effect-dark engagement assessment.",
            summary=f"Engagement {scope.engagement_ref} at {assessment.stage}; next: {assessment.next_actions[0]}.",
        )


SERVICE_OPERATIONS_EXECUTABLE_PRIMITIVES: tuple[BusinessProcessPrimitive[Any, Any], ...] = (
    PrepareBusinessArtifactGenerationPrimitive(),
    ValidateGeneratedBusinessArtifactPrimitive(),
    ProposeServiceEngagementTransitionPrimitive(),
    ProposeServiceEngagementInvoicePrimitive(),
    AssessServiceEngagementPrimitive(),
)


SERVICE_OPERATIONS_INTEGRATION_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.capability_pack_integration_manifest.v1",
    "capability_pack": "service_business_operations_and_artifact_production",
    "golden_loops": [SERVICE_ENGAGEMENT_GOLDEN_LOOP, BUSINESS_ARTIFACT_GOLDEN_LOOP],
    "modules": {
        "artifact_domain": "lightbulb.business_artifact_production",
        "engagement_domain": "lightbulb.service_engagement",
        "primitives": "lightbulb.service_operations_primitives",
        "mcp": "lightbulb.mcp_service_operations",
    },
    "stacked_on": {"branch": "fable/contract-delivery-acceptance-core"},
    "primitive_refs": [item.primitive_ref for item in SERVICE_OPERATIONS_EXECUTABLE_PRIMITIVES],
    "executable_registry": {
        "file": "lightbulb/executable_primitives.py",
        "import": "from lightbulb.service_operations_primitives import SERVICE_OPERATIONS_EXECUTABLE_PRIMITIVES",
        "splice": "*SERVICE_OPERATIONS_EXECUTABLE_PRIMITIVES in BUILTIN_EXECUTABLE_PRIMITIVES",
        "placement_hint": "after *CONTRACT_DELIVERY_EXECUTABLE_PRIMITIVES",
    },
    "mcp": {
        "file": "lightbulb/mcp_server.py",
        "registration": "from lightbulb.mcp_service_operations import register_service_operations; register_service_operations(mcp)",
        "tools": [
            "artifact_prepare_generation",
            "artifact_generate_with_host_model",
            "artifact_submit_generated",
            "artifact_list_kinds",
            "service_engagement_propose_transition",
            "service_engagement_propose_invoice",
            "service_engagement_assess",
        ],
        "resources": [
            "lightbulb://artifact-production/kinds",
            "lightbulb://artifact-production/legal-policy-schema",
            "lightbulb://service-engagement/stages",
        ],
        "delegation": (
            "artifact_generate_with_host_model uses the SDK executor interface: session sampling "
            "only when the client advertises the capability, otherwise a tool round-trip ticket the "
            "host model fulfils via artifact_submit_generated. No single protocol operation is baked "
            "into the business domain."
        ),
    },
    "public_exports": {
        "file": "lightbulb/__init__.py",
        "names": [
            "SERVICE_OPERATIONS_EXECUTABLE_PRIMITIVES",
            "SERVICE_OPERATIONS_INTEGRATION_MANIFEST",
            "PrepareBusinessArtifactGenerationPrimitive",
            "ValidateGeneratedBusinessArtifactPrimitive",
            "ProposeServiceEngagementTransitionPrimitive",
            "ProposeServiceEngagementInvoicePrimitive",
            "AssessServiceEngagementPrimitive",
            "ArtifactGenerationInput",
            "ArtifactGenerationRequest",
            "GeneratedBusinessArtifact",
            "LegalDocumentPolicy",
            "ServiceEngagementSnapshot",
            "ServiceEngagementInvoiceCandidate",
            "prepare_business_artifact_generation",
            "validate_generated_business_artifact",
            "materialize_service_engagement_transition",
            "propose_service_engagement_invoice",
            "assess_service_engagement",
        ],
    },
    "not_claimed": ["hosted execution", "artifact file writes (documents.generate_business_artifact remains the effect path)", "invoice issuance or settlement", "certification or production readiness"],
}


__all__ = [
    "ARTIFACT_PREPARE_OPERATION",
    "ARTIFACT_VALIDATE_OPERATION",
    "ENGAGEMENT_ASSESS_OPERATION",
    "ENGAGEMENT_INVOICE_OPERATION",
    "ENGAGEMENT_TRANSITION_OPERATION",
    "SERVICE_OPERATIONS_EXECUTABLE_PRIMITIVES",
    "SERVICE_OPERATIONS_INTEGRATION_MANIFEST",
    "AssessServiceEngagementPrimitive",
    "PrepareBusinessArtifactGenerationPrimitive",
    "ProposeServiceEngagementInvoicePrimitive",
    "ProposeServiceEngagementTransitionPrimitive",
    "ValidateGeneratedBusinessArtifactPrimitive",
    "example_artifact_generation_input",
]
