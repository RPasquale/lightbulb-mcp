"""Executable primitives for the commercial-to-legal handoff capability pack.

Three read-only proposal/validation primitives expose
``lightbulb.commercial_legal_handoff`` behind the canonical
``BusinessProcessPrimitive`` contract.  They compile a legal review packet
from an approved quote, validate a legal review outcome against that packet's
boundaries, and reconcile executed-agreement facts into one
``ExecutedCommercialAgreementCustodyCandidate`` plus its contract-to-cash,
service-delivery, and obligation-fulfillment projections.

None of them decides legal meaning or negotiation posture, mutates a sales
artifact, discards a legal deviation, signs anything, records custody, or
invokes a connector.  ``COMMERCIAL_LEGAL_HANDOFF_EXECUTABLE_PRIMITIVES`` is the
only tuple the central registry needs to splice in;
``COMMERCIAL_LEGAL_HANDOFF_INTEGRATION_MANIFEST`` records the deferred shared
surfaces.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any, Generic, TypeVar

from pydantic import BaseModel

from lightbulb.commercial_legal_handoff import (
    COMMERCIAL_LEGAL_HANDOFF_GOLDEN_LOOP,
    CommercialLegalHandoffEffectBoundary,
    CommercialLegalHandoffScope,
    ExecutedAgreementReconciliation,
    ExecutedAgreementReconciliationInput,
    LegalReviewOutcomeValidation,
    LegalReviewOutcomeValidationInput,
    LegalReviewPacket,
    LegalReviewPacketInput,
    compile_legal_review_packet,
    reconcile_executed_agreement,
    seal_legal_review_outcome,
    validate_legal_review_outcome,
)
from lightbulb.commercial_operations_lifecycle import (
    commercial_command_evidence_digest,
    materialize_commercial_operations_candidate,
    seal_commercial_command,
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


LEGAL_REVIEW_PACKET_OPERATION = _read_operation(
    "commercial_legal_compile_review_packet", "sdk.commercial.compile_legal_review_packet"
)
LEGAL_REVIEW_OUTCOME_OPERATION = _read_operation(
    "commercial_legal_validate_review_outcome", "sdk.commercial.validate_legal_review_outcome"
)
EXECUTED_AGREEMENT_RECONCILIATION_OPERATION = _read_operation(
    "commercial_legal_reconcile_executed_agreement",
    "sdk.commercial.reconcile_executed_agreement",
)

_AUTHORITY_BOUNDARY = {
    "sales_agent": "decides the commercial objective, quote economics, and when to request review",
    "legal_agent": "decides legal interpretation, negotiation posture, findings, and disposition",
    "sdk": (
        "defines the typed handoff, validates outcomes against packet boundaries, and "
        "reconciles executed facts; never decides law, mutates sales artifacts, or "
        "discards deviations"
    ),
    "spring": "authorizes approvals, retains executed agreement custody, persistence, audit",
    "connector_runtime": "document retrieval and approved e-signature or communication writes",
    "workflow": "observes signature, delivery, obligation, invoice, and collection outcomes",
    "mcp": "thin projection of the same three governed operations",
}


def _request_digest(payload: Mapping[str, Any]) -> str:
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _scope_matches_context(
    scope: CommercialLegalHandoffScope,
    requested_by_ref: str,
    context: PrimitiveExecutionContext,
) -> bool:
    runtime = context.scope
    commercial = scope.commercial
    return (
        commercial.tenant_ref == runtime.tenant_ref
        and commercial.company_ref == runtime.company_ref
        and commercial.project_ref == runtime.project_ref
        and runtime.project_id is not None
        and commercial.project_id == runtime.project_id
        and runtime.actor_ref is not None
        and requested_by_ref == runtime.actor_ref
    )


class _HandoffPrimitive(BusinessProcessPrimitive[InputT, OutputT], Generic[InputT, OutputT]):
    connector_tools = ()
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    operation_spec: PrimitiveOperationSpec
    golden_loop = COMMERCIAL_LEGAL_HANDOFF_GOLDEN_LOOP

    def implementation_contract(self) -> dict[str, Any]:
        contract = super().implementation_contract()
        contract["operation_contract"] = self.operation_spec.to_dict()
        contract["effect_boundary"] = CommercialLegalHandoffEffectBoundary().to_dict()
        contract["authority_boundary"] = dict(_AUTHORITY_BOUNDARY)
        contract["golden_loop"] = self.golden_loop
        contract["invariants"] = {
            "economic_change_forces_commercial_revision": True,
            "legal_cannot_mutate_sales_artifacts": True,
            "sales_cannot_discard_unresolved_deviations": True,
            "signed_agreement_must_match_reviewed_digest_and_signers": True,
            "only_custody_candidate_enters_authoritative_custody": True,
        }
        return contract

    def _scope_blocked(
        self, *, request_digest: str, evidence_refs: list[PrimitiveEvidenceRef]
    ) -> PrimitiveExecutionResult[OutputT]:
        blocker = PrimitiveBlocker(
            code="SCOPE_MISMATCH",
            message=(
                "Runtime tenant/company/project UUID and authenticated actor must be "
                "present and exactly match the handoff input."
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
        status = (
            PrimitiveExecutionStatus.BLOCKED if blocker is not None else PrimitiveExecutionStatus.PREVIEW
        )
        receipt = PrimitiveOperationReceipt(
            spec=self.operation_spec,
            status=(
                PrimitiveOperationStatus.BLOCKED if blocker is not None else PrimitiveOperationStatus.PREVIEW
            ),
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
                        "legal_determination_made": False,
                        "commercial_artifact_mutated": False,
                        "custody_recorded": False,
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


# --------------------------------------------------------------------------- #
# Deterministic example bundle (built from a real commercial lifecycle snapshot)
# --------------------------------------------------------------------------- #

_EXAMPLE_PROJECT_ID = "40100000-0000-4000-8000-000000000001"
_EXAMPLE_ACTOR = "actor-requester-example"
_EXAMPLE_COMMERCIAL_SCOPE = {
    "tenant_ref": "authenticated",
    "company_ref": "selected",
    "project_ref": "workflow-improvement",
    "project_id": _EXAMPLE_PROJECT_ID,
    "customer_ref": "customer-example",
    "product_ref": "product-example",
    "currency": "USD",
}


def _digest_of(seed: str) -> str:
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def _example_quote_proposed_snapshot() -> dict[str, Any]:
    transition_ref = "transition-quote-example"
    occurred_at = "2026-08-25T09:00:00Z"
    command: dict[str, Any] = {
        "kind": "propose_quote",
        "scope": dict(_EXAMPLE_COMMERCIAL_SCOPE),
        "transition_ref": transition_ref,
        "idempotency_key": "idem-transition-quote-example",
        "requested_by_ref": _EXAMPLE_ACTOR,
        "expected_version": 0,
        "expected_snapshot_digest": "0" * 64,
        "occurred_at": occurred_at,
        "configuration": {
            "schema": "lightbulb.commercial_configuration_snapshot.v1",
            "configuration_ref": "configuration-example",
            "revision": 1,
            "account_ref": "customer-example",
            "status": "validated",
            "price_book_ref": "price-book-example",
            "currency": "USD",
            "effective_at": "2026-08-25T00:00:00Z",
            "expires_at": "2027-08-25T00:00:00Z",
            "lines": [
                {
                    "configuration_line_ref": "configuration-line-example",
                    "product_ref": "product-example",
                    "quantity": "2.000000",
                    "list_unit_price": "100.000000",
                    "configured_unit_price": "90.000000",
                    "discount_ratio": "0.100000",
                    "option_refs": ["option-support"],
                }
            ],
            "evidence_refs": ["evidence-cpq-example", "evidence-pricing-example"],
        },
        "quote": {
            "schema": "lightbulb.commercial_quote_snapshot.v1",
            "quote_ref": "quote-example",
            "revision": 1,
            "configuration_ref": "configuration-example",
            "account_ref": "customer-example",
            "status": "pending_approval",
            "currency": "USD",
            "valid_until": "2026-09-25T00:00:00Z",
            "subtotal": "180.000000",
            "tax_total": "0.000000",
            "total": "180.000000",
            "approval_required": True,
            "approval_status": "pending",
            "prepared_by_ref": "actor-seller-example",
            "lines": [
                {
                    "quote_line_ref": "quote-line-example",
                    "configuration_line_ref": "configuration-line-example",
                    "product_ref": "product-example",
                    "quantity": "2.000000",
                    "unit_price": "90.000000",
                    "line_total": "180.000000",
                }
            ],
            "evidence_refs": ["evidence-pricing-example"],
        },
        "configured_by_ref": "actor-seller-example",
        "configuration_evidence_ref": "evidence-cpq-example",
        "pricing_evidence_ref": "evidence-pricing-example",
        "evidence_refs": [
            {
                "schema": "lightbulb.primitive_evidence_ref.v1",
                "evidence_ref": evidence_ref,
                "kind": kind,
                "issuer_ref": "authoritative-host-example",
                "subject_ref": transition_ref,
                "sha256": "0" * 64,
                "observed_at": occurred_at,
                "verification_grade": "attested",
                "classification": "confidential",
            }
            for evidence_ref, kind in (
                ("evidence-cpq-example", "cpq_configuration"),
                ("evidence-pricing-example", "pricing"),
            )
        ],
    }
    digest = commercial_command_evidence_digest(command)
    for evidence in command["evidence_refs"]:
        evidence["sha256"] = digest
    result = materialize_commercial_operations_candidate(
        {
            "scope": dict(_EXAMPLE_COMMERCIAL_SCOPE),
            "command": seal_commercial_command(command),
            "current_snapshot": None,
        }
    )
    assert result.snapshot is not None
    return result.snapshot.to_dict()


class _ExampleBundle:
    def __init__(self) -> None:
        self._built: dict[str, Any] | None = None

    def get(self) -> dict[str, Any]:
        if self._built is not None:
            return self._built
        snapshot = _example_quote_proposed_snapshot()
        scope = {
            "commercial": dict(_EXAMPLE_COMMERCIAL_SCOPE),
            "opportunity_ref": "opportunity-example",
            "evidence_custody_ref": "custody-example",
            "authorized_evidence_issuer_refs": [
                "spring-example",
                "esign-host-example",
                "legal-host-example",
            ],
        }
        approved_quote = {
            **snapshot["quote"],
            "revision": 2,
            "status": "accepted",
            "approval_status": "approved",
            "approved_by_ref": "actor-sales-manager-example",
            "evidence_refs": ["evidence-quote-approval-example"],
        }
        draft_order = {
            "schema": "lightbulb.commercial_order_snapshot.v1",
            "order_ref": "order-example",
            "revision": 1,
            "quote_ref": "quote-example",
            "contract_ref": "contract-example",
            "account_ref": "customer-example",
            "status": "draft",
            "currency": "USD",
            "total": "180.000000",
            "lines": [
                {
                    "order_line_ref": "order-line-example",
                    "quote_line_ref": "quote-line-example",
                    "product_ref": "product-example",
                    "quantity": "2.000000",
                    "unit_price": "90.000000",
                    "line_total": "180.000000",
                }
            ],
            "evidence_refs": ["evidence-order-example"],
        }
        draft_contract = {
            "schema": "lightbulb.commercial_contract_snapshot.v1",
            "contract_ref": "contract-example",
            "revision": 1,
            "quote_ref": "quote-example",
            "order_ref": "order-example",
            "account_ref": "customer-example",
            "status": "pending_signature",
            "currency": "USD",
            "contract_value": "180.000000",
            "effective_at": "2026-09-01T00:00:00Z",
            "expires_at": "2027-08-31T00:00:00Z",
            "signature_status": "pending",
            "required_signer_refs": ["signer-company-example", "signer-customer-example"],
            "completed_signer_refs": [],
            "amendment_pending": False,
            "evidence_refs": [],
        }
        packet_input = {
            "scope": scope,
            "commercial_snapshot": snapshot,
            "approved_quote": approved_quote,
            "draft_order": draft_order,
            "draft_contract": draft_contract,
            "agreement_package": [
                {
                    "document_kind": "msa",
                    "artifact_ref": "document-msa-example",
                    "artifact_digest": _digest_of("msa:v1"),
                    "version": 1,
                },
                {
                    "document_kind": "order_form",
                    "artifact_ref": "document-order-form-example",
                    "artifact_digest": _digest_of("order-form:v1"),
                    "version": 1,
                },
            ],
            "commercial_terms": {
                "entitlements": [
                    {
                        "order_line_ref": "order-line-example",
                        "product_ref": "product-example",
                        "quantity": "2.000000",
                        "unit_price": "90.000000",
                    }
                ],
                "delivery": {
                    "delivery_model": "saas",
                    "start_at": "2026-09-01T00:00:00Z",
                    "milestones": [
                        {
                            "milestone_ref": "milestone-go-live-example",
                            "description": "Production tenant live",
                            "due_at": "2026-09-15T00:00:00Z",
                        }
                    ],
                },
                "acceptance": {"acceptance_window_days": 10, "criteria_refs": ["acceptance-example"]},
                "billing": {
                    "billing_model": "flat",
                    "frequency": "annually",
                    "payment_terms_days": 30,
                    "currency": "USD",
                    "total": "180.000000",
                    "invoicing_trigger": "signature",
                },
                "renewal": {"auto_renew": True, "term_months": 12, "notice_days": 60},
                "termination": {"for_convenience": False, "notice_days": 30, "cure_days": 30},
                "notice": {"channel": "email", "address_ref": "notice-address-example"},
            },
            "jurisdiction_ref": "US-DE",
            "required_playbook_refs": ["playbook-liability-example", "playbook-standard-example"],
            "negotiation_boundaries": [
                {"term_path": "price", "boundary": "fixed"},
                {
                    "term_path": "liability",
                    "boundary": "negotiable_within_policy",
                    "policy_ref": "playbook-liability-example",
                },
            ],
            "required_reviewer_refs": ["actor-legal-example"],
            "required_approvals": [
                {
                    "approval_kind": "finance",
                    "approver_role_ref": "role-finance-example",
                    "reason": "Non-standard payment terms",
                }
            ],
            "requested_completion_at": "2026-09-05T00:00:00Z",
            "source_artifact_refs": ["document-msa-example", "document-order-form-example"],
            "requested_by_ref": _EXAMPLE_ACTOR,
        }
        packet = compile_legal_review_packet(packet_input)
        outcome = seal_legal_review_outcome(
            {
                "packet_digest": packet.packet_digest,
                "reviewed_documents": [
                    {
                        "document_kind": "msa",
                        "artifact_ref": "document-msa-example",
                        "version": 2,
                        "artifact_digest": _digest_of("msa:v2"),
                    },
                    {
                        "document_kind": "order_form",
                        "artifact_ref": "document-order-form-example",
                        "version": 1,
                        "artifact_digest": _digest_of("order-form:v1"),
                    },
                ],
                "findings": [
                    {
                        "finding_ref": "finding-liability-example",
                        "document_kind": "msa",
                        "clause_ref": "12.1",
                        "clause_text_digest": _digest_of("clause:12.1"),
                        "source_evidence_ref": "document-msa-example",
                        "category": "liability",
                        "severity": "medium",
                        "description": "Liability cap raised to twelve months of fees",
                    },
                    {
                        "finding_ref": "finding-reporting-example",
                        "document_kind": "msa",
                        "clause_ref": "7.2",
                        "clause_text_digest": _digest_of("clause:7.2"),
                        "source_evidence_ref": "document-msa-example",
                        "category": "other",
                        "severity": "low",
                        "description": "Monthly usage reporting commitment",
                    },
                ],
                "accepted_deviations": [
                    {
                        "deviation_ref": "deviation-liability-example",
                        "finding_ref": "finding-liability-example",
                        "term_path": "liability",
                        "playbook_ref": "playbook-liability-example",
                        "accepted_by_ref": "actor-legal-example",
                        "rationale": "Within the liability playbook envelope",
                    }
                ],
                "signature_readiness": "ready",
                "required_signer_refs": ["signer-company-example", "signer-customer-example"],
                "proposed_obligations": [
                    {
                        "obligation_ref": "obligation-monthly-report-example",
                        "document_kind": "msa",
                        "clause_ref": "7.2",
                        "clause_text_digest": _digest_of("clause:7.2"),
                        "source_evidence_ref": "document-msa-example",
                        "kind": "reporting",
                        "direction": "owed_by_company",
                        "title": "Deliver the monthly usage report",
                        "summary": "Usage report delivered to the counterparty portal each month",
                    }
                ],
                "disposition": "approved",
                "reviewed_by_ref": "actor-legal-example",
                "reviewed_at": "2026-09-03T00:00:00Z",
                "review_evidence": {
                    "schema": "lightbulb.primitive_evidence_ref.v1",
                    "evidence_ref": "evidence-legal-review-example",
                    "kind": "legal_review",
                    "issuer_ref": "legal-host-example",
                    "subject_ref": packet.packet_digest,
                    "sha256": packet.packet_digest,
                    "observed_at": "2026-09-03T00:00:00Z",
                    "verification_grade": "attested",
                    "classification": "confidential",
                },
            }
        )
        validation_input = {
            "scope": scope,
            "packet": packet.to_dict(),
            "outcome": outcome,
            "requested_by_ref": _EXAMPLE_ACTOR,
        }
        validation = validate_legal_review_outcome(validation_input)

        def signature(signer_ref: str, signed_at: str) -> dict[str, Any]:
            return {
                "signer_ref": signer_ref,
                "signed_at": signed_at,
                "document_kind": "msa",
                "artifact_digest": _digest_of("msa:v2"),
                "evidence": {
                    "schema": "lightbulb.primitive_evidence_ref.v1",
                    "evidence_ref": f"evidence-signature-{signer_ref}",
                    "kind": "contract_signature",
                    "issuer_ref": "esign-host-example",
                    "subject_ref": "contract-example",
                    "sha256": _digest_of(f"signature:{signer_ref}"),
                    "observed_at": signed_at,
                    "verification_grade": "verified",
                    "classification": "confidential",
                },
            }

        reconciliation_input = {
            "scope": scope,
            "packet": packet.to_dict(),
            "outcome": outcome,
            "validation": validation.to_dict(),
            "current_commercial_snapshot": snapshot,
            "executed_documents": [
                {
                    "document_kind": "msa",
                    "artifact_ref": "document-msa-example",
                    "version": 2,
                    "artifact_digest": _digest_of("msa:v2"),
                    "executed_at": "2026-09-04T01:00:00Z",
                },
                {
                    "document_kind": "order_form",
                    "artifact_ref": "document-order-form-example",
                    "version": 1,
                    "artifact_digest": _digest_of("order-form:v1"),
                    "executed_at": "2026-09-04T01:00:00Z",
                },
            ],
            "signatures": [
                signature("signer-company-example", "2026-09-04T00:00:00Z"),
                signature("signer-customer-example", "2026-09-04T01:00:00Z"),
            ],
            "reconciled_at": "2026-09-04T02:00:00Z",
            "requested_by_ref": _EXAMPLE_ACTOR,
        }
        self._built = {
            "packet_input": packet_input,
            "validation_input": validation_input,
            "reconciliation_input": reconciliation_input,
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


class CompileLegalReviewPacketPrimitive(_HandoffPrimitive[LegalReviewPacketInput, LegalReviewPacket]):
    primitive_ref = "commercial.compile_legal_review_packet"
    version = "0.1.0"
    title = "Compile a typed legal review packet from an approved quote"
    description = (
        "Bind the opportunity, customer, approved quote, draft order, draft contract, "
        "agreement package, commercial term sheet, jurisdiction, playbooks, negotiation "
        "boundaries, reviewers, approvals, deadline, and source artifact references into "
        "one sealed packet with an exact approved-commercial-terms digest."
    )
    input_model = LegalReviewPacketInput
    output_model = LegalReviewPacket
    risk_level = "medium"
    operation_spec = LEGAL_REVIEW_PACKET_OPERATION
    example_inputs: Mapping[str, Any] = _LazyExample("packet_input")

    def _execute(
        self, context: PrimitiveExecutionContext, inputs: LegalReviewPacketInput
    ) -> PrimitiveExecutionResult[LegalReviewPacket]:
        request_digest = _request_digest(inputs.to_dict())
        if not _scope_matches_context(inputs.scope, inputs.requested_by_ref, context):
            return self._scope_blocked(request_digest=request_digest, evidence_refs=[])
        packet = compile_legal_review_packet(inputs)
        return self._result(
            output=packet,
            request_digest=request_digest,
            evidence_refs=[],
            external_refs={
                "packet_digest": packet.packet_digest,
                "commercial_terms_digest": packet.commercial_terms_digest,
                "contract_ref": packet.contract_ref,
            },
            event_type="commercial.legal_review_packet_compiled",
            event_payload={
                "opportunity_ref": packet.opportunity_ref,
                "quote_ref": packet.quote_ref,
                "quote_revision": packet.quote_revision,
                "contract_ref": packet.contract_ref,
                "documents": len(packet.agreement_package),
                "required_reviewers": len(packet.required_reviewer_refs),
            },
            evidence_kind="commercial_legal_review_packet",
            evidence_summary="Sealed review packet; legal review, approvals, and custody remain Spring-governed.",
            summary=(
                f"Compiled legal review packet for {packet.contract_ref} "
                f"(quote {packet.quote_ref} r{packet.quote_revision})."
            ),
        )


class ValidateLegalReviewOutcomePrimitive(
    _HandoffPrimitive[LegalReviewOutcomeValidationInput, LegalReviewOutcomeValidation]
):
    primitive_ref = "commercial.validate_legal_review_outcome"
    version = "0.1.0"
    title = "Validate a legal review outcome against its packet"
    description = (
        "Check a legal agent's typed outcome (reviewed versions, findings, accepted and "
        "unresolved deviations, changed terms, approvals, signature readiness, signers, "
        "proposed obligations, disposition) against the packet's boundaries. Reports "
        "violations and whether a commercial revision is forced; never re-decides law."
    )
    input_model = LegalReviewOutcomeValidationInput
    output_model = LegalReviewOutcomeValidation
    risk_level = "medium"
    operation_spec = LEGAL_REVIEW_OUTCOME_OPERATION
    example_inputs: Mapping[str, Any] = _LazyExample("validation_input")

    def _execute(
        self, context: PrimitiveExecutionContext, inputs: LegalReviewOutcomeValidationInput
    ) -> PrimitiveExecutionResult[LegalReviewOutcomeValidation]:
        request_digest = _request_digest(inputs.to_dict())
        evidence_refs = [inputs.outcome.review_evidence]
        if not _scope_matches_context(inputs.scope, inputs.requested_by_ref, context):
            return self._scope_blocked(request_digest=request_digest, evidence_refs=evidence_refs)
        validation = validate_legal_review_outcome(inputs)
        blocker = None
        if not validation.accepted:
            blocker = PrimitiveBlocker(
                code=validation.violations[0].code,
                message=validation.violations[0].detail,
                field="outcome",
                retryable=False,
            )
        return self._result(
            output=validation,
            request_digest=request_digest,
            evidence_refs=evidence_refs,
            external_refs={
                "validation_digest": validation.validation_digest,
                "packet_digest": validation.packet_digest,
                "outcome_digest": validation.outcome_digest,
            },
            event_type="commercial.legal_review_outcome_validated",
            event_payload={
                "accepted": validation.accepted,
                "effective_disposition": validation.effective_disposition,
                "violations": [item.code for item in validation.violations],
                "commercial_revision_required": validation.commercial_revision_required,
                "deviation_discarded": False,
            },
            evidence_kind="commercial_legal_review_outcome_validation",
            evidence_summary="Structural validation of a legal outcome; not a legal determination.",
            summary=(
                "Legal review outcome accepted against the packet boundaries."
                if validation.accepted
                else f"Legal review outcome violates the packet: {len(validation.violations)} violation(s)."
            ),
            blocker=blocker,
        )


class ReconcileExecutedAgreementPrimitive(
    _HandoffPrimitive[ExecutedAgreementReconciliationInput, ExecutedAgreementReconciliation]
):
    primitive_ref = "commercial.reconcile_executed_agreement"
    version = "0.1.0"
    title = "Reconcile an executed agreement into a custody candidate"
    description = (
        "Reconcile the packet, validated legal outcome, current commercial snapshot, "
        "executed document digests, and verified signatures. Changed economics force a "
        "commercial revision, unresolved deviations block, digest or signer mismatches "
        "reject, and the only success is an ExecutedCommercialAgreementCustodyCandidate "
        "with contract-to-cash, service-delivery, and obligation-fulfillment projections."
    )
    input_model = ExecutedAgreementReconciliationInput
    output_model = ExecutedAgreementReconciliation
    risk_level = "high"
    operation_spec = EXECUTED_AGREEMENT_RECONCILIATION_OPERATION
    example_inputs: Mapping[str, Any] = _LazyExample("reconciliation_input")

    def _execute(
        self, context: PrimitiveExecutionContext, inputs: ExecutedAgreementReconciliationInput
    ) -> PrimitiveExecutionResult[ExecutedAgreementReconciliation]:
        request_digest = _request_digest(inputs.to_dict())
        evidence_refs = [inputs.outcome.review_evidence, *(item.evidence for item in inputs.signatures)]
        if not _scope_matches_context(inputs.scope, inputs.requested_by_ref, context):
            return self._scope_blocked(request_digest=request_digest, evidence_refs=evidence_refs)
        reconciliation = reconcile_executed_agreement(inputs)
        blocker = None
        external_refs: dict[str, str] = {
            "reconciliation_digest": reconciliation.reconciliation_digest,
            "disposition": reconciliation.disposition,
        }
        if reconciliation.custody_candidate is not None:
            external_refs["custody_candidate_digest"] = reconciliation.custody_candidate.custody_candidate_digest
            external_refs["executed_agreement_digest"] = reconciliation.custody_candidate.executed_agreement_digest
        else:
            blocker = PrimitiveBlocker(
                code=reconciliation.blockers[0].code,
                message=reconciliation.blockers[0].detail,
                retryable=False,
            )
        return self._result(
            output=reconciliation,
            request_digest=request_digest,
            evidence_refs=evidence_refs,
            external_refs=external_refs,
            event_type="commercial.executed_agreement_reconciled",
            event_payload={
                "disposition": reconciliation.disposition,
                "blockers": [item.code for item in reconciliation.blockers],
                "contract_ref": inputs.packet.contract_ref,
                "signature_performed": False,
                "deviation_discarded": False,
            },
            evidence_kind="executed_agreement_reconciliation",
            evidence_summary=(
                "Portable custody candidate or blocker set; Spring decides custody, approvals, and effects."
            ),
            summary=(
                f"Executed agreement {inputs.packet.contract_ref} reconciled into a custody candidate."
                if reconciliation.custody_candidate is not None
                else f"Executed agreement reconciliation blocked: {reconciliation.disposition}."
            ),
            blocker=blocker,
        )


COMMERCIAL_LEGAL_HANDOFF_EXECUTABLE_PRIMITIVES: tuple[BusinessProcessPrimitive[Any, Any], ...] = (
    CompileLegalReviewPacketPrimitive(),
    ValidateLegalReviewOutcomePrimitive(),
    ReconcileExecutedAgreementPrimitive(),
)


COMMERCIAL_LEGAL_HANDOFF_INTEGRATION_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.capability_pack_integration_manifest.v1",
    "capability_pack": "commercial_legal_handoff",
    "golden_loop": COMMERCIAL_LEGAL_HANDOFF_GOLDEN_LOOP,
    "golden_loop_lifecycle": [
        "sales opportunity / approved quote",
        "typed legal review packet",
        "legal review and negotiation outcome",
        "commercial reconciliation",
        "executed agreement custody candidate",
        "projections: contract-to-cash (review_contract_order), project/service delivery, contract-obligation fulfillment",
    ],
    "modules": {
        "domain": "lightbulb.commercial_legal_handoff",
        "primitives": "lightbulb.commercial_legal_handoff_primitives",
    },
    "reuses": [
        "lightbulb.commercial_operations_lifecycle.CommercialLifecycleScope",
        "lightbulb.commercial_operations_lifecycle.CommercialOperationsLifecycleSnapshot",
        "lightbulb.commercial_controls.CommercialQuoteSnapshot",
        "lightbulb.commercial_controls.CommercialOrderSnapshot",
        "lightbulb.commercial_controls.CommercialContractSnapshot",
        "lightbulb.primitive_runtime.PrimitiveEvidenceRef",
    ],
    "primitive_refs": [item.primitive_ref for item in COMMERCIAL_LEGAL_HANDOFF_EXECUTABLE_PRIMITIVES],
    "executable_registry": {
        "file": "lightbulb/executable_primitives.py",
        "import": (
            "from lightbulb.commercial_legal_handoff_primitives import "
            "COMMERCIAL_LEGAL_HANDOFF_EXECUTABLE_PRIMITIVES"
        ),
        "splice": "*COMMERCIAL_LEGAL_HANDOFF_EXECUTABLE_PRIMITIVES in BUILTIN_EXECUTABLE_PRIMITIVES",
        "placement_hint": "after *COMMERCIAL_OPERATIONS_LIFECYCLE_EXECUTABLE_PRIMITIVES",
    },
    "public_exports": {
        "file": "lightbulb/__init__.py",
        "names": [
            "COMMERCIAL_LEGAL_HANDOFF_EXECUTABLE_PRIMITIVES",
            "COMMERCIAL_LEGAL_HANDOFF_GOLDEN_LOOP",
            "COMMERCIAL_LEGAL_HANDOFF_INTEGRATION_MANIFEST",
            "CompileLegalReviewPacketPrimitive",
            "ValidateLegalReviewOutcomePrimitive",
            "ReconcileExecutedAgreementPrimitive",
            "CommercialLegalHandoffScope",
            "LegalReviewPacket",
            "LegalReviewOutcome",
            "LegalReviewOutcomeValidation",
            "ExecutedCommercialAgreementCustodyCandidate",
            "ExecutedAgreementReconciliation",
            "ContractToCashProjection",
            "ServiceDeliveryProjection",
            "ObligationFulfillmentProjection",
            "compile_legal_review_packet",
            "validate_legal_review_outcome",
            "reconcile_executed_agreement",
            "seal_legal_review_outcome",
        ],
    },
    "catalog": {
        "file": "lightbulb/business_primitives.py",
        "note": (
            "No Backbone catalog entry is required; registry membership makes the pack "
            "discoverable through sdk_only_business_primitive_capability_projections()."
        ),
    },
    "mcp": {
        "file": "lightbulb/mcp_server.py",
        "note": "No hand-written MCP tool; the generic run_sdk_business_primitive projection applies.",
    },
    "spring": {
        "note": (
            "Spring owns the authoritative executed-agreement custody record. The custody "
            "candidate is the only input Spring should accept for that record; projections "
            "are derived views, never a second source of truth."
        ),
    },
    "not_claimed": [
        "hosted execution",
        "Spring custody persistence or RBAC",
        "e-signature or connector writes",
        "certification or production readiness",
    ],
}


__all__ = [
    "COMMERCIAL_LEGAL_HANDOFF_EXECUTABLE_PRIMITIVES",
    "COMMERCIAL_LEGAL_HANDOFF_INTEGRATION_MANIFEST",
    "EXECUTED_AGREEMENT_RECONCILIATION_OPERATION",
    "LEGAL_REVIEW_OUTCOME_OPERATION",
    "LEGAL_REVIEW_PACKET_OPERATION",
    "CompileLegalReviewPacketPrimitive",
    "ReconcileExecutedAgreementPrimitive",
    "ValidateLegalReviewOutcomePrimitive",
]
