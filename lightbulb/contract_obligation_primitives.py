"""Executable primitives for the contract-obligation capability pack.

Five proposal/validation primitives expose the deterministic mechanics in
``lightbulb.contract_obligations`` behind the canonical
``BusinessProcessPrimitive`` contract.  Every primitive is read-only,
declares zero connector Tools, and returns a portable candidate that Spring
must still authorize, persist, and act on.  None of them decides legal
meaning, declares breach, waives an obligation, contacts a counterparty, or
moves money.

The pack is intentionally self-contained: ``CONTRACT_OBLIGATION_EXECUTABLE_PRIMITIVES``
is the only tuple the central executable registry needs to splice in, and
``CONTRACT_OBLIGATION_INTEGRATION_MANIFEST`` records exactly which shared
surfaces the final integration commit must touch.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any, Generic, TypeVar

from pydantic import BaseModel

from lightbulb.connector_execution import ConnectorEffect
from lightbulb.commercial_legal_handoff import reconcile_executed_agreement
from lightbulb.commercial_legal_handoff_primitives import (
    ReconcileExecutedAgreementPrimitive as _ReconcileExecutedAgreementPrimitive,
)
from lightbulb.contract_obligation_intake import (
    ContractObligationIntakeInput,
    ContractObligationRoutingInput,
    ObligationRoutingPlan,
    build_contract_obligation_normalization_input,
    route_contract_obligation_register,
)
from lightbulb.contract_obligations import (
    CONTRACT_OBLIGATION_GOLDEN_LOOP,
    MAX_OBLIGATION_TRANSITIONS,
    ContractObligationEffectBoundary,
    ContractObligationEvaluationInput,
    ContractObligationNormalizationInput,
    ContractObligationPortfolioAssessment,
    ContractObligationPortfolioInput,
    ContractObligationScheduleInput,
    ContractObligationScope,
    ContractObligationTransitionInput,
    ContractObligationTransitionResult,
    ObligationFulfillmentEvaluation,
    ObligationRegister,
    ObligationSchedule,
    assess_contract_obligation_portfolio,
    compile_contract_obligation_schedule,
    evaluate_contract_obligation_fulfillment,
    genesis_instance_state_digest,
    materialize_contract_obligation_transition,
    normalize_contract_obligation_candidates,
    seal_contract_obligation_command,
)
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


InputT = TypeVar("InputT", bound=BaseModel)
OutputT = TypeVar("OutputT", bound=BaseModel)


def _read_operation(
    operation_ref: str,
    tool: str,
    *,
    freshness: PrimitiveOperationFreshnessClass,
) -> PrimitiveOperationSpec:
    return PrimitiveOperationSpec(
        operation_ref=operation_ref,
        tool=tool,
        effect=ConnectorEffect.READ,
        approval_required=False,
        replay_class=PrimitiveOperationReplayClass.SAFE,
        freshness_class=freshness,
        recovery_policy=PrimitiveOperationRecoveryPolicy.NONE,
    )


CONTRACT_OBLIGATION_NORMALIZE_OPERATION = _read_operation(
    "contract_obligation_normalize_candidates",
    "sdk.legal.normalize_contract_obligation_candidates",
    freshness=PrimitiveOperationFreshnessClass.CURRENT,
)
CONTRACT_OBLIGATION_SCHEDULE_OPERATION = _read_operation(
    "contract_obligation_compile_schedule",
    "sdk.legal.compile_contract_obligation_schedule",
    freshness=PrimitiveOperationFreshnessClass.BOUNDED,
)
CONTRACT_OBLIGATION_EVALUATE_OPERATION = _read_operation(
    "contract_obligation_evaluate_fulfillment",
    "sdk.legal.evaluate_contract_obligation_fulfillment",
    freshness=PrimitiveOperationFreshnessClass.CURRENT,
)
CONTRACT_OBLIGATION_PORTFOLIO_OPERATION = _read_operation(
    "contract_obligation_assess_portfolio",
    "sdk.legal.assess_contract_obligation_portfolio",
    freshness=PrimitiveOperationFreshnessClass.BOUNDED,
)
CONTRACT_OBLIGATION_INTAKE_OPERATION = _read_operation(
    "contract_obligation_intake_from_custody",
    "sdk.legal.intake_contract_obligations_from_custody",
    freshness=PrimitiveOperationFreshnessClass.CURRENT,
)
CONTRACT_OBLIGATION_ROUTING_OPERATION = _read_operation(
    "contract_obligation_route_register",
    "sdk.legal.route_contract_obligation_register",
    freshness=PrimitiveOperationFreshnessClass.CURRENT,
)
CONTRACT_OBLIGATION_TRANSITION_OPERATION = PrimitiveOperationSpec(
    operation_ref="contract_obligation_propose_transition",
    tool="sdk.legal.propose_contract_obligation_transition",
    effect=ConnectorEffect.READ,
    approval_required=False,
    replay_class=PrimitiveOperationReplayClass.NEVER,
    freshness_class=PrimitiveOperationFreshnessClass.CURRENT,
    recovery_policy=PrimitiveOperationRecoveryPolicy.MANUAL_RECONCILIATION,
)

_AUTHORITY_BOUNDARY = {
    "legal_or_commercial_agent": (
        "interprets clauses, proposes obligations, chooses evidence, and decides "
        "when to request a transition"
    ),
    "sdk": (
        "validates, schedules, evaluates, and proposes typed obligation mechanics; "
        "never decides legal meaning, breach, waiver, or scope"
    ),
    "spring": (
        "identity, RBAC, the obligation register of record, review and approval, "
        "evidence custody, persistence, schedules, and every transition of record"
    ),
    "connector_runtime": (
        "retrieves documents and performs approved communications, task, and "
        "calendar writes"
    ),
    "workflow": "observes deadlines and evidence and invokes bounded transitions",
    "mcp": (
        "thin discovery, preview, assessment, and governed transition-request "
        "projection over these primitive contracts"
    ),
}


def _request_digest(payload: Mapping[str, Any]) -> str:
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _scope_matches_context(
    scope: ContractObligationScope,
    requested_by_ref: str,
    context: PrimitiveExecutionContext,
    *,
    idempotency_key: str | None = None,
) -> bool:
    runtime = context.scope
    matched = (
        scope.tenant_ref == runtime.tenant_ref
        and scope.company_ref == runtime.company_ref
        and scope.project_ref == runtime.project_ref
        and runtime.project_id is not None
        and scope.project_id == runtime.project_id
        and runtime.actor_ref is not None
        and requested_by_ref == runtime.actor_ref
    )
    if idempotency_key is not None:
        matched = matched and (
            context.idempotency_key is not None
            and idempotency_key == context.idempotency_key
        )
    return matched


def _scope_blocked_result(
    primitive: "_ContractObligationPrimitive[Any, Any]",
    *,
    spec: PrimitiveOperationSpec,
    request_digest: str,
    evidence_refs: list[PrimitiveEvidenceRef],
) -> PrimitiveExecutionResult[Any]:
    blocker = PrimitiveBlocker(
        code="SCOPE_MISMATCH",
        message=(
            "Runtime tenant/company/project UUID and authenticated actor (and the "
            "idempotency key for transitions) must be present and exactly match "
            "the contract-obligation input."
        ),
        field="scope",
        retryable=False,
    )
    return PrimitiveExecutionResult[Any](
        status=PrimitiveExecutionStatus.BLOCKED,
        primitive_ref=primitive.primitive_ref,
        primitive_version=primitive.version,
        summary=f"{primitive.title} rejected at the scope boundary.",
        blockers=[blocker],
        evidence_refs=evidence_refs,
        operation_receipts=[
            PrimitiveOperationReceipt(
                spec=spec,
                status=PrimitiveOperationStatus.BLOCKED,
                request_digest=request_digest,
                evidence_refs=evidence_refs,
                error=blocker,
            )
        ],
    )


class _ContractObligationPrimitive(BusinessProcessPrimitive[InputT, OutputT], Generic[InputT, OutputT]):
    connector_tools = ()
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    operation_spec: PrimitiveOperationSpec
    golden_loop = CONTRACT_OBLIGATION_GOLDEN_LOOP

    def implementation_contract(self) -> dict[str, Any]:
        contract = super().implementation_contract()
        contract["operation_contract"] = self.operation_spec.to_dict()
        contract["effect_boundary"] = ContractObligationEffectBoundary().to_dict()
        contract["authority_boundary"] = dict(_AUTHORITY_BOUNDARY)
        contract["golden_loop"] = self.golden_loop
        return contract

    def _preview_result(
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
        receipt = PrimitiveOperationReceipt(
            spec=self.operation_spec,
            status=(
                PrimitiveOperationStatus.BLOCKED
                if blocker is not None
                else PrimitiveOperationStatus.PREVIEW
            ),
            request_digest=request_digest,
            evidence_refs=evidence_refs,
            external_refs=dict(external_refs),
            error=blocker,
        )
        return PrimitiveExecutionResult[OutputT](
            status=(
                PrimitiveExecutionStatus.BLOCKED
                if blocker is not None
                else PrimitiveExecutionStatus.PREVIEW
            ),
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
# Shared deterministic example bundle
# --------------------------------------------------------------------------- #

_EXAMPLE_PROJECT_ID = "40100000-0000-4000-8000-000000000001"
_EXAMPLE_ACTOR = "actor-requester-example"
_EXAMPLE_IDEMPOTENCY_KEY = "idem-obligation-transition-example"


def _digest_of(seed: str) -> str:
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def _example_scope() -> dict[str, Any]:
    return {
        "tenant_ref": "authenticated",
        "company_ref": "selected",
        "project_ref": "workflow-improvement",
        "project_id": _EXAMPLE_PROJECT_ID,
        "agreement_ref": "agreement-example",
        "evidence_custody_ref": "custody-example",
        "authorized_evidence_issuer_refs": ["spring-example", "clm-host-example"],
    }


def _example_agreement() -> dict[str, Any]:
    return {
        "agreement_ref": "agreement-example",
        "version": 1,
        "agreement_digest": _digest_of("agreement-example:v1"),
        "approval_evidence_ref": "approval-example",
        "approved_at": "2026-01-15T00:00:00Z",
        "effective_at": "2026-02-01T00:00:00Z",
        "expires_at": "2027-01-31T00:00:00Z",
    }


def _example_normalization_input() -> dict[str, Any]:
    policy = {
        "escalate_after_overdue_days": 5,
        "escalate_to_role_ref": "role-legal-ops-example",
        "max_exception_days": 30,
    }
    return {
        "scope": _example_scope(),
        "agreement": _example_agreement(),
        "clause_index": [
            {
                "clause_ref": "7.2",
                "heading": "Monthly reporting",
                "clause_text_digest": _digest_of("clause:7.2"),
                "source_evidence_ref": "document-agreement-example-v1",
            },
            {
                "clause_ref": "9.1",
                "heading": "Annual fee",
                "clause_text_digest": _digest_of("clause:9.1"),
                "source_evidence_ref": "document-agreement-example-v1",
            },
        ],
        "candidates": [
            {
                "candidate_ref": "candidate-report-example",
                "obligation_ref": "obligation-monthly-report-example",
                "clause_ref": "7.2",
                "clause_text_digest": _digest_of("clause:7.2"),
                "kind": "reporting",
                "direction": "owed_by_company",
                "title": "Deliver the monthly usage report",
                "criteria": [
                    {
                        "criterion_ref": "report-delivered",
                        "description": "Usage report delivered to the counterparty portal",
                        "evidence_kind": "portal_receipt",
                        "minimum_verification_grade": "attested",
                    }
                ],
                "responsible_party_ref": "party-operations-example",
                "counterparty_ref": "party-counterparty-example",
                "due_rule": {
                    "rule_version": 1,
                    "kind": "recurring",
                    "timezone": "America/New_York",
                    "due_local_time": "17:00",
                    "calendar": {"roll": "following"},
                    "recurrence": {
                        "frequency": "monthly",
                        "interval": 1,
                        "start_date": "2026-02-28",
                        "day_of_month": 31,
                    },
                },
                "evidence_freshness_days": 45,
                "escalation_policy": policy,
                "proposed_by_ref": "agent-legal-example",
                "proposal_evidence_ref": "agent-trace-example-1",
            },
            {
                "candidate_ref": "candidate-fee-example",
                "obligation_ref": "obligation-annual-fee-example",
                "clause_ref": "9.1",
                "clause_text_digest": _digest_of("clause:9.1"),
                "kind": "monetary",
                "direction": "owed_to_company",
                "title": "Receive the annual platform fee",
                "monetary": {"amount": "12000.00", "currency": "USD"},
                "criteria": [
                    {
                        "criterion_ref": "fee-received",
                        "description": "Annual fee received in full",
                        "evidence_kind": "bank_receipt",
                        "minimum_verification_grade": "verified",
                        "measure": "quantity",
                        "target_quantity": "12000.00",
                        "unit": "USD",
                    }
                ],
                "responsible_party_ref": "party-counterparty-example",
                "counterparty_ref": "party-counterparty-example",
                "due_rule": {
                    "rule_version": 1,
                    "kind": "relative_to_agreement",
                    "timezone": "Europe/London",
                    "anchor": "agreement_effective_at",
                    "offset_days": 30,
                },
                "materiality": "high",
                "escalation_policy": policy,
                "proposed_by_ref": "agent-legal-example",
                "proposal_evidence_ref": "agent-trace-example-2",
            },
        ],
        "requested_by_ref": _EXAMPLE_ACTOR,
    }


class _ExampleBundle:
    """Lazily materialized, deterministic example artifacts shared by examples."""

    def __init__(self) -> None:
        self._built: dict[str, Any] | None = None

    def get(self) -> dict[str, Any]:
        if self._built is not None:
            return self._built
        scope = _example_scope()
        normalization = _example_normalization_input()
        register = normalize_contract_obligation_candidates(normalization)
        review = {
            "reviewed_by_ref": "actor-register-reviewer-example",
            "review_evidence": {
                "schema": "lightbulb.primitive_evidence_ref.v1",
                "evidence_ref": "evidence-register-review-example",
                "kind": "obligation_register_review",
                "issuer_ref": "spring-example",
                "subject_ref": register.register_digest,
                "sha256": register.register_digest,
                "observed_at": "2026-02-02T09:00:00Z",
                "effective_at": "2026-02-02T09:00:00Z",
                "verification_grade": "attested",
                "classification": "confidential",
            },
        }
        schedule_input = {
            "scope": scope,
            "obligation_register": register.to_dict(),
            "review": review,
            "horizon": {"from_date": "2026-02-01", "to_date": "2026-12-31"},
            "as_of": "2026-02-03T00:00:00Z",
            "requested_by_ref": _EXAMPLE_ACTOR,
        }
        schedule = compile_contract_obligation_schedule(schedule_input)
        instance = next(
            item
            for item in schedule.instances
            if item.obligation_ref == "obligation-monthly-report-example"
        )
        definition = next(
            item
            for item in register.definitions
            if item.obligation_ref == instance.obligation_ref
        )
        evidence = [
            {
                "use_ref": "use-report-receipt-example",
                "custody_ref": "custody-example",
                "criterion_ref": "report-delivered",
                "assertion": "satisfied",
                "reference": {
                    "schema": "lightbulb.primitive_evidence_ref.v1",
                    "evidence_ref": "evidence-report-receipt-example",
                    "kind": "portal_receipt",
                    "issuer_ref": "clm-host-example",
                    "subject_ref": instance.instance_ref,
                    "sha256": _digest_of("portal-receipt-example"),
                    "observed_at": "2026-02-27T12:00:00Z",
                    "effective_at": "2026-02-27T12:00:00Z",
                    "verification_grade": "attested",
                    "classification": "confidential",
                },
            }
        ]
        evaluation_input = {
            "scope": scope,
            "definition": definition.to_dict(),
            "instance": instance.to_dict(),
            "evidence": evidence,
            "as_of": "2026-02-27T13:00:00Z",
            "requested_by_ref": _EXAMPLE_ACTOR,
        }
        evaluation = evaluate_contract_obligation_fulfillment(evaluation_input)
        command = seal_contract_obligation_command(
            {
                "kind": "record_fulfillment",
                "scope": scope,
                "instance_ref": instance.instance_ref,
                "obligation_ref": instance.obligation_ref,
                "definition_digest": instance.definition_digest,
                "transition_ref": "transition-record-fulfillment-example",
                "idempotency_key": _EXAMPLE_IDEMPOTENCY_KEY,
                "expected_version": 0,
                "expected_state_digest": genesis_instance_state_digest(scope, instance),
                "occurred_at": "2026-02-27T14:00:00Z",
                "host_outcome_report": "reported_certain",
                "requested_by_ref": _EXAMPLE_ACTOR,
                "evidence": evidence,
                "package": {
                    "kind": "record_fulfillment",
                    "evaluation": evaluation.to_dict(),
                },
            }
        )
        transition_input = {
            "scope": scope,
            "definition": definition.to_dict(),
            "instance": instance.to_dict(),
            "command": command,
        }
        transition = materialize_contract_obligation_transition(transition_input)
        assert transition.snapshot is not None
        portfolio_input = {
            "scope": scope,
            "as_of": "2026-04-10T00:00:00Z",
            "upcoming_window_days": 30,
            "definitions": [item.to_dict() for item in register.definitions],
            "snapshots": [transition.snapshot.to_dict()],
            "unstarted_instances": [
                item.to_dict()
                for item in schedule.instances
                if item.instance_ref != instance.instance_ref
            ],
            "requested_by_ref": _EXAMPLE_ACTOR,
        }
        reconciliation = reconcile_executed_agreement(
            dict(_ReconcileExecutedAgreementPrimitive.example_inputs)
        )
        assert reconciliation.obligation_fulfillment is not None
        assert reconciliation.custody_candidate is not None
        projection = reconciliation.obligation_fulfillment
        custody_scope = {
            **scope,
            "agreement_ref": projection.agreement_ref,
            "authorized_evidence_issuer_refs": ["spring-example", "clm-host-example"],
        }
        intake_input = {
            "scope": custody_scope,
            "projection": projection.to_dict(),
            "custody_candidate_digest": reconciliation.custody_candidate.custody_candidate_digest,
            "custody_approval_evidence_ref": "evidence-custody-approval-example",
            "custody_approved_at": "2026-09-04T03:00:00Z",
            "completions": [
                {
                    "obligation_ref": item.obligation_ref,
                    "criteria": [
                        {
                            "criterion_ref": f"{item.obligation_ref}:delivered",
                            "description": item.summary,
                            "evidence_kind": "portal_receipt",
                        }
                    ],
                    "responsible_party_ref": "party-operations-example",
                    "due_rule": {
                        "rule_version": 1,
                        "kind": "recurring",
                        "timezone": "America/New_York",
                        "recurrence": {
                            "frequency": "monthly",
                            "start_date": "2026-09-30",
                            "day_of_month": 31,
                        },
                    },
                    "escalation_policy": {
                        "escalate_after_overdue_days": 5,
                        "escalate_to_role_ref": "role-legal-ops-example",
                        "max_exception_days": 30,
                    },
                    "proposed_by_ref": "agent-legal-example",
                    "proposal_evidence_ref": "evidence-legal-review-example",
                }
                for item in projection.proposed_obligations
            ],
            "requested_by_ref": _EXAMPLE_ACTOR,
        }
        routing_input = {
            "scope": scope,
            "obligation_register": register.to_dict(),
            "counterparty_role": "customer",
            "requested_by_ref": _EXAMPLE_ACTOR,
        }
        self._built = {
            "intake_input": intake_input,
            "routing_input": routing_input,
            "normalization_input": normalization,
            "schedule_input": schedule_input,
            "evaluation_input": evaluation_input,
            "transition_input": transition_input,
            "portfolio_input": portfolio_input,
        }
        return self._built


_EXAMPLES = _ExampleBundle()


class _LazyExample(Mapping[str, Any]):
    """Mapping view over one example input, materialized on first access."""

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


class NormalizeContractObligationCandidatesPrimitive(
    _ContractObligationPrimitive[ContractObligationNormalizationInput, ObligationRegister]
):
    primitive_ref = "legal.normalize_contract_obligation_candidates"
    version = "0.1.0"
    title = "Normalize clause-cited contract obligation candidates"
    description = (
        "Validate agent-proposed obligations against one exact approved agreement "
        "version and its retained clause index, producing a deterministic register "
        "candidate with sealed definition digests, rejections, and amendment "
        "supersession lineage. Legal meaning is never decided."
    )
    input_model = ContractObligationNormalizationInput
    output_model = ObligationRegister
    risk_level = "medium"
    operation_spec = CONTRACT_OBLIGATION_NORMALIZE_OPERATION
    example_inputs: Mapping[str, Any] = _LazyExample("normalization_input")

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: ContractObligationNormalizationInput,
    ) -> PrimitiveExecutionResult[ObligationRegister]:
        request_digest = _request_digest(inputs.to_dict())
        if not _scope_matches_context(inputs.scope, inputs.requested_by_ref, context):
            return _scope_blocked_result(
                self, spec=self.operation_spec, request_digest=request_digest, evidence_refs=[]
            )
        register = normalize_contract_obligation_candidates(inputs)
        blocker = None
        if not register.definitions:
            blocker = PrimitiveBlocker(
                code="NO_CANDIDATES_ACCEPTED",
                message="Every candidate was rejected; see register rejections.",
                field="candidates",
                retryable=False,
            )
        return self._preview_result(
            output=register,
            request_digest=request_digest,
            evidence_refs=[],
            external_refs={
                "register_digest": register.register_digest,
                "agreement_version": str(register.agreement.version),
            },
            event_type="legal.contract_obligation_register_candidate_normalized",
            event_payload={
                "agreement_ref": register.agreement.agreement_ref,
                "agreement_version": register.agreement.version,
                "accepted": len(register.definitions),
                "rejected": len(register.rejections),
                "superseded": len(register.supersessions),
            },
            evidence_kind="contract_obligation_register_candidate",
            evidence_summary=(
                "Portable register candidate; Spring review and approval remain required "
                "before scheduling."
            ),
            summary=(
                f"Normalized {len(register.definitions)} obligation definition(s) and "
                f"rejected {len(register.rejections)} candidate(s) with no authoritative effect."
            ),
            blocker=blocker,
        )


class CompileContractObligationSchedulePrimitive(
    _ContractObligationPrimitive[ContractObligationScheduleInput, ObligationSchedule]
):
    primitive_ref = "legal.compile_contract_obligation_schedule"
    version = "0.1.0"
    title = "Compile a bounded contract obligation schedule"
    description = (
        "Expand a reviewed obligation register into dated instances inside one bounded "
        "horizon, honoring recurrence, timezone and business-calendar rules, "
        "conditional activation, dependencies, notice windows, and evidence lead "
        "times. Deferred and truncated obligations are reported, never dropped."
    )
    input_model = ContractObligationScheduleInput
    output_model = ObligationSchedule
    risk_level = "medium"
    operation_spec = CONTRACT_OBLIGATION_SCHEDULE_OPERATION
    example_inputs: Mapping[str, Any] = _LazyExample("schedule_input")

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: ContractObligationScheduleInput,
    ) -> PrimitiveExecutionResult[ObligationSchedule]:
        request_digest = _request_digest(inputs.to_dict())
        evidence_refs = [inputs.review.review_evidence]
        if not _scope_matches_context(inputs.scope, inputs.requested_by_ref, context):
            return _scope_blocked_result(
                self,
                spec=self.operation_spec,
                request_digest=request_digest,
                evidence_refs=evidence_refs,
            )
        schedule = compile_contract_obligation_schedule(inputs)
        blocker = None
        if not schedule.instances:
            blocker = PrimitiveBlocker(
                code="NO_INSTANCES_IN_HORIZON",
                message="No obligation instance falls inside the requested horizon.",
                field="horizon",
                retryable=False,
            )
        return self._preview_result(
            output=schedule,
            request_digest=request_digest,
            evidence_refs=evidence_refs,
            external_refs={
                "schedule_digest": schedule.schedule_digest,
                "register_digest": schedule.register_digest,
            },
            event_type="legal.contract_obligation_schedule_compiled",
            event_payload={
                "register_digest": schedule.register_digest,
                "instances": len(schedule.instances),
                "deferred": len(schedule.deferred),
                "truncated": len(schedule.truncations),
                "horizon": schedule.horizon.to_dict(),
            },
            evidence_kind="contract_obligation_schedule_candidate",
            evidence_summary=(
                "Portable schedule candidate; Spring owns the schedule of record and any "
                "task or calendar writes."
            ),
            summary=(
                f"Compiled {len(schedule.instances)} obligation instance(s), deferred "
                f"{len(schedule.deferred)}, truncated {len(schedule.truncations)}."
            ),
            blocker=blocker,
        )


class EvaluateContractObligationFulfillmentPrimitive(
    _ContractObligationPrimitive[
        ContractObligationEvaluationInput, ObligationFulfillmentEvaluation
    ]
):
    primitive_ref = "legal.evaluate_contract_obligation_fulfillment"
    version = "0.1.0"
    title = "Evaluate contract obligation fulfillment evidence"
    description = (
        "Compare retained, custody-bound evidence against one obligation instance's "
        "exact criteria and return verified, incomplete, conflicting, stale, or "
        "indeterminate with per-criterion findings and exclusions. The verdict is "
        "evidence arithmetic, not a legal or breach determination."
    )
    input_model = ContractObligationEvaluationInput
    output_model = ObligationFulfillmentEvaluation
    risk_level = "medium"
    operation_spec = CONTRACT_OBLIGATION_EVALUATE_OPERATION
    example_inputs: Mapping[str, Any] = _LazyExample("evaluation_input")

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: ContractObligationEvaluationInput,
    ) -> PrimitiveExecutionResult[ObligationFulfillmentEvaluation]:
        request_digest = _request_digest(inputs.to_dict())
        evidence_refs = [item.reference for item in inputs.evidence]
        if not _scope_matches_context(inputs.scope, inputs.requested_by_ref, context):
            return _scope_blocked_result(
                self,
                spec=self.operation_spec,
                request_digest=request_digest,
                evidence_refs=evidence_refs,
            )
        evaluation = evaluate_contract_obligation_fulfillment(inputs)
        return self._preview_result(
            output=evaluation,
            request_digest=request_digest,
            evidence_refs=evidence_refs,
            external_refs={
                "evaluation_digest": evaluation.evaluation_digest,
                "instance_ref": evaluation.instance_ref,
                "verdict": evaluation.verdict,
            },
            event_type="legal.contract_obligation_fulfillment_evaluated",
            event_payload={
                "instance_ref": evaluation.instance_ref,
                "obligation_ref": evaluation.obligation_ref,
                "verdict": evaluation.verdict,
                "fulfillment_ratio": str(evaluation.fulfillment_ratio),
                "excluded_evidence": len(evaluation.exclusions),
                "breach_declared": False,
            },
            evidence_kind="contract_obligation_fulfillment_evaluation",
            evidence_summary=(
                "Deterministic evidence evaluation; not a legal determination, waiver, "
                "or breach declaration."
            ),
            summary=(
                f"Evaluated {evaluation.instance_ref}: verdict {evaluation.verdict} "
                f"(ratio {evaluation.fulfillment_ratio})."
            ),
        )


class ProposeContractObligationTransitionPrimitive(
    _ContractObligationPrimitive[
        ContractObligationTransitionInput, ContractObligationTransitionResult
    ]
):
    primitive_ref = "legal.propose_contract_obligation_transition"
    version = "0.1.0"
    title = "Propose a bounded contract obligation transition"
    description = (
        "Validate and materialize one scope-, revision-, idempotency-, and "
        "evidence-bound transition candidate for a single obligation instance "
        "(scheduled, evidence pending, fulfilled, exception, superseded, escalated, "
        "or authoritative change required) without recording it, waiving anything, "
        "declaring breach, or performing an external effect."
    )
    input_model = ContractObligationTransitionInput
    output_model = ContractObligationTransitionResult
    risk_level = "high"
    mcp_idempotent = False
    operation_spec = CONTRACT_OBLIGATION_TRANSITION_OPERATION
    example_inputs: Mapping[str, Any] = _LazyExample("transition_input")

    def implementation_contract(self) -> dict[str, Any]:
        contract = super().implementation_contract()
        contract["lifecycle_guarantees"] = {
            "maximum_transitions": MAX_OBLIGATION_TRANSITIONS,
            "terminal_statuses": [
                "fulfilled_verified",
                "superseded",
                "escalated_unresolved",
                "authoritative_change_required",
            ],
            "scope_binding": (
                "exact tenant, company, project reference and UUID, agreement, custody, "
                "instance, obligation, and definition digest"
            ),
            "runtime_attribution": (
                "runtime project UUID, authenticated actor, and idempotency key must be "
                "present and exactly match the validated transition command"
            ),
            "history": "instance-local ordered replay with canonical state digests",
            "evidence": "custody-bound, issuer-authorized, instance-bound, single-use",
            "genesis_replay": "durable Spring idempotency ledger remains required",
            "ambiguous_outcome": "fail closed; manual Spring reconciliation; never auto-retry",
        }
        return contract

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: ContractObligationTransitionInput,
    ) -> PrimitiveExecutionResult[ContractObligationTransitionResult]:
        command = inputs.command
        evidence_refs = [item.reference for item in command.evidence]
        if not _scope_matches_context(
            inputs.scope,
            command.requested_by_ref,
            context,
            idempotency_key=command.idempotency_key,
        ):
            return _scope_blocked_result(
                self,
                spec=self.operation_spec,
                request_digest=command.request_digest,
                evidence_refs=evidence_refs,
            )
        output = materialize_contract_obligation_transition(inputs)
        receipt = output.transition_receipt
        blocker: PrimitiveBlocker | None
        recovery_plan: PrimitiveRecoveryPlan | None
        if output.candidate_validated:
            receipt_status = PrimitiveOperationStatus.PREVIEW
            execution_status = PrimitiveExecutionStatus.PREVIEW
            recovery_disposition = PrimitiveRecoveryDisposition.NOT_REQUIRED
            recovery_plan = None
            blocker = None
        elif receipt.status == "in_doubt":
            receipt_status = PrimitiveOperationStatus.IN_DOUBT
            execution_status = PrimitiveExecutionStatus.BLOCKED
            recovery_disposition = PrimitiveRecoveryDisposition.MANUAL_RECONCILIATION_REQUIRED
            recovery_plan = PrimitiveRecoveryPlan(
                policy=PrimitiveOperationRecoveryPolicy.MANUAL_RECONCILIATION,
                disposition=recovery_disposition,
                instructions=receipt.recovery.instructions,
            )
            blocker = PrimitiveBlocker(
                code=receipt.rejection_code or "OUTCOME_IN_DOUBT",
                message=receipt.recovery.instructions or "Manual reconciliation is required.",
                retryable=False,
            )
        else:
            receipt_status = PrimitiveOperationStatus.BLOCKED
            execution_status = PrimitiveExecutionStatus.BLOCKED
            recovery_disposition = PrimitiveRecoveryDisposition.NOT_REQUIRED
            recovery_plan = None
            blocker = PrimitiveBlocker(
                code=receipt.rejection_code or "TRANSITION_REJECTED",
                message=receipt.recovery.instructions
                or "Contract obligation transition was rejected.",
                retryable=False,
            )
        operation_receipt = PrimitiveOperationReceipt(
            spec=self.operation_spec,
            status=receipt_status,
            request_digest=command.request_digest,
            evidence_refs=evidence_refs,
            external_refs=(
                {
                    "state_digest": output.snapshot.state_digest,
                    "transition_ref": command.transition_ref,
                    "instance_ref": command.instance_ref,
                    "to_status": output.snapshot.status,
                }
                if output.candidate_validated and output.snapshot is not None
                else {}
            ),
            recovery_disposition=recovery_disposition,
            recovery_plan=recovery_plan,
            error=blocker,
        )
        return PrimitiveExecutionResult[ContractObligationTransitionResult](
            status=execution_status,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                "Contract obligation transition candidate validated with no authoritative effect."
                if output.candidate_validated
                else "Contract obligation transition rejected without changing live state."
            ),
            output=output,
            events=[
                PrimitiveEvent(
                    type="legal.contract_obligation_transition_candidate_evaluated",
                    payload={
                        "instance_ref": command.instance_ref,
                        "obligation_ref": command.obligation_ref,
                        "transition_ref": command.transition_ref,
                        "command_kind": command.kind,
                        "candidate_validated": output.candidate_validated,
                        "to_status": receipt.to_status,
                        "request_digest": command.request_digest,
                        "legal_determination_made": False,
                        "obligation_waived": False,
                        "breach_declared": False,
                        "connector_effect_executed": False,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="contract_obligation_transition_receipt",
                    summary=(
                        "Portable SDK candidate receipt; not an approval, register write, "
                        "waiver, breach declaration, or audit record."
                    ),
                    refs={
                        "transition_ref": command.transition_ref,
                        "request_digest": command.request_digest,
                    },
                )
            ],
            evidence_refs=evidence_refs,
            operation_receipts=[operation_receipt],
            recovery_plan=recovery_plan,
            blockers=[blocker] if blocker is not None else [],
        )


class AssessContractObligationPortfolioPrimitive(
    _ContractObligationPrimitive[
        ContractObligationPortfolioInput, ContractObligationPortfolioAssessment
    ]
):
    primitive_ref = "legal.assess_contract_obligation_portfolio"
    version = "0.1.0"
    title = "Assess a contract obligation portfolio"
    description = (
        "Produce an effect-dark view of upcoming obligations, overdue evidence, "
        "exceptions past cure, dependency conflicts, escalation candidates, and "
        "material monetary exposure across retained instance snapshots. It proposes "
        "no transition and performs no effect."
    )
    input_model = ContractObligationPortfolioInput
    output_model = ContractObligationPortfolioAssessment
    risk_level = "low"
    operation_spec = CONTRACT_OBLIGATION_PORTFOLIO_OPERATION
    example_inputs: Mapping[str, Any] = _LazyExample("portfolio_input")

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: ContractObligationPortfolioInput,
    ) -> PrimitiveExecutionResult[ContractObligationPortfolioAssessment]:
        request_digest = _request_digest(inputs.to_dict())
        if not _scope_matches_context(inputs.scope, inputs.requested_by_ref, context):
            return _scope_blocked_result(
                self, spec=self.operation_spec, request_digest=request_digest, evidence_refs=[]
            )
        assessment = assess_contract_obligation_portfolio(inputs)
        return self._preview_result(
            output=assessment,
            request_digest=request_digest,
            evidence_refs=[],
            external_refs={"assessment_digest": assessment.assessment_digest},
            event_type="legal.contract_obligation_portfolio_assessed",
            event_payload={
                "as_of": assessment.as_of,
                "status_counts": dict(assessment.status_counts),
                "upcoming": len(assessment.upcoming),
                "overdue": len(assessment.overdue),
                "evidence_overdue": len(assessment.evidence_overdue),
                "escalation_candidates": len(assessment.escalation_candidates),
                "dependency_conflicts": len(assessment.dependency_conflicts),
            },
            evidence_kind="contract_obligation_portfolio_assessment",
            evidence_summary=(
                "Effect-dark portfolio assessment; escalation candidates are proposals "
                "for the workflow and Spring, not actions."
            ),
            summary=(
                f"Assessed portfolio as of {assessment.as_of}: {len(assessment.overdue)} "
                f"overdue, {len(assessment.upcoming)} upcoming, "
                f"{len(assessment.escalation_candidates)} escalation candidate(s)."
            ),
        )


class IntakeContractObligationsFromCustodyPrimitive(
    _ContractObligationPrimitive[ContractObligationIntakeInput, ContractObligationNormalizationInput]
):
    primitive_ref = "legal.intake_contract_obligations_from_custody"
    version = "0.1.0"
    title = "Intake contract obligations from an executed agreement custody projection"
    description = (
        "Bind the obligation-fulfillment projection of an executed-agreement custody "
        "candidate (exact agreement reference, version, digest, clause index, proposed "
        "obligations) to the legal agent's typed completions, producing the exact "
        "normalization input for the obligation register. Amendments cite the prior register."
    )
    input_model = ContractObligationIntakeInput
    output_model = ContractObligationNormalizationInput
    risk_level = "medium"
    operation_spec = CONTRACT_OBLIGATION_INTAKE_OPERATION
    example_inputs: Mapping[str, Any] = _LazyExample("intake_input")

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: ContractObligationIntakeInput,
    ) -> PrimitiveExecutionResult[ContractObligationNormalizationInput]:
        request_digest = _request_digest(inputs.to_dict())
        if not _scope_matches_context(inputs.scope, inputs.requested_by_ref, context):
            return _scope_blocked_result(
                self, spec=self.operation_spec, request_digest=request_digest, evidence_refs=[]
            )
        normalization = build_contract_obligation_normalization_input(inputs)
        return self._preview_result(
            output=normalization,
            request_digest=request_digest,
            evidence_refs=[],
            external_refs={
                "custody_candidate_digest": inputs.custody_candidate_digest,
                "agreement_ref": normalization.agreement.agreement_ref,
                "agreement_version": str(normalization.agreement.version),
            },
            event_type="legal.contract_obligations_intake_from_custody",
            event_payload={
                "agreement_ref": normalization.agreement.agreement_ref,
                "agreement_version": normalization.agreement.version,
                "candidates": len(normalization.candidates),
                "amendment": normalization.prior_register is not None,
            },
            evidence_kind="contract_obligation_intake",
            evidence_summary=(
                "Normalization input bound to an executed agreement custody projection; "
                "the register still requires normalization and Spring review."
            ),
            summary=(
                f"Bound {len(normalization.candidates)} projected obligation(s) to agreement "
                f"{normalization.agreement.agreement_ref} v{normalization.agreement.version}."
            ),
        )


class RouteContractObligationRegisterPrimitive(
    _ContractObligationPrimitive[ContractObligationRoutingInput, ObligationRoutingPlan]
):
    primitive_ref = "legal.route_contract_obligation_register"
    version = "0.1.0"
    title = "Route registered contract obligations toward their fulfilling loops"
    description = (
        "Propose one deterministic downstream route per registered obligation: customer "
        "commitments to project/service delivery, billing and payment terms to "
        "contract-to-cash, supplier commitments to procurement, compliance and data "
        "obligations to compliance controls, notice deadlines to legal review. A proposal "
        "only; no loop is started."
    )
    input_model = ContractObligationRoutingInput
    output_model = ObligationRoutingPlan
    risk_level = "low"
    operation_spec = CONTRACT_OBLIGATION_ROUTING_OPERATION
    example_inputs: Mapping[str, Any] = _LazyExample("routing_input")

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: ContractObligationRoutingInput,
    ) -> PrimitiveExecutionResult[ObligationRoutingPlan]:
        request_digest = _request_digest(inputs.to_dict())
        if not _scope_matches_context(inputs.scope, inputs.requested_by_ref, context):
            return _scope_blocked_result(
                self, spec=self.operation_spec, request_digest=request_digest, evidence_refs=[]
            )
        plan = route_contract_obligation_register(inputs)
        return self._preview_result(
            output=plan,
            request_digest=request_digest,
            evidence_refs=[],
            external_refs={
                "routing_digest": plan.routing_digest,
                "register_digest": plan.register_digest,
            },
            event_type="legal.contract_obligation_register_routed",
            event_payload={
                "register_digest": plan.register_digest,
                "route_counts": dict(plan.route_counts),
                "downstream_loop_started": False,
            },
            evidence_kind="contract_obligation_routing_plan",
            evidence_summary="Deterministic routing proposal; target loops own their own admission.",
            summary=f"Routed {len(plan.assignments)} obligation(s): {dict(plan.route_counts)}.",
        )


CONTRACT_OBLIGATION_EXECUTABLE_PRIMITIVES: tuple[BusinessProcessPrimitive[Any, Any], ...] = (
    IntakeContractObligationsFromCustodyPrimitive(),
    NormalizeContractObligationCandidatesPrimitive(),
    CompileContractObligationSchedulePrimitive(),
    EvaluateContractObligationFulfillmentPrimitive(),
    ProposeContractObligationTransitionPrimitive(),
    AssessContractObligationPortfolioPrimitive(),
    RouteContractObligationRegisterPrimitive(),
)


CONTRACT_OBLIGATION_INTEGRATION_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.capability_pack_integration_manifest.v1",
    "capability_pack": "contract_obligation_management",
    "golden_loop": CONTRACT_OBLIGATION_GOLDEN_LOOP,
    "golden_loop_lifecycle": [
        "approved agreement version",
        "obligation candidates",
        "reviewed obligation register",
        "scheduled obligation instances",
        "evidence due",
        "fulfillment evaluated",
        "fulfilled_verified | exception_open | authoritative_change_required | escalated_unresolved",
    ],
    "modules": {
        "domain": "lightbulb.contract_obligations",
        "intake_and_routing": "lightbulb.contract_obligation_intake",
        "primitives": "lightbulb.contract_obligation_primitives",
    },
    "stacked_on": {
        "branch": "fable/commercial-legal-handoff-core",
        "module": "lightbulb.commercial_legal_handoff",
        "consumes": (
            "ObligationFulfillmentProjection derived from "
            "ExecutedCommercialAgreementCustodyCandidate"
        ),
    },
    "primitive_refs": [item.primitive_ref for item in CONTRACT_OBLIGATION_EXECUTABLE_PRIMITIVES],
    "executable_registry": {
        "file": "lightbulb/executable_primitives.py",
        "import": (
            "from lightbulb.contract_obligation_primitives import "
            "CONTRACT_OBLIGATION_EXECUTABLE_PRIMITIVES"
        ),
        "splice": "*CONTRACT_OBLIGATION_EXECUTABLE_PRIMITIVES in BUILTIN_EXECUTABLE_PRIMITIVES",
        "placement_hint": "after *COMPLIANCE_RISK_LIFECYCLE_EXECUTABLE_PRIMITIVES",
    },
    "public_exports": {
        "file": "lightbulb/__init__.py",
        "names": [
            "CONTRACT_OBLIGATION_EXECUTABLE_PRIMITIVES",
            "CONTRACT_OBLIGATION_GOLDEN_LOOP",
            "CONTRACT_OBLIGATION_INTEGRATION_MANIFEST",
            "NormalizeContractObligationCandidatesPrimitive",
            "CompileContractObligationSchedulePrimitive",
            "EvaluateContractObligationFulfillmentPrimitive",
            "ProposeContractObligationTransitionPrimitive",
            "AssessContractObligationPortfolioPrimitive",
            "IntakeContractObligationsFromCustodyPrimitive",
            "RouteContractObligationRegisterPrimitive",
            "ContractObligationScope",
            "ContractObligationIntakeInput",
            "ObligationRoutingPlan",
            "build_contract_obligation_normalization_input",
            "route_contract_obligation_register",
            "ObligationRegister",
            "ObligationSchedule",
            "ObligationFulfillmentEvaluation",
            "ContractObligationInstanceSnapshot",
            "ContractObligationTransitionResult",
            "ContractObligationPortfolioAssessment",
            "normalize_contract_obligation_candidates",
            "compile_contract_obligation_schedule",
            "evaluate_contract_obligation_fulfillment",
            "materialize_contract_obligation_transition",
            "assess_contract_obligation_portfolio",
            "seal_contract_obligation_command",
            "seal_obligation_definition",
        ],
    },
    "catalog": {
        "file": "lightbulb/business_primitives.py",
        "note": (
            "No Backbone catalog entry is required: registry membership alone makes the "
            "pack discoverable through sdk_only_business_primitive_capability_projections(). "
            "Add BusinessPrimitive entries only if a domain-agent fallback route exists."
        ),
    },
    "mcp": {
        "file": "lightbulb/mcp_server.py",
        "note": (
            "No hand-written MCP tool. The generic run_sdk_business_primitive projection "
            "covers discovery, preview, assessment, and governed transition requests once "
            "the registry splice lands."
        ),
    },
    "readme": {
        "file": "README.md",
        "row": (
            "| Contract obligations | `legal.normalize_contract_obligation_candidates`, "
            "`legal.compile_contract_obligation_schedule`, "
            "`legal.evaluate_contract_obligation_fulfillment`, "
            "`legal.propose_contract_obligation_transition`, "
            "`legal.assess_contract_obligation_portfolio` | One approved agreement version "
            "→ reviewed register → bounded schedule → evidence evaluation → bounded "
            "transitions → effect-dark portfolio |"
        ),
    },
    "not_claimed": [
        "hosted execution",
        "Spring register persistence or RBAC",
        "connector writes",
        "certification or production readiness",
    ],
}


__all__ = [
    "CONTRACT_OBLIGATION_EVALUATE_OPERATION",
    "CONTRACT_OBLIGATION_EXECUTABLE_PRIMITIVES",
    "CONTRACT_OBLIGATION_INTAKE_OPERATION",
    "CONTRACT_OBLIGATION_INTEGRATION_MANIFEST",
    "CONTRACT_OBLIGATION_NORMALIZE_OPERATION",
    "CONTRACT_OBLIGATION_PORTFOLIO_OPERATION",
    "CONTRACT_OBLIGATION_ROUTING_OPERATION",
    "CONTRACT_OBLIGATION_SCHEDULE_OPERATION",
    "CONTRACT_OBLIGATION_TRANSITION_OPERATION",
    "AssessContractObligationPortfolioPrimitive",
    "CompileContractObligationSchedulePrimitive",
    "EvaluateContractObligationFulfillmentPrimitive",
    "IntakeContractObligationsFromCustodyPrimitive",
    "NormalizeContractObligationCandidatesPrimitive",
    "ProposeContractObligationTransitionPrimitive",
    "RouteContractObligationRegisterPrimitive",
]
