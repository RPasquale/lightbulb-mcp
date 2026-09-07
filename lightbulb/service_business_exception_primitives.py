"""Executable primitives for the service-business exception and recovery branches.

``service.open_exception_case`` opens a typed case against a cycle,
``service.advance_exception_case`` materializes one replay-fenced case
transition (returning the loop resolution when the case ends), and
``service.assess_exception_portfolio`` reports rework, dispute, delinquency,
and win-back pressure across cases.  Read-only; Spring executes every effect
the bound primitives propose.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

from pydantic import Field, field_validator

from lightbulb.connector_execution import ConnectorEffect
from lightbulb.primitive_runtime import (
    BusinessProcessPrimitive,
    PrimitiveBlocker,
    PrimitiveExecutionContext,
    PrimitiveExecutionResult,
    PrimitiveOperationFreshnessClass,
    PrimitiveOperationRecoveryPolicy,
    PrimitiveOperationReplayClass,
    PrimitiveOperationSpec,
)
from lightbulb.service_business_exceptions import (
    SERVICE_EXCEPTION_CATALOG,
    SERVICE_EXCEPTIONS_LOOP_EXTENSION,
    TERMINAL_CASE_STATUSES,
    CaseTransitionResult,
    ExceptionKind,
    ExceptionPortfolioAssessment,
    ExceptionReceipt,
    ServiceExceptionCase,
    ServiceExceptionCommand,
    ServiceExceptionPolicy,
    advance_exception_case,
    assess_exception_portfolio,
    open_exception_case,
    policy_for_plan,
    seal_exception_command,
)
from lightbulb.service_business_loop import OpaqueRef, ServiceBusinessCycleState, _StrictModel, _timestamp, advance_service_business_cycle, compile_service_business_blueprint, open_service_business_cycle, seal_cycle_command
from lightbulb.service_business_primitives import _EXAMPLE_ACTOR, _EXAMPLE_SCOPE, _ServiceBusinessPrimitive
from lightbulb.service_operations_primitives import _scope_matches


def _spec(operation_ref: str, tool: str) -> PrimitiveOperationSpec:
    return PrimitiveOperationSpec(operation_ref=operation_ref, tool=tool, effect=ConnectorEffect.READ, approval_required=False, replay_class=PrimitiveOperationReplayClass.SAFE, freshness_class=PrimitiveOperationFreshnessClass.CURRENT, recovery_policy=PrimitiveOperationRecoveryPolicy.NONE)


OPEN_OPERATION = _spec("service_exception_open_case", "sdk.service.open_exception_case")
ADVANCE_OPERATION = _spec("service_exception_advance_case", "sdk.service.advance_exception_case")
ASSESS_OPERATION = _spec("service_exception_assess_portfolio", "sdk.service.assess_exception_portfolio")


class OpenExceptionCaseInput(_StrictModel):
    policy: ServiceExceptionPolicy
    cycle: ServiceBusinessCycleState
    kind: ExceptionKind
    case_ref: OpaqueRef
    opened_at: str
    requested_by_ref: OpaqueRef
    receipt: ExceptionReceipt = Field(default_factory=ExceptionReceipt)
    reason: str | None = Field(default=None, max_length=500)

    @field_validator("opened_at")
    @classmethod
    def _opened(cls, value: str) -> str:
        return _timestamp(value, field_name="opened_at")


class AdvanceExceptionCaseInput(_StrictModel):
    policy: ServiceExceptionPolicy
    case: ServiceExceptionCase
    command: ServiceExceptionCommand
    cycle_scope: dict[str, str]


class AssessExceptionPortfolioInput(_StrictModel):
    policy: ServiceExceptionPolicy
    cases: tuple[ServiceExceptionCase, ...] = Field(default_factory=tuple, max_length=500)
    cycles_completed: int = Field(ge=0, le=1_000_000)
    scope: dict[str, str]
    requested_by_ref: OpaqueRef
    assessed_at: str

    @field_validator("assessed_at")
    @classmethod
    def _assessed(cls, value: str) -> str:
        return _timestamp(value, field_name="assessed_at")


def _request_digest(payload: Mapping[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class _ExampleBundle:
    def __init__(self) -> None:
        self._built: dict[str, Any] | None = None

    def get(self) -> dict[str, Any]:
        if self._built is not None:
            return self._built
        plan = compile_service_business_blueprint("consulting")
        policy = policy_for_plan(plan)
        scope = {**_EXAMPLE_SCOPE, "cycle_ref": "cycle-example", "customer_ref": "customer-example", "currency": "USD"}
        opened = open_service_business_cycle(plan, scope, opened_at="2026-09-01T00:00:00Z", actor_ref=_EXAMPLE_ACTOR, lead_refs=["lead-example"])
        qualified = advance_service_business_cycle(plan, opened, seal_cycle_command({"event": "complete_stage", "stage": "qualify", "transition_ref": "qualify:cycle-example", "idempotency_key": "cycle-example:qualify", "expected_version": opened.version, "expected_state_digest": opened.state_digest, "occurred_at": "2026-09-01T12:00:00Z", "actor_ref": _EXAMPLE_ACTOR, "receipt": {"lead_refs": ["lead-example"], "lead_score": 78, "qualification": "qualified"}}))
        assert qualified.state is not None
        cycle = qualified.state
        case = open_exception_case(policy, cycle, kind="quote_revision", case_ref="case-example", opened_at="2026-09-02T00:00:00Z", actor_ref=_EXAMPLE_ACTOR)
        command = seal_exception_command({"event": "revise_quote", "transition_ref": "revise:case-example:2", "idempotency_key": "case-example:revise:2", "expected_version": case.version, "expected_state_digest": case.state_digest, "occurred_at": "2026-09-03T00:00:00Z", "actor_ref": _EXAMPLE_ACTOR, "receipt": {"quote_ref": "quote-example", "quote_revision": 2, "quote_total": "9500"}})
        plain_scope = dict(_EXAMPLE_SCOPE)
        self._built = {
            "open": {"policy": policy.to_dict(), "cycle": cycle.to_dict(), "kind": "quote_revision", "case_ref": "case-example", "opened_at": "2026-09-02T00:00:00Z", "requested_by_ref": _EXAMPLE_ACTOR},
            "advance": {"policy": policy.to_dict(), "case": case.to_dict(), "command": command, "cycle_scope": plain_scope},
            "assess": {"policy": policy.to_dict(), "cases": [case.to_dict()], "cycles_completed": 1, "scope": plain_scope, "requested_by_ref": _EXAMPLE_ACTOR, "assessed_at": "2026-09-04T00:00:00Z"},
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


def example_exception_inputs() -> dict[str, Any]:
    return {key: dict(value) for key, value in _EXAMPLES.get().items()}


class _ExceptionPrimitive(_ServiceBusinessPrimitive):
    def implementation_contract(self) -> dict[str, Any]:
        contract = super().implementation_contract()
        contract["golden_loop_extension"] = SERVICE_EXCEPTIONS_LOOP_EXTENSION
        contract["exception_catalog"] = SERVICE_EXCEPTION_CATALOG
        contract["hard_rules"] = {**contract.get("hard_rules", {}), "finite_revisions_rework_offers_and_dunning_steps": True, "credit_never_exceeds_dispute": True, "write_off_and_discount_need_approval_and_policy_limits": True, "resolution_states_how_the_cycle_resumes": True}
        return contract


class OpenExceptionCasePrimitive(_ExceptionPrimitive):
    primitive_ref = "service.open_exception_case"
    version = "0.1.0"
    title = "Open an exception case against a service-business cycle"
    description = (
        "Open one of the seven typed branches (quote revision, scope change, acceptance rework, invoice dispute, collection "
        "delinquency, warranty claim, churn win-back) against a cycle. The cycle's own facts decide admissibility: nothing "
        "outstanding means no delinquency, no declined renewal means no win-back, no accepted delivery or an expired support "
        "window means no warranty claim."
    )
    input_model = OpenExceptionCaseInput
    output_model = ServiceExceptionCase
    risk_level = "medium"
    operation_spec = OPEN_OPERATION
    example_inputs: Mapping[str, Any] = _LazyExample("open")

    def _execute(self, context: PrimitiveExecutionContext, inputs: OpenExceptionCaseInput) -> PrimitiveExecutionResult[ServiceExceptionCase]:
        request_digest = _request_digest(inputs.to_dict())
        scope = inputs.cycle.scope
        if not _scope_matches(scope.tenant_ref, scope.company_ref, scope.project_ref, scope.project_id, inputs.requested_by_ref, context):
            return self._blocked(request_digest=request_digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the cycle scope.")
        try:
            case = open_exception_case(inputs.policy, inputs.cycle, kind=inputs.kind, case_ref=inputs.case_ref, opened_at=inputs.opened_at, actor_ref=inputs.requested_by_ref, receipt=inputs.receipt, reason=inputs.reason)
        except ValueError as exc:
            return self._blocked(request_digest=request_digest, code="CASE_NOT_ADMISSIBLE", message=str(exc)[:500])
        return self._preview(output=case, request_digest=request_digest, external_refs={"case_ref": case.case_ref, "cycle_ref": case.binding.cycle_ref, "state_digest": case.state_digest}, event_type="service.exception_case_opened", event_payload={"kind": case.kind, "origin_stage": case.binding.origin_stage, "at_risk_amount": str(case.ledger.at_risk_amount)}, evidence_kind="service_exception_case", evidence_summary="Typed exception case bound to the cycle; candidate until Spring retains it.", summary=f"Opened {case.kind} against {case.binding.cycle_ref} at {case.binding.origin_stage}.")


class AdvanceExceptionCasePrimitive(_ExceptionPrimitive):
    primitive_ref = "service.advance_exception_case"
    version = "0.1.0"
    title = "Advance an exception case by one transition"
    description = (
        "Materialize one replay-fenced case transition: quote revisions and rework rounds within limits, change orders within "
        "the policy ceiling, credit notes never above the dispute, dunning steps in ladder order, payment plans that sum to the "
        "balance, write-offs and win-back discounts inside policy with approvals. A terminal transition returns the loop resolution."
    )
    input_model = AdvanceExceptionCaseInput
    output_model = CaseTransitionResult
    risk_level = "medium"
    operation_spec = ADVANCE_OPERATION
    example_inputs: Mapping[str, Any] = _LazyExample("advance")

    def _execute(self, context: PrimitiveExecutionContext, inputs: AdvanceExceptionCaseInput) -> PrimitiveExecutionResult[CaseTransitionResult]:
        request_digest = _request_digest(inputs.to_dict())
        scope = inputs.cycle_scope
        if not all(key in scope for key in ("tenant_ref", "company_ref", "project_ref", "project_id")) or not _scope_matches(scope["tenant_ref"], scope["company_ref"], scope["project_ref"], scope["project_id"], inputs.command.actor_ref, context):
            return self._blocked(request_digest=request_digest, code="SCOPE_MISMATCH", message="Runtime scope and acting actor must exactly match the cycle scope and the command.")
        try:
            result = advance_exception_case(inputs.policy, inputs.case, inputs.command)
        except ValueError as exc:
            return self._blocked(request_digest=request_digest, code="CASE_NOT_BOUND", message=str(exc)[:500])
        receipt = result.receipt
        blocker = None if result.candidate_validated else PrimitiveBlocker(code=str(receipt.rejection_code), message=str(receipt.recovery.instructions)[:500], retryable=receipt.recovery.disposition in {"refresh_state", "await_approval"})
        return self._preview(output=result, request_digest=request_digest, external_refs={"case_ref": inputs.case.case_ref, "transition_ref": receipt.transition_ref, "to_state_digest": receipt.to_state_digest}, event_type="service.exception_case_advanced", event_payload={"kind": inputs.case.kind, "event": receipt.event, "transition_status": receipt.status, "from_status": receipt.from_status, "to_status": receipt.to_status, "rejection_code": receipt.rejection_code, "recovery": receipt.recovery.disposition, "resolution": None if result.resolution is None else result.resolution.cycle_disposition}, evidence_kind="service_exception_transition", evidence_summary="Replay-fenced case transition; nothing sent, issued, granted, or written off.", summary=(f"{receipt.event}: {receipt.from_status} -> {receipt.to_status}" + (f"; cycle {result.resolution.cycle_disposition} at {result.resolution.resume_stage}" if result.resolution else "") if result.candidate_validated else f"{receipt.event} rejected: {receipt.rejection_code} ({receipt.recovery.disposition})."), blocker=blocker)


class AssessExceptionPortfolioPrimitive(_ExceptionPrimitive):
    primitive_ref = "service.assess_exception_portfolio"
    version = "0.1.0"
    title = "Assess the exception portfolio of a service business"
    description = "Effect-dark portfolio view: open cases by kind, receivable at risk, credits and write-offs, rework and dispute rates per completed cycle, win-back rate, exhausted dunning ladders, learnings and recommendations."
    input_model = AssessExceptionPortfolioInput
    output_model = ExceptionPortfolioAssessment
    risk_level = "low"
    operation_spec = ASSESS_OPERATION
    example_inputs: Mapping[str, Any] = _LazyExample("assess")

    def _execute(self, context: PrimitiveExecutionContext, inputs: AssessExceptionPortfolioInput) -> PrimitiveExecutionResult[ExceptionPortfolioAssessment]:
        request_digest = _request_digest(inputs.to_dict())
        scope = inputs.scope
        if not all(key in scope for key in ("tenant_ref", "company_ref", "project_ref", "project_id")) or not _scope_matches(scope["tenant_ref"], scope["company_ref"], scope["project_ref"], scope["project_id"], inputs.requested_by_ref, context):
            return self._blocked(request_digest=request_digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request scope.")
        try:
            assessment = assess_exception_portfolio(inputs.policy, inputs.cases, cycles_completed=inputs.cycles_completed, assessed_at=inputs.assessed_at)
        except ValueError as exc:
            return self._blocked(request_digest=request_digest, code="CASES_NOT_BOUND", message=str(exc)[:500])
        return self._preview(output=assessment, request_digest=request_digest, external_refs={"assessment_digest": assessment.assessment_digest}, event_type="service.exception_portfolio_assessed", event_payload={"case_count": assessment.case_count, "open_count": assessment.open_count, "receivable_at_risk": str(assessment.receivable_at_risk), "learnings": list(assessment.learnings)}, evidence_kind="service_exception_portfolio", evidence_summary="Portfolio assessment; no effect.", summary=assessment.learnings[0] if assessment.learnings else "No exception cases.")


SERVICE_EXCEPTION_EXECUTABLE_PRIMITIVES: tuple[BusinessProcessPrimitive[Any, Any], ...] = (
    OpenExceptionCasePrimitive(),
    AdvanceExceptionCasePrimitive(),
    AssessExceptionPortfolioPrimitive(),
)

SERVICE_EXCEPTION_INTEGRATION_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.capability_pack_integration_manifest.v1",
    "capability_pack": "service_business_exceptions",
    "golden_loop_extension": SERVICE_EXCEPTIONS_LOOP_EXTENSION,
    "extends": "service.market_to_renewal_business@0.1.0",
    "stacked_on": "fable/service-business-golden-loop (PR #479)",
    "modules": {"domain": "lightbulb.service_business_exceptions", "primitives": "lightbulb.service_business_exception_primitives"},
    "exception_kinds": SERVICE_EXCEPTION_CATALOG,
    "primitive_refs": [item.primitive_ref for item in SERVICE_EXCEPTION_EXECUTABLE_PRIMITIVES],
    "executable_registry": {"file": "lightbulb/executable_primitives.py", "import": "from lightbulb.service_business_exception_primitives import SERVICE_EXCEPTION_EXECUTABLE_PRIMITIVES", "splice": "*SERVICE_EXCEPTION_EXECUTABLE_PRIMITIVES in BUILTIN_EXECUTABLE_PRIMITIVES"},
    "public_exports": {"file": "lightbulb/__init__.py", "names": ["SERVICE_EXCEPTION_EXECUTABLE_PRIMITIVES", "SERVICE_EXCEPTION_INTEGRATION_MANIFEST", "ServiceExceptionPolicy", "ServiceExceptionCase", "CaseResolution", "open_exception_case", "advance_exception_case", "resolve_case", "assess_exception_portfolio", "policy_for_plan"]},
    "non_goals": ["no reminder, credit note, write-off, or discount effect executed here", "no replacement of the contract change-order or customer-service mechanics", "no certification or production-readiness claim"],
}

__all__ = [
    "ADVANCE_OPERATION",
    "ASSESS_OPERATION",
    "OPEN_OPERATION",
    "SERVICE_EXCEPTION_EXECUTABLE_PRIMITIVES",
    "SERVICE_EXCEPTION_INTEGRATION_MANIFEST",
    "AdvanceExceptionCaseInput",
    "AdvanceExceptionCasePrimitive",
    "AssessExceptionPortfolioInput",
    "AssessExceptionPortfolioPrimitive",
    "OpenExceptionCaseInput",
    "OpenExceptionCasePrimitive",
    "example_exception_inputs",
]

_TERMINAL = TERMINAL_CASE_STATUSES
