"""Executable primitives for the Finance Close Engine Golden Operating Loop.

``blueprint.compile_finance_close`` builds the plan from a profile or custom
blueprint, ``finance_close.advance_close`` materializes one replay-fenced
period-close transition (trial balance, reconciliations and exceptions,
adjustments, lock, independent approval, close, reopen),
``finance_close.verify_books`` seals the books verification whose digest the
company operating system reconciles on, and ``finance_close.assess_close``
derives on-time and exception metrics.  Read-only; Spring authorizes posting,
locking, and closing.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import Field, field_validator

from lightbulb.company_engine_core import OpaqueRef, StrictModel, timestamp
from lightbulb.company_engine_primitives_base import EXAMPLE_ACTOR, EXAMPLE_SCOPE, EnginePrimitive, LazyExample, RequestScope, read_spec, request_digest, scope_matches
from lightbulb.finance_close_engine import (
    FINANCE_CLOSE_GOLDEN_LOOP,
    FINANCE_CLOSE_KIND,
    FINANCE_CLOSE_MANIFEST,
    FINANCE_CLOSE_PROFILES,
    STAGE_ORDER,
    BooksVerification,
    CloseCommand,
    CloseState,
    CloseTransitionResult,
    FinanceCloseAssessment,
    FinanceCloseBlueprint,
    FinanceCloseLoopPlan,
    advance_period_close,
    assess_finance_close,
    compile_finance_close_blueprint,
    open_period_close,
    seal_close_command,
    verify_books,
)
from lightbulb.primitive_runtime import BusinessProcessPrimitive, PrimitiveExecutionContext, PrimitiveExecutionResult


class CompileFinanceCloseInput(StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    profile: str = Field(min_length=1, max_length=40)
    blueprint: FinanceCloseBlueprint | None = None
    overrides: dict[str, Any] = Field(default_factory=dict)


class AdvanceCloseInput(StrictModel):
    plan: FinanceCloseLoopPlan
    state: CloseState  # type: ignore[valid-type]
    command: CloseCommand  # type: ignore[valid-type]


class VerifyBooksInput(StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    plan: FinanceCloseLoopPlan
    state: CloseState  # type: ignore[valid-type]


class AssessCloseInput(StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    plan: FinanceCloseLoopPlan
    states: tuple[CloseState, ...] = Field(default_factory=tuple, max_length=120)  # type: ignore[valid-type]
    assessed_at: str

    @field_validator("assessed_at")
    @classmethod
    def _assessed(cls, value: str) -> str:
        return timestamp(value, field_name="assessed_at")


class _Examples:
    def __init__(self) -> None:
        self._built: dict[str, Any] | None = None

    def get(self) -> dict[str, Any]:
        if self._built is not None:
            return self._built
        plan = compile_finance_close_blueprint("weekly_close")
        scope = {**EXAMPLE_SCOPE, "entity_ref": "close-example", "currency": "CAD"}
        state = open_period_close(plan, scope, period_start="2026-10-05T00:00:00Z", period_end=None, ledger_ref="ledger-example", preparer_ref="preparer-example", opened_at="2026-10-05T00:00:00Z", actor_ref=EXAMPLE_ACTOR)
        command = seal_close_command({"event": "capture_trial_balance", "transition_ref": "capture:close-example", "idempotency_key": "close-example:capture", "expected_version": state.version, "expected_state_digest": state.state_digest, "occurred_at": "2026-10-12T01:00:00Z", "actor_ref": EXAMPLE_ACTOR, "receipt": {"trial_balance_ref": "trial-balance-example", "debits": "125000.00", "credits": "125000.00"}})
        self._built = {
            "compile": {"scope": EXAMPLE_SCOPE, "requested_by_ref": EXAMPLE_ACTOR, "profile": "weekly_close", "overrides": {"materiality": "300"}},
            "advance": {"plan": plan.to_dict(), "state": state.to_dict(), "command": command},
            "verify": {"scope": EXAMPLE_SCOPE, "requested_by_ref": EXAMPLE_ACTOR, "plan": plan.to_dict(), "state": state.to_dict()},
            "assess": {"scope": EXAMPLE_SCOPE, "requested_by_ref": EXAMPLE_ACTOR, "plan": plan.to_dict(), "states": [state.to_dict()], "assessed_at": "2026-10-13T00:00:00Z"},
        }
        return self._built


_EXAMPLES = _Examples()


def example_finance_close_inputs() -> dict[str, Any]:
    return {key: dict(value) for key, value in _EXAMPLES.get().items()}


class _FinanceClosePrimitive(EnginePrimitive[Any, Any]):
    golden_loop = FINANCE_CLOSE_GOLDEN_LOOP
    engine = FINANCE_CLOSE_KIND
    loop_stages = STAGE_ORDER
    profiles = tuple(sorted(FINANCE_CLOSE_PROFILES))
    hard_rules = {"trial_balance_balances_inside_materiality": True, "every_required_account_reconciles_or_opens_an_exception": True, "exceptions_resolve_before_reconciliation_completes": True, "adjustments_stop_at_lock_and_stay_inside_the_multiple": True, "approval_independent_of_the_preparer": True, "close_inside_the_deadline_and_reopen_inside_the_window": True, "verified_books_are_a_sealed_proof": True, "no_journal_posted_ledger_locked_or_period_closed_here": True}
    authority_boundary = {"agent": "prepares packages, proposes reconciliations and adjustments", "sdk": "fences the close, seals the books verification", "spring": "authorizes posting, locking, closing; persists closes", "connectors": "read the ledger and settlements", "mcp": "projects these primitives and the loop"}


class CompileFinanceClosePrimitive(_FinanceClosePrimitive):
    primitive_ref = "blueprint.compile_finance_close"
    version = "0.1.0"
    title = "Compile a finance close blueprint into a loop plan"
    description = "Turn a profile (weekly_close, fortnightly_close, monthly_close) or a custom blueprint (ledger system, materiality, variance threshold, required reconciliations, independent approval, deadlines) into the capture → reconcile → resolve → adjust → lock → approve → close → verify plan."
    input_model = CompileFinanceCloseInput
    output_model = FinanceCloseLoopPlan
    risk_level = "low"
    operation_spec = read_spec("finance_close_compile_blueprint", "sdk.blueprint.compile_finance_close")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "compile")

    def _execute(self, context: PrimitiveExecutionContext, inputs: CompileFinanceCloseInput) -> PrimitiveExecutionResult[FinanceCloseLoopPlan]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            plan = compile_finance_close_blueprint(inputs.blueprint.to_dict() if inputs.profile == "custom" and inputs.blueprint is not None else inputs.profile, inputs.overrides)
        except ValueError as exc:
            return self.blocked(digest=digest, code="BLUEPRINT_INVALID", message=str(exc))
        bp = plan.blueprint
        return self.preview(output=plan, digest=digest, external_refs={"plan_digest": plan.plan_digest}, event_type="blueprint.finance_close_compiled", event_payload={"profile": bp.profile, "ledger_system": bp.ledger_system, "materiality": str(bp.materiality), "reconciliations": list(bp.required_reconciliations)}, evidence_kind="finance_close_loop_plan", evidence_summary="Loop plan; nothing executed.", summary=f"Compiled {bp.profile} on {bp.ledger_system}: {len(bp.required_reconciliations)} reconciliation(s), materiality {bp.currency} {bp.materiality}, close within {bp.close_deadline_days} day(s).")


class AdvanceClosePrimitive(_FinanceClosePrimitive):
    primitive_ref = "finance_close.advance_close"
    version = "0.1.0"
    title = "Advance a period close by one transition"
    description = "Materialize one replay-fenced close transition: capture the trial balance inside materiality, reconcile accounts inside the variance threshold or open exceptions, resolve exceptions, record adjustments, lock subledgers, approve independently, close inside the deadline, reopen inside the window."
    input_model = AdvanceCloseInput
    output_model = CloseTransitionResult
    risk_level = "medium"
    operation_spec = read_spec("finance_close_advance", "sdk.finance_close.advance_close")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "advance")

    def _execute(self, context: PrimitiveExecutionContext, inputs: AdvanceCloseInput) -> PrimitiveExecutionResult[CloseTransitionResult]:
        digest = request_digest(inputs.to_dict())
        scope = inputs.state.scope
        if not scope_matches(RequestScope.from_engine_scope(scope), inputs.command.actor_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and acting actor must exactly match the close scope and the command.")
        try:
            result = advance_period_close(inputs.plan, inputs.state, inputs.command)
        except ValueError as exc:
            return self.blocked(digest=digest, code="STATE_NOT_BOUND", message=str(exc))
        return self.transition_preview(result=result, digest=digest, entity_ref=scope.entity_ref, event_prefix="finance_close")


class VerifyBooksPrimitive(_FinanceClosePrimitive):
    primitive_ref = "finance_close.verify_books"
    version = "0.1.0"
    title = "Seal the books verification for a period"
    description = "Prove whether a close state is verified books: closed, balanced inside materiality, no open exceptions, independently approved. The sealed close_state_digest is the proof the company operating system requires to reconcile an operating period."
    input_model = VerifyBooksInput
    output_model = BooksVerification
    risk_level = "low"
    operation_spec = read_spec("finance_close_verify_books", "sdk.finance_close.verify_books")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "verify")

    def _execute(self, context: PrimitiveExecutionContext, inputs: VerifyBooksInput) -> PrimitiveExecutionResult[BooksVerification]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            verification = verify_books(inputs.plan, inputs.state)
        except ValueError as exc:
            return self.blocked(digest=digest, code="STATE_NOT_BOUND", message=str(exc))
        return self.preview(output=verification, digest=digest, external_refs={"verification_digest": verification.verification_digest, "close_state_digest": verification.close_state_digest}, event_type="finance_close.books_verified" if verification.verified else "finance_close.books_unverified", event_payload={"verified": verification.verified, "period_end": verification.period_end, "reasons": list(verification.reasons)}, evidence_kind="books_verification", evidence_summary="Sealed verification; no effect.", summary=f"Books for the period ending {verification.period_end} are {'verified' if verification.verified else 'not verified: ' + '; '.join(verification.reasons)}.")


class AssessClosePrimitive(_FinanceClosePrimitive):
    primitive_ref = "finance_close.assess_close"
    version = "0.1.0"
    title = "Assess the close engine (learn stage)"
    description = "Effect-dark close metrics across periods: on-time rate, average days to close, exceptions raised and open, adjustments, reopens, with learnings against targets."
    input_model = AssessCloseInput
    output_model = FinanceCloseAssessment
    risk_level = "low"
    operation_spec = read_spec("finance_close_assess", "sdk.finance_close.assess_close")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "assess")

    def _execute(self, context: PrimitiveExecutionContext, inputs: AssessCloseInput) -> PrimitiveExecutionResult[FinanceCloseAssessment]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            assessment = assess_finance_close(inputs.plan, inputs.states, assessed_at=inputs.assessed_at)
        except ValueError as exc:
            return self.blocked(digest=digest, code="STATES_NOT_BOUND", message=str(exc))
        return self.preview(output=assessment, digest=digest, external_refs={"assessment_digest": assessment.assessment_digest}, event_type="finance_close.assessed", event_payload={"periods": assessment.periods, "closed": assessment.closed, "on_time_percent": str(assessment.on_time_percent) if assessment.on_time_percent is not None else None}, evidence_kind="finance_close_assessment", evidence_summary="Close metrics; no effect.", summary=f"{assessment.closed} of {assessment.periods} period(s) closed: {assessment.learnings[0]}")


FINANCE_CLOSE_EXECUTABLE_PRIMITIVES: tuple[BusinessProcessPrimitive[Any, Any], ...] = (
    CompileFinanceClosePrimitive(),
    AdvanceClosePrimitive(),
    VerifyBooksPrimitive(),
    AssessClosePrimitive(),
)

FINANCE_CLOSE_INTEGRATION_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.capability_pack_integration_manifest.v1",
    "capability_pack": "finance_close_golden_loop",
    "golden_loop": FINANCE_CLOSE_GOLDEN_LOOP,
    "engine": FINANCE_CLOSE_MANIFEST,
    "modules": {"domain": "lightbulb.finance_close_engine", "primitives": "lightbulb.finance_close_primitives", "core": "lightbulb.company_engine_core"},
    "reuses": ["finance.discover_trial_balance", "finance.evaluate_period_reconciliation", "finance.prepare_adjusting_entries_package", "finance.prepare_subledger_lock_package", "finance.prepare_close_approval_package", "finance.propose_period_close_transition", "finance.prepare_close_evidence_bundle", "finance.build_close_audit_packet", "approval.request_decision", "company_operating_system reconcile gate"],
    "required_connectors": FINANCE_CLOSE_MANIFEST["required_connectors"],
    "primitive_refs": [item.primitive_ref for item in FINANCE_CLOSE_EXECUTABLE_PRIMITIVES],
    "non_goals": ["no journal posted, ledger locked, or period closed here", "no provider read here", "no certification or production-readiness claim"],
}

__all__ = [
    "FINANCE_CLOSE_EXECUTABLE_PRIMITIVES",
    "FINANCE_CLOSE_INTEGRATION_MANIFEST",
    "AdvanceCloseInput",
    "AdvanceClosePrimitive",
    "AssessCloseInput",
    "AssessClosePrimitive",
    "CompileFinanceCloseInput",
    "CompileFinanceClosePrimitive",
    "VerifyBooksInput",
    "VerifyBooksPrimitive",
    "example_finance_close_inputs",
]
