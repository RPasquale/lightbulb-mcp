"""Executable primitives for the Appointment Business Golden Operating Loop.

``blueprint.compile_appointment_business`` builds the plan from a profile,
``appointment.generate_availability`` computes deterministic open slots,
``appointment.advance_booking`` materializes one replay-fenced booking
transition with policy-derived deposits and fees, and
``appointment.assess_schedule`` derives utilization, no-show and late-cancel
rates, rebooking, and revenue.  Read-only; Spring authorizes calendar writes,
payments, reminders, and fees.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, Field, field_validator

from lightbulb.appointment_business_loop import (
    APPOINTMENT_BUSINESS_ARCHETYPE_MANIFEST,
    APPOINTMENT_BUSINESS_GOLDEN_LOOP,
    APPOINTMENT_BUSINESS_PROFILES,
    STAGE_ORDER,
    AppointmentBusinessBlueprint,
    AppointmentBusinessLoopPlan,
    Availability,
    BookingCommand,
    BookingState,
    BookingTransitionResult,
    ExistingBooking,
    OpaqueRef,
    ScheduleAssessment,
    _StrictModel,
    _timestamp,
    advance_booking,
    assess_schedule,
    compile_appointment_business_blueprint,
    generate_availability,
    open_booking,
    seal_booking_command,
)
from lightbulb.connector_execution import ConnectorEffect
from lightbulb.primitive_runtime import (
    BusinessProcessPrimitive,
    PrimitiveBlocker,
    PrimitiveEvent,
    PrimitiveEvidence,
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


def _spec(operation_ref: str, tool: str) -> PrimitiveOperationSpec:
    return PrimitiveOperationSpec(operation_ref=operation_ref, tool=tool, effect=ConnectorEffect.READ, approval_required=False, replay_class=PrimitiveOperationReplayClass.SAFE, freshness_class=PrimitiveOperationFreshnessClass.CURRENT, recovery_policy=PrimitiveOperationRecoveryPolicy.NONE)


_EXAMPLE_PROJECT_ID = "40100000-0000-4000-8000-000000000001"
_EXAMPLE_ACTOR = "actor-requester-example"
_EXAMPLE_SCOPE = {"tenant_ref": "authenticated", "company_ref": "selected", "project_ref": "workflow-improvement", "project_id": _EXAMPLE_PROJECT_ID}


class RequestScope(_StrictModel):
    tenant_ref: OpaqueRef
    company_ref: OpaqueRef
    project_ref: OpaqueRef
    project_id: str


class CompileAppointmentBusinessInput(_StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    profile: str = Field(min_length=1, max_length=40)
    blueprint: AppointmentBusinessBlueprint | None = None
    overrides: dict[str, Any] = Field(default_factory=dict)


class GenerateAvailabilityInput(_StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    plan: AppointmentBusinessLoopPlan
    service_ref: OpaqueRef
    provider_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=200)
    window_start: str
    window_end: str
    existing_bookings: tuple[ExistingBooking, ...] = Field(default_factory=tuple, max_length=5000)
    now: str | None = None

    @field_validator("window_start", "window_end", "now")
    @classmethod
    def _times(cls, value: str | None, info: Any) -> str | None:
        return None if value is None else _timestamp(value, field_name=str(info.field_name))


class AdvanceBookingInput(_StrictModel):
    plan: AppointmentBusinessLoopPlan
    state: BookingState
    command: BookingCommand


class AssessScheduleInput(_StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    plan: AppointmentBusinessLoopPlan
    bookings: tuple[BookingState, ...] = Field(default_factory=tuple, max_length=5000)
    capacity_minutes: int = Field(ge=0, le=100_000_000)
    assessed_at: str

    @field_validator("assessed_at")
    @classmethod
    def _assessed(cls, value: str) -> str:
        return _timestamp(value, field_name="assessed_at")


def _request_digest(payload: Mapping[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _scope_matches(scope: RequestScope, requesting_ref: str, context: PrimitiveExecutionContext) -> bool:
    runtime = context.scope
    matched = scope.tenant_ref == runtime.tenant_ref and scope.company_ref == runtime.company_ref and scope.project_ref == runtime.project_ref and runtime.project_id is not None and scope.project_id == str(runtime.project_id)
    if runtime.actor_ref is not None:
        matched = matched and requesting_ref == runtime.actor_ref
    return matched


class _ExampleBundle:
    def __init__(self) -> None:
        self._built: dict[str, Any] | None = None

    def get(self) -> dict[str, Any]:
        if self._built is not None:
            return self._built
        plan = compile_appointment_business_blueprint("salon")
        availability = generate_availability(plan, service_ref="cut", provider_refs=["stylist-example"], window_start="2026-09-15T00:00:00Z", window_end="2026-09-16T00:00:00Z", now="2026-09-13T08:00:00Z")
        scope = {**_EXAMPLE_SCOPE, "booking_ref": "booking-example", "customer_ref": "customer-example", "currency": "USD"}
        state = open_booking(plan, scope, requested_at="2026-09-13T08:00:00Z", actor_ref=_EXAMPLE_ACTOR, receipt={"service_ref": "cut", "provider_ref": "stylist-example", "starts_at": "2026-09-15T09:00:00Z", "availability_digest": availability.availability_digest})
        command = seal_booking_command({"event": "collect_deposit", "transition_ref": "deposit:booking-example", "idempotency_key": "booking-example:deposit", "expected_version": state.version, "expected_state_digest": state.state_digest, "occurred_at": "2026-09-13T08:05:00Z", "actor_ref": _EXAMPLE_ACTOR, "receipt": {"payment_ref": "payment-example", "amount": "11.00"}})
        self._built = {
            "compile": {"scope": _EXAMPLE_SCOPE, "requested_by_ref": _EXAMPLE_ACTOR, "profile": "salon", "overrides": {"deposit_percent": "25"}},
            "availability": {"scope": _EXAMPLE_SCOPE, "requested_by_ref": _EXAMPLE_ACTOR, "plan": plan.to_dict(), "service_ref": "cut", "provider_refs": ["stylist-example"], "window_start": "2026-09-15T00:00:00Z", "window_end": "2026-09-16T00:00:00Z", "now": "2026-09-13T08:00:00Z"},
            "advance": {"plan": plan.to_dict(), "state": state.to_dict(), "command": command},
            "assess": {"scope": _EXAMPLE_SCOPE, "requested_by_ref": _EXAMPLE_ACTOR, "plan": plan.to_dict(), "bookings": [state.to_dict()], "capacity_minutes": 480, "assessed_at": "2026-09-16T00:00:00Z"},
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


def example_appointment_inputs() -> dict[str, Any]:
    return {key: dict(value) for key, value in _EXAMPLES.get().items()}


class _AppointmentPrimitive(BusinessProcessPrimitive[InputT, OutputT], Generic[InputT, OutputT]):
    connector_tools = ()
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    operation_spec: PrimitiveOperationSpec

    def implementation_contract(self) -> dict[str, Any]:
        contract = super().implementation_contract()
        contract["operation_contract"] = self.operation_spec.to_dict()
        contract["golden_loop"] = APPOINTMENT_BUSINESS_GOLDEN_LOOP
        contract["archetype"] = APPOINTMENT_BUSINESS_ARCHETYPE_MANIFEST["archetype"]
        contract["loop_stages"] = list(STAGE_ORDER)
        contract["profiles"] = sorted(APPOINTMENT_BUSINESS_PROFILES)
        contract["hard_rules"] = {"slots_inside_working_hours_notice_and_horizon": True, "buffers_and_existing_bookings_respected": True, "deposits_and_fees_derived_from_policy": True, "reminders_follow_the_schedule": True, "intake_consent_before_regulated_visits": True, "no_calendar_write_payment_or_reminder_here": True}
        contract["authority_boundary"] = {"agent": "chooses services, providers, and outreach", "sdk": "generates availability, fences bookings, derives fees, measures the schedule", "spring": "authorizes calendar writes, payments, reminders, fees; persists bookings", "connectors": "execute calendar, payment, and CRM operations", "mcp": "projects these primitives and the loop"}
        return contract

    def _blocked(self, *, request_digest: str, code: str, message: str) -> PrimitiveExecutionResult[OutputT]:
        blocker = PrimitiveBlocker(code=code, message=message, field="scope" if code == "SCOPE_MISMATCH" else None, retryable=False)
        return PrimitiveExecutionResult[OutputT](status=PrimitiveExecutionStatus.BLOCKED, primitive_ref=self.primitive_ref, primitive_version=self.version, summary=f"{self.title} blocked: {code}.", blockers=[blocker], operation_receipts=[PrimitiveOperationReceipt(spec=self.operation_spec, status=PrimitiveOperationStatus.BLOCKED, request_digest=request_digest, error=blocker)])

    def _preview(self, *, output: OutputT, request_digest: str, external_refs: Mapping[str, str], event_type: str, event_payload: Mapping[str, Any], evidence_kind: str, evidence_summary: str, summary: str, blocker: PrimitiveBlocker | None = None) -> PrimitiveExecutionResult[OutputT]:
        status = PrimitiveExecutionStatus.BLOCKED if blocker else PrimitiveExecutionStatus.PREVIEW
        return PrimitiveExecutionResult[OutputT](
            status=status, primitive_ref=self.primitive_ref, primitive_version=self.version, summary=summary, output=output,
            events=[PrimitiveEvent(type=event_type, payload={**dict(event_payload), "request_digest": request_digest, "connector_effect_executed": False, "calendar_written": False})],
            evidence=[PrimitiveEvidence(kind=evidence_kind, summary=evidence_summary, refs={"request_digest": request_digest, **dict(external_refs)})],
            operation_receipts=[PrimitiveOperationReceipt(spec=self.operation_spec, status=PrimitiveOperationStatus.BLOCKED if blocker else PrimitiveOperationStatus.PREVIEW, request_digest=request_digest, external_refs=dict(external_refs), error=blocker)],
            blockers=[blocker] if blocker else [],
        )


class CompileAppointmentBusinessPrimitive(_AppointmentPrimitive[CompileAppointmentBusinessInput, AppointmentBusinessLoopPlan]):
    primitive_ref = "blueprint.compile_appointment_business"
    version = "0.1.0"
    title = "Compile an appointment-business Company Blueprint into a loop plan"
    description = "Turn a ready-made profile (clinic, salon, trades_visit, coaching) or a custom blueprint (working hours, services, slot and buffer lengths, horizon, notice, cancellation window, fees, deposit, reminders, waitlist, intake consent, targets) into the attract → book → remind → arrive → serve → pay → rebook → learn plan."
    input_model = CompileAppointmentBusinessInput
    output_model = AppointmentBusinessLoopPlan
    risk_level = "low"
    operation_spec = _spec("appointment_compile_blueprint", "sdk.blueprint.compile_appointment_business")
    example_inputs: Mapping[str, Any] = _LazyExample("compile")

    def _execute(self, context: PrimitiveExecutionContext, inputs: CompileAppointmentBusinessInput) -> PrimitiveExecutionResult[AppointmentBusinessLoopPlan]:
        request_digest = _request_digest(inputs.to_dict())
        if not _scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self._blocked(request_digest=request_digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            plan = compile_appointment_business_blueprint(inputs.blueprint.to_dict() if inputs.profile == "custom" and inputs.blueprint is not None else inputs.profile, inputs.overrides)
        except ValueError as exc:
            return self._blocked(request_digest=request_digest, code="BLUEPRINT_INVALID", message=str(exc)[:500])
        return self._preview(output=plan, request_digest=request_digest, external_refs={"plan_digest": plan.plan_digest}, event_type="blueprint.appointment_business_compiled", event_payload={"profile": plan.blueprint.profile, "services": len(plan.blueprint.services), "deposit_percent": str(plan.blueprint.deposit_percent), "cancellation_window_hours": plan.blueprint.cancellation_window_hours}, evidence_kind="appointment_business_loop_plan", evidence_summary="Loop plan with stage bindings; nothing executed.", summary=f"Compiled {plan.blueprint.profile} appointment plan ({len(plan.blueprint.services)} services, {plan.blueprint.cancellation_window_hours}h cancellation window).")


class GenerateAvailabilityPrimitive(_AppointmentPrimitive[GenerateAvailabilityInput, Availability]):
    primitive_ref = "appointment.generate_availability"
    version = "0.1.0"
    title = "Generate available slots"
    description = "Deterministic open slots for a service across providers inside working hours, the booking horizon, the notice period, and buffers around existing bookings; the sealed availability digest is what a booking links."
    input_model = GenerateAvailabilityInput
    output_model = Availability
    risk_level = "low"
    operation_spec = _spec("appointment_generate_availability", "sdk.appointment.generate_availability")
    example_inputs: Mapping[str, Any] = _LazyExample("availability")

    def _execute(self, context: PrimitiveExecutionContext, inputs: GenerateAvailabilityInput) -> PrimitiveExecutionResult[Availability]:
        request_digest = _request_digest(inputs.to_dict())
        if not _scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self._blocked(request_digest=request_digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            availability = generate_availability(inputs.plan, service_ref=inputs.service_ref, provider_refs=inputs.provider_refs, window_start=inputs.window_start, window_end=inputs.window_end, existing_bookings=inputs.existing_bookings, now=inputs.now)
        except ValueError as exc:
            return self._blocked(request_digest=request_digest, code="AVAILABILITY_INVALID", message=str(exc)[:500])
        return self._preview(output=availability, request_digest=request_digest, external_refs={"availability_digest": availability.availability_digest}, event_type="appointment.availability_generated", event_payload={"service_ref": inputs.service_ref, "slots": len(availability.slots), "capacity_minutes": availability.capacity_minutes, "booked_minutes": availability.booked_minutes, "truncated": availability.truncated}, evidence_kind="appointment_availability", evidence_summary="Open slots computed from the blueprint and existing bookings; no calendar read or write.", summary=f"{len(availability.slots)} open slot(s) for {inputs.service_ref} across {len(availability.provider_refs)} provider(s).")


class AdvanceBookingPrimitive(_AppointmentPrimitive[AdvanceBookingInput, BookingTransitionResult]):
    primitive_ref = "appointment.advance_booking"
    version = "0.1.0"
    title = "Advance a booking by one transition"
    description = "Materialize one replay-fenced booking transition: deposit at the policy amount, reminders on the schedule, confirmation, bounded reschedules inside hours and notice, cancellation with the window-derived late fee, check-in with intake consent, service, payment of the exact balance, no-show fee, and follow-up with rebooking or satisfaction."
    input_model = AdvanceBookingInput
    output_model = BookingTransitionResult
    risk_level = "medium"
    operation_spec = _spec("appointment_advance_booking", "sdk.appointment.advance_booking")
    example_inputs: Mapping[str, Any] = _LazyExample("advance")

    def _execute(self, context: PrimitiveExecutionContext, inputs: AdvanceBookingInput) -> PrimitiveExecutionResult[BookingTransitionResult]:
        request_digest = _request_digest(inputs.to_dict())
        scope = inputs.state.scope
        if not _scope_matches(RequestScope(tenant_ref=scope.tenant_ref, company_ref=scope.company_ref, project_ref=scope.project_ref, project_id=scope.project_id), inputs.command.actor_ref, context):
            return self._blocked(request_digest=request_digest, code="SCOPE_MISMATCH", message="Runtime scope and acting actor must exactly match the booking scope and the command.")
        try:
            result = advance_booking(inputs.plan, inputs.state, inputs.command)
        except ValueError as exc:
            return self._blocked(request_digest=request_digest, code="STATE_NOT_BOUND", message=str(exc)[:500])
        receipt = result.receipt
        blocker = None if result.candidate_validated else PrimitiveBlocker(code=str(receipt.rejection_code), message=str(receipt.recovery.instructions)[:500], retryable=receipt.recovery.disposition in {"refresh_state", "await_approval"})
        return self._preview(output=result, request_digest=request_digest, external_refs={"booking_ref": scope.booking_ref, "transition_ref": receipt.transition_ref, "to_state_digest": receipt.to_state_digest}, event_type="appointment.booking_advanced", event_payload={"event": receipt.event, "transition_status": receipt.status, "from_status": receipt.from_status, "to_status": receipt.to_status, "rejection_code": receipt.rejection_code, "recovery": receipt.recovery.disposition}, evidence_kind="appointment_booking_transition", evidence_summary="Replay-fenced booking transition; candidate until Spring retains it.", summary=(f"{receipt.event}: {receipt.from_status} -> {receipt.to_status} (v{receipt.to_version})." if result.candidate_validated else f"{receipt.event} rejected: {receipt.rejection_code} ({receipt.recovery.disposition})."), blocker=blocker)


class AssessSchedulePrimitive(_AppointmentPrimitive[AssessScheduleInput, ScheduleAssessment]):
    primitive_ref = "appointment.assess_schedule"
    version = "0.1.0"
    title = "Assess a schedule (learn stage)"
    description = "Effect-dark schedule metrics: utilization against capacity, no-show and late-cancel rates against the blueprint ceiling, rebooking rate against target, revenue, fees, unpaid balances, average ticket and satisfaction, with recommendations."
    input_model = AssessScheduleInput
    output_model = ScheduleAssessment
    risk_level = "low"
    operation_spec = _spec("appointment_assess_schedule", "sdk.appointment.assess_schedule")
    example_inputs: Mapping[str, Any] = _LazyExample("assess")

    def _execute(self, context: PrimitiveExecutionContext, inputs: AssessScheduleInput) -> PrimitiveExecutionResult[ScheduleAssessment]:
        request_digest = _request_digest(inputs.to_dict())
        if not _scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self._blocked(request_digest=request_digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            assessment = assess_schedule(inputs.plan, inputs.bookings, capacity_minutes=inputs.capacity_minutes, assessed_at=inputs.assessed_at)
        except ValueError as exc:
            return self._blocked(request_digest=request_digest, code="BOOKINGS_NOT_BOUND", message=str(exc)[:500])
        return self._preview(output=assessment, request_digest=request_digest, external_refs={"assessment_digest": assessment.assessment_digest}, event_type="appointment.schedule_assessed", event_payload={"bookings": assessment.bookings, "utilization_percent": None if assessment.utilization_percent is None else str(assessment.utilization_percent), "no_show_rate_percent": None if assessment.no_show_rate_percent is None else str(assessment.no_show_rate_percent), "learnings": list(assessment.learnings)}, evidence_kind="appointment_schedule_assessment", evidence_summary="Schedule metrics; no effect.", summary=f"{assessment.bookings} booking(s): {assessment.learnings[0]}")


APPOINTMENT_BUSINESS_EXECUTABLE_PRIMITIVES: tuple[BusinessProcessPrimitive[Any, Any], ...] = (
    CompileAppointmentBusinessPrimitive(),
    GenerateAvailabilityPrimitive(),
    AdvanceBookingPrimitive(),
    AssessSchedulePrimitive(),
)

APPOINTMENT_BUSINESS_INTEGRATION_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.capability_pack_integration_manifest.v1",
    "capability_pack": "appointment_business_golden_loop",
    "golden_loop": APPOINTMENT_BUSINESS_GOLDEN_LOOP,
    "archetype": APPOINTMENT_BUSINESS_ARCHETYPE_MANIFEST,
    "base": "origin/main d6528edc87ee79ad5fb2c2d39339901a99517b21",
    "modules": {"domain": "lightbulb.appointment_business_loop", "primitives": "lightbulb.appointment_business_primitives"},
    "reuses": ["calendar.schedule_meeting and calendar.* connector tools", "finance.create_invoice, finance.collect_payment", "communication.write_email, communication.plan_governed_voice_call", "service.* cases", "growth.* funnel, customer value, unit economics", "compliance.evaluate_regulated_controls (intake consent)"],
    "primitive_refs": [item.primitive_ref for item in APPOINTMENT_BUSINESS_EXECUTABLE_PRIMITIVES],
    "executable_registry": {"file": "lightbulb/executable_primitives.py", "import": "from lightbulb.appointment_business_primitives import APPOINTMENT_BUSINESS_EXECUTABLE_PRIMITIVES", "splice": "*APPOINTMENT_BUSINESS_EXECUTABLE_PRIMITIVES in BUILTIN_EXECUTABLE_PRIMITIVES"},
    "golden_loop_registry": {"note": "register appointment.booking_to_rebooking_business@0.1.0 with STAGE_ORDER and the booking event table"},
    "company_blueprints": {"note": "register the appointment_business archetype with APPOINTMENT_BUSINESS_PROFILES; composable with the other archetypes"},
    "public_exports": {"file": "lightbulb/__init__.py", "names": ["APPOINTMENT_BUSINESS_EXECUTABLE_PRIMITIVES", "APPOINTMENT_BUSINESS_INTEGRATION_MANIFEST", "APPOINTMENT_BUSINESS_PROFILES", "APPOINTMENT_BUSINESS_ARCHETYPE_MANIFEST", "AppointmentBusinessBlueprint", "AppointmentBusinessLoopPlan", "Availability", "BookingState", "compile_appointment_business_blueprint", "generate_availability", "open_booking", "advance_booking", "assess_schedule"]},
    "non_goals": ["no calendar write, payment, reminder, or fee executed here", "no personal health or identity data on the wire (identity-like fields are refused)", "no certification or production-readiness claim"],
}

__all__ = [
    "APPOINTMENT_BUSINESS_EXECUTABLE_PRIMITIVES",
    "APPOINTMENT_BUSINESS_INTEGRATION_MANIFEST",
    "AdvanceBookingInput",
    "AdvanceBookingPrimitive",
    "AssessScheduleInput",
    "AssessSchedulePrimitive",
    "CompileAppointmentBusinessInput",
    "CompileAppointmentBusinessPrimitive",
    "GenerateAvailabilityInput",
    "GenerateAvailabilityPrimitive",
    "RequestScope",
    "example_appointment_inputs",
]
