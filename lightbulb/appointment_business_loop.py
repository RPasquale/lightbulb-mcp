"""Appointment Business Golden Operating Loop and Company Blueprint profiles.

Clinics, salons, trades site visits, coaches, studios, and every other
business that sells time in slots share one loop::

    Attract -> Book (deposit, intake) -> Confirm and remind -> Arrive
           -> Serve -> Pay -> Follow up and rebook -> Learn

and the branches that come with it: cancellations inside and outside the
window, late-cancel and no-show fees, reschedules, waitlists, and overbooked
providers.  This pack types the schedule (working hours, providers, slot and
buffer lengths, horizon), deterministic availability generation, a
replay-fenced per-booking lifecycle with policy-derived fees, and a schedule
assessment (utilization, no-show and late-cancel rates, rebooking, revenue).

Nothing here writes to a calendar, takes a payment, or sends a reminder;
those are Spring-authorized effects executed through ``calendar.*``,
``finance.collect_payment``, and ``communication.write_email``.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from datetime import datetime, time, timedelta, timezone
from decimal import Decimal, InvalidOperation
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationInfo, field_validator, model_validator


APPOINTMENT_BUSINESS_GOLDEN_LOOP = "appointment.booking_to_rebooking_business@0.1.0"
APPOINTMENT_BUSINESS_ARCHETYPE = "appointment_business"
BLUEPRINT_SCHEMA = "lightbulb.appointment_business_blueprint.v1"
PLAN_SCHEMA = "lightbulb.appointment_business_loop_plan.v1"
AVAILABILITY_SCHEMA = "lightbulb.appointment_availability.v1"
BOOKING_COMMAND_SCHEMA = "lightbulb.appointment_booking_command.v1"
BOOKING_STATE_SCHEMA = "lightbulb.appointment_booking_state.v1"
BOOKING_RESULT_SCHEMA = "lightbulb.appointment_booking_transition_result.v1"
SCHEDULE_ASSESSMENT_SCHEMA = "lightbulb.appointment_schedule_assessment.v1"
GENESIS_DIGEST = "0" * 64
MAX_BOOKING_TRANSITIONS = 60
MAX_AVAILABILITY_SLOTS = 5000

_REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_SECRET_LIKE_KEYS = ("secret", "password", "passwd", "token", "api_key", "apikey", "authorization", "credential", "private_key", "client_secret", "tenant_id", "company_id", "user_id", "card_number", "cvc", "date_of_birth", "national_id", "insurance_number")
_SECRET_LIKE_VALUES: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{8,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{16,}", re.IGNORECASE),
    re.compile(r"(?<![0-9A-Za-z-])\d{13,19}(?![0-9A-Za-z-])"),
)
_MONEY_QUANTUM = Decimal("0.01")

OpaqueRef = Annotated[str, StringConstraints(pattern=_REF_PATTERN)]
Sha256Digest = Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)]
ShortText = Annotated[str, StringConstraints(min_length=1, max_length=300)]
BoundedText = Annotated[str, StringConstraints(min_length=1, max_length=2000)]
CurrencyCode = Annotated[str, StringConstraints(pattern=r"^[A-Z]{3}$")]
ClockTime = Annotated[str, StringConstraints(pattern=r"^(?:[01]\d|2[0-3]):[0-5]\d$")]

BlueprintProfile = Literal["clinic", "salon", "trades_visit", "coaching", "custom"]
Weekday = Literal["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
_WEEKDAYS: tuple[str, ...] = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
BookingStatus = Literal["requested", "waitlisted", "booked", "confirmed", "checked_in", "in_service", "completed", "paid", "followed_up", "cancelled", "cancelled_late", "no_show"]
TERMINAL_BOOKING_STATUSES: frozenset[str] = frozenset({"followed_up", "cancelled", "cancelled_late", "no_show"})
BookingEvent = Literal["book", "offer_slot", "collect_deposit", "send_reminder", "confirm", "reschedule", "cancel", "check_in", "start_service", "complete", "record_payment", "mark_no_show", "follow_up"]
LoopStage = Literal["attract", "book", "remind", "arrive", "serve", "pay", "rebook", "learn"]
STAGE_ORDER: tuple[str, ...] = ("attract", "book", "remind", "arrive", "serve", "pay", "rebook", "learn")
RecoveryDisposition = Literal["not_required", "do_not_replay", "refresh_state", "correct_input", "manual_reconciliation", "await_approval"]
_TABLE: dict[tuple[str, str], str] = {
    ("requested", "book"): "booked", ("requested", "cancel"): "cancelled",
    ("waitlisted", "offer_slot"): "requested", ("waitlisted", "cancel"): "cancelled",
    ("booked", "collect_deposit"): "booked", ("booked", "send_reminder"): "booked", ("booked", "confirm"): "confirmed", ("booked", "reschedule"): "booked", ("booked", "cancel"): "cancelled", ("booked", "check_in"): "checked_in", ("booked", "mark_no_show"): "no_show",
    ("confirmed", "send_reminder"): "confirmed", ("confirmed", "reschedule"): "booked", ("confirmed", "cancel"): "cancelled", ("confirmed", "check_in"): "checked_in", ("confirmed", "mark_no_show"): "no_show",
    ("checked_in", "start_service"): "in_service",
    ("in_service", "complete"): "completed",
    ("completed", "record_payment"): "paid",
    ("paid", "follow_up"): "followed_up",
}
_KNOWN_PRIMITIVE_REFS: frozenset[str] = frozenset(
    {
        "blueprint.compile_appointment_business", "appointment.generate_availability", "appointment.advance_booking", "appointment.assess_schedule",
        "demand_gen.plan_audience_growth", "demand_gen.plan_content_calendar", "crm.qualify_lead", "communication.plan_crm_conversation_turn", "communication.write_email", "communication.plan_governed_voice_call",
        "calendar.schedule_meeting", "finance.create_invoice", "finance.collect_payment", "service.intake_and_classify_case", "service.verify_case_resolution",
        "growth.build_funnel_snapshot", "growth.review_customer_value", "growth.build_unit_economics", "learning.plan_optimization_sweep", "compliance.evaluate_regulated_controls",
    }
)
_KNOWN_CONNECTOR_TOOLS: frozenset[str] = frozenset({"calendar.get_availability", "calendar.create_event", "calendar.update_event", "calendar.delete_event", "calendar.list_events", "square.create_invoice", "square.list_payments", "stripe.create_invoice", "xero.create_invoice", "hubspot.create_workflow"})


# --------------------------------------------------------------------------- #
# Strict model and helpers
# --------------------------------------------------------------------------- #


def _reject_secret_like_payload(value: Any, *, path: str = "input") -> None:
    if isinstance(value, str):
        if any(pattern.search(value) for pattern in _SECRET_LIKE_VALUES):
            raise ValueError(f"{path} carries a secret-like, card-like, or identity-like value and is never accepted")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            lowered = str(key).lower()
            if any(marker in lowered for marker in _SECRET_LIKE_KEYS):
                raise ValueError(f"{path}.{key} is a credential-, card-, or personal-identity field and is never accepted")
            _reject_secret_like_payload(item, path=f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _reject_secret_like_payload(item, path=f"{path}[{index}]")


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True, revalidate_instances="always", serialize_by_alias=True, strict=True)

    @model_validator(mode="before")
    @classmethod
    def _portable_payload(cls, value: Any) -> Any:
        if isinstance(value, BaseModel):
            value = value.model_dump(mode="json", by_alias=True, exclude_none=True)
        if not isinstance(value, Mapping):
            return value
        _reject_secret_like_payload(value)
        return {str(key): (tuple(item) if isinstance(item, list) else item) for key, item in value.items()}

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def _detached(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", by_alias=True, exclude_none=True)
    if isinstance(value, Mapping):
        return {str(key): _detached(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_detached(item) for item in value]
    return value


def _timestamp(value: str, *, field_name: str) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(f"{field_name} must be an ISO-8601 UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError(f"{field_name} must be an ISO-8601 UTC timestamp ending in Z") from exc
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parsed(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1] + "+00:00")


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _decimal(value: Any, *, field_name: str, allow_negative: bool = False) -> Decimal:
    if isinstance(value, bool) or isinstance(value, float):
        raise ValueError(f"{field_name} must be a decimal string, integer, or Decimal")
    try:
        parsed = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"{field_name} must be a decimal") from exc
    if not parsed.is_finite() or (parsed < 0 and not allow_negative) or abs(parsed) > Decimal("1000000000000"):
        raise ValueError(f"{field_name} must be a finite {'bounded' if allow_negative else 'non-negative bounded'} decimal")
    return parsed.quantize(_MONEY_QUANTUM)


def _stable_digest(value: Any) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _skip(info: ValidationInfo) -> bool:
    return bool((info.context or {}).get("skip_appointment_digests"))


def _sealed_digest(model: type[_StrictModel], payload: Any, field: str) -> str:
    raw = dict(_detached(payload))
    raw.setdefault(field, GENESIS_DIGEST)
    parsed = model.model_validate(raw, context={"skip_appointment_digests": True})
    return _stable_digest({key: value for key, value in parsed.to_dict().items() if key != field})


def _seal(model: type[_StrictModel], payload: Mapping[str, Any], field: str) -> Any:
    raw = dict(_detached(payload))
    raw[field] = _sealed_digest(model, raw, field)
    return model.model_validate(raw)


def _unique(values: Sequence[str], *, label: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must be unique")


def _clock(value: str) -> time:
    hours, minutes = value.split(":")
    return time(int(hours), int(minutes))


# --------------------------------------------------------------------------- #
# Blueprint and plan
# --------------------------------------------------------------------------- #


class WorkingHours(_StrictModel):
    weekday: Weekday
    opens: ClockTime
    closes: ClockTime

    @model_validator(mode="after")
    def _ordered(self) -> "WorkingHours":
        if _clock(self.closes) <= _clock(self.opens):
            raise ValueError(f"{self.weekday} must close after it opens")
        return self


class ServiceOffering(_StrictModel):
    service_ref: OpaqueRef
    name: ShortText
    duration_minutes: int = Field(ge=5, le=1440)
    price: Decimal
    requires_intake: bool = False
    rebooking_interval_days: int = Field(default=0, ge=0, le=365)

    @field_validator("price", mode="before")
    @classmethod
    def _price(cls, value: Any) -> Decimal:
        return _decimal(value, field_name="price")


class AppointmentBusinessBlueprint(_StrictModel):
    schema_id: Literal["lightbulb.appointment_business_blueprint.v1"] = Field(default=BLUEPRINT_SCHEMA, alias="schema")
    profile: BlueprintProfile
    name: ShortText
    working_hours: tuple[WorkingHours, ...] = Field(min_length=1, max_length=7)
    services: tuple[ServiceOffering, ...] = Field(min_length=1, max_length=100)
    slot_minutes: int = Field(default=15, ge=5, le=240)
    buffer_minutes: int = Field(default=0, ge=0, le=240)
    booking_horizon_days: int = Field(default=60, ge=1, le=365)
    min_notice_hours: int = Field(default=2, ge=0, le=720)
    cancellation_window_hours: int = Field(default=24, ge=0, le=720)
    late_cancel_fee_percent: Decimal = Field(default=Decimal("50"), validate_default=True)
    no_show_fee_percent: Decimal = Field(default=Decimal("100"), validate_default=True)
    deposit_percent: Decimal = Field(default=Decimal("0"), validate_default=True)
    reminder_hours_before: tuple[int, ...] = Field(default=(48, 2), max_length=5)
    max_reschedules: int = Field(default=2, ge=0, le=10)
    waitlist_enabled: bool = True
    intake_consent_required: bool = False
    target_utilization_percent: Decimal = Field(default=Decimal("75"), validate_default=True)
    max_no_show_rate_percent: Decimal = Field(default=Decimal("8"), validate_default=True)
    target_rebooking_rate_percent: Decimal = Field(default=Decimal("40"), validate_default=True)
    currency: CurrencyCode = "USD"
    notes: BoundedText | None = None
    blueprint_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("late_cancel_fee_percent", "no_show_fee_percent", "deposit_percent", "target_utilization_percent", "max_no_show_rate_percent", "target_rebooking_rate_percent", mode="before")
    @classmethod
    def _percents(cls, value: Any, info: ValidationInfo) -> Decimal:
        parsed = _decimal(value, field_name=str(info.field_name))
        if parsed > 100:
            raise ValueError(f"{info.field_name} must be between 0 and 100")
        return parsed

    @model_validator(mode="after")
    def _blueprint_is_exact(self, info: ValidationInfo) -> "AppointmentBusinessBlueprint":
        _unique([item.weekday for item in self.working_hours], label="working-hour weekdays")
        _unique([item.service_ref for item in self.services], label="service refs")
        hours = list(self.reminder_hours_before)
        if any(hour < 1 for hour in hours) or hours != sorted(hours, reverse=True) or len(set(hours)) != len(hours):
            raise ValueError("reminder hours must be distinct positive values in descending order")
        if any(item.duration_minutes % self.slot_minutes for item in self.services):
            raise ValueError("every service duration must be a multiple of the slot length")
        if _skip(info):
            return self
        if self.blueprint_digest != _sealed_digest(AppointmentBusinessBlueprint, self, "blueprint_digest"):
            raise ValueError("blueprint_digest must commit the exact blueprint")
        return self

    def service(self, service_ref: str) -> ServiceOffering | None:
        return next((item for item in self.services if item.service_ref == service_ref), None)

    def hours_for(self, weekday: str) -> WorkingHours | None:
        return next((item for item in self.working_hours if item.weekday == weekday), None)


def seal_appointment_business_blueprint(blueprint: Mapping[str, Any]) -> dict[str, Any]:
    raw = dict(_detached(blueprint))
    raw["blueprint_digest"] = _sealed_digest(AppointmentBusinessBlueprint, raw, "blueprint_digest")
    return AppointmentBusinessBlueprint.model_validate(raw).to_dict()


_WEEKDAY_HOURS = [{"weekday": day, "opens": "09:00", "closes": "17:00"} for day in ("mon", "tue", "wed", "thu", "fri")]
APPOINTMENT_BUSINESS_PROFILES: dict[str, dict[str, Any]] = {
    "clinic": {"profile": "clinic", "name": "Outpatient clinic", "working_hours": _WEEKDAY_HOURS, "services": [{"service_ref": "consult", "name": "Consultation", "duration_minutes": 30, "price": "120", "requires_intake": True, "rebooking_interval_days": 90}, {"service_ref": "follow-up", "name": "Follow-up", "duration_minutes": 15, "price": "60", "requires_intake": False, "rebooking_interval_days": 30}], "slot_minutes": 15, "buffer_minutes": 5, "booking_horizon_days": 90, "min_notice_hours": 24, "cancellation_window_hours": 24, "late_cancel_fee_percent": "50", "no_show_fee_percent": "100", "deposit_percent": "0", "reminder_hours_before": [72, 24], "max_reschedules": 2, "waitlist_enabled": True, "intake_consent_required": True, "target_utilization_percent": "80", "max_no_show_rate_percent": "5", "target_rebooking_rate_percent": "60", "notes": "Consent and intake before the first visit; no-shows billed in full."},
    "salon": {"profile": "salon", "name": "Salon or studio", "working_hours": [*_WEEKDAY_HOURS[1:], {"weekday": "sat", "opens": "09:00", "closes": "15:00"}], "services": [{"service_ref": "cut", "name": "Cut", "duration_minutes": 45, "price": "55", "rebooking_interval_days": 42}, {"service_ref": "colour", "name": "Colour", "duration_minutes": 120, "price": "140", "rebooking_interval_days": 56}], "slot_minutes": 15, "buffer_minutes": 10, "booking_horizon_days": 60, "min_notice_hours": 2, "cancellation_window_hours": 24, "late_cancel_fee_percent": "50", "no_show_fee_percent": "50", "deposit_percent": "20", "reminder_hours_before": [48, 2], "max_reschedules": 3, "waitlist_enabled": True, "intake_consent_required": False, "target_utilization_percent": "70", "max_no_show_rate_percent": "8", "target_rebooking_rate_percent": "50", "notes": "Deposit at booking; rebook at the chair."},
    "trades_visit": {"profile": "trades_visit", "name": "Trades site visits", "working_hours": [{"weekday": day, "opens": "08:00", "closes": "16:00"} for day in ("mon", "tue", "wed", "thu", "fri")], "services": [{"service_ref": "site-visit", "name": "Site visit and quote", "duration_minutes": 60, "price": "0", "rebooking_interval_days": 0}, {"service_ref": "install", "name": "Installation", "duration_minutes": 240, "price": "480", "rebooking_interval_days": 365}], "slot_minutes": 30, "buffer_minutes": 30, "booking_horizon_days": 45, "min_notice_hours": 24, "cancellation_window_hours": 48, "late_cancel_fee_percent": "25", "no_show_fee_percent": "25", "deposit_percent": "30", "reminder_hours_before": [48, 24], "max_reschedules": 2, "waitlist_enabled": False, "intake_consent_required": False, "target_utilization_percent": "65", "max_no_show_rate_percent": "10", "target_rebooking_rate_percent": "20", "notes": "Travel buffers between visits; deposits on installs."},
    "coaching": {"profile": "coaching", "name": "Coaching or tutoring", "working_hours": [*_WEEKDAY_HOURS, {"weekday": "sat", "opens": "10:00", "closes": "14:00"}], "services": [{"service_ref": "session", "name": "Session", "duration_minutes": 60, "price": "90", "rebooking_interval_days": 7}], "slot_minutes": 30, "buffer_minutes": 0, "booking_horizon_days": 30, "min_notice_hours": 12, "cancellation_window_hours": 48, "late_cancel_fee_percent": "100", "no_show_fee_percent": "100", "deposit_percent": "100", "reminder_hours_before": [24], "max_reschedules": 1, "waitlist_enabled": True, "intake_consent_required": False, "target_utilization_percent": "60", "max_no_show_rate_percent": "5", "target_rebooking_rate_percent": "80", "notes": "Prepaid sessions; weekly rebooking."},
}


class StageBinding(_StrictModel):
    stage: LoopStage
    title: ShortText
    primitive_refs: tuple[ShortText, ...] = Field(min_length=1, max_length=12)
    connector_tools: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=12)
    booking_events: tuple[BookingEvent, ...] = Field(default_factory=tuple, max_length=8)
    gate: Literal["none", "spring_approval", "customer_consent"] = "none"

    @model_validator(mode="after")
    def _bound_to_known(self) -> "StageBinding":
        unknown = [ref for ref in self.primitive_refs if ref not in _KNOWN_PRIMITIVE_REFS]
        if unknown:
            raise ValueError(f"stage {self.stage} binds unknown primitives: {unknown}")
        unknown_tools = [tool for tool in self.connector_tools if tool not in _KNOWN_CONNECTOR_TOOLS]
        if unknown_tools:
            raise ValueError(f"stage {self.stage} binds unknown connector tools: {unknown_tools}")
        return self


class AppointmentBusinessLoopPlan(_StrictModel):
    schema_id: Literal["lightbulb.appointment_business_loop_plan.v1"] = Field(default=PLAN_SCHEMA, alias="schema")
    golden_loop: Literal["appointment.booking_to_rebooking_business@0.1.0"] = APPOINTMENT_BUSINESS_GOLDEN_LOOP
    archetype: Literal["appointment_business"] = APPOINTMENT_BUSINESS_ARCHETYPE
    blueprint: AppointmentBusinessBlueprint
    stages: tuple[StageBinding, ...] = Field(min_length=8, max_length=8)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _plan_is_exact(self, info: ValidationInfo) -> "AppointmentBusinessLoopPlan":
        if tuple(item.stage for item in self.stages) != STAGE_ORDER:
            raise ValueError("plan stages must follow the loop order exactly")
        if _skip(info):
            return self
        if self.plan_digest != _sealed_digest(AppointmentBusinessLoopPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self

    def stage(self, name: str) -> StageBinding:
        return next(item for item in self.stages if item.stage == name)


def _stage_bindings(blueprint: AppointmentBusinessBlueprint) -> list[dict[str, Any]]:
    intake: tuple[str, ...] = ("compliance.evaluate_regulated_controls",) if blueprint.intake_consent_required else ()
    return [
        {"stage": "attract", "title": "Attract bookings", "primitive_refs": ("demand_gen.plan_audience_growth", "demand_gen.plan_content_calendar", "crm.qualify_lead"), "gate": "none"},
        {"stage": "book", "title": "Book a slot" + (" with deposit" if blueprint.deposit_percent > 0 else ""), "primitive_refs": ("appointment.generate_availability", "appointment.advance_booking", "calendar.schedule_meeting") + (("finance.collect_payment",) if blueprint.deposit_percent > 0 else ()) + intake, "connector_tools": ("calendar.get_availability", "calendar.create_event"), "booking_events": ("book", "offer_slot", "collect_deposit", "reschedule", "cancel"), "gate": "customer_consent" if blueprint.intake_consent_required else "none"},
        {"stage": "remind", "title": "Confirm and remind", "primitive_refs": ("communication.write_email", "communication.plan_governed_voice_call", "appointment.advance_booking"), "connector_tools": ("calendar.update_event",), "booking_events": ("send_reminder", "confirm", "reschedule", "cancel"), "gate": "spring_approval"},
        {"stage": "arrive", "title": "Arrive: check-in, late cancel, no-show", "primitive_refs": ("appointment.advance_booking",), "booking_events": ("check_in", "mark_no_show", "cancel"), "gate": "none"},
        {"stage": "serve", "title": "Serve", "primitive_refs": ("appointment.advance_booking", "service.intake_and_classify_case"), "booking_events": ("start_service", "complete"), "gate": "none"},
        {"stage": "pay", "title": "Pay", "primitive_refs": ("finance.create_invoice", "finance.collect_payment", "appointment.advance_booking"), "connector_tools": ("square.create_invoice", "square.list_payments"), "booking_events": ("record_payment",), "gate": "spring_approval"},
        {"stage": "rebook", "title": "Follow up and rebook", "primitive_refs": ("communication.write_email", "growth.review_customer_value", "appointment.advance_booking"), "connector_tools": ("hubspot.create_workflow",), "booking_events": ("follow_up",), "gate": "none"},
        {"stage": "learn", "title": "Learn: utilization, no-shows, rebooking", "primitive_refs": ("appointment.assess_schedule", "growth.build_funnel_snapshot", "growth.build_unit_economics", "learning.plan_optimization_sweep"), "gate": "none"},
    ]


def compile_appointment_business_blueprint(profile: str | Mapping[str, Any], overrides: Mapping[str, Any] | None = None) -> AppointmentBusinessLoopPlan:
    if isinstance(profile, str):
        if profile not in APPOINTMENT_BUSINESS_PROFILES:
            raise ValueError(f"unknown appointment business profile {profile!r}; choose one of {sorted(APPOINTMENT_BUSINESS_PROFILES)} or pass a custom blueprint")
        raw: dict[str, Any] = json.loads(json.dumps(APPOINTMENT_BUSINESS_PROFILES[profile]))
    else:
        raw = dict(_detached(profile))
    for key, value in dict(overrides or {}).items():
        if key in {"schema", "blueprint_digest"}:
            raise ValueError("overrides cannot set schema or digest fields")
        raw[key] = value
    blueprint = AppointmentBusinessBlueprint.model_validate(seal_appointment_business_blueprint(raw))
    payload = {"blueprint": blueprint.to_dict(), "stages": _stage_bindings(blueprint)}
    payload["plan_digest"] = _sealed_digest(AppointmentBusinessLoopPlan, payload, "plan_digest")
    return AppointmentBusinessLoopPlan.model_validate(payload)


# --------------------------------------------------------------------------- #
# Availability
# --------------------------------------------------------------------------- #


class ExistingBooking(_StrictModel):
    booking_ref: OpaqueRef
    provider_ref: OpaqueRef
    starts_at: str
    ends_at: str

    @field_validator("starts_at", "ends_at")
    @classmethod
    def _times(cls, value: str, info: ValidationInfo) -> str:
        return _timestamp(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _ordered(self) -> "ExistingBooking":
        if _parsed(self.ends_at) <= _parsed(self.starts_at):
            raise ValueError("a booking must end after it starts")
        return self


class AvailableSlot(_StrictModel):
    provider_ref: OpaqueRef
    starts_at: str
    ends_at: str


class Availability(_StrictModel):
    schema_id: Literal["lightbulb.appointment_availability.v1"] = Field(default=AVAILABILITY_SCHEMA, alias="schema")
    plan_digest: Sha256Digest
    service_ref: OpaqueRef
    window_start: str
    window_end: str
    provider_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=200)
    slots: tuple[AvailableSlot, ...] = Field(default_factory=tuple, max_length=MAX_AVAILABILITY_SLOTS)
    capacity_minutes: int = Field(ge=0)
    booked_minutes: int = Field(ge=0)
    truncated: bool = False
    availability_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _availability_is_exact(self, info: ValidationInfo) -> "Availability":
        if _skip(info):
            return self
        if self.availability_digest != _sealed_digest(Availability, self, "availability_digest"):
            raise ValueError("availability_digest must commit the exact availability")
        return self


def _overlaps(start: datetime, end: datetime, bookings: Sequence[ExistingBooking], provider_ref: str, buffer: timedelta) -> bool:
    for booking in bookings:
        if booking.provider_ref != provider_ref:
            continue
        booked_start, booked_end = _parsed(booking.starts_at) - buffer, _parsed(booking.ends_at) + buffer
        if start < booked_end and end > booked_start:
            return True
    return False


def generate_availability(plan: AppointmentBusinessLoopPlan | Mapping[str, Any], *, service_ref: str, provider_refs: Sequence[str], window_start: str, window_end: str, existing_bookings: Sequence[ExistingBooking | Mapping[str, Any]] = (), now: str | None = None) -> Availability:
    """Deterministic open slots for a service across providers inside working hours, horizon, notice, and buffers."""

    parsed_plan = AppointmentBusinessLoopPlan.model_validate(_detached(plan))
    blueprint = parsed_plan.blueprint
    service = blueprint.service(service_ref)
    if service is None:
        raise ValueError(f"unknown service {service_ref}")
    providers = list(dict.fromkeys(provider_refs))
    if not providers:
        raise ValueError("at least one provider is required")
    start, end = _parsed(_timestamp(window_start, field_name="window_start")), _parsed(_timestamp(window_end, field_name="window_end"))
    if end <= start:
        raise ValueError("the window must end after it starts")
    reference = _parsed(_timestamp(now, field_name="now")) if now else start
    earliest = reference + timedelta(hours=blueprint.min_notice_hours)
    latest = reference + timedelta(days=blueprint.booking_horizon_days)
    bookings = [ExistingBooking.model_validate(_detached(item)) for item in existing_bookings]
    duration, step, buffer = timedelta(minutes=service.duration_minutes), timedelta(minutes=blueprint.slot_minutes), timedelta(minutes=blueprint.buffer_minutes)
    slots: list[dict[str, str]] = []
    capacity_minutes = 0
    truncated = False
    day = start.replace(hour=0, minute=0, second=0, microsecond=0)
    while day < end:
        hours = blueprint.hours_for(_WEEKDAYS[day.weekday()])
        if hours is not None:
            opens = day.replace(hour=_clock(hours.opens).hour, minute=_clock(hours.opens).minute)
            closes = day.replace(hour=_clock(hours.closes).hour, minute=_clock(hours.closes).minute)
            capacity_minutes += int((closes - opens).total_seconds() // 60) * len(providers)
            for provider in providers:
                cursor = opens
                while cursor + duration <= closes:
                    slot_end = cursor + duration
                    if cursor >= max(start, earliest) and slot_end <= min(end, latest) and not _overlaps(cursor, slot_end, bookings, provider, buffer):
                        if len(slots) >= MAX_AVAILABILITY_SLOTS:
                            truncated = True
                            break
                        slots.append({"provider_ref": provider, "starts_at": _iso(cursor), "ends_at": _iso(slot_end)})
                    cursor += step
                if truncated:
                    break
        if truncated:
            break
        day += timedelta(days=1)
    booked = sum(int((_parsed(item.ends_at) - _parsed(item.starts_at)).total_seconds() // 60) for item in bookings if item.provider_ref in providers and start <= _parsed(item.starts_at) < end)
    payload = {"plan_digest": parsed_plan.plan_digest, "service_ref": service_ref, "window_start": _iso(start), "window_end": _iso(end), "provider_refs": providers, "slots": slots, "capacity_minutes": capacity_minutes, "booked_minutes": booked, "truncated": truncated}
    return _seal(Availability, payload, "availability_digest")


# --------------------------------------------------------------------------- #
# Booking lifecycle
# --------------------------------------------------------------------------- #


class BookingScope(_StrictModel):
    tenant_ref: OpaqueRef
    company_ref: OpaqueRef
    project_ref: OpaqueRef
    project_id: str
    booking_ref: OpaqueRef
    customer_ref: OpaqueRef
    currency: CurrencyCode

    @field_validator("project_id")
    @classmethod
    def _project_id(cls, value: str) -> str:
        from uuid import UUID

        try:
            parsed = UUID(value)
        except ValueError as exc:
            raise ValueError("project_id must be a canonical UUID") from exc
        if str(parsed) != value:
            raise ValueError("project_id must be a canonical UUID")
        return value


class BookingReceipt(_StrictModel):
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    service_ref: OpaqueRef | None = None
    provider_ref: OpaqueRef | None = None
    starts_at: str | None = None
    availability_digest: Sha256Digest | None = None
    intake_consent_ref: OpaqueRef | None = None
    calendar_event_ref: OpaqueRef | None = None
    payment_ref: OpaqueRef | None = None
    amount: Decimal | None = None
    reminder_channel: Literal["email", "sms", "call"] | None = None
    confirmation_ref: OpaqueRef | None = None
    cancel_reason: ShortText | None = None
    checked_in_at: str | None = None
    case_ref: OpaqueRef | None = None
    invoice_ref: OpaqueRef | None = None
    rebooked_booking_ref: OpaqueRef | None = None
    satisfaction: int | None = Field(default=None, ge=0, le=10)

    @field_validator("amount", mode="before")
    @classmethod
    def _amount(cls, value: Any) -> Any:
        return None if value is None else _decimal(value, field_name="amount")

    @field_validator("starts_at", "checked_in_at")
    @classmethod
    def _times(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else _timestamp(value, field_name=str(info.field_name))


class BookingCommand(_StrictModel):
    schema_id: Literal["lightbulb.appointment_booking_command.v1"] = Field(default=BOOKING_COMMAND_SCHEMA, alias="schema")
    event: BookingEvent
    transition_ref: OpaqueRef
    idempotency_key: OpaqueRef
    expected_version: int = Field(ge=0, le=MAX_BOOKING_TRANSITIONS)
    expected_state_digest: Sha256Digest
    occurred_at: str
    actor_ref: OpaqueRef
    receipt: BookingReceipt = Field(default_factory=BookingReceipt)
    reason: BoundedText | None = None
    request_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("occurred_at")
    @classmethod
    def _occurred(cls, value: str) -> str:
        return _timestamp(value, field_name="occurred_at")

    @model_validator(mode="after")
    def _command_is_exact(self, info: ValidationInfo) -> "BookingCommand":
        if self.event in {"cancel", "mark_no_show"} and self.reason is None:
            raise ValueError(f"{self.event} requires a reason")
        if _skip(info):
            return self
        if self.request_digest != booking_command_digest(self):
            raise ValueError("request_digest must commit the exact normalized command")
        return self


def booking_command_digest(command: BookingCommand | Mapping[str, Any]) -> str:
    return _sealed_digest(BookingCommand, command, "request_digest")


def seal_booking_command(command: Mapping[str, Any]) -> dict[str, Any]:
    raw = dict(_detached(command))
    raw["request_digest"] = booking_command_digest(raw)
    return BookingCommand.model_validate(raw).to_dict()


class BookingLedger(_StrictModel):
    service_ref: OpaqueRef | None = None
    provider_ref: OpaqueRef | None = None
    starts_at: str | None = None
    ends_at: str | None = None
    price: Decimal = Field(default=Decimal("0"), validate_default=True)
    deposit_due: Decimal = Field(default=Decimal("0"), validate_default=True)
    deposit_paid: Decimal = Field(default=Decimal("0"), validate_default=True)
    fee_charged: Decimal = Field(default=Decimal("0"), validate_default=True)
    paid_total: Decimal = Field(default=Decimal("0"), validate_default=True)
    reminders_sent: int = Field(default=0, ge=0)
    reschedules: int = Field(default=0, ge=0)
    intake_consent_ref: OpaqueRef | None = None
    calendar_event_ref: OpaqueRef | None = None
    checked_in_at: str | None = None
    service_minutes: int = Field(default=0, ge=0)
    cancel_reason: ShortText | None = None
    rebooked_booking_ref: OpaqueRef | None = None
    satisfaction: int | None = Field(default=None, ge=0, le=10)
    outcome: Literal["attended", "cancelled_in_window", "cancelled_late", "no_show"] | None = None

    @field_validator("price", "deposit_due", "deposit_paid", "fee_charged", "paid_total", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _decimal(value, field_name=str(info.field_name))


class BookingTransition(_StrictModel):
    to_version: int = Field(ge=1, le=MAX_BOOKING_TRANSITIONS)
    prior_state_digest: Sha256Digest
    to_status: BookingStatus
    transition_digest: Sha256Digest
    command: BookingCommand

    @model_validator(mode="after")
    def _self_proving(self) -> "BookingTransition":
        if self.command.expected_version != self.to_version - 1 or self.command.expected_state_digest != self.prior_state_digest:
            raise ValueError("transition must match the command's revision and state fences")
        if self.transition_digest != _transition_digest(self.to_version, self.prior_state_digest, self.to_status, self.command):
            raise ValueError("transition digest must commit the exact transition")
        return self


def _transition_digest(to_version: int, prior: str, to_status: str, command: BookingCommand) -> str:
    return _stable_digest({"to_version": to_version, "prior_state_digest": prior, "to_status": to_status, "request_digest": command.request_digest, "transition_ref": command.transition_ref, "idempotency_key": command.idempotency_key})


def _state_digest(plan_digest: str, scope: BookingScope, history: Sequence[BookingTransition]) -> str:
    return _stable_digest({"plan_digest": plan_digest, "scope": scope.to_dict(), "transitions": [item.transition_digest for item in history]})


class _Rejected(ValueError):
    def __init__(self, code: str, instructions: str, recovery: RecoveryDisposition) -> None:
        super().__init__(instructions)
        self.code, self.instructions, self.recovery = code, instructions, recovery


def _place(blueprint: AppointmentBusinessBlueprint, data: dict[str, Any], r: BookingReceipt, at: datetime, *, reschedule: bool) -> None:
    service = blueprint.service(str(r.service_ref or data.get("service_ref") or ""))
    if service is None or r.provider_ref is None or r.starts_at is None:
        raise _Rejected("SLOT_MISSING", "a booking names the service, the provider, and the slot start", "correct_input")
    if r.availability_digest is None:
        raise _Rejected("AVAILABILITY_MISSING", "a booking links the availability digest the slot came from", "correct_input")
    start = _parsed(r.starts_at)
    hours = blueprint.hours_for(_WEEKDAYS[start.weekday()])
    end = start + timedelta(minutes=service.duration_minutes)
    if hours is None or start.time() < _clock(hours.opens) or end.time() > _clock(hours.closes) or end.date() != start.date():
        raise _Rejected("OUTSIDE_WORKING_HOURS", "the slot must fall inside the provider's working hours", "correct_input")
    if start < at + timedelta(hours=blueprint.min_notice_hours):
        raise _Rejected("NOTICE_TOO_SHORT", f"bookings need {blueprint.min_notice_hours} hours' notice", "correct_input")
    if start > at + timedelta(days=blueprint.booking_horizon_days):
        raise _Rejected("BEYOND_HORIZON", f"bookings are open {blueprint.booking_horizon_days} days ahead", "correct_input")
    if service.requires_intake and blueprint.intake_consent_required and r.intake_consent_ref is None and data.get("intake_consent_ref") is None:
        raise _Rejected("INTAKE_CONSENT_MISSING", "this service needs intake consent before booking", "correct_input")
    if reschedule and int(data.get("reschedules", 0)) + 1 > blueprint.max_reschedules:
        raise _Rejected("RESCHEDULE_LIMIT", f"the blueprint allows {blueprint.max_reschedules} reschedule(s)", "manual_reconciliation")
    data.update({"service_ref": service.service_ref, "provider_ref": r.provider_ref, "starts_at": _iso(start), "ends_at": _iso(end), "price": str(service.price), "deposit_due": str((service.price * blueprint.deposit_percent / Decimal(100)).quantize(_MONEY_QUANTUM)), "service_minutes": service.duration_minutes})
    if r.intake_consent_ref is not None:
        data["intake_consent_ref"] = r.intake_consent_ref
    if r.calendar_event_ref is not None:
        data["calendar_event_ref"] = r.calendar_event_ref
    if reschedule:
        data["reschedules"] = int(data.get("reschedules", 0)) + 1
        data["reminders_sent"] = 0


def _apply(plan: AppointmentBusinessLoopPlan, status: str, ledger: BookingLedger, command: BookingCommand) -> tuple[str, BookingLedger]:
    if status in TERMINAL_BOOKING_STATUSES:
        raise _Rejected("BOOKING_TERMINAL", f"booking is {status}; no further transitions", "do_not_replay")
    next_status = _TABLE.get((status, command.event))
    if next_status is None:
        raise _Rejected("ILLEGAL_TRANSITION", f"{command.event} is not a legal transition from {status}", "correct_input")
    blueprint, r, at = plan.blueprint, command.receipt, _parsed(command.occurred_at)
    data = ledger.to_dict()
    event = command.event
    if event == "book":
        _place(blueprint, data, r, at, reschedule=False)
    elif event == "offer_slot":
        if not blueprint.waitlist_enabled:
            raise _Rejected("WAITLIST_DISABLED", "this blueprint has no waitlist", "correct_input")
        if r.starts_at is None or r.provider_ref is None:
            raise _Rejected("SLOT_MISSING", "an offer names the provider and slot", "correct_input")
    elif event == "collect_deposit":
        if ledger.deposit_due <= 0:
            raise _Rejected("NO_DEPOSIT_DUE", "this booking takes no deposit", "correct_input")
        if r.payment_ref is None or r.amount != ledger.deposit_due:
            raise _Rejected("DEPOSIT_MISMATCH", f"deposit due is {ledger.deposit_due}", "correct_input")
        data.update({"deposit_paid": str(ledger.deposit_due), "paid_total": str(ledger.paid_total + ledger.deposit_due)})
    elif event == "send_reminder":
        if r.reminder_channel is None:
            raise _Rejected("REMINDER_CHANNEL_MISSING", "a reminder names its channel", "correct_input")
        if ledger.reminders_sent >= len(blueprint.reminder_hours_before):
            raise _Rejected("REMINDERS_EXHAUSTED", "every scheduled reminder was sent", "correct_input")
        due = _parsed(str(ledger.starts_at)) - timedelta(hours=blueprint.reminder_hours_before[ledger.reminders_sent])
        if at < due:
            raise _Rejected("REMINDER_TOO_EARLY", f"reminder {ledger.reminders_sent + 1} is due at {_iso(due)}", "correct_input")
        data["reminders_sent"] = ledger.reminders_sent + 1
    elif event == "confirm":
        if r.confirmation_ref is None:
            raise _Rejected("CONFIRMATION_MISSING", "a confirmation links the customer's confirmation", "correct_input")
    elif event == "reschedule":
        _place(blueprint, data, r, at, reschedule=True)
    elif event == "cancel":
        if status in {"requested", "waitlisted"}:
            data.update({"cancel_reason": r.cancel_reason or "cancelled before booking", "outcome": "cancelled_in_window"})
        else:
            inside_window = at > _parsed(str(ledger.starts_at)) - timedelta(hours=blueprint.cancellation_window_hours)
            if inside_window:
                next_status = "cancelled_late"
                fee = (ledger.price * blueprint.late_cancel_fee_percent / Decimal(100)).quantize(_MONEY_QUANTUM)
                data.update({"fee_charged": str(fee), "outcome": "cancelled_late"})
            else:
                data.update({"fee_charged": "0", "outcome": "cancelled_in_window"})
            data["cancel_reason"] = r.cancel_reason or "cancelled"
    elif event == "check_in":
        if blueprint.intake_consent_required and blueprint.service(str(ledger.service_ref)) is not None and blueprint.service(str(ledger.service_ref)).requires_intake and ledger.intake_consent_ref is None and r.intake_consent_ref is None:  # type: ignore[union-attr]
            raise _Rejected("INTAKE_CONSENT_MISSING", "intake consent must be on file before the visit", "correct_input")
        if at < _parsed(str(ledger.starts_at)) - timedelta(hours=2):
            raise _Rejected("CHECK_IN_TOO_EARLY", "check-in opens two hours before the slot", "correct_input")
        data["checked_in_at"] = command.occurred_at
        if r.intake_consent_ref is not None:
            data["intake_consent_ref"] = r.intake_consent_ref
    elif event == "mark_no_show":
        if at < _parsed(str(ledger.starts_at)):
            raise _Rejected("SLOT_NOT_STARTED", "a no-show is recorded only after the slot start", "correct_input")
        fee = (ledger.price * blueprint.no_show_fee_percent / Decimal(100)).quantize(_MONEY_QUANTUM)
        data.update({"fee_charged": str(fee), "outcome": "no_show"})
    elif event == "start_service":
        pass
    elif event == "complete":
        data["outcome"] = "attended"
        if r.case_ref is not None:
            data.setdefault("evidence", None)
    elif event == "record_payment":
        balance = (ledger.price - ledger.deposit_paid).quantize(_MONEY_QUANTUM)
        if balance > 0 and (r.payment_ref is None or r.amount is None):
            raise _Rejected("PAYMENT_MISSING", f"a balance of {balance} is due", "correct_input")
        if balance > 0 and r.amount != balance:
            raise _Rejected("PAYMENT_AMOUNT_MISMATCH", f"balance due is {balance}; got {r.amount}", "correct_input")
        data["paid_total"] = str(ledger.paid_total + (balance if balance > 0 else Decimal("0")))
    elif event == "follow_up":
        service = blueprint.service(str(ledger.service_ref))
        if service is not None and service.rebooking_interval_days > 0 and r.rebooked_booking_ref is None and r.satisfaction is None:
            raise _Rejected("FOLLOW_UP_EMPTY", "a follow-up records a rebooking or the customer's satisfaction", "correct_input")
        data.update({"rebooked_booking_ref": r.rebooked_booking_ref, "satisfaction": r.satisfaction})
    data.pop("evidence", None)
    return next_status, BookingLedger.model_validate(data)


class BookingState(_StrictModel):
    schema_id: Literal["lightbulb.appointment_booking_state.v1"] = Field(default=BOOKING_STATE_SCHEMA, alias="schema")
    plan_digest: Sha256Digest
    scope: BookingScope
    status: BookingStatus
    version: int = Field(ge=1, le=MAX_BOOKING_TRANSITIONS)
    transition_history: tuple[BookingTransition, ...] = Field(min_length=1, max_length=MAX_BOOKING_TRANSITIONS)
    ledger: BookingLedger
    state_digest: Sha256Digest

    @model_validator(mode="after")
    def _state_is_exact(self, info: ValidationInfo) -> "BookingState":
        history = self.transition_history
        if self.version != len(history) or [item.to_version for item in history] != list(range(1, self.version + 1)):
            raise ValueError("booking version must equal a contiguous transition history")
        for field_name in ("transition_ref", "idempotency_key", "request_digest"):
            _unique([str(getattr(item.command, field_name)) for item in history], label=f"historical {field_name} values")
        prefix: tuple[BookingTransition, ...] = ()
        for transition in history:
            if transition.prior_state_digest != _state_digest(self.plan_digest, self.scope, prefix):
                raise ValueError("historical transition has a discontinuous state digest")
            prefix = (*prefix, transition)
        if self.state_digest != _state_digest(self.plan_digest, self.scope, history):
            raise ValueError("state_digest must commit the exact booking state")
        plan: AppointmentBusinessLoopPlan | None = (info.context or {}).get("appointment_plan")
        if plan is not None:
            if plan.plan_digest != self.plan_digest:
                raise ValueError("booking belongs to a different loop plan")
            status, ledger = _OPENING_STATUS[history[0].command.event], BookingLedger()
            if history[0].command.event == "book":
                status, ledger = _apply(plan, "requested", ledger, history[0].command)
            for transition in history[1:]:
                try:
                    status, ledger = _apply(plan, status, ledger, transition.command)
                except _Rejected as exc:
                    raise ValueError(f"historical transition {transition.to_version} is invalid: {exc.code}") from exc
                if status != transition.to_status:
                    raise ValueError("historical transition status does not match the booking table")
            if self.status != status or self.ledger != ledger:
                raise ValueError("booking status and ledger must be derived from history")
        return self


_OPENING_STATUS: dict[str, str] = {"book": "booked", "offer_slot": "waitlisted"}


class BookingRecovery(_StrictModel):
    disposition: RecoveryDisposition
    automatic_retry_allowed: Literal[False] = False
    instructions: BoundedText | None = None

    @model_validator(mode="after")
    def _bounded(self) -> "BookingRecovery":
        if (self.disposition == "not_required") != (self.instructions is None):
            raise ValueError("recovery instructions must match the disposition")
        return self


class BookingTransitionReceipt(_StrictModel):
    transition_ref: OpaqueRef
    idempotency_key: OpaqueRef
    request_digest: Sha256Digest
    event: BookingEvent
    status: Literal["candidate_materialized", "rejected"]
    from_version: int = Field(ge=0)
    to_version: int = Field(ge=0)
    from_status: BookingStatus
    to_status: BookingStatus
    from_state_digest: Sha256Digest
    to_state_digest: Sha256Digest
    rejection_code: str | None = Field(default=None, min_length=1, max_length=120)
    recovery: BookingRecovery


class BookingEffectBoundary(_StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    calendar_written: Literal[False] = False
    payment_taken: Literal[False] = False
    reminder_sent: Literal[False] = False
    fee_charged: Literal[False] = False


class BookingTransitionResult(_StrictModel):
    schema_id: Literal["lightbulb.appointment_booking_transition_result.v1"] = Field(default=BOOKING_RESULT_SCHEMA, alias="schema")
    candidate_validated: bool
    state: BookingState | None = None
    receipt: BookingTransitionReceipt
    effect_boundary: BookingEffectBoundary = Field(default_factory=BookingEffectBoundary)

    @model_validator(mode="after")
    def _coherent(self) -> "BookingTransitionResult":
        if self.candidate_validated != (self.receipt.status == "candidate_materialized") or (self.candidate_validated and self.state is None):
            raise ValueError("result must carry a state exactly when a candidate was materialized")
        return self


def _validate_plan_state(plan: AppointmentBusinessLoopPlan | Mapping[str, Any], state: BookingState | Mapping[str, Any]) -> tuple[AppointmentBusinessLoopPlan, BookingState]:
    parsed_plan = AppointmentBusinessLoopPlan.model_validate(_detached(plan))
    unbound = BookingState.model_validate(_detached(state))
    if unbound.plan_digest != parsed_plan.plan_digest:
        raise ValueError("booking belongs to a different loop plan")
    return parsed_plan, BookingState.model_validate(unbound.to_dict(), context={"appointment_plan": parsed_plan})


def open_booking(plan: AppointmentBusinessLoopPlan | Mapping[str, Any], scope: BookingScope | Mapping[str, Any], *, requested_at: str, actor_ref: str, receipt: BookingReceipt | Mapping[str, Any], waitlist: bool = False) -> BookingState:
    """Open a booking by placing it in a slot (or on the waitlist when no slot fits)."""

    parsed_plan = AppointmentBusinessLoopPlan.model_validate(_detached(plan))
    parsed_scope = BookingScope.model_validate(_detached(scope))
    if parsed_scope.currency != parsed_plan.blueprint.currency:
        raise ValueError("booking currency must match the blueprint currency")
    event = "offer_slot" if waitlist else "book"
    genesis = _state_digest(parsed_plan.plan_digest, parsed_scope, ())
    command = BookingCommand.model_validate(seal_booking_command({"event": event, "transition_ref": f"{event}:{parsed_scope.booking_ref}", "idempotency_key": f"{parsed_scope.booking_ref}:{event}", "expected_version": 0, "expected_state_digest": genesis, "occurred_at": requested_at, "actor_ref": actor_ref, "receipt": _detached(receipt)}))
    if waitlist:
        if not parsed_plan.blueprint.waitlist_enabled:
            raise ValueError("WAITLIST_DISABLED: this blueprint has no waitlist")
        status, ledger = "waitlisted", BookingLedger()
    else:
        try:
            status, ledger = _apply(parsed_plan, "requested", BookingLedger(), command)
        except _Rejected as exc:
            raise ValueError(f"{exc.code}: {exc.instructions}") from exc
    transition = BookingTransition(to_version=1, prior_state_digest=genesis, to_status=status, transition_digest=_transition_digest(1, genesis, status, command), command=command)
    return BookingState.model_validate({"plan_digest": parsed_plan.plan_digest, "scope": parsed_scope.to_dict(), "status": status, "version": 1, "transition_history": [transition.to_dict()], "ledger": ledger.to_dict(), "state_digest": _state_digest(parsed_plan.plan_digest, parsed_scope, (transition,))}, context={"appointment_plan": parsed_plan})


def advance_booking(plan: AppointmentBusinessLoopPlan | Mapping[str, Any], state: BookingState | Mapping[str, Any], command: BookingCommand | Mapping[str, Any]) -> BookingTransitionResult:
    parsed_plan, parsed_state = _validate_plan_state(plan, state)
    parsed_command = BookingCommand.model_validate(_detached(command))
    from_version, from_status, from_digest = parsed_state.version, parsed_state.status, parsed_state.state_digest

    def rejected(exc: _Rejected) -> BookingTransitionResult:
        receipt = BookingTransitionReceipt(transition_ref=parsed_command.transition_ref, idempotency_key=parsed_command.idempotency_key, request_digest=parsed_command.request_digest, event=parsed_command.event, status="rejected", from_version=from_version, to_version=from_version, from_status=from_status, to_status=from_status, from_state_digest=from_digest, to_state_digest=from_digest, rejection_code=exc.code, recovery=BookingRecovery(disposition=exc.recovery, instructions=exc.instructions))
        return BookingTransitionResult(candidate_validated=False, receipt=receipt)

    try:
        for prior in parsed_state.transition_history:
            if prior.command.request_digest == parsed_command.request_digest:
                raise _Rejected("TRANSITION_ALREADY_APPLIED", "this exact transition is already retained; duplicate delivery ignored", "do_not_replay")
            if prior.command.transition_ref == parsed_command.transition_ref or prior.command.idempotency_key == parsed_command.idempotency_key:
                raise _Rejected("IDEMPOTENCY_CONFLICT", "a different transition already used this reference or idempotency key", "manual_reconciliation")
        if parsed_command.expected_version != from_version or parsed_command.expected_state_digest != from_digest:
            raise _Rejected("STALE_STATE", "revision or state fence does not match; refresh and retry with the current state", "refresh_state")
        if _parsed(parsed_command.occurred_at) < _parsed(parsed_state.transition_history[-1].command.occurred_at):
            raise _Rejected("NON_CHRONOLOGICAL_TRANSITION", "transition precedes the last retained transition", "correct_input")
        if from_version >= MAX_BOOKING_TRANSITIONS:
            raise _Rejected("TRANSITION_BOUND_REACHED", "the booking reached its bounded transition count", "manual_reconciliation")
        if from_status == "waitlisted" and parsed_command.event == "offer_slot":
            next_status, ledger = "requested", parsed_state.ledger
            if not parsed_plan.blueprint.waitlist_enabled or parsed_command.receipt.starts_at is None or parsed_command.receipt.provider_ref is None:
                raise _Rejected("SLOT_MISSING", "an offer names the provider and slot", "correct_input")
        else:
            next_status, ledger = _apply(parsed_plan, from_status, parsed_state.ledger, parsed_command)
    except _Rejected as exc:
        return rejected(exc)
    transition = BookingTransition(to_version=from_version + 1, prior_state_digest=from_digest, to_status=next_status, transition_digest=_transition_digest(from_version + 1, from_digest, next_status, parsed_command), command=parsed_command)
    history = (*parsed_state.transition_history, transition)
    new_state = BookingState.model_validate({"plan_digest": parsed_state.plan_digest, "scope": parsed_state.scope.to_dict(), "status": next_status, "version": from_version + 1, "transition_history": [item.to_dict() for item in history], "ledger": ledger.to_dict(), "state_digest": _state_digest(parsed_state.plan_digest, parsed_state.scope, history)}, context={"appointment_plan": parsed_plan})
    receipt = BookingTransitionReceipt(transition_ref=parsed_command.transition_ref, idempotency_key=parsed_command.idempotency_key, request_digest=parsed_command.request_digest, event=parsed_command.event, status="candidate_materialized", from_version=from_version, to_version=new_state.version, from_status=from_status, to_status=next_status, from_state_digest=from_digest, to_state_digest=new_state.state_digest, recovery=BookingRecovery(disposition="not_required"))
    return BookingTransitionResult(candidate_validated=True, state=new_state, receipt=receipt)


# --------------------------------------------------------------------------- #
# Schedule assessment
# --------------------------------------------------------------------------- #


class ScheduleAssessment(_StrictModel):
    schema_id: Literal["lightbulb.appointment_schedule_assessment.v1"] = Field(default=SCHEDULE_ASSESSMENT_SCHEMA, alias="schema")
    golden_loop: Literal["appointment.booking_to_rebooking_business@0.1.0"] = APPOINTMENT_BUSINESS_GOLDEN_LOOP
    profile: BlueprintProfile
    currency: CurrencyCode
    bookings: int = Field(ge=0)
    by_status: dict[str, int] = Field(default_factory=dict)
    capacity_minutes: int = Field(ge=0)
    served_minutes: int = Field(ge=0)
    utilization_percent: Decimal | None = None
    attended: int = Field(ge=0)
    no_shows: int = Field(ge=0)
    late_cancellations: int = Field(ge=0)
    no_show_rate_percent: Decimal | None = None
    late_cancel_rate_percent: Decimal | None = None
    rebooked: int = Field(ge=0)
    rebooking_rate_percent: Decimal | None = None
    revenue: Decimal
    fees_charged: Decimal
    outstanding_balance: Decimal
    average_ticket: Decimal | None = None
    average_satisfaction: Decimal | None = None
    learnings: tuple[BoundedText, ...] = Field(default_factory=tuple, max_length=30)
    recommendations: tuple[BoundedText, ...] = Field(default_factory=tuple, max_length=20)
    effect_boundary: BookingEffectBoundary = Field(default_factory=BookingEffectBoundary)
    assessed_at: str
    assessment_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("utilization_percent", "no_show_rate_percent", "late_cancel_rate_percent", "rebooking_rate_percent", "revenue", "fees_charged", "outstanding_balance", "average_ticket", "average_satisfaction", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Any:
        return None if value is None else _decimal(value, field_name=str(info.field_name))

    @field_validator("assessed_at")
    @classmethod
    def _assessed(cls, value: str) -> str:
        return _timestamp(value, field_name="assessed_at")

    @model_validator(mode="after")
    def _assessment_is_exact(self, info: ValidationInfo) -> "ScheduleAssessment":
        if _skip(info):
            return self
        if self.assessment_digest != _sealed_digest(ScheduleAssessment, self, "assessment_digest"):
            raise ValueError("assessment_digest must commit the exact assessment")
        return self


def assess_schedule(plan: AppointmentBusinessLoopPlan | Mapping[str, Any], bookings: Sequence[BookingState | Mapping[str, Any]], *, capacity_minutes: int, assessed_at: str) -> ScheduleAssessment:
    """Effect-dark schedule metrics: utilization, no-show and late-cancel rates, rebooking, revenue, fees, balances, satisfaction."""

    parsed_plan = AppointmentBusinessLoopPlan.model_validate(_detached(plan))
    parsed = [_validate_plan_state(parsed_plan, item)[1] for item in bookings]
    if capacity_minutes < 0:
        raise ValueError("capacity_minutes cannot be negative")
    blueprint = parsed_plan.blueprint
    quantum = Decimal("0.01")
    by_status: dict[str, int] = {}
    for booking in parsed:
        by_status[booking.status] = by_status.get(booking.status, 0) + 1
    attended = [booking for booking in parsed if booking.ledger.outcome == "attended"]
    no_shows = [booking for booking in parsed if booking.ledger.outcome == "no_show"]
    late = [booking for booking in parsed if booking.ledger.outcome == "cancelled_late"]
    decided = len(attended) + len(no_shows) + len(late)
    served_minutes = sum(booking.ledger.service_minutes for booking in attended)
    utilization = (Decimal(served_minutes) / Decimal(capacity_minutes) * 100).quantize(quantum) if capacity_minutes else None
    no_show_rate = (Decimal(len(no_shows)) / Decimal(decided) * 100).quantize(quantum) if decided else None
    late_rate = (Decimal(len(late)) / Decimal(decided) * 100).quantize(quantum) if decided else None
    followed = [booking for booking in parsed if booking.status == "followed_up"]
    rebooked = sum(1 for booking in followed if booking.ledger.rebooked_booking_ref is not None)
    rebooking_rate = (Decimal(rebooked) / Decimal(len(followed)) * 100).quantize(quantum) if followed else None
    revenue = sum((booking.ledger.paid_total for booking in parsed), Decimal("0")).quantize(quantum)
    fees = sum((booking.ledger.fee_charged for booking in parsed), Decimal("0")).quantize(quantum)
    outstanding = sum((max(booking.ledger.price - booking.ledger.paid_total, Decimal("0")) for booking in parsed if booking.status in {"completed"}), Decimal("0")).quantize(quantum)
    average_ticket = (revenue / Decimal(len(attended))).quantize(quantum) if attended and revenue > 0 else None
    satisfaction = [booking.ledger.satisfaction for booking in parsed if booking.ledger.satisfaction is not None]
    average_satisfaction = (Decimal(sum(satisfaction)) / Decimal(len(satisfaction))).quantize(quantum) if satisfaction else None
    learnings: list[str] = []
    recommendations: list[str] = []
    if utilization is not None and utilization < blueprint.target_utilization_percent:
        learnings.append(f"utilization {utilization}% is below the {blueprint.target_utilization_percent.quantize(quantum)}% target")
        recommendations.append("open the waitlist to fill gaps and promote off-peak slots")
    if no_show_rate is not None and no_show_rate > blueprint.max_no_show_rate_percent:
        learnings.append(f"no-show rate {no_show_rate}% exceeds the {blueprint.max_no_show_rate_percent.quantize(quantum)}% ceiling")
        recommendations.append("add a deposit or an earlier reminder step; enforce the no-show fee")
    if late_rate is not None and late_rate > Decimal("10"):
        learnings.append(f"late cancellations at {late_rate}%")
        recommendations.append("lengthen the cancellation window or confirm two days out")
    if rebooking_rate is not None and rebooking_rate < blueprint.target_rebooking_rate_percent:
        learnings.append(f"rebooking rate {rebooking_rate}% is below the {blueprint.target_rebooking_rate_percent.quantize(quantum)}% target")
        recommendations.append("offer the next slot at the end of the visit and follow up inside the rebooking interval")
    if outstanding > 0:
        learnings.append(f"{outstanding} {blueprint.currency} unpaid on completed visits")
        recommendations.append("take payment at completion before the customer leaves")
    if not learnings:
        learnings.append("schedule is inside blueprint targets")
    payload = {"profile": blueprint.profile, "currency": blueprint.currency, "bookings": len(parsed), "by_status": dict(sorted(by_status.items())), "capacity_minutes": capacity_minutes, "served_minutes": served_minutes, "utilization_percent": None if utilization is None else str(utilization), "attended": len(attended), "no_shows": len(no_shows), "late_cancellations": len(late), "no_show_rate_percent": None if no_show_rate is None else str(no_show_rate), "late_cancel_rate_percent": None if late_rate is None else str(late_rate), "rebooked": rebooked, "rebooking_rate_percent": None if rebooking_rate is None else str(rebooking_rate), "revenue": str(revenue), "fees_charged": str(fees), "outstanding_balance": str(outstanding), "average_ticket": None if average_ticket is None else str(average_ticket), "average_satisfaction": None if average_satisfaction is None else str(average_satisfaction), "learnings": learnings, "recommendations": recommendations, "assessed_at": assessed_at}
    return _seal(ScheduleAssessment, payload, "assessment_digest")


APPOINTMENT_BUSINESS_ARCHETYPE_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_blueprint_archetype.v1",
    "archetype": APPOINTMENT_BUSINESS_ARCHETYPE,
    "title": "Appointment business",
    "golden_loop": APPOINTMENT_BUSINESS_GOLDEN_LOOP,
    "composed_with": ["calendar.schedule_meeting", "finance.create_invoice", "finance.collect_payment", "communication.write_email", "communication.plan_governed_voice_call", "service.* cases", "growth.* funnel and customer value"],
    "profiles": sorted(APPOINTMENT_BUSINESS_PROFILES),
    "booking_statuses": list(BookingStatus.__args__),  # type: ignore[attr-defined]
    "booking_events": list(BookingEvent.__args__),  # type: ignore[attr-defined]
    "economic_spine": {"acquire_demand": "attract", "create_offer": "book (service and slot)", "agree_purchase": "book (deposit, consent)", "deliver_value": "serve", "accept_value": "complete / follow-up satisfaction", "monetize": "pay", "learn": "learn"},
    "composable_with": ["service_business", "subscription_business", "product_commerce", "saas_product", "marketplace_business"],
    "explicit_inputs_never_invented": ["working hours and provider capacity", "intake consent", "cancellation and no-show policy", "payments and fees"],
}

__all__ = [
    "APPOINTMENT_BUSINESS_ARCHETYPE",
    "APPOINTMENT_BUSINESS_ARCHETYPE_MANIFEST",
    "APPOINTMENT_BUSINESS_GOLDEN_LOOP",
    "APPOINTMENT_BUSINESS_PROFILES",
    "MAX_AVAILABILITY_SLOTS",
    "MAX_BOOKING_TRANSITIONS",
    "STAGE_ORDER",
    "TERMINAL_BOOKING_STATUSES",
    "AppointmentBusinessBlueprint",
    "AppointmentBusinessLoopPlan",
    "Availability",
    "AvailableSlot",
    "BookingCommand",
    "BookingEffectBoundary",
    "BookingLedger",
    "BookingReceipt",
    "BookingRecovery",
    "BookingScope",
    "BookingState",
    "BookingTransition",
    "BookingTransitionReceipt",
    "BookingTransitionResult",
    "ExistingBooking",
    "ScheduleAssessment",
    "ServiceOffering",
    "StageBinding",
    "WorkingHours",
    "advance_booking",
    "assess_schedule",
    "booking_command_digest",
    "compile_appointment_business_blueprint",
    "generate_availability",
    "open_booking",
    "seal_appointment_business_blueprint",
    "seal_booking_command",
]
