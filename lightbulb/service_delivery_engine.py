"""Service Delivery Engine Golden Operating Loop: case intake to verified resolution.

The service engine the company operating system and the SaaS operating
engine hand cases to.  A delivery blueprint fixes the channels, the severity
SLA table, escalation tiers, the verification policy (who confirms a
resolution and how long before an unanswered verification counts as
unreachable), the reopen window, and remedy limits.  Each case is a
replay-fenced lifecycle::

    intaken -> classified -> assigned -> (escalated) -> in_progress
      -> resolution_submitted -> verified | rejected -> closed  (| reopened)

Guards: classification sets the severity that fixes the SLA clocks; a case
assigns only to a tier allowed for its severity; escalation moves up one
tier at a time; a resolution needs evidence and, when remedy is offered, an
approval reference inside the remedy ceiling; the customer (or an
independent verifier) confirms the outcome before the case closes;
unreachable customers close only after the verification window; reopening
stays inside the reopen window.

:func:`case_resolved_signal` turns a closed and verified case into the
``signals.case_resolved`` payload the company operating system routes.
Nothing here messages a customer, refunds, or reads a provider.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    MONEY_QUANTUM,
    BoundedText,
    CurrencyCode,
    LifecycleSpec,
    OpaqueRef,
    Sha256Digest,
    ShortText,
    StrictModel,
    decimal_value,
    detached,
    iso,
    parsed,
    percent_value,
    require,
    seal,
    sealed_digest,
    skip_digests,
    timestamp,
    unique,
)

SERVICE_DELIVERY_GOLDEN_LOOP = "service.case_intake_to_verified_resolution@0.1.0"
SERVICE_DELIVERY_KIND = "service_delivery"
BLUEPRINT_SCHEMA = "lightbulb.service_delivery_blueprint.v1"
PLAN_SCHEMA = "lightbulb.service_delivery_loop_plan.v1"
ASSESSMENT_SCHEMA = "lightbulb.service_delivery_assessment.v1"
MAX_CASE_TRANSITIONS = 120

Profile = Literal["commerce_support", "engagement_delivery", "saas_support", "local_aftercare", "marketplace_disputes", "custom"]
Channel = Literal["email", "chat", "voice", "web", "sms", "whatsapp", "social"]
CHANNELS: tuple[str, ...] = ("email", "chat", "voice", "web", "sms", "whatsapp", "social")
Severity = Literal["sev1", "sev2", "sev3", "sev4"]
SEVERITIES: tuple[str, ...] = ("sev1", "sev2", "sev3", "sev4")
Tier = Literal["tier1", "tier2", "tier3", "engineering", "account_owner"]
TIERS: tuple[str, ...] = ("tier1", "tier2", "tier3", "engineering", "account_owner")
Verifier = Literal["customer", "independent_verifier"]
RemedyKind = Literal["none", "refund", "credit", "replacement", "rework"]
LoopStage = Literal["intake", "classify", "assign", "work", "resolve", "verify", "close", "learn"]
STAGE_ORDER: tuple[str, ...] = ("intake", "classify", "assign", "work", "resolve", "verify", "close", "learn")

CaseStatus = Literal["intaken", "classified", "assigned", "escalated", "in_progress", "resolution_submitted", "verified", "rejected", "closed", "reopened"]
CASE_STATUSES: tuple[str, ...] = ("intaken", "classified", "assigned", "escalated", "in_progress", "resolution_submitted", "verified", "rejected", "closed", "reopened")
TERMINAL_CASE_STATUSES: frozenset[str] = frozenset()
CaseEvent = Literal["intake", "classify", "assign", "escalate", "start_work", "submit_resolution", "verify", "reject_resolution", "close", "reopen"]
CASE_EVENTS: tuple[str, ...] = ("intake", "classify", "assign", "escalate", "start_work", "submit_resolution", "verify", "reject_resolution", "close", "reopen")
_CASE_TABLE: dict[tuple[str, str], str] = {
    ("new", "intake"): "intaken",
    ("intaken", "classify"): "classified",
    ("classified", "assign"): "assigned",
    ("assigned", "escalate"): "escalated",
    ("assigned", "start_work"): "in_progress",
    ("escalated", "assign"): "assigned",
    ("escalated", "start_work"): "in_progress",
    ("in_progress", "escalate"): "escalated",
    ("in_progress", "submit_resolution"): "resolution_submitted",
    ("resolution_submitted", "verify"): "verified",
    ("resolution_submitted", "reject_resolution"): "rejected",
    ("resolution_submitted", "close"): "closed",
    ("rejected", "start_work"): "in_progress",
    ("rejected", "escalate"): "escalated",
    ("verified", "close"): "closed",
    ("closed", "reopen"): "reopened",
    ("reopened", "assign"): "assigned",
    ("reopened", "start_work"): "in_progress",
}
_TIER_RANK: Mapping[str, int] = {tier: index for index, tier in enumerate(TIERS)}
_KNOWN_PRIMITIVE_REFS: frozenset[str] = frozenset(
    {
        "blueprint.compile_service_delivery", "service_delivery.advance_case", "service_delivery.assess_delivery",
        "service.intake_and_classify_case", "service.route_and_escalate_case", "service.submit_resolution_for_verification", "service.verify_case_resolution", "service.evaluate_case_resolution_controls", "service.propose_remedy_authorization",
        "communication.write_email", "communication.classify_reply", "communication.normalize_provider_outcome", "approval.request_decision", "customer_success.prevent_returns_and_expand_ltv", "learning.plan_optimization_sweep",
    }
)


def _money(value: Any, name: str) -> Decimal:
    result = decimal_value(value, field_name=name)
    if result < 0:
        raise ValueError(f"{name} must not be negative")
    return result


# --------------------------------------------------------------------------- #
# Blueprint and plan
# --------------------------------------------------------------------------- #


class SeveritySla(StrictModel):
    severity: Severity
    first_response_hours: int = Field(ge=1, le=240)
    resolution_hours: int = Field(ge=1, le=2000)
    allowed_tiers: tuple[Tier, ...] = Field(min_length=1, max_length=5)
    escalate_to: Tier | None = None

    @model_validator(mode="after")
    def _guard(self) -> SeveritySla:
        unique(list(self.allowed_tiers), label="allowed tiers")
        if self.resolution_hours < self.first_response_hours:
            raise ValueError("resolution window must be at least the first-response window")
        if self.escalate_to is not None and self.escalate_to in self.allowed_tiers:
            raise ValueError("escalation target must be above the allowed tiers")
        return self


class VerificationPolicy(StrictModel):
    verifier: Verifier = "customer"
    verification_window_hours: int = Field(default=72, ge=1, le=720)
    reopen_window_days: int = Field(default=14, ge=1, le=120)
    allow_close_when_unreachable: bool = True


class RemedyPolicy(StrictModel):
    allowed: tuple[RemedyKind, ...] = Field(default=("none",), min_length=1, max_length=5)
    max_remedy_value: Decimal = Field(default=Decimal("0"), validate_default=True)
    approval_required_above: Decimal = Field(default=Decimal("0"), validate_default=True)

    @field_validator("max_remedy_value", "approval_required_above", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _money(value, str(info.field_name))

    @model_validator(mode="after")
    def _guard(self) -> RemedyPolicy:
        unique(list(self.allowed), label="remedy kinds")
        if self.approval_required_above > self.max_remedy_value:
            raise ValueError("the approval threshold cannot exceed the remedy ceiling")
        return self


class DeliveryTargets(StrictModel):
    min_sla_attainment_percent: Decimal = Field(default=Decimal("90"), validate_default=True)
    min_verified_resolution_percent: Decimal = Field(default=Decimal("80"), validate_default=True)
    max_reopen_rate_percent: Decimal = Field(default=Decimal("10"), validate_default=True)

    @field_validator("min_sla_attainment_percent", "min_verified_resolution_percent", "max_reopen_rate_percent", mode="before")
    @classmethod
    def _pct(cls, value: Any, info: ValidationInfo) -> Decimal:
        return percent_value(value, field_name=str(info.field_name))


class ServiceDeliveryBlueprint(StrictModel):
    company_ref: OpaqueRef | None = None
    schema_id: str = Field(default=BLUEPRINT_SCHEMA, alias="schema")
    profile: Profile
    name: ShortText
    currency: CurrencyCode
    channels: tuple[Channel, ...] = Field(min_length=1, max_length=7)
    slas: tuple[SeveritySla, ...] = Field(min_length=4, max_length=4)
    verification: VerificationPolicy
    remedy: RemedyPolicy
    targets: DeliveryTargets
    blueprint_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> ServiceDeliveryBlueprint:
        unique(list(self.channels), label="channels")
        if tuple(item.severity for item in self.slas) != SEVERITIES:
            raise ValueError("slas must cover sev1..sev4 in order")
        if not skip_digests(info) and self.blueprint_digest != sealed_digest(ServiceDeliveryBlueprint, self, "blueprint_digest"):
            raise ValueError("blueprint_digest must commit the exact blueprint")
        return self

    def sla(self, severity: str) -> SeveritySla:
        return next(item for item in self.slas if item.severity == severity)


_SLAS = [
    {"severity": "sev1", "first_response_hours": 1, "resolution_hours": 8, "allowed_tiers": ["tier2", "tier3"], "escalate_to": "engineering"},
    {"severity": "sev2", "first_response_hours": 4, "resolution_hours": 24, "allowed_tiers": ["tier1", "tier2"], "escalate_to": "tier3"},
    {"severity": "sev3", "first_response_hours": 8, "resolution_hours": 72, "allowed_tiers": ["tier1", "tier2"], "escalate_to": "tier3"},
    {"severity": "sev4", "first_response_hours": 24, "resolution_hours": 168, "allowed_tiers": ["tier1"], "escalate_to": "tier2"},
]
SERVICE_DELIVERY_PROFILES: dict[str, dict[str, Any]] = {
    "commerce_support": {"profile": "commerce_support", "name": "Commerce customer support", "currency": "AUD", "channels": ["email", "chat", "social"], "slas": _SLAS, "verification": {"verifier": "customer", "verification_window_hours": 72, "reopen_window_days": 14, "allow_close_when_unreachable": True}, "remedy": {"allowed": ["none", "refund", "credit", "replacement"], "max_remedy_value": "500", "approval_required_above": "100"}, "targets": {"min_sla_attainment_percent": "90", "min_verified_resolution_percent": "80", "max_reopen_rate_percent": "10"}},
    "engagement_delivery": {"profile": "engagement_delivery", "name": "Professional services engagement delivery", "currency": "AUD", "channels": ["email", "voice", "web"], "slas": [{**_SLAS[0], "allowed_tiers": ["tier2", "account_owner"], "escalate_to": None, "resolution_hours": 24}, {**_SLAS[1], "allowed_tiers": ["tier1", "tier2"], "escalate_to": "account_owner"}, {**_SLAS[2], "allowed_tiers": ["tier1", "tier2"], "escalate_to": "account_owner"}, {**_SLAS[3], "allowed_tiers": ["tier1"], "escalate_to": "tier2"}], "verification": {"verifier": "customer", "verification_window_hours": 120, "reopen_window_days": 30, "allow_close_when_unreachable": False}, "remedy": {"allowed": ["none", "rework", "credit"], "max_remedy_value": "5000", "approval_required_above": "500"}, "targets": {"min_sla_attainment_percent": "85", "min_verified_resolution_percent": "90", "max_reopen_rate_percent": "5"}},
    "saas_support": {"profile": "saas_support", "name": "SaaS product support", "currency": "CAD", "channels": ["email", "chat", "web"], "slas": _SLAS, "verification": {"verifier": "customer", "verification_window_hours": 48, "reopen_window_days": 14, "allow_close_when_unreachable": True}, "remedy": {"allowed": ["none", "credit"], "max_remedy_value": "300", "approval_required_above": "50"}, "targets": {"min_sla_attainment_percent": "92", "min_verified_resolution_percent": "80", "max_reopen_rate_percent": "8"}},
}


SERVICE_DELIVERY_PROFILES["local_aftercare"] = {
    **SERVICE_DELIVERY_PROFILES["engagement_delivery"], "profile": "local_aftercare",
    "name": "Local services aftercare", "currency": "AUD",
}
SERVICE_DELIVERY_PROFILES["marketplace_disputes"] = {
    **SERVICE_DELIVERY_PROFILES["commerce_support"], "profile": "marketplace_disputes",
    "name": "Marketplace dispute resolution", "currency": "CAD",
    "verification": {"verifier": "customer", "verification_window_hours": 72, "reopen_window_days": 30, "allow_close_when_unreachable": False},
}


class StageBinding(StrictModel):
    stage: LoopStage
    title: ShortText
    primitive_refs: tuple[str, ...] = Field(min_length=1, max_length=8)
    gate: ShortText | None = None

    @field_validator("primitive_refs")
    @classmethod
    def _refs(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for ref in value:
            if ref not in _KNOWN_PRIMITIVE_REFS:
                raise ValueError(f"unknown primitive ref {ref}")
        return value


class ServiceDeliveryLoopPlan(StrictModel):
    schema_id: str = Field(default=PLAN_SCHEMA, alias="schema")
    golden_loop: Literal["service.case_intake_to_verified_resolution@0.1.0"] = SERVICE_DELIVERY_GOLDEN_LOOP
    blueprint: ServiceDeliveryBlueprint
    stages: tuple[StageBinding, ...] = Field(min_length=len(STAGE_ORDER), max_length=len(STAGE_ORDER))
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> ServiceDeliveryLoopPlan:
        if tuple(item.stage for item in self.stages) != STAGE_ORDER:
            raise ValueError("stages must follow the loop order")
        if not skip_digests(info) and self.plan_digest != sealed_digest(ServiceDeliveryLoopPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self

    def stage(self, name: str) -> StageBinding:
        return next(item for item in self.stages if item.stage == name)


def _stages(bp: ServiceDeliveryBlueprint) -> tuple[StageBinding, ...]:
    return (
        StageBinding(stage="intake", title=f"Intake on {', '.join(bp.channels)}", primitive_refs=("service.intake_and_classify_case", "communication.normalize_provider_outcome", "service_delivery.advance_case")),
        StageBinding(stage="classify", title="Classify severity and start the SLA clocks", primitive_refs=("service.intake_and_classify_case", "service_delivery.advance_case")),
        StageBinding(stage="assign", title="Assign inside the severity's tiers; escalate one tier at a time", primitive_refs=("service.route_and_escalate_case", "service_delivery.advance_case")),
        StageBinding(stage="work", title="Work the case inside the resolution window", primitive_refs=("communication.write_email", "service_delivery.advance_case"), gate="spring_authorized_send"),
        StageBinding(stage="resolve", title=f"Submit a resolution with evidence; remedies up to {bp.currency} {bp.remedy.max_remedy_value}", primitive_refs=("service.submit_resolution_for_verification", "service.propose_remedy_authorization", "approval.request_decision", "service_delivery.advance_case"), gate="human_approval_above_remedy_threshold"),
        StageBinding(stage="verify", title=f"{bp.verification.verifier.replace('_', ' ')} confirms inside {bp.verification.verification_window_hours}h", primitive_refs=("service.verify_case_resolution", "service.evaluate_case_resolution_controls", "service_delivery.advance_case"), gate="customer_or_independent_verification"),
        StageBinding(stage="close", title=f"Close; reopen inside {bp.verification.reopen_window_days} day(s)", primitive_refs=("service_delivery.advance_case",)),
        StageBinding(stage="learn", title="Assess SLA attainment, verified resolutions, reopen rate", primitive_refs=("service_delivery.assess_delivery", "customer_success.prevent_returns_and_expand_ltv", "learning.plan_optimization_sweep")),
    )


def compile_service_delivery_blueprint(blueprint: str | ServiceDeliveryBlueprint | Mapping[str, Any], overrides: Mapping[str, Any] | None = None) -> ServiceDeliveryLoopPlan:
    if isinstance(blueprint, str):
        if blueprint not in SERVICE_DELIVERY_PROFILES:
            raise ValueError(f"unknown service delivery profile {blueprint!r}; known: {sorted(SERVICE_DELIVERY_PROFILES)}")
        raw: dict[str, Any] = dict(SERVICE_DELIVERY_PROFILES[blueprint])
    elif isinstance(blueprint, ServiceDeliveryBlueprint):
        raw = blueprint.to_dict()
        raw.pop("blueprint_digest", None)
    else:
        raw = dict(detached(blueprint))
    if overrides:
        if any(key in ("schema", "blueprint_digest") for key in overrides):
            raise ValueError("overrides cannot set schema or digest fields")
        raw.update(detached(overrides))
    raw["blueprint_digest"] = sealed_digest(ServiceDeliveryBlueprint, raw, "blueprint_digest")
    bp = ServiceDeliveryBlueprint.model_validate(raw)
    return seal(ServiceDeliveryLoopPlan, {"blueprint": bp, "stages": _stages(bp)}, "plan_digest")


# --------------------------------------------------------------------------- #
# Case lifecycle
# --------------------------------------------------------------------------- #


class CaseReceipt(StrictModel):
    entity_scope: dict[str, Any] | None = None
    authorization_proof: dict[str, Any] | None = None
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    case_ref: OpaqueRef | None = None
    customer_ref: OpaqueRef | None = None
    channel: Channel | None = None
    subject: ShortText | None = None
    consent_ref: OpaqueRef | None = None
    severity: Severity | None = None
    classification_ref: OpaqueRef | None = None
    tier: Tier | None = None
    assignee_ref: OpaqueRef | None = None
    first_response_at: str | None = None
    resolution_ref: OpaqueRef | None = None
    summary: BoundedText | None = None
    remedy_kind: RemedyKind | None = None
    remedy_value: Decimal | None = None
    approval_ref: OpaqueRef | None = None
    verifier_ref: OpaqueRef | None = None
    verification_ref: OpaqueRef | None = None
    unreachable: bool | None = None

    @field_validator("first_response_at")
    @classmethod
    def _stamp(cls, value: str | None) -> str | None:
        return None if value is None else timestamp(value, field_name="first_response_at")

    @field_validator("remedy_value", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal | None:
        return None if value is None else _money(value, "remedy_value")


class CaseLedger(StrictModel):
    entity_scope: dict[str, Any] | None = None
    consent_ref: OpaqueRef | None = None
    authorization_proof_digest: Sha256Digest | None = None
    case_ref: str | None = None
    customer_ref: str | None = None
    channel: str | None = None
    opened_at: str | None = None
    severity: str | None = None
    first_response_due: str | None = None
    resolution_due: str | None = None
    first_response_at: str | None = None
    first_response_met: bool | None = None
    tier: str | None = None
    assignee_ref: str | None = None
    escalations: int = Field(default=0, ge=0)
    resolution_ref: str | None = None
    resolved_at: str | None = None
    resolution_met: bool | None = None
    remedy_kind: str | None = None
    remedy_value: Decimal = Decimal("0.00")
    approval_ref: str | None = None
    rejections: int = Field(default=0, ge=0)
    verified: bool = False
    verifier_ref: str | None = None
    verification_ref: str | None = None
    unreachable: bool = False
    closed_at: str | None = None
    reopen_count: int = Field(default=0, ge=0)
    outcome: Literal["open", "closed", "reopened"] = "open"

    @field_validator("remedy_value", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return _money(value, "remedy_value")


class CaseEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    message_sent: Literal[False] = False
    remedy_issued: Literal[False] = False
    money_spent: Literal[False] = False
    provider_read: Literal[False] = False


def _hours_after(stamp: str, hours: int) -> str:
    from datetime import timedelta

    return iso(parsed(stamp) + timedelta(hours=hours))


def _apply_case(plan: ServiceDeliveryLoopPlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    bp, r, event = plan.blueprint, command.receipt, command.event
    if event == "intake":
        if r.entity_scope is not None:
            from lightbulb.company_engine_core import EngineScope
            scope = EngineScope.model_validate(r.entity_scope)
            require(command.expected_state_digest == CASE_LIFECYCLE.state_digest(plan.plan_digest, scope, ()), "SCOPE_MISMATCH", "retain this case's actual execution scope")
            data["entity_scope"] = r.entity_scope
        require(r.case_ref is not None and r.customer_ref is not None and r.channel is not None and r.subject is not None, "INTAKE_MISSING", "intake names the case, the customer, the channel, and the subject")
        require(r.channel in bp.channels, "CHANNEL_NOT_SUPPORTED", f"{r.channel} is not one of {list(bp.channels)}")
        if r.channel in ("sms", "whatsapp", "voice"):
            require(r.consent_ref is not None, "CONSENT_MISSING", f"{r.channel} contact needs the customer consent reference")
        data.update({"case_ref": r.case_ref, "customer_ref": r.customer_ref, "channel": r.channel, "opened_at": command.occurred_at, "consent_ref": r.consent_ref})
    elif event == "classify":
        require(r.severity is not None and r.classification_ref is not None, "CLASSIFICATION_MISSING", "classification names the severity and the classification record")
        sla = bp.sla(str(r.severity))
        opened = str(data["opened_at"])
        data.update({"severity": r.severity, "first_response_due": _hours_after(opened, sla.first_response_hours), "resolution_due": _hours_after(opened, sla.resolution_hours)})
    elif event == "assign":
        require(r.tier is not None and r.assignee_ref is not None, "ASSIGNMENT_MISSING", "assignment names the tier and the assignee")
        sla = bp.sla(str(data["severity"]))
        allowed = set(sla.allowed_tiers) | ({sla.escalate_to} if sla.escalate_to else set())
        require(r.tier in allowed, "TIER_NOT_ALLOWED", f"{data['severity']} cases assign to {sorted(allowed)}, not {r.tier}")
        if data.get("tier") is not None and status == "escalated":
            require(_TIER_RANK[str(r.tier)] >= _TIER_RANK[str(data["tier"])], "TIER_DOWNGRADE", "an escalated case does not assign to a lower tier")
        data.update({"tier": r.tier, "assignee_ref": r.assignee_ref})
    elif event == "escalate":
        sla = bp.sla(str(data["severity"]))
        require(sla.escalate_to is not None, "NO_ESCALATION_PATH", f"{data['severity']} has no escalation tier in this blueprint")
        current = str(data.get("tier"))
        require(_TIER_RANK.get(current, -1) < _TIER_RANK[str(sla.escalate_to)], "ALREADY_AT_TOP_TIER", f"the case is already at {current}")
        require(r.tier is None or _TIER_RANK[str(r.tier)] == _TIER_RANK[current] + 1 or r.tier == sla.escalate_to, "ESCALATION_SKIPS_TIERS", "escalate one tier at a time")
        data.update({"escalations": int(data.get("escalations", 0)) + 1, "tier": r.tier or sla.escalate_to, "assignee_ref": r.assignee_ref})
    elif event == "start_work":
        first = r.first_response_at or data.get("first_response_at") or command.occurred_at
        if data.get("first_response_at") is None:
            data.update({"first_response_at": first, "first_response_met": parsed(str(first)) <= parsed(str(data["first_response_due"]))})
    elif event == "submit_resolution":
        require(r.resolution_ref is not None and r.summary is not None and len(r.evidence_refs) >= 1, "RESOLUTION_MISSING", "a resolution names its reference, a summary, and at least one evidence reference")
        kind = r.remedy_kind or "none"
        require(kind in bp.remedy.allowed, "REMEDY_NOT_ALLOWED", f"{kind} is not an allowed remedy ({list(bp.remedy.allowed)})")
        value = r.remedy_value if r.remedy_value is not None else Decimal("0")
        if kind != "none":
            require(value > 0, "REMEDY_VALUE_MISSING", "a remedy carries its value")
            require(value <= bp.remedy.max_remedy_value, "REMEDY_ABOVE_CEILING", f"remedy {value} exceeds the {bp.remedy.max_remedy_value} ceiling; escalate", "manual_reconciliation")
            if value > bp.remedy.approval_required_above:
                from lightbulb.authority_matrix import require_authorization_proof
                require(r.authorization_proof is not None, "APPROVAL_REQUIRED", f"remedies above {bp.remedy.approval_required_above} require an exact authority proof", "await_approval")
                proof = require_authorization_proof(r.authorization_proof, category="remedy", amount=value, currency=bp.currency, command=command, plan_digest=plan.plan_digest, company_ref=bp.company_ref, entity_ref=(data.get("entity_scope") or {}).get("entity_ref"))
                data["authorization_proof_digest"] = proof.proof_digest
                r = CaseReceipt.model_validate({**r.to_dict(), "approval_ref": proof.approval_task_id})
        data.update({"resolution_ref": r.resolution_ref, "resolved_at": command.occurred_at, "resolution_met": parsed(command.occurred_at) <= parsed(str(data["resolution_due"])), "remedy_kind": kind, "remedy_value": str(value.quantize(MONEY_QUANTUM)), "approval_ref": r.approval_ref})
    elif event == "verify":
        require(r.verifier_ref is not None and r.verification_ref is not None, "VERIFICATION_MISSING", "verification names the verifier and the verification record")
        if bp.verification.verifier == "customer":
            require(r.verifier_ref == data.get("customer_ref"), "VERIFIER_NOT_CUSTOMER", "this blueprint verifies with the customer")
        else:
            require(r.verifier_ref != data.get("assignee_ref") and r.verifier_ref != command.actor_ref, "VERIFIER_NOT_INDEPENDENT", "the verifier must be independent of the assignee and the acting actor", "await_approval")
        data.update({"verified": True, "verifier_ref": r.verifier_ref, "verification_ref": r.verification_ref})
    elif event == "reject_resolution":
        data.update({"rejections": int(data.get("rejections", 0)) + 1, "resolution_ref": None, "resolved_at": None, "resolution_met": None, "verified": False})
    elif event == "close":
        if status == "resolution_submitted":
            require(bp.verification.allow_close_when_unreachable, "VERIFICATION_REQUIRED", "this blueprint closes only verified resolutions", "manual_reconciliation")
            require(r.unreachable is True, "VERIFICATION_PENDING", "close an unverified resolution only by declaring the customer unreachable")
            window_end = parsed(_hours_after(str(data["resolved_at"]), bp.verification.verification_window_hours))
            require(parsed(command.occurred_at) >= window_end, "VERIFICATION_WINDOW_OPEN", f"the verification window runs until {window_end.isoformat()}")
            data.update({"unreachable": True})
        data.update({"closed_at": command.occurred_at, "outcome": "closed"})
    elif event == "reopen":
        closed_at = data.get("closed_at")
        limit = parsed(_hours_after(str(closed_at), bp.verification.reopen_window_days * 24))
        require(closed_at is not None and parsed(command.occurred_at) <= limit, "REOPEN_WINDOW_CLOSED", f"cases reopen within {bp.verification.reopen_window_days} day(s) of closing; open a new case", "manual_reconciliation")
        data.update({"reopen_count": int(data.get("reopen_count", 0)) + 1, "outcome": "reopened", "closed_at": None, "verified": False, "verifier_ref": None, "verification_ref": None, "unreachable": False, "resolution_ref": None, "resolved_at": None, "resolution_met": None})
    return next_status, data


CASE_LIFECYCLE = LifecycleSpec(entity="service_case", schema_prefix="service_delivery_case", statuses=CASE_STATUSES, terminal=TERMINAL_CASE_STATUSES, events=CASE_EVENTS, table=_CASE_TABLE, opening_event="intake", reason_events=("reject_resolution", "reopen", "escalate"), apply=_apply_case, ledger_model=CaseLedger, receipt_model=CaseReceipt, effect_boundary_model=CaseEffectBoundary, plan_model=ServiceDeliveryLoopPlan, max_transitions=MAX_CASE_TRANSITIONS)
CaseCommand = CASE_LIFECYCLE.Command
CaseState = CASE_LIFECYCLE.State
CaseTransitionResult = CASE_LIFECYCLE.TransitionResult
seal_case_command = CASE_LIFECYCLE.seal_command
case_command_digest = CASE_LIFECYCLE.command_digest


def open_case(plan: ServiceDeliveryLoopPlan | Mapping[str, Any], scope: Mapping[str, Any] | Any, *, case_ref: str, customer_ref: str, channel: str, subject: str, opened_at: str, actor_ref: str, consent_ref: str | None = None) -> Any:
    parsed_plan = ServiceDeliveryLoopPlan.model_validate(detached(plan))
    receipt: dict[str, Any] = {"entity_scope": detached(scope), "case_ref": case_ref, "customer_ref": customer_ref, "channel": channel, "subject": subject}
    if consent_ref is not None:
        receipt["consent_ref"] = consent_ref
    return CASE_LIFECYCLE.open(parsed_plan, scope, opened_at=opened_at, actor_ref=actor_ref, receipt=receipt)


def advance_case(plan: ServiceDeliveryLoopPlan | Mapping[str, Any], state: Any, command: Any) -> Any:
    return CASE_LIFECYCLE.advance(plan, state, command)


def case_resolved_signal(plan: ServiceDeliveryLoopPlan | Mapping[str, Any], state: Any, *, emitted_at: str) -> dict[str, Any]:
    """The ``signals.case_resolved`` payload for a closed case; ``resolution_verified`` is never asserted for unreachable closes."""

    _, bound = CASE_LIFECYCLE.bind(plan, state)
    if bound.status != "closed":
        raise ValueError(f"CASE_NOT_CLOSED: the case is {bound.status}")
    return {"name": "signals.case_resolved", "producer": "service_delivery", "emitted_at": emitted_at, "payload": {"case_ref": str(bound.ledger.case_ref), "resolution_verified": bool(bound.ledger.verified), "severity": str(bound.ledger.severity), "sla_met": bool(bound.ledger.resolution_met) if bound.ledger.resolution_met is not None else False, "case_state_digest": bound.state_digest}}


# --------------------------------------------------------------------------- #
# Assessment
# --------------------------------------------------------------------------- #


class ServiceDeliveryAssessment(StrictModel):
    schema_id: str = Field(default=ASSESSMENT_SCHEMA, alias="schema")
    plan_digest: Sha256Digest
    assessed_at: str
    cases: int = Field(ge=0)
    closed: int = Field(ge=0)
    verified: int = Field(ge=0)
    unreachable_closes: int = Field(ge=0)
    reopened: int = Field(ge=0)
    escalations: int = Field(ge=0)
    first_response_attainment_percent: Decimal | None = None
    resolution_attainment_percent: Decimal | None = None
    verified_resolution_percent: Decimal | None = None
    reopen_rate_percent: Decimal | None = None
    remedy_total: Decimal
    by_severity: dict[str, int] = Field(default_factory=dict)
    learnings: tuple[BoundedText, ...] = Field(min_length=1, max_length=12)
    assessment_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("assessed_at")
    @classmethod
    def _assessed(cls, value: str) -> str:
        return timestamp(value, field_name="assessed_at")

    @field_validator("remedy_total", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return _money(value, "remedy_total")

    @field_validator("first_response_attainment_percent", "resolution_attainment_percent", "verified_resolution_percent", "reopen_rate_percent", mode="before")
    @classmethod
    def _optional(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else _money(value, str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> ServiceDeliveryAssessment:
        if not skip_digests(info) and self.assessment_digest != sealed_digest(ServiceDeliveryAssessment, self, "assessment_digest"):
            raise ValueError("assessment_digest must commit the exact assessment")
        return self


def _rate(numerator: int, denominator: int) -> Decimal | None:
    return (Decimal(numerator) / Decimal(denominator) * Decimal("100")).quantize(Decimal("0.01")) if denominator else None


def assess_service_delivery(plan: ServiceDeliveryLoopPlan | Mapping[str, Any], states: Sequence[Any], *, assessed_at: str) -> ServiceDeliveryAssessment:
    parsed_plan = ServiceDeliveryLoopPlan.model_validate(detached(plan))
    bp = parsed_plan.blueprint
    bound = [CASE_LIFECYCLE.bind(parsed_plan, item)[1] for item in states]
    closed = [item for item in bound if item.status == "closed"]
    responded = [item for item in bound if item.ledger.first_response_met is not None]
    resolved = [item for item in bound if item.ledger.resolution_met is not None]
    first_response = _rate(sum(1 for item in responded if item.ledger.first_response_met), len(responded))
    resolution = _rate(sum(1 for item in resolved if item.ledger.resolution_met), len(resolved))
    verified = _rate(sum(1 for item in closed if item.ledger.verified), len(closed))
    reopen_rate = _rate(sum(1 for item in bound if item.ledger.reopen_count > 0), len(bound))
    by_severity: dict[str, int] = {}
    for item in bound:
        if item.ledger.severity:
            by_severity[str(item.ledger.severity)] = by_severity.get(str(item.ledger.severity), 0) + 1
    learnings: list[str] = []
    if not bound:
        learnings.append("no cases yet; intake starts the first case")
    if first_response is not None and first_response < bp.targets.min_sla_attainment_percent:
        learnings.append(f"first-response attainment {first_response}% is below the {bp.targets.min_sla_attainment_percent}% target")
    if resolution is not None and resolution < bp.targets.min_sla_attainment_percent:
        learnings.append(f"resolution attainment {resolution}% is below the {bp.targets.min_sla_attainment_percent}% target")
    if verified is not None and verified < bp.targets.min_verified_resolution_percent:
        learnings.append(f"only {verified}% of closes were verified; reduce unreachable closes")
    if reopen_rate is not None and reopen_rate > bp.targets.max_reopen_rate_percent:
        learnings.append(f"reopen rate {reopen_rate}% exceeds the {bp.targets.max_reopen_rate_percent}% target")
    if not learnings:
        learnings.append("service delivery is inside blueprint targets")
    return seal(ServiceDeliveryAssessment, {"plan_digest": parsed_plan.plan_digest, "assessed_at": assessed_at, "cases": len(bound), "closed": len(closed), "verified": sum(1 for item in closed if item.ledger.verified), "unreachable_closes": sum(1 for item in closed if item.ledger.unreachable), "reopened": sum(1 for item in bound if item.ledger.reopen_count > 0), "escalations": sum(item.ledger.escalations for item in bound), "first_response_attainment_percent": first_response, "resolution_attainment_percent": resolution, "verified_resolution_percent": verified, "reopen_rate_percent": reopen_rate, "remedy_total": sum((item.ledger.remedy_value for item in bound), Decimal("0")).quantize(MONEY_QUANTUM), "by_severity": by_severity, "learnings": tuple(learnings[:12])}, "assessment_digest")


SERVICE_DELIVERY_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": SERVICE_DELIVERY_KIND,
    "golden_loop": SERVICE_DELIVERY_GOLDEN_LOOP,
    "stages": list(STAGE_ORDER),
    "profiles": sorted(SERVICE_DELIVERY_PROFILES),
    "case_statuses": list(CASE_STATUSES),
    "case_events": list(CASE_EVENTS),
    "channels": list(CHANNELS),
    "tiers": list(TIERS),
    "required_connectors": ["zendesk", "intercom", "gmail", "twilio", "stripe"],
    "hard_rules": ["severity fixes the SLA clocks at classification", "cases assign only inside the severity's tiers and escalate one tier at a time", "resolutions carry evidence; remedies stay inside the ceiling and carry approval above the threshold", "the customer or an independent verifier confirms before close", "unreachable closes wait for the verification window and never claim verification", "reopening stays inside the window"],
}

__all__ = [
    "CASE_EVENTS",
    "CASE_LIFECYCLE",
    "CASE_STATUSES",
    "CHANNELS",
    "SERVICE_DELIVERY_GOLDEN_LOOP",
    "SERVICE_DELIVERY_KIND",
    "SERVICE_DELIVERY_MANIFEST",
    "SERVICE_DELIVERY_PROFILES",
    "SEVERITIES",
    "STAGE_ORDER",
    "TIERS",
    "CaseCommand",
    "CaseEffectBoundary",
    "CaseLedger",
    "CaseReceipt",
    "CaseState",
    "CaseTransitionResult",
    "DeliveryTargets",
    "RemedyPolicy",
    "ServiceDeliveryAssessment",
    "ServiceDeliveryBlueprint",
    "ServiceDeliveryLoopPlan",
    "SeveritySla",
    "StageBinding",
    "VerificationPolicy",
    "advance_case",
    "assess_service_delivery",
    "case_command_digest",
    "case_resolved_signal",
    "compile_service_delivery_blueprint",
    "open_case",
    "seal_case_command",
]
