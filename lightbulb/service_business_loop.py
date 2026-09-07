"""Service Business Golden Operating Loop and Company Blueprint profiles.

Composes the existing substrate into one out-of-the-box loop::

    Market -> Qualify -> Quote -> Agreement -> Deliver
           -> Verify acceptance -> Invoice -> Collect -> Support/Renew -> Learn

Every stage binds to primitives that already exist (``crm.qualify_lead``,
``demand_gen.*``, the commercial/legal handoff, the ``ServiceEngagement``
chain, contract delivery acceptance, ``finance.create_invoice``,
``finance.collect_payment``, governed artifact generation).  Delivery modes
cover customer-performed work, trades and field service, consultant or agency
deliverables, software leased to a coding harness, and automated digital
delivery.  For software, the harness submits the Builder Result and an
independent evaluator applies the Acceptance Contract; the same binding may
never implement and accept one assignment.

The loop state is a digest-chained, replay-fenced cycle record.  It links to
engagement snapshots, custody candidates, work packets, invoices, and
payments by reference and digest; it never persists, never calls a provider,
and never mints authority.  Software delivery binds to the
``software.approved_change_to_verified_production`` loop **by reference only**
so this pack stays independent of that branch until integration.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.business_artifact_production import BUSINESS_ARTIFACT_GOLDEN_LOOP
from lightbulb.commercial_legal_handoff import COMMERCIAL_LEGAL_HANDOFF_GOLDEN_LOOP
from lightbulb.contract_delivery_acceptance import CONTRACT_DELIVERY_GOLDEN_LOOP
from lightbulb.contract_obligations import CONTRACT_OBLIGATION_GOLDEN_LOOP
from lightbulb.service_engagement import (
    SERVICE_ENGAGEMENT_GOLDEN_LOOP,
    BoundedText,
    CurrencyCode,
    EngagementStage,
    OpaqueRef,
    ServiceEngagementSnapshot,
    Sha256Digest,
    ShortText,
    _decimal,
    _detached,
    _digest_without,
    _parsed_timestamp,
    _StrictModel,
    _timestamp,
)


SERVICE_BUSINESS_GOLDEN_LOOP = "service.market_to_renewal_business@0.1.0"
SERVICE_BUSINESS_ARCHETYPE = "service_business"
SOFTWARE_PRODUCTION_GOLDEN_LOOP_REF = "software.approved_change_to_verified_production@0.1.0"
BLUEPRINT_SCHEMA = "lightbulb.service_business_blueprint.v1"
PLAN_SCHEMA = "lightbulb.service_business_loop_plan.v1"
CYCLE_COMMAND_SCHEMA = "lightbulb.service_business_cycle_command.v1"
CYCLE_STATE_SCHEMA = "lightbulb.service_business_cycle_state.v1"
CYCLE_RESULT_SCHEMA = "lightbulb.service_business_cycle_transition_result.v1"
CYCLE_ASSESSMENT_SCHEMA = "lightbulb.service_business_cycle_assessment.v1"
GENESIS_DIGEST = "0" * 64
MAX_CYCLE_TRANSITIONS = 40

LoopStage = Literal["market", "qualify", "quote", "agreement", "deliver", "verify_acceptance", "invoice", "collect", "support_renew", "learn"]
STAGE_ORDER: tuple[str, ...] = ("market", "qualify", "quote", "agreement", "deliver", "verify_acceptance", "invoice", "collect", "support_renew", "learn")
CycleStatus = Literal["opened", "market_completed", "qualified", "quoted", "agreed", "delivered", "acceptance_verified", "invoiced", "collected", "supported", "completed", "disqualified", "cancelled"]
STATUS_AFTER_STAGE: dict[str, str] = {
    "market": "market_completed",
    "qualify": "qualified",
    "quote": "quoted",
    "agreement": "agreed",
    "deliver": "delivered",
    "verify_acceptance": "acceptance_verified",
    "invoice": "invoiced",
    "collect": "collected",
    "support_renew": "supported",
    "learn": "completed",
}
STATUS_BEFORE_STAGE: dict[str, str] = {"market": "opened", **{STAGE_ORDER[index]: STATUS_AFTER_STAGE[STAGE_ORDER[index - 1]] for index in range(1, len(STAGE_ORDER))}}
TERMINAL_CYCLE_STATUSES: frozenset[str] = frozenset({"completed", "disqualified", "cancelled"})
_PRE_AGREEMENT_STATUSES: frozenset[str] = frozenset({"opened", "market_completed", "qualified", "quoted"})

BlueprintProfile = Literal["consulting", "trades", "software_delivery", "agency", "custom"]
DeliveryMode = Literal["customer_performed", "field_service", "consultant_deliverable", "software_delivery_harness", "automated_digital"]
AcceptancePolicy = Literal["customer_approval", "independent_evaluator", "customer_and_independent_evaluator"]
InvoiceScheduleKind = Literal["deposit_then_final", "milestone", "final_only", "time_and_materials"]
InvoiceKind = Literal["deposit", "milestone", "final", "time_and_materials"]
RenewalPolicy = Literal["none", "offer_renewal", "auto_renew_with_notice"]
RenewalDecision = Literal["renewed", "declined", "not_offered", "pending"]
AcceptanceState = Literal["accepted", "accepted_partial", "rejected"]
Qualification = Literal["qualified", "disqualified", "needs_research"]
LoopArtifactKind = Literal["proposal", "quote_summary", "estimate", "statement_of_work", "contract", "invoice", "presentation", "one_pager", "case_study"]
StageGate = Literal["none", "spring_approval", "independent_evaluator", "customer_approval"]
CycleEvent = Literal["complete_stage", "disqualify", "cancel"]
RecoveryDisposition = Literal["not_required", "do_not_replay", "refresh_state", "correct_input", "manual_reconciliation"]

_INVOICE_KINDS_BY_SCHEDULE: dict[str, frozenset[str]] = {
    "deposit_then_final": frozenset({"deposit", "final"}),
    "milestone": frozenset({"deposit", "milestone", "final"}),
    "final_only": frozenset({"final"}),
    "time_and_materials": frozenset({"time_and_materials", "final"}),
}
_ENGAGEMENT_STAGES_BY_LOOP_STAGE: dict[str, frozenset[str]] = {
    "quote": frozenset({"quote_proposed", "quote_approved"}),
    "agreement": frozenset({"agreement_executed"}),
    "deliver": frozenset({"delivery_planned", "delivery_in_progress", "accepted"}),
    "verify_acceptance": frozenset({"accepted"}),
    "invoice": frozenset({"invoiced", "paid"}),
    "collect": frozenset({"paid", "closed"}),
}
_KNOWN_PRIMITIVE_REFS: frozenset[str] = frozenset(
    {
        "demand_gen.plan_audience_growth", "demand_gen.plan_content_calendar", "communication.plan_crm_conversation_turn", "communication.write_email",
        "crm.qualify_lead", "calendar.schedule_meeting",
        "commercial.evaluate_quote_order_contract_controls", "commercial.propose_operations_transition", "documents.prepare_business_artifact_generation",
        "documents.validate_generated_business_artifact", "documents.generate_business_artifact",
        "commercial.compile_legal_review_packet", "commercial.validate_legal_review_outcome", "commercial.reconcile_executed_agreement", "legal.draft_contract", "legal.review_contract",
        "legal.intake_contract_obligations_from_custody", "legal.compile_contract_obligation_schedule",
        "project.compile_contract_delivery_plan", "project.create_work_packet", "project.bind_contract_deliverable_to_work_packet", "project.evaluate_contractual_delivery_evidence",
        "project.compile_customer_acceptance_candidate", "maintenance.propose_work_order_transition", "service.propose_engagement_transition",
        "project.request_software_production", "project.assess_software_production_result",
        "service.propose_engagement_invoice", "finance.create_invoice", "finance.collect_payment", "service.assess_engagement",
        "service.intake_and_classify_case", "service.verify_case_resolution", "commercial.propose_contract_change_order", "growth.review_customer_value",
        "growth.build_unit_economics", "growth.review_profit", "learning.plan_optimization_sweep",
    }
)
_EFFECT_PRIMITIVE_REFS: frozenset[str] = frozenset({"documents.generate_business_artifact", "project.create_work_packet", "finance.create_invoice", "finance.collect_payment", "calendar.schedule_meeting", "communication.write_email"})
_DELIVERY_PRIMITIVES_BY_MODE: dict[str, tuple[str, ...]] = {
    "customer_performed": ("project.compile_contract_delivery_plan", "project.evaluate_contractual_delivery_evidence"),
    "field_service": ("project.compile_contract_delivery_plan", "project.create_work_packet", "maintenance.propose_work_order_transition", "project.evaluate_contractual_delivery_evidence"),
    "consultant_deliverable": ("project.compile_contract_delivery_plan", "project.create_work_packet", "project.bind_contract_deliverable_to_work_packet", "project.evaluate_contractual_delivery_evidence"),
    "software_delivery_harness": ("project.compile_contract_delivery_plan", "project.create_work_packet", "project.bind_contract_deliverable_to_work_packet", "project.request_software_production", "project.assess_software_production_result"),
    "automated_digital": ("project.compile_contract_delivery_plan", "documents.prepare_business_artifact_generation", "documents.validate_generated_business_artifact", "documents.generate_business_artifact"),
}
_ACCEPTANCE_BY_MODE_DEFAULT: dict[str, str] = {
    "customer_performed": "customer_approval",
    "field_service": "customer_approval",
    "consultant_deliverable": "customer_approval",
    "software_delivery_harness": "customer_and_independent_evaluator",
    "automated_digital": "independent_evaluator",
}


def _stable_digest(value: Any) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _skip(info: ValidationInfo) -> bool:
    return bool((info.context or {}).get("skip_service_business_digests"))


def _sealed_digest(model: type[_StrictModel], payload: Any, field: str) -> str:
    raw = dict(_detached(payload))
    raw.setdefault(field, GENESIS_DIGEST)
    parsed = model.model_validate(raw, context={"skip_service_business_digests": True})
    return _digest_without(parsed.to_dict(), field)


# --------------------------------------------------------------------------- #
# Blueprint and plan
# --------------------------------------------------------------------------- #


class InvoiceSchedule(_StrictModel):
    kind: InvoiceScheduleKind = "deposit_then_final"
    deposit_percent: Decimal = Field(default=Decimal("0"), validate_default=True)
    milestone_count: int = Field(default=0, ge=0, le=50)
    net_days: int = Field(default=14, ge=0, le=180)

    @field_validator("deposit_percent", mode="before")
    @classmethod
    def _percent(cls, value: Any) -> Decimal:
        parsed = _decimal(value, field_name="deposit_percent")
        if parsed < 0 or parsed > 100:
            raise ValueError("deposit_percent must be between 0 and 100")
        return parsed

    @model_validator(mode="after")
    def _coherent(self) -> "InvoiceSchedule":
        if self.kind == "deposit_then_final" and self.deposit_percent <= 0:
            raise ValueError("deposit_then_final requires a positive deposit percent")
        if self.kind == "milestone" and self.milestone_count < 1:
            raise ValueError("milestone schedules need at least one milestone")
        if self.kind in {"final_only", "time_and_materials"} and self.deposit_percent != 0:
            raise ValueError(f"{self.kind} schedules do not take a deposit")
        return self


class ServiceBusinessBlueprint(_StrictModel):
    """Company Blueprint profile for a service business (consulting, trades, software delivery, agency, custom)."""

    schema_id: Literal["lightbulb.service_business_blueprint.v1"] = Field(default=BLUEPRINT_SCHEMA, alias="schema")
    profile: BlueprintProfile
    name: ShortText
    delivery_mode: DeliveryMode
    acceptance_policy: AcceptancePolicy
    invoice_schedule: InvoiceSchedule
    renewal_policy: RenewalPolicy = "offer_renewal"
    support_window_days: int = Field(default=30, ge=0, le=730)
    target_gross_margin_percent: Decimal = Field(default=Decimal("40"), validate_default=True)
    qualification_threshold: int = Field(default=60, ge=0, le=100)
    required_artifacts: tuple[LoopArtifactKind, ...] = Field(default_factory=tuple, max_length=9)
    marketing_channels: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=20)
    currency: CurrencyCode = "USD"
    notes: BoundedText | None = None
    blueprint_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("target_gross_margin_percent", mode="before")
    @classmethod
    def _margin(cls, value: Any) -> Decimal:
        parsed = _decimal(value, field_name="target_gross_margin_percent")
        if parsed < 0 or parsed > 100:
            raise ValueError("target_gross_margin_percent must be between 0 and 100")
        return parsed

    @model_validator(mode="after")
    def _blueprint_is_exact(self, info: ValidationInfo) -> "ServiceBusinessBlueprint":
        if len(set(self.required_artifacts)) != len(self.required_artifacts) or len(set(self.marketing_channels)) != len(self.marketing_channels):
            raise ValueError("required artifacts and marketing channels must be unique")
        if self.delivery_mode == "software_delivery_harness" and self.acceptance_policy == "customer_approval":
            raise ValueError("software delivered through a coding harness requires an independent evaluator")
        if self.renewal_policy == "none" and self.support_window_days == 0 and self.profile != "custom":
            raise ValueError("profiles without renewal must still state a support window")
        if _skip(info):
            return self
        if self.blueprint_digest != _sealed_digest(ServiceBusinessBlueprint, self, "blueprint_digest"):
            raise ValueError("blueprint_digest must commit the exact blueprint")
        return self


def seal_service_business_blueprint(blueprint: Mapping[str, Any]) -> dict[str, Any]:
    raw = dict(_detached(blueprint))
    raw["blueprint_digest"] = _sealed_digest(ServiceBusinessBlueprint, raw, "blueprint_digest")
    return ServiceBusinessBlueprint.model_validate(raw).to_dict()


SERVICE_BUSINESS_PROFILES: dict[str, dict[str, Any]] = {
    "consulting": {
        "profile": "consulting", "name": "Consulting practice", "delivery_mode": "consultant_deliverable", "acceptance_policy": "customer_approval",
        "invoice_schedule": {"kind": "deposit_then_final", "deposit_percent": "30", "net_days": 14}, "renewal_policy": "offer_renewal", "support_window_days": 30,
        "target_gross_margin_percent": "55", "qualification_threshold": 60, "required_artifacts": ["proposal", "statement_of_work", "invoice"],
        "marketing_channels": ["content", "referrals", "linkedin"], "notes": "Scope, estimate, proposal, SOW, deliverables accepted by the customer, deposit then final invoice.",
    },
    "trades": {
        "profile": "trades", "name": "Trades and field service", "delivery_mode": "field_service", "acceptance_policy": "customer_approval",
        "invoice_schedule": {"kind": "deposit_then_final", "deposit_percent": "50", "net_days": 7}, "renewal_policy": "none", "support_window_days": 90,
        "target_gross_margin_percent": "35", "qualification_threshold": 50, "required_artifacts": ["estimate", "invoice"],
        "marketing_channels": ["local_search", "referrals", "social"], "notes": "Estimate, work order, on-site completion confirmed by the customer, warranty support window.",
    },
    "software_delivery": {
        "profile": "software_delivery", "name": "Software delivery leased to a coding harness", "delivery_mode": "software_delivery_harness", "acceptance_policy": "customer_and_independent_evaluator",
        "invoice_schedule": {"kind": "milestone", "deposit_percent": "20", "milestone_count": 3, "net_days": 30}, "renewal_policy": "offer_renewal", "support_window_days": 60,
        "target_gross_margin_percent": "45", "qualification_threshold": 65, "required_artifacts": ["proposal", "statement_of_work", "contract", "invoice"],
        "marketing_channels": ["content", "partnerships", "linkedin"], "notes": "Builder Result from Codex, Claude Code, or another harness; an independent evaluator applies the Acceptance Contract; milestone invoicing.",
    },
    "agency": {
        "profile": "agency", "name": "Creative or marketing agency", "delivery_mode": "consultant_deliverable", "acceptance_policy": "customer_approval",
        "invoice_schedule": {"kind": "time_and_materials", "net_days": 30}, "renewal_policy": "auto_renew_with_notice", "support_window_days": 30,
        "target_gross_margin_percent": "50", "qualification_threshold": 55, "required_artifacts": ["proposal", "contract", "invoice", "presentation"],
        "marketing_channels": ["content", "social", "events"], "notes": "Retainer-style deliverables billed on time and materials with notice-based renewal.",
    },
}


class StageBinding(_StrictModel):
    stage: LoopStage
    title: ShortText
    primitive_refs: tuple[ShortText, ...] = Field(min_length=1, max_length=12)
    engagement_stages: tuple[EngagementStage, ...] = Field(default_factory=tuple, max_length=6)
    required_artifacts: tuple[LoopArtifactKind, ...] = Field(default_factory=tuple, max_length=6)
    effect_primitive_refs: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=6)
    gate: StageGate = "none"
    golden_loops: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=6)

    @model_validator(mode="after")
    def _bound_to_known_primitives(self) -> "StageBinding":
        unknown = [ref for ref in self.primitive_refs if ref not in _KNOWN_PRIMITIVE_REFS]
        if unknown:
            raise ValueError(f"stage {self.stage} binds unknown primitives: {unknown}")
        if any(ref not in self.primitive_refs for ref in self.effect_primitive_refs):
            raise ValueError("effect primitives must be among the stage's bound primitives")
        if any(ref not in _EFFECT_PRIMITIVE_REFS for ref in self.effect_primitive_refs):
            raise ValueError("only effect-bearing primitives may be declared as stage effects")
        return self


class ServiceBusinessLoopPlan(_StrictModel):
    schema_id: Literal["lightbulb.service_business_loop_plan.v1"] = Field(default=PLAN_SCHEMA, alias="schema")
    golden_loop: Literal["service.market_to_renewal_business@0.1.0"] = SERVICE_BUSINESS_GOLDEN_LOOP
    archetype: Literal["service_business"] = SERVICE_BUSINESS_ARCHETYPE
    blueprint: ServiceBusinessBlueprint
    stages: tuple[StageBinding, ...] = Field(min_length=10, max_length=10)
    builder_evaluator_separation_required: bool
    composed_golden_loops: tuple[ShortText, ...] = Field(min_length=1, max_length=12)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _plan_is_exact(self, info: ValidationInfo) -> "ServiceBusinessLoopPlan":
        if tuple(item.stage for item in self.stages) != STAGE_ORDER:
            raise ValueError("plan stages must follow the loop order exactly")
        if self.builder_evaluator_separation_required != (self.blueprint.acceptance_policy != "customer_approval"):
            raise ValueError("builder/evaluator separation follows the acceptance policy")
        if _skip(info):
            return self
        if self.plan_digest != _sealed_digest(ServiceBusinessLoopPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self

    def stage(self, name: str) -> StageBinding:
        return next(item for item in self.stages if item.stage == name)


def _stage_bindings(blueprint: ServiceBusinessBlueprint) -> list[dict[str, Any]]:
    artifacts = set(blueprint.required_artifacts)
    quote_artifacts = tuple(kind for kind in ("proposal", "quote_summary", "estimate", "presentation", "one_pager") if kind in artifacts)
    agreement_artifacts = tuple(kind for kind in ("statement_of_work", "contract") if kind in artifacts)
    invoice_artifacts = ("invoice",) if "invoice" in artifacts else ()
    delivery_refs = _DELIVERY_PRIMITIVES_BY_MODE[blueprint.delivery_mode]
    acceptance_gate: str = {"customer_approval": "customer_approval", "independent_evaluator": "independent_evaluator", "customer_and_independent_evaluator": "independent_evaluator"}[blueprint.acceptance_policy]
    delivery_loops = (CONTRACT_DELIVERY_GOLDEN_LOOP,) + ((SOFTWARE_PRODUCTION_GOLDEN_LOOP_REF,) if blueprint.delivery_mode == "software_delivery_harness" else ()) + ((BUSINESS_ARTIFACT_GOLDEN_LOOP,) if blueprint.delivery_mode == "automated_digital" else ())
    return [
        {"stage": "market", "title": "Acquire demand", "primitive_refs": ("demand_gen.plan_audience_growth", "demand_gen.plan_content_calendar", "communication.plan_crm_conversation_turn"), "gate": "none"},
        {"stage": "qualify", "title": "Qualify the lead", "primitive_refs": ("crm.qualify_lead", "calendar.schedule_meeting"), "effect_primitive_refs": ("calendar.schedule_meeting",), "gate": "none"},
        {"stage": "quote", "title": "Scope, estimate, and quote", "primitive_refs": ("commercial.evaluate_quote_order_contract_controls", "commercial.propose_operations_transition", "documents.prepare_business_artifact_generation", "documents.validate_generated_business_artifact", "documents.generate_business_artifact", "service.propose_engagement_transition"), "engagement_stages": ("quote_proposed", "quote_approved"), "required_artifacts": quote_artifacts, "effect_primitive_refs": ("documents.generate_business_artifact",), "gate": "spring_approval", "golden_loops": (SERVICE_ENGAGEMENT_GOLDEN_LOOP, BUSINESS_ARTIFACT_GOLDEN_LOOP)},
        {"stage": "agreement", "title": "Service agreement or SOW", "primitive_refs": ("commercial.compile_legal_review_packet", "commercial.validate_legal_review_outcome", "commercial.reconcile_executed_agreement", "legal.intake_contract_obligations_from_custody", "legal.compile_contract_obligation_schedule", "service.propose_engagement_transition"), "engagement_stages": ("agreement_executed",), "required_artifacts": agreement_artifacts, "gate": "spring_approval", "golden_loops": (COMMERCIAL_LEGAL_HANDOFF_GOLDEN_LOOP, CONTRACT_OBLIGATION_GOLDEN_LOOP)},
        {"stage": "deliver", "title": f"Deliver value ({blueprint.delivery_mode})", "primitive_refs": delivery_refs + ("service.propose_engagement_transition",), "engagement_stages": ("delivery_planned", "delivery_in_progress"), "effect_primitive_refs": tuple(ref for ref in delivery_refs if ref in _EFFECT_PRIMITIVE_REFS), "gate": "spring_approval", "golden_loops": delivery_loops},
        {"stage": "verify_acceptance", "title": "Verify acceptance", "primitive_refs": ("project.evaluate_contractual_delivery_evidence", "project.compile_customer_acceptance_candidate", "service.propose_engagement_transition"), "engagement_stages": ("accepted",), "gate": acceptance_gate, "golden_loops": (CONTRACT_DELIVERY_GOLDEN_LOOP,)},
        {"stage": "invoice", "title": "Invoice accepted value", "primitive_refs": ("service.propose_engagement_invoice", "finance.create_invoice", "service.propose_engagement_transition") + (("documents.generate_business_artifact",) if invoice_artifacts else ()), "engagement_stages": ("invoiced",), "required_artifacts": invoice_artifacts, "effect_primitive_refs": ("finance.create_invoice",) + (("documents.generate_business_artifact",) if invoice_artifacts else ()), "gate": "spring_approval"},
        {"stage": "collect", "title": "Collect payment", "primitive_refs": ("finance.collect_payment", "communication.write_email", "service.propose_engagement_transition", "service.assess_engagement"), "engagement_stages": ("paid", "closed"), "effect_primitive_refs": ("finance.collect_payment", "communication.write_email"), "gate": "spring_approval"},
        {"stage": "support_renew", "title": "Support and renew", "primitive_refs": ("service.intake_and_classify_case", "service.verify_case_resolution", "commercial.propose_contract_change_order", "growth.review_customer_value"), "gate": "none"},
        {"stage": "learn", "title": "Learn: delivery quality, margin, renewals", "primitive_refs": ("growth.build_unit_economics", "growth.review_profit", "learning.plan_optimization_sweep"), "gate": "none"},
    ]


def compile_service_business_blueprint(profile: str | Mapping[str, Any], overrides: Mapping[str, Any] | None = None) -> ServiceBusinessLoopPlan:
    """Build the loop plan for a ready-made profile (or a custom blueprint mapping) with optional overrides."""

    if isinstance(profile, str):
        if profile not in SERVICE_BUSINESS_PROFILES:
            raise ValueError(f"unknown service business profile {profile!r}; choose one of {sorted(SERVICE_BUSINESS_PROFILES)} or pass a custom blueprint")
        raw: dict[str, Any] = json.loads(json.dumps(SERVICE_BUSINESS_PROFILES[profile]))
    else:
        raw = dict(_detached(profile))
    for key, value in dict(overrides or {}).items():
        if key in {"schema", "blueprint_digest"}:
            raise ValueError("overrides cannot set schema or digest fields")
        if isinstance(value, Mapping) and isinstance(raw.get(key), Mapping):
            raw[key] = {**raw[key], **value}
        else:
            raw[key] = value
    blueprint = ServiceBusinessBlueprint.model_validate(seal_service_business_blueprint(raw))
    composed = (SERVICE_ENGAGEMENT_GOLDEN_LOOP, COMMERCIAL_LEGAL_HANDOFF_GOLDEN_LOOP, CONTRACT_OBLIGATION_GOLDEN_LOOP, CONTRACT_DELIVERY_GOLDEN_LOOP, BUSINESS_ARTIFACT_GOLDEN_LOOP) + ((SOFTWARE_PRODUCTION_GOLDEN_LOOP_REF,) if blueprint.delivery_mode == "software_delivery_harness" else ())
    payload = {"blueprint": blueprint.to_dict(), "stages": _stage_bindings(blueprint), "builder_evaluator_separation_required": blueprint.acceptance_policy != "customer_approval", "composed_golden_loops": composed}
    payload["plan_digest"] = _sealed_digest(ServiceBusinessLoopPlan, payload, "plan_digest")
    return ServiceBusinessLoopPlan.model_validate(payload)


# --------------------------------------------------------------------------- #
# Cycle: scope, receipts, commands
# --------------------------------------------------------------------------- #


class ServiceBusinessScope(_StrictModel):
    tenant_ref: OpaqueRef
    company_ref: OpaqueRef
    project_ref: OpaqueRef
    project_id: str
    cycle_ref: OpaqueRef
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


class StageReceipt(_StrictModel):
    """What the agent links when it completes a stage; every field is a reference, digest, amount, or decision."""

    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    artifact_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=20)
    artifact_kinds: tuple[LoopArtifactKind, ...] = Field(default_factory=tuple, max_length=9)
    campaign_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=20)
    lead_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    lead_score: int | None = Field(default=None, ge=0, le=100)
    qualification: Qualification | None = None
    engagement_state_digest: Sha256Digest | None = None
    engagement_stage: EngagementStage | None = None
    quote_ref: OpaqueRef | None = None
    quote_total: Decimal | None = None
    agreement_ref: OpaqueRef | None = None
    custody_candidate_digest: Sha256Digest | None = None
    delivery_mode: DeliveryMode | None = None
    builder_ref: OpaqueRef | None = None
    work_packet_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    software_production_handle_digest: Sha256Digest | None = None
    software_production_status: ShortText | None = None
    customer_acceptance_ref: OpaqueRef | None = None
    evaluator_ref: OpaqueRef | None = None
    acceptance_state: AcceptanceState | None = None
    accepted_amount: Decimal | None = None
    invoice_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    invoice_kind: InvoiceKind | None = None
    invoiced_amount: Decimal | None = None
    payment_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    collected_amount: Decimal | None = None
    support_case_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    renewal_decision: RenewalDecision | None = None
    renewal_offer_ref: OpaqueRef | None = None
    delivered_cost: Decimal | None = None
    delivery_quality_score: int | None = Field(default=None, ge=0, le=100)
    customer_satisfaction: int | None = Field(default=None, ge=0, le=10)

    @field_validator("quote_total", "accepted_amount", "invoiced_amount", "collected_amount", "delivered_cost", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Any:
        if value is None:
            return None
        parsed = _decimal(value, field_name=str(info.field_name))
        if parsed < 0:
            raise ValueError(f"{info.field_name} cannot be negative")
        return parsed


class ServiceBusinessCycleCommand(_StrictModel):
    schema_id: Literal["lightbulb.service_business_cycle_command.v1"] = Field(default=CYCLE_COMMAND_SCHEMA, alias="schema")
    event: CycleEvent
    stage: LoopStage | None = None
    transition_ref: OpaqueRef
    idempotency_key: OpaqueRef
    expected_version: int = Field(ge=0, le=MAX_CYCLE_TRANSITIONS)
    expected_state_digest: Sha256Digest
    occurred_at: str
    actor_ref: OpaqueRef
    receipt: StageReceipt | None = None
    reason: BoundedText | None = None
    request_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("occurred_at")
    @classmethod
    def _occurred(cls, value: str) -> str:
        return _timestamp(value, field_name="occurred_at")

    @model_validator(mode="after")
    def _command_is_exact(self, info: ValidationInfo) -> "ServiceBusinessCycleCommand":
        if (self.event == "complete_stage") != (self.stage is not None):
            raise ValueError("complete_stage names a stage; disqualify and cancel do not")
        if self.event != "complete_stage" and self.reason is None:
            raise ValueError("disqualify and cancel require a reason")
        if self.event == "complete_stage" and self.receipt is None:
            raise ValueError("completing a stage requires a stage receipt")
        if _skip(info):
            return self
        if self.request_digest != cycle_command_digest(self):
            raise ValueError("request_digest must commit the exact normalized command")
        return self


def cycle_command_digest(command: ServiceBusinessCycleCommand | Mapping[str, Any]) -> str:
    return _sealed_digest(ServiceBusinessCycleCommand, command, "request_digest")


def seal_cycle_command(command: Mapping[str, Any]) -> dict[str, Any]:
    raw = dict(_detached(command))
    raw["request_digest"] = cycle_command_digest(raw)
    return ServiceBusinessCycleCommand.model_validate(raw).to_dict()


# --------------------------------------------------------------------------- #
# Cycle state
# --------------------------------------------------------------------------- #


class CycleLedger(_StrictModel):
    quote_total: Decimal = Field(default=Decimal("0"), validate_default=True)
    accepted_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    invoiced_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    collected_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    delivered_cost: Decimal = Field(default=Decimal("0"), validate_default=True)
    lead_score: int | None = Field(default=None, ge=0, le=100)
    builder_ref: OpaqueRef | None = None
    evaluator_ref: OpaqueRef | None = None
    customer_acceptance_ref: OpaqueRef | None = None
    acceptance_state: AcceptanceState | None = None
    renewal_decision: RenewalDecision | None = None
    delivery_quality_score: int | None = Field(default=None, ge=0, le=100)
    customer_satisfaction: int | None = Field(default=None, ge=0, le=10)
    engagement_state_digest: Sha256Digest | None = None
    engagement_stage: EngagementStage | None = None
    artifact_kinds: tuple[LoopArtifactKind, ...] = Field(default_factory=tuple, max_length=9)
    invoice_kinds: tuple[InvoiceKind, ...] = Field(default_factory=tuple, max_length=50)
    work_packet_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)

    @field_validator("quote_total", "accepted_amount", "invoiced_amount", "collected_amount", "delivered_cost", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Any:
        return _decimal(value, field_name=str(info.field_name))


class CycleTransition(_StrictModel):
    to_version: int = Field(ge=1, le=MAX_CYCLE_TRANSITIONS)
    prior_state_digest: Sha256Digest
    to_status: CycleStatus
    transition_digest: Sha256Digest
    command: ServiceBusinessCycleCommand

    @model_validator(mode="after")
    def _self_proving(self) -> "CycleTransition":
        if self.command.expected_version != self.to_version - 1 or self.command.expected_state_digest != self.prior_state_digest:
            raise ValueError("transition must match the command's revision and state fences")
        if self.transition_digest != _transition_digest(self.to_version, self.prior_state_digest, self.to_status, self.command):
            raise ValueError("transition digest must commit the exact transition")
        return self


def _transition_digest(to_version: int, prior: str, to_status: str, command: ServiceBusinessCycleCommand) -> str:
    return _stable_digest({"to_version": to_version, "prior_state_digest": prior, "to_status": to_status, "request_digest": command.request_digest, "transition_ref": command.transition_ref, "idempotency_key": command.idempotency_key})


def _state_digest(plan_digest: str, scope: ServiceBusinessScope, history: Sequence[CycleTransition]) -> str:
    return _stable_digest({"plan_digest": plan_digest, "scope": scope.to_dict(), "transitions": [item.transition_digest for item in history]})


def genesis_cycle_state_digest(plan_digest: str, scope: ServiceBusinessScope | Mapping[str, Any]) -> str:
    return _state_digest(plan_digest, ServiceBusinessScope.model_validate(_detached(scope)), ())


class _Rejected(ValueError):
    def __init__(self, code: str, instructions: str, recovery: RecoveryDisposition) -> None:
        super().__init__(instructions)
        self.code, self.instructions, self.recovery = code, instructions, recovery


def _apply(plan: ServiceBusinessLoopPlan, status: str, ledger: CycleLedger, command: ServiceBusinessCycleCommand) -> tuple[str, CycleLedger]:
    if status in TERMINAL_CYCLE_STATUSES:
        raise _Rejected("CYCLE_TERMINAL", f"cycle is {status}; no further transitions", "do_not_replay")
    if command.event == "cancel":
        return "cancelled", ledger
    if command.event == "disqualify":
        if status not in _PRE_AGREEMENT_STATUSES:
            raise _Rejected("DISQUALIFY_AFTER_AGREEMENT", "a lead cannot be disqualified once an agreement is executed; cancel instead", "correct_input")
        return "disqualified", ledger
    stage = str(command.stage)
    if STATUS_BEFORE_STAGE[stage] != status:
        raise _Rejected("ILLEGAL_TRANSITION", f"{stage} is not the next stage after {status}", "correct_input")
    receipt = command.receipt
    assert receipt is not None
    data = ledger.to_dict()
    blueprint = plan.blueprint
    binding = plan.stage(stage)
    missing_artifacts = [kind for kind in binding.required_artifacts if kind not in receipt.artifact_kinds and kind not in ledger.artifact_kinds]
    if missing_artifacts:
        raise _Rejected("ARTIFACT_MISSING", f"{stage} requires generated artifacts: {', '.join(missing_artifacts)}", "correct_input")
    if len(receipt.artifact_kinds) != len(receipt.artifact_refs):
        raise _Rejected("ARTIFACT_REFS_MISMATCH", "each artifact kind needs its artifact reference", "correct_input")
    expected_engagement = _ENGAGEMENT_STAGES_BY_LOOP_STAGE.get(stage)
    if expected_engagement is not None:
        if receipt.engagement_stage is None or receipt.engagement_state_digest is None:
            raise _Rejected("ENGAGEMENT_LINK_MISSING", f"{stage} must link the engagement snapshot digest and stage", "correct_input")
        if receipt.engagement_stage not in expected_engagement:
            raise _Rejected("ENGAGEMENT_STAGE_MISMATCH", f"{stage} expects the engagement at {', '.join(sorted(expected_engagement))}, not {receipt.engagement_stage}", "correct_input")
        data["engagement_state_digest"], data["engagement_stage"] = receipt.engagement_state_digest, receipt.engagement_stage
    if stage == "market":
        if not receipt.campaign_refs and not receipt.lead_refs:
            raise _Rejected("DEMAND_EVIDENCE_MISSING", "market completion links campaigns or leads", "correct_input")
    elif stage == "qualify":
        if receipt.qualification is None or receipt.lead_score is None:
            raise _Rejected("QUALIFICATION_MISSING", "qualify completion links the crm.qualify_lead outcome (qualification and score)", "correct_input")
        if receipt.qualification != "qualified" or receipt.lead_score < blueprint.qualification_threshold:
            raise _Rejected("LEAD_NOT_QUALIFIED", f"lead is {receipt.qualification} with score {receipt.lead_score} (threshold {blueprint.qualification_threshold}); disqualify or research further", "correct_input")
        data["lead_score"] = receipt.lead_score
    elif stage == "quote":
        if receipt.quote_ref is None or receipt.quote_total is None or receipt.quote_total <= 0:
            raise _Rejected("QUOTE_MISSING", "quote completion links the quote reference and a positive total", "correct_input")
        data["quote_total"] = str(receipt.quote_total)
    elif stage == "agreement":
        if receipt.agreement_ref is None or receipt.custody_candidate_digest is None:
            raise _Rejected("AGREEMENT_CUSTODY_MISSING", "agreement completion links the executed agreement and its custody candidate digest", "correct_input")
        if receipt.invoice_kind is not None or receipt.invoiced_amount is not None:
            if receipt.invoice_kind != "deposit" or blueprint.invoice_schedule.deposit_percent <= 0 or not receipt.invoice_refs or not receipt.invoiced_amount:
                raise _Rejected("DEPOSIT_NOT_IN_SCHEDULE", "only a deposit invoice may accompany the agreement, and only when the schedule takes a deposit", "correct_input")
            maximum = (Decimal(data["quote_total"]) * blueprint.invoice_schedule.deposit_percent / Decimal(100)).quantize(Decimal("0.01"))
            if receipt.invoiced_amount > maximum:
                raise _Rejected("DEPOSIT_EXCEEDS_SCHEDULE", f"deposit {receipt.invoiced_amount} exceeds {blueprint.invoice_schedule.deposit_percent}% of the quote ({maximum})", "correct_input")
            data["invoiced_amount"] = str(Decimal(data["invoiced_amount"]) + receipt.invoiced_amount)
            data["invoice_kinds"] = [*data.get("invoice_kinds", []), "deposit"]
    elif stage == "deliver":
        if receipt.delivery_mode != blueprint.delivery_mode:
            raise _Rejected("DELIVERY_MODE_MISMATCH", f"blueprint delivers by {blueprint.delivery_mode}, receipt says {receipt.delivery_mode}", "correct_input")
        mode = blueprint.delivery_mode
        if mode == "software_delivery_harness":
            if receipt.builder_ref is None or receipt.software_production_handle_digest is None or receipt.software_production_status is None:
                raise _Rejected("SOFTWARE_PRODUCTION_LINK_MISSING", "software delivery links the harness builder binding and the software-production run handle digest and status", "correct_input")
        elif mode in {"field_service", "consultant_deliverable"}:
            if not receipt.work_packet_refs:
                raise _Rejected("WORK_PACKET_MISSING", f"{mode} delivery links at least one work packet", "correct_input")
        elif mode == "automated_digital":
            if not receipt.artifact_refs:
                raise _Rejected("DIGITAL_ARTIFACT_MISSING", "automated digital delivery links the generated artifacts", "correct_input")
        elif not receipt.evidence_refs:
            raise _Rejected("DELIVERY_EVIDENCE_MISSING", "customer-performed delivery links completion evidence", "correct_input")
        if receipt.builder_ref is not None:
            data["builder_ref"] = receipt.builder_ref
        data["work_packet_refs"] = list(receipt.work_packet_refs)
    elif stage == "verify_acceptance":
        if receipt.acceptance_state not in {"accepted", "accepted_partial"} or receipt.accepted_amount is None or receipt.accepted_amount <= 0:
            raise _Rejected("ACCEPTANCE_NOT_ASSERTED", "acceptance completion carries an accepted state and a positive accepted amount", "correct_input")
        policy = blueprint.acceptance_policy
        if policy in {"customer_approval", "customer_and_independent_evaluator"} and receipt.customer_acceptance_ref is None:
            raise _Rejected("CUSTOMER_ACCEPTANCE_MISSING", "the acceptance policy requires the customer's acceptance reference", "correct_input")
        if policy in {"independent_evaluator", "customer_and_independent_evaluator"}:
            if receipt.evaluator_ref is None:
                raise _Rejected("EVALUATOR_MISSING", "the acceptance policy requires an independent evaluator reference", "correct_input")
            if ledger.builder_ref is not None and receipt.evaluator_ref == ledger.builder_ref:
                raise _Rejected("BUILDER_SELF_ACCEPTANCE", "the binding that built the work cannot accept it", "correct_input")
            if blueprint.delivery_mode == "software_delivery_harness" and receipt.software_production_status != "production_verified":
                raise _Rejected("SOFTWARE_NOT_VERIFIED", "software acceptance requires the software-production run to be production_verified", "correct_input")
        if Decimal(data["quote_total"]) > 0 and receipt.accepted_amount > Decimal(data["quote_total"]):
            raise _Rejected("ACCEPTED_EXCEEDS_QUOTE", "accepted value cannot exceed the quoted total without a change order", "correct_input")
        data.update({"accepted_amount": str(receipt.accepted_amount), "acceptance_state": receipt.acceptance_state, "customer_acceptance_ref": receipt.customer_acceptance_ref, "evaluator_ref": receipt.evaluator_ref})
    elif stage == "invoice":
        if not receipt.invoice_refs or receipt.invoice_kind is None or receipt.invoiced_amount is None or receipt.invoiced_amount <= 0:
            raise _Rejected("INVOICE_MISSING", "invoice completion links issued invoices, their kind, and a positive amount", "correct_input")
        if receipt.invoice_kind not in _INVOICE_KINDS_BY_SCHEDULE[blueprint.invoice_schedule.kind] or receipt.invoice_kind == "deposit":
            raise _Rejected("INVOICE_KIND_NOT_IN_SCHEDULE", f"{receipt.invoice_kind} invoices are not part of the {blueprint.invoice_schedule.kind} schedule at this stage", "correct_input")
        total = Decimal(data["invoiced_amount"]) + receipt.invoiced_amount
        if total > Decimal(data["accepted_amount"]):
            raise _Rejected("INVOICE_EXCEEDS_ACCEPTED", f"cumulative invoices {total} exceed accepted value {data['accepted_amount']}", "correct_input")
        data["invoiced_amount"] = str(total)
        data["invoice_kinds"] = [*data.get("invoice_kinds", []), receipt.invoice_kind]
    elif stage == "collect":
        if not receipt.payment_refs or receipt.collected_amount is None or receipt.collected_amount <= 0:
            raise _Rejected("PAYMENT_MISSING", "collect completion links payments and a positive collected amount", "correct_input")
        total = Decimal(data["collected_amount"]) + receipt.collected_amount
        if total > Decimal(data["invoiced_amount"]):
            raise _Rejected("COLLECTED_EXCEEDS_INVOICED", f"collected {total} exceeds invoiced {data['invoiced_amount']}", "correct_input")
        data["collected_amount"] = str(total)
    elif stage == "support_renew":
        if receipt.renewal_decision is None:
            raise _Rejected("RENEWAL_DECISION_MISSING", "support/renew completion records the renewal decision", "correct_input")
        allowed = {"none": {"not_offered"}, "offer_renewal": {"renewed", "declined", "pending"}, "auto_renew_with_notice": {"renewed", "declined"}}[blueprint.renewal_policy]
        if receipt.renewal_decision not in allowed:
            raise _Rejected("RENEWAL_OUTSIDE_POLICY", f"renewal policy {blueprint.renewal_policy} allows {', '.join(sorted(allowed))}", "correct_input")
        if receipt.renewal_decision == "renewed" and receipt.renewal_offer_ref is None:
            raise _Rejected("RENEWAL_OFFER_MISSING", "a renewal links the renewal offer or change order reference", "correct_input")
        data["renewal_decision"] = receipt.renewal_decision
        if receipt.customer_satisfaction is not None:
            data["customer_satisfaction"] = receipt.customer_satisfaction
    elif stage == "learn":
        if receipt.delivered_cost is None or receipt.delivery_quality_score is None:
            raise _Rejected("LEARNING_INPUTS_MISSING", "learn completion records delivered cost and the delivery quality score", "correct_input")
        data["delivered_cost"], data["delivery_quality_score"] = str(receipt.delivered_cost), receipt.delivery_quality_score
        if receipt.customer_satisfaction is not None:
            data["customer_satisfaction"] = receipt.customer_satisfaction
    if receipt.artifact_kinds:
        data["artifact_kinds"] = sorted(set(data.get("artifact_kinds", [])) | set(receipt.artifact_kinds))
    return STATUS_AFTER_STAGE[stage], CycleLedger.model_validate(data)


class ServiceBusinessCycleState(_StrictModel):
    schema_id: Literal["lightbulb.service_business_cycle_state.v1"] = Field(default=CYCLE_STATE_SCHEMA, alias="schema")
    plan_digest: Sha256Digest
    scope: ServiceBusinessScope
    status: CycleStatus
    version: int = Field(ge=1, le=MAX_CYCLE_TRANSITIONS)
    transition_history: tuple[CycleTransition, ...] = Field(min_length=1, max_length=MAX_CYCLE_TRANSITIONS)
    ledger: CycleLedger
    state_digest: Sha256Digest

    @model_validator(mode="after")
    def _state_is_exact(self, info: ValidationInfo) -> "ServiceBusinessCycleState":
        history = self.transition_history
        if self.version != len(history) or [item.to_version for item in history] != list(range(1, self.version + 1)):
            raise ValueError("cycle version must equal a contiguous transition history")
        for field_name in ("transition_ref", "idempotency_key", "request_digest"):
            values = [str(getattr(item.command, field_name)) for item in history]
            if len(values) != len(set(values)):
                raise ValueError(f"historical {field_name} values must be unique")
        prefix: tuple[CycleTransition, ...] = ()
        for index, transition in enumerate(history):
            if transition.prior_state_digest != _state_digest(self.plan_digest, self.scope, prefix):
                raise ValueError("historical transition has a discontinuous state digest")
            if index == 0 and (transition.command.event != "complete_stage" or transition.command.stage != "market" and transition.command.stage != "qualify"):
                pass
            prefix = (*prefix, transition)
        if self.state_digest != _state_digest(self.plan_digest, self.scope, history):
            raise ValueError("state_digest must commit the exact cycle state")
        plan: ServiceBusinessLoopPlan | None = (info.context or {}).get("service_business_plan")
        if plan is not None:
            status, ledger = "opened", CycleLedger()
            for transition in history:
                try:
                    status, ledger = _apply(plan, status, ledger, transition.command)
                except _Rejected as exc:
                    raise ValueError(f"historical transition {transition.to_version} is invalid: {exc.code}") from exc
                if status != transition.to_status:
                    raise ValueError("historical transition status does not match the loop table")
            if self.status != status or self.ledger != ledger:
                raise ValueError("cycle status and ledger must be derived from history")
        return self


class CycleRecovery(_StrictModel):
    disposition: RecoveryDisposition
    automatic_retry_allowed: Literal[False] = False
    instructions: BoundedText | None = None

    @model_validator(mode="after")
    def _bounded(self) -> "CycleRecovery":
        if (self.disposition == "not_required") != (self.instructions is None):
            raise ValueError("recovery instructions must match the disposition")
        return self


class CycleTransitionReceipt(_StrictModel):
    transition_ref: OpaqueRef
    idempotency_key: OpaqueRef
    request_digest: Sha256Digest
    event: CycleEvent
    stage: LoopStage | None = None
    status: Literal["candidate_materialized", "rejected"]
    from_version: int = Field(ge=0)
    to_version: int = Field(ge=0)
    from_status: CycleStatus
    to_status: CycleStatus
    from_state_digest: Sha256Digest
    to_state_digest: Sha256Digest
    rejection_code: str | None = Field(default=None, min_length=1, max_length=120)
    recovery: CycleRecovery


class CycleEffectBoundary(_StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    connector_effect_executed: Literal[False] = False
    invoice_issued: Literal[False] = False
    payment_recorded: Literal[False] = False


class CycleTransitionResult(_StrictModel):
    schema_id: Literal["lightbulb.service_business_cycle_transition_result.v1"] = Field(default=CYCLE_RESULT_SCHEMA, alias="schema")
    candidate_validated: bool
    state: ServiceBusinessCycleState | None = None
    receipt: CycleTransitionReceipt
    effect_boundary: CycleEffectBoundary = Field(default_factory=CycleEffectBoundary)

    @model_validator(mode="after")
    def _coherent(self) -> "CycleTransitionResult":
        if self.candidate_validated != (self.receipt.status == "candidate_materialized") or (self.candidate_validated and self.state is None):
            raise ValueError("result must carry a state exactly when a candidate was materialized")
        return self


def _validate_plan_state(plan: ServiceBusinessLoopPlan | Mapping[str, Any], state: ServiceBusinessCycleState | Mapping[str, Any]) -> tuple[ServiceBusinessLoopPlan, ServiceBusinessCycleState]:
    parsed_plan = ServiceBusinessLoopPlan.model_validate(_detached(plan))
    unbound = ServiceBusinessCycleState.model_validate(_detached(state))
    if unbound.plan_digest != parsed_plan.plan_digest:
        raise ValueError("cycle state belongs to a different loop plan")
    parsed_state = ServiceBusinessCycleState.model_validate(unbound.to_dict(), context={"service_business_plan": parsed_plan})
    return parsed_plan, parsed_state


def open_service_business_cycle(plan: ServiceBusinessLoopPlan | Mapping[str, Any], scope: ServiceBusinessScope | Mapping[str, Any], *, opened_at: str, actor_ref: str, campaign_refs: Sequence[str] = (), lead_refs: Sequence[str] = ()) -> ServiceBusinessCycleState:
    """Open a cycle by completing the market stage with the demand evidence that started it."""

    parsed_plan = ServiceBusinessLoopPlan.model_validate(_detached(plan))
    parsed_scope = ServiceBusinessScope.model_validate(_detached(scope))
    if parsed_scope.currency != parsed_plan.blueprint.currency:
        raise ValueError("cycle currency must match the blueprint currency")
    genesis = _state_digest(parsed_plan.plan_digest, parsed_scope, ())
    command = ServiceBusinessCycleCommand.model_validate(seal_cycle_command({"event": "complete_stage", "stage": "market", "transition_ref": f"market:{parsed_scope.cycle_ref}", "idempotency_key": f"{parsed_scope.cycle_ref}:market", "expected_version": 0, "expected_state_digest": genesis, "occurred_at": opened_at, "actor_ref": actor_ref, "receipt": {"campaign_refs": list(campaign_refs), "lead_refs": list(lead_refs)}}))
    status, ledger = _apply(parsed_plan, "opened", CycleLedger(), command)
    transition = CycleTransition(to_version=1, prior_state_digest=genesis, to_status=status, transition_digest=_transition_digest(1, genesis, status, command), command=command)
    return ServiceBusinessCycleState.model_validate({"plan_digest": parsed_plan.plan_digest, "scope": parsed_scope.to_dict(), "status": status, "version": 1, "transition_history": [transition.to_dict()], "ledger": ledger.to_dict(), "state_digest": _state_digest(parsed_plan.plan_digest, parsed_scope, (transition,))}, context={"service_business_plan": parsed_plan})


def advance_service_business_cycle(plan: ServiceBusinessLoopPlan | Mapping[str, Any], state: ServiceBusinessCycleState | Mapping[str, Any], command: ServiceBusinessCycleCommand | Mapping[str, Any]) -> CycleTransitionResult:
    """Materialize one replay-fenced cycle transition; never persists, never issues an invoice or payment."""

    parsed_plan, parsed_state = _validate_plan_state(plan, state)
    parsed_command = ServiceBusinessCycleCommand.model_validate(_detached(command))
    from_version, from_status, from_digest = parsed_state.version, parsed_state.status, parsed_state.state_digest

    def rejected(exc: _Rejected) -> CycleTransitionResult:
        receipt = CycleTransitionReceipt(transition_ref=parsed_command.transition_ref, idempotency_key=parsed_command.idempotency_key, request_digest=parsed_command.request_digest, event=parsed_command.event, stage=parsed_command.stage, status="rejected", from_version=from_version, to_version=from_version, from_status=from_status, to_status=from_status, from_state_digest=from_digest, to_state_digest=from_digest, rejection_code=exc.code, recovery=CycleRecovery(disposition=exc.recovery, instructions=exc.instructions))
        return CycleTransitionResult(candidate_validated=False, receipt=receipt)

    try:
        for prior in parsed_state.transition_history:
            if prior.command.request_digest == parsed_command.request_digest:
                raise _Rejected("TRANSITION_ALREADY_APPLIED", "this exact transition is already retained; duplicate delivery ignored", "do_not_replay")
            if prior.command.transition_ref == parsed_command.transition_ref or prior.command.idempotency_key == parsed_command.idempotency_key:
                raise _Rejected("IDEMPOTENCY_CONFLICT", "a different transition already used this reference or idempotency key", "manual_reconciliation")
        if parsed_command.expected_version != from_version or parsed_command.expected_state_digest != from_digest:
            raise _Rejected("STALE_STATE", "revision or state fence does not match; refresh and retry with the current state", "refresh_state")
        if _parsed_timestamp(parsed_command.occurred_at) < _parsed_timestamp(parsed_state.transition_history[-1].command.occurred_at):
            raise _Rejected("NON_CHRONOLOGICAL_TRANSITION", "transition precedes the last retained transition", "correct_input")
        if from_version >= MAX_CYCLE_TRANSITIONS:
            raise _Rejected("TRANSITION_BOUND_REACHED", "the cycle reached its bounded transition count", "manual_reconciliation")
        next_status, ledger = _apply(parsed_plan, from_status, parsed_state.ledger, parsed_command)
    except _Rejected as exc:
        return rejected(exc)
    transition = CycleTransition(to_version=from_version + 1, prior_state_digest=from_digest, to_status=next_status, transition_digest=_transition_digest(from_version + 1, from_digest, next_status, parsed_command), command=parsed_command)
    history = (*parsed_state.transition_history, transition)
    new_state = ServiceBusinessCycleState.model_validate({"plan_digest": parsed_state.plan_digest, "scope": parsed_state.scope.to_dict(), "status": next_status, "version": from_version + 1, "transition_history": [item.to_dict() for item in history], "ledger": ledger.to_dict(), "state_digest": _state_digest(parsed_state.plan_digest, parsed_state.scope, history)}, context={"service_business_plan": parsed_plan})
    receipt = CycleTransitionReceipt(transition_ref=parsed_command.transition_ref, idempotency_key=parsed_command.idempotency_key, request_digest=parsed_command.request_digest, event=parsed_command.event, stage=parsed_command.stage, status="candidate_materialized", from_version=from_version, to_version=new_state.version, from_status=from_status, to_status=next_status, from_state_digest=from_digest, to_state_digest=new_state.state_digest, recovery=CycleRecovery(disposition="not_required"))
    return CycleTransitionResult(candidate_validated=True, state=new_state, receipt=receipt)


def verify_engagement_link(state: ServiceBusinessCycleState | Mapping[str, Any], snapshot: ServiceEngagementSnapshot | Mapping[str, Any]) -> bool:
    """True when the retained engagement link matches the supplied engagement snapshot exactly."""

    parsed_state = ServiceBusinessCycleState.model_validate(_detached(state))
    parsed = ServiceEngagementSnapshot.model_validate(_detached(snapshot))
    return parsed_state.ledger.engagement_state_digest == parsed.state_digest and parsed_state.ledger.engagement_stage == parsed.stage and parsed_state.scope.customer_ref == parsed.scope.customer_ref


# --------------------------------------------------------------------------- #
# Assessment (the Learn stage)
# --------------------------------------------------------------------------- #


class ServiceBusinessCycleAssessment(_StrictModel):
    schema_id: Literal["lightbulb.service_business_cycle_assessment.v1"] = Field(default=CYCLE_ASSESSMENT_SCHEMA, alias="schema")
    golden_loop: Literal["service.market_to_renewal_business@0.1.0"] = SERVICE_BUSINESS_GOLDEN_LOOP
    profile: BlueprintProfile
    cycle_ref: OpaqueRef
    status: CycleStatus
    version: int = Field(ge=1)
    stages_completed: tuple[LoopStage, ...] = Field(default_factory=tuple, max_length=10)
    next_stage: LoopStage | None = None
    quote_total: Decimal
    accepted_amount: Decimal
    invoiced_amount: Decimal
    collected_amount: Decimal
    delivered_cost: Decimal
    outstanding_receivable: Decimal
    uninvoiced_accepted_value: Decimal
    gross_margin_percent: Decimal | None = None
    margin_versus_target_points: Decimal | None = None
    delivery_quality_score: int | None = Field(default=None, ge=0, le=100)
    customer_satisfaction: int | None = Field(default=None, ge=0, le=10)
    renewal_decision: RenewalDecision | None = None
    acceptance_independent: bool
    learnings: tuple[BoundedText, ...] = Field(default_factory=tuple, max_length=20)
    next_cycle_recommendations: tuple[BoundedText, ...] = Field(default_factory=tuple, max_length=20)
    effect_boundary: CycleEffectBoundary = Field(default_factory=CycleEffectBoundary)
    assessed_at: str
    assessment_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("quote_total", "accepted_amount", "invoiced_amount", "collected_amount", "delivered_cost", "outstanding_receivable", "uninvoiced_accepted_value", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Any:
        return None if value is None else _decimal(value, field_name=str(info.field_name))

    @field_validator("gross_margin_percent", "margin_versus_target_points", mode="before")
    @classmethod
    def _signed(cls, value: Any, info: ValidationInfo) -> Any:
        if value is None:
            return None
        if isinstance(value, bool) or isinstance(value, float):
            raise ValueError(f"{info.field_name} must be a decimal string or Decimal")
        try:
            parsed = Decimal(str(value))
        except Exception as exc:  # noqa: BLE001
            raise ValueError(f"{info.field_name} must be a decimal") from exc
        if not parsed.is_finite() or abs(parsed) > Decimal("100000"):
            raise ValueError(f"{info.field_name} must be a finite bounded decimal")
        return parsed.quantize(Decimal("0.01"))

    @field_validator("assessed_at")
    @classmethod
    def _assessed(cls, value: str) -> str:
        return _timestamp(value, field_name="assessed_at")

    @model_validator(mode="after")
    def _assessment_is_exact(self, info: ValidationInfo) -> "ServiceBusinessCycleAssessment":
        if _skip(info):
            return self
        if self.assessment_digest != _sealed_digest(ServiceBusinessCycleAssessment, self, "assessment_digest"):
            raise ValueError("assessment_digest must commit the exact assessment")
        return self


def assess_service_business_cycle(plan: ServiceBusinessLoopPlan | Mapping[str, Any], state: ServiceBusinessCycleState | Mapping[str, Any], *, assessed_at: str) -> ServiceBusinessCycleAssessment:
    """Effect-dark learn-stage assessment: delivery quality, margin against the blueprint target, cash position, renewal, and next-cycle candidates."""

    parsed_plan, parsed_state = _validate_plan_state(plan, state)
    ledger = parsed_state.ledger
    blueprint = parsed_plan.blueprint
    completed = tuple(str(item.command.stage) for item in parsed_state.transition_history if item.command.event == "complete_stage")
    next_stage = None if parsed_state.status in TERMINAL_CYCLE_STATUSES else STAGE_ORDER[len(completed)]
    quantum = Decimal("0.01")
    outstanding = (ledger.invoiced_amount - ledger.collected_amount).quantize(quantum)
    uninvoiced = max(ledger.accepted_amount - ledger.invoiced_amount, Decimal("0")).quantize(quantum)
    margin: Decimal | None = None
    margin_gap: Decimal | None = None
    if "learn" in completed and ledger.accepted_amount > 0:
        margin = ((ledger.accepted_amount - ledger.delivered_cost) / ledger.accepted_amount * Decimal(100)).quantize(quantum)
        margin_gap = (margin - blueprint.target_gross_margin_percent).quantize(quantum)
    learnings: list[str] = []
    recommendations: list[str] = []
    if parsed_state.status == "disqualified":
        learnings.append("lead disqualified before agreement; qualification threshold held")
        recommendations.append("review marketing channel fit for the disqualified lead source")
    if ledger.acceptance_state == "accepted_partial":
        learnings.append("customer accepted part of the delivered value; scope or quality gap on the remainder")
        recommendations.append("tighten acceptance criteria at quote time and bind each deliverable to a work packet")
    if margin is not None and margin_gap is not None:
        if margin_gap < 0:
            learnings.append(f"gross margin {margin}% missed the {blueprint.target_gross_margin_percent.quantize(quantum)}% target by {abs(margin_gap)} points")
            recommendations.append("re-estimate delivery cost for this profile or raise the quote for comparable scope")
        else:
            learnings.append(f"gross margin {margin}% met the {blueprint.target_gross_margin_percent.quantize(quantum)}% target")
    if ledger.delivery_quality_score is not None and ledger.delivery_quality_score < 70:
        learnings.append(f"delivery quality {ledger.delivery_quality_score}/100 is below the 70 floor")
        recommendations.append("add an independent evaluator or a pre-acceptance review to the delivery stage")
    if outstanding > 0 and "collect" in completed:
        learnings.append(f"{outstanding} {blueprint.currency} remains outstanding after collection")
        recommendations.append("shorten net terms or raise the deposit percent for this profile")
    if ledger.renewal_decision == "renewed":
        learnings.append("customer renewed; delivery and pricing are working for this segment")
        recommendations.append("offer the same scope shape to comparable qualified leads")
    elif ledger.renewal_decision == "declined":
        learnings.append("customer declined renewal")
        recommendations.append("capture the decline reason through a support case before the next quote to this segment")
    if parsed_state.status == "completed" and not learnings:
        learnings.append("cycle completed within blueprint policy")
    payload = {
        "profile": blueprint.profile, "cycle_ref": parsed_state.scope.cycle_ref, "status": parsed_state.status, "version": parsed_state.version,
        "stages_completed": completed, "next_stage": next_stage,
        "quote_total": str(ledger.quote_total), "accepted_amount": str(ledger.accepted_amount), "invoiced_amount": str(ledger.invoiced_amount), "collected_amount": str(ledger.collected_amount), "delivered_cost": str(ledger.delivered_cost),
        "outstanding_receivable": str(outstanding), "uninvoiced_accepted_value": str(uninvoiced),
        "gross_margin_percent": None if margin is None else str(margin), "margin_versus_target_points": None if margin_gap is None else str(margin_gap),
        "delivery_quality_score": ledger.delivery_quality_score, "customer_satisfaction": ledger.customer_satisfaction, "renewal_decision": ledger.renewal_decision,
        "acceptance_independent": ledger.evaluator_ref is not None and ledger.evaluator_ref != ledger.builder_ref,
        "learnings": learnings, "next_cycle_recommendations": recommendations, "assessed_at": assessed_at,
    }
    payload["assessment_digest"] = _sealed_digest(ServiceBusinessCycleAssessment, payload, "assessment_digest")
    return ServiceBusinessCycleAssessment.model_validate(payload)


SERVICE_BUSINESS_ARCHETYPE_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_blueprint_archetype.v1",
    "archetype": SERVICE_BUSINESS_ARCHETYPE,
    "title": "Service business",
    "golden_loop": SERVICE_BUSINESS_GOLDEN_LOOP,
    "composed_golden_loops": [SERVICE_ENGAGEMENT_GOLDEN_LOOP, COMMERCIAL_LEGAL_HANDOFF_GOLDEN_LOOP, CONTRACT_OBLIGATION_GOLDEN_LOOP, CONTRACT_DELIVERY_GOLDEN_LOOP, BUSINESS_ARTIFACT_GOLDEN_LOOP, SOFTWARE_PRODUCTION_GOLDEN_LOOP_REF],
    "profiles": sorted(SERVICE_BUSINESS_PROFILES),
    "delivery_modes": list(DeliveryMode.__args__),  # type: ignore[attr-defined]
    "economic_spine": {"acquire_demand": "market", "create_offer": "quote", "agree_purchase": "agreement", "deliver_value": "deliver", "accept_value": "verify_acceptance", "monetize": "invoice+collect", "learn": "learn"},
    "composable_with": ["product_commerce", "subscription_business", "saas_product", "appointment_business", "marketplace_business"],
    "authority": "the agent chooses the offer and strategy; primitives define operations; this loop composes them; Spring authorizes effects; connectors execute; MCP projects both primitives and the loop",
}

__all__ = [
    "BLUEPRINT_SCHEMA",
    "CYCLE_ASSESSMENT_SCHEMA",
    "CYCLE_COMMAND_SCHEMA",
    "CYCLE_RESULT_SCHEMA",
    "CYCLE_STATE_SCHEMA",
    "MAX_CYCLE_TRANSITIONS",
    "PLAN_SCHEMA",
    "SERVICE_BUSINESS_ARCHETYPE",
    "SERVICE_BUSINESS_ARCHETYPE_MANIFEST",
    "SERVICE_BUSINESS_GOLDEN_LOOP",
    "SERVICE_BUSINESS_PROFILES",
    "SOFTWARE_PRODUCTION_GOLDEN_LOOP_REF",
    "STAGE_ORDER",
    "STATUS_AFTER_STAGE",
    "TERMINAL_CYCLE_STATUSES",
    "CycleEffectBoundary",
    "CycleLedger",
    "CycleRecovery",
    "CycleTransition",
    "CycleTransitionReceipt",
    "CycleTransitionResult",
    "InvoiceSchedule",
    "ServiceBusinessBlueprint",
    "ServiceBusinessCycleAssessment",
    "ServiceBusinessCycleCommand",
    "ServiceBusinessCycleState",
    "ServiceBusinessLoopPlan",
    "ServiceBusinessScope",
    "StageBinding",
    "StageReceipt",
    "advance_service_business_cycle",
    "assess_service_business_cycle",
    "compile_service_business_blueprint",
    "cycle_command_digest",
    "genesis_cycle_state_digest",
    "open_service_business_cycle",
    "seal_cycle_command",
    "seal_service_business_blueprint",
    "verify_engagement_link",
]
