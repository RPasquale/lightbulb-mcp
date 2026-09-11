"""Pipeline Engine Golden Operating Loop: ICP to qualified, booked pipeline.

The engine that lets a B2B business acquire clients itself under governance::

    Define ICP -> Source and enrich -> Plan sequences -> Compose touches
      -> Engage (approve, send) -> Observe engagement -> Qualify and book
      -> Forecast and learn

What is typed here: the pipeline blueprint (ICP criteria, outreach channel
policy with spacing and consent, sequence templates, approved claims,
suppression rules, the qualification rubric, meeting policy, CRM system,
targets), deterministic ICP fit scoring, a sealed sequence plan, a
replay-fenced per-prospect lifecycle whose touches obey the template, the
spacing, consent, suppression, and approved claims, engagement and reply
observation, rubric-scored qualification, meeting booking inside the
policy window, hand-off to the CRM deal, and a pipeline forecast against
targets.

Nothing here sends an email, a message, or a call, enrols anyone in a
provider sequence, books a calendar slot, or writes to a CRM.  Spring
authorizes those effects; the Connector Runtime executes them through the
``hubspot.*``, ``salesforce.*``, ``gmail.*``, ``linkedin.*``, ``twilio.*``,
``calendar.*``, ``apollo.*``, and ``clearbit.*`` tools.  Consent, do-not-contact
lists, approved claims, and human approvals are explicit inputs.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    MONEY_QUANTUM,
    BoundedText,
    CurrencyCode,
    EngineScope,
    LifecycleSpec,
    OpaqueRef,
    Sha256Digest,
    ShortText,
    StrictModel,
    add_days,
    decimal_value,
    detached,
    parsed,
    percent_value,
    ratio_percent,
    require,
    seal,
    sealed_digest,
    skip_digests,
    stable_digest,
    timestamp,
    unique,
)

PIPELINE_ENGINE_GOLDEN_LOOP = "revenue.icp_to_qualified_pipeline@0.1.0"
PIPELINE_ENGINE_KIND = "pipeline_engine"
BLUEPRINT_SCHEMA = "lightbulb.pipeline_engine_blueprint.v1"
PLAN_SCHEMA = "lightbulb.pipeline_engine_loop_plan.v1"
ICP_FIT_SCHEMA = "lightbulb.icp_fit_evaluation.v1"
SEQUENCE_PLAN_SCHEMA = "lightbulb.outreach_sequence_plan.v1"
FORECAST_SCHEMA = "lightbulb.pipeline_forecast.v1"
MAX_PROSPECT_TRANSITIONS = 200

OutreachChannel = Literal["email", "linkedin", "voice", "sms"]
OUTREACH_CHANNELS: tuple[str, ...] = ("email", "linkedin", "voice", "sms")
CONSENT_CHANNELS: frozenset[str] = frozenset({"voice", "sms"})
TouchIntent = Literal["introduce", "value", "proof", "ask", "breakup"]
ReplyDisposition = Literal["positive", "objection", "not_now", "negative", "out_of_office", "wrong_person"]
CrmSystem = Literal["hubspot", "salesforce"]
BlueprintProfile = Literal["b2b_saas_outbound", "agency_outbound", "enterprise_abm", "partner_channel", "custom"]
LoopStage = Literal["define_icp", "source_and_enrich", "plan_sequences", "compose_touches", "engage", "observe_engagement", "qualify_and_book", "forecast_and_learn"]
STAGE_ORDER: tuple[str, ...] = ("define_icp", "source_and_enrich", "plan_sequences", "compose_touches", "engage", "observe_engagement", "qualify_and_book", "forecast_and_learn")

ProspectStatus = Literal["sourced", "enriched", "sequenced", "engaged", "replied", "qualified", "disqualified", "meeting_booked", "handed_off", "lost", "suppressed"]
PROSPECT_STATUSES: tuple[str, ...] = ("sourced", "enriched", "sequenced", "engaged", "replied", "qualified", "disqualified", "meeting_booked", "handed_off", "lost", "suppressed")
TERMINAL_PROSPECT_STATUSES: frozenset[str] = frozenset({"handed_off", "lost", "suppressed", "disqualified"})
ProspectEvent = Literal["source", "enrich", "sequence", "touch", "observe", "reply", "qualify", "book_meeting", "hand_off", "lose", "suppress"]
PROSPECT_EVENTS: tuple[str, ...] = ("source", "enrich", "sequence", "touch", "observe", "reply", "qualify", "book_meeting", "hand_off", "lose", "suppress")
_PROSPECT_TABLE: dict[tuple[str, str], str] = {
    ("new", "source"): "sourced",
    ("sourced", "enrich"): "enriched",
    ("sourced", "suppress"): "suppressed",
    ("sourced", "lose"): "lost",
    ("enriched", "sequence"): "sequenced",
    ("enriched", "suppress"): "suppressed",
    ("enriched", "lose"): "lost",
    ("sequenced", "touch"): "engaged",
    ("sequenced", "suppress"): "suppressed",
    ("sequenced", "lose"): "lost",
    ("engaged", "touch"): "engaged",
    ("engaged", "observe"): "engaged",
    ("engaged", "reply"): "replied",
    ("engaged", "suppress"): "suppressed",
    ("engaged", "lose"): "lost",
    ("replied", "touch"): "engaged",
    ("replied", "qualify"): "qualified",
    ("replied", "suppress"): "suppressed",
    ("replied", "lose"): "lost",
    ("qualified", "book_meeting"): "meeting_booked",
    ("qualified", "lose"): "lost",
    ("qualified", "suppress"): "suppressed",
    ("meeting_booked", "hand_off"): "handed_off",
    ("meeting_booked", "lose"): "lost",
    ("meeting_booked", "book_meeting"): "meeting_booked",
}

_KNOWN_PRIMITIVE_REFS: frozenset[str] = frozenset(
    {
        "blueprint.compile_pipeline_engine", "pipeline.evaluate_icp_fit", "pipeline.plan_sequence", "pipeline.advance_prospect", "pipeline.forecast_pipeline",
        "crm.qualify_lead", "crm.orchestrate_profit_aware_lifecycle", "communication.write_email", "communication.plan_crm_conversation_turn", "communication.plan_governed_voice_call",
        "calendar.schedule_meeting", "demand_gen.plan_audience_growth", "growth.build_funnel_snapshot", "growth.review_customer_value", "learning.plan_optimization_sweep",
        "approval.request_decision", "compliance.evaluate_regulated_controls", "commercial.compile_legal_review_packet", "service.advance_business_cycle", "subscription.advance_account",
    }
)
_KNOWN_CONNECTOR_TOOLS: frozenset[str] = frozenset(
    {
        "hubspot.get_contact", "hubspot.create_contact", "hubspot.update_contact", "hubspot.create_deal", "hubspot.enroll_sequence", "hubspot.list_engagements", "hubspot.create_workflow",
        "salesforce.get_contact", "salesforce.create_lead", "salesforce.create_opportunity", "salesforce.list_activities",
        "apollo.search_people", "apollo.enrich_person", "clearbit.enrich_company",
        "gmail.send_email", "gmail.get_thread", "linkedin.send_message", "linkedin.get_profile", "twilio.send_sms_turn", "twilio.place_call_turn", "twilio.lookup_call_status",
        "calendar.get_availability", "calendar.create_event",
    }
)
_CHANNEL_TOOLS: dict[str, tuple[str, ...]] = {"email": ("gmail.send_email", "gmail.get_thread"), "linkedin": ("linkedin.send_message", "linkedin.get_profile"), "voice": ("twilio.place_call_turn", "twilio.lookup_call_status"), "sms": ("twilio.send_sms_turn",)}
_CRM_TOOLS: dict[str, tuple[str, ...]] = {"hubspot": ("hubspot.get_contact", "hubspot.create_contact", "hubspot.update_contact", "hubspot.create_deal", "hubspot.enroll_sequence", "hubspot.list_engagements"), "salesforce": ("salesforce.get_contact", "salesforce.create_lead", "salesforce.create_opportunity", "salesforce.list_activities")}


# --------------------------------------------------------------------------- #
# Blueprint and plan
# --------------------------------------------------------------------------- #


class IcpCriteria(StrictModel):
    industries: tuple[ShortText, ...] = Field(min_length=1, max_length=40)
    min_employees: int = Field(default=1, ge=1, le=1_000_000)
    max_employees: int = Field(default=1_000_000, ge=1, le=1_000_000)
    regions: tuple[ShortText, ...] = Field(min_length=1, max_length=40)
    buyer_titles: tuple[ShortText, ...] = Field(min_length=1, max_length=40)
    required_signals: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=20)
    disqualifiers: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=20)
    fit_threshold: int = Field(default=60, ge=1, le=100)

    @model_validator(mode="after")
    def _bands(self) -> "IcpCriteria":
        if self.max_employees < self.min_employees:
            raise ValueError("max_employees must be at least min_employees")
        return self


class OutreachChannelPolicy(StrictModel):
    channel: OutreachChannel
    max_touches: int = Field(default=4, ge=1, le=20)
    min_hours_between_touches: int = Field(default=48, ge=1, le=720)
    daily_cap: int = Field(default=100, ge=1, le=100000)
    requires_approval: bool = False
    enabled: bool = True


class SequenceStep(StrictModel):
    step: int = Field(ge=1, le=20)
    channel: OutreachChannel
    day_offset: int = Field(ge=0, le=180)
    intent: TouchIntent


class SequenceTemplate(StrictModel):
    sequence_ref: OpaqueRef
    name: ShortText
    steps: tuple[SequenceStep, ...] = Field(min_length=1, max_length=20)

    @model_validator(mode="after")
    def _ordered(self) -> "SequenceTemplate":
        if [item.step for item in self.steps] != list(range(1, len(self.steps) + 1)):
            raise ValueError(f"sequence {self.sequence_ref} steps must be numbered 1..n")
        offsets = [item.day_offset for item in self.steps]
        if offsets != sorted(offsets):
            raise ValueError(f"sequence {self.sequence_ref} day offsets must not decrease")
        if self.steps[-1].intent != "breakup" and len(self.steps) > 1:
            raise ValueError(f"sequence {self.sequence_ref} must end with a breakup touch")
        return self


class ApprovedClaim(StrictModel):
    claim_ref: OpaqueRef
    text: ShortText
    evidence_ref: OpaqueRef


class RubricDimension(StrictModel):
    dimension: Literal["need", "authority", "timing", "budget", "fit"]
    weight: int = Field(ge=1, le=100)


class PipelineEngineBlueprint(StrictModel):
    schema_id: Literal["lightbulb.pipeline_engine_blueprint.v1"] = Field(default=BLUEPRINT_SCHEMA, alias="schema")
    profile: BlueprintProfile
    name: ShortText
    icp: IcpCriteria
    channels: tuple[OutreachChannelPolicy, ...] = Field(min_length=1, max_length=4)
    sequences: tuple[SequenceTemplate, ...] = Field(min_length=1, max_length=20)
    approved_claims: tuple[ApprovedClaim, ...] = Field(default_factory=tuple, max_length=100)
    prohibited_terms: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=100)
    suppression_list_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=20)
    rubric: tuple[RubricDimension, ...] = Field(min_length=1, max_length=5)
    qualification_threshold: int = Field(default=65, ge=1, le=100)
    meeting_window_days: int = Field(default=14, ge=1, le=90)
    crm_system: CrmSystem = "hubspot"
    average_deal_value: Decimal = Field(default=Decimal("10000"), validate_default=True)
    target_reply_rate_percent: Decimal = Field(default=Decimal("8"), validate_default=True)
    target_meeting_rate_percent: Decimal = Field(default=Decimal("3"), validate_default=True)
    target_qualified_per_period: int = Field(default=10, ge=1, le=100000)
    currency: CurrencyCode = "USD"
    # False is an explicit compatibility/simulation policy, never evidence of
    # eligible outreach. New plans require the replayed permission register.
    require_permission_register: bool = True
    permission_company_ref: OpaqueRef | None = None
    notes: BoundedText | None = None
    blueprint_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("average_deal_value", mode="before")
    @classmethod
    def _deal(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="average_deal_value")

    @field_validator("target_reply_rate_percent", "target_meeting_rate_percent", mode="before")
    @classmethod
    def _rates(cls, value: Any, info: ValidationInfo) -> Decimal:
        return percent_value(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _blueprint_is_exact(self, info: ValidationInfo) -> "PipelineEngineBlueprint":
        unique([item.channel for item in self.channels], label="channels")
        unique([item.sequence_ref for item in self.sequences], label="sequence refs")
        unique([item.claim_ref for item in self.approved_claims], label="approved claim refs")
        unique([item.dimension for item in self.rubric], label="rubric dimensions")
        enabled = {item.channel for item in self.channels if item.enabled}
        if not enabled:
            raise ValueError("at least one outreach channel must be enabled")
        for sequence in self.sequences:
            unknown = sorted({step.channel for step in sequence.steps} - enabled)
            if unknown:
                raise ValueError(f"sequence {sequence.sequence_ref} uses channels that are not enabled: {unknown}")
            for channel in enabled:
                policy = self.channel(channel)
                count = sum(1 for step in sequence.steps if step.channel == channel)
                if policy is not None and count > policy.max_touches:
                    raise ValueError(f"sequence {sequence.sequence_ref} exceeds the {channel} touch limit")
        if sum(item.weight for item in self.rubric) != 100:
            raise ValueError("rubric weights must sum to 100")
        if skip_digests(info):
            return self
        if self.blueprint_digest != sealed_digest(PipelineEngineBlueprint, self, "blueprint_digest"):
            raise ValueError("blueprint_digest must commit the exact blueprint")
        return self

    def channel(self, name: str) -> OutreachChannelPolicy | None:
        return next((item for item in self.channels if item.channel == name), None)

    def sequence(self, ref: str) -> SequenceTemplate | None:
        return next((item for item in self.sequences if item.sequence_ref == ref), None)

    def claim(self, ref: str) -> ApprovedClaim | None:
        return next((item for item in self.approved_claims if item.claim_ref == ref), None)


def seal_pipeline_engine_blueprint(blueprint: Mapping[str, Any]) -> dict[str, Any]:
    raw = dict(detached(blueprint))
    raw["blueprint_digest"] = sealed_digest(PipelineEngineBlueprint, raw, "blueprint_digest")
    return PipelineEngineBlueprint.model_validate(raw).to_dict()


_RUBRIC = [{"dimension": "need", "weight": 30}, {"dimension": "authority", "weight": 25}, {"dimension": "timing", "weight": 20}, {"dimension": "budget", "weight": 15}, {"dimension": "fit", "weight": 10}]
_SEQ_EMAIL_LINKEDIN = {"sequence_ref": "seq-email-linkedin", "name": "Email and LinkedIn, 3 weeks", "steps": [{"step": 1, "channel": "email", "day_offset": 0, "intent": "introduce"}, {"step": 2, "channel": "linkedin", "day_offset": 2, "intent": "value"}, {"step": 3, "channel": "email", "day_offset": 5, "intent": "proof"}, {"step": 4, "channel": "email", "day_offset": 10, "intent": "ask"}, {"step": 5, "channel": "email", "day_offset": 18, "intent": "breakup"}]}
PIPELINE_ENGINE_PROFILES: dict[str, dict[str, Any]] = {
    "b2b_saas_outbound": {"profile": "b2b_saas_outbound", "name": "B2B SaaS outbound", "icp": {"industries": ["software", "fintech", "professional services"], "min_employees": 20, "max_employees": 2000, "regions": ["AU", "CA", "US", "UK"], "buyer_titles": ["Head of Operations", "COO", "VP Finance", "CFO"], "required_signals": ["hiring ops roles"], "disqualifiers": ["competitor", "public sector"], "fit_threshold": 60}, "channels": [{"channel": "email", "max_touches": 4, "min_hours_between_touches": 48, "daily_cap": 150}, {"channel": "linkedin", "max_touches": 2, "min_hours_between_touches": 72, "daily_cap": 40}, {"channel": "voice", "max_touches": 1, "min_hours_between_touches": 96, "daily_cap": 20, "requires_approval": True}], "sequences": [_SEQ_EMAIL_LINKEDIN], "approved_claims": [{"claim_ref": "claim-soc2", "text": "SOC 2 Type II certified", "evidence_ref": "audit:soc2-2026"}, {"claim_ref": "claim-30pct", "text": "customers close the books 30% faster", "evidence_ref": "case-study:acme"}], "prohibited_terms": ["guaranteed", "risk-free"], "suppression_list_refs": ["dnc-global"], "rubric": _RUBRIC, "qualification_threshold": 65, "meeting_window_days": 14, "crm_system": "hubspot", "average_deal_value": "18000", "target_reply_rate_percent": "8", "target_meeting_rate_percent": "3", "target_qualified_per_period": 12, "notes": "Voice needs approval; replies classified before qualification."},
    "agency_outbound": {"profile": "agency_outbound", "name": "Agency outbound", "icp": {"industries": ["ecommerce", "consumer brands", "hospitality"], "min_employees": 5, "max_employees": 500, "regions": ["AU", "CA"], "buyer_titles": ["Founder", "Marketing Director", "Head of Growth"], "required_signals": [], "disqualifiers": ["agency"], "fit_threshold": 55}, "channels": [{"channel": "email", "max_touches": 4, "min_hours_between_touches": 48, "daily_cap": 80}, {"channel": "linkedin", "max_touches": 3, "min_hours_between_touches": 48, "daily_cap": 40}], "sequences": [_SEQ_EMAIL_LINKEDIN], "approved_claims": [{"claim_ref": "claim-roas", "text": "average 4x ROAS across retained clients", "evidence_ref": "report:2026-q2"}], "prohibited_terms": ["guaranteed"], "suppression_list_refs": ["dnc-global"], "rubric": _RUBRIC, "qualification_threshold": 60, "meeting_window_days": 10, "crm_system": "hubspot", "average_deal_value": "6000", "target_reply_rate_percent": "10", "target_meeting_rate_percent": "4", "target_qualified_per_period": 8, "notes": "Founder-led buyers; short cycles."},
    "enterprise_abm": {"profile": "enterprise_abm", "name": "Enterprise account-based", "icp": {"industries": ["banking", "insurance", "healthcare"], "min_employees": 1000, "max_employees": 1000000, "regions": ["AU", "CA", "US"], "buyer_titles": ["CIO", "CDO", "VP Engineering", "Head of Data"], "required_signals": ["digital transformation budget", "cloud migration"], "disqualifiers": ["active RFP with incumbent"], "fit_threshold": 70}, "channels": [{"channel": "email", "max_touches": 5, "min_hours_between_touches": 72, "daily_cap": 30}, {"channel": "linkedin", "max_touches": 3, "min_hours_between_touches": 96, "daily_cap": 15}, {"channel": "voice", "max_touches": 2, "min_hours_between_touches": 120, "daily_cap": 10, "requires_approval": True}], "sequences": [{"sequence_ref": "seq-abm", "name": "Multi-thread ABM, 6 weeks", "steps": [{"step": 1, "channel": "linkedin", "day_offset": 0, "intent": "introduce"}, {"step": 2, "channel": "email", "day_offset": 3, "intent": "value"}, {"step": 3, "channel": "email", "day_offset": 10, "intent": "proof"}, {"step": 4, "channel": "voice", "day_offset": 17, "intent": "ask"}, {"step": 5, "channel": "email", "day_offset": 24, "intent": "ask"}, {"step": 6, "channel": "email", "day_offset": 40, "intent": "breakup"}]}], "approved_claims": [{"claim_ref": "claim-iso", "text": "ISO 27001 certified", "evidence_ref": "cert:iso27001"}], "prohibited_terms": ["guaranteed", "unlimited"], "suppression_list_refs": ["dnc-global", "dnc-enterprise"], "rubric": _RUBRIC, "qualification_threshold": 70, "meeting_window_days": 21, "crm_system": "salesforce", "average_deal_value": "250000", "target_reply_rate_percent": "5", "target_meeting_rate_percent": "2", "target_qualified_per_period": 4, "notes": "Salesforce; multiple threads per account."},
    "partner_channel": {"profile": "partner_channel", "name": "Partner and referral channel", "icp": {"industries": ["accounting", "consulting", "system integration"], "min_employees": 3, "max_employees": 5000, "regions": ["AU", "CA"], "buyer_titles": ["Partner", "Practice Lead", "Alliances Manager"], "required_signals": [], "disqualifiers": ["exclusive with competitor"], "fit_threshold": 50}, "channels": [{"channel": "email", "max_touches": 3, "min_hours_between_touches": 72, "daily_cap": 40}, {"channel": "linkedin", "max_touches": 2, "min_hours_between_touches": 72, "daily_cap": 20}], "sequences": [{"sequence_ref": "seq-partner", "name": "Partner intro", "steps": [{"step": 1, "channel": "email", "day_offset": 0, "intent": "introduce"}, {"step": 2, "channel": "linkedin", "day_offset": 4, "intent": "value"}, {"step": 3, "channel": "email", "day_offset": 12, "intent": "breakup"}]}], "approved_claims": [{"claim_ref": "claim-margin", "text": "20% referral margin", "evidence_ref": "partner-program:2026"}], "prohibited_terms": [], "suppression_list_refs": ["dnc-global"], "rubric": _RUBRIC, "qualification_threshold": 55, "meeting_window_days": 21, "crm_system": "hubspot", "average_deal_value": "40000", "target_reply_rate_percent": "12", "target_meeting_rate_percent": "5", "target_qualified_per_period": 5, "notes": "Partners refer many deals; value the relationship."},
}


class StageBinding(StrictModel):
    stage: LoopStage
    title: ShortText
    primitive_refs: tuple[ShortText, ...] = Field(min_length=1, max_length=12)
    connector_tools: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=30)
    prospect_events: tuple[ProspectEvent, ...] = Field(default_factory=tuple, max_length=12)
    gate: Literal["none", "spring_approval", "platform_policy", "customer_consent"] = "none"

    @model_validator(mode="after")
    def _bound_to_known(self) -> "StageBinding":
        unknown = [ref for ref in self.primitive_refs if ref not in _KNOWN_PRIMITIVE_REFS]
        if unknown:
            raise ValueError(f"stage {self.stage} binds unknown primitives: {unknown}")
        unknown_tools = [tool for tool in self.connector_tools if tool not in _KNOWN_CONNECTOR_TOOLS]
        if unknown_tools:
            raise ValueError(f"stage {self.stage} binds unknown connector tools: {unknown_tools}")
        return self


class PipelineEngineLoopPlan(StrictModel):
    schema_id: Literal["lightbulb.pipeline_engine_loop_plan.v1"] = Field(default=PLAN_SCHEMA, alias="schema")
    golden_loop: Literal["revenue.icp_to_qualified_pipeline@0.1.0"] = PIPELINE_ENGINE_GOLDEN_LOOP
    engine: Literal["pipeline_engine"] = PIPELINE_ENGINE_KIND
    blueprint: PipelineEngineBlueprint
    stages: tuple[StageBinding, ...] = Field(min_length=8, max_length=8)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _plan_is_exact(self, info: ValidationInfo) -> "PipelineEngineLoopPlan":
        if tuple(item.stage for item in self.stages) != STAGE_ORDER:
            raise ValueError("plan stages must follow the loop order exactly")
        if skip_digests(info):
            return self
        if self.plan_digest != sealed_digest(PipelineEngineLoopPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self

    def stage(self, name: str) -> StageBinding:
        return next(item for item in self.stages if item.stage == name)


def _stage_bindings(bp: PipelineEngineBlueprint) -> list[dict[str, Any]]:
    enabled = [item for item in bp.channels if item.enabled]
    channel_tools = tuple(dict.fromkeys(tool for item in enabled for tool in _CHANNEL_TOOLS[item.channel]))
    crm_tools = _CRM_TOOLS[bp.crm_system]
    consent = any(item.channel in CONSENT_CHANNELS for item in enabled)
    approval = any(item.requires_approval for item in enabled)
    return [
        {"stage": "define_icp", "title": "Define the ideal customer profile", "primitive_refs": ("pipeline.evaluate_icp_fit", "demand_gen.plan_audience_growth"), "gate": "none"},
        {"stage": "source_and_enrich", "title": "Source and enrich prospects that fit", "primitive_refs": ("pipeline.evaluate_icp_fit", "pipeline.advance_prospect", "crm.qualify_lead"), "connector_tools": ("apollo.search_people", "apollo.enrich_person", "clearbit.enrich_company") + crm_tools[:1], "prospect_events": ("source", "enrich", "suppress"), "gate": "none"},
        {"stage": "plan_sequences", "title": "Plan the outreach sequence per prospect", "primitive_refs": ("pipeline.plan_sequence", "pipeline.advance_prospect"), "prospect_events": ("sequence",), "gate": "none"},
        {"stage": "compose_touches", "title": "Compose touches from approved claims", "primitive_refs": ("pipeline.advance_prospect", "communication.write_email", "communication.plan_crm_conversation_turn") + (("communication.plan_governed_voice_call",) if any(item.channel == "voice" for item in enabled) else ()) + (("compliance.evaluate_regulated_controls",) if consent else ()), "prospect_events": ("touch",), "gate": "customer_consent" if consent else "platform_policy"},
        {"stage": "engage", "title": "Engage through the CRM and channels" + (" (voice needs approval)" if approval else ""), "primitive_refs": ("pipeline.advance_prospect",) + (("approval.request_decision",) if approval else ()), "connector_tools": channel_tools + tuple(tool for tool in crm_tools if tool.endswith("enroll_sequence") or tool.endswith("create_contact") or tool.endswith("create_lead")), "prospect_events": ("touch",), "gate": "spring_approval"},
        {"stage": "observe_engagement", "title": "Observe opens, clicks, replies, bounces", "primitive_refs": ("pipeline.advance_prospect", "growth.build_funnel_snapshot"), "connector_tools": tuple(tool for tool in crm_tools if tool.endswith("list_engagements") or tool.endswith("list_activities")) + tuple(tool for tool in channel_tools if tool.endswith("get_thread") or tool.endswith("lookup_call_status")), "prospect_events": ("observe", "reply", "suppress"), "gate": "none"},
        {"stage": "qualify_and_book", "title": f"Qualify on the rubric (threshold {bp.qualification_threshold}) and book inside {bp.meeting_window_days} days", "primitive_refs": ("pipeline.advance_prospect", "crm.qualify_lead", "calendar.schedule_meeting"), "connector_tools": ("calendar.get_availability", "calendar.create_event") + tuple(tool for tool in crm_tools if tool.endswith("create_deal") or tool.endswith("create_opportunity")), "prospect_events": ("qualify", "book_meeting", "hand_off", "lose"), "gate": "spring_approval"},
        {"stage": "forecast_and_learn", "title": "Forecast pipeline and learn", "primitive_refs": ("pipeline.forecast_pipeline", "growth.review_customer_value", "learning.plan_optimization_sweep"), "gate": "none"},
    ]


def compile_pipeline_engine_blueprint(profile: str | Mapping[str, Any], overrides: Mapping[str, Any] | None = None) -> PipelineEngineLoopPlan:
    if isinstance(profile, str):
        if profile not in PIPELINE_ENGINE_PROFILES:
            raise ValueError(f"unknown pipeline engine profile {profile!r}; choose one of {sorted(PIPELINE_ENGINE_PROFILES)} or pass a custom blueprint")
        raw: dict[str, Any] = json.loads(json.dumps(PIPELINE_ENGINE_PROFILES[profile]))
    else:
        raw = dict(detached(profile))
    for key, value in dict(overrides or {}).items():
        if key in {"schema", "blueprint_digest"}:
            raise ValueError("overrides cannot set schema or digest fields")
        raw[key] = value
    blueprint = PipelineEngineBlueprint.model_validate(seal_pipeline_engine_blueprint(raw))
    payload = {"blueprint": blueprint.to_dict(), "stages": _stage_bindings(blueprint)}
    payload["plan_digest"] = sealed_digest(PipelineEngineLoopPlan, payload, "plan_digest")
    return PipelineEngineLoopPlan.model_validate(payload)


# --------------------------------------------------------------------------- #
# ICP fit
# --------------------------------------------------------------------------- #


class ProspectFacts(StrictModel):
    """Firmographic and role facts about a prospect; opaque references only, no personal identifiers."""

    prospect_ref: OpaqueRef
    account_ref: OpaqueRef
    industry: ShortText
    employees: int = Field(ge=1, le=10_000_000)
    region: ShortText
    title: ShortText
    signals: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=20)
    flags: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=20)
    source_ref: OpaqueRef


class IcpFitEvaluation(StrictModel):
    schema_id: Literal["lightbulb.icp_fit_evaluation.v1"] = Field(default=ICP_FIT_SCHEMA, alias="schema")
    plan_digest: Sha256Digest
    prospect_ref: OpaqueRef
    score: int = Field(ge=0, le=100)
    fits: bool
    disqualified_by: ShortText | None = None
    reasons: tuple[ShortText, ...] = Field(min_length=1, max_length=12)
    evaluation_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _exact(self, info: ValidationInfo) -> "IcpFitEvaluation":
        if skip_digests(info):
            return self
        if self.evaluation_digest != sealed_digest(IcpFitEvaluation, self, "evaluation_digest"):
            raise ValueError("evaluation_digest must commit the exact evaluation")
        return self


def _norm(value: str) -> str:
    return value.strip().lower()


def evaluate_icp_fit(plan: PipelineEngineLoopPlan | Mapping[str, Any], facts: ProspectFacts | Mapping[str, Any]) -> IcpFitEvaluation:
    """Deterministic ICP fit: industry 30, size 20, region 20, title 20, signals 10; disqualifiers are absolute."""

    parsed_plan = PipelineEngineLoopPlan.model_validate(detached(plan))
    icp = parsed_plan.blueprint.icp
    f = ProspectFacts.model_validate(detached(facts))
    flags = {_norm(item) for item in f.flags}
    reasons: list[str] = []
    for disqualifier in icp.disqualifiers:
        if _norm(disqualifier) in flags:
            payload = {"plan_digest": parsed_plan.plan_digest, "prospect_ref": f.prospect_ref, "score": 0, "fits": False, "disqualified_by": disqualifier, "reasons": [f"disqualified: {disqualifier}"]}
            return seal(IcpFitEvaluation, payload, "evaluation_digest")
    score = 0
    if _norm(f.industry) in {_norm(item) for item in icp.industries}:
        score += 30
        reasons.append(f"industry {f.industry} is in the ICP")
    else:
        reasons.append(f"industry {f.industry} is outside the ICP")
    if icp.min_employees <= f.employees <= icp.max_employees:
        score += 20
        reasons.append(f"{f.employees} employees inside the {icp.min_employees}-{icp.max_employees} band")
    else:
        reasons.append(f"{f.employees} employees outside the {icp.min_employees}-{icp.max_employees} band")
    if _norm(f.region) in {_norm(item) for item in icp.regions}:
        score += 20
        reasons.append(f"region {f.region} is served")
    else:
        reasons.append(f"region {f.region} is not served")
    if any(_norm(title) in _norm(f.title) or _norm(f.title) in _norm(title) for title in icp.buyer_titles):
        score += 20
        reasons.append(f"title {f.title} matches a buyer title")
    else:
        reasons.append(f"title {f.title} is not a buyer title")
    if icp.required_signals:
        present = {_norm(item) for item in f.signals}
        matched = [signal for signal in icp.required_signals if _norm(signal) in present]
        score += int(10 * len(matched) / len(icp.required_signals))
        reasons.append(f"{len(matched)} of {len(icp.required_signals)} required signals present")
    else:
        score += 10
    payload = {"plan_digest": parsed_plan.plan_digest, "prospect_ref": f.prospect_ref, "score": score, "fits": score >= icp.fit_threshold, "disqualified_by": None, "reasons": reasons}
    return seal(IcpFitEvaluation, payload, "evaluation_digest")


# --------------------------------------------------------------------------- #
# Sequence plan
# --------------------------------------------------------------------------- #


class ScheduledTouch(StrictModel):
    step: int = Field(ge=1, le=20)
    channel: OutreachChannel
    intent: TouchIntent
    not_before: str
    requires_approval: bool
    requires_consent: bool


class SequencePlan(StrictModel):
    schema_id: Literal["lightbulb.outreach_sequence_plan.v1"] = Field(default=SEQUENCE_PLAN_SCHEMA, alias="schema")
    plan_digest: Sha256Digest
    prospect_ref: OpaqueRef
    sequence_ref: OpaqueRef
    starts_at: str
    touches: tuple[ScheduledTouch, ...] = Field(min_length=1, max_length=20)
    sequence_plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("starts_at")
    @classmethod
    def _starts(cls, value: str) -> str:
        return timestamp(value, field_name="starts_at")

    @model_validator(mode="after")
    def _exact(self, info: ValidationInfo) -> "SequencePlan":
        if skip_digests(info):
            return self
        if self.sequence_plan_digest != sealed_digest(SequencePlan, self, "sequence_plan_digest"):
            raise ValueError("sequence_plan_digest must commit the exact plan")
        return self

    def touch(self, step: int) -> ScheduledTouch | None:
        return next((item for item in self.touches if item.step == step), None)


def plan_sequence(plan: PipelineEngineLoopPlan | Mapping[str, Any], *, prospect_ref: str, sequence_ref: str, starts_at: str) -> SequencePlan:
    parsed_plan = PipelineEngineLoopPlan.model_validate(detached(plan))
    bp = parsed_plan.blueprint
    template = bp.sequence(sequence_ref)
    if template is None:
        raise ValueError(f"SEQUENCE_UNKNOWN: {sequence_ref} is not a blueprint sequence")
    start = timestamp(starts_at, field_name="starts_at")
    touches = []
    for step in template.steps:
        policy = bp.channel(step.channel)
        touches.append({"step": step.step, "channel": step.channel, "intent": step.intent, "not_before": add_days(start, step.day_offset), "requires_approval": bool(policy is not None and policy.requires_approval), "requires_consent": step.channel in CONSENT_CHANNELS})
    payload = {"plan_digest": parsed_plan.plan_digest, "prospect_ref": prospect_ref, "sequence_ref": sequence_ref, "starts_at": start, "touches": touches}
    return seal(SequencePlan, payload, "sequence_plan_digest")


# --------------------------------------------------------------------------- #
# Prospect lifecycle
# --------------------------------------------------------------------------- #


class ProspectReceipt(StrictModel):
    entity_scope: EngineScope | None = None
    eligibility_receipt: dict[str, Any] | None = None
    suppression_digest: Sha256Digest | None = None
    sequence_plan: dict[str, Any] | None = None
    sequence_channel_daily_caps: dict[OutreachChannel, int] | None = Field(default=None, max_length=4)
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    account_ref: OpaqueRef | None = None
    source_ref: OpaqueRef | None = None
    fit_evaluation_digest: Sha256Digest | None = None
    fit_score: int | None = Field(default=None, ge=0, le=100)
    enrichment_ref: OpaqueRef | None = None
    suppression_check_ref: OpaqueRef | None = None
    sequence_plan_digest: Sha256Digest | None = None
    sequence_ref: OpaqueRef | None = None
    step: int | None = Field(default=None, ge=1, le=20)
    channel: OutreachChannel | None = None
    intent: TouchIntent | None = None
    touch_ref: OpaqueRef | None = None
    subject: ShortText | None = None
    body: BoundedText | None = None
    claim_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=20)
    consent_ref: OpaqueRef | None = None
    approval_ref: OpaqueRef | None = None
    engagement_ref: OpaqueRef | None = None
    opens: int | None = Field(default=None, ge=0)
    clicks: int | None = Field(default=None, ge=0)
    bounced: bool | None = None
    unsubscribed: bool | None = None
    reply_ref: OpaqueRef | None = None
    disposition: ReplyDisposition | None = None
    scores: dict[str, int] | None = None
    meeting_ref: OpaqueRef | None = None
    meeting_at: str | None = None
    deal_ref: OpaqueRef | None = None
    deal_value: Decimal | None = None

    @field_validator("deal_value", mode="before")
    @classmethod
    def _deal(cls, value: Any) -> Any:
        return None if value is None else decimal_value(value, field_name="deal_value")

    @field_validator("meeting_at")
    @classmethod
    def _meeting(cls, value: str | None) -> str | None:
        return None if value is None else timestamp(value, field_name="meeting_at")


class ProspectLedger(StrictModel):
    channel_daily_caps: dict[str, int] = Field(default_factory=dict)
    entity_scope: EngineScope | None = None
    consent_ref: OpaqueRef | None = None
    suppression_list_refs: tuple[OpaqueRef, ...] = ()
    sequence_plan: dict[str, Any] | None = None
    sends_by_day: dict[str, int] = Field(default_factory=dict)
    account_ref: OpaqueRef | None = None
    source_ref: OpaqueRef | None = None
    fit_evaluation_digest: Sha256Digest | None = None
    fit_score: int = Field(default=0, ge=0, le=100)
    enrichment_ref: OpaqueRef | None = None
    suppression_check_ref: OpaqueRef | None = None
    sequence_ref: OpaqueRef | None = None
    sequence_plan_digest: Sha256Digest | None = None
    touches: int = Field(default=0, ge=0)
    next_step: int = Field(default=1, ge=1, le=21)
    last_touch_at: str | None = None
    last_channel: OutreachChannel | None = None
    touch_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple)
    opens: int = Field(default=0, ge=0)
    clicks: int = Field(default=0, ge=0)
    replies: int = Field(default=0, ge=0)
    reply_disposition: ReplyDisposition | None = None
    qualification_score: int | None = Field(default=None, ge=0, le=100)
    meeting_ref: OpaqueRef | None = None
    meeting_at: str | None = None
    deal_ref: OpaqueRef | None = None
    deal_value: Decimal = Field(default=Decimal("0"), validate_default=True)
    suppression_reason: ShortText | None = None
    lost_reason: ShortText | None = None
    outcome: Literal["handed_off", "lost", "suppressed", "disqualified"] | None = None

    @field_validator("deal_value", mode="before")
    @classmethod
    def _deal(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="deal_value")


class ProspectEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    message_sent: Literal[False] = False
    call_placed: Literal[False] = False
    crm_written: Literal[False] = False
    meeting_booked: Literal[False] = False
    provider_read: Literal[False] = False


def _prohibited(text: str | None, terms: Sequence[str]) -> str | None:
    if not text:
        return None
    lowered = text.lower()
    return next((term for term in terms if term.lower() in lowered), None)


def _apply_prospect(plan: PipelineEngineLoopPlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    bp, r, event, at = plan.blueprint, command.receipt, command.event, parsed(command.occurred_at)
    if event == "source":
        if r.entity_scope is not None:
            require(command.expected_state_digest == PROSPECT_LIFECYCLE.state_digest(plan.plan_digest, r.entity_scope, ()), "SCOPE_MISMATCH", "the permission scope belongs to this prospect")
            data["entity_scope"] = r.entity_scope.to_dict()
        require(r.account_ref is not None and r.source_ref is not None and r.fit_evaluation_digest is not None and r.fit_score is not None, "FIT_MISSING", "sourcing links the account, the source, and the sealed ICP fit evaluation")
        require(r.fit_score >= bp.icp.fit_threshold, "BELOW_FIT_THRESHOLD", f"fit {r.fit_score} is below the {bp.icp.fit_threshold} threshold; do not source", "manual_reconciliation")
        data.update({"account_ref": r.account_ref, "source_ref": r.source_ref, "fit_evaluation_digest": r.fit_evaluation_digest, "fit_score": r.fit_score})
    elif event == "enrich":
        require(r.enrichment_ref is not None, "ENRICHMENT_MISSING", "enrichment links the enrichment record")
        require(r.suppression_check_ref is not None, "SUPPRESSION_CHECK_MISSING", f"enrichment must carry the suppression check against {list(bp.suppression_list_refs)}")
        data.update({"enrichment_ref": r.enrichment_ref, "suppression_check_ref": r.suppression_check_ref})
    elif event == "sequence":
        require(r.sequence_ref is not None and r.sequence_plan_digest is not None, "SEQUENCE_MISSING", "sequencing links the blueprint sequence and the sealed sequence plan")
        require(bp.sequence(str(r.sequence_ref)) is not None, "SEQUENCE_UNKNOWN", f"{r.sequence_ref} is not a blueprint sequence")
        data.update({"sequence_ref": r.sequence_ref, "sequence_plan_digest": r.sequence_plan_digest, "next_step": 1})
        if r.sequence_channel_daily_caps is not None:
            caps = {policy.channel: policy.daily_cap for policy in bp.channels if policy.enabled}
            require(r.sequence_channel_daily_caps == caps, "SEQUENCE_CHANNEL_POLICY_MISMATCH",
                    "sequencing may retain only the exact enabled blueprint channel caps")
            data["channel_daily_caps"] = caps
        if bp.require_permission_register or r.sequence_plan is not None:
            require(r.sequence_plan is not None, "SEQUENCE_MISSING", "retain the sequence plan so not_before is enforced by the lifecycle")
            sequence = SequencePlan.model_validate(r.sequence_plan)
            require(sequence.sequence_plan_digest == r.sequence_plan_digest and sequence.sequence_ref == r.sequence_ref and sequence.prospect_ref == data["entity_scope"]["entity_ref"], "SEQUENCE_MISMATCH", "the retained plan must belong to this prospect and sequence")
            data["sequence_plan"] = sequence.to_dict()
    elif event == "touch":
        template = bp.sequence(str(data.get("sequence_ref")))
        require(template is not None, "SEQUENCE_MISSING", "sequence the prospect before touching")
        assert template is not None
        step_number = int(data.get("next_step", 1))
        require(step_number <= len(template.steps), "SEQUENCE_EXHAUSTED", "every step of the sequence was sent", "manual_reconciliation")
        step = template.steps[step_number - 1]
        require(r.step == step.step and r.channel == step.channel, "STEP_MISMATCH", f"the next touch is step {step.step} on {step.channel}")
        policy = bp.channel(step.channel)
        require(policy is not None and policy.enabled, "CHANNEL_NOT_ENABLED", f"{step.channel} is not enabled")
        assert policy is not None
        if data.get("sequence_plan"):
            sequence = SequencePlan.model_validate(data["sequence_plan"])
            require(at >= parsed(sequence.touches[step_number - 1].not_before), "TOUCH_NOT_DUE", "the retained sequence plan's not_before clock has not arrived")
        day_key = f"{step.channel}:{command.occurred_at[:10]}"
        sends = dict(data.get("sends_by_day", {}))
        require(sends.get(day_key, 0) < policy.daily_cap, "DAILY_CAP_EXCEEDED", "the channel's daily send cap has been reached")
        data["channel_daily_caps"] = {**data.get("channel_daily_caps", {}), step.channel: policy.daily_cap}
        if bp.require_permission_register or r.eligibility_receipt is not None:
            from lightbulb._permission_gates import eligibility
            proof = eligibility(r.eligibility_receipt, r.suppression_digest, channel=step.channel, at=command.occurred_at, company_ref=bp.permission_company_ref, scope=data.get("entity_scope"))
            data.update(consent_ref=f"eligibility:{proof.eligibility_digest[:24]}", suppression_list_refs=[f"suppression:{proof.suppression_digest}"])
        require(r.touch_ref is not None and (r.subject is not None or r.body is not None), "TOUCH_MISSING", "a touch names its touch_ref and carries a subject or body")
        last = data.get("last_touch_at")
        if last is not None:
            hours = (at - parsed(str(last))).total_seconds() / 3600
            require(hours >= policy.min_hours_between_touches, "TOUCH_TOO_SOON", f"{step.channel} touches need {policy.min_hours_between_touches} hours between them")
        for ref in r.claim_refs:
            require(bp.claim(ref) is not None, "CLAIM_NOT_APPROVED", f"{ref} is not an approved claim", "manual_reconciliation")
        hit = _prohibited(r.subject, bp.prohibited_terms) or _prohibited(r.body, bp.prohibited_terms)
        require(hit is None, "BRAND_SAFETY_VIOLATION", f"touch uses the prohibited term {hit!r}", "manual_reconciliation")
        if step.channel in CONSENT_CHANNELS and not (bp.require_permission_register or r.eligibility_receipt is not None):
            require(r.consent_ref is not None, "CONSENT_MISSING", f"{step.channel} touches need the prospect consent reference")
        if policy.requires_approval:
            require(r.approval_ref is not None, "APPROVAL_REQUIRED", f"{step.channel} touches need a server-issued approval reference", "await_approval")
        digest = stable_digest({"step": step.step, "channel": step.channel, "subject": r.subject, "body": r.body, "claims": list(r.claim_refs)})
        sends[day_key] = sends.get(day_key, 0) + 1
        data["sends_by_day"] = sends
        data.update({"touches": int(data.get("touches", 0)) + 1, "next_step": step_number + 1, "last_touch_at": command.occurred_at, "last_channel": step.channel, "touch_digests": [*data.get("touch_digests", []), digest]})
    elif event == "observe":
        require(r.engagement_ref is not None, "ENGAGEMENT_MISSING", "an observation links the engagement record")
        data.update({"opens": int(data.get("opens", 0)) + (r.opens or 0), "clicks": int(data.get("clicks", 0)) + (r.clicks or 0)})
        if r.bounced or r.unsubscribed:
            next_status = "suppressed"
            data.update({"suppression_reason": "unsubscribed" if r.unsubscribed else "bounced", "outcome": "suppressed"})
    elif event == "reply":
        require(r.reply_ref is not None and r.disposition is not None, "REPLY_MISSING", "a reply links the reply record and its classified disposition")
        data.update({"replies": int(data.get("replies", 0)) + 1, "reply_disposition": r.disposition})
        if r.disposition in {"negative", "wrong_person"}:
            next_status = "lost"
            data.update({"lost_reason": f"reply: {r.disposition}", "outcome": "lost"})
    elif event == "qualify":
        require(r.scores is not None and set(r.scores) == {item.dimension for item in bp.rubric}, "RUBRIC_INCOMPLETE", f"qualification scores every rubric dimension: {[item.dimension for item in bp.rubric]}")
        assert r.scores is not None
        require(all(0 <= value <= 100 for value in r.scores.values()), "RUBRIC_SCORE_INVALID", "rubric scores are 0..100")
        total = sum(r.scores[item.dimension] * item.weight for item in bp.rubric) // 100
        data["qualification_score"] = total
        if total < bp.qualification_threshold:
            next_status = "disqualified"
            data.update({"lost_reason": f"rubric {total} below {bp.qualification_threshold}", "outcome": "disqualified"})
    elif event == "book_meeting":
        require(r.meeting_ref is not None and r.meeting_at is not None, "MEETING_MISSING", "booking links the meeting reference and start time")
        meeting = parsed(str(r.meeting_at))
        require(meeting >= at, "MEETING_IN_PAST", "the meeting must start after the booking time")
        require((meeting - at).days <= bp.meeting_window_days, "MEETING_OUTSIDE_WINDOW", f"meetings book inside {bp.meeting_window_days} days")
        data.update({"meeting_ref": r.meeting_ref, "meeting_at": r.meeting_at})
    elif event == "hand_off":
        require(r.deal_ref is not None, "DEAL_MISSING", f"hand-off links the {bp.crm_system} deal reference")
        data.update({"deal_ref": r.deal_ref, "deal_value": str(r.deal_value if r.deal_value is not None else bp.average_deal_value), "outcome": "handed_off"})
    elif event == "lose":
        data.update({"lost_reason": str(command.reason)[:300], "outcome": "lost"})
    elif event == "suppress":
        data.update({"suppression_reason": str(command.reason)[:300], "outcome": "suppressed"})
    return next_status, data


PROSPECT_LIFECYCLE = LifecycleSpec(entity="prospect", schema_prefix="pipeline_prospect", statuses=PROSPECT_STATUSES, terminal=TERMINAL_PROSPECT_STATUSES, events=PROSPECT_EVENTS, table=_PROSPECT_TABLE, opening_event="source", reason_events=("lose", "suppress"), apply=_apply_prospect, ledger_model=ProspectLedger, receipt_model=ProspectReceipt, effect_boundary_model=ProspectEffectBoundary, plan_model=PipelineEngineLoopPlan, max_transitions=MAX_PROSPECT_TRANSITIONS)
ProspectCommand = PROSPECT_LIFECYCLE.Command
ProspectState = PROSPECT_LIFECYCLE.State
ProspectTransitionResult = PROSPECT_LIFECYCLE.TransitionResult
seal_prospect_command = PROSPECT_LIFECYCLE.seal_command
prospect_command_digest = PROSPECT_LIFECYCLE.command_digest


def open_prospect(plan: PipelineEngineLoopPlan | Mapping[str, Any], scope: EngineScope | Mapping[str, Any], *, facts: ProspectFacts | Mapping[str, Any], fit: IcpFitEvaluation | Mapping[str, Any], opened_at: str, actor_ref: str) -> Any:
    """Source a prospect from a sealed ICP fit evaluation; below-threshold or disqualified prospects never open."""

    parsed_plan = PipelineEngineLoopPlan.model_validate(detached(plan))
    parsed_fit = IcpFitEvaluation.model_validate(detached(fit))
    parsed_facts = ProspectFacts.model_validate(detached(facts))
    if parsed_fit.plan_digest != parsed_plan.plan_digest:
        raise ValueError("FIT_NOT_BOUND: the fit evaluation belongs to a different loop plan")
    if parsed_fit.prospect_ref != parsed_facts.prospect_ref:
        raise ValueError("FIT_PROSPECT_MISMATCH: the fit evaluation is for another prospect")
    if not parsed_fit.fits:
        raise ValueError(f"BELOW_FIT_THRESHOLD: {parsed_fit.reasons[0]}")
    receipt = {"account_ref": parsed_facts.account_ref, "source_ref": parsed_facts.source_ref, "fit_evaluation_digest": parsed_fit.evaluation_digest, "fit_score": parsed_fit.score}
    return PROSPECT_LIFECYCLE.open(parsed_plan, scope, opened_at=opened_at, actor_ref=actor_ref, receipt={**receipt, "entity_scope": detached(scope)})


def advance_prospect(plan: PipelineEngineLoopPlan | Mapping[str, Any], state: Any, command: Any) -> Any:
    return PROSPECT_LIFECYCLE.advance(plan, state, command)


# --------------------------------------------------------------------------- #
# Forecast
# --------------------------------------------------------------------------- #


class PipelineForecast(StrictModel):
    schema_id: Literal["lightbulb.pipeline_forecast.v1"] = Field(default=FORECAST_SCHEMA, alias="schema")
    golden_loop: Literal["revenue.icp_to_qualified_pipeline@0.1.0"] = PIPELINE_ENGINE_GOLDEN_LOOP
    profile: BlueprintProfile
    currency: CurrencyCode
    prospects: int = Field(ge=0)
    by_status: dict[str, int] = Field(default_factory=dict)
    touched: int = Field(ge=0)
    replied: int = Field(ge=0)
    positive_replies: int = Field(ge=0)
    qualified: int = Field(ge=0)
    meetings: int = Field(ge=0)
    handed_off: int = Field(ge=0)
    suppressed: int = Field(ge=0)
    reply_rate_percent: Decimal | None = None
    meeting_rate_percent: Decimal | None = None
    average_fit_score: Decimal | None = None
    average_qualification_score: Decimal | None = None
    handed_off_value: Decimal
    weighted_pipeline_value: Decimal
    learnings: tuple[ShortText, ...] = Field(min_length=1, max_length=12)
    recommendations: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=12)
    forecast_at: str
    forecast_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("reply_rate_percent", "meeting_rate_percent", "average_fit_score", "average_qualification_score", "handed_off_value", "weighted_pipeline_value", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Any:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))

    @field_validator("forecast_at")
    @classmethod
    def _at(cls, value: str) -> str:
        return timestamp(value, field_name="forecast_at")

    @model_validator(mode="after")
    def _exact(self, info: ValidationInfo) -> "PipelineForecast":
        if skip_digests(info):
            return self
        if self.forecast_digest != sealed_digest(PipelineForecast, self, "forecast_digest"):
            raise ValueError("forecast_digest must commit the exact forecast")
        return self


_STAGE_PROBABILITY: dict[str, Decimal] = {"sourced": Decimal("0.02"), "enriched": Decimal("0.03"), "sequenced": Decimal("0.05"), "engaged": Decimal("0.08"), "replied": Decimal("0.15"), "qualified": Decimal("0.35"), "meeting_booked": Decimal("0.60"), "handed_off": Decimal("1")}


def forecast_pipeline(plan: PipelineEngineLoopPlan | Mapping[str, Any], prospects: Sequence[Any], *, forecast_at: str) -> PipelineForecast:
    parsed_plan = PipelineEngineLoopPlan.model_validate(detached(plan))
    bp = parsed_plan.blueprint
    bound = [PROSPECT_LIFECYCLE.bind(parsed_plan, item)[1] for item in prospects]
    touched = [item for item in bound if item.ledger.touches > 0]
    replied = [item for item in bound if item.ledger.replies > 0]
    positive = [item for item in replied if item.ledger.reply_disposition == "positive"]
    qualified = [item for item in bound if item.ledger.qualification_score is not None and item.ledger.qualification_score >= bp.qualification_threshold]
    meetings = [item for item in bound if item.ledger.meeting_ref is not None]
    handed = [item for item in bound if item.status == "handed_off"]
    suppressed = [item for item in bound if item.status == "suppressed"]
    reply_rate = ratio_percent(len(replied), len(touched))
    meeting_rate = ratio_percent(len(meetings), len(touched))
    fit_scores = [Decimal(item.ledger.fit_score) for item in bound]
    q_scores = [Decimal(item.ledger.qualification_score) for item in bound if item.ledger.qualification_score is not None]
    handed_value = sum((item.ledger.deal_value for item in handed), Decimal("0"))
    weighted = sum((bp.average_deal_value * _STAGE_PROBABILITY.get(item.status, Decimal("0")) for item in bound if item.status not in {"handed_off", "lost", "suppressed", "disqualified"}), Decimal("0")) + handed_value
    learnings: list[str] = []
    recommendations: list[str] = []
    if reply_rate is not None and reply_rate < bp.target_reply_rate_percent:
        learnings.append(f"reply rate {reply_rate}% is below the {bp.target_reply_rate_percent}% target")
        recommendations.append("tighten the ICP or rewrite the introduce and value touches")
    if meeting_rate is not None and meeting_rate < bp.target_meeting_rate_percent:
        learnings.append(f"meeting rate {meeting_rate}% is below the {bp.target_meeting_rate_percent}% target")
        recommendations.append("add a proof touch before the ask and shorten the meeting window")
    if len(qualified) < bp.target_qualified_per_period:
        learnings.append(f"{len(qualified)} qualified against a target of {bp.target_qualified_per_period}")
        recommendations.append("increase sourcing volume inside the ICP before widening it")
    if suppressed:
        learnings.append(f"{len(suppressed)} prospect(s) suppressed; keep suppression lists current")
    if not learnings:
        learnings.append("pipeline is inside blueprint targets")
    payload = {"profile": bp.profile, "currency": bp.currency, "prospects": len(bound), "by_status": {status: sum(1 for item in bound if item.status == status) for status in sorted({item.status for item in bound})}, "touched": len(touched), "replied": len(replied), "positive_replies": len(positive), "qualified": len(qualified), "meetings": len(meetings), "handed_off": len(handed), "suppressed": len(suppressed), "reply_rate_percent": None if reply_rate is None else str(reply_rate), "meeting_rate_percent": None if meeting_rate is None else str(meeting_rate), "average_fit_score": None if not fit_scores else str((sum(fit_scores) / Decimal(len(fit_scores))).quantize(MONEY_QUANTUM)), "average_qualification_score": None if not q_scores else str((sum(q_scores) / Decimal(len(q_scores))).quantize(MONEY_QUANTUM)), "handed_off_value": str(handed_value), "weighted_pipeline_value": str(weighted.quantize(MONEY_QUANTUM)), "learnings": learnings, "recommendations": recommendations, "forecast_at": forecast_at}
    return seal(PipelineForecast, payload, "forecast_digest")


PIPELINE_ENGINE_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine.v1",
    "engine": PIPELINE_ENGINE_KIND,
    "title": "Pipeline engine",
    "golden_loop": PIPELINE_ENGINE_GOLDEN_LOOP,
    "profiles": sorted(PIPELINE_ENGINE_PROFILES),
    "channels": list(OUTREACH_CHANNELS),
    "prospect_statuses": list(PROSPECT_STATUSES),
    "prospect_events": list(PROSPECT_EVENTS),
    "required_connectors": sorted({tool.split(".")[0] for tool in _KNOWN_CONNECTOR_TOOLS}),
    "hands_off_to": ["commercial.approved_quote_to_executed_agreement_custody@0.1.0", "service.market_to_renewal_business@0.1.0", "subscription.trial_to_renewal_business@0.1.0"],
    "composes_with_archetypes": ["service_business", "subscription_business", "saas_product", "marketplace_business"],
    "economic_spine": {"acquire_demand": "define_icp / source_and_enrich / plan_sequences / compose_touches / engage", "create_offer": "qualify_and_book (hand-off to quote)", "agree_purchase": "handed to the commercial loop", "learn": "forecast_and_learn"},
    "explicit_inputs_never_invented": ["ICP criteria", "consent for voice and SMS", "suppression lists", "approved claims", "human approval for gated channels", "reply dispositions and rubric scores from evidence"],
}

__all__ = [
    "CONSENT_CHANNELS",
    "OUTREACH_CHANNELS",
    "PIPELINE_ENGINE_GOLDEN_LOOP",
    "PIPELINE_ENGINE_KIND",
    "PIPELINE_ENGINE_MANIFEST",
    "PIPELINE_ENGINE_PROFILES",
    "PROSPECT_EVENTS",
    "PROSPECT_LIFECYCLE",
    "PROSPECT_STATUSES",
    "STAGE_ORDER",
    "TERMINAL_PROSPECT_STATUSES",
    "ApprovedClaim",
    "IcpCriteria",
    "IcpFitEvaluation",
    "OutreachChannelPolicy",
    "PipelineEngineBlueprint",
    "PipelineEngineLoopPlan",
    "PipelineForecast",
    "ProspectCommand",
    "ProspectEffectBoundary",
    "ProspectFacts",
    "ProspectLedger",
    "ProspectReceipt",
    "ProspectState",
    "ProspectTransitionResult",
    "RubricDimension",
    "ScheduledTouch",
    "SequencePlan",
    "SequenceStep",
    "SequenceTemplate",
    "StageBinding",
    "advance_prospect",
    "compile_pipeline_engine_blueprint",
    "evaluate_icp_fit",
    "forecast_pipeline",
    "open_prospect",
    "plan_sequence",
    "prospect_command_digest",
    "seal_pipeline_engine_blueprint",
    "seal_prospect_command",
]
