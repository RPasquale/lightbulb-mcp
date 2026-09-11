"""Business sales configuration compiled into the existing pipeline contracts.

The host supplies the offer, targeting and reviewed copy. These models neither
discover contacts nor grant permission to send. Current permission and exact
provider authority are checked again by the sales host before any outreach.
"""
from __future__ import annotations

from decimal import Decimal
from email.utils import parseaddr
import re
from typing import Any, Literal
from uuid import UUID

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    BoundedText, CurrencyCode, GENESIS_DIGEST, OpaqueRef, Sha256Digest, ShortText,
    StrictModel, decimal_value, detached, seal, sealed_digest, skip_digests,
)
from lightbulb.connector_execution import ExecutionScope
from lightbulb.pipeline_engine_loop import (
    ApprovedClaim, BlueprintProfile, IcpCriteria, OutreachChannelPolicy,
    PipelineEngineLoopPlan, SequencePlan, SequenceTemplate,
    compile_pipeline_engine_blueprint, plan_sequence,
)


class SalesPlaybookError(ValueError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise SalesPlaybookError(code)


def _address(value: str) -> str:
    name, address = parseaddr(value)
    _require(not name and address == value and len(address) <= 254 and address.count("@") == 1
             and all(ord(char) > 32 for char in address) and "." in address.rsplit("@", 1)[-1],
             "SALES_CONTACT_ADDRESS_INVALID")
    return value


class SalesOffer(StrictModel):
    offer_ref: OpaqueRef
    title: ShortText
    description: BoundedText
    currency: CurrencyCode
    amount: Decimal = Field(gt=0)
    claim_declarations: tuple[ApprovedClaim, ...] = Field(default_factory=tuple, max_length=100)

    @field_validator("amount", mode="before")
    @classmethod
    def _amount(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="amount")


class SalesGoals(StrictModel):
    objective: Literal["meeting", "qualified_opportunity", "proposal"]
    reply_rate_percent: Decimal = Field(gt=0, le=100)
    meeting_rate_percent: Decimal = Field(gt=0, le=100)
    qualified_per_period: int = Field(ge=1, le=100000)

    @field_validator("reply_rate_percent", "meeting_rate_percent", mode="before")
    @classmethod
    def _rates(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))


class SalesEmailTemplate(StrictModel):
    step: int = Field(ge=1, le=20)
    subject: ShortText
    body: BoundedText
    claim_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=100)

    @field_validator("subject")
    @classmethod
    def _subject(cls, value: str) -> str:
        _require("\r" not in value and "\n" not in value, "SALES_SUBJECT_INVALID")
        return value


class SalesPlaybookSpec(StrictModel):
    playbook_ref: OpaqueRef
    company_ref: OpaqueRef
    scope: ExecutionScope
    offer: SalesOffer
    profile: BlueprintProfile
    icp: IcpCriteria
    email_policy: OutreachChannelPolicy
    sequence: SequenceTemplate
    messages: tuple[SalesEmailTemplate, ...] = Field(min_length=1, max_length=20)
    goals: SalesGoals
    prohibited_terms: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=100)
    suppression_list_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=20)

    @model_validator(mode="after")
    def _exact(self):
        _require(self.scope.project_id is not None and bool(self.scope.actor_ref), "SALES_SCOPE_REQUIRED")
        _require(self.email_policy.channel == "email" and self.email_policy.enabled
                 and self.email_policy.requires_approval, "SALES_APPROVED_EMAIL_REQUIRED")
        _require(all(step.channel == "email" for step in self.sequence.steps), "SALES_EMAIL_SEQUENCE_REQUIRED")
        _require([message.step for message in self.messages] == [step.step for step in self.sequence.steps],
                 "SALES_MESSAGE_STEPS_MISMATCH")
        for previous, current in zip(self.sequence.steps, self.sequence.steps[1:]):
            _require((current.day_offset - previous.day_offset) * 24 >= self.email_policy.min_hours_between_touches,
                     "SALES_SEQUENCE_SPACING_INVALID")
        claims = {claim.claim_ref for claim in self.offer.claim_declarations}
        for message in self.messages:
            _require(set(message.claim_refs) <= claims, "SALES_CLAIM_NOT_APPROVED")
            _require(not any(term.lower() in (message.subject + "\n" + message.body).lower()
                             for term in self.prohibited_terms), "SALES_PROHIBITED_COPY")
        return self


def _pipeline(spec: SalesPlaybookSpec) -> PipelineEngineLoopPlan:
    return compile_pipeline_engine_blueprint(spec.profile, {
        "name": spec.offer.title, "currency": spec.offer.currency,
        "icp": spec.icp.to_dict(), "channels": [spec.email_policy.to_dict()],
        "sequences": [spec.sequence.to_dict()],
        "approved_claims": [claim.to_dict() for claim in spec.offer.claim_declarations],
        "prohibited_terms": list(spec.prohibited_terms), "suppression_list_refs": list(spec.suppression_list_refs),
        "average_deal_value": str(spec.offer.amount), "require_permission_register": True,
        "permission_company_ref": spec.company_ref,
        "target_reply_rate_percent": str(spec.goals.reply_rate_percent),
        "target_meeting_rate_percent": str(spec.goals.meeting_rate_percent),
        "target_qualified_per_period": spec.goals.qualified_per_period,
    })


class SalesPlaybook(StrictModel):
    schema_id: Literal["lightbulb.company_sales_playbook.v1"] = Field(default="lightbulb.company_sales_playbook.v1", alias="schema")
    spec: SalesPlaybookSpec
    pipeline_plan: PipelineEngineLoopPlan
    playbook_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _bound(self, info: ValidationInfo):
        _require(self.pipeline_plan == _pipeline(self.spec), "SALES_PLAYBOOK_PLAN_MISMATCH")
        if not skip_digests(info):
            _require(self.playbook_digest == sealed_digest(type(self), self, "playbook_digest"),
                     "SALES_PLAYBOOK_DIGEST_MISMATCH")
        return self

    def sequence_for(self, prospect_ref: str, *, starts_at: str) -> SequencePlan:
        return plan_sequence(self.pipeline_plan, prospect_ref=prospect_ref,
                             sequence_ref=self.spec.sequence.sequence_ref, starts_at=starts_at)

    def message_for(self, step: int) -> SalesEmailTemplate:
        message = next((message for message in self.spec.messages if message.step == step), None)
        _require(message is not None, "SALES_MESSAGE_STEP_MISSING")
        return message


def compile_sales_playbook(spec: Any) -> SalesPlaybook:
    source = SalesPlaybookSpec.model_validate(detached(spec))
    return seal(SalesPlaybook, {"spec": source.to_dict(), "pipeline_plan": _pipeline(source).to_dict()}, "playbook_digest")


class SalesBillingGuard(StrictModel):
    policy_ref: OpaqueRef
    source_ref: OpaqueRef
    invoice_ref: OpaqueRef


class SalesProspectBinding(StrictModel):
    """Trusted deployment input; references current permission rather than asserting it."""
    binding_ref: OpaqueRef
    playbook_ref: OpaqueRef
    prospect_ref: OpaqueRef
    account_ref: OpaqueRef
    connector_account_ref: OpaqueRef
    permission_entity_ref: OpaqueRef
    endpoint_digest: Sha256Digest
    endpoint_key_ref: OpaqueRef
    crm_conversation_id: UUID
    crm_channel_identity_id: UUID
    crm_contact_id: UUID
    to_address: str
    from_address: str
    sequence: SequencePlan
    thread_ref: OpaqueRef | None = None
    parent_message_id: str | None = Field(default=None, max_length=998)
    purpose: Literal["acquisition", "expansion", "winback", "billing_recovery", "activation", "renewal"] = "acquisition"
    billing_guard: SalesBillingGuard | None = None

    @field_validator("to_address", "from_address")
    @classmethod
    def _addresses(cls, value: str) -> str:
        return _address(value)

    @model_validator(mode="after")
    def _exact(self):
        _require(self.sequence.prospect_ref == self.prospect_ref, "SALES_SEQUENCE_PROSPECT_MISMATCH")
        _require(self.to_address.lower() != self.from_address.lower(), "SALES_CONTACT_IDENTITY_INVALID")
        _require(self.purpose != "billing_recovery" or self.billing_guard is not None, "SALES_BILLING_GUARD_REQUIRED")
        _require((self.thread_ref is None) == (self.parent_message_id is None), "SALES_THREAD_PARENT_REQUIRED")
        if self.parent_message_id is not None:
            _require(re.fullmatch(r"<[^<>\s@]+@[^<>\s@]+>", self.parent_message_id) is not None,
                     "SALES_PARENT_MESSAGE_ID_INVALID")
        return self

    @field_validator("crm_conversation_id", "crm_channel_identity_id", "crm_contact_id", mode="before")
    @classmethod
    def _crm_ids(cls, value: Any) -> UUID:
        return value if isinstance(value, UUID) else UUID(value)


def bind_sales_playbook(playbook: Any, binding: Any, bundle: Any) -> tuple[SalesPlaybook, SalesProspectBinding]:
    """Bind an existing prospect's configuration to this exact company bundle."""
    playbook = SalesPlaybook.model_validate(detached(playbook))
    binding = SalesProspectBinding.model_validate(detached(binding))
    _require(playbook.spec.company_ref == bundle.company_ref
             and playbook.spec.scope.model_dump(mode="json") == {**bundle.scope, "actor_ref": bundle.actor_ref},
             "SALES_PLAYBOOK_SCOPE_MISMATCH")
    _require(bundle.pipeline_plan is not None and playbook.pipeline_plan.plan_digest == bundle.pipeline_plan.plan_digest,
             "SALES_PLAYBOOK_PLAN_MISMATCH")
    _require(binding.playbook_ref == playbook.spec.playbook_ref, "SALES_PLAYBOOK_BINDING_MISMATCH")
    _require(binding.sequence == playbook.sequence_for(binding.prospect_ref, starts_at=binding.sequence.starts_at),
             "SALES_SEQUENCE_BINDING_MISMATCH")
    return playbook, binding


__all__ = ["SalesPlaybookError", "SalesOffer", "SalesGoals", "SalesEmailTemplate", "SalesPlaybookSpec",
           "SalesPlaybook", "SalesBillingGuard", "SalesProspectBinding", "compile_sales_playbook", "bind_sales_playbook"]
