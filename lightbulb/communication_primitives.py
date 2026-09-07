"""Proposal-only executable primitive for a governed CRM conversation turn.

The primitive deliberately plans with opaque CRM references and content
digests.  Private addresses and message text are resolved only by the trusted
host when :mod:`lightbulb.communication_materializer` executes the plan.
"""

from __future__ import annotations

import hashlib
import json
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from lightbulb.communication_contracts import CommunicationPurpose
from lightbulb.primitive_runtime import (
    BusinessProcessPrimitive,
    PrimitiveEvent,
    PrimitiveEvidence,
    PrimitiveExecutionContext,
    PrimitiveExecutionResult,
    PrimitiveExecutionStatus,
)


COMMUNICATION_TURN_PLAN_SCHEMA = "lightbulb.communication_turn_plan.v1"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"


class CommunicationTurnKind(str, Enum):
    REPLY_TO_INBOUND = "reply_to_inbound"
    OUTBOUND_FOLLOW_UP = "outbound_follow_up"


class CommunicationTurnPhase(str, Enum):
    RESOLVE_CRM_CONTEXT = "resolve_crm_context"
    EVALUATE_CONTACT_POLICY = "evaluate_contact_policy"
    DRAFT_PRIVATE_MESSAGE = "draft_private_message"
    OBTAIN_CONTENT_BOUND_APPROVAL = "obtain_content_bound_approval"
    RESERVE_CONTACT_SLOT = "reserve_contact_slot"
    DISPATCH_GOVERNED_REPLY = "dispatch_governed_reply"
    OBSERVE_PROVIDER_THREAD = "observe_provider_thread"
    CLASSIFY_VERIFIED_REPLY = "classify_verified_reply"
    APPEND_CRM_TOUCHPOINTS = "append_crm_touchpoints"


class PlanCrmConversationTurnInput(BaseModel):
    """Opaque, deterministic inputs for one supported email-provider tracer."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    analysis_as_of: str
    plan_ref: str = Field(min_length=1, max_length=160)
    objective_ref: str = Field(min_length=1, max_length=200)
    objective_digest: str = Field(pattern=_SHA256_PATTERN)
    turn_kind: CommunicationTurnKind
    purpose: CommunicationPurpose
    provider: Literal["gmail", "outlook"] = "gmail"
    crm_conversation_ref: str = Field(min_length=1, max_length=200)
    crm_contact_ref: str = Field(min_length=1, max_length=200)
    source_message_ref: str | None = Field(default=None, max_length=200)
    source_message_digest: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    connector_account_ref: str = Field(min_length=1, max_length=200)
    growth_source_ref: str | None = Field(default=None, max_length=200)
    growth_source_digest: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )

    @field_validator("analysis_as_of")
    @classmethod
    def _utc_timestamp(cls, value: str) -> str:
        from datetime import datetime, timezone

        clean = value.strip()
        try:
            parsed = datetime.fromisoformat(clean.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("analysis_as_of must be valid ISO-8601") from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("analysis_as_of must include a UTC offset")
        return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    @field_validator(
        "plan_ref",
        "objective_ref",
        "crm_conversation_ref",
        "crm_contact_ref",
        "source_message_ref",
        "connector_account_ref",
        "growth_source_ref",
    )
    @classmethod
    def _opaque_refs(cls, value: str | None) -> str | None:
        if value is None:
            return None
        clean = value.strip()
        if (
            clean != value
            or not clean
            or any(ord(character) < 33 for character in clean)
        ):
            raise ValueError(
                "references must contain visible non-whitespace characters"
            )
        return clean

    @model_validator(mode="after")
    def _paired_sources(self) -> "PlanCrmConversationTurnInput":
        if (self.source_message_ref is None) != (self.source_message_digest is None):
            raise ValueError(
                "source message reference and digest must be supplied together"
            )
        if self.turn_kind == CommunicationTurnKind.REPLY_TO_INBOUND and (
            self.source_message_ref is None
        ):
            raise ValueError(
                "reply_to_inbound requires a source message reference and digest"
            )
        if (self.growth_source_ref is None) != (self.growth_source_digest is None):
            raise ValueError(
                "Growth source reference and digest must be supplied together"
            )
        return self


class CommunicationTurnPlan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_id: Literal["lightbulb.communication_turn_plan.v1"] = Field(
        default=COMMUNICATION_TURN_PLAN_SCHEMA,
        alias="schema",
    )
    plan_ref: str
    plan_digest: str = Field(pattern=_SHA256_PATTERN)
    analysis_as_of: str
    objective_ref: str
    objective_digest: str = Field(pattern=_SHA256_PATTERN)
    turn_kind: CommunicationTurnKind
    purpose: CommunicationPurpose
    channel: Literal["email"] = "email"
    provider: Literal["gmail", "outlook"] = "gmail"
    crm_conversation_ref: str
    crm_contact_ref: str
    source_message_ref: str | None = None
    source_message_digest: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    connector_account_ref: str
    growth_source_ref: str | None = None
    growth_source_digest: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    phases: tuple[CommunicationTurnPhase, ...]
    required_capabilities: tuple[str, ...]
    durable_private_content_allowed: Literal[False] = False
    live_systems_changed: Literal[False] = False

    @model_validator(mode="after")
    def _digest_is_canonical(self) -> "CommunicationTurnPlan":
        expected = _plan_digest(
            self.model_dump(
                mode="json",
                by_alias=True,
                exclude={"plan_digest"},
            )
        )
        if self.plan_digest != expected:
            raise ValueError("communication turn plan digest is not canonical")
        return self


_PHASES = tuple(CommunicationTurnPhase)
_COMMON_CAPABILITIES = (
    "crm.resolve_conversation_context",
    "host.evaluate_communication_policy",
    "host.reserve_communication_contact",
    "crm.append_communication_touchpoint",
)
_PROVIDER_CAPABILITIES = {
    "gmail": ("gmail.send_email", "gmail.get_thread"),
    "outlook": ("microsoft.reply_email", "microsoft.get_conversation"),
}
_CAPABILITIES = tuple(
    dict.fromkeys(
        (*_COMMON_CAPABILITIES, *sum(_PROVIDER_CAPABILITIES.values(), ()))
    )
)


def _plan_digest(payload: dict[str, Any]) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def plan_crm_conversation_turn(
    inputs: PlanCrmConversationTurnInput,
) -> CommunicationTurnPlan:
    payload: dict[str, Any] = {
        "schema": COMMUNICATION_TURN_PLAN_SCHEMA,
        "plan_ref": inputs.plan_ref,
        "analysis_as_of": inputs.analysis_as_of,
        "objective_ref": inputs.objective_ref,
        "objective_digest": inputs.objective_digest,
        "turn_kind": inputs.turn_kind.value,
        "purpose": inputs.purpose.value,
        "channel": "email",
        "provider": inputs.provider,
        "crm_conversation_ref": inputs.crm_conversation_ref,
        "crm_contact_ref": inputs.crm_contact_ref,
        "source_message_ref": inputs.source_message_ref,
        "source_message_digest": inputs.source_message_digest,
        "connector_account_ref": inputs.connector_account_ref,
        "growth_source_ref": inputs.growth_source_ref,
        "growth_source_digest": inputs.growth_source_digest,
        "phases": [phase.value for phase in _PHASES],
        "required_capabilities": list(
            (*_COMMON_CAPABILITIES, *_PROVIDER_CAPABILITIES[inputs.provider])
        ),
        "durable_private_content_allowed": False,
        "live_systems_changed": False,
    }
    return CommunicationTurnPlan.model_validate(
        {**payload, "plan_digest": _plan_digest(payload)}
    )


class PlanCrmConversationTurnPrimitive(
    BusinessProcessPrimitive[PlanCrmConversationTurnInput, CommunicationTurnPlan]
):
    """Compose the trusted-host communication loop without dispatching it."""

    primitive_ref = "communication.plan_crm_conversation_turn"
    version = "1.0.0"
    title = "Plan governed CRM conversation turn"
    description = (
        "Plan a provider-selected, policy-gated CRM conversation turn using only opaque "
        "CRM references and content commitments; no connector is invoked."
    )
    input_model = PlanCrmConversationTurnInput
    output_model = CommunicationTurnPlan
    connector_tools: tuple[str, ...] = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs = {
        "analysis_as_of": "2026-08-19T12:00:00Z",
        "plan_ref": "acme-reply-turn-1",
        "objective_ref": "crm-objective-acme-reply",
        "objective_digest": "c" * 64,
        "turn_kind": "reply_to_inbound",
        "purpose": "sales",
        "crm_conversation_ref": "crm-conversation-acme",
        "crm_contact_ref": "crm-contact-acme",
        "source_message_ref": "crm-message-42",
        "source_message_digest": "a" * 64,
        "connector_account_ref": "gmail-sales-primary",
    }

    def implementation_contract(self) -> dict[str, Any]:
        contract = super().implementation_contract()
        contract.update(
            {
                "capability_hints": list(_CAPABILITIES),
                "capability_hints_are_dispatch_authority": False,
                "communication_blueprint": {
                    "phases": [phase.value for phase in _PHASES],
                    "private_values_in_durable_artifacts": False,
                    "crm_is_canonical_customer_timeline": True,
                    "growth_source_is_opaque_and_optional": True,
                    "provider_materializers": {
                        "gmail": "materialize_gmail_communication_turn",
                        "outlook": "materialize_outlook_communication_turn",
                    },
                    "outcome_runtime": "CommunicationRuntime",
                    "omitted_channels": ["slack", "teams", "sms", "voice"],
                },
            }
        )
        return contract

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: PlanCrmConversationTurnInput,
    ) -> PrimitiveExecutionResult[CommunicationTurnPlan]:
        del context
        output = plan_crm_conversation_turn(inputs)
        return PrimitiveExecutionResult[CommunicationTurnPlan](
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                f"Planned a policy-gated {output.provider} CRM turn without "
                "exposing private content or changing a live system."
            ),
            output=output,
            events=[
                PrimitiveEvent(
                    type="communication.turn_planned",
                    payload={
                        "plan_ref": output.plan_ref,
                        "plan_digest": output.plan_digest,
                        "crm_conversation_ref": output.crm_conversation_ref,
                        "live_systems_changed": False,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="communication_turn_plan",
                    summary=(
                        "The SDK compiled an immutable communication plan from opaque "
                        "CRM references and digests without connector traffic."
                    ),
                    refs={"plan_sha256": output.plan_digest},
                )
            ],
        )


__all__ = [
    "COMMUNICATION_TURN_PLAN_SCHEMA",
    "CommunicationTurnKind",
    "CommunicationTurnPhase",
    "CommunicationTurnPlan",
    "PlanCrmConversationTurnInput",
    "PlanCrmConversationTurnPrimitive",
    "plan_crm_conversation_turn",
]
