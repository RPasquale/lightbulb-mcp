"""Typed ID-only projection of Spring's source-bound Economic Spine V2 authority."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


_MODEL_EXECUTION_RUN_ID = (
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)


EconomicSpineLoopRef = Literal[
    "procurement.approved_commitment_to_matched_close",
    "finance.period_reconciliation_approved_close_candidate",
    "workflow.verified_evidence_to_publish_approval",
]

EconomicSpineRunState = Literal[
    "requisition_draft",
    "requisition_pending_approval",
    "spend_commitment_approved",
    "purchase_order_issued",
    "goods_received",
    "matched_procurement_closed",
    "period_open_evidence_pending",
    "period_open_validated",
    "trial_balance_validated",
    "reconciliations_validated",
    "exception_disposition_retained",
    "reconciliation_evidence_custody_sealed",
    "approved_close_review_packet_retained",
    "approved_close_candidate",
    "verified_gap_identified",
    "packet_proposed",
    "implementation_approved",
    "artifact_returned",
    "independent_acceptance_recorded",
    "staging_canary_passed",
    "capability_publish_approved",
    "failed_with_evidence",
    "cancelled_with_evidence",
    "manual_reconciliation_required",
]

EconomicSpineEffectDisposition = Literal[
    "NO_EFFECT",
    "EFFECT_NOT_ATTEMPTED",
    "EFFECT_CONFIRMED_SUCCEEDED",
    "EFFECT_CONFIRMED_FAILED",
    "EFFECT_AMBIGUOUS",
]
EconomicSpineTerminalDisposition = Literal[
    "OPEN", "SUCCEEDED", "FAILED", "CANCELLED", "RECONCILIATION_REQUIRED"
]
EconomicSpineReconciliationDisposition = Literal[
    "CONFIRMED_APPLIED", "CONFIRMED_NOT_APPLIED", "UNRESOLVED"
]

_SUCCESS = {
    "procurement.approved_commitment_to_matched_close":
        "matched_procurement_closed",
    "finance.period_reconciliation_approved_close_candidate":
        "approved_close_candidate",
    "workflow.verified_evidence_to_publish_approval":
        "capability_publish_approved",
}
_PREFIX = {
    "procurement.approved_commitment_to_matched_close": "ppr_",
    "finance.period_reconciliation_approved_close_candidate": "pcr_",
    "workflow.verified_evidence_to_publish_approval": "wir_",
}
_STATES = {
    "procurement.approved_commitment_to_matched_close": {
        "requisition_draft", "requisition_pending_approval",
        "spend_commitment_approved", "purchase_order_issued",
        "goods_received", "matched_procurement_closed",
        "failed_with_evidence", "cancelled_with_evidence",
        "manual_reconciliation_required",
    },
    "finance.period_reconciliation_approved_close_candidate": {
        "period_open_evidence_pending", "period_open_validated",
        "trial_balance_validated", "reconciliations_validated",
        "exception_disposition_retained",
        "reconciliation_evidence_custody_sealed",
        "approved_close_review_packet_retained",
        "approved_close_candidate",
        "failed_with_evidence", "cancelled_with_evidence",
        "manual_reconciliation_required",
    },
    "workflow.verified_evidence_to_publish_approval": {
        "verified_gap_identified", "packet_proposed",
        "implementation_approved", "artifact_returned",
        "independent_acceptance_recorded", "staging_canary_passed",
        "capability_publish_approved", "failed_with_evidence",
        "cancelled_with_evidence", "manual_reconciliation_required",
    },
}


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid", frozen=True, populate_by_name=True, serialize_by_alias=True
    )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


class EconomicSpineRunStart(_StrictModel):
    """Opaque START identities; the trusted source observation is created in Spring."""

    source_observation_id: UUID
    command_id: UUID
    model_execution_run_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=512,
        description="Ignored legacy correlation hint; Spring mints runtime authority.",
    )

    @field_validator("model_execution_run_id")
    @classmethod
    def _exact_model_execution_identity(cls, value: str | None) -> str | None:
        if value is not None and (
            value != value.strip()
            or any(ord(character) < 32 for character in value)
        ):
            raise ValueError("model_execution_run_id must be exact")
        return value


class EconomicSpineRunTransition(_StrictModel):
    """One idempotent command over one immutable server-owned observation."""

    observation_id: UUID
    command_id: UUID


class EconomicSpineRun(_StrictModel):
    schema_id: Literal["lightbulb.economic_spine_run.v2"] = Field(alias="schema")
    run_ref: str = Field(pattern=r"^(ppr|pcr|wir)_[0-9a-f]{32}$")
    loop_ref: EconomicSpineLoopRef
    certification_version: Literal["0.3.0", "0.4.0"]
    execution_version: Literal["0.1.0", "0.2.0"]
    loop_version: Literal["0.1.0", "0.2.0"]
    model_execution_run_id: str = Field(
        min_length=1,
        max_length=512,
        description=(
            "Spring-owned UUID on current runs; legacy terminal reads may retain an old hint."
        ),
    )
    tenant_id: UUID
    company_id: UUID
    project_id: UUID
    source_observation_id: UUID
    state: EconomicSpineRunState
    state_observation_id: UUID
    revision: int = Field(ge=0)
    deadline_at: str
    terminal_success: bool
    terminal: bool
    terminal_disposition: EconomicSpineTerminalDisposition
    economic_closure: EconomicSpineTerminalDisposition
    effect_disposition: EconomicSpineEffectDisposition
    effect_may_have_occurred: bool
    reconciliation_disposition: EconomicSpineReconciliationDisposition | None = None
    reconciliation_observation_id: UUID | None = None
    reconciliation_revision: int | None = Field(default=None, ge=1)
    provider_effect_claimed: bool
    deployment_authorized: Literal[False]
    external_effect_authorized: Literal[False]
    manifest_state_exact: Literal[True]

    @field_validator("deadline_at")
    @classmethod
    def _utc_deadline(cls, value: str) -> str:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("deadline_at must be ISO-8601") from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("deadline_at must include a UTC offset")
        return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    @field_validator("model_execution_run_id")
    @classmethod
    def _exact_model_execution_identity(cls, value: str) -> str:
        if value != value.strip() or any(ord(character) < 32 for character in value):
            raise ValueError("model_execution_run_id must be exact")
        return value

    @model_validator(mode="after")
    def _authority_shape(self) -> "EconomicSpineRun":
        identity = (
            self.certification_version,
            self.execution_version,
            self.loop_version,
        )
        allowed_identities = (
            {("0.3.0", "0.1.0", "0.1.0"), ("0.4.0", "0.2.0", "0.2.0")}
            if self.loop_ref
            == "finance.period_reconciliation_approved_close_candidate"
            else {("0.3.0", "0.1.0", "0.1.0")}
        )
        if identity not in allowed_identities:
            raise ValueError("certification/execution/loop version identity is invalid")
        if not self.run_ref.startswith(_PREFIX[self.loop_ref]):
            raise ValueError("run_ref does not match loop_ref")
        if self.state not in _STATES[self.loop_ref]:
            raise ValueError("state does not belong to loop_ref")
        expected_disposition: EconomicSpineTerminalDisposition = "OPEN"
        if self.state == _SUCCESS[self.loop_ref]:
            expected_disposition = "SUCCEEDED"
        elif self.state == "failed_with_evidence":
            expected_disposition = "FAILED"
        elif self.state == "cancelled_with_evidence":
            expected_disposition = "CANCELLED"
        elif self.state == "manual_reconciliation_required":
            expected_disposition = "RECONCILIATION_REQUIRED"
        if self.terminal_disposition != expected_disposition:
            raise ValueError("terminal disposition differs from the manifest state")
        if self.economic_closure != expected_disposition:
            raise ValueError("economic closure differs from terminal disposition")
        terminal = expected_disposition != "OPEN"
        if (
            not terminal
            and re.fullmatch(_MODEL_EXECUTION_RUN_ID, self.model_execution_run_id) is None
        ):
            raise ValueError(
                "nonterminal economic-spine runs require the retained model execution UUID"
            )
        if self.terminal != terminal or self.terminal_success != (
            expected_disposition == "SUCCEEDED"
        ):
            raise ValueError("terminal flags differ from terminal disposition")
        effect_may_have_occurred = self.effect_disposition in {
            "EFFECT_CONFIRMED_SUCCEEDED", "EFFECT_AMBIGUOUS"
        }
        if self.effect_may_have_occurred != effect_may_have_occurred:
            raise ValueError("effect_may_have_occurred differs from effect custody")
        if self.provider_effect_claimed != (
            self.effect_disposition == "EFFECT_CONFIRMED_SUCCEEDED"
        ):
            raise ValueError("provider effect claim differs from retained confirmation")
        if expected_disposition == "RECONCILIATION_REQUIRED" and (
            self.effect_disposition != "EFFECT_AMBIGUOUS"
        ):
            raise ValueError("manual reconciliation requires an ambiguous effect")
        if expected_disposition == "FAILED" and (
            self.effect_disposition == "EFFECT_AMBIGUOUS"
        ):
            raise ValueError("failure cannot conceal an ambiguous effect")
        if expected_disposition == "CANCELLED" and self.effect_disposition not in {
            "NO_EFFECT", "EFFECT_NOT_ATTEMPTED", "EFFECT_CONFIRMED_FAILED"
        }:
            raise ValueError("cancellation cannot conceal a possible effect")
        reconciliation_fields = (
            self.reconciliation_disposition,
            self.reconciliation_observation_id,
            self.reconciliation_revision,
        )
        if any(item is not None for item in reconciliation_fields) and not all(
            item is not None for item in reconciliation_fields
        ):
            raise ValueError("reconciliation projection must be complete")
        if self.reconciliation_disposition is not None and (
            expected_disposition != "RECONCILIATION_REQUIRED"
        ):
            raise ValueError("only an ambiguity-terminal run can carry reconciliation")
        current_period = (
            self.loop_ref
            == "finance.period_reconciliation_approved_close_candidate"
            and identity == ("0.4.0", "0.2.0", "0.2.0")
        )
        if current_period and (
            self.state == "manual_reconciliation_required"
            or self.effect_disposition == "EFFECT_AMBIGUOUS"
            or any(item is not None for item in reconciliation_fields)
        ):
            raise ValueError(
                "Period Reconciliation 0.4/0.2 cannot carry ambiguity or "
                "reconciliation state"
            )
        return self


__all__ = [
    "EconomicSpineEffectDisposition",
    "EconomicSpineLoopRef",
    "EconomicSpineReconciliationDisposition",
    "EconomicSpineRun",
    "EconomicSpineRunStart",
    "EconomicSpineRunState",
    "EconomicSpineRunTransition",
    "EconomicSpineTerminalDisposition",
]
