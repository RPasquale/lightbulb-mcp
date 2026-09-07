"""Typed design contract for the quarantined Verified Improvement 0.3 loop.

The lifecycle shape remains available for design and validation. Its reviewed
Spring source authority is not present in this candidate, so no SDK, Agent, MCP,
ChatGPT, or hosted HTTP entrypoint may start or advance it. No contract value in
this module authorizes a merge, deployment, publication, connector, or provider
effect.
"""

from __future__ import annotations

from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from lightbulb.economic_spine_runs import EconomicSpineRun


VERIFIED_IMPROVEMENT_LOOP_REF = (
    "workflow.verified_evidence_to_publish_approval"
)
VERIFIED_IMPROVEMENT_CERTIFICATION_VERSION = "0.3.0"
VERIFIED_IMPROVEMENT_EXECUTION_VERSION = "0.1.0"
VERIFIED_IMPROVEMENT_CONTRACT_SCHEMA = (
    "lightbulb.verified_improvement_contract.v3"
)
VERIFIED_IMPROVEMENT_AVAILABILITY = "QUARANTINED_SOURCE_AUTHORITY_UNAVAILABLE"

VerifiedImprovementState = Literal[
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


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid", frozen=True, populate_by_name=True, serialize_by_alias=True
    )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


class VerifiedImprovementStart(_StrictModel):
    """Start from one retained, current measured-outcome set."""

    measurement_set_id: UUID
    command_id: UUID
    model_execution_run_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=512,
        description="Ignored legacy correlation hint; Spring mints runtime authority.",
    )

    @model_validator(mode="after")
    def _exact_execution_identity(self) -> "VerifiedImprovementStart":
        if self.model_execution_run_id is not None and (
            self.model_execution_run_id != self.model_execution_run_id.strip()
            or any(ord(character) < 32 for character in self.model_execution_run_id)
        ):
            raise ValueError("model_execution_run_id must be exact")
        return self


class VerifiedImprovementSourceCommand(_StrictModel):
    """One idempotent command over one opaque, server-resolved source identity."""

    source_record_id: UUID
    command_id: UUID


class VerifiedImprovementContract(_StrictModel):
    """Versioned semantic contract shared by SDK, Agents, MCP, and ChatGPT."""

    schema_id: Literal["lightbulb.verified_improvement_contract.v3"] = Field(
        alias="schema"
    )
    loop_ref: Literal["workflow.verified_evidence_to_publish_approval"]
    certification_version: Literal["0.3.0"]
    execution_version: Literal["0.1.0"]
    ordered_states: tuple[VerifiedImprovementState, ...]
    reviewed_harnesses: tuple[Literal["claude_code", "codex", "cursor"], ...]
    access_surface_independent: Literal[True]
    source_ids_only: Literal[True]
    signed_receipts: tuple[
        Literal[
            "lease",
            "heartbeat",
            "reconnect",
            "cooperative_cancel",
            "usage",
            "artifact",
        ],
        ...,
    ]
    independent_evaluator_required: Literal[True]
    staging_canary_required: Literal[True]
    separate_publish_approval_required: Literal[True]
    terminal_result: Literal["approved_publication_candidate"]
    merge_authorized: Literal[False]
    deploy_authorized: Literal[False]
    external_publish_authorized: Literal[False]
    deadline_seconds: Literal[1209600]
    budget_microusd: Literal[100000000]
    measured_customer_outcomes: tuple[
        Literal[
            "verified_improvement_adoption_rate",
            "artifact_correction_rate",
            "time_to_publish_approval_seconds",
        ],
        ...,
    ]

    @model_validator(mode="after")
    def _exact_deep_loop(self) -> "VerifiedImprovementContract":
        if self.ordered_states != (
            "verified_gap_identified",
            "packet_proposed",
            "implementation_approved",
            "artifact_returned",
            "independent_acceptance_recorded",
            "staging_canary_passed",
            "capability_publish_approved",
        ):
            raise ValueError("Verified Improvement lifecycle is not exact")
        if self.reviewed_harnesses != ("claude_code", "codex", "cursor"):
            raise ValueError("Reviewed coding-harness set is not exact")
        if self.signed_receipts != (
            "lease",
            "heartbeat",
            "reconnect",
            "cooperative_cancel",
            "usage",
            "artifact",
        ):
            raise ValueError("Coding-harness receipt contract is not exact")
        if self.measured_customer_outcomes != (
            "verified_improvement_adoption_rate",
            "artifact_correction_rate",
            "time_to_publish_approval_seconds",
        ):
            raise ValueError("Measured-customer-outcome contract is not exact")
        return self


VERIFIED_IMPROVEMENT_CONTRACT = VerifiedImprovementContract(
    schema=VERIFIED_IMPROVEMENT_CONTRACT_SCHEMA,
    loop_ref=VERIFIED_IMPROVEMENT_LOOP_REF,
    certification_version=VERIFIED_IMPROVEMENT_CERTIFICATION_VERSION,
    execution_version=VERIFIED_IMPROVEMENT_EXECUTION_VERSION,
    ordered_states=(
        "verified_gap_identified",
        "packet_proposed",
        "implementation_approved",
        "artifact_returned",
        "independent_acceptance_recorded",
        "staging_canary_passed",
        "capability_publish_approved",
    ),
    reviewed_harnesses=("claude_code", "codex", "cursor"),
    access_surface_independent=True,
    source_ids_only=True,
    signed_receipts=(
        "lease",
        "heartbeat",
        "reconnect",
        "cooperative_cancel",
        "usage",
        "artifact",
    ),
    independent_evaluator_required=True,
    staging_canary_required=True,
    separate_publish_approval_required=True,
    terminal_result="approved_publication_candidate",
    merge_authorized=False,
    deploy_authorized=False,
    external_publish_authorized=False,
    deadline_seconds=1209600,
    budget_microusd=100000000,
    measured_customer_outcomes=(
        "verified_improvement_adoption_rate",
        "artifact_correction_rate",
        "time_to_publish_approval_seconds",
    ),
)


def parse_verified_improvement_run(value: Any) -> EconomicSpineRun:
    """Validate the shared V1914 projection and its exact improvement identity."""

    run = value if isinstance(value, EconomicSpineRun) else EconomicSpineRun.model_validate(value)
    if run.loop_ref != VERIFIED_IMPROVEMENT_LOOP_REF:
        raise ValueError("Run is not Verified Improvement custody")
    if run.certification_version != VERIFIED_IMPROVEMENT_CERTIFICATION_VERSION:
        raise ValueError("Run is not Verified Improvement certification 0.3.0")
    if run.execution_version != VERIFIED_IMPROVEMENT_EXECUTION_VERSION:
        raise ValueError("Run is not Verified Improvement execution 0.1.0")
    return run


__all__ = [
    "VERIFIED_IMPROVEMENT_AVAILABILITY",
    "VERIFIED_IMPROVEMENT_CERTIFICATION_VERSION",
    "VERIFIED_IMPROVEMENT_CONTRACT",
    "VERIFIED_IMPROVEMENT_CONTRACT_SCHEMA",
    "VERIFIED_IMPROVEMENT_EXECUTION_VERSION",
    "VERIFIED_IMPROVEMENT_LOOP_REF",
    "VerifiedImprovementContract",
    "VerifiedImprovementSourceCommand",
    "VerifiedImprovementStart",
    "VerifiedImprovementState",
    "parse_verified_improvement_run",
]
