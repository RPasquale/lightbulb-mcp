"""Build a finance-close audit packet candidate with outcome evidence.

The primitive binds the exact eight-transition close candidate, final sealed
command, a Spring-reported hosted execution/readback observation, and all nine
lighthouse business outcomes. Structural metrics are recomputed from retained
history. Spring must still authenticate execution and outcome evidence, retain
the packet, and certify any production claim. No close, persistence, connector,
provider, journal, approval, or outcome-ledger write occurs here.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Annotated, Any, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from lightbulb.finance_close_lifecycle import (
    PeriodCloseLifecycleSnapshot,
    materialize_period_close_candidate,
    period_close_scope_digest,
)
from lightbulb.finance_close_period_transition import (
    ClosePeriodTransitionCommandResult,
    PrepareClosePeriodTransitionCommandInput,
    PrepareClosePeriodTransitionCommandPrimitive,
    prepare_close_period_transition_command,
)
from lightbulb.finance_close_workspace import FinanceCloseWorkspace
from lightbulb.operational_readiness import BusinessOutcomeMeasurement
from lightbulb.primitive_runtime import (
    BusinessProcessPrimitive,
    PrimitiveBlocker,
    PrimitiveEvent,
    PrimitiveEvidence,
    PrimitiveEvidenceVerificationGrade,
    PrimitiveExecutionContext,
    PrimitiveExecutionResult,
    PrimitiveExecutionStatus,
)

FINANCE_CLOSE_AUDIT_PACKET_INPUT_SCHEMA = (
    "lightbulb.finance_close_audit_packet_input.v1"
)
FINANCE_CLOSE_AUDIT_PACKET_RESULT_SCHEMA = (
    "lightbulb.finance_close_audit_packet_result.v1"
)
FINANCE_CLOSE_EXECUTION_OBSERVATION_SCHEMA = (
    "lightbulb.finance_close_execution_observation.v1"
)

_ZERO_DIGEST = "0" * 64
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@+\-]{0,199}$"
_TRANSITION_KINDS = (
    "open_period",
    "capture_trial_balance",
    "reconcile_accounts",
    "record_adjusting_entries",
    "lock_subledgers",
    "consolidate",
    "approve_close",
    "close_period",
)
_OUTCOME_CONTRACT = {
    "close_cycle_duration": ("period_close_cycle_minutes", "decrease", "minutes"),
    "reconciliation_coverage": (
        "reconciliation_coverage_percent",
        "increase",
        "percent",
    ),
    "unresolved_exception_count": (
        "unresolved_close_exception_count",
        "decrease",
        "count",
    ),
    "manual_touch_count": ("close_manual_touch_count", "decrease", "count"),
    "adjustment_rework_count": (
        "adjustment_rework_count",
        "decrease",
        "count",
    ),
    "approval_latency": ("close_approval_latency_minutes", "decrease", "minutes"),
    "post_readback_success": (
        "close_post_readback_success_percent",
        "increase",
        "percent",
    ),
    "ambiguity_resolution_time": (
        "close_ambiguity_resolution_minutes",
        "decrease",
        "minutes",
    ),
    "duplicate_external_effect_count": (
        "duplicate_external_effect_count",
        "decrease",
        "count",
    ),
}


def _visible_ref(value: str) -> str:
    if value != value.strip() or any(ord(character) < 33 for character in value):
        raise ValueError("references must contain visible non-whitespace characters")
    return value


OpaqueRef = Annotated[
    str,
    StringConstraints(pattern=_REF_PATTERN),
    AfterValidator(_visible_ref),
]
Sha256Digest = Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)]


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        revalidate_instances="always",
        serialize_by_alias=True,
        strict=True,
    )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def _stable_digest(value: Any) -> str:
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _timestamp(value: str, *, field_name: str) -> str:
    if not isinstance(value, str) or value != value.strip():
        raise ValueError(f"{field_name} must be a trimmed UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field_name} must be valid ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field_name} must include a UTC offset")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parsed_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _minutes_between(start: str, end: str) -> Decimal:
    seconds = Decimal(
        str((_parsed_timestamp(end) - _parsed_timestamp(start)).total_seconds())
    )
    return (seconds / Decimal(60)).normalize()


class FinanceCloseExecutionObservation(_StrictModel):
    schema_id: Literal["lightbulb.finance_close_execution_observation.v1"] = Field(
        default=FINANCE_CLOSE_EXECUTION_OBSERVATION_SCHEMA,
        alias="schema",
    )
    issuer_ref: OpaqueRef
    environment_ref: OpaqueRef
    environment_class: Literal["test", "canary", "production"]
    workspace_digest: Sha256Digest
    scope_digest: Sha256Digest
    lifecycle_version: Literal[8] = 8
    lifecycle_state_digest: Sha256Digest
    close_candidate_ref: OpaqueRef
    command_request_digest: Sha256Digest
    hosted_execution_ref: OpaqueRef
    execution_receipt_ref: OpaqueRef
    execution_receipt_digest: Sha256Digest
    persistence_receipt_ref: OpaqueRef
    persistence_receipt_digest: Sha256Digest
    period_state_ref: OpaqueRef
    period_state_digest: Sha256Digest
    readback_observation_ref: OpaqueRef
    readback_observation_digest: Sha256Digest
    execution_state: Literal["reported_applied"] = "reported_applied"
    persistence_state: Literal["reported_committed"] = "reported_committed"
    period_state: Literal["reported_closed"] = "reported_closed"
    independent_readback_verified: Literal[True] = True
    ambiguity_state: Literal["none"] = "none"
    duplicate_external_effect_count: Literal[0] = 0
    closed_through_at: str
    executed_at: str
    observed_at: str
    production_certified: Literal[False] = False

    @field_validator("closed_through_at", "executed_at", "observed_at")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=info.field_name)

    @model_validator(mode="after")
    def _observation_follows_execution(self) -> "FinanceCloseExecutionObservation":
        if _parsed_timestamp(self.observed_at) < _parsed_timestamp(self.executed_at):
            raise ValueError("close execution observation cannot precede execution")
        return self

    def evidence_digest(self) -> str:
        return _stable_digest(self.to_dict())


class FinanceCloseAuditPacketInput(_StrictModel):
    schema_id: Literal["lightbulb.finance_close_audit_packet_input.v1"] = Field(
        default=FINANCE_CLOSE_AUDIT_PACKET_INPUT_SCHEMA,
        alias="schema",
    )
    packet_ref: OpaqueRef
    workspace: FinanceCloseWorkspace
    final_transition: ClosePeriodTransitionCommandResult
    lifecycle_snapshot: PeriodCloseLifecycleSnapshot
    execution_observation: FinanceCloseExecutionObservation
    business_outcomes: tuple[BusinessOutcomeMeasurement, ...] = Field(
        min_length=len(_OUTCOME_CONTRACT),
        max_length=len(_OUTCOME_CONTRACT),
    )
    prepared_by_ref: OpaqueRef
    prepared_at: str

    @field_validator(
        "workspace",
        "final_transition",
        "lifecycle_snapshot",
        mode="before",
    )
    @classmethod
    def _detached_sources(cls, value: Any, info: Any) -> Any:
        model_type: type[BaseModel] = {
            "workspace": FinanceCloseWorkspace,
            "final_transition": ClosePeriodTransitionCommandResult,
            "lifecycle_snapshot": PeriodCloseLifecycleSnapshot,
        }[info.field_name]
        if isinstance(value, model_type):
            return value
        if isinstance(value, dict):
            return model_type.model_validate_json(json.dumps(value, default=str))
        return value

    @field_validator("business_outcomes", mode="before")
    @classmethod
    def _outcomes_tuple(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("prepared_at")
    @classmethod
    def _prepared_at(cls, value: str) -> str:
        return _timestamp(value, field_name="prepared_at")

    @model_validator(mode="after")
    def _exact_complete_close(self) -> "FinanceCloseAuditPacketInput":
        workspace = self.workspace
        transition = self.final_transition
        snapshot = self.lifecycle_snapshot
        observation = self.execution_observation
        scope = workspace.close_scope
        materialized = materialize_period_close_candidate(transition.lifecycle_input)
        if (
            materialized.snapshot is None
            or not materialized.candidate_validated
            or materialized.snapshot != snapshot
            or snapshot.version != 8
            or snapshot.status != "close_candidate_validated"
            or snapshot.close_candidate is None
            or tuple(item.command.kind for item in snapshot.transition_history)
            != _TRANSITION_KINDS
        ):
            raise ValueError(
                "the exact complete version-eight close candidate is required"
            )
        if (
            transition.workspace_ref != workspace.workspace_ref
            or transition.workspace_revision != workspace.workspace_revision
            or transition.workspace_digest != workspace.content_digest
            or transition.lifecycle_input.snapshot is None
            or transition.lifecycle_input.snapshot.scope != scope
            or transition.lifecycle_input.command.package != snapshot.close_candidate
        ):
            raise ValueError("final transition must bind the exact close workspace")
        command = transition.lifecycle_input.command
        if (
            observation.issuer_ref != scope.spring_authority_ref
            or observation.workspace_digest != workspace.content_digest
            or observation.scope_digest != period_close_scope_digest(scope)
            or observation.lifecycle_state_digest != snapshot.state_digest
            or observation.close_candidate_ref
            != snapshot.close_candidate.close_candidate_ref
            or observation.command_request_digest != command.request_digest
            or observation.closed_through_at != scope.period_ended_at
        ):
            raise ValueError(
                "execution observation must bind the exact complete close candidate"
            )
        if _parsed_timestamp(observation.executed_at) < _parsed_timestamp(
            command.occurred_at
        ):
            raise ValueError("reported close execution cannot precede its command")
        if _parsed_timestamp(self.prepared_at) < _parsed_timestamp(
            observation.observed_at
        ):
            raise ValueError("audit packet cannot precede execution observation")

        refs = tuple(item.outcome_ref for item in self.business_outcomes)
        if refs != tuple(sorted(_OUTCOME_CONTRACT)) or len(set(refs)) != len(refs):
            raise ValueError("all nine close outcomes must use exact canonical order")
        outcomes = {item.outcome_ref: item for item in self.business_outcomes}
        for outcome_ref, contract in _OUTCOME_CONTRACT.items():
            measurement = outcomes[outcome_ref]
            if (
                measurement.metric_name,
                measurement.direction,
                measurement.unit,
            ) != contract:
                raise ValueError(
                    f"business outcome {outcome_ref} must use its exact metric contract"
                )
            measured_at = _parsed_timestamp(measurement.measured_at)
            if measured_at < _parsed_timestamp(
                observation.executed_at
            ) or measured_at > _parsed_timestamp(self.prepared_at):
                raise ValueError(
                    "business outcomes must be measured after execution and before packet preparation"
                )
            if measurement.source_system_ref != "spring-business-outcomes-ledger":
                raise ValueError("business outcomes require the Spring outcome ledger")
            for evidence in measurement.evidence_refs:
                if (
                    evidence.issuer_ref != scope.spring_authority_ref
                    or evidence.subject_ref != observation.close_candidate_ref
                    or evidence.verification_grade
                    not in {
                        PrimitiveEvidenceVerificationGrade.ATTESTED,
                        PrimitiveEvidenceVerificationGrade.VERIFIED,
                    }
                    or _parsed_timestamp(evidence.observed_at) > measured_at
                ):
                    raise ValueError(
                        "business outcome evidence must be exact, scoped, and attested"
                    )

        reconciliation_count = len(
            snapshot.reconciliations.account_reconciliations
        ) + len(snapshot.reconciliations.subledger_reconciliations)
        derived = {
            "close_cycle_duration": _minutes_between(
                snapshot.transition_history[0].command.occurred_at,
                observation.executed_at,
            ),
            "reconciliation_coverage": Decimal(100 if reconciliation_count else 0),
            "unresolved_exception_count": Decimal(0),
            "approval_latency": _minutes_between(
                snapshot.consolidation.consolidated_at,
                snapshot.close_approval.approved_at,
            ),
            "post_readback_success": Decimal(100),
            "ambiguity_resolution_time": Decimal(0),
            "duplicate_external_effect_count": Decimal(0),
        }
        for outcome_ref, expected in derived.items():
            if outcomes[outcome_ref].observed != expected:
                raise ValueError(
                    f"business outcome {outcome_ref} must equal retained close evidence"
                )
        return self


class FinanceCloseTransitionAuditRecord(_StrictModel):
    sequence: int = Field(ge=1, le=8)
    kind: OpaqueRef
    transition_ref: OpaqueRef
    occurred_at: str
    requested_by_ref: OpaqueRef
    command_request_digest: Sha256Digest
    command_content_digest: Sha256Digest
    evidence_digest: Sha256Digest
    transition_digest: Sha256Digest

    @field_validator("occurred_at")
    @classmethod
    def _occurred_at(cls, value: str) -> str:
        return _timestamp(value, field_name="occurred_at")


class FinanceCloseOutcomeSummary(_StrictModel):
    outcome_ref: OpaqueRef
    metric_name: OpaqueRef
    baseline: Decimal
    observed: Decimal
    target: Decimal
    target_met: bool
    improved_from_baseline: bool
    measurement_digest: Sha256Digest

    @field_validator("baseline", "observed", "target", mode="before")
    @classmethod
    def _decimal_metrics(cls, value: Any) -> Decimal:
        if isinstance(value, bool):
            raise ValueError("outcome metrics must be finite numbers")
        try:
            parsed = Decimal(str(value))
        except (InvalidOperation, ValueError, TypeError) as exc:
            raise ValueError("outcome metrics must be finite numbers") from exc
        if not parsed.is_finite():
            raise ValueError("outcome metrics must be finite numbers")
        return parsed


class FinanceCloseAuditPacketResult(_StrictModel):
    schema_id: Literal["lightbulb.finance_close_audit_packet_result.v1"] = Field(
        default=FINANCE_CLOSE_AUDIT_PACKET_RESULT_SCHEMA,
        alias="schema",
    )
    packet_ref: OpaqueRef
    workspace_ref: OpaqueRef
    workspace_revision: int = Field(ge=1)
    workspace_digest: Sha256Digest
    lifecycle_version: Literal[8] = 8
    lifecycle_state_digest: Sha256Digest
    final_command_request_digest: Sha256Digest
    execution_observation_digest: Sha256Digest
    transition_records: tuple[FinanceCloseTransitionAuditRecord, ...] = Field(
        min_length=8, max_length=8
    )
    outcome_summaries: tuple[FinanceCloseOutcomeSummary, ...] = Field(
        min_length=len(_OUTCOME_CONTRACT),
        max_length=len(_OUTCOME_CONTRACT),
    )
    prepared_by_ref: OpaqueRef
    prepared_at: str
    transition_evidence_digest: Sha256Digest
    business_outcome_digest: Sha256Digest
    packet_digest: Sha256Digest = _ZERO_DIGEST
    execution_authentication_state: Literal["spring_revalidation_required"] = (
        "spring_revalidation_required"
    )
    business_outcome_authentication_state: Literal["spring_revalidation_required"] = (
        "spring_revalidation_required"
    )
    audit_custody_state: Literal["spring_retention_required"] = (
        "spring_retention_required"
    )
    structural_close_lifecycle_complete: Literal[True] = True
    hosted_execution_reported: Literal[True] = True
    production_certified: Literal[False] = False
    period_close_authorized: Literal[False] = False
    persistence_authorized: Literal[False] = False
    connector_calls_authorized: Literal[False] = False

    @field_validator("transition_records", "outcome_summaries", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("prepared_at")
    @classmethod
    def _prepared_at(cls, value: str) -> str:
        return _timestamp(value, field_name="prepared_at")

    def digest_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"packet_digest"},
            exclude_none=True,
        )

    @model_validator(mode="after")
    def _sealed_packet(self) -> "FinanceCloseAuditPacketResult":
        if tuple(item.sequence for item in self.transition_records) != tuple(
            range(1, 9)
        ):
            raise ValueError("audit transition records must be contiguous")
        if tuple(item.kind for item in self.transition_records) != _TRANSITION_KINDS:
            raise ValueError(
                "audit transition records must retain exact lifecycle order"
            )
        if self.transition_evidence_digest != _stable_digest(
            [item.to_dict() for item in self.transition_records]
        ):
            raise ValueError("transition_evidence_digest must bind exact records")
        if self.business_outcome_digest != _stable_digest(
            [item.to_dict() for item in self.outcome_summaries]
        ):
            raise ValueError("business_outcome_digest must bind exact outcomes")
        expected = _stable_digest(self.digest_payload())
        if self.packet_digest not in {_ZERO_DIGEST, expected}:
            raise ValueError("packet_digest does not match close audit packet")
        object.__setattr__(self, "packet_digest", expected)
        return self


def _outcome_summary(
    measurement: BusinessOutcomeMeasurement,
) -> FinanceCloseOutcomeSummary:
    target_met = (
        measurement.observed >= measurement.target
        if measurement.direction == "increase"
        else measurement.observed <= measurement.target
    )
    improved = (
        measurement.observed > measurement.baseline
        if measurement.direction == "increase"
        else measurement.observed < measurement.baseline
    )
    return FinanceCloseOutcomeSummary(
        outcome_ref=measurement.outcome_ref,
        metric_name=measurement.metric_name,
        baseline=measurement.baseline,
        observed=measurement.observed,
        target=measurement.target,
        target_met=target_met,
        improved_from_baseline=improved,
        measurement_digest=_stable_digest(measurement.to_dict()),
    )


def build_finance_close_audit_packet(
    inputs: FinanceCloseAuditPacketInput,
) -> FinanceCloseAuditPacketResult:
    inputs = FinanceCloseAuditPacketInput.model_validate(inputs)
    snapshot = inputs.lifecycle_snapshot
    records = tuple(
        FinanceCloseTransitionAuditRecord(
            sequence=index,
            kind=record.command.kind,
            transition_ref=record.command.transition_ref,
            occurred_at=record.command.occurred_at,
            requested_by_ref=record.command.requested_by_ref,
            command_request_digest=record.command.request_digest,
            command_content_digest=record.command_content_digest,
            evidence_digest=record.evidence_digest,
            transition_digest=record.transition_digest,
        )
        for index, record in enumerate(snapshot.transition_history, start=1)
    )
    outcomes = tuple(_outcome_summary(item) for item in inputs.business_outcomes)
    return FinanceCloseAuditPacketResult(
        packet_ref=inputs.packet_ref,
        workspace_ref=inputs.workspace.workspace_ref,
        workspace_revision=inputs.workspace.workspace_revision,
        workspace_digest=inputs.workspace.content_digest,
        lifecycle_state_digest=snapshot.state_digest,
        final_command_request_digest=inputs.final_transition.command_request_digest,
        execution_observation_digest=inputs.execution_observation.evidence_digest(),
        transition_records=records,
        outcome_summaries=outcomes,
        prepared_by_ref=inputs.prepared_by_ref,
        prepared_at=inputs.prepared_at,
        transition_evidence_digest=_stable_digest([item.to_dict() for item in records]),
        business_outcome_digest=_stable_digest([item.to_dict() for item in outcomes]),
    )


def _outcome_evidence(
    *,
    outcome_ref: str,
    close_candidate_ref: str,
    issuer_ref: str,
) -> dict[str, Any]:
    return {
        "evidence_ref": f"evidence:close-outcome:{outcome_ref}",
        "kind": "business_outcome",
        "issuer_ref": issuer_ref,
        "subject_ref": close_candidate_ref,
        "sha256": _stable_digest({"outcome_ref": outcome_ref}),
        "observed_at": "2026-09-01T15:04:00Z",
        "effective_at": "2026-09-01T15:00:00Z",
        "verification_grade": "verified",
        "classification": "restricted",
        "retention_policy": "finance-seven-years",
        "jurisdiction": "US",
    }


def _example_inputs() -> dict[str, Any]:
    transition_inputs = PrepareClosePeriodTransitionCommandInput.model_validate(
        PrepareClosePeriodTransitionCommandPrimitive.example_inputs
    )
    final_transition = prepare_close_period_transition_command(transition_inputs)
    lifecycle = materialize_period_close_candidate(final_transition.lifecycle_input)
    if lifecycle.snapshot is None:  # pragma: no cover - invariant guard
        raise RuntimeError("example final close transition was not materialized")
    workspace = transition_inputs.workspace
    snapshot = lifecycle.snapshot
    scope = workspace.close_scope
    close_candidate_ref = snapshot.close_candidate.close_candidate_ref
    observation = {
        "issuer_ref": scope.spring_authority_ref,
        "environment_ref": "canary:finance-lighthouse",
        "environment_class": "canary",
        "workspace_digest": workspace.content_digest,
        "scope_digest": period_close_scope_digest(scope),
        "lifecycle_state_digest": snapshot.state_digest,
        "close_candidate_ref": close_candidate_ref,
        "command_request_digest": final_transition.command_request_digest,
        "hosted_execution_ref": "hosted-close-execution:2026-08",
        "execution_receipt_ref": "receipt:hosted-close:2026-08",
        "execution_receipt_digest": _stable_digest({"execution": "reported-applied"}),
        "persistence_receipt_ref": "receipt:close-persistence:2026-08",
        "persistence_receipt_digest": _stable_digest(
            {"persistence": "reported-committed"}
        ),
        "period_state_ref": "period-state:2026-08:closed",
        "period_state_digest": _stable_digest({"period_state": "reported-closed"}),
        "readback_observation_ref": "readback:period-state:2026-08",
        "readback_observation_digest": _stable_digest({"readback": "reported-closed"}),
        "closed_through_at": scope.period_ended_at,
        "executed_at": "2026-09-01T15:00:00Z",
        "observed_at": "2026-09-01T15:01:00Z",
    }
    values = {
        "adjustment_rework_count": ("6", "1", "1"),
        "ambiguity_resolution_time": ("60", "0", "15"),
        "approval_latency": ("120", "20", "30"),
        "close_cycle_duration": ("900", "148", "600"),
        "duplicate_external_effect_count": ("1", "0", "0"),
        "manual_touch_count": ("40", "8", "10"),
        "post_readback_success": ("95", "100", "99"),
        "reconciliation_coverage": ("85", "100", "99"),
        "unresolved_exception_count": ("12", "0", "0"),
    }
    outcomes = []
    for outcome_ref in sorted(_OUTCOME_CONTRACT):
        metric_name, direction, unit = _OUTCOME_CONTRACT[outcome_ref]
        baseline, observed, target = values[outcome_ref]
        outcomes.append(
            {
                "outcome_ref": outcome_ref,
                "metric_name": metric_name,
                "direction": direction,
                "unit": unit,
                "baseline": baseline,
                "observed": observed,
                "target": target,
                "sample_count": 1,
                "measured_at": "2026-09-01T15:05:00Z",
                "source_system_ref": "spring-business-outcomes-ledger",
                "evidence_refs": [
                    _outcome_evidence(
                        outcome_ref=outcome_ref,
                        close_candidate_ref=close_candidate_ref,
                        issuer_ref=scope.spring_authority_ref,
                    )
                ],
            }
        )
    return {
        "packet_ref": "audit-packet:finance-close:2026-08",
        "workspace": workspace.to_dict(),
        "final_transition": final_transition.to_dict(),
        "lifecycle_snapshot": snapshot.to_dict(),
        "execution_observation": observation,
        "business_outcomes": outcomes,
        "prepared_by_ref": "controller:audit-packet-preparer",
        "prepared_at": "2026-09-01T15:10:00Z",
    }


class BuildFinanceCloseAuditPacketPrimitive(
    BusinessProcessPrimitive[
        FinanceCloseAuditPacketInput,
        FinanceCloseAuditPacketResult,
    ]
):
    primitive_ref = "finance.build_close_audit_packet"
    version = "1.0.0"
    title = "Build complete close audit packet candidate"
    description = (
        "Bind all eight close transitions, the final command, a Spring execution/readback "
        "observation, and all nine business outcomes without certifying production or "
        "writing an audit or outcome ledger."
    )
    input_model = FinanceCloseAuditPacketInput
    output_model = FinanceCloseAuditPacketResult
    connector_tools = ()
    risk_level = "high"
    approval_required = False
    example_inputs = _example_inputs()
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False

    def implementation_contract(self) -> dict[str, Any]:
        contract = super().implementation_contract()
        contract["effect_boundary"] = {
            "connector_operations": 0,
            "provider_calls": 0,
            "period_closes": 0,
            "audit_packet_writes": 0,
            "outcome_ledger_writes": 0,
            "production_certifications": 0,
            "persistence_writes": 0,
        }
        contract["authority_boundary"] = (
            "Spring must authenticate execution, readback, outcome measurements, and "
            "evidence custody before persisting or certifying this packet"
        )
        return contract

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: FinanceCloseAuditPacketInput,
    ) -> PrimitiveExecutionResult[FinanceCloseAuditPacketResult]:
        scope = inputs.workspace.close_scope
        if (
            context.scope.tenant_ref != scope.tenant_ref
            or context.scope.company_ref != scope.company_ref
            or context.scope.project_ref != scope.project_ref
            or context.scope.project_id != scope.project_id
            or context.scope.actor_ref != inputs.prepared_by_ref
        ):
            blocker = PrimitiveBlocker(
                code="finance_close_audit_packet_scope_mismatch",
                message=(
                    "Runtime tenant, company, project, UUID, and preparer must exactly "
                    "match the close audit packet request."
                ),
            )
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.BLOCKED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary=blocker.message,
                blockers=[blocker],
            )
        output = build_finance_close_audit_packet(inputs)
        return PrimitiveExecutionResult(
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                "Built a complete structural close audit packet candidate; Spring "
                "execution, outcome, custody, persistence, and certification authority remain."
            ),
            output=output,
            events=[
                PrimitiveEvent(
                    type="finance.close_audit_packet_candidate_built",
                    payload={
                        "packet_ref": output.packet_ref,
                        "workspace_ref": output.workspace_ref,
                        "lifecycle_state_digest": output.lifecycle_state_digest,
                        "transition_evidence_digest": output.transition_evidence_digest,
                        "business_outcome_digest": output.business_outcome_digest,
                        "packet_digest": output.packet_digest,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="finance_close_audit_packet_candidate",
                    summary=(
                        "All close transitions and outcomes are content-bound; Spring "
                        "authentication, retention, and certification remain required."
                    ),
                    labels=[
                        "monthly_close",
                        "structural_candidate_only",
                        "nine_business_outcomes",
                        "spring_revalidation_required",
                    ],
                    refs={"packet_digest": output.packet_digest},
                )
            ],
        )


FINANCE_CLOSE_AUDIT_PACKET_EXECUTABLE_PRIMITIVES: tuple[
    BusinessProcessPrimitive[Any, Any], ...
] = (BuildFinanceCloseAuditPacketPrimitive(),)


__all__ = [
    "FINANCE_CLOSE_AUDIT_PACKET_INPUT_SCHEMA",
    "FINANCE_CLOSE_AUDIT_PACKET_RESULT_SCHEMA",
    "FINANCE_CLOSE_EXECUTION_OBSERVATION_SCHEMA",
    "BuildFinanceCloseAuditPacketPrimitive",
    "FINANCE_CLOSE_AUDIT_PACKET_EXECUTABLE_PRIMITIVES",
    "FinanceCloseAuditPacketInput",
    "FinanceCloseAuditPacketResult",
    "FinanceCloseExecutionObservation",
    "FinanceCloseOutcomeSummary",
    "FinanceCloseTransitionAuditRecord",
    "build_finance_close_audit_packet",
]
