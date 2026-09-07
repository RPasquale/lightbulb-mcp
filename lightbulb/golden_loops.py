"""Typed declarations and evidence-bound certification for Golden Operating Loops.

This module is a company-building contract, not an execution authority.  A
manifest names the one canonical workflow that every product surface projects.
Only Spring plus a named operator may attach a certification record after the
existing operational-readiness evaluator has accepted current evidence.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from enum import Enum
from typing import Annotated, Any, Literal

from typing_extensions import Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from lightbulb.connector_execution import ConnectorEffect
from lightbulb.dynamic_workflow_hosts import BUILTIN_DYNAMIC_WORKFLOW_HOST_IDS
from lightbulb.operational_readiness import (
    OperationalReadinessInput,
    OperationalReadinessResult,
    ReadinessGate,
    evaluate_operational_readiness,
)
from lightbulb.primitive_runtime import (
    PrimitiveEvidenceRef,
    PrimitiveEvidenceVerificationGrade,
)


LOOP_CERTIFICATION_MANIFEST_SCHEMA = (
    "lightbulb.loop_certification_manifest.v1"
)
LOOP_CERTIFICATION_RECORD_SCHEMA = "lightbulb.loop_certification_record.v1"
LOOP_CERTIFICATION_CANDIDATE_SCHEMA = (
    "lightbulb.loop_certification_candidate.v1"
)
GOLDEN_LOOP_CATALOG_SCHEMA = "lightbulb.golden_loop_catalog.v1"
SPRING_OPERATOR_CERTIFICATION_PENDING_BLOCKER = (
    "spring_operator_certification_pending"
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SEMVER_RE = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)


def _as_tuple(value: Any) -> Any:
    return tuple(value) if isinstance(value, list) else value


def _stable_digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            default=str,
        ).encode("utf-8")
    ).hexdigest()


def _timestamp(value: str, *, label: str) -> str:
    if value != value.strip():
        raise ValueError(f"{label} must not contain surrounding whitespace")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be valid ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{label} must include a UTC offset")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parsed_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _unique(values: tuple[Any, ...], *, label: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must be unique")


def _enum_value(value: Any, enum_type: type[Enum]) -> Any:
    if isinstance(value, enum_type):
        return value
    if isinstance(value, str):
        try:
            return enum_type(value)
        except ValueError:
            return value
    return value


PortableRef = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=200,
        pattern=r"^[a-z][a-z0-9_.-]{0,199}$",
    ),
]
OpaqueRef = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=300,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,299}$",
    ),
]
ToolName = Annotated[
    str,
    StringConstraints(
        min_length=3,
        max_length=160,
        pattern=r"^[a-z0-9][a-z0-9_-]{0,63}(?:\.[a-z0-9][a-z0-9_-]{0,63})+$",
    ),
]


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


class CapabilityLifecycleState(str, Enum):
    CERTIFIED = "CERTIFIED"
    SUPPORTING = "SUPPORTING"
    PREVIEW = "PREVIEW"
    QUARANTINED = "QUARANTINED"
    RETIRED = "RETIRED"


class GoldenLoopPortfolioDomain(str, Enum):
    REVENUE_ACQUISITION = "revenue_acquisition"
    PRODUCT_DELIVERY = "product_delivery"
    FINANCE_OPERATIONS = "finance_operations"
    SERVICE_RETENTION = "service_retention"


class LoopTerminalDisposition(str, Enum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    RECONCILIATION_REQUIRED = "reconciliation_required"


class LoopSurface(str, Enum):
    AGENTS = "agents"
    SDK = "sdk"
    MCP = "mcp"
    CHATGPT = "chatgpt"


class LoopCertificationGate(str, Enum):
    TYPED_VERSIONED_CONTRACTS = "typed_versioned_contracts"
    PRODUCTION_SHAPED_COMPLETION = "production_shaped_completion"
    SCOPE_ISOLATION_AND_RBAC = "scope_isolation_and_rbac"
    APPROVAL_AND_EFFECT_CONTROL = "approval_and_effect_control"
    RESTART_REPLICA_AND_RECOVERY = "restart_replica_and_recovery"
    AMBIGUOUS_EFFECT_SAFETY = "ambiguous_effect_safety"
    CROSS_SURFACE_PARITY = "cross_surface_parity"
    HARNESS_CONFORMANCE = "harness_conformance"
    LIVE_PROVIDER_CONFORMANCE = "live_provider_conformance"
    MEASURED_CUSTOMER_OUTCOME = "measured_customer_outcome"


class AmbiguousOutcomePolicy(str, Enum):
    NOT_APPLICABLE = "not_applicable"
    STATUS_PROBE_THEN_RECONCILE = "status_probe_then_reconcile"
    MANUAL_RECONCILIATION_NO_REPLAY = "manual_reconciliation_no_replay"


class LoopTrigger(_StrictModel):
    trigger_ref: PortableRef
    event_ref: PortableRef
    description: str = Field(min_length=1, max_length=1_000)
    required_input_refs: tuple[PortableRef, ...] = Field(
        min_length=1,
        max_length=100,
    )

    @field_validator("required_input_refs", mode="before")
    @classmethod
    def _tuple_inputs(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _inputs_are_unique(self) -> Self:
        _unique(self.required_input_refs, label="trigger input references")
        return self


class LoopTerminalState(_StrictModel):
    state: PortableRef
    disposition: LoopTerminalDisposition
    outcome_description: str = Field(min_length=1, max_length=1_000)
    required_evidence_kinds: tuple[PortableRef, ...] = Field(
        min_length=1,
        max_length=100,
    )
    human_visible: Literal[True] = True

    @field_validator("disposition", mode="before")
    @classmethod
    def _disposition_enum(cls, value: Any) -> Any:
        return _enum_value(value, LoopTerminalDisposition)

    @field_validator("required_evidence_kinds", mode="before")
    @classmethod
    def _tuple_evidence(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _evidence_is_unique(self) -> Self:
        _unique(self.required_evidence_kinds, label="terminal evidence kinds")
        return self


class LoopTransition(_StrictModel):
    from_state: PortableRef
    event_ref: PortableRef
    to_state: PortableRef
    refinement_kind: Literal["append_only_settlement"] | None = None


class LoopStateMachine(_StrictModel):
    initial_state: PortableRef
    states: tuple[PortableRef, ...] = Field(min_length=5, max_length=200)
    transitions: tuple[LoopTransition, ...] = Field(min_length=4, max_length=1_000)
    terminal_states: tuple[LoopTerminalState, ...] = Field(min_length=3, max_length=100)

    @field_validator("states", "transitions", "terminal_states", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _graph_is_bounded_and_terminal(self) -> Self:
        _unique(self.states, label="loop states")
        terminal_names = tuple(item.state for item in self.terminal_states)
        _unique(terminal_names, label="terminal states")
        dispositions = {item.disposition for item in self.terminal_states}
        bounded_dispositions = {
            LoopTerminalDisposition.SUCCEEDED,
            LoopTerminalDisposition.FAILED,
            LoopTerminalDisposition.CANCELLED,
        }
        if frozenset(dispositions) not in {
            frozenset(bounded_dispositions),
            frozenset(LoopTerminalDisposition),
        }:
            raise ValueError(
                "terminal states must cover success, failure, and cancellation, with "
                "reconciliation present only when ambiguous effects are applicable"
            )
        known = set(self.states)
        if self.initial_state not in known:
            raise ValueError("initial_state must be a declared state")
        if self.initial_state in terminal_names:
            raise ValueError("initial_state cannot be terminal")
        if not set(terminal_names).issubset(known):
            raise ValueError("every terminal state must be declared")
        edges = tuple(
            (item.from_state, item.event_ref, item.to_state)
            for item in self.transitions
        )
        _unique(edges, label="loop transitions")
        _unique(
            tuple((source, event_ref) for source, event_ref, _ in edges),
            label="loop transition source/event pairs",
        )
        if any(source not in known or target not in known for source, _, target in edges):
            raise ValueError("transitions may reference only declared states")
        terminal_set = set(terminal_names)
        for transition in self.transitions:
            source_terminal = transition.from_state in terminal_set
            if source_terminal:
                if (
                    transition.refinement_kind != "append_only_settlement"
                    or transition.to_state not in terminal_set
                ):
                    raise ValueError(
                        "terminal transitions must be explicit append-only settlement refinements"
                    )
            elif transition.refinement_kind is not None:
                raise ValueError(
                    "append-only settlement refinement must start from a terminal state"
                )

        outgoing: dict[str, set[str]] = {state: set() for state in known}
        reverse: dict[str, set[str]] = {state: set() for state in known}
        for source, _, target in edges:
            outgoing[source].add(target)
            reverse[target].add(source)
        nonterminal = known - terminal_set
        if any(not outgoing[state] for state in nonterminal):
            raise ValueError("every non-terminal state needs an outgoing transition")

        reachable = {self.initial_state}
        frontier = [self.initial_state]
        while frontier:
            source = frontier.pop()
            for target in outgoing[source] - reachable:
                reachable.add(target)
                frontier.append(target)
        if reachable != known:
            raise ValueError("every loop state must be reachable from initial_state")

        reaches_terminal = set(terminal_names)
        frontier = list(terminal_names)
        while frontier:
            target = frontier.pop()
            for source in reverse[target] - reaches_terminal:
                reaches_terminal.add(source)
                frontier.append(source)
        if not nonterminal.issubset(reaches_terminal):
            raise ValueError("every non-terminal state must have a path to a terminal state")
        return self


class LoopToolRequirement(_StrictModel):
    binding_ref: PortableRef
    acceptable_tools: tuple[ToolName, ...] = Field(min_length=1, max_length=100)
    effect: ConnectorEffect
    approval_required: bool
    connector_account_binding_required: bool
    idempotency_required: bool
    ambiguous_outcome_policy: AmbiguousOutcomePolicy

    @field_validator("effect", mode="before")
    @classmethod
    def _effect_enum(cls, value: Any) -> Any:
        return _enum_value(value, ConnectorEffect)

    @field_validator("ambiguous_outcome_policy", mode="before")
    @classmethod
    def _ambiguity_enum(cls, value: Any) -> Any:
        return _enum_value(value, AmbiguousOutcomePolicy)

    @field_validator("acceptable_tools", mode="before")
    @classmethod
    def _tuple_tools(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _effect_is_governed(self) -> Self:
        _unique(self.acceptable_tools, label="acceptable Tools")
        if self.effect == ConnectorEffect.WRITE:
            if not all(
                (
                    self.approval_required,
                    self.connector_account_binding_required,
                    self.idempotency_required,
                )
            ):
                raise ValueError(
                    "write Tool requirements need approval, account binding, and idempotency"
                )
            if self.ambiguous_outcome_policy == AmbiguousOutcomePolicy.NOT_APPLICABLE:
                raise ValueError("write Tool requirements need an ambiguity policy")
        elif self.ambiguous_outcome_policy != AmbiguousOutcomePolicy.NOT_APPLICABLE:
            raise ValueError("only write Tool requirements use ambiguity recovery")
        return self


class LoopPrimitiveStep(_StrictModel):
    step_ref: PortableRef
    primitive_ref: PortableRef
    primitive_version: str = Field(min_length=5, max_length=80)
    agent_role_ref: PortableRef
    effect: ConnectorEffect
    approval_required: bool
    tool_binding_refs: tuple[PortableRef, ...] = Field(
        default_factory=tuple,
        max_length=50,
    )
    emits_event_ref: PortableRef

    @field_validator("effect", mode="before")
    @classmethod
    def _effect_enum(cls, value: Any) -> Any:
        return _enum_value(value, ConnectorEffect)

    @field_validator("primitive_version")
    @classmethod
    def _semantic_version(cls, value: str) -> str:
        if not _SEMVER_RE.fullmatch(value):
            raise ValueError("primitive_version must be semantic versioning")
        return value

    @field_validator("tool_binding_refs", mode="before")
    @classmethod
    def _tuple_bindings(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _step_effect_is_governed(self) -> Self:
        _unique(self.tool_binding_refs, label="step Tool bindings")
        if self.effect == ConnectorEffect.WRITE and not self.approval_required:
            raise ValueError("write primitive steps require approval")
        return self


class LoopArtifactRequirement(_StrictModel):
    artifact_ref: PortableRef
    evidence_kind: PortableRef
    produced_by_agent_role_ref: PortableRef
    accepted_by_role_ref: PortableRef
    required_for_success: Literal[True] = True
    correction_allowed: bool = True


class LoopOutcomeMetric(_StrictModel):
    metric_ref: PortableRef
    direction: Literal["increase", "decrease"]
    unit: str = Field(min_length=1, max_length=80)
    source_system_ref: OpaqueRef
    required_sample_count: int = Field(ge=1, le=1_000_000_000)
    measurement_window_seconds: int = Field(ge=1, le=31_536_000)
    certification_target: Decimal | None = None
    certification_comparison: Literal["at_least", "at_most"] | None = None

    @field_validator("certification_target", mode="before")
    @classmethod
    def _target_decimal(cls, value: Any) -> Decimal | None:
        if value is None:
            return None
        try:
            parsed = Decimal(str(value))
        except (InvalidOperation, ValueError) as exc:
            raise ValueError("certification_target must be a finite decimal") from exc
        if not parsed.is_finite() or parsed < 0:
            raise ValueError("certification_target must be a finite non-negative decimal")
        return parsed

    @model_validator(mode="after")
    def _target_direction_is_coherent(self) -> Self:
        if (self.certification_target is None) != (
            self.certification_comparison is None
        ):
            raise ValueError("metric target and comparison must be declared together")
        if self.certification_target is None:
            return self
        expected = "at_least" if self.direction == "increase" else "at_most"
        if self.certification_comparison != expected:
            raise ValueError("metric comparison must match the declared direction")
        if self.unit == "percent" and self.certification_target > Decimal("100"):
            raise ValueError("percent certification targets cannot exceed 100")
        return self


class LoopExecutionBudget(_StrictModel):
    max_elapsed_seconds: int = Field(ge=1, le=31_536_000)
    max_cost_microusd: int = Field(ge=0, le=10_000_000_000_000)
    max_primitive_steps: int = Field(ge=1, le=10_000)
    max_agent_turns: int = Field(ge=1, le=100_000)


class LoopExecutionPolicy(_StrictModel):
    idempotency_scope: Literal["tenant_company_project_loop_run_step"] = (
        "tenant_company_project_loop_run_step"
    )
    durable_checkpoints_required: Literal[True] = True
    cancellation_fence_required: Literal[True] = True
    restart_from_checkpoint_required: Literal[True] = True
    replica_handoff_fencing_required: Literal[True] = True
    automatic_retry_of_ambiguous_writes: Literal[False] = False
    ambiguous_effect_event_ref: PortableRef | None = None
    ambiguous_effect_terminal_state: PortableRef | None = None

    @model_validator(mode="after")
    def _ambiguity_refs_are_both_applicable_or_both_absent(self) -> Self:
        if (self.ambiguous_effect_event_ref is None) != (
            self.ambiguous_effect_terminal_state is None
        ):
            raise ValueError(
                "ambiguous effect event and terminal refs must be declared together"
            )
        return self


class LoopHarnessPolicy(_StrictModel):
    required: bool
    contract_ref: Literal["lightbulb.dynamic_workflow_control.v1"] = (
        "lightbulb.dynamic_workflow_control.v1"
    )
    allowed_harnesses: tuple[str, ...] = Field(min_length=1, max_length=20)
    exact_scope_required: Literal[True] = True
    work_packet_digest_required: Literal[True] = True
    acceptance_contract_digest_required: Literal[True] = True
    repository_workspace_binding_required: Literal[True] = True
    capability_and_write_policy_required: Literal[True] = True
    exclusive_lease_required: Literal[True] = True
    heartbeat_required: Literal[True] = True
    reconnect_required: Literal[True] = True
    cancellation_required: Literal[True] = True
    content_addressed_evidence_required: Literal[True] = True
    independent_evaluator_required: Literal[True] = True
    remediation_and_final_acceptance_required: Literal[True] = True

    @field_validator("allowed_harnesses", mode="before")
    @classmethod
    def _tuple_harnesses(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _harnesses_are_supported(self) -> Self:
        _unique(self.allowed_harnesses, label="allowed harnesses")
        if any(item not in BUILTIN_DYNAMIC_WORKFLOW_HOST_IDS for item in self.allowed_harnesses):
            raise ValueError("allowed_harnesses contains an unknown Dynamic Workflow host")
        return self


class LoopSurfaceProjection(_StrictModel):
    surface: LoopSurface
    entrypoint_ref: OpaqueRef
    lifecycle: CapabilityLifecycleState
    participation: Literal["CALLABLE", "CANDIDATE_ONLY", "BLOCKED"] = "CALLABLE"
    blocker_code: PortableRef | None = None
    optional: bool = False
    canonical_run_ref_field: Literal["run_ref"] = "run_ref"

    @field_validator("surface", mode="before")
    @classmethod
    def _surface_enum(cls, value: Any) -> Any:
        return _enum_value(value, LoopSurface)

    @field_validator("lifecycle", mode="before")
    @classmethod
    def _lifecycle_enum(cls, value: Any) -> Any:
        return _enum_value(value, CapabilityLifecycleState)

    @model_validator(mode="after")
    def _chatgpt_is_the_only_optional_product_surface(self) -> Self:
        if self.optional != (self.surface == LoopSurface.CHATGPT):
            raise ValueError("ChatGPT is optional; Agents, SDK, and MCP are required surfaces")
        callable_projection = self.participation == "CALLABLE"
        if callable_projection != (self.blocker_code is None):
            raise ValueError(
                "candidate-only and blocked surfaces require an exact blocker_code; "
                "callable surfaces must not declare one"
            )
        return self


class LoopImplementationBinding(_StrictModel):
    canonical_workflow_ref: OpaqueRef
    workflow_version: str = Field(min_length=5, max_length=80)
    execution_loop_version: str = Field(min_length=5, max_length=80)
    runtime_owner: Literal[
        "spring_autocompany_kernel",
        "spring_dynamic_workflow",
        "spring_hosted_lifecycle",
    ]
    runtime_adapter_ref: OpaqueRef
    authority_owner: Literal["spring_control_plane"] = "spring_control_plane"
    connector_owner: Literal["connector_runtime"] = "connector_runtime"
    source_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=100)

    @field_validator("workflow_version", "execution_loop_version")
    @classmethod
    def _semantic_versions(cls, value: str, info: Any) -> str:
        if not _SEMVER_RE.fullmatch(value):
            raise ValueError(f"{info.field_name} must use semantic versioning")
        return value

    @field_validator("source_refs", mode="before")
    @classmethod
    def _tuple_sources(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _sources_are_unique(self) -> Self:
        _unique(self.source_refs, label="canonical implementation source refs")
        return self


class LoopCertificationTest(_StrictModel):
    test_ref: OpaqueRef
    gate: LoopCertificationGate
    environment: Literal["contract", "integration", "production_shaped", "sandbox", "canary"]
    required_evidence_kind: PortableRef

    @field_validator("gate", mode="before")
    @classmethod
    def _gate_enum(cls, value: Any) -> Any:
        return _enum_value(value, LoopCertificationGate)


class LoopCertificationTestExecutionEvidence(_StrictModel):
    test_ref: OpaqueRef
    gate: LoopCertificationGate
    declared_environment: Literal[
        "contract",
        "integration",
        "production_shaped",
        "sandbox",
        "canary",
    ]
    evidence_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=100)

    @field_validator("gate", mode="before")
    @classmethod
    def _gate_enum(cls, value: Any) -> Any:
        return _enum_value(value, LoopCertificationGate)

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _tuple_evidence_refs(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _evidence_refs_are_unique(self) -> Self:
        _unique(self.evidence_refs, label="test execution evidence refs")
        return self


class LoopOutcomeCertificationMeasurement(_StrictModel):
    metric_ref: PortableRef
    direction: Literal["increase", "decrease"]
    unit: str = Field(min_length=1, max_length=80)
    source_system_ref: OpaqueRef
    baseline: Decimal
    observed: Decimal
    target: Decimal
    comparison: Literal["at_least", "at_most"]
    required_sample_count: int = Field(ge=1, le=1_000_000_000)
    sample_count: int = Field(ge=1, le=1_000_000_000)
    window_started_at: str
    window_ended_at: str
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=1,
        max_length=100,
    )
    measurement_digest: str = Field(
        default="",
        pattern=r"^(?:[0-9a-f]{64})?$",
    )

    @field_validator("baseline", "observed", "target", mode="before")
    @classmethod
    def _measurement_decimals(cls, value: Any) -> Decimal:
        if isinstance(value, bool) or not isinstance(
            value,
            (str, int, float, Decimal),
        ):
            raise ValueError("outcome measurements must use decimal values")
        try:
            parsed = Decimal(str(value))
        except (InvalidOperation, ValueError) as exc:
            raise ValueError("outcome measurements must use finite decimals") from exc
        if not parsed.is_finite() or abs(parsed) > Decimal("1e24"):
            raise ValueError("outcome measurements must use bounded finite decimals")
        return parsed

    @field_validator("window_started_at", "window_ended_at")
    @classmethod
    def _measurement_timestamps(cls, value: str, info: Any) -> str:
        return _timestamp(value, label=info.field_name)

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _tuple_measurement_evidence(cls, value: Any) -> Any:
        return _as_tuple(value)

    @field_validator("measurement_digest")
    @classmethod
    def _optional_measurement_digest(cls, value: str) -> str:
        clean = value.strip().lower()
        if clean and not _SHA256_RE.fullmatch(clean):
            raise ValueError("measurement_digest must be lowercase SHA-256")
        return clean

    def _measurement_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"measurement_digest"},
        )

    @model_validator(mode="after")
    def _measurement_is_exact_and_passing(self) -> Self:
        if _parsed_timestamp(self.window_started_at) >= _parsed_timestamp(
            self.window_ended_at
        ):
            raise ValueError("outcome measurement window must be ordered")
        if self.sample_count < self.required_sample_count:
            raise ValueError("outcome sample count is below the declared minimum")
        expected_comparison = (
            "at_least" if self.direction == "increase" else "at_most"
        )
        if self.comparison != expected_comparison:
            raise ValueError("outcome comparison must match direction")
        if self.unit == "percent" and any(
            value < Decimal("0") or value > Decimal("100")
            for value in (self.baseline, self.observed, self.target)
        ):
            raise ValueError("percent outcome measurements must be between zero and 100")
        target_met = (
            self.observed >= self.target
            if self.direction == "increase"
            else self.observed <= self.target
        )
        improved = (
            self.observed > self.baseline
            if self.direction == "increase"
            else self.observed < self.baseline
        )
        if not target_met or not improved:
            raise ValueError("outcome measurement must improve and meet its target")
        evidence_ids = tuple(item.evidence_ref for item in self.evidence_refs)
        _unique(evidence_ids, label="outcome measurement evidence refs")
        if evidence_ids != tuple(sorted(evidence_ids)):
            raise ValueError("outcome measurement evidence must use canonical order")
        expected_digest = _stable_digest(self._measurement_payload())
        if self.measurement_digest and self.measurement_digest != expected_digest:
            raise ValueError("measurement_digest must match the exact measurement")
        object.__setattr__(self, "measurement_digest", expected_digest)
        return self


class LoopCertificationGateEvidence(_StrictModel):
    gate: LoopCertificationGate
    test_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=100)
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(min_length=1, max_length=100)

    @field_validator("gate", mode="before")
    @classmethod
    def _gate_enum(cls, value: Any) -> Any:
        return _enum_value(value, LoopCertificationGate)

    @field_validator("test_refs", "evidence_refs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _evidence_is_unique(self) -> Self:
        _unique(self.test_refs, label="certification test refs")
        _unique(
            tuple(item.evidence_ref for item in self.evidence_refs),
            label="certification evidence refs",
        )
        return self


class LoopCertificationCandidate(_StrictModel):
    """Evidence-sealed proposal for Spring/operator certification.

    This result never grants production certification or deployment authority.
    Spring must rebuild it from the retained readiness result and evidence before
    recording an operator decision.
    """

    schema_id: Literal["lightbulb.loop_certification_candidate.v1"] = Field(
        default=LOOP_CERTIFICATION_CANDIDATE_SCHEMA,
        alias="schema",
    )
    loop_ref: PortableRef
    loop_version: str = Field(min_length=5, max_length=80)
    declaration_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    environment_ref: OpaqueRef
    evaluated_at: str
    operational_readiness_input_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    operational_readiness_evidence_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    operational_readiness_evaluation_digest: str = Field(
        pattern=r"^[0-9a-f]{64}$"
    )
    required_readiness_gates: tuple[ReadinessGate, ...] = Field(
        min_length=1,
        max_length=9,
    )
    gate_evidence: tuple[LoopCertificationGateEvidence, ...] = Field(
        min_length=10,
        max_length=10,
    )
    test_execution_evidence: tuple[
        LoopCertificationTestExecutionEvidence,
        ...,
    ] = Field(min_length=10, max_length=500)
    outcome_measurements: tuple[
        LoopOutcomeCertificationMeasurement,
        ...,
    ] = Field(min_length=1, max_length=100)
    gate_evidence_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_digest: str = Field(
        default="",
        pattern=r"^(?:[0-9a-f]{64})?$",
    )
    ready_for_operator_certification: Literal[True] = True
    production_certified: Literal[False] = False
    deployment_authorized: Literal[False] = False

    @field_validator(
        "declaration_digest",
        "operational_readiness_input_digest",
        "operational_readiness_evidence_digest",
        "operational_readiness_evaluation_digest",
        "gate_evidence_digest",
        "candidate_digest",
    )
    @classmethod
    def _candidate_digests(cls, value: str) -> str:
        clean = value.strip().lower()
        if clean and not _SHA256_RE.fullmatch(clean):
            raise ValueError("candidate digests must be lowercase SHA-256")
        return clean

    @field_validator("loop_version")
    @classmethod
    def _semantic_version(cls, value: str) -> str:
        if not _SEMVER_RE.fullmatch(value):
            raise ValueError("loop_version must use semantic versioning")
        return value

    @field_validator("evaluated_at")
    @classmethod
    def _evaluation_timestamp(cls, value: str) -> str:
        return _timestamp(value, label="evaluated_at")

    @field_validator(
        "required_readiness_gates",
        "gate_evidence",
        "test_execution_evidence",
        "outcome_measurements",
        mode="before",
    )
    @classmethod
    def _candidate_tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    def _candidate_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"candidate_digest"},
        )

    @model_validator(mode="after")
    def _candidate_is_content_bound(self) -> Self:
        _unique(self.required_readiness_gates, label="required readiness gates")
        gates = tuple(item.gate for item in self.gate_evidence)
        _unique(gates, label="candidate certification gates")
        if set(gates) != set(LoopCertificationGate):
            raise ValueError("candidate must bind evidence for all ten gates")
        if gates != tuple(LoopCertificationGate):
            raise ValueError("candidate certification gates must use canonical order")
        test_refs = tuple(item.test_ref for item in self.test_execution_evidence)
        _unique(test_refs, label="candidate test execution refs")
        expected_test_refs = tuple(
            test_ref
            for item in self.gate_evidence
            for test_ref in item.test_refs
        )
        if set(test_refs) != set(expected_test_refs):
            raise ValueError(
                "candidate test executions must cover the exact gate test refs"
            )
        canonical_tests = tuple(
            sorted(
                self.test_execution_evidence,
                key=lambda item: (
                    tuple(LoopCertificationGate).index(item.gate),
                    item.test_ref,
                ),
            )
        )
        if self.test_execution_evidence != canonical_tests:
            raise ValueError("candidate test executions must use canonical order")
        evidence_by_gate = {
            item.gate: {evidence.evidence_ref for evidence in item.evidence_refs}
            for item in self.gate_evidence
        }
        if any(
            not set(item.evidence_refs).issubset(evidence_by_gate[item.gate])
            for item in self.test_execution_evidence
        ):
            raise ValueError(
                "candidate test execution evidence must come from its exact gate"
            )
        measurement_refs = tuple(
            item.metric_ref for item in self.outcome_measurements
        )
        _unique(measurement_refs, label="candidate outcome measurement refs")
        if measurement_refs != tuple(sorted(measurement_refs)):
            raise ValueError("candidate outcome measurements must use canonical order")
        expected_evidence_digest = _stable_digest(
            [item.to_dict() for item in self.gate_evidence]
        )
        if self.gate_evidence_digest != expected_evidence_digest:
            raise ValueError("gate_evidence_digest must match exact gate evidence")
        expected_candidate_digest = _stable_digest(self._candidate_payload())
        if self.candidate_digest and self.candidate_digest != expected_candidate_digest:
            raise ValueError("candidate_digest must match the exact candidate")
        object.__setattr__(self, "candidate_digest", expected_candidate_digest)
        return self


class LoopCertificationRecord(_StrictModel):
    """Portable projection of a Spring-issued record, not proof of issuance.

    Parsing or constructing this model validates content and evidence shape
    only. Any consumer making a production decision must resolve
    ``spring_certification_ref`` and ``record_digest`` from Spring under the
    authenticated scope and trusted clock.
    """

    schema_id: Literal["lightbulb.loop_certification_record.v1"] = Field(
        default=LOOP_CERTIFICATION_RECORD_SCHEMA,
        alias="schema",
    )
    loop_ref: PortableRef
    loop_version: str = Field(min_length=5, max_length=80)
    declaration_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    environment_ref: OpaqueRef
    candidate_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    runtime_artifact_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    operational_readiness_input_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    operational_readiness_evidence_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    operational_readiness_evaluation_digest: str = Field(
        pattern=r"^[0-9a-f]{64}$"
    )
    spring_certification_ref: OpaqueRef
    spring_audit_event_ref: OpaqueRef
    spring_evidence_custody_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    operator_ref: OpaqueRef
    certified_at: str
    expires_at: str
    operator_approved: Literal[True]
    superseded_administrative_blockers: tuple[
        Literal["spring_operator_certification_pending"], ...
    ] = Field(min_length=1, max_length=1)
    gate_evidence: tuple[LoopCertificationGateEvidence, ...] = Field(
        min_length=10,
        max_length=10,
    )
    test_execution_evidence: tuple[
        LoopCertificationTestExecutionEvidence,
        ...,
    ] = Field(min_length=10, max_length=500)
    outcome_measurements: tuple[
        LoopOutcomeCertificationMeasurement,
        ...,
    ] = Field(min_length=1, max_length=100)
    record_digest: str = Field(
        default="",
        pattern=r"^(?:[0-9a-f]{64})?$",
    )

    @field_validator(
        "declaration_digest",
        "candidate_digest",
        "runtime_artifact_digest",
        "operational_readiness_input_digest",
        "operational_readiness_evidence_digest",
        "operational_readiness_evaluation_digest",
        "spring_evidence_custody_digest",
    )
    @classmethod
    def _required_digests(cls, value: str) -> str:
        clean = value.strip().lower()
        if not _SHA256_RE.fullmatch(clean):
            raise ValueError("certification digests must be lowercase SHA-256")
        return clean

    @field_validator("record_digest")
    @classmethod
    def _optional_record_digest(cls, value: str) -> str:
        clean = value.strip().lower()
        if clean and not _SHA256_RE.fullmatch(clean):
            raise ValueError("record_digest must be lowercase SHA-256")
        return clean

    @field_validator("loop_version")
    @classmethod
    def _semantic_version(cls, value: str) -> str:
        if not _SEMVER_RE.fullmatch(value):
            raise ValueError("loop_version must use semantic versioning")
        return value

    @field_validator("certified_at", "expires_at")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _timestamp(value, label=info.field_name)

    @field_validator(
        "gate_evidence",
        "test_execution_evidence",
        "outcome_measurements",
        "superseded_administrative_blockers",
        mode="before",
    )
    @classmethod
    def _tuple_gate_evidence(cls, value: Any) -> Any:
        return _as_tuple(value)

    def _record_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"record_digest"},
        )

    @model_validator(mode="after")
    def _all_gates_are_evidence_bound_and_current(self) -> Self:
        if self.superseded_administrative_blockers != (
            SPRING_OPERATOR_CERTIFICATION_PENDING_BLOCKER,
        ):
            raise ValueError(
                "certification must supersede the exact administrative pending blocker"
            )
        gates = tuple(item.gate for item in self.gate_evidence)
        _unique(gates, label="certification gates")
        if set(gates) != set(LoopCertificationGate):
            raise ValueError("certification record must bind evidence for all ten gates")
        if gates != tuple(LoopCertificationGate):
            raise ValueError("certification gates must use canonical order")
        test_refs = tuple(item.test_ref for item in self.test_execution_evidence)
        _unique(test_refs, label="certification test execution refs")
        gate_test_refs = {
            item.gate: set(item.test_refs) for item in self.gate_evidence
        }
        if set(test_refs) != set().union(*gate_test_refs.values()):
            raise ValueError(
                "certification test executions must cover exact gate test refs"
            )
        canonical_tests = tuple(
            sorted(
                self.test_execution_evidence,
                key=lambda item: (
                    tuple(LoopCertificationGate).index(item.gate),
                    item.test_ref,
                ),
            )
        )
        if self.test_execution_evidence != canonical_tests:
            raise ValueError("certification test executions must use canonical order")
        gate_evidence_refs = {
            item.gate: {evidence.evidence_ref for evidence in item.evidence_refs}
            for item in self.gate_evidence
        }
        if any(
            item.test_ref not in gate_test_refs[item.gate]
            or not set(item.evidence_refs).issubset(gate_evidence_refs[item.gate])
            for item in self.test_execution_evidence
        ):
            raise ValueError(
                "certification test evidence must bind its exact gate and evidence"
            )
        measurement_refs = tuple(
            item.metric_ref for item in self.outcome_measurements
        )
        _unique(measurement_refs, label="certification outcome measurement refs")
        if measurement_refs != tuple(sorted(measurement_refs)):
            raise ValueError("certification outcome measurements must use canonical order")
        if _parsed_timestamp(self.certified_at) >= _parsed_timestamp(self.expires_at):
            raise ValueError("certification must expire after it is granted")

        certified_at = _parsed_timestamp(self.certified_at)
        evidence_refs = tuple(
            evidence.evidence_ref
            for gate_evidence in self.gate_evidence
            for evidence in gate_evidence.evidence_refs
        )
        _unique(evidence_refs, label="certification evidence refs")
        for gate_evidence in self.gate_evidence:
            for evidence in gate_evidence.evidence_refs:
                if evidence.subject_ref != self.declaration_digest:
                    raise ValueError(
                        "certification evidence must bind the exact loop declaration digest"
                    )
                if evidence.verification_grade not in {
                    PrimitiveEvidenceVerificationGrade.ATTESTED,
                    PrimitiveEvidenceVerificationGrade.VERIFIED,
                }:
                    raise ValueError("certification evidence must be attested or verified")
                observed_at = _parsed_timestamp(evidence.observed_at)
                effective_at = (
                    _parsed_timestamp(evidence.effective_at)
                    if evidence.effective_at is not None
                    else observed_at
                )
                if observed_at > certified_at or effective_at > certified_at:
                    raise ValueError(
                        "certification evidence cannot post-date certification"
                    )
        for measurement in self.outcome_measurements:
            if _parsed_timestamp(measurement.window_ended_at) > certified_at:
                raise ValueError(
                    "outcome measurement window cannot post-date certification"
                )
            for evidence in measurement.evidence_refs:
                if evidence.subject_ref != self.declaration_digest:
                    raise ValueError(
                        "outcome evidence must bind the exact loop declaration digest"
                    )
                if evidence.verification_grade not in {
                    PrimitiveEvidenceVerificationGrade.ATTESTED,
                    PrimitiveEvidenceVerificationGrade.VERIFIED,
                }:
                    raise ValueError("outcome evidence must be attested or verified")
                if _parsed_timestamp(evidence.observed_at) > certified_at:
                    raise ValueError(
                        "outcome evidence cannot post-date certification"
                    )

        expected_digest = _stable_digest(self._record_payload())
        if self.record_digest and self.record_digest != expected_digest:
            raise ValueError("record_digest must match the exact certification record")
        object.__setattr__(self, "record_digest", expected_digest)
        return self


def build_loop_certification_candidate(
    manifest: LoopCertificationManifest | dict[str, Any],
    readiness_input: OperationalReadinessInput | dict[str, Any],
    readiness_result: OperationalReadinessResult | dict[str, Any],
    gate_evidence: tuple[LoopCertificationGateEvidence, ...]
    | list[LoopCertificationGateEvidence]
    | list[dict[str, Any]],
    test_execution_evidence: tuple[
        LoopCertificationTestExecutionEvidence,
        ...,
    ]
    | list[LoopCertificationTestExecutionEvidence]
    | list[dict[str, Any]],
    outcome_measurements: tuple[LoopOutcomeCertificationMeasurement, ...]
    | list[LoopOutcomeCertificationMeasurement]
    | list[dict[str, Any]],
) -> LoopCertificationCandidate:
    """Bind one loop to retained readiness, exact tests, and measured outcomes.

    The returned object is deliberately non-authoritative. It is suitable for a
    Spring/operator review request, not for changing lifecycle or deployment
    state.
    """

    parsed_manifest = LoopCertificationManifest.model_validate(manifest)
    parsed_readiness_input = OperationalReadinessInput.model_validate(readiness_input)
    parsed_readiness = OperationalReadinessResult.model_validate(readiness_result)
    supplied_gate_evidence = tuple(
        LoopCertificationGateEvidence.model_validate(item) for item in gate_evidence
    )
    supplied_test_evidence = tuple(
        LoopCertificationTestExecutionEvidence.model_validate(item)
        for item in test_execution_evidence
    )
    supplied_outcome_measurements = tuple(
        LoopOutcomeCertificationMeasurement.model_validate(item)
        for item in outcome_measurements
    )

    if parsed_manifest.lifecycle == CapabilityLifecycleState.RETIRED:
        raise ValueError("RETIRED loops cannot enter certification")
    if parsed_manifest.certification is not None:
        raise ValueError("an already-certified loop cannot create a new candidate")
    if parsed_manifest.known_blockers != (
        SPRING_OPERATOR_CERTIFICATION_PENDING_BLOCKER,
    ):
        raise ValueError(
            "certification requires the sole reserved Spring/operator pending blocker"
        )
    if any(
        item.certification_target is None
        for item in parsed_manifest.outcome_metrics
    ):
        raise ValueError("explicit outcome targets are required before certification")
    recomputed_readiness = evaluate_operational_readiness(parsed_readiness_input)
    if recomputed_readiness != parsed_readiness:
        raise ValueError(
            "retained readiness input must reproduce the exact readiness result"
        )
    if parsed_readiness.disposition != "ready_for_operator_certification":
        raise ValueError("operational readiness is not ready for operator certification")

    findings_by_readiness_gate: dict[str, list[str]] = {}
    for finding in parsed_readiness.findings:
        findings_by_readiness_gate.setdefault(finding.gate, []).append(finding.status)
    for gate in parsed_manifest.required_operational_readiness_gates:
        statuses = findings_by_readiness_gate.get(gate, [])
        if not statuses or any(status != "pass" for status in statuses):
            raise ValueError(f"required operational readiness gate is not passing: {gate}")

    evidence_by_gate = {item.gate: item for item in supplied_gate_evidence}
    if len(evidence_by_gate) != len(supplied_gate_evidence):
        raise ValueError("certification gate evidence must be unique by gate")
    if set(evidence_by_gate) != set(LoopCertificationGate):
        raise ValueError("certification evidence must cover all ten gates")
    parsed_gate_evidence = tuple(
        evidence_by_gate[gate] for gate in LoopCertificationGate
    )

    readiness_timestamp = datetime.fromisoformat(
        parsed_readiness.evaluated_at.replace("Z", "+00:00")
    )
    acceptable_grades = {
        PrimitiveEvidenceVerificationGrade.ATTESTED,
        PrimitiveEvidenceVerificationGrade.VERIFIED,
    }
    for gate in LoopCertificationGate:
        declared_tests = tuple(
            sorted(
                test.test_ref
                for test in parsed_manifest.certification_tests
                if test.gate == gate
            )
        )
        supplied = evidence_by_gate[gate]
        if tuple(sorted(supplied.test_refs)) != declared_tests:
            raise ValueError(
                f"certification evidence must bind the exact declared tests for {gate.value}"
            )
        required_kinds = {
            test.required_evidence_kind
            for test in parsed_manifest.certification_tests
            if test.gate == gate
        }
        supplied_kinds = {item.kind for item in supplied.evidence_refs}
        if not required_kinds.issubset(supplied_kinds):
            raise ValueError(
                f"certification evidence kinds are incomplete for {gate.value}"
            )
        for evidence in supplied.evidence_refs:
            if evidence.subject_ref != parsed_manifest.declaration_digest:
                raise ValueError(
                    "certification evidence must bind the exact loop declaration digest"
                )
            if evidence.verification_grade not in acceptable_grades:
                raise ValueError("certification evidence must be attested or verified")
            observed_at = datetime.fromisoformat(
                evidence.observed_at.replace("Z", "+00:00")
            )
            effective_at = (
                datetime.fromisoformat(evidence.effective_at.replace("Z", "+00:00"))
                if evidence.effective_at is not None
                else observed_at
            )
            if observed_at > readiness_timestamp or effective_at > readiness_timestamp:
                raise ValueError(
                    "certification evidence cannot post-date operational readiness"
                )

    declared_tests_by_ref = {
        item.test_ref: item for item in parsed_manifest.certification_tests
    }
    supplied_tests_by_ref = {
        item.test_ref: item for item in supplied_test_evidence
    }
    if len(supplied_tests_by_ref) != len(supplied_test_evidence):
        raise ValueError("test execution evidence must be unique by test_ref")
    if set(supplied_tests_by_ref) != set(declared_tests_by_ref):
        raise ValueError("test execution evidence must cover every exact declared test")
    for test_ref, declared_test in declared_tests_by_ref.items():
        execution = supplied_tests_by_ref[test_ref]
        if (
            execution.gate != declared_test.gate
            or execution.declared_environment != declared_test.environment
        ):
            raise ValueError(
                "test execution evidence must bind the declared gate and environment"
            )
        evidence_by_ref = {
            item.evidence_ref: item
            for item in evidence_by_gate[declared_test.gate].evidence_refs
        }
        if not set(execution.evidence_refs).issubset(evidence_by_ref):
            raise ValueError(
                "test execution evidence must reference evidence from its exact gate"
            )
        if declared_test.required_evidence_kind not in {
            evidence_by_ref[ref].kind for ref in execution.evidence_refs
        }:
            raise ValueError(
                "test execution evidence must bind its declared evidence kind"
            )
    parsed_test_evidence = tuple(
        sorted(
            supplied_test_evidence,
            key=lambda item: (
                tuple(LoopCertificationGate).index(item.gate),
                item.test_ref,
            ),
        )
    )

    declared_metrics = {
        item.metric_ref: item for item in parsed_manifest.outcome_metrics
    }
    measurements_by_ref = {
        item.metric_ref: item for item in supplied_outcome_measurements
    }
    if len(measurements_by_ref) != len(supplied_outcome_measurements):
        raise ValueError("outcome measurements must be unique by metric_ref")
    if set(measurements_by_ref) != set(declared_metrics):
        raise ValueError("outcome measurements must cover every exact declared metric")
    if set(parsed_readiness_input.policy.required_business_outcomes) != set(
        declared_metrics
    ):
        raise ValueError(
            "readiness policy must require every exact Golden Loop outcome metric"
        )
    readiness_outcomes = {
        item.outcome_ref: item for item in parsed_readiness_input.business_outcomes
    }
    if set(readiness_outcomes) != set(declared_metrics):
        raise ValueError(
            "retained readiness input must measure every exact Golden Loop outcome"
        )
    for metric_ref, metric in declared_metrics.items():
        measurement = measurements_by_ref[metric_ref]
        if (
            measurement.direction != metric.direction
            or measurement.unit != metric.unit
            or measurement.source_system_ref != metric.source_system_ref
            or measurement.required_sample_count != metric.required_sample_count
            or measurement.target != metric.certification_target
            or measurement.comparison != metric.certification_comparison
        ):
            raise ValueError(
                "outcome measurement must bind the exact declared metric contract"
            )
        if _parsed_timestamp(measurement.window_ended_at) > readiness_timestamp:
            raise ValueError(
                "outcome measurement window cannot post-date operational readiness"
            )
        retained = readiness_outcomes[metric_ref]
        if (
            retained.metric_name != metric_ref
            or retained.direction != measurement.direction
            or retained.unit != measurement.unit
            or retained.source_system_ref != measurement.source_system_ref
            or retained.baseline != measurement.baseline
            or retained.observed != measurement.observed
            or retained.target != measurement.target
            or retained.sample_count != measurement.sample_count
            or retained.measured_at != measurement.window_ended_at
            or retained.evidence_refs != measurement.evidence_refs
        ):
            raise ValueError(
                "outcome measurement must match the exact retained readiness input"
            )
        for evidence in measurement.evidence_refs:
            if evidence.subject_ref != parsed_manifest.declaration_digest:
                raise ValueError(
                    "outcome evidence must bind the exact loop declaration digest"
                )
            if evidence.verification_grade not in acceptable_grades:
                raise ValueError("outcome evidence must be attested or verified")
            observed_at = _parsed_timestamp(evidence.observed_at)
            effective_at = (
                _parsed_timestamp(evidence.effective_at)
                if evidence.effective_at is not None
                else observed_at
            )
            if observed_at > readiness_timestamp or effective_at > readiness_timestamp:
                raise ValueError(
                    "outcome evidence cannot post-date operational readiness"
                )
    parsed_outcome_measurements = tuple(
        measurements_by_ref[metric_ref] for metric_ref in sorted(measurements_by_ref)
    )

    gate_evidence_digest = _stable_digest(
        [item.to_dict() for item in parsed_gate_evidence]
    )
    return LoopCertificationCandidate(
        loop_ref=parsed_manifest.loop_ref,
        loop_version=parsed_manifest.version,
        declaration_digest=parsed_manifest.declaration_digest,
        environment_ref=parsed_readiness.environment_ref,
        evaluated_at=parsed_readiness.evaluated_at,
        operational_readiness_input_digest=parsed_readiness.input_digest,
        operational_readiness_evidence_digest=parsed_readiness.evidence_digest,
        operational_readiness_evaluation_digest=parsed_readiness.evaluation_digest,
        required_readiness_gates=(
            parsed_manifest.required_operational_readiness_gates
        ),
        gate_evidence=parsed_gate_evidence,
        test_execution_evidence=parsed_test_evidence,
        outcome_measurements=parsed_outcome_measurements,
        gate_evidence_digest=gate_evidence_digest,
    )


class LoopCertificationManifest(_StrictModel):
    schema_id: Literal["lightbulb.loop_certification_manifest.v1"] = Field(
        default=LOOP_CERTIFICATION_MANIFEST_SCHEMA,
        alias="schema",
    )
    loop_ref: PortableRef
    version: str = Field(min_length=5, max_length=80)
    title: str = Field(min_length=1, max_length=300)
    portfolio_domain: GoldenLoopPortfolioDomain
    buyer: str = Field(min_length=1, max_length=300)
    business_objective: str = Field(min_length=1, max_length=2_000)
    lifecycle: CapabilityLifecycleState
    gtm_visible: bool = False
    triggers: tuple[LoopTrigger, ...] = Field(min_length=1, max_length=50)
    state_machine: LoopStateMachine
    agent_role_refs: tuple[PortableRef, ...] = Field(min_length=1, max_length=100)
    primitive_steps: tuple[LoopPrimitiveStep, ...] = Field(min_length=1, max_length=500)
    tool_requirements: tuple[LoopToolRequirement, ...] = Field(
        default_factory=tuple,
        max_length=500,
    )
    artifact_requirements: tuple[LoopArtifactRequirement, ...] = Field(
        min_length=1,
        max_length=500,
    )
    execution_policy: LoopExecutionPolicy
    budget: LoopExecutionBudget
    completion_slo_seconds: int = Field(ge=1, le=31_536_000)
    outcome_metrics: tuple[LoopOutcomeMetric, ...] = Field(min_length=1, max_length=100)
    surfaces: tuple[LoopSurfaceProjection, ...] = Field(min_length=4, max_length=4)
    harness_policy: LoopHarnessPolicy
    implementation: LoopImplementationBinding
    required_operational_readiness_gates: tuple[ReadinessGate, ...] = Field(
        min_length=1,
        max_length=9,
    )
    certification_tests: tuple[LoopCertificationTest, ...] = Field(
        min_length=10,
        max_length=500,
    )
    known_blockers: tuple[str, ...] = Field(default_factory=tuple, max_length=100)
    certification: LoopCertificationRecord | None = None
    declaration_digest: str = Field(
        default="",
        pattern=r"^(?:[0-9a-f]{64})?$",
    )

    @field_validator("portfolio_domain", mode="before")
    @classmethod
    def _portfolio_domain_enum(cls, value: Any) -> Any:
        return _enum_value(value, GoldenLoopPortfolioDomain)

    @field_validator("lifecycle", mode="before")
    @classmethod
    def _lifecycle_enum(cls, value: Any) -> Any:
        return _enum_value(value, CapabilityLifecycleState)

    @field_validator("version")
    @classmethod
    def _semantic_version(cls, value: str) -> str:
        if not _SEMVER_RE.fullmatch(value):
            raise ValueError("loop version must use semantic versioning")
        return value

    @field_validator(
        "triggers",
        "agent_role_refs",
        "primitive_steps",
        "tool_requirements",
        "artifact_requirements",
        "outcome_metrics",
        "surfaces",
        "required_operational_readiness_gates",
        "certification_tests",
        "known_blockers",
        mode="before",
    )
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @field_validator("declaration_digest")
    @classmethod
    def _optional_digest(cls, value: str) -> str:
        clean = value.strip().lower()
        if clean and not _SHA256_RE.fullmatch(clean):
            raise ValueError("declaration_digest must be lowercase SHA-256")
        return clean

    def _declaration_payload(self) -> dict[str, Any]:
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={
                "lifecycle",
                "gtm_visible",
                "known_blockers",
                "certification",
                "declaration_digest",
            },
            exclude_none=True,
        )
        for surface in payload.get("surfaces", []):
            surface.pop("lifecycle", None)
        return payload

    @model_validator(mode="after")
    def _manifest_is_closed_and_honest(self) -> Self:
        expected_digest = _stable_digest(self._declaration_payload())
        if self.declaration_digest and self.declaration_digest != expected_digest:
            raise ValueError("declaration_digest does not match the canonical declaration")
        object.__setattr__(self, "declaration_digest", expected_digest)

        _unique(tuple(item.trigger_ref for item in self.triggers), label="loop triggers")
        _unique(self.agent_role_refs, label="loop agent roles")
        _unique(tuple(item.step_ref for item in self.primitive_steps), label="primitive steps")
        _unique(
            tuple(item.binding_ref for item in self.tool_requirements),
            label="loop Tool bindings",
        )
        _unique(
            tuple(item.artifact_ref for item in self.artifact_requirements),
            label="loop artifacts",
        )
        _unique(
            tuple(item.metric_ref for item in self.outcome_metrics),
            label="loop outcome metrics",
        )

        roles = set(self.agent_role_refs)
        if any(item.agent_role_ref not in roles for item in self.primitive_steps):
            raise ValueError("every primitive step must use a declared agent role")
        if any(
            item.produced_by_agent_role_ref not in roles
            for item in self.artifact_requirements
        ):
            raise ValueError("every artifact producer must use a declared agent role")
        if any(
            item.accepted_by_role_ref not in roles
            for item in self.artifact_requirements
        ):
            raise ValueError("every artifact acceptor must use a declared agent role")

        bindings = {item.binding_ref: item for item in self.tool_requirements}
        for step in self.primitive_steps:
            if any(ref not in bindings for ref in step.tool_binding_refs):
                raise ValueError("primitive steps may use only declared Tool bindings")
            step_bindings = [bindings[ref] for ref in step.tool_binding_refs]
            write_bindings = [
                item for item in step_bindings if item.effect == ConnectorEffect.WRITE
            ]
            if write_bindings and (
                step.effect != ConnectorEffect.WRITE or not step.approval_required
            ):
                raise ValueError(
                    "steps using write Tool bindings must declare a write effect and approval"
                )
            if step.effect == ConnectorEffect.WRITE and not write_bindings:
                raise ValueError("write primitive steps need a write Tool binding")

        if self.completion_slo_seconds > self.budget.max_elapsed_seconds:
            raise ValueError("completion SLO cannot exceed the loop elapsed-time budget")

        reconciliation_state = self.execution_policy.ambiguous_effect_terminal_state
        reconciliation_states = {
            item.state
            for item in self.state_machine.terminal_states
            if item.disposition == LoopTerminalDisposition.RECONCILIATION_REQUIRED
        }
        if reconciliation_state is None:
            if reconciliation_states:
                raise ValueError(
                    "ambiguity-not-applicable loops cannot declare reconciliation terminals"
                )
        else:
            if reconciliation_state not in reconciliation_states:
                raise ValueError(
                    "ambiguous_effect_terminal_state must be a human-visible "
                    "reconciliation terminal"
                )
            if not any(
                item.event_ref == self.execution_policy.ambiguous_effect_event_ref
                and item.to_state == reconciliation_state
                for item in self.state_machine.transitions
            ):
                raise ValueError("the state machine must route ambiguity to reconciliation")

        surfaces = tuple(item.surface for item in self.surfaces)
        _unique(surfaces, label="loop surfaces")
        if set(surfaces) != set(LoopSurface):
            raise ValueError("Agents, SDK, MCP, and ChatGPT projections are all required")

        test_gates = {item.gate for item in self.certification_tests}
        if test_gates != set(LoopCertificationGate):
            raise ValueError("certification tests must cover all ten certification gates")
        _unique(
            tuple(item.test_ref for item in self.certification_tests),
            label="certification tests",
        )
        _unique(
            self.required_operational_readiness_gates,
            label="operational readiness gates",
        )

        if self.lifecycle == CapabilityLifecycleState.CERTIFIED:
            if not self.gtm_visible:
                raise ValueError("CERTIFIED loops must be GTM-visible")
            if self.known_blockers:
                raise ValueError("CERTIFIED loops cannot retain known blockers")
            if self.certification is None:
                raise ValueError("CERTIFIED loops require a Spring/operator certification")
            if (
                self.certification.loop_ref != self.loop_ref
                or self.certification.loop_version != self.version
                or self.certification.declaration_digest != expected_digest
            ):
                raise ValueError("certification must bind this exact loop declaration")
            evidence_by_gate = {
                item.gate: item for item in self.certification.gate_evidence
            }
            for gate in LoopCertificationGate:
                declared_tests = tuple(
                    sorted(
                        test.test_ref
                        for test in self.certification_tests
                        if test.gate == gate
                    )
                )
                supplied = evidence_by_gate[gate]
                if tuple(sorted(supplied.test_refs)) != declared_tests:
                    raise ValueError(
                        "certification must bind the exact declared tests for "
                        f"{gate.value}"
                    )
                required_kinds = {
                    test.required_evidence_kind
                    for test in self.certification_tests
                    if test.gate == gate
                }
                supplied_kinds = {
                    evidence.kind for evidence in supplied.evidence_refs
                }
                if not required_kinds.issubset(supplied_kinds):
                    raise ValueError(
                        "certification evidence kinds are incomplete for "
                        f"{gate.value}"
                    )
            test_executions = {
                item.test_ref: item
                for item in self.certification.test_execution_evidence
            }
            declared_tests_by_ref = {
                item.test_ref: item for item in self.certification_tests
            }
            if set(test_executions) != set(declared_tests_by_ref):
                raise ValueError(
                    "certification must bind every exact test execution"
                )
            for test_ref, declared_test in declared_tests_by_ref.items():
                execution = test_executions[test_ref]
                if (
                    execution.gate != declared_test.gate
                    or execution.declared_environment != declared_test.environment
                ):
                    raise ValueError(
                        "certification test execution must bind its declared environment"
                    )
                evidence_by_ref = {
                    item.evidence_ref: item
                    for item in evidence_by_gate[declared_test.gate].evidence_refs
                }
                if declared_test.required_evidence_kind not in {
                    evidence_by_ref[ref].kind for ref in execution.evidence_refs
                }:
                    raise ValueError(
                        "certification test execution lacks its declared evidence kind"
                    )
            if any(
                item.certification_target is None for item in self.outcome_metrics
            ):
                raise ValueError("CERTIFIED loops require explicit outcome targets")
            outcome_measurements = {
                item.metric_ref: item
                for item in self.certification.outcome_measurements
            }
            declared_metrics = {
                item.metric_ref: item for item in self.outcome_metrics
            }
            if set(outcome_measurements) != set(declared_metrics):
                raise ValueError(
                    "certification must measure every exact declared outcome"
                )
            for metric_ref, metric in declared_metrics.items():
                measurement = outcome_measurements[metric_ref]
                if (
                    measurement.direction != metric.direction
                    or measurement.unit != metric.unit
                    or measurement.source_system_ref != metric.source_system_ref
                    or measurement.required_sample_count
                    != metric.required_sample_count
                    or measurement.target != metric.certification_target
                    or measurement.comparison != metric.certification_comparison
                ):
                    raise ValueError(
                        "certification outcome must bind the exact metric contract"
                    )
            required_surfaces = [item for item in self.surfaces if not item.optional]
            if any(
                item.lifecycle != CapabilityLifecycleState.CERTIFIED
                for item in required_surfaces
            ):
                raise ValueError("required loop surfaces must be certified together")
        else:
            if self.gtm_visible:
                raise ValueError("only CERTIFIED loops may be GTM-visible")
            if self.certification is not None:
                raise ValueError("non-certified loops cannot carry certification authority")
            if self.lifecycle in {
                CapabilityLifecycleState.PREVIEW,
                CapabilityLifecycleState.QUARANTINED,
            } and not self.known_blockers:
                raise ValueError("PREVIEW and QUARANTINED loops must disclose blockers")
        return self

    def manifest_digest(self) -> str:
        return _stable_digest(self.to_dict())


class GoldenLoopCatalog(_StrictModel):
    schema_id: Literal["lightbulb.golden_loop_catalog.v1"] = Field(
        default=GOLDEN_LOOP_CATALOG_SCHEMA,
        alias="schema",
    )
    manifests: tuple[LoopCertificationManifest, ...] = Field(
        min_length=1,
        max_length=1_000,
    )
    catalog_digest: str = Field(
        default="",
        pattern=r"^(?:[0-9a-f]{64})?$",
    )

    @field_validator("manifests", mode="before")
    @classmethod
    def _tuple_manifests(cls, value: Any) -> Any:
        return _as_tuple(value)

    @field_validator("catalog_digest")
    @classmethod
    def _optional_digest(cls, value: str) -> str:
        clean = value.strip().lower()
        if clean and not _SHA256_RE.fullmatch(clean):
            raise ValueError("catalog_digest must be lowercase SHA-256")
        return clean

    @model_validator(mode="after")
    def _catalog_is_unique_and_sealed(self) -> Self:
        keys = tuple((item.loop_ref, item.version) for item in self.manifests)
        _unique(keys, label="Golden Loop versions")
        canonical = tuple(sorted(self.manifests, key=lambda item: (item.loop_ref, item.version)))
        if self.manifests != canonical:
            raise ValueError("Golden Loop manifests must use canonical ref/version order")
        expected = _stable_digest([item.to_dict() for item in self.manifests])
        if self.catalog_digest and self.catalog_digest != expected:
            raise ValueError("catalog_digest does not match the exact manifest set")
        object.__setattr__(self, "catalog_digest", expected)
        return self

    def get(self, loop_ref: str, version: str) -> LoopCertificationManifest:
        for manifest in self.manifests:
            if manifest.loop_ref == loop_ref and manifest.version == version:
                return manifest
        raise KeyError(f"Golden Loop is not declared: {loop_ref}@{version}")

    def assert_initial_gtm_coverage(self) -> None:
        domains = {item.portfolio_domain for item in self.manifests}
        missing = set(GoldenLoopPortfolioDomain) - domains
        if missing:
            raise ValueError(
                "Golden Loop catalog is missing GTM portfolio domains: "
                + ", ".join(sorted(item.value for item in missing))
            )


__all__ = [
    "AmbiguousOutcomePolicy",
    "CapabilityLifecycleState",
    "GOLDEN_LOOP_CATALOG_SCHEMA",
    "GoldenLoopCatalog",
    "GoldenLoopPortfolioDomain",
    "LOOP_CERTIFICATION_CANDIDATE_SCHEMA",
    "LOOP_CERTIFICATION_MANIFEST_SCHEMA",
    "LOOP_CERTIFICATION_RECORD_SCHEMA",
    "SPRING_OPERATOR_CERTIFICATION_PENDING_BLOCKER",
    "LoopArtifactRequirement",
    "LoopCertificationGate",
    "LoopCertificationGateEvidence",
    "LoopCertificationCandidate",
    "LoopCertificationManifest",
    "LoopCertificationRecord",
    "LoopCertificationTest",
    "LoopCertificationTestExecutionEvidence",
    "LoopExecutionBudget",
    "LoopExecutionPolicy",
    "LoopHarnessPolicy",
    "LoopImplementationBinding",
    "LoopOutcomeMetric",
    "LoopOutcomeCertificationMeasurement",
    "LoopPrimitiveStep",
    "LoopStateMachine",
    "LoopSurface",
    "LoopSurfaceProjection",
    "LoopTerminalDisposition",
    "LoopTerminalState",
    "LoopToolRequirement",
    "LoopTransition",
    "LoopTrigger",
    "build_loop_certification_candidate",
]
