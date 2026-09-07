"""Generated MCP projection for the software-production golden loop (Work Package 1C).

The catalog mirrors ``lightbulb.dynamic_workflow_mcp``: one canonical
snake_case wire shape, explicit transport aliases, exact OAuth scopes,
optimistic concurrency and idempotency on every mutation, and fail-closed
validation.  Unlike the hand-written dynamic-workflow schemas, every tool
schema here is **derived from the SDK models** in ``software_production`` and
``software_production_loop`` so the projection cannot drift from the domain.

MCP stays a thin projection: the authenticated principal supplies tenant,
project, and actor identity; Spring's Execution Run remains the source of
truth for run identity, revision, and cancellation; the Tasks-extension
projection is data on every response with a polling fallback because the
FastMCP runtime does not implement the Tasks capability.
"""

from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from dataclasses import dataclass
from types import MappingProxyType
from typing import Annotated, Any, Callable, Iterable, Literal, Mapping, Protocol, Sequence
from uuid import NAMESPACE_URL, uuid5

from pydantic import BaseModel, Field, StringConstraints, ValidationError, field_validator

from lightbulb.software_production import (
    TERMINAL_STATUSES,
    AcceptanceSpecification,
    BudgetPolicy,
    ChangeObjective,
    ChangeRisk,
    ChangeScope,
    EvidenceReceipt,
    EvidenceRequirements,
    HarnessFamily,
    HarnessPolicy,
    ReleasePolicy,
    RiskPolicy,
    RunEvent,
    RunStatus,
    SoftwareProductionCompilation,
    WorkSpecification,
    compile_software_production_request,
    seal_software_production_request,
)
from lightbulb.software_production_loop import (
    BudgetLedger,
    CancellationState,
    EffectReceipt,
    ExecutionRunControl,
    InMemoryHarnessGrantPort,
    LoopTransitionReceipt,
    LoopTransitionResult,
    OpaqueRef,
    Sha256Digest,
    ShortText,
    SoftwareProductionLoopRunner,
    SoftwareProductionLoopState,
    _StrictModel,
    _timestamp,
    admit_software_production_run,
    apply_control_update,
    apply_software_production_event,
    seal_loop_command,
)


PROTOCOL_VERSION = "0.1"
MANIFEST_SCHEMA = "lightbulb.software_production_mcp_manifest.v1"
READ_SCOPE = "lightbulb:software_production.read"
WRITE_SCOPE = "lightbulb:software_production.write"
APPROVE_SCOPE = "lightbulb:software_production.approve"
TOOL_PREFIX = "software_production_"
RUN_REF_PATTERN = r"^spr_[a-f0-9]{32}$"
MANIFEST_RESOURCE_URI = "software-production://manifest"
DEPRECATIONS_RESOURCE_URI = "software-production://deprecations"

_EXPECTED_OPERATIONS = ("start", "status", "supply_input", "approve_checkpoint", "cancel", "resolve_reconciliation")
_SNAKE_CASE = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$")
_FORBIDDEN_FIELD_MARKERS = ("tenant", "company_id", "user_id", "project_id", "actor", "execution_run_id", "session", "token", "credential", "secret", "api_key", "capability")
_MAX_JSON_BYTES = 1_048_576
_MAX_JSON_DEPTH = 16
_MAX_JSON_NODES = 20_000

RunRef = Annotated[str, StringConstraints(pattern=RUN_REF_PATTERN)]
IdempotencyKey = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")]
BoundedReason = Annotated[str, StringConstraints(min_length=1, max_length=2000)]

TaskStatus = Literal["working", "input_required", "completed", "failed", "cancelled"]
Awaiting = Literal[
    "spring_work_packet", "spring_harness_selection", "spring_builder_grant", "builder_result", "evaluator_verdict", "release_candidate",
    "ci_and_policy", "staging_verification", "production_approval", "production_effect", "production_observation", "production_verification",
    "reconciliation", "none",
]
ClientEvent = Literal[
    "produce_change", "accept", "reject", "form_release_candidate", "verify_ci_and_policy", "verify_staging", "execute_production",
    "observe_production", "verify_production", "roll_back", "block",
]
_ROLE_BY_CLIENT_EVENT: dict[str, str] = {
    "produce_change": "builder",
    "accept": "evaluator",
    "reject": "evaluator",
    "form_release_candidate": "release_connector",
    "verify_ci_and_policy": "release_connector",
    "verify_staging": "release_connector",
    "execute_production": "release_connector",
    "roll_back": "release_connector",
    "block": "release_connector",
    "observe_production": "observer",
    "verify_production": "observer",
}
_AWAITING_BY_STATUS: dict[str, str] = {
    "request_admitted": "spring_work_packet",
    "work_packet_compiled": "spring_harness_selection",
    "harness_selected": "spring_builder_grant",
    "builder_authorized": "builder_result",
    "change_produced": "evaluator_verdict",
    "independent_acceptance": "release_candidate",
    "release_candidate_formed": "ci_and_policy",
    "ci_and_policy_verified": "staging_verification",
    "staging_verified": "production_approval",
    "production_release_authorized": "production_effect",
    "production_effect_executed": "production_observation",
    "production_observed": "production_verification",
}
_INPUT_REQUIRED_AWAITING = frozenset({"builder_result", "evaluator_verdict", "production_approval", "reconciliation"})


class SoftwareProductionMcpProtocolError(ValueError):
    """Base class for catalog, authorization, and payload failures."""


class UnknownSoftwareProductionOperation(SoftwareProductionMcpProtocolError):
    """Raised when an operation/tool name is not exactly cataloged."""


class SoftwareProductionScopeError(SoftwareProductionMcpProtocolError):
    """Raised when every required OAuth scope is not present."""


class SoftwareProductionPayloadError(SoftwareProductionMcpProtocolError):
    """Raised when an input or output fails its declared schema."""


class SoftwareProductionCatalogError(SoftwareProductionMcpProtocolError):
    """Raised when the catalog violates a protocol invariant."""


# --------------------------------------------------------------------------- #
# Wire models (derived schemas)
# --------------------------------------------------------------------------- #


class PublicScope(_StrictModel):
    company_ref: OpaqueRef
    project_ref: OpaqueRef


class PublicOrigin(_StrictModel):
    """Public originating-workflow references; the requesting agent and idempotency key come from the envelope."""

    originating_workflow_ref: OpaqueRef
    originating_run_ref: OpaqueRef
    originating_step_ref: OpaqueRef | None = None


class SoftwareProductionStartBody(_StrictModel):
    """The 1A request minus scope and actor identity, which the authenticated principal supplies."""

    origin: PublicOrigin
    objective: ChangeObjective
    change_scope: ChangeScope
    work: WorkSpecification
    acceptance: AcceptanceSpecification
    harness_policy: HarnessPolicy
    risk: RiskPolicy
    release: ReleasePolicy
    budget: BudgetPolicy = Field(default_factory=BudgetPolicy)
    evidence: EvidenceRequirements | None = None
    requested_at: str

    @field_validator("requested_at")
    @classmethod
    def _requested(cls, value: str) -> str:
        return _timestamp(value, field_name="requested_at")


class StartInput(_StrictModel):
    company_ref: OpaqueRef
    project_ref: OpaqueRef
    expected_revision: Literal[0] = 0
    idempotency_key: IdempotencyKey
    request: SoftwareProductionStartBody


class StatusInput(_StrictModel):
    company_ref: OpaqueRef
    project_ref: OpaqueRef
    run_ref: RunRef


class SuppliedLoopInput(_StrictModel):
    """What a bound builder, evaluator, release connector, or observer may supply; the role is implied by the event."""

    event: ClientEvent
    receipts: tuple[EvidenceReceipt, ...] = Field(default_factory=tuple, max_length=50)
    effects: tuple[EffectReceipt, ...] = Field(default_factory=tuple, max_length=10)
    evaluator_accepted: bool | None = None
    reason: BoundedReason | None = None
    host_outcome_report: Literal["reported_certain", "reported_in_doubt", "unreported"] = "reported_certain"


class SupplyInputInput(_StrictModel):
    company_ref: OpaqueRef
    project_ref: OpaqueRef
    run_ref: RunRef
    expected_revision: int = Field(ge=1, le=120)
    idempotency_key: IdempotencyKey
    input: SuppliedLoopInput


class ApproveCheckpointInput(_StrictModel):
    company_ref: OpaqueRef
    project_ref: OpaqueRef
    run_ref: RunRef
    expected_revision: int = Field(ge=1, le=120)
    idempotency_key: IdempotencyKey
    checkpoint: Literal["production_release"]
    decision: Literal["approve", "deny"]
    approval_ref: OpaqueRef
    reason: BoundedReason | None = None


class CancelInput(_StrictModel):
    company_ref: OpaqueRef
    project_ref: OpaqueRef
    run_ref: RunRef
    expected_revision: int = Field(ge=1, le=120)
    idempotency_key: IdempotencyKey
    reason: BoundedReason


class ResolveReconciliationInput(_StrictModel):
    company_ref: OpaqueRef
    project_ref: OpaqueRef
    run_ref: RunRef
    expected_revision: int = Field(ge=1, le=120)
    idempotency_key: IdempotencyKey
    reconciliation_ref: OpaqueRef
    disposition: Literal["resume", "fail", "roll_back"]
    evidence: tuple[EvidenceReceipt, ...] = Field(default_factory=tuple, max_length=50)
    effects: tuple[EffectReceipt, ...] = Field(default_factory=tuple, max_length=10)
    reason: BoundedReason


class TaskProjection(_StrictModel):
    """MCP Tasks-extension shape projected from the Spring Execution Run; delivered by polling."""

    task_id: RunRef
    status: TaskStatus
    status_message: ShortText
    created_at: str
    last_updated_at: str
    poll_interval_ms: int = Field(default=5000, ge=250, le=600_000)
    ttl_ms: int | None = Field(default=None, ge=1000)
    identity_source: Literal["spring_execution_run"] = "spring_execution_run"
    delivery: Literal["polling"] = "polling"

    @field_validator("created_at", "last_updated_at")
    @classmethod
    def _times(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=str(info.field_name))


class RunProjection(_StrictModel):
    run_ref: RunRef
    revision: int = Field(ge=1, le=120)
    status: RunStatus
    state_digest: Sha256Digest
    compilation_digest: Sha256Digest
    scope: PublicScope
    awaiting: Awaiting
    cancellation_state: CancellationState
    task: TaskProjection


class StartOutput(RunProjection):
    request_digest: Sha256Digest
    acceptance_contract_digest: Sha256Digest
    effective_risk: ChangeRisk
    allowed_hosts: tuple[HarnessFamily, ...] = Field(min_length=1)


class StatusOutput(RunProjection):
    evidence_kinds: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=50)
    budget: BudgetLedger
    last_event: RunEvent
    last_transition_at: str
    reconciliation_pending: bool


class TransitionOutput(RunProjection):
    transition: LoopTransitionReceipt


class CancelOutput(RunProjection):
    cancelled: Literal[True] = True
    cancelled_at: str


# --------------------------------------------------------------------------- #
# Mechanics: request assembly, command assembly, projections
# --------------------------------------------------------------------------- #


def run_ref_for(execution_run_id: str) -> str:
    """Public opaque handle for a Spring Execution Run id (never the raw UUID)."""

    return "spr_" + hashlib.sha256(f"software-production-run:{execution_run_id}".encode("utf-8")).hexdigest()[:32]


def build_start_request(body: SoftwareProductionStartBody | Mapping[str, Any], *, tenant_ref: str, company_ref: str, project_ref: str, project_id: str, requesting_agent_ref: str, idempotency_key: str) -> dict[str, Any]:
    """Assemble and seal the 1A request from a public start body plus principal-resolved identity."""

    parsed = SoftwareProductionStartBody.model_validate(body)
    raw = parsed.to_dict()
    origin = raw.pop("origin")
    request = {
        "scope": {"tenant_ref": tenant_ref, "company_ref": company_ref, "project_ref": project_ref, "project_id": project_id},
        "origin": {**origin, "requesting_agent_ref": requesting_agent_ref, "idempotency_key": idempotency_key},
        **raw,
    }
    return seal_software_production_request(request)


def loop_command_for_input(state: SoftwareProductionLoopState | Mapping[str, Any], supplied: SuppliedLoopInput | Mapping[str, Any], *, actor_ref: str, idempotency_key: str, expected_revision: int, occurred_at: str) -> dict[str, Any]:
    """Seal a loop command for a client-supplied input; role follows the event and fences follow the run."""

    parsed_state = SoftwareProductionLoopState.model_validate(state)
    parsed = SuppliedLoopInput.model_validate(supplied)
    if 1 <= expected_revision < parsed_state.version:
        # An exact retry of an already-retained transition must reproduce the same command so it is answered as a duplicate.
        expected_digest = parsed_state.transition_history[expected_revision].prior_state_digest
    else:
        expected_digest = parsed_state.state_digest
    retained = next((item.command for item in parsed_state.transition_history if item.command.idempotency_key == idempotency_key), None)
    if retained is not None:
        occurred_at = retained.occurred_at
    return seal_loop_command(
        {
            "event": parsed.event,
            "transition_ref": f"{parsed.event}:{parsed_state.compilation_digest[:12]}:{expected_revision + 1}",
            "idempotency_key": idempotency_key,
            "expected_version": expected_revision,
            "expected_state_digest": expected_digest,
            "expected_cancellation_fence": parsed_state.control.cancellation_fence,
            "occurred_at": occurred_at,
            "actor_ref": actor_ref,
            "actor_role": _ROLE_BY_CLIENT_EVENT[parsed.event],
            "host_outcome_report": parsed.host_outcome_report,
            "receipts": [item.to_dict() for item in parsed.receipts],
            "effects": [item.to_dict() for item in parsed.effects],
            "evaluator_accepted": parsed.evaluator_accepted,
            "reason": parsed.reason,
        }
    )


def awaiting_for(compilation: SoftwareProductionCompilation, state: SoftwareProductionLoopState, *, reconciliation_pending: bool = False) -> str:
    if reconciliation_pending:
        return "reconciliation"
    if state.status in TERMINAL_STATUSES:
        return "none"
    awaiting = _AWAITING_BY_STATUS[state.status]
    if awaiting == "staging_verification" and "staging" not in compilation.dynamic_workflow_start.workflow_spec["release_policy"]["allowed_environments"]:
        return "production_approval"
    return awaiting


def task_projection(state: SoftwareProductionLoopState, *, run_ref: str, awaiting: str, created_at: str, updated_at: str, poll_interval_ms: int = 5000) -> dict[str, Any]:
    """Project the run onto the MCP Tasks status vocabulary; Spring's run is the identity, polling is the delivery."""

    if state.status == "cancelled":
        status, message = "cancelled", "the Execution Run was cancelled"
    elif state.status == "production_verified":
        status, message = "completed", "production verified by the independent observer"
    elif state.status in TERMINAL_STATUSES:
        status, message = "failed", f"run ended in {state.status}"
    elif awaiting == "reconciliation":
        status, message = "input_required", "an ambiguous outcome awaits reconciliation"
    elif state.control.cancellation_state != "ACTIVE":
        status, message = "working", "cancellation requested; only cancel may proceed"
    elif awaiting in _INPUT_REQUIRED_AWAITING:
        status, message = "input_required", f"awaiting {awaiting.replace('_', ' ')}"
    else:
        status, message = "working", f"awaiting {awaiting.replace('_', ' ')}"
    return TaskProjection(task_id=run_ref, status=status, status_message=message, created_at=created_at, last_updated_at=updated_at, poll_interval_ms=poll_interval_ms).to_dict()


def project_run(compilation: SoftwareProductionCompilation, state: SoftwareProductionLoopState, *, run_ref: str, created_at: str, updated_at: str, reconciliation_pending: bool = False) -> dict[str, Any]:
    awaiting = awaiting_for(compilation, state, reconciliation_pending=reconciliation_pending)
    return {
        "run_ref": run_ref,
        "revision": state.version,
        "status": state.status,
        "state_digest": state.state_digest,
        "compilation_digest": state.compilation_digest,
        "scope": {"company_ref": compilation.scope.company_ref, "project_ref": compilation.scope.project_ref},
        "awaiting": awaiting,
        "cancellation_state": state.control.cancellation_state,
        "task": task_projection(state, run_ref=run_ref, awaiting=awaiting, created_at=created_at, updated_at=updated_at),
    }


# --------------------------------------------------------------------------- #
# Catalog
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class SoftwareProductionMcpOperation:
    """Immutable declarative operation contract with model-derived schemas."""

    operation: str
    tool_name: str
    title: str
    description: str
    required_scopes: tuple[str, ...]
    mutating: bool
    destructive: bool
    input_model: type[BaseModel]
    output_model: type[BaseModel]
    input_schema: Mapping[str, Any]
    output_schema: Mapping[str, Any]
    input_aliases: Mapping[str, tuple[str, ...]]
    output_aliases: Mapping[str, tuple[str, ...]]
    state_preconditions: tuple[str, ...] = ()
    task_statuses: tuple[str, ...] = ()

    @property
    def read_only(self) -> bool:
        return not self.mutating


@dataclass(frozen=True, slots=True)
class ValidatedSoftwareProductionCall:
    operation: SoftwareProductionMcpOperation
    payload: Mapping[str, Any]


def _camel_case(value: str) -> str:
    head, *tail = value.split("_")
    return head + "".join(piece[:1].upper() + piece[1:] for piece in tail)


def _top_level_aliases(schema: Mapping[str, Any]) -> dict[str, tuple[str, ...]]:
    aliases: dict[str, tuple[str, ...]] = {}
    for name in schema.get("properties", {}):
        alias = _camel_case(name)
        if alias != name:
            aliases[name] = (alias,)
    return aliases


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze(item) for key, item in value.items()})
    if isinstance(value, list | tuple):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return deepcopy(value)


def derive_schema(model: type[BaseModel], *, mode: Literal["validation", "serialization"]) -> dict[str, Any]:
    """JSON Schema generated from the SDK model; the envelope is always a closed object."""

    schema = model.model_json_schema(by_alias=True, mode=mode)
    schema["type"] = "object"
    schema["additionalProperties"] = False
    schema.setdefault("x-lightbulb-max-json-bytes", _MAX_JSON_BYTES)
    schema.setdefault("x-lightbulb-max-depth", _MAX_JSON_DEPTH)
    schema.setdefault("x-lightbulb-max-nodes", _MAX_JSON_NODES)
    schema["x-lightbulb-derived-from"] = f"{model.__module__}.{model.__qualname__}"
    return schema


def _operation(operation: str, title: str, description: str, *, required_scopes: Sequence[str], mutating: bool, destructive: bool, input_model: type[BaseModel], output_model: type[BaseModel], state_preconditions: Sequence[str] = (), task_statuses: Sequence[str] = ()) -> SoftwareProductionMcpOperation:
    input_schema = derive_schema(input_model, mode="validation")
    output_schema = derive_schema(output_model, mode="serialization")
    return SoftwareProductionMcpOperation(
        operation=operation,
        tool_name=TOOL_PREFIX + operation,
        title=title,
        description=description,
        required_scopes=tuple(required_scopes),
        mutating=mutating,
        destructive=destructive,
        input_model=input_model,
        output_model=output_model,
        input_schema=_freeze(input_schema),
        output_schema=_freeze(output_schema),
        input_aliases=_freeze(_top_level_aliases(input_schema)),
        output_aliases=_freeze(_top_level_aliases(output_schema)),
        state_preconditions=tuple(state_preconditions),
        task_statuses=tuple(task_statuses),
    )


_OPERATIONS = (
    _operation(
        "start",
        "Start governed software production",
        "Compile a typed software-production request onto the Work Packet and immutable acceptance contract, register the Spring Execution Run, and admit the loop. Scope, actor, and idempotency come from the authenticated principal and envelope; no harness is selected here.",
        required_scopes=(WRITE_SCOPE,),
        mutating=True,
        destructive=False,
        input_model=StartInput,
        output_model=StartOutput,
        state_preconditions=("authenticated_scope_exact", "acceptance_contract_immutable", "execution_run_registered_by_spring"),
        task_statuses=("working", "input_required"),
    ),
    _operation(
        "status",
        "Software production status",
        "Read the bounded run projection: lifecycle status, revision, what input is awaited, cancellation state, and the Tasks-style task projection for polling.",
        required_scopes=(READ_SCOPE,),
        mutating=False,
        destructive=False,
        input_model=StatusInput,
        output_model=StatusOutput,
        state_preconditions=("authenticated_scope_exact", "run_visible_to_principal"),
        task_statuses=("working", "input_required", "completed", "failed", "cancelled"),
    ),
    _operation(
        "supply_input",
        "Supply a loop input",
        "Submit one builder result, evaluator verdict, release-connector effect receipt, or observation as a replay-fenced loop transition. The role is implied by the event and must match the principal's binding; duplicates, stale revisions, and ambiguous outcomes are rejected with a typed recovery disposition.",
        required_scopes=(WRITE_SCOPE,),
        mutating=True,
        destructive=False,
        input_model=SupplyInputInput,
        output_model=TransitionOutput,
        state_preconditions=("authenticated_scope_exact", "expected_revision_current", "binding_role_matches_event", "builder_cannot_evaluate_own_work", "effects_authorized_by_connector_runtime"),
        task_statuses=("working", "input_required", "completed", "failed"),
    ),
    _operation(
        "approve_checkpoint",
        "Approve or deny a release checkpoint",
        "Record a human production-release approval or denial against an authorized approval reference. Approval authority stays in Spring; this tool never executes a deployment.",
        required_scopes=(WRITE_SCOPE, APPROVE_SCOPE),
        mutating=True,
        destructive=False,
        input_model=ApproveCheckpointInput,
        output_model=TransitionOutput,
        state_preconditions=("authenticated_scope_exact", "expected_revision_current", "approval_ref_issued_by_spring", "release_policy_allows_production"),
        task_statuses=("working", "failed"),
    ),
    _operation(
        "cancel",
        "Cancel software production",
        "Request cancellation of a non-terminal run through Spring's cancellation fence with optimistic concurrency.",
        required_scopes=(WRITE_SCOPE,),
        mutating=True,
        destructive=True,
        input_model=CancelInput,
        output_model=CancelOutput,
        state_preconditions=("authenticated_scope_exact", "expected_revision_current", "run_not_terminal"),
        task_statuses=("cancelled",),
    ),
    _operation(
        "resolve_reconciliation",
        "Resolve an ambiguous outcome",
        "Resolve a run parked on an in-doubt effect or host outcome: resume with the retained state, fail it with a reason, or roll back with connector evidence. Never replays the ambiguous effect.",
        required_scopes=(WRITE_SCOPE, APPROVE_SCOPE),
        mutating=True,
        destructive=True,
        input_model=ResolveReconciliationInput,
        output_model=TransitionOutput,
        state_preconditions=("authenticated_scope_exact", "expected_revision_current", "reconciliation_pending", "no_automatic_replay"),
        task_statuses=("working", "input_required", "failed"),
    ),
)


def validate_catalog(operations: Iterable[SoftwareProductionMcpOperation], *, require_complete: bool = True) -> tuple[SoftwareProductionMcpOperation, ...]:
    materialized = tuple(operations)
    by_operation: dict[str, SoftwareProductionMcpOperation] = {}
    tool_names: set[str] = set()
    known_scopes = {READ_SCOPE, WRITE_SCOPE, APPROVE_SCOPE}
    for item in materialized:
        if not isinstance(item, SoftwareProductionMcpOperation):
            raise SoftwareProductionCatalogError("catalog entries must be SoftwareProductionMcpOperation")
        if not _SNAKE_CASE.fullmatch(item.operation):
            raise SoftwareProductionCatalogError(f"invalid operation name: {item.operation!r}")
        if item.operation in by_operation or item.tool_name in tool_names:
            raise SoftwareProductionCatalogError("operation and tool names must be unique")
        if item.tool_name != TOOL_PREFIX + item.operation:
            raise SoftwareProductionCatalogError(f"tool name for {item.operation!r} must be {TOOL_PREFIX + item.operation!r}")
        if not item.required_scopes or any(scope not in known_scopes for scope in item.required_scopes):
            raise SoftwareProductionCatalogError(f"{item.operation} has missing or unknown scope requirements")
        if item.mutating and WRITE_SCOPE not in item.required_scopes:
            raise SoftwareProductionCatalogError(f"mutating operation {item.operation} must require the write scope")
        if not item.mutating and item.required_scopes != (READ_SCOPE,):
            raise SoftwareProductionCatalogError(f"read-only operation {item.operation} must require only the read scope")
        if item.destructive and not item.mutating:
            raise SoftwareProductionCatalogError("destructive operations must be mutating")
        if any(not isinstance(value, str) or not _SNAKE_CASE.fullmatch(value) for value in item.state_preconditions):
            raise SoftwareProductionCatalogError(f"{item.operation} has invalid state precondition names")
        if item.mutating and not item.state_preconditions:
            raise SoftwareProductionCatalogError(f"mutating operation {item.operation} must declare state preconditions")
        if not item.task_statuses or any(status not in {"working", "input_required", "completed", "failed", "cancelled"} for status in item.task_statuses):
            raise SoftwareProductionCatalogError(f"{item.operation} must declare the task statuses it can yield")
        for direction, schema, model in (("input", item.input_schema, item.input_model), ("output", item.output_schema, item.output_model)):
            if schema.get("type") != "object" or schema.get("additionalProperties") is not False:
                raise SoftwareProductionCatalogError(f"{item.operation} {direction} must be a closed object schema")
            properties = schema.get("properties")
            if not isinstance(properties, Mapping):
                raise SoftwareProductionCatalogError(f"{item.operation} {direction} properties are required")
            if any(not _SNAKE_CASE.fullmatch(str(name)) for name in properties):
                raise SoftwareProductionCatalogError(f"{item.operation} {direction} fields must use canonical snake_case")
            forbidden = [name for name in properties if any(marker in str(name).lower() for marker in _FORBIDDEN_FIELD_MARKERS)]
            if forbidden:
                raise SoftwareProductionCatalogError(f"{item.operation} {direction} exposes identity or credential fields: {forbidden}")
            if set(properties) != set(model.model_fields):
                raise SoftwareProductionCatalogError(f"{item.operation} {direction} schema drifted from {model.__name__}")
            missing_schema = set(schema.get("required", ())) - set(properties)
            if missing_schema:
                raise SoftwareProductionCatalogError(f"{item.operation} {direction} requires undeclared fields: {sorted(missing_schema)}")
        input_properties = set(item.input_schema.get("properties", {}))
        input_required = set(item.input_schema.get("required", ()))
        if not {"company_ref", "project_ref"}.issubset(input_required):
            raise SoftwareProductionCatalogError(f"operation {item.operation} must require public company and project scope")
        if item.operation != "start" and "run_ref" not in input_required:
            raise SoftwareProductionCatalogError(f"operation {item.operation} must require the public run handle")
        if item.mutating and not ({"idempotency_key"}.issubset(input_required) and "expected_revision" in input_properties):
            raise SoftwareProductionCatalogError(f"mutating operation {item.operation} must require revision and idempotency")
        if not item.mutating and {"expected_revision", "idempotency_key"} & input_properties:
            raise SoftwareProductionCatalogError(f"read-only operation {item.operation} cannot expose mutation controls")
        output_required = set(item.output_schema.get("required", ()))
        if not {"run_ref", "revision", "status", "task", "awaiting"}.issubset(output_required):
            raise SoftwareProductionCatalogError(f"operation {item.operation} output must carry the run projection")
        by_operation[item.operation] = item
        tool_names.add(item.tool_name)
    if require_complete and tuple(by_operation) != _EXPECTED_OPERATIONS:
        raise SoftwareProductionCatalogError(f"catalog operations must be exactly {_EXPECTED_OPERATIONS!r} in protocol order")
    return materialized


OPERATIONS = validate_catalog(_OPERATIONS)
OPERATION_CATALOG: Mapping[str, SoftwareProductionMcpOperation] = MappingProxyType({item.operation: item for item in OPERATIONS})
TOOL_CATALOG: Mapping[str, SoftwareProductionMcpOperation] = MappingProxyType({item.tool_name: item for item in OPERATIONS})

DEPRECATED_TOOL_ALIASES: Mapping[str, Mapping[str, Any]] = MappingProxyType(
    {
        "software_delivery_context": MappingProxyType({"replacement": "software_production_status", "file": "lightbulb/mcp_server.py", "notes": "Context reads become the run projection; no free-form delivery context object.", "since_protocol": PROTOCOL_VERSION, "removal": "two release cycles after the alias ships; the alias answers with a deprecation notice and the replacement tool name"}),
        "software_delivery_loop": MappingProxyType({"replacement": "software_production_start", "file": "lightbulb/mcp_server.py", "notes": "The loop starts from a typed request; progress is supplied through software_production_supply_input and read through software_production_status.", "since_protocol": PROTOCOL_VERSION, "removal": "two release cycles after the alias ships"}),
        "software_spot_weld_fix": MappingProxyType({"replacement": "software_production_start", "file": "lightbulb/mcp_server.py", "notes": "A spot-weld fix is a start with change_type=defect_fix and automation_level=candidate_only; no separate fix tool.", "since_protocol": PROTOCOL_VERSION, "removal": "two release cycles after the alias ships"}),
    }
)


def get_operation(identifier: str) -> SoftwareProductionMcpOperation:
    if not isinstance(identifier, str) or not identifier:
        raise UnknownSoftwareProductionOperation("operation identifier must be a non-empty string")
    operation = OPERATION_CATALOG.get(identifier) or TOOL_CATALOG.get(identifier)
    if operation is None:
        raise UnknownSoftwareProductionOperation(f"unknown software-production operation: {identifier!r}")
    return operation


def require_operation_scopes(identifier: str, granted_scopes: str | Iterable[str]) -> SoftwareProductionMcpOperation:
    operation = get_operation(identifier)
    if isinstance(granted_scopes, str):
        granted = {scope for scope in granted_scopes.split() if scope}
    else:
        try:
            supplied = tuple(granted_scopes)
        except TypeError as exc:
            raise SoftwareProductionScopeError("granted scopes must be a string or iterable") from exc
        if any(not isinstance(scope, str) or not scope for scope in supplied):
            raise SoftwareProductionScopeError("granted scope iterables may contain only non-empty strings")
        granted = set(supplied)
    missing = [scope for scope in operation.required_scopes if scope not in granted]
    if missing:
        raise SoftwareProductionScopeError(f"{operation.tool_name} requires scope(s): {', '.join(missing)}")
    return operation


def normalize_transport_payload(identifier: str, payload: Mapping[str, Any], *, direction: str = "input") -> dict[str, Any]:
    operation = get_operation(identifier)
    if direction not in {"input", "output"}:
        raise SoftwareProductionPayloadError("direction must be 'input' or 'output'")
    if not isinstance(payload, Mapping):
        raise SoftwareProductionPayloadError(f"{direction} payload must be an object")
    alias_catalog = operation.input_aliases if direction == "input" else operation.output_aliases
    alias_to_canonical = {alias: canonical for canonical, aliases in alias_catalog.items() for alias in aliases}
    normalized: dict[str, Any] = {}
    for raw_key, value in payload.items():
        if not isinstance(raw_key, str):
            raise SoftwareProductionPayloadError(f"{direction} object keys must be strings")
        canonical = alias_to_canonical.get(raw_key, raw_key)
        if canonical in normalized:
            raise SoftwareProductionPayloadError(f"ambiguous {direction} field supplied more than once: {canonical}")
        normalized[canonical] = deepcopy(value)
    return normalized


def _json_stats(value: Any, depth: int) -> tuple[int, int]:
    if isinstance(value, Mapping):
        nodes, deepest = 1, depth
        for item in value.values():
            child_nodes, child_depth = _json_stats(item, depth + 1)
            nodes += child_nodes
            deepest = max(deepest, child_depth)
        return nodes, deepest
    if isinstance(value, (list, tuple)):
        nodes, deepest = 1, depth
        for item in value:
            child_nodes, child_depth = _json_stats(item, depth + 1)
            nodes += child_nodes
            deepest = max(deepest, child_depth)
        return nodes, deepest
    return 1, depth


def _check_bounds(schema: Mapping[str, Any], payload: Mapping[str, Any], path: str) -> None:
    try:
        encoded = json.dumps(payload, ensure_ascii=False, default=str)
    except (TypeError, ValueError) as exc:
        raise SoftwareProductionPayloadError(f"{path} must be JSON-serializable") from exc
    if len(encoded.encode("utf-8")) > int(schema.get("x-lightbulb-max-json-bytes", _MAX_JSON_BYTES)):
        raise SoftwareProductionPayloadError(f"{path} exceeds the bounded JSON size")
    nodes, depth = _json_stats(payload, 1)
    if depth > int(schema.get("x-lightbulb-max-depth", _MAX_JSON_DEPTH)) or nodes > int(schema.get("x-lightbulb-max-nodes", _MAX_JSON_NODES)):
        raise SoftwareProductionPayloadError(f"{path} exceeds the bounded JSON depth or node count")


def _validate_with_model(model: type[BaseModel], payload: Any, path: str) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        raise SoftwareProductionPayloadError(f"{path} must be an object")
    try:
        parsed = model.model_validate(dict(payload))
    except (ValidationError, ValueError) as exc:
        first = exc.errors()[0] if isinstance(exc, ValidationError) and exc.errors() else None
        location = ".".join(str(part) for part in first["loc"]) if first else ""
        message = first["msg"] if first else str(exc)
        raise SoftwareProductionPayloadError(f"{path}{'.' + location if location else ''}: {message}") from exc
    return parsed.to_dict()  # type: ignore[attr-defined]


def validate_operation_input(identifier: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    operation = get_operation(identifier)
    path = f"{operation.tool_name}.input"
    if isinstance(payload, Mapping):
        _check_bounds(operation.input_schema, payload, path)
    return _validate_with_model(operation.input_model, payload, path)


def validate_operation_output(identifier: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    operation = get_operation(identifier)
    path = f"{operation.tool_name}.output"
    if isinstance(payload, Mapping):
        _check_bounds(operation.output_schema, payload, path)
    validated = _validate_with_model(operation.output_model, payload, path)
    if validated["task"]["status"] not in operation.task_statuses:
        raise SoftwareProductionPayloadError(f"{path}.task.status {validated['task']['status']!r} is not a status {operation.tool_name} can yield")
    return validated


def validate_operation_exchange(identifier: str, input_payload: Mapping[str, Any], output_payload: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    operation = get_operation(identifier)
    validated_input = validate_operation_input(identifier, input_payload)
    validated_output = validate_operation_output(identifier, output_payload)
    if operation.operation != "start" and validated_output["run_ref"] != validated_input["run_ref"]:
        raise SoftwareProductionPayloadError(f"{operation.tool_name} output belongs to a different run")
    if validated_output["scope"] != {"company_ref": validated_input["company_ref"], "project_ref": validated_input["project_ref"]}:
        raise SoftwareProductionPayloadError(f"{operation.tool_name} output scope does not match the request scope")
    if validated_output["task"]["task_id"] != validated_output["run_ref"]:
        raise SoftwareProductionPayloadError(f"{operation.tool_name} task identity must be the run handle")
    if operation.operation == "cancel" and validated_output["status"] != "cancelled":
        raise SoftwareProductionPayloadError(f"{operation.tool_name} output must be a cancelled run")
    return validated_input, validated_output


def authorize_and_validate_call(identifier: str, payload: Mapping[str, Any], granted_scopes: str | Iterable[str], *, transport_aliases: bool = False) -> ValidatedSoftwareProductionCall:
    operation = require_operation_scopes(identifier, granted_scopes)
    candidate = normalize_transport_payload(identifier, payload, direction="input") if transport_aliases else payload
    validated = validate_operation_input(identifier, candidate)
    return ValidatedSoftwareProductionCall(operation=operation, payload=_freeze(validated))


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #


def render_mcp_tool(identifier: str) -> dict[str, Any]:
    operation = get_operation(identifier)
    security_schemes = [{"type": "oauth2", "scopes": list(operation.required_scopes)}]
    metadata = {
        "securitySchemes": deepcopy(security_schemes),
        "lightbulb/protocol": MANIFEST_SCHEMA,
        "lightbulb/protocolVersion": PROTOCOL_VERSION,
        "lightbulb/operation": operation.operation,
        "lightbulb/requiredScopes": list(operation.required_scopes),
        "lightbulb/statePreconditions": list(operation.state_preconditions),
        "lightbulb/transportAliases": {"input": _thaw(operation.input_aliases), "output": _thaw(operation.output_aliases)},
        "lightbulb/schemaSource": {"input": operation.input_schema["x-lightbulb-derived-from"], "output": operation.output_schema["x-lightbulb-derived-from"]},
        "lightbulb/taskProjection": {"identitySource": "spring_execution_run", "delivery": "polling", "tasksCapabilityRequired": False, "statuses": list(operation.task_statuses)},
        "lightbulb/actorScope": {"identitySource": "authenticated_principal", "tenantSource": "authenticated_principal", "companyField": "company_ref", "projectField": "project_ref", "clientActorIdsAllowed": False, "resolution": "fail_closed"},
    }
    return {
        "name": operation.tool_name,
        "title": operation.title,
        "description": operation.description,
        "inputSchema": _thaw(operation.input_schema),
        "outputSchema": _thaw(operation.output_schema),
        "annotations": {"readOnlyHint": operation.read_only, "destructiveHint": operation.destructive, "idempotentHint": operation.mutating, "openWorldHint": False},
        "securitySchemes": security_schemes,
        "_meta": metadata,
    }


def render_manifest() -> dict[str, Any]:
    return {
        "schema": MANIFEST_SCHEMA,
        "protocol_version": PROTOCOL_VERSION,
        "canonical_field_style": "snake_case",
        "tool_prefix": TOOL_PREFIX,
        "scope_vocabulary": {"read": READ_SCOPE, "write": WRITE_SCOPE, "approve": APPROVE_SCOPE},
        "actor_scope": {"identity_source": "authenticated_principal", "tenant_source": "authenticated_principal", "company_field": "company_ref", "project_field": "project_ref", "client_actor_ids_allowed": False, "resolution": "fail_closed"},
        "run_identity": {"source": "spring_execution_run", "public_handle_pattern": RUN_REF_PATTERN, "raw_run_ids_exposed": False},
        "task_projection": {"delivery": "polling", "tasks_capability_required": False, "statuses": ["working", "input_required", "completed", "failed", "cancelled"], "awaiting_vocabulary": list(Awaiting.__args__)},  # type: ignore[attr-defined]
        "operations": [
            {
                "operation": operation.operation,
                "tool_name": operation.tool_name,
                "required_scopes": list(operation.required_scopes),
                "mutating": operation.mutating,
                "read_only": operation.read_only,
                "destructive": operation.destructive,
                "state_preconditions": list(operation.state_preconditions),
                "task_statuses": list(operation.task_statuses),
                "input_aliases": _thaw(operation.input_aliases),
                "output_aliases": _thaw(operation.output_aliases),
                "schema_source": {"input": operation.input_schema["x-lightbulb-derived-from"], "output": operation.output_schema["x-lightbulb-derived-from"]},
            }
            for operation in OPERATIONS
        ],
        "deprecated_aliases": _thaw(DEPRECATED_TOOL_ALIASES),
        "resources": [MANIFEST_RESOURCE_URI, DEPRECATIONS_RESOURCE_URI],
        "tools": [render_mcp_tool(operation.operation) for operation in OPERATIONS],
    }


def render_manifest_json(*, pretty: bool = False) -> str:
    separators = None if pretty else (",", ":")
    return json.dumps(render_manifest(), ensure_ascii=False, indent=2 if pretty else None, separators=separators, sort_keys=True)


# --------------------------------------------------------------------------- #
# Backend port and in-memory reference backend
# --------------------------------------------------------------------------- #


class McpPrincipal(_StrictModel):
    """Identity the host resolves from the authenticated session; never built from a client payload."""

    tenant_ref: OpaqueRef
    project_id: str
    actor_ref: OpaqueRef
    granted_scopes: tuple[str, ...] = Field(default_factory=tuple)
    bound_roles: tuple[Literal["builder", "evaluator", "release_connector", "observer", "approver"], ...] = Field(default_factory=tuple)


class SoftwareProductionMcpBackend(Protocol):
    def start(self, call: ValidatedSoftwareProductionCall, principal: McpPrincipal) -> Mapping[str, Any]: ...

    def status(self, call: ValidatedSoftwareProductionCall, principal: McpPrincipal) -> Mapping[str, Any]: ...

    def supply_input(self, call: ValidatedSoftwareProductionCall, principal: McpPrincipal) -> Mapping[str, Any]: ...

    def approve_checkpoint(self, call: ValidatedSoftwareProductionCall, principal: McpPrincipal) -> Mapping[str, Any]: ...

    def cancel(self, call: ValidatedSoftwareProductionCall, principal: McpPrincipal) -> Mapping[str, Any]: ...

    def resolve_reconciliation(self, call: ValidatedSoftwareProductionCall, principal: McpPrincipal) -> Mapping[str, Any]: ...


class SoftwareProductionMcpBackendError(SoftwareProductionMcpProtocolError):
    """A backend precondition failed (unknown run, scope mismatch, role not bound, nothing to reconcile)."""


@dataclass
class _RunRecord:
    compilation: SoftwareProductionCompilation
    state: SoftwareProductionLoopState
    created_at: str
    updated_at: str
    reconciliation_pending: bool = False


class InMemorySoftwareProductionBackend:
    """Reference backend: simulates Spring's registration, the Spring-owned stages, and retention in memory.

    It exists for tests and local demos.  The hosted backend is Spring, which
    owns the Execution Run, the harness resolution, the grants, and persistence.
    """

    def __init__(self, *, clock: Callable[[], str], simulate_spring_stages: bool = True, harness_family: HarnessFamily | None = None) -> None:
        self._clock, self._simulate, self._harness = clock, simulate_spring_stages, harness_family
        self._runs: dict[str, _RunRecord] = {}
        self._by_idempotency: dict[str, str] = {}
        self._runner = SoftwareProductionLoopRunner(grants=InMemoryHarnessGrantPort(), release=None)

    @property
    def runs(self) -> Mapping[str, _RunRecord]:
        return MappingProxyType(self._runs)

    def _record(self, call: ValidatedSoftwareProductionCall, principal: McpPrincipal) -> tuple[str, _RunRecord]:
        run_ref = call.payload["run_ref"]
        record = self._runs.get(run_ref)
        if record is None:
            raise SoftwareProductionMcpBackendError(f"unknown run {run_ref}")
        scope = record.compilation.scope
        if scope.tenant_ref != principal.tenant_ref or scope.project_id != principal.project_id or scope.company_ref != call.payload["company_ref"] or scope.project_ref != call.payload["project_ref"]:
            raise SoftwareProductionMcpBackendError("run is outside the principal's scope")
        return run_ref, record

    def _project(self, run_ref: str, record: _RunRecord, **extra: Any) -> dict[str, Any]:
        return {**project_run(record.compilation, record.state, run_ref=run_ref, created_at=record.created_at, updated_at=record.updated_at, reconciliation_pending=record.reconciliation_pending), **extra}

    def _apply(self, run_ref: str, record: _RunRecord, command: Mapping[str, Any]) -> LoopTransitionResult:
        result = apply_software_production_event(record.compilation, record.state, command)
        if result.state is not None:
            record.state = result.state
            record.updated_at = result.state.transition_history[-1].command.occurred_at
        if result.receipt.status == "in_doubt":
            record.reconciliation_pending = True
        return result

    def start(self, call: ValidatedSoftwareProductionCall, principal: McpPrincipal) -> Mapping[str, Any]:
        payload = call.payload
        existing = self._by_idempotency.get(payload["idempotency_key"])
        if existing is not None:
            record = self._runs[existing]
            return self._project(existing, record, request_digest=record.compilation.request_digest, acceptance_contract_digest=record.compilation.acceptance_contract_digest, effective_risk=record.compilation.effective_risk, allowed_hosts=list(record.compilation.dynamic_workflow_start.allowed_hosts))
        request = build_start_request(payload["request"], tenant_ref=principal.tenant_ref, company_ref=payload["company_ref"], project_ref=payload["project_ref"], project_id=principal.project_id, requesting_agent_ref=principal.actor_ref, idempotency_key=payload["idempotency_key"])
        compilation = compile_software_production_request(request)
        execution_run_id = str(uuid5(NAMESPACE_URL, f"lightbulb:software-production:{compilation.compilation_digest}"))
        now = self._clock()
        state = admit_software_production_run(compilation, ExecutionRunControl(execution_run_id=execution_run_id, revision=1, cancellation_fence=0), admitted_at=now, actor_ref="spring:execution-run-authority")
        run_ref = run_ref_for(execution_run_id)
        record = _RunRecord(compilation=compilation, state=state, created_at=now, updated_at=now)
        self._runs[run_ref] = record
        self._by_idempotency[payload["idempotency_key"]] = run_ref
        if self._simulate:
            self._apply(run_ref, record, self._runner._command(record.state, "compile_work_packet", now, role="spring", actor_ref="spring:work-packet", receipts=[{"kind": "work_packet", "ref": f"work-packet:{compilation.work_packet_digest[:12]}", "issuer_ref": "spring:work-packet", "observed_at": now, "independent_of_builder": True, "digest": compilation.work_packet_digest}]))
            family = self._harness or compilation.dynamic_workflow_start.allowed_hosts[0]
            self._apply(run_ref, record, self._runner._command(record.state, "select_harness", now, role="spring", actor_ref="spring:execution-host-policy", selected_harness_family=family))
            grant = self._runner.grants.issue_grant(compilation=compilation, harness_family=family, at=now)
            self._apply(run_ref, record, self._runner._command(record.state, "authorize_builder", now, role="spring", actor_ref="spring:grant-authority", grant=grant.to_dict(), receipts=[{"kind": "provider_grant", "ref": grant.grant_ref, "issuer_ref": "in-memory-grant-authority", "observed_at": now, "independent_of_builder": True, "digest": grant.grant_digest}]))
        return self._project(run_ref, record, request_digest=compilation.request_digest, acceptance_contract_digest=compilation.acceptance_contract_digest, effective_risk=compilation.effective_risk, allowed_hosts=list(compilation.dynamic_workflow_start.allowed_hosts))

    def status(self, call: ValidatedSoftwareProductionCall, principal: McpPrincipal) -> Mapping[str, Any]:
        run_ref, record = self._record(call, principal)
        last = record.state.transition_history[-1].command
        return self._project(run_ref, record, evidence_kinds=sorted(record.state.receipt_set.kinds()), budget=record.state.budget.to_dict(), last_event=last.event, last_transition_at=last.occurred_at, reconciliation_pending=record.reconciliation_pending)

    def supply_input(self, call: ValidatedSoftwareProductionCall, principal: McpPrincipal) -> Mapping[str, Any]:
        run_ref, record = self._record(call, principal)
        supplied = call.payload["input"]
        role = _ROLE_BY_CLIENT_EVENT[supplied["event"]]
        if role not in principal.bound_roles:
            raise SoftwareProductionMcpBackendError(f"principal is not bound as {role}")
        command = loop_command_for_input(record.state, supplied, actor_ref=principal.actor_ref, idempotency_key=call.payload["idempotency_key"], expected_revision=call.payload["expected_revision"], occurred_at=self._clock())
        result = self._apply(run_ref, record, command)
        return self._project(run_ref, record, transition=result.receipt.to_dict())

    def approve_checkpoint(self, call: ValidatedSoftwareProductionCall, principal: McpPrincipal) -> Mapping[str, Any]:
        run_ref, record = self._record(call, principal)
        if "approver" not in principal.bound_roles:
            raise SoftwareProductionMcpBackendError("principal is not bound as approver")
        now = self._clock()
        payload = call.payload
        base = {"idempotency_key": payload["idempotency_key"], "expected_version": payload["expected_revision"], "expected_state_digest": record.state.state_digest, "expected_cancellation_fence": record.state.control.cancellation_fence, "occurred_at": now, "actor_ref": principal.actor_ref, "actor_role": "approver"}
        if payload["decision"] == "approve":
            command = seal_loop_command({**base, "event": "authorize_production", "transition_ref": f"authorize_production:{record.state.compilation_digest[:12]}:{payload['expected_revision'] + 1}", "receipts": [{"kind": "release_approval", "ref": payload["approval_ref"], "issuer_ref": principal.actor_ref, "observed_at": now, "independent_of_builder": True}]})
        else:
            command = seal_loop_command({**base, "event": "deny_release", "transition_ref": f"deny_release:{record.state.compilation_digest[:12]}:{payload['expected_revision'] + 1}", "reason": payload.get("reason") or "release denied by approver"})
        result = self._apply(run_ref, record, command)
        return self._project(run_ref, record, transition=result.receipt.to_dict())

    def cancel(self, call: ValidatedSoftwareProductionCall, principal: McpPrincipal) -> Mapping[str, Any]:
        run_ref, record = self._record(call, principal)
        now = self._clock()
        control = record.state.control
        fenced = apply_control_update(record.state, {**control.to_dict(), "revision": control.revision + 1, "cancellation_fence": control.cancellation_fence + 1, "cancellation_state": "CANCEL_REQUESTED"})
        record.state = fenced
        command = seal_loop_command({"event": "cancel", "transition_ref": f"cancel:{fenced.compilation_digest[:12]}:{call.payload['expected_revision'] + 1}", "idempotency_key": call.payload["idempotency_key"], "expected_version": call.payload["expected_revision"], "expected_state_digest": fenced.state_digest, "expected_cancellation_fence": fenced.control.cancellation_fence, "occurred_at": now, "actor_ref": "spring:execution-run-authority", "actor_role": "spring", "reason": call.payload["reason"]})
        result = self._apply(run_ref, record, command)
        if not result.candidate_validated:
            raise SoftwareProductionMcpBackendError(f"cancel rejected: {result.receipt.rejection_code}")
        return self._project(run_ref, record, cancelled=True, cancelled_at=now)

    def resolve_reconciliation(self, call: ValidatedSoftwareProductionCall, principal: McpPrincipal) -> Mapping[str, Any]:
        run_ref, record = self._record(call, principal)
        if "approver" not in principal.bound_roles:
            raise SoftwareProductionMcpBackendError("principal is not bound as approver")
        if not record.reconciliation_pending:
            raise SoftwareProductionMcpBackendError("nothing awaits reconciliation")
        payload = call.payload
        now = self._clock()
        if payload["disposition"] == "resume":
            record.reconciliation_pending = False
            record.updated_at = now
            receipt = LoopTransitionReceipt(transition_ref=f"reconciliation:{payload['reconciliation_ref']}", idempotency_key=payload["idempotency_key"], request_digest=record.state.state_digest, event="require_reconciliation", status="rejected", from_version=record.state.version, to_version=record.state.version, from_status=record.state.status, to_status=record.state.status, from_state_digest=record.state.state_digest, to_state_digest=record.state.state_digest, rejection_code="RECONCILED_WITHOUT_TRANSITION", recovery={"disposition": "refresh_state", "instructions": "reconciliation resumed the retained state; re-read status and continue"})
            return self._project(run_ref, record, transition=receipt.to_dict())
        event = "block" if payload["disposition"] == "fail" else "roll_back"
        command = seal_loop_command({"event": event, "transition_ref": f"{event}:{record.state.compilation_digest[:12]}:{payload['expected_revision'] + 1}", "idempotency_key": payload["idempotency_key"], "expected_version": payload["expected_revision"], "expected_state_digest": record.state.state_digest, "expected_cancellation_fence": record.state.control.cancellation_fence, "occurred_at": now, "actor_ref": principal.actor_ref, "actor_role": "release_connector", "receipts": list(payload["evidence"]), "effects": list(payload["effects"]), "reason": payload["reason"]})
        result = self._apply(run_ref, record, command)
        if result.candidate_validated:
            record.reconciliation_pending = False
        return self._project(run_ref, record, transition=result.receipt.to_dict())


# --------------------------------------------------------------------------- #
# FastMCP registration (thin projection)
# --------------------------------------------------------------------------- #


def register_software_production(mcp: Any, *, backend: SoftwareProductionMcpBackend, principal_provider: Callable[[], McpPrincipal]) -> tuple[str, ...]:
    """Install the six cataloged tools (with the derived schemas verbatim) and two resources on a FastMCP server."""

    from mcp.server.fastmcp.tools.base import Tool
    from mcp.server.fastmcp.utilities.func_metadata import ArgModelBase, FuncMetadata
    from mcp.types import ToolAnnotations
    from pydantic import ConfigDict, create_model

    installed: list[str] = []
    for operation in OPERATIONS:
        arg_model = create_model(
            f"{operation.input_model.__name__}Args",
            __base__=ArgModelBase,
            __config__=None,
            **{name: (info.annotation, info) for name, info in operation.input_model.model_fields.items()},
        )
        arg_model.model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

        def handler(_operation: SoftwareProductionMcpOperation = operation, **arguments: Any) -> dict[str, Any]:
            payload = {key: value.to_dict() if isinstance(value, BaseModel) else value for key, value in arguments.items()}
            principal = principal_provider()
            call = authorize_and_validate_call(_operation.operation, payload, principal.granted_scopes)
            method = getattr(backend, _operation.operation)
            return validate_operation_output(_operation.operation, method(call, principal))

        tool = Tool(
            fn=handler,
            name=operation.tool_name,
            title=operation.title,
            description=operation.description,
            parameters=_thaw(operation.input_schema),
            fn_metadata=FuncMetadata(arg_model=arg_model, output_schema=_thaw(operation.output_schema), output_model=operation.output_model),
            is_async=False,
            context_kwarg=None,
            annotations=ToolAnnotations(title=operation.title, readOnlyHint=operation.read_only, destructiveHint=operation.destructive, idempotentHint=operation.mutating, openWorldHint=False),
            meta=render_mcp_tool(operation.operation)["_meta"],
        )
        mcp._tool_manager._tools[tool.name] = tool  # the projection installs the derived schema verbatim
        installed.append(tool.name)

    @mcp.resource(MANIFEST_RESOURCE_URI, name="software_production_manifest", description="Deterministic software-production MCP manifest for cross-runtime parity.", mime_type="application/json")
    def _manifest() -> str:
        return render_manifest_json(pretty=True)

    @mcp.resource(DEPRECATIONS_RESOURCE_URI, name="software_production_deprecations", description="Deprecation plan for the legacy software_delivery_* tools.", mime_type="application/json")
    def _deprecations() -> str:
        return json.dumps(_thaw(DEPRECATED_TOOL_ALIASES), indent=2, sort_keys=True)

    return tuple(installed)


SOFTWARE_PRODUCTION_MCP_INTEGRATION_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.capability_pack_integration_manifest.v1",
    "capability_pack": "software_production_mcp_projection",
    "work_package": "1C",
    "stacked_on": "fable/software-production-golden-loop (Work Package 1B)",
    "modules": {"projection": "lightbulb.software_production_mcp"},
    "tools": [item.tool_name for item in OPERATIONS],
    "resources": [MANIFEST_RESOURCE_URI, DEPRECATIONS_RESOURCE_URI],
    "mcp_server": {"file": "lightbulb/mcp_server.py", "register": "register_software_production(mcp, backend=<Spring-backed backend>, principal_provider=<session principal>)", "deprecate": sorted(DEPRECATED_TOOL_ALIASES), "note": "aliases answer with a deprecation notice naming the replacement tool for two release cycles"},
    "generated_tools": {"file": "lightbulb/mcp_generated_tools.py", "note": "render_manifest() is the parity fixture; no hand-written tool descriptors"},
    "non_goals": ["no second runtime in MCP", "no raw run, tenant, project, or actor identifiers on the wire", "no Tasks capability claim (polling projection only)", "no automatic production authority"],
}

__all__ = [
    "APPROVE_SCOPE",
    "DEPRECATED_TOOL_ALIASES",
    "DEPRECATIONS_RESOURCE_URI",
    "MANIFEST_RESOURCE_URI",
    "MANIFEST_SCHEMA",
    "OPERATION_CATALOG",
    "OPERATIONS",
    "PROTOCOL_VERSION",
    "READ_SCOPE",
    "RUN_REF_PATTERN",
    "SOFTWARE_PRODUCTION_MCP_INTEGRATION_MANIFEST",
    "TOOL_CATALOG",
    "TOOL_PREFIX",
    "WRITE_SCOPE",
    "ApproveCheckpointInput",
    "CancelInput",
    "CancelOutput",
    "InMemorySoftwareProductionBackend",
    "McpPrincipal",
    "PublicOrigin",
    "PublicScope",
    "ResolveReconciliationInput",
    "RunProjection",
    "SoftwareProductionCatalogError",
    "SoftwareProductionMcpBackend",
    "SoftwareProductionMcpBackendError",
    "SoftwareProductionMcpOperation",
    "SoftwareProductionMcpProtocolError",
    "SoftwareProductionPayloadError",
    "SoftwareProductionScopeError",
    "SoftwareProductionStartBody",
    "StartInput",
    "StartOutput",
    "StatusInput",
    "StatusOutput",
    "SuppliedLoopInput",
    "SupplyInputInput",
    "TaskProjection",
    "TransitionOutput",
    "UnknownSoftwareProductionOperation",
    "ValidatedSoftwareProductionCall",
    "authorize_and_validate_call",
    "awaiting_for",
    "build_start_request",
    "derive_schema",
    "get_operation",
    "loop_command_for_input",
    "normalize_transport_payload",
    "project_run",
    "register_software_production",
    "render_manifest",
    "render_manifest_json",
    "render_mcp_tool",
    "require_operation_scopes",
    "run_ref_for",
    "task_projection",
    "validate_catalog",
    "validate_operation_exchange",
    "validate_operation_input",
    "validate_operation_output",
]
