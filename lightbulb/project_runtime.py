"""Project-scoped composition and execution for custom agentic workflows."""

from __future__ import annotations

import re
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Literal, Mapping
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from lightbulb.connector_execution import (
    ConnectorErrorKind,
    ConnectorExecutionRequest,
    ConnectorExecutionResult,
    ConnectorExecutionStatus,
    ConnectorExecutor,
    ExecutionScope,
)
from lightbulb.primitive_runtime import (
    ExecutablePrimitiveRuntime,
    PrimitiveCall,
    PrimitiveBlocker,
    PrimitiveCorrelation,
    PrimitiveEvent,
    PrimitiveExecutionResult,
    PrimitiveExecutionStatus,
    PrimitiveOperationReceipt,
    PrimitiveRecoveryDisposition,
    PrimitiveRunMode,
    PrimitiveRunSession,
    PrimitiveRegistry,
    ProjectPrimitiveRun,
)
from lightbulb.runtime_outcomes import RuntimeOutcomeRecorder


PROJECT_SPEC_SCHEMA = "lightbulb.project_spec.v1"
PROJECT_VALIDATION_SCHEMA = "lightbulb.project_validation.v1"
PROJECT_WORKFLOW_RUN_SCHEMA = "lightbulb.project_workflow_run.v1"

_KEY_RE = re.compile(r"^[a-z][a-z0-9_-]{0,127}$")
_END = "__end__"


class RetryPolicy(BaseModel):
    """Bounded deterministic retries for durable primitive failures."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    # One attempt preserves the pre-retry behavior for existing projects.
    # Projects opt into automatic retries explicitly.
    max_attempts: int = Field(default=1, ge=1, le=10)
    initial_delay_seconds: int = Field(default=5, ge=1, le=86_400)
    backoff_multiplier: int = Field(default=2, ge=1, le=10)
    max_delay_seconds: int = Field(default=300, ge=1, le=604_800)

    @model_validator(mode="after")
    def _validate_delay_bounds(self) -> "RetryPolicy":
        if self.max_delay_seconds < self.initial_delay_seconds:
            raise ValueError("max_delay_seconds must be at least initial_delay_seconds")
        return self

    def delay_seconds(self, failed_attempt: int) -> int:
        """Return capped exponential backoff after a failed attempt."""
        if isinstance(failed_attempt, bool) or failed_attempt < 1:
            raise ValueError("failed_attempt must be a positive integer")
        delay = self.initial_delay_seconds * (
            self.backoff_multiplier ** (failed_attempt - 1)
        )
        return min(delay, self.max_delay_seconds)


class ProjectPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    writes_require_approval: Literal[True] = True
    default_preview_only: bool = True
    max_workflow_steps: int = Field(default=50, ge=1, le=1000)
    max_step_visits: int = Field(default=3, ge=1, le=100)
    retry_policy: RetryPolicy = Field(default_factory=RetryPolicy)


class ProjectWorkflowStep(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    primitive_ref: str
    input_mapping: Dict[str, Any] = Field(default_factory=dict)
    routes: Dict[str, str] = Field(default_factory=dict)
    next_step: str | None = None

    @field_validator("id")
    @classmethod
    def _validate_id(cls, value: str) -> str:
        clean = value.strip().lower()
        if not _KEY_RE.fullmatch(clean):
            raise ValueError("step id must be a lowercase project key")
        return clean

    @field_validator("primitive_ref")
    @classmethod
    def _validate_primitive_ref(cls, value: str) -> str:
        clean = value.strip().lower()
        if "." not in clean:
            raise ValueError("primitive_ref must be a dotted business capability name")
        return clean

    @field_validator("next_step")
    @classmethod
    def _normalize_next_step(cls, value: str | None) -> str | None:
        if value is None:
            return None
        clean = value.strip().lower()
        return clean or None

    @field_validator("routes")
    @classmethod
    def _normalize_routes(cls, value: Mapping[str, str]) -> Dict[str, str]:
        return {
            str(event).strip(): str(target).strip().lower()
            for event, target in value.items()
            if str(event).strip() and str(target).strip()
        }


class ProjectWorkflow(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    key: str
    version: str = Field(default="1.0.0", min_length=1, max_length=80)
    title: str = Field(min_length=1, max_length=300)
    trigger_event: str = Field(default="manual.requested", min_length=1, max_length=160)
    entry_step: str
    steps: list[ProjectWorkflowStep] = Field(min_length=1, max_length=1000)

    @field_validator("key", "entry_step")
    @classmethod
    def _validate_keys(cls, value: str) -> str:
        clean = value.strip().lower()
        if not _KEY_RE.fullmatch(clean):
            raise ValueError(
                "workflow and step keys must use lowercase letters, digits, _ or -"
            )
        return clean

    @model_validator(mode="after")
    def _validate_graph(self) -> "ProjectWorkflow":
        step_ids = [step.id for step in self.steps]
        if len(step_ids) != len(set(step_ids)):
            raise ValueError("workflow step ids must be unique")
        known = set(step_ids)
        if self.entry_step not in known:
            raise ValueError("entry_step must reference a workflow step")
        for step in self.steps:
            targets = list(step.routes.values())
            if step.next_step:
                targets.append(step.next_step)
            unknown = [
                target for target in targets if target != _END and target not in known
            ]
            if unknown:
                raise ValueError(
                    f"step {step.id} routes to unknown step(s): {', '.join(sorted(set(unknown)))}"
                )
        return self


class LightbulbProject(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_id: str = Field(default=PROJECT_SPEC_SCHEMA, alias="schema")
    project_ref: str
    hosted_project_id: UUID | None = None
    name: str = Field(min_length=1, max_length=300)
    version: str = Field(default="1.0.0", min_length=1, max_length=80)
    primitive_refs: list[str] = Field(min_length=1, max_length=1000)
    connector_tools: list[str] = Field(default_factory=list, max_length=5000)
    secret_refs: Dict[str, str] = Field(default_factory=dict)
    workflows: list[ProjectWorkflow] = Field(default_factory=list, max_length=1000)
    policy: ProjectPolicy = Field(default_factory=ProjectPolicy)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("project_ref")
    @classmethod
    def _validate_project_ref(cls, value: str) -> str:
        clean = value.strip().lower()
        if not _KEY_RE.fullmatch(clean):
            raise ValueError("project_ref must be a lowercase project key")
        return clean

    @field_validator("primitive_refs", "connector_tools")
    @classmethod
    def _normalize_capabilities(cls, values: list[str]) -> list[str]:
        normalized = [
            str(value).strip().lower() for value in values if str(value).strip()
        ]
        if len(normalized) != len(set(normalized)):
            raise ValueError("project capability references must be unique")
        if any("." not in value for value in normalized):
            raise ValueError("project capability references must be dotted names")
        return normalized

    @model_validator(mode="after")
    def _validate_workflows(self) -> "LightbulbProject":
        workflow_keys = [workflow.key for workflow in self.workflows]
        if len(workflow_keys) != len(set(workflow_keys)):
            raise ValueError("project workflow keys must be unique")
        allowed = set(self.primitive_refs)
        undeclared = sorted(
            {
                step.primitive_ref
                for workflow in self.workflows
                for step in workflow.steps
                if step.primitive_ref not in allowed
            }
        )
        if undeclared:
            raise ValueError(
                "workflow steps use undeclared primitives: " + ", ".join(undeclared)
            )
        return self

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True)


class ProjectValidationSeverity(str, Enum):
    ERROR = "error"
    WARNING = "warning"


class ProjectValidationIssue(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    severity: ProjectValidationSeverity
    code: str
    message: str
    ref: str | None = None


class ProjectValidationResult(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    schema_id: str = Field(default=PROJECT_VALIDATION_SCHEMA, alias="schema")
    valid: bool
    project_ref: str
    issues: list[ProjectValidationIssue] = Field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True)


class ProjectWorkflowStepRun(BaseModel):
    model_config = ConfigDict(extra="forbid")

    step_id: str
    primitive_ref: str
    step_visit: int = Field(default=1, ge=1, le=100)
    attempt: int = Field(default=1, ge=1, le=100)
    invocation: int = Field(default=1, ge=1)
    status: PrimitiveExecutionStatus
    result: PrimitiveExecutionResult[Any]


class ProjectWorkflowRunStatus(str, Enum):
    RUNNING = "running"
    SCHEDULED = "scheduled"
    DISPATCHED = "dispatched"
    COMPLETED = "completed"
    PREVIEW = "preview"
    PENDING_APPROVAL = "pending_approval"
    NEEDS_INPUT = "needs_input"
    WAITING_FOR_RECOVERY = "waiting_for_recovery"
    BLOCKED = "blocked"
    FAILED = "failed"


def _authoritative_recovery_receipts(
    result: PrimitiveExecutionResult[Any],
) -> list[PrimitiveOperationReceipt]:
    return [
        receipt
        for receipt in result.unresolved_operation_receipts()
        if receipt.recovery_disposition != PrimitiveRecoveryDisposition.RETRY_ALLOWED
    ]


def _workflow_result_with_recovery_gate(
    result: PrimitiveExecutionResult[Any],
) -> tuple[PrimitiveExecutionResult[Any], list[PrimitiveOperationReceipt]]:
    unresolved = _authoritative_recovery_receipts(result)
    if (
        result.status
        in {
            PrimitiveExecutionStatus.COMPLETED,
            PrimitiveExecutionStatus.PREVIEW,
        }
        and unresolved
    ):
        result = PrimitiveExecutionResult[Any].model_validate(
            {
                **result.to_dict(),
                "status": PrimitiveExecutionStatus.BLOCKED.value,
                "summary": (
                    "Primitive reported success with an unresolved operation; "
                    "workflow execution failed closed."
                ),
                "blockers": [
                    *[blocker.model_dump(mode="json") for blocker in result.blockers],
                    {
                        "code": "operation_recovery_required",
                        "message": (
                            "Resolve every ambiguous operation receipt before "
                            "continuing the workflow."
                        ),
                        "retryable": False,
                    },
                ],
                "retryable": False,
            }
        )
        unresolved = _authoritative_recovery_receipts(result)
    return result, unresolved


class ProjectWorkflowRun(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    schema_id: str = Field(default=PROJECT_WORKFLOW_RUN_SCHEMA, alias="schema")
    run_ref: str
    project_ref: str
    workflow_key: str
    status: ProjectWorkflowRunStatus
    step_runs: list[ProjectWorkflowStepRun] = Field(default_factory=list)
    events: list[PrimitiveEvent] = Field(default_factory=list)
    paused_step: str | None = None
    resume_at: datetime | None = None
    blockers: list[PrimitiveBlocker] = Field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True)


class ProjectConnectorExecutor:
    """Restrict an adapter to the Tools declared by one project."""

    def __init__(self, inner: ConnectorExecutor, allowed_tools: list[str]) -> None:
        self._inner = inner
        self._allowed_tools = set(allowed_tools)

    def supports(self, tool: str) -> bool:
        normalized = tool.strip().lower()
        return normalized in self._allowed_tools and self._inner.supports(normalized)

    def execute(self, request: ConnectorExecutionRequest) -> ConnectorExecutionResult:
        if request.tool not in self._allowed_tools:
            return ConnectorExecutionResult(
                status=ConnectorExecutionStatus.BLOCKED,
                tool=request.tool,
                message="The Tool is not declared by this Lightbulb project.",
                error_kind=ConnectorErrorKind.PERMISSION_DENIED,
                error_code="project_tool_not_allowed",
            )
        return self._inner.execute(request)


class BindingResolutionError(ValueError):
    pass


def _read_path(root: Any, path: list[str], reference: str) -> Any:
    current = root
    for part in path:
        if isinstance(current, BaseModel):
            current = current.model_dump(mode="python")
        if isinstance(current, Mapping) and part in current:
            current = current[part]
            continue
        if isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
            continue
        raise BindingResolutionError(f"Unable to resolve workflow binding: {reference}")
    return current


def _resolve_binding(
    value: Any,
    *,
    workflow_inputs: Mapping[str, Any],
    step_results: Mapping[str, PrimitiveExecutionResult[Any]],
    last_event: PrimitiveEvent | None,
) -> Any:
    if isinstance(value, list):
        return [
            _resolve_binding(
                item,
                workflow_inputs=workflow_inputs,
                step_results=step_results,
                last_event=last_event,
            )
            for item in value
        ]
    if isinstance(value, Mapping):
        return {
            key: _resolve_binding(
                item,
                workflow_inputs=workflow_inputs,
                step_results=step_results,
                last_event=last_event,
            )
            for key, item in value.items()
        }
    if not isinstance(value, str) or not value.startswith("$"):
        return value
    if value == "$input":
        return dict(workflow_inputs)
    if value.startswith("$input."):
        return _read_path(workflow_inputs, value[len("$input.") :].split("."), value)
    if value.startswith("$steps."):
        parts = value[len("$steps.") :].split(".")
        if len(parts) < 2:
            raise BindingResolutionError(f"Invalid workflow binding: {value}")
        step_id, path = parts[0], parts[1:]
        result = step_results.get(step_id)
        if result is None:
            raise BindingResolutionError(
                f"Workflow binding references an incomplete step: {value}"
            )
        return _read_path(result.to_dict(), path, value)
    if value == "$last_event":
        return last_event.model_dump(mode="python") if last_event else None
    if value.startswith("$last_event."):
        if last_event is None:
            raise BindingResolutionError(
                f"Workflow binding has no prior event: {value}"
            )
        return _read_path(
            last_event.model_dump(mode="python"),
            value[len("$last_event.") :].split("."),
            value,
        )
    raise BindingResolutionError(f"Unsupported workflow binding: {value}")


def _step_inputs(
    step: ProjectWorkflowStep,
    *,
    workflow_inputs: Mapping[str, Any],
    step_results: Mapping[str, PrimitiveExecutionResult[Any]],
    last_event: PrimitiveEvent | None,
) -> Dict[str, Any]:
    if not step.input_mapping:
        return dict(workflow_inputs)
    resolved: Dict[str, Any] = {}
    if "*" in step.input_mapping:
        inherited = _resolve_binding(
            step.input_mapping["*"],
            workflow_inputs=workflow_inputs,
            step_results=step_results,
            last_event=last_event,
        )
        if not isinstance(inherited, Mapping):
            raise BindingResolutionError(
                "the '*' workflow binding must resolve to an object"
            )
        resolved.update(inherited)
    for key, value in step.input_mapping.items():
        if key == "*":
            continue
        resolved[key] = _resolve_binding(
            value,
            workflow_inputs=workflow_inputs,
            step_results=step_results,
            last_event=last_event,
        )
    return resolved


class ProjectRuntime:
    def __init__(
        self,
        project: LightbulbProject,
        registry: PrimitiveRegistry,
        connectors: ConnectorExecutor,
        outcome_recorder: RuntimeOutcomeRecorder | None = None,
    ) -> None:
        self.project = project
        self.registry = registry
        self.connectors = ProjectConnectorExecutor(connectors, project.connector_tools)
        self.outcome_recorder = outcome_recorder
        self.primitive_runtime = ExecutablePrimitiveRuntime(
            registry,
            self.connectors,
            outcome_recorder=outcome_recorder,
        )

    def durable(self, checkpoint_store: Any = None) -> Any:
        """Add revisioned checkpoints, scheduling, events, and worker leases."""
        from lightbulb.durable_runtime import (
            DurableProjectRuntime,
            InMemoryCheckpointStore,
        )

        return DurableProjectRuntime(
            self, checkpoint_store or InMemoryCheckpointStore()
        )

    def validate(self) -> ProjectValidationResult:
        issues: list[ProjectValidationIssue] = []
        for primitive_ref in self.project.primitive_refs:
            if not self.registry.supports(primitive_ref):
                issues.append(
                    ProjectValidationIssue(
                        severity=ProjectValidationSeverity.ERROR,
                        code="primitive_not_registered",
                        message="No executable implementation is registered.",
                        ref=primitive_ref,
                    )
                )
        for tool in self.project.connector_tools:
            if not self.connectors.supports(tool):
                issues.append(
                    ProjectValidationIssue(
                        severity=ProjectValidationSeverity.WARNING,
                        code="connector_not_ready",
                        message="The declared Tool is unavailable in the selected connector adapter.",
                        ref=tool,
                    )
                )
        return ProjectValidationResult(
            valid=not any(
                issue.severity == ProjectValidationSeverity.ERROR for issue in issues
            ),
            project_ref=self.project.project_ref,
            issues=issues,
        )

    def implementation_manifest(self) -> Dict[str, Any]:
        return {
            "schema": "lightbulb.project_implementation_manifest.v1",
            "project": self.project.to_dict(),
            "primitive_implementations": [
                self.registry.get(ref).implementation_contract()
                for ref in self.project.primitive_refs
                if self.registry.supports(ref)
            ],
            "validation": self.validate().to_dict(),
        }

    def bind_workflow_learning_record(
        self,
        run: ProjectWorkflowRun,
        *,
        scope: Any,
        skill_search_receipt: Any,
        typed_inputs: Any,
        typed_outputs: Any,
        evidence: Any,
        policy: Any,
        used_skill_binding_sha256s: Any = (),
    ) -> Any:
        """Bind a completed standard run to proposal-only learning evidence.

        This is intentionally a post-execution adapter over ``run_workflow``.
        The host must first persist typed input/output artifacts and verify the
        outcome.  The returned record can request learning admission, but never
        starts GEPA, AutoML, Prime, Puffer, promotion, or serving.
        """
        from lightbulb.governed_skill_search import (
            ExactAgentSkillScope,
            compile_workflow_execution_learning_record,
        )

        parsed_run = ProjectWorkflowRun.model_validate(run)
        parsed_scope = ExactAgentSkillScope.model_validate(scope)
        if parsed_run.project_ref != self.project.project_ref:
            raise ValueError("workflow run does not belong to this project runtime")
        hosted_project_id = str(self.project.hosted_project_id or "").strip()
        scoped_project_id = (
            str(parsed_scope.project_id) if parsed_scope.project_id else ""
        )
        if hosted_project_id != scoped_project_id:
            raise ValueError(
                "workflow learning scope does not match the runtime's hosted project"
            )
        primitive_contracts = {
            primitive_ref: self.registry.get(primitive_ref).implementation_contract()
            for primitive_ref in {
                step_run.primitive_ref for step_run in list(parsed_run.step_runs or [])
            }
        }
        return compile_workflow_execution_learning_record(
            run=parsed_run,
            scope=parsed_scope,
            skill_search_receipt=skill_search_receipt,
            primitive_contracts=primitive_contracts,
            typed_inputs=typed_inputs,
            typed_outputs=typed_outputs,
            evidence=evidence,
            policy=policy,
            used_skill_binding_sha256s=used_skill_binding_sha256s,
        )

    def open_primitive_run(
        self,
        *,
        run_ref: str,
        idempotency_key: str | None = None,
        preview_only: bool | None = None,
        approval_refs: Mapping[str, str] | None = None,
        connector_account_refs: Mapping[str, str] | None = None,
        tenant_ref: str = "authenticated",
        company_ref: str = "selected",
        actor_ref: str | None = None,
        workflow_key: str | None = None,
        source: str = "lightbulb_project_runtime",
    ) -> PrimitiveRunSession:
        """Open the Project adapter over the shared Executable Primitive Runtime."""
        mode = None
        if preview_only is not None:
            mode = PrimitiveRunMode.PREVIEW if preview_only else PrimitiveRunMode.APPLY
        return self.primitive_runtime.open(
            ProjectPrimitiveRun(
                project=self.project,
                scope=ExecutionScope(
                    tenant_ref=tenant_ref,
                    company_ref=company_ref,
                    project_ref=self.project.project_ref,
                    project_id=self.project.hosted_project_id,
                    actor_ref=actor_ref,
                ),
                run_ref=run_ref,
                mode=mode,
                approval_refs=dict(approval_refs or {}),
                connector_account_refs=dict(connector_account_refs or {}),
                correlation=PrimitiveCorrelation(
                    source=source,
                    workflow_key=workflow_key,
                ),
                idempotency_key=(
                    run_ref if idempotency_key is None else idempotency_key
                ),
            )
        )

    def execute_primitive(
        self,
        primitive_ref: str,
        inputs: Mapping[str, Any],
        *,
        preview_only: bool | None = None,
        approval_refs: Mapping[str, str] | None = None,
        connector_account_refs: Mapping[str, str] | None = None,
        run_ref: str | None = None,
        idempotency_key: str | None = None,
        tenant_ref: str = "authenticated",
        company_ref: str = "selected",
        actor_ref: str | None = None,
    ) -> PrimitiveExecutionResult[Any]:
        actual_run_ref = run_ref or f"run-{uuid4()}"
        session = self.open_primitive_run(
            run_ref=actual_run_ref,
            idempotency_key=(
                actual_run_ref if idempotency_key is None else idempotency_key
            ),
            preview_only=preview_only,
            approval_refs=approval_refs,
            connector_account_refs=connector_account_refs,
            tenant_ref=tenant_ref,
            company_ref=company_ref,
            actor_ref=actor_ref,
        )
        return session.execute(
            PrimitiveCall(primitive_ref=primitive_ref, inputs=inputs)
        )

    def run_workflow(
        self,
        workflow_key: str,
        inputs: Mapping[str, Any],
        *,
        preview_only: bool | None = None,
        approval_refs: Mapping[str, str] | None = None,
        connector_account_refs: Mapping[str, str] | None = None,
        run_ref: str | None = None,
        idempotency_key: str | None = None,
        tenant_ref: str = "authenticated",
        company_ref: str = "selected",
        actor_ref: str | None = None,
    ) -> ProjectWorkflowRun:
        validation = self.validate()
        normalized_key = workflow_key.strip().lower()
        actual_run_ref = run_ref or f"run-{uuid4()}"
        if not validation.valid:
            return ProjectWorkflowRun(
                run_ref=actual_run_ref,
                project_ref=self.project.project_ref,
                workflow_key=normalized_key,
                status=ProjectWorkflowRunStatus.BLOCKED,
                blockers=[
                    PrimitiveBlocker(code=issue.code, message=issue.message)
                    for issue in validation.issues
                    if issue.severity == ProjectValidationSeverity.ERROR
                ],
            )
        workflow = next(
            (item for item in self.project.workflows if item.key == normalized_key),
            None,
        )
        if workflow is None:
            return ProjectWorkflowRun(
                run_ref=actual_run_ref,
                project_ref=self.project.project_ref,
                workflow_key=normalized_key,
                status=ProjectWorkflowRunStatus.BLOCKED,
                blockers=[
                    PrimitiveBlocker(
                        code="workflow_not_found",
                        message="Workflow is not declared by this Lightbulb project.",
                    )
                ],
            )

        event_log: list[PrimitiveEvent] = []
        session = self.open_primitive_run(
            run_ref=actual_run_ref,
            idempotency_key=(
                actual_run_ref if idempotency_key is None else idempotency_key
            ),
            preview_only=preview_only,
            approval_refs=approval_refs,
            connector_account_refs=connector_account_refs,
            tenant_ref=tenant_ref,
            company_ref=company_ref,
            actor_ref=actor_ref,
            workflow_key=workflow.key,
        )
        step_by_id = {step.id: step for step in workflow.steps}
        step_results: Dict[str, PrimitiveExecutionResult[Any]] = {}
        step_runs: list[ProjectWorkflowStepRun] = []
        visits: Dict[str, int] = {}
        current_step = workflow.entry_step
        last_event: PrimitiveEvent | None = None
        saw_preview = False

        for _ in range(self.project.policy.max_workflow_steps):
            visits[current_step] = visits.get(current_step, 0) + 1
            if visits[current_step] > self.project.policy.max_step_visits:
                return ProjectWorkflowRun(
                    run_ref=actual_run_ref,
                    project_ref=self.project.project_ref,
                    workflow_key=workflow.key,
                    status=ProjectWorkflowRunStatus.BLOCKED,
                    step_runs=step_runs,
                    events=event_log,
                    paused_step=current_step,
                    blockers=[
                        PrimitiveBlocker(
                            code="workflow_loop_limit",
                            message="A workflow step exceeded the project's visit limit.",
                        )
                    ],
                )
            step = step_by_id[current_step]
            try:
                step_input = _step_inputs(
                    step,
                    workflow_inputs=inputs,
                    step_results=step_results,
                    last_event=last_event,
                )
            except BindingResolutionError as exc:
                return ProjectWorkflowRun(
                    run_ref=actual_run_ref,
                    project_ref=self.project.project_ref,
                    workflow_key=workflow.key,
                    status=ProjectWorkflowRunStatus.NEEDS_INPUT,
                    step_runs=step_runs,
                    events=event_log,
                    paused_step=step.id,
                    blockers=[
                        PrimitiveBlocker(
                            code="binding_resolution_failed", message=str(exc)
                        )
                    ],
                )
            result = session.execute(
                PrimitiveCall(
                    primitive_ref=step.primitive_ref,
                    inputs=step_input,
                    step_id=step.id,
                    execution_ref=f"{step.id}:{visits[current_step]}",
                )
            )
            result, unresolved_recovery = _workflow_result_with_recovery_gate(result)
            event_log.extend(result.events)
            step_results[step.id] = result
            step_runs.append(
                ProjectWorkflowStepRun(
                    step_id=step.id,
                    primitive_ref=step.primitive_ref,
                    step_visit=visits[current_step],
                    attempt=1,
                    invocation=1,
                    status=result.status,
                    result=result,
                )
            )
            if result.events:
                last_event = result.events[-1]
            if result.status == PrimitiveExecutionStatus.PREVIEW:
                saw_preview = True
            if result.status not in {
                PrimitiveExecutionStatus.COMPLETED,
                PrimitiveExecutionStatus.PREVIEW,
            }:
                recovery_required = bool(unresolved_recovery)
                status = (
                    ProjectWorkflowRunStatus.WAITING_FOR_RECOVERY
                    if recovery_required
                    else ProjectWorkflowRunStatus(result.status.value)
                )
                blockers = list(result.blockers)
                if recovery_required and not any(
                    blocker.code == "operation_recovery_required"
                    for blocker in blockers
                ):
                    blockers.append(
                        PrimitiveBlocker(
                            code="operation_recovery_required",
                            message=(
                                "Resolve every ambiguous operation receipt before "
                                "continuing the workflow."
                            ),
                        )
                    )
                return ProjectWorkflowRun(
                    run_ref=actual_run_ref,
                    project_ref=self.project.project_ref,
                    workflow_key=workflow.key,
                    status=status,
                    step_runs=step_runs,
                    events=event_log,
                    paused_step=step.id,
                    blockers=blockers,
                )

            target = None
            for event in result.events:
                if event.type in step.routes:
                    target = step.routes[event.type]
                    break
            target = target or step.next_step
            if not target or target == _END:
                return ProjectWorkflowRun(
                    run_ref=actual_run_ref,
                    project_ref=self.project.project_ref,
                    workflow_key=workflow.key,
                    status=(
                        ProjectWorkflowRunStatus.PREVIEW
                        if saw_preview
                        else ProjectWorkflowRunStatus.COMPLETED
                    ),
                    step_runs=step_runs,
                    events=event_log,
                )
            current_step = target

        return ProjectWorkflowRun(
            run_ref=actual_run_ref,
            project_ref=self.project.project_ref,
            workflow_key=workflow.key,
            status=ProjectWorkflowRunStatus.BLOCKED,
            step_runs=step_runs,
            events=event_log,
            paused_step=current_step,
            blockers=[
                PrimitiveBlocker(
                    code="workflow_step_limit",
                    message="Workflow exceeded the project's maximum step count.",
                )
            ],
        )


__all__ = [
    "PROJECT_SPEC_SCHEMA",
    "PROJECT_VALIDATION_SCHEMA",
    "PROJECT_WORKFLOW_RUN_SCHEMA",
    "BindingResolutionError",
    "LightbulbProject",
    "ProjectPolicy",
    "ProjectRuntime",
    "RetryPolicy",
    "ProjectValidationIssue",
    "ProjectValidationResult",
    "ProjectValidationSeverity",
    "ProjectWorkflow",
    "ProjectWorkflowRun",
    "ProjectWorkflowRunStatus",
    "ProjectWorkflowStep",
]
