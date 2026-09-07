"""Provider-neutral contracts for durable, evaluator-gated dynamic workflows.

This module deliberately contains no model, network, filesystem, or host-runtime
dependencies.  Hosts execute the typed assignments and return typed results;
the state machine only validates and records deterministic transitions.

Context and session fields are opaque binding fingerprints, not provider IDs.
Adapters must domain-separate and irreversibly bind their raw identifiers into
``dwh_<sha256>`` references before constructing any contract in this module.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterable, Mapping
from typing_extensions import Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


DYNAMIC_WORKFLOW_STATE_SCHEMA = "lightbulb.dynamic_workflow_state.v1"
DYNAMIC_WORKFLOW_HANDOFF_SCHEMA = "lightbulb.dynamic_workflow_handoff.v1"

_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_OPAQUE_BINDING_RE = re.compile(r"^dwh_[a-f0-9]{64}$")
_GENESIS_DIGEST = "0" * 64


def _canonical_json(value: Any) -> bytes:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json", by_alias=True)
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _nonblank(value: str, *, label: str) -> str:
    clean = value.strip()
    if not clean:
        raise ValueError(f"{label} must not be blank")
    return clean


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamps must include a timezone")
    return value.astimezone(timezone.utc)


def _opaque_binding(value: str) -> str:
    clean = value.strip().lower()
    if not _OPAQUE_BINDING_RE.fullmatch(clean):
        raise ValueError(
            "context and session bindings must be opaque dwh_<sha256> references, "
            "never raw provider identifiers"
        )
    return clean


class DynamicWorkflowError(RuntimeError):
    """Base error for rejected dynamic-workflow transitions."""


class ScopeMismatchError(DynamicWorkflowError):
    """A transition attempted to cross a tenant, company, user, or project."""


class InvalidTransitionError(DynamicWorkflowError):
    """A command is inconsistent with the current durable workflow state."""


class WorkflowRunStatus(str, Enum):
    PLANNING = "planning"
    BUILDING = "building"
    EVALUATING = "evaluating"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    BLOCKED = "blocked"
    BUDGET_EXHAUSTED = "budget_exhausted"
    CANCELLED = "cancelled"

    @property
    def terminal(self) -> bool:
        return self in {
            self.ACCEPTED,
            self.REJECTED,
            self.BLOCKED,
            self.BUDGET_EXHAUSTED,
            self.CANCELLED,
        }


class EvaluatorDecision(str, Enum):
    ACCEPT = "accept"
    RETRY_BUILD = "retry_build"
    REVISE_PLAN = "revise_plan"
    REJECT = "reject"
    BLOCK = "block"


class BuilderOutcome(str, Enum):
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"


class DynamicWorkflowRole(str, Enum):
    ORCHESTRATOR = "orchestrator"
    PLANNER = "planner"
    BUILDER = "builder"
    EVALUATOR = "evaluator"


class _FrozenModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        str_strip_whitespace=True,
    )


class _DigestedModel(_FrozenModel):
    digest: str = ""

    @model_validator(mode="after")
    def _seal_digest(self) -> Self:
        payload = self.model_dump(mode="json", exclude={"digest"}, by_alias=True)
        expected = _sha256(payload)
        if self.digest and self.digest != expected:
            raise ValueError("digest does not match the canonical payload")
        object.__setattr__(self, "digest", expected)
        return self


class DynamicWorkflowScope(_FrozenModel):
    """Complete authority scope; every field is required and compared exactly."""

    tenant_id: str = Field(min_length=1, max_length=200)
    company_id: str = Field(min_length=1, max_length=200)
    user_id: str = Field(min_length=1, max_length=200)
    project_ref: str = Field(min_length=1, max_length=200)

    @field_validator("tenant_id", "company_id", "user_id", "project_ref")
    @classmethod
    def _required_scope(cls, value: str) -> str:
        return _nonblank(value, label="scope field")

    def require_exact(self, other: "DynamicWorkflowScope") -> None:
        if self != other:
            raise ScopeMismatchError(
                "dynamic workflow scope mismatch; tenant, company, user, and "
                "project must all match"
            )


class WorkflowLimits(_FrozenModel):
    """Finite run limits. Equality with a limit is allowed; exceeding it is not."""

    max_plan_revisions: int = Field(default=3, ge=1, le=100)
    max_build_attempts: int = Field(default=8, ge=1, le=10_000)
    max_evaluation_attempts: int = Field(default=8, ge=1, le=10_000)
    max_iterations: int = Field(default=8, ge=1, le=10_000)
    max_elapsed_seconds: int = Field(default=14_400, ge=1, le=31_536_000)
    max_tokens: int = Field(default=10_000_000, ge=1)
    max_cost_microusd: int = Field(default=100_000_000, ge=0)
    max_handoff_bytes: int = Field(
        default=1_000_000,
        ge=256,
        description="Maximum cumulative serialized bytes in the handoff chain.",
    )
    max_no_progress_digests: int = Field(default=2, ge=1, le=100)


class UsageDelta(_FrozenModel):
    elapsed_seconds: int = Field(default=0, ge=0)
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    cost_microusd: int = Field(default=0, ge=0)

    @property
    def tokens(self) -> int:
        return self.input_tokens + self.output_tokens


class UsageTotals(_FrozenModel):
    elapsed_seconds: int = Field(default=0, ge=0)
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    cost_microusd: int = Field(default=0, ge=0)

    @property
    def tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    def add(self, delta: UsageDelta) -> "UsageTotals":
        return UsageTotals(
            elapsed_seconds=self.elapsed_seconds + delta.elapsed_seconds,
            input_tokens=self.input_tokens + delta.input_tokens,
            output_tokens=self.output_tokens + delta.output_tokens,
            cost_microusd=self.cost_microusd + delta.cost_microusd,
        )


class EvidenceRef(_FrozenModel):
    """Content-addressed evidence; raw evidence never enters the control state."""

    ref: str = Field(min_length=1, max_length=2000)
    sha256: str
    kind: str = Field(min_length=1, max_length=120)
    media_type: str | None = Field(default=None, max_length=200)

    @field_validator("ref", "kind")
    @classmethod
    def _nonempty(cls, value: str) -> str:
        return _nonblank(value, label="evidence reference")

    @field_validator("sha256")
    @classmethod
    def _valid_sha256(cls, value: str) -> str:
        clean = value.strip().lower()
        if not _SHA256_RE.fullmatch(clean):
            raise ValueError("sha256 must contain exactly 64 lowercase hex characters")
        return clean


class AcceptanceCriterion(_DigestedModel):
    """An immutable acceptance obligation fixed before planning begins."""

    criterion_id: str = Field(min_length=1, max_length=160)
    description: str = Field(min_length=1, max_length=4000)
    required_evidence: tuple[str, ...] = Field(min_length=1, max_length=50)

    @field_validator("criterion_id", "description")
    @classmethod
    def _required_text(cls, value: str) -> str:
        return _nonblank(value, label="acceptance criterion")

    @field_validator("required_evidence")
    @classmethod
    def _unique_evidence_kinds(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        clean = tuple(_nonblank(item, label="required evidence kind") for item in value)
        if len(clean) != len(set(clean)):
            raise ValueError("required evidence kinds must be unique")
        return clean


class CriterionEvaluation(_FrozenModel):
    """Default-fail result for one immutable criterion."""

    criterion_id: str = Field(min_length=1, max_length=160)
    accepted: bool = False
    reason: str = Field(default="not_evaluated", min_length=1, max_length=4000)
    evidence_refs: tuple[EvidenceRef, ...] = Field(default_factory=tuple, max_length=200)

    @model_validator(mode="after")
    def _accepted_requires_evidence(self) -> Self:
        if self.accepted and not self.evidence_refs:
            raise ValueError("an accepted criterion must cite content-addressed evidence")
        return self


class PlannerPlan(_DigestedModel):
    scope: DynamicWorkflowScope
    run_ref: str = Field(min_length=1, max_length=200)
    plan_id: str = Field(min_length=1, max_length=200)
    revision: int = Field(ge=1)
    objective: str = Field(min_length=1, max_length=20_000)
    acceptance_criteria: tuple[AcceptanceCriterion, ...] = Field(min_length=1, max_length=500)
    work_items: tuple[str, ...] = Field(min_length=1, max_length=1000)
    planner_context_id: str = Field(min_length=1, max_length=300)
    planner_session_id: str = Field(min_length=1, max_length=300)
    occurred_at: datetime
    usage: UsageDelta = Field(default_factory=UsageDelta)

    @field_validator("run_ref", "plan_id", "objective", "planner_context_id", "planner_session_id")
    @classmethod
    def _plan_text(cls, value: str) -> str:
        return _nonblank(value, label="plan field")

    @field_validator("planner_context_id", "planner_session_id")
    @classmethod
    def _opaque_planner_binding(cls, value: str) -> str:
        return _opaque_binding(value)

    @field_validator("work_items")
    @classmethod
    def _plan_work(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(_nonblank(item, label="work item") for item in value)

    @field_validator("occurred_at")
    @classmethod
    def _plan_time(cls, value: datetime) -> datetime:
        return _utc(value)

    @model_validator(mode="after")
    def _unique_criteria(self) -> Self:
        ids = [criterion.criterion_id for criterion in self.acceptance_criteria]
        if len(ids) != len(set(ids)):
            raise ValueError("plan acceptance criterion ids must be unique")
        return self


class BuilderAssignment(_DigestedModel):
    scope: DynamicWorkflowScope
    run_ref: str = Field(min_length=1, max_length=200)
    assignment_id: str = Field(min_length=1, max_length=200)
    plan_digest: str
    plan_revision: int = Field(ge=1)
    iteration: int = Field(ge=1)
    instructions: str = Field(min_length=1, max_length=20_000)
    acceptance_criteria_digest: str
    builder_context_id: str = Field(min_length=1, max_length=300)
    builder_session_id: str = Field(min_length=1, max_length=300)
    prior_verdict_digest: str | None = None
    occurred_at: datetime
    usage: UsageDelta = Field(default_factory=UsageDelta)

    @field_validator("run_ref", "assignment_id", "instructions", "builder_context_id", "builder_session_id")
    @classmethod
    def _assignment_text(cls, value: str) -> str:
        return _nonblank(value, label="builder assignment field")

    @field_validator("builder_context_id", "builder_session_id")
    @classmethod
    def _opaque_builder_binding(cls, value: str) -> str:
        return _opaque_binding(value)

    @field_validator("plan_digest", "acceptance_criteria_digest", "prior_verdict_digest")
    @classmethod
    def _assignment_digest(cls, value: str | None) -> str | None:
        if value is None:
            return None
        clean = value.strip().lower()
        if not _SHA256_RE.fullmatch(clean):
            raise ValueError("artifact digests must be lowercase SHA-256 values")
        return clean

    @field_validator("occurred_at")
    @classmethod
    def _assignment_time(cls, value: datetime) -> datetime:
        return _utc(value)


class BuilderResult(_DigestedModel):
    scope: DynamicWorkflowScope
    run_ref: str = Field(min_length=1, max_length=200)
    assignment_id: str = Field(min_length=1, max_length=200)
    plan_digest: str
    iteration: int = Field(ge=1)
    builder_context_id: str = Field(min_length=1, max_length=300)
    builder_session_id: str = Field(min_length=1, max_length=300)
    outcome: BuilderOutcome
    summary: str = Field(min_length=1, max_length=20_000)
    evidence_refs: tuple[EvidenceRef, ...] = Field(default_factory=tuple, max_length=1000)
    progress_digest: str
    occurred_at: datetime
    usage: UsageDelta = Field(default_factory=UsageDelta)

    @field_validator("run_ref", "assignment_id", "builder_context_id", "builder_session_id", "summary")
    @classmethod
    def _result_text(cls, value: str) -> str:
        return _nonblank(value, label="builder result field")

    @field_validator("builder_context_id", "builder_session_id")
    @classmethod
    def _opaque_result_binding(cls, value: str) -> str:
        return _opaque_binding(value)

    @field_validator("plan_digest", "progress_digest")
    @classmethod
    def _result_digest(cls, value: str) -> str:
        clean = value.strip().lower()
        if not _SHA256_RE.fullmatch(clean):
            raise ValueError("artifact digests must be lowercase SHA-256 values")
        return clean

    @field_validator("occurred_at")
    @classmethod
    def _result_time(cls, value: datetime) -> datetime:
        return _utc(value)


class EvaluatorVerdict(_DigestedModel):
    scope: DynamicWorkflowScope
    run_ref: str = Field(min_length=1, max_length=200)
    verdict_id: str = Field(min_length=1, max_length=200)
    plan_digest: str
    builder_result_digest: str
    evaluator_context_id: str = Field(min_length=1, max_length=300)
    evaluator_session_id: str = Field(min_length=1, max_length=300)
    decision: EvaluatorDecision
    accepted: bool = False
    summary: str = Field(min_length=1, max_length=20_000)
    criterion_results: tuple[CriterionEvaluation, ...] = Field(default_factory=tuple, max_length=500)
    occurred_at: datetime
    usage: UsageDelta = Field(default_factory=UsageDelta)

    @field_validator("run_ref", "verdict_id", "evaluator_context_id", "evaluator_session_id", "summary")
    @classmethod
    def _verdict_text(cls, value: str) -> str:
        return _nonblank(value, label="evaluator verdict field")

    @field_validator("evaluator_context_id", "evaluator_session_id")
    @classmethod
    def _opaque_evaluator_binding(cls, value: str) -> str:
        return _opaque_binding(value)

    @field_validator("plan_digest", "builder_result_digest")
    @classmethod
    def _verdict_digest(cls, value: str) -> str:
        clean = value.strip().lower()
        if not _SHA256_RE.fullmatch(clean):
            raise ValueError("artifact digests must be lowercase SHA-256 values")
        return clean

    @field_validator("occurred_at")
    @classmethod
    def _verdict_time(cls, value: datetime) -> datetime:
        return _utc(value)

    @model_validator(mode="after")
    def _decision_is_fail_closed(self) -> Self:
        ids = [result.criterion_id for result in self.criterion_results]
        if len(ids) != len(set(ids)):
            raise ValueError("criterion results must be unique")
        if self.decision == EvaluatorDecision.ACCEPT and not self.accepted:
            raise ValueError("accept decisions require an explicit accepted=true assertion")
        if self.decision != EvaluatorDecision.ACCEPT and self.accepted:
            raise ValueError("only an accept decision may assert accepted=true")
        return self


class DynamicWorkflowHandoff(_DigestedModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        str_strip_whitespace=True,
    )

    schema_id: str = Field(default=DYNAMIC_WORKFLOW_HANDOFF_SCHEMA, alias="schema")
    scope: DynamicWorkflowScope
    run_ref: str = Field(min_length=1, max_length=200)
    sequence: int = Field(ge=1)
    source_role: DynamicWorkflowRole
    target_role: DynamicWorkflowRole
    artifact_type: str = Field(min_length=1, max_length=160)
    artifact_digest: str
    summary: str = Field(min_length=1, max_length=20_000)
    evidence_refs: tuple[EvidenceRef, ...] = Field(default_factory=tuple, max_length=1000)
    previous_digest: str
    occurred_at: datetime

    @field_validator("run_ref", "artifact_type", "summary")
    @classmethod
    def _handoff_text(cls, value: str) -> str:
        return _nonblank(value, label="handoff field")

    @field_validator("artifact_digest", "previous_digest")
    @classmethod
    def _handoff_digest(cls, value: str) -> str:
        clean = value.strip().lower()
        if not _SHA256_RE.fullmatch(clean):
            raise ValueError("handoff links must be lowercase SHA-256 values")
        return clean

    @field_validator("occurred_at")
    @classmethod
    def _handoff_time(cls, value: datetime) -> datetime:
        return _utc(value)

    @property
    def byte_size(self) -> int:
        return len(_canonical_json(self))


def _criteria_digest(criteria: Iterable[AcceptanceCriterion]) -> str:
    return _sha256([criterion.digest for criterion in criteria])


class DynamicWorkflowState(_FrozenModel):
    """Immutable durable state for a single provider-neutral workflow run."""

    schema_id: str = Field(default=DYNAMIC_WORKFLOW_STATE_SCHEMA, alias="schema")
    scope: DynamicWorkflowScope
    run_ref: str = Field(min_length=1, max_length=200)
    objective: str = Field(min_length=1, max_length=20_000)
    acceptance_criteria: tuple[AcceptanceCriterion, ...] = Field(min_length=1, max_length=500)
    criterion_results: tuple[CriterionEvaluation, ...] = Field(min_length=1, max_length=500)
    limits: WorkflowLimits = Field(default_factory=WorkflowLimits)
    status: WorkflowRunStatus = WorkflowRunStatus.PLANNING
    revision: int = Field(default=0, ge=0)
    created_at: datetime
    updated_at: datetime
    plan_revisions: int = Field(default=0, ge=0)
    build_attempts: int = Field(default=0, ge=0)
    evaluation_attempts: int = Field(default=0, ge=0)
    iterations: int = Field(default=0, ge=0)
    usage: UsageTotals = Field(default_factory=UsageTotals)
    handoff_bytes: int = Field(default=0, ge=0)
    repeated_no_progress_digests: int = Field(default=0, ge=0)
    last_progress_digest: str | None = None
    current_plan: PlannerPlan | None = None
    current_assignment: BuilderAssignment | None = None
    current_builder_result: BuilderResult | None = None
    current_verdict: EvaluatorVerdict | None = None
    handoffs: tuple[DynamicWorkflowHandoff, ...] = Field(default_factory=tuple)
    builder_context_ids: tuple[str, ...] = Field(default_factory=tuple)
    builder_session_ids: tuple[str, ...] = Field(default_factory=tuple)
    evaluator_context_ids: tuple[str, ...] = Field(default_factory=tuple)
    evaluator_session_ids: tuple[str, ...] = Field(default_factory=tuple)
    terminal_reason: str | None = Field(default=None, max_length=4000)

    @field_validator("run_ref", "objective")
    @classmethod
    def _state_text(cls, value: str) -> str:
        return _nonblank(value, label="workflow state field")

    @field_validator("created_at", "updated_at")
    @classmethod
    def _state_time(cls, value: datetime) -> datetime:
        return _utc(value)

    @field_validator("last_progress_digest")
    @classmethod
    def _state_progress_digest(cls, value: str | None) -> str | None:
        if value is None:
            return None
        clean = value.strip().lower()
        if not _SHA256_RE.fullmatch(clean):
            raise ValueError("last_progress_digest must be a lowercase SHA-256 value")
        return clean

    @field_validator(
        "builder_context_ids",
        "builder_session_ids",
        "evaluator_context_ids",
        "evaluator_session_ids",
    )
    @classmethod
    def _opaque_binding_history(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(_opaque_binding(item) for item in value)

    @model_validator(mode="after")
    def _validate_durable_invariants(self) -> Self:
        if self.updated_at < self.created_at:
            raise ValueError("updated_at must not precede created_at")

        criterion_ids = [criterion.criterion_id for criterion in self.acceptance_criteria]
        if len(criterion_ids) != len(set(criterion_ids)):
            raise ValueError("acceptance criterion ids must be unique")
        result_ids = [result.criterion_id for result in self.criterion_results]
        if result_ids != criterion_ids:
            raise ValueError("criterion results must exactly follow immutable criteria order")

        previous = _GENESIS_DIGEST
        byte_count = 0
        handoffs_by_type: dict[str, list[tuple[int, DynamicWorkflowHandoff]]] = {
            "planner_plan": [],
            "builder_assignment": [],
            "builder_result": [],
            "evaluator_verdict": [],
            "workflow_control": [],
        }
        expected_roles = {
            "planner_plan": (
                {DynamicWorkflowRole.PLANNER},
                {DynamicWorkflowRole.ORCHESTRATOR},
            ),
            "builder_assignment": (
                {DynamicWorkflowRole.ORCHESTRATOR},
                {DynamicWorkflowRole.BUILDER},
            ),
            "builder_result": (
                {DynamicWorkflowRole.BUILDER},
                {DynamicWorkflowRole.EVALUATOR, DynamicWorkflowRole.ORCHESTRATOR},
            ),
            "evaluator_verdict": (
                {DynamicWorkflowRole.EVALUATOR},
                {DynamicWorkflowRole.ORCHESTRATOR},
            ),
            "workflow_control": (
                {DynamicWorkflowRole.ORCHESTRATOR},
                {DynamicWorkflowRole.ORCHESTRATOR},
            ),
        }
        for sequence, handoff in enumerate(self.handoffs, start=1):
            if handoff.sequence != sequence or handoff.previous_digest != previous:
                raise ValueError("handoff digest chain is discontinuous")
            if handoff.scope != self.scope or handoff.run_ref != self.run_ref:
                raise ValueError("handoff scope or run_ref does not match state")
            if handoff.artifact_type not in handoffs_by_type:
                raise ValueError("handoff artifact_type is not part of the v1 contract")
            sources, targets = expected_roles[handoff.artifact_type]
            if handoff.source_role not in sources or handoff.target_role not in targets:
                raise ValueError("handoff roles do not match artifact_type")
            if not self.created_at <= handoff.occurred_at <= self.updated_at:
                raise ValueError("handoff occurred_at is outside the durable state interval")
            handoffs_by_type[handoff.artifact_type].append((sequence, handoff))
            previous = handoff.digest
            byte_count += handoff.byte_size
        if byte_count != self.handoff_bytes:
            raise ValueError("handoff_bytes does not match serialized handoff chain")
        if self.handoff_bytes > self.limits.max_handoff_bytes:
            raise ValueError("handoff chain exceeds max_handoff_bytes")
        if self.revision not in {len(self.handoffs), len(self.handoffs) + 1}:
            raise ValueError("revision does not match durable transition history")
        if (
            self.revision == len(self.handoffs) + 1
            and self.status != WorkflowRunStatus.BUDGET_EXHAUSTED
        ):
            raise ValueError("only an unrecordable budget transition may omit a handoff")
        if self.plan_revisions > self.limits.max_plan_revisions:
            raise ValueError("plan_revisions exceeds configured limit")
        if self.build_attempts > self.limits.max_build_attempts:
            raise ValueError("build_attempts exceeds configured limit")
        if self.evaluation_attempts > self.limits.max_evaluation_attempts:
            raise ValueError("evaluation_attempts exceeds configured limit")
        if self.iterations > self.limits.max_iterations:
            raise ValueError("iterations exceeds configured limit")

        for artifact in (
            self.current_plan,
            self.current_assignment,
            self.current_builder_result,
            self.current_verdict,
        ):
            if artifact is not None:
                if artifact.scope != self.scope or artifact.run_ref != self.run_ref:
                    raise ValueError("current artifact scope or run_ref does not match state")
                if not self.created_at <= artifact.occurred_at <= self.updated_at:
                    raise ValueError("current artifact occurred_at is outside the durable state interval")

        if len(handoffs_by_type["planner_plan"]) != self.plan_revisions:
            raise ValueError("plan_revisions does not match planner handoffs")
        if len(handoffs_by_type["builder_assignment"]) != self.build_attempts:
            raise ValueError("build_attempts does not match assignment handoffs")
        if len(handoffs_by_type["evaluator_verdict"]) != self.evaluation_attempts:
            raise ValueError("evaluation_attempts does not match evaluator handoffs")
        if self.iterations != self.build_attempts:
            raise ValueError("iterations must match recorded builder assignments")
        if len(self.builder_context_ids) != self.build_attempts:
            raise ValueError("builder context history does not match build_attempts")
        if len(self.builder_session_ids) != self.build_attempts:
            raise ValueError("builder session history does not match build_attempts")
        if len(self.evaluator_context_ids) != self.evaluation_attempts:
            raise ValueError("evaluator context history does not match evaluation_attempts")
        if len(self.evaluator_session_ids) != self.evaluation_attempts:
            raise ValueError("evaluator session history does not match evaluation_attempts")
        if len(self.evaluator_context_ids) != len(set(self.evaluator_context_ids)):
            raise ValueError("evaluator contexts must be fresh for every attempt")
        if len(self.evaluator_session_ids) != len(set(self.evaluator_session_ids)):
            raise ValueError("evaluator sessions must be fresh for every attempt")
        if set(self.builder_context_ids) & set(self.evaluator_context_ids):
            raise ValueError("builder and evaluator context histories must be disjoint")
        if set(self.builder_session_ids) & set(self.evaluator_session_ids):
            raise ValueError("builder and evaluator session histories must be disjoint")

        current_by_type = {
            "planner_plan": self.current_plan,
            "builder_assignment": self.current_assignment,
            "builder_result": self.current_builder_result,
            "evaluator_verdict": self.current_verdict,
        }
        latest_sequence: dict[str, int] = {}
        for artifact_type, artifact in current_by_type.items():
            recorded = handoffs_by_type[artifact_type]
            if artifact is None:
                if artifact_type == "planner_plan" and recorded:
                    raise ValueError("recorded plans require current_plan")
                continue
            if not recorded or recorded[-1][1].artifact_digest != artifact.digest:
                raise ValueError(
                    f"current {artifact_type} does not match its latest handoff digest"
                )
            latest_sequence[artifact_type] = recorded[-1][0]

        if self.current_plan is not None:
            if self.current_plan.revision != self.plan_revisions:
                raise ValueError("current plan revision does not match plan_revisions")
            if self.current_plan.objective != self.objective:
                raise ValueError("current plan changed the durable objective")
            if self.current_plan.acceptance_criteria != self.acceptance_criteria:
                raise ValueError("current plan changed immutable acceptance criteria")
        elif self.plan_revisions:
            raise ValueError("plan revisions require a current plan")

        if self.current_assignment is not None:
            if self.current_plan is None:
                raise ValueError("current assignment requires a current plan")
            if (
                self.current_assignment.plan_digest != self.current_plan.digest
                or self.current_assignment.plan_revision != self.current_plan.revision
                or self.current_assignment.acceptance_criteria_digest
                != self.acceptance_criteria_digest
            ):
                raise ValueError("current assignment does not bind the current plan")
            if self.current_assignment.iteration > self.iterations:
                raise ValueError("current assignment iteration exceeds durable iterations")
            verdict_sequence = latest_sequence.get("evaluator_verdict", 0)
            assignment_sequence = latest_sequence.get("builder_assignment", 0)
            if assignment_sequence > verdict_sequence:
                expected_prior = self.current_verdict.digest if self.current_verdict else None
                if self.current_assignment.prior_verdict_digest != expected_prior:
                    raise ValueError("current assignment does not bind the preceding verdict")

        if self.current_builder_result is not None:
            if self.current_assignment is None:
                raise ValueError("current builder result requires a current assignment")
            if (
                self.current_builder_result.assignment_id
                != self.current_assignment.assignment_id
                or self.current_builder_result.plan_digest
                != self.current_assignment.plan_digest
                or self.current_builder_result.iteration != self.current_assignment.iteration
                or self.current_builder_result.builder_context_id
                != self.current_assignment.builder_context_id
                or self.current_builder_result.builder_session_id
                != self.current_assignment.builder_session_id
            ):
                raise ValueError("current builder result does not bind the current assignment")

        verdict_sequence = latest_sequence.get("evaluator_verdict", 0)
        result_sequence = latest_sequence.get("builder_result", 0)
        plan_sequence = latest_sequence.get("planner_plan", 0)
        assignment_sequence = latest_sequence.get("builder_assignment", 0)
        if self.current_verdict is not None and verdict_sequence > max(
            result_sequence, plan_sequence, assignment_sequence
        ):
            if self.current_plan is None or self.current_builder_result is None:
                raise ValueError("latest evaluator verdict requires its evaluated artifacts")
            if (
                self.current_verdict.plan_digest != self.current_plan.digest
                or self.current_verdict.builder_result_digest
                != self.current_builder_result.digest
            ):
                raise ValueError("current evaluator verdict does not bind evaluated artifacts")

        if self.status in {WorkflowRunStatus.BUILDING, WorkflowRunStatus.EVALUATING}:
            if self.current_plan is None:
                raise ValueError(f"{self.status.value} state requires a current plan")
        if self.status == WorkflowRunStatus.EVALUATING:
            if (
                self.current_assignment is None
                or self.current_builder_result is None
                or self.current_builder_result.outcome != BuilderOutcome.COMPLETED
            ):
                raise ValueError("evaluating state requires a completed current builder result")
        if self.status == WorkflowRunStatus.ACCEPTED:
            if (
                self.current_verdict is None
                or self.current_verdict.decision != EvaluatorDecision.ACCEPT
                or not self.current_verdict.accepted
                or not all(result.accepted for result in self.criterion_results)
            ):
                raise ValueError("accepted state requires a complete accepted evaluator verdict")
        if self.status == WorkflowRunStatus.REJECTED:
            if self.current_verdict is None or self.current_verdict.decision != EvaluatorDecision.REJECT:
                raise ValueError("rejected state requires a rejecting evaluator verdict")

        if self.status.terminal and not self.terminal_reason:
            raise ValueError("terminal workflow states require a reason")
        if not self.status.terminal and self.terminal_reason is not None:
            raise ValueError("non-terminal workflow states cannot have a terminal reason")
        return self

    @classmethod
    def create(
        cls,
        *,
        scope: DynamicWorkflowScope | Mapping[str, Any],
        run_ref: str,
        objective: str,
        acceptance_criteria: Iterable[AcceptanceCriterion | Mapping[str, Any]],
        created_at: datetime,
        limits: WorkflowLimits | Mapping[str, Any] | None = None,
    ) -> "DynamicWorkflowState":
        resolved_scope = DynamicWorkflowScope.model_validate(scope)
        criteria = tuple(
            criterion
            if isinstance(criterion, AcceptanceCriterion)
            else AcceptanceCriterion.model_validate(criterion)
            for criterion in acceptance_criteria
        )
        if not criteria:
            raise ValueError("at least one immutable acceptance criterion is required")
        default_failures = tuple(
            CriterionEvaluation(criterion_id=criterion.criterion_id)
            for criterion in criteria
        )
        resolved_limits = (
            WorkflowLimits()
            if limits is None
            else WorkflowLimits.model_validate(limits)
        )
        timestamp = _utc(created_at)
        return cls(
            scope=resolved_scope,
            run_ref=run_ref,
            objective=objective,
            acceptance_criteria=criteria,
            criterion_results=default_failures,
            limits=resolved_limits,
            created_at=timestamp,
            updated_at=timestamp,
        )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True)

    @property
    def acceptance_criteria_digest(self) -> str:
        return _criteria_digest(self.acceptance_criteria)

    @property
    def latest_handoff_digest(self) -> str:
        return self.handoffs[-1].digest if self.handoffs else _GENESIS_DIGEST

    def submit_plan(self, plan: PlannerPlan) -> "DynamicWorkflowState":
        self._require_phase(WorkflowRunStatus.PLANNING)
        self._require_artifact(plan.scope, plan.run_ref, plan.occurred_at)
        if plan.revision != self.plan_revisions + 1:
            raise InvalidTransitionError("plan revision must increase by exactly one")
        if plan.objective != self.objective:
            raise InvalidTransitionError("planner cannot change the durable objective")
        if plan.acceptance_criteria != self.acceptance_criteria:
            raise InvalidTransitionError("planner cannot change immutable acceptance criteria")
        if self.plan_revisions >= self.limits.max_plan_revisions:
            return self._budget_terminal("max_plan_revisions", plan.occurred_at, plan.usage)

        usage = self._usage_after(plan.usage, plan.occurred_at)
        budget = self._usage_budget_reason(usage, plan.occurred_at)
        if budget:
            return self._budget_terminal(budget, plan.occurred_at, plan.usage)
        return self._record(
            occurred_at=plan.occurred_at,
            usage=usage,
            source=DynamicWorkflowRole.PLANNER,
            target=DynamicWorkflowRole.ORCHESTRATOR,
            artifact_type="planner_plan",
            artifact_digest=plan.digest,
            summary=f"Plan revision {plan.revision}: {len(plan.work_items)} work item(s)",
            evidence_refs=(),
            status=WorkflowRunStatus.BUILDING,
            plan_revisions=self.plan_revisions + 1,
            current_plan=plan,
            current_assignment=None,
            current_builder_result=None,
        )

    def assign_builder(self, assignment: BuilderAssignment) -> "DynamicWorkflowState":
        self._require_phase(WorkflowRunStatus.BUILDING)
        self._require_artifact(assignment.scope, assignment.run_ref, assignment.occurred_at)
        if self.current_plan is None:
            raise InvalidTransitionError("a builder cannot be assigned before a plan")
        if self.current_assignment is not None and self.current_builder_result is None:
            raise InvalidTransitionError("the current builder assignment has no result")
        if assignment.plan_digest != self.current_plan.digest:
            raise InvalidTransitionError("assignment does not reference the current plan")
        if assignment.plan_revision != self.current_plan.revision:
            raise InvalidTransitionError("assignment plan revision is stale")
        if assignment.acceptance_criteria_digest != self.acceptance_criteria_digest:
            raise InvalidTransitionError("assignment acceptance criteria digest is stale")
        if assignment.iteration != self.iterations + 1:
            raise InvalidTransitionError("builder iteration must increase by exactly one")
        expected_prior = self.current_verdict.digest if self.current_verdict else None
        if assignment.prior_verdict_digest != expected_prior:
            raise InvalidTransitionError("assignment must bind the latest evaluator verdict")
        if assignment.builder_context_id in self.evaluator_context_ids:
            raise InvalidTransitionError("builder context was previously used for evaluation")
        if assignment.builder_session_id in self.evaluator_session_ids:
            raise InvalidTransitionError("builder session was previously used for evaluation")
        if self.build_attempts >= self.limits.max_build_attempts:
            return self._budget_terminal("max_build_attempts", assignment.occurred_at, assignment.usage)
        if self.iterations >= self.limits.max_iterations:
            return self._budget_terminal("max_iterations", assignment.occurred_at, assignment.usage)

        usage = self._usage_after(assignment.usage, assignment.occurred_at)
        budget = self._usage_budget_reason(usage, assignment.occurred_at)
        if budget:
            return self._budget_terminal(budget, assignment.occurred_at, assignment.usage)
        return self._record(
            occurred_at=assignment.occurred_at,
            usage=usage,
            source=DynamicWorkflowRole.ORCHESTRATOR,
            target=DynamicWorkflowRole.BUILDER,
            artifact_type="builder_assignment",
            artifact_digest=assignment.digest,
            summary=f"Builder assignment for iteration {assignment.iteration}",
            evidence_refs=(),
            status=WorkflowRunStatus.BUILDING,
            build_attempts=self.build_attempts + 1,
            iterations=self.iterations + 1,
            current_assignment=assignment,
            current_builder_result=None,
            builder_context_ids=self.builder_context_ids + (assignment.builder_context_id,),
            builder_session_ids=self.builder_session_ids + (assignment.builder_session_id,),
        )

    def record_builder_result(self, result: BuilderResult) -> "DynamicWorkflowState":
        self._require_phase(WorkflowRunStatus.BUILDING)
        self._require_artifact(result.scope, result.run_ref, result.occurred_at)
        assignment = self.current_assignment
        if assignment is None or self.current_builder_result is not None:
            raise InvalidTransitionError("there is no unresolved builder assignment")
        if result.assignment_id != assignment.assignment_id:
            raise InvalidTransitionError("builder result assignment_id does not match")
        if result.plan_digest != assignment.plan_digest or result.iteration != assignment.iteration:
            raise InvalidTransitionError("builder result plan or iteration does not match")
        if (
            result.builder_context_id != assignment.builder_context_id
            or result.builder_session_id != assignment.builder_session_id
        ):
            raise InvalidTransitionError("builder result must come from the assigned context and session")

        repeated = (
            self.repeated_no_progress_digests + 1
            if result.progress_digest == self.last_progress_digest
            else 0
        )
        usage = self._usage_after(result.usage, result.occurred_at)
        budget = self._usage_budget_reason(usage, result.occurred_at)
        if budget:
            return self._budget_terminal(budget, result.occurred_at, result.usage)

        if repeated >= self.limits.max_no_progress_digests:
            return self._record(
                occurred_at=result.occurred_at,
                usage=usage,
                source=DynamicWorkflowRole.BUILDER,
                target=DynamicWorkflowRole.ORCHESTRATOR,
                artifact_type="builder_result",
                artifact_digest=result.digest,
                summary=result.summary,
                evidence_refs=result.evidence_refs,
                status=WorkflowRunStatus.BLOCKED,
                terminal_reason="no_progress_digest_limit",
                current_builder_result=result,
                repeated_no_progress_digests=repeated,
                last_progress_digest=result.progress_digest,
            )

        if result.outcome == BuilderOutcome.BLOCKED:
            status = WorkflowRunStatus.BLOCKED
            reason = "builder_blocked"
            target = DynamicWorkflowRole.ORCHESTRATOR
        elif result.outcome == BuilderOutcome.FAILED:
            status = WorkflowRunStatus.BUILDING
            reason = None
            target = DynamicWorkflowRole.ORCHESTRATOR
        else:
            status = WorkflowRunStatus.EVALUATING
            reason = None
            target = DynamicWorkflowRole.EVALUATOR

        if result.outcome == BuilderOutcome.FAILED and (
            self.build_attempts >= self.limits.max_build_attempts
            or self.iterations >= self.limits.max_iterations
        ):
            status = WorkflowRunStatus.BUDGET_EXHAUSTED
            reason = (
                "max_build_attempts"
                if self.build_attempts >= self.limits.max_build_attempts
                else "max_iterations"
            )

        return self._record(
            occurred_at=result.occurred_at,
            usage=usage,
            source=DynamicWorkflowRole.BUILDER,
            target=target,
            artifact_type="builder_result",
            artifact_digest=result.digest,
            summary=result.summary,
            evidence_refs=result.evidence_refs,
            status=status,
            terminal_reason=reason,
            current_builder_result=result,
            repeated_no_progress_digests=repeated,
            last_progress_digest=result.progress_digest,
        )

    def record_evaluator_verdict(self, verdict: EvaluatorVerdict) -> "DynamicWorkflowState":
        self._require_phase(WorkflowRunStatus.EVALUATING)
        self._require_artifact(verdict.scope, verdict.run_ref, verdict.occurred_at)
        assignment = self.current_assignment
        result = self.current_builder_result
        plan = self.current_plan
        if assignment is None or result is None or plan is None:
            raise InvalidTransitionError("evaluation requires a plan and completed builder result")
        if verdict.plan_digest != plan.digest or verdict.builder_result_digest != result.digest:
            raise InvalidTransitionError("evaluator verdict references stale artifacts")
        if verdict.evaluator_context_id in self.builder_context_ids:
            raise InvalidTransitionError("evaluator must use a fresh context distinct from every builder")
        if verdict.evaluator_session_id in self.builder_session_ids:
            raise InvalidTransitionError("evaluator must use a fresh session distinct from every builder")
        if verdict.evaluator_context_id in self.evaluator_context_ids:
            raise InvalidTransitionError("each evaluator attempt requires a fresh context")
        if verdict.evaluator_session_id in self.evaluator_session_ids:
            raise InvalidTransitionError("each evaluator attempt requires a fresh session")
        if self.evaluation_attempts >= self.limits.max_evaluation_attempts:
            return self._budget_terminal(
                "max_evaluation_attempts", verdict.occurred_at, verdict.usage
            )

        normalized_results = self._normalize_verdict_results(verdict)
        if verdict.decision == EvaluatorDecision.ACCEPT:
            failed = [item.criterion_id for item in normalized_results if not item.accepted]
            if failed:
                raise InvalidTransitionError(
                    "accept verdict is fail-closed; criteria not proven: " + ", ".join(failed)
                )

        usage = self._usage_after(verdict.usage, verdict.occurred_at)
        budget = self._usage_budget_reason(usage, verdict.occurred_at)
        if budget:
            return self._budget_terminal(budget, verdict.occurred_at, verdict.usage)

        attempts = self.evaluation_attempts + 1
        if verdict.decision == EvaluatorDecision.ACCEPT:
            status = WorkflowRunStatus.ACCEPTED
            reason = "all_acceptance_criteria_proven"
        elif verdict.decision == EvaluatorDecision.REJECT:
            status = WorkflowRunStatus.REJECTED
            reason = "evaluator_rejected"
        elif verdict.decision == EvaluatorDecision.BLOCK:
            status = WorkflowRunStatus.BLOCKED
            reason = "evaluator_blocked"
        elif verdict.decision == EvaluatorDecision.REVISE_PLAN:
            status = WorkflowRunStatus.PLANNING
            reason = None
        else:
            status = WorkflowRunStatus.BUILDING
            reason = None

        if status == WorkflowRunStatus.PLANNING and self.plan_revisions >= self.limits.max_plan_revisions:
            status = WorkflowRunStatus.BUDGET_EXHAUSTED
            reason = "max_plan_revisions"
        elif status == WorkflowRunStatus.BUILDING and (
            self.build_attempts >= self.limits.max_build_attempts
            or self.iterations >= self.limits.max_iterations
        ):
            status = WorkflowRunStatus.BUDGET_EXHAUSTED
            reason = (
                "max_build_attempts"
                if self.build_attempts >= self.limits.max_build_attempts
                else "max_iterations"
            )
        elif not status.terminal and attempts >= self.limits.max_evaluation_attempts:
            status = WorkflowRunStatus.BUDGET_EXHAUSTED
            reason = "max_evaluation_attempts"

        evidence = tuple(
            evidence_ref
            for criterion_result in normalized_results
            for evidence_ref in criterion_result.evidence_refs
        )
        return self._record(
            occurred_at=verdict.occurred_at,
            usage=usage,
            source=DynamicWorkflowRole.EVALUATOR,
            target=DynamicWorkflowRole.ORCHESTRATOR,
            artifact_type="evaluator_verdict",
            artifact_digest=verdict.digest,
            summary=verdict.summary,
            evidence_refs=evidence,
            status=status,
            terminal_reason=reason,
            evaluation_attempts=attempts,
            criterion_results=normalized_results,
            current_verdict=verdict,
            evaluator_context_ids=self.evaluator_context_ids + (verdict.evaluator_context_id,),
            evaluator_session_ids=self.evaluator_session_ids + (verdict.evaluator_session_id,),
        )

    def cancel(
        self,
        *,
        scope: DynamicWorkflowScope,
        reason: str,
        occurred_at: datetime,
    ) -> "DynamicWorkflowState":
        self._require_active()
        self._require_artifact(scope, self.run_ref, occurred_at)
        clean_reason = _nonblank(reason, label="cancellation reason")
        return self._record_control(
            status=WorkflowRunStatus.CANCELLED,
            reason=clean_reason,
            occurred_at=_utc(occurred_at),
        )

    def block(
        self,
        *,
        scope: DynamicWorkflowScope,
        reason: str,
        occurred_at: datetime,
    ) -> "DynamicWorkflowState":
        self._require_active()
        self._require_artifact(scope, self.run_ref, occurred_at)
        clean_reason = _nonblank(reason, label="block reason")
        return self._record_control(
            status=WorkflowRunStatus.BLOCKED,
            reason=clean_reason,
            occurred_at=_utc(occurred_at),
        )

    def _normalize_verdict_results(
        self, verdict: EvaluatorVerdict
    ) -> tuple[CriterionEvaluation, ...]:
        known = {criterion.criterion_id: criterion for criterion in self.acceptance_criteria}
        supplied = {result.criterion_id: result for result in verdict.criterion_results}
        unknown = sorted(set(supplied) - set(known))
        if unknown:
            raise InvalidTransitionError(
                "evaluator returned unknown criteria: " + ", ".join(unknown)
            )
        normalized: list[CriterionEvaluation] = []
        for criterion in self.acceptance_criteria:
            result = supplied.get(criterion.criterion_id)
            if result is None:
                normalized.append(CriterionEvaluation(criterion_id=criterion.criterion_id))
                continue
            if result.accepted:
                evidence_kinds = {evidence.kind for evidence in result.evidence_refs}
                missing = sorted(set(criterion.required_evidence) - evidence_kinds)
                if missing:
                    raise InvalidTransitionError(
                        f"criterion {criterion.criterion_id} lacks required evidence kinds: "
                        + ", ".join(missing)
                    )
            normalized.append(result)
        return tuple(normalized)

    def _require_active(self) -> None:
        if self.status.terminal:
            raise InvalidTransitionError(f"workflow is terminal: {self.status.value}")

    def _require_phase(self, expected: WorkflowRunStatus) -> None:
        self._require_active()
        if self.status != expected:
            raise InvalidTransitionError(
                f"transition requires {expected.value}, current status is {self.status.value}"
            )

    def _require_artifact(
        self,
        scope: DynamicWorkflowScope,
        run_ref: str,
        occurred_at: datetime,
    ) -> None:
        self.scope.require_exact(scope)
        if run_ref != self.run_ref:
            raise InvalidTransitionError("artifact run_ref does not match durable state")
        timestamp = _utc(occurred_at)
        if timestamp < self.updated_at:
            raise InvalidTransitionError("artifact occurred_at precedes the durable state")

    def _usage_after(self, delta: UsageDelta, occurred_at: datetime) -> UsageTotals:
        reported = self.usage.add(delta)
        authoritative_elapsed = math.ceil(
            max(0.0, (_utc(occurred_at) - self.created_at).total_seconds())
        )
        return UsageTotals(
            elapsed_seconds=max(reported.elapsed_seconds, authoritative_elapsed),
            input_tokens=reported.input_tokens,
            output_tokens=reported.output_tokens,
            cost_microusd=reported.cost_microusd,
        )

    def _usage_budget_reason(
        self, usage: UsageTotals, occurred_at: datetime
    ) -> str | None:
        authoritative_elapsed = max(
            0.0, (_utc(occurred_at) - self.created_at).total_seconds()
        )
        if (
            authoritative_elapsed > self.limits.max_elapsed_seconds
            or usage.elapsed_seconds > self.limits.max_elapsed_seconds
        ):
            return "max_elapsed_seconds"
        if usage.tokens > self.limits.max_tokens:
            return "max_tokens"
        if usage.cost_microusd > self.limits.max_cost_microusd:
            return "max_cost_microusd"
        return None

    def _record_control(
        self,
        *,
        status: WorkflowRunStatus,
        reason: str,
        occurred_at: datetime,
    ) -> "DynamicWorkflowState":
        artifact_digest = _sha256(
            {
                "run_ref": self.run_ref,
                "scope": self.scope.model_dump(mode="json"),
                "status": status.value,
                "reason": reason,
                "occurred_at": occurred_at.isoformat(),
                "revision": self.revision + 1,
            }
        )
        return self._record(
            occurred_at=occurred_at,
            usage=self._usage_after(UsageDelta(), occurred_at),
            source=DynamicWorkflowRole.ORCHESTRATOR,
            target=DynamicWorkflowRole.ORCHESTRATOR,
            artifact_type="workflow_control",
            artifact_digest=artifact_digest,
            summary=reason,
            evidence_refs=(),
            status=status,
            terminal_reason=reason,
        )

    def _budget_terminal(
        self,
        reason: str,
        occurred_at: datetime,
        usage_delta: UsageDelta,
    ) -> "DynamicWorkflowState":
        return self._next(
            status=WorkflowRunStatus.BUDGET_EXHAUSTED,
            terminal_reason=reason,
            updated_at=_utc(occurred_at),
            usage=self._usage_after(usage_delta, occurred_at),
        )

    def _record(
        self,
        *,
        occurred_at: datetime,
        usage: UsageTotals,
        source: DynamicWorkflowRole,
        target: DynamicWorkflowRole,
        artifact_type: str,
        artifact_digest: str,
        summary: str,
        evidence_refs: tuple[EvidenceRef, ...],
        **updates: Any,
    ) -> "DynamicWorkflowState":
        handoff = DynamicWorkflowHandoff(
            scope=self.scope,
            run_ref=self.run_ref,
            sequence=len(self.handoffs) + 1,
            source_role=source,
            target_role=target,
            artifact_type=artifact_type,
            artifact_digest=artifact_digest,
            summary=summary,
            evidence_refs=evidence_refs,
            previous_digest=self.latest_handoff_digest,
            occurred_at=occurred_at,
        )
        new_bytes = self.handoff_bytes + handoff.byte_size
        if new_bytes > self.limits.max_handoff_bytes:
            return self._next(
                status=WorkflowRunStatus.BUDGET_EXHAUSTED,
                terminal_reason="max_handoff_bytes",
                updated_at=occurred_at,
                usage=usage,
            )
        updates.update(
            updated_at=occurred_at,
            usage=usage,
            handoffs=self.handoffs + (handoff,),
            handoff_bytes=new_bytes,
        )
        return self._next(**updates)

    def _next(self, **updates: Any) -> "DynamicWorkflowState":
        payload = self.model_dump(mode="python", by_alias=False)
        payload.update(updates)
        payload["revision"] = self.revision + 1
        return type(self).model_validate(payload)


__all__ = [
    "DYNAMIC_WORKFLOW_HANDOFF_SCHEMA",
    "DYNAMIC_WORKFLOW_STATE_SCHEMA",
    "AcceptanceCriterion",
    "BuilderAssignment",
    "BuilderOutcome",
    "BuilderResult",
    "CriterionEvaluation",
    "DynamicWorkflowError",
    "DynamicWorkflowHandoff",
    "DynamicWorkflowRole",
    "DynamicWorkflowScope",
    "DynamicWorkflowState",
    "EvaluatorDecision",
    "EvaluatorVerdict",
    "EvidenceRef",
    "InvalidTransitionError",
    "PlannerPlan",
    "ScopeMismatchError",
    "UsageDelta",
    "UsageTotals",
    "WorkflowLimits",
    "WorkflowRunStatus",
]
