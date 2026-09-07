"""Executable learning primitives for governed Lightbulb optimization workflows.

This module deliberately plans against the runtimes that the Spring Control
Plane already admits.  It does not launch trainers, reserve capacity, publish a
dataset, or promote a model.  The output is a deterministic, typed handoff for
the existing Project learning-run preparation and admission surfaces.
"""

from __future__ import annotations

import hashlib
import json
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from pydantic_core import PydanticCustomError

from lightbulb.primitive_runtime import (
    BusinessProcessPrimitive,
    PrimitiveBlocker,
    PrimitiveEvent,
    PrimitiveEvidence,
    PrimitiveExecutionContext,
    PrimitiveExecutionResult,
    PrimitiveExecutionStatus,
)
from lightbulb.project_learning_runs import (
    PROJECT_BILLABLE_LEARNING_RUNTIMES,
    PROJECT_CAPACITY_RUNTIMES,
    PROJECT_LEARNING_RUNTIMES,
)


OPTIMIZATION_SWEEP_PLAN_SCHEMA = "lightbulb.optimization_sweep_plan.v1"
LEARNING_EVENT_STREAM_CONTRACT_SCHEMA = (
    "lightbulb.learning_event_stream_contract.v1"
)

LearningRuntime = Literal[
    "automl",
    "spark_feature_matrix",
    "gepa_autoresearch",
    "pufferlib_v4",
    "prime_rl",
]
OptimizationTarget = Literal[
    "predictive_model",
    "numeric_control_policy",
    "llm_agent_policy",
    "hybrid_agent",
]
FeatureBackend = Literal["auto", "local", "spark"]
MetricDirection = Literal["maximize", "minimize"]

_MONEY_QUANTUM = Decimal("0.000001")
_SPARK_ROW_THRESHOLD = 250_000
_SPARK_FEATURE_THRESHOLD = 2_000
_SPARK_EVENT_RATE_THRESHOLD = 1_000


def _decimal6(value: Decimal) -> str:
    return format(value.quantize(_MONEY_QUANTUM), "f")


def _allocate_decimal(total: Decimal, count: int) -> list[Decimal]:
    if count <= 0:
        return []
    micros = int((total * 1_000_000).to_integral_exact())
    quotient, remainder = divmod(micros, count)
    return [
        Decimal(quotient + (1 if index < remainder else 0)) / Decimal(1_000_000)
        for index in range(count)
    ]


def _allocate_integer(total: int, count: int) -> list[int]:
    if count <= 0:
        return []
    quotient, remainder = divmod(total, count)
    return [
        quotient + (1 if index < remainder else 0)
        for index in range(count)
    ]


class LearningDataProfile(BaseModel):
    """Bounded scale signals used for local runtime selection."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    row_count: int = Field(default=0, ge=0, le=10_000_000_000_000)
    feature_count: int = Field(default=0, ge=0, le=10_000_000)
    events_per_second: int = Field(default=0, ge=0, le=10_000_000_000)
    streaming: bool = False
    event_time_available: bool = True


class OptimizationSweepBudget(BaseModel):
    """One total budget that the planner divides across selected runtimes."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_platform_cost_usd: Decimal = Field(
        default=Decimal("5.000000"),
        ge=0,
        le=1_000_000,
    )
    max_provider_cost_usd: Decimal = Field(
        default=Decimal("0.000000"),
        ge=0,
        le=1_000_000,
    )
    max_gpu_seconds: int = Field(default=3_600, ge=0, le=31_536_000)
    max_tokens: int = Field(default=100_000, ge=0, le=1_000_000_000_000)
    max_steps: int = Field(default=10_000, ge=1, le=1_000_000_000_000)
    max_attempts: int = Field(default=3, ge=1, le=10)
    lease_seconds: int = Field(default=300, ge=60, le=7_200)

    @field_validator("max_platform_cost_usd", "max_provider_cost_usd", mode="before")
    @classmethod
    def _finite_six_place_money(cls, value: Any) -> Decimal:
        try:
            parsed = Decimal(str(value))
        except (InvalidOperation, TypeError, ValueError) as exc:
            raise ValueError("cost budgets must be finite decimals") from exc
        if not parsed.is_finite() or parsed < 0:
            raise ValueError("cost budgets must be finite non-negative decimals")
        if parsed != parsed.quantize(_MONEY_QUANTUM):
            raise ValueError("cost budgets support at most six decimal places")
        return parsed


class PlanOptimizationSweepInput(BaseModel):
    """Business-level inputs; scope and credentials are intentionally absent."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    training_pack_receipt_id: UUID
    optimization_objective: str = Field(min_length=1, max_length=2_000)
    primary_metric: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$",
    )
    direction: MetricDirection = "maximize"
    target: OptimizationTarget = "predictive_model"
    data_profile: LearningDataProfile = Field(default_factory=LearningDataProfile)
    feature_backend: FeatureBackend = "auto"
    include_auto_research: bool = False
    include_feature_engineering: bool = True
    minimum_improvement: Decimal = Field(
        default=Decimal("0.010000"),
        gt=0,
        le=1,
    )
    budget: OptimizationSweepBudget = Field(default_factory=OptimizationSweepBudget)

    @field_validator("optimization_objective", "primary_metric", mode="before")
    @classmethod
    def _strip_text(cls, value: Any) -> Any:
        if not isinstance(value, str):
            return value
        stripped = value.strip()
        if not stripped:
            raise ValueError("text fields must not be blank")
        return stripped

    @field_validator("minimum_improvement", mode="before")
    @classmethod
    def _finite_six_place_improvement(cls, value: Any) -> Decimal:
        try:
            parsed = Decimal(str(value))
        except (InvalidOperation, TypeError, ValueError) as exc:
            raise ValueError("minimum_improvement must be a finite decimal") from exc
        if not parsed.is_finite() or parsed != parsed.quantize(_MONEY_QUANTUM):
            raise ValueError("minimum_improvement supports at most six decimal places")
        return parsed

    @model_validator(mode="after")
    def _require_event_time_for_stream_features(self) -> "PlanOptimizationSweepInput":
        if (
            self.include_feature_engineering
            and self.data_profile.streaming
            and not self.data_profile.event_time_available
        ):
            raise PydanticCustomError(
                "event_time_required",
                "streaming feature engineering requires event_time_available=true "
                "to preserve point-in-time correctness",
            )
        if (
            self.include_feature_engineering
            and self.feature_backend == "local"
            and (
                self.data_profile.streaming
                or self.data_profile.row_count >= _SPARK_ROW_THRESHOLD
                or self.data_profile.feature_count >= _SPARK_FEATURE_THRESHOLD
                or self.data_profile.events_per_second
                >= _SPARK_EVENT_RATE_THRESHOLD
            )
        ):
            raise PydanticCustomError(
                "local_feature_capacity_exceeded",
                "feature_backend=local exceeds the conservative local scale "
                "boundary; use feature_backend=auto or spark",
            )
        selected = _selected_runtimes(self)
        stage_count = len(selected)
        billable_count = sum(
            runtime in PROJECT_BILLABLE_LEARNING_RUNTIMES
            for _, runtime, _ in selected
        )
        platform_count = stage_count - billable_count
        if self.budget.max_steps < stage_count:
            raise PydanticCustomError(
                "step_budget_too_small",
                f"budget.max_steps must be at least the selected stage count "
                f"({stage_count})",
            )
        if (
            billable_count
            and self.budget.max_provider_cost_usd
            < _MONEY_QUANTUM * billable_count
        ):
            raise PydanticCustomError(
                "provider_budget_required",
                "budget.max_provider_cost_usd must provide a positive "
                "six-decimal allocation for every selected billable runtime",
            )
        if (
            platform_count
            and self.budget.max_platform_cost_usd
            < _MONEY_QUANTUM * platform_count
        ):
            raise PydanticCustomError(
                "platform_budget_required",
                "budget.max_platform_cost_usd must provide a positive "
                "six-decimal allocation for every selected platform runtime",
            )
        return self


class LearningRunPreparationPlan(BaseModel):
    """Exact arguments for ``prepare_project_learning_run`` minus authority."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    training_pack_receipt_id: UUID
    primary_metric: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$",
    )
    runtime: LearningRuntime
    direction: MetricDirection
    minimum_improvement: str
    max_cost_usd: str
    max_platform_cost_usd: str
    max_gpu_seconds: int = Field(ge=0, le=31_536_000)
    max_tokens: int = Field(ge=0, le=1_000_000_000_000)
    max_steps: int = Field(ge=1, le=1_000_000_000_000)
    max_attempts: int = Field(ge=1, le=10)
    lease_seconds: int = Field(ge=60, le=7_200)
    preemptible: bool

    @field_validator(
        "minimum_improvement",
        "max_cost_usd",
        "max_platform_cost_usd",
        mode="before",
    )
    @classmethod
    def _normalize_decimal_fields(cls, value: Any) -> str:
        try:
            parsed = Decimal(str(value))
        except (InvalidOperation, TypeError, ValueError) as exc:
            raise ValueError("budget values must be finite six-place decimals") from exc
        if (
            not parsed.is_finite()
            or parsed < 0
            or parsed > Decimal("1000000")
            or parsed != parsed.quantize(_MONEY_QUANTUM)
        ):
            raise ValueError("budget values must be finite six-place decimals")
        return _decimal6(parsed)

    @model_validator(mode="after")
    def _match_prepare_builder_cost_rules(self) -> "LearningRunPreparationPlan":
        improvement = Decimal(self.minimum_improvement)
        if improvement <= 0 or improvement > 1:
            raise ValueError("minimum_improvement must be greater than zero and at most one")
        provider_cost = Decimal(self.max_cost_usd)
        platform_cost = Decimal(self.max_platform_cost_usd)
        if (
            self.runtime in PROJECT_BILLABLE_LEARNING_RUNTIMES
            and provider_cost <= 0
        ):
            raise ValueError("billable runtimes require positive max_cost_usd")
        if (
            self.runtime not in PROJECT_BILLABLE_LEARNING_RUNTIMES
            and platform_cost <= 0
        ):
            raise ValueError(
                "platform runtimes require positive max_platform_cost_usd"
            )
        return self


class OptimizationSweepStage(BaseModel):
    """One independently prepared and admitted Project learning run."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    stage_id: str
    ordinal: int = Field(ge=1, le=10)
    capability: str
    runtime: LearningRuntime
    depends_on: list[str] = Field(default_factory=list)
    rationale: str
    preparation: LearningRunPreparationPlan
    capacity_runtime: Literal["automl", "spark", "prime", "puffer"]
    billable: bool
    provider_account_binding_required: bool
    operator_approval_required: bool
    preparation_confirmation_required: bool = True
    admission_confirmation_required: bool = True
    emits: list[str] = Field(default_factory=list)


class LearningEventStreamContract(BaseModel):
    """Spring receipt snapshot contract; it does not claim a Kafka stream."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_id: str = Field(
        default=LEARNING_EVENT_STREAM_CONTRACT_SCHEMA,
        alias="schema",
    )
    source_runtime: Literal["spring_project_learning_run_service"] = (
        "spring_project_learning_run_service"
    )
    transport: Literal["control_plane_event_ledger"] = (
        "control_plane_event_ledger"
    )
    kafka_projection_status: Literal["not_bound_by_this_planner"] = (
        "not_bound_by_this_planner"
    )
    delivery_semantics: Literal["bounded_latest_receipt_snapshot"] = (
        "bounded_latest_receipt_snapshot"
    )
    ordering: Literal["not_exposed_as_stream_order"] = (
        "not_exposed_as_stream_order"
    )
    deduplication: Literal["spring_tenant_scoped_idempotency_key"] = (
        "spring_tenant_scoped_idempotency_key"
    )
    cursor_available: Literal[False] = False
    complete_history_available: Literal[False] = False
    credentials_in_event_payload_allowed: bool = False
    events: list[str]


class OptimizationSweepResourceTotals(BaseModel):
    """Auditable totals for one multi-runtime sweep."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    platform_cost_usd: str
    provider_cost_usd: str
    gpu_seconds: int = Field(ge=0)
    tokens: int = Field(ge=0)
    steps: int = Field(ge=0)

    @field_validator("platform_cost_usd", "provider_cost_usd", mode="before")
    @classmethod
    def _normalize_money(cls, value: Any) -> str:
        try:
            parsed = Decimal(str(value))
        except (InvalidOperation, TypeError, ValueError) as exc:
            raise ValueError("cost totals must be finite six-place decimals") from exc
        if (
            not parsed.is_finite()
            or parsed < 0
            or parsed != parsed.quantize(_MONEY_QUANTUM)
        ):
            raise ValueError("cost totals must be finite six-place decimals")
        return _decimal6(parsed)


class OptimizationSweepBudgetLedger(BaseModel):
    """Requested, allocated, and deliberately unused resource caps."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    requested: OptimizationSweepResourceTotals
    allocated: OptimizationSweepResourceTotals
    unallocated: OptimizationSweepResourceTotals


class OptimizationSweepSafety(BaseModel):
    """Typed authority boundary for a locally compiled plan."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scope_verification: Literal["deferred_to_spring_prepare_and_admission"] = (
        "deferred_to_spring_prepare_and_admission"
    )
    training_pack_receipt_ownership_verified: bool = False
    rbac_verified: bool = False
    required_server_permissions: list[str] = Field(
        default_factory=lambda: [
            "automl.experiments.execute",
            "learning.runs.execute",
        ]
    )
    caller_supplied_tenant_or_company_scope_allowed: bool = False
    credentials_or_provider_secrets_accepted: bool = False
    dataset_publication_authorized: bool = False
    capacity_or_commercial_admission_authorized: bool = False
    training_execution_authorized: bool = False
    model_or_policy_promotion_authorized: bool = False
    production_action_authorized: bool = False
    each_stage_requires_fresh_server_validation: bool = True


class OptimizationSweepOutput(BaseModel):
    """Deterministic plan that grants no execution or promotion authority."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_id: str = Field(default=OPTIMIZATION_SWEEP_PLAN_SCHEMA, alias="schema")
    plan_digest: str
    objective: str
    training_pack_receipt_id: UUID
    primary_metric: str
    direction: MetricDirection
    target: OptimizationTarget
    feature_engineering_mode: Literal[
        "spark_feature_matrix",
        "automl_in_process",
        "training_pack_features",
        "not_requested",
    ]
    stages: list[OptimizationSweepStage]
    budget_ledger: OptimizationSweepBudgetLedger
    event_stream: LearningEventStreamContract
    next_actions: list[str]
    safety: OptimizationSweepSafety


def _spark_selected(inputs: PlanOptimizationSweepInput) -> bool:
    if not inputs.include_feature_engineering:
        return False
    if inputs.feature_backend == "spark":
        return True
    if inputs.feature_backend == "local":
        return False
    profile = inputs.data_profile
    return bool(
        profile.streaming
        or profile.row_count >= _SPARK_ROW_THRESHOLD
        or profile.feature_count >= _SPARK_FEATURE_THRESHOLD
        or profile.events_per_second >= _SPARK_EVENT_RATE_THRESHOLD
    )


def _selected_runtimes(
    inputs: PlanOptimizationSweepInput,
) -> list[tuple[str, LearningRuntime, str]]:
    selected: list[tuple[str, LearningRuntime, str]] = []
    if inputs.include_auto_research:
        selected.append(
            (
                "auto_research",
                "gepa_autoresearch",
                "Generate and evaluate bounded research hypotheses before model or policy work.",
            )
        )
    if _spark_selected(inputs):
        selected.append(
            (
                "distributed_feature_engineering",
                "spark_feature_matrix",
                "Materialize a point-in-time feature matrix without driver-side full collection.",
            )
        )
    if inputs.target in {"predictive_model", "hybrid_agent"}:
        selected.append(
            (
                "automated_model_selection",
                "automl",
                "Run bounded feature, algorithm, and hyperparameter selection against the locked metric.",
            )
        )
    if inputs.target in {"numeric_control_policy", "hybrid_agent"}:
        selected.append(
            (
                "numeric_policy_optimization",
                "pufferlib_v4",
                "Train a CUDA-capable numeric control policy in the isolated PufferLib lane.",
            )
        )
    if inputs.target in {"llm_agent_policy", "hybrid_agent"}:
        selected.append(
            (
                "llm_policy_optimization",
                "prime_rl",
                "Train and evaluate an LLM policy in the isolated PRIME-RL lane.",
            )
        )
    return selected


def _stage_allocations(
    selected: list[tuple[str, LearningRuntime, str]],
    budget: OptimizationSweepBudget,
) -> dict[LearningRuntime, dict[str, Any]]:
    platform = [
        runtime
        for _, runtime, _ in selected
        if runtime not in PROJECT_BILLABLE_LEARNING_RUNTIMES
    ]
    billable = [
        runtime
        for _, runtime, _ in selected
        if runtime in PROJECT_BILLABLE_LEARNING_RUNTIMES
    ]
    gpu = [runtime for _, runtime, _ in selected if runtime != "spark_feature_matrix"]
    token = [
        runtime
        for _, runtime, _ in selected
        if runtime in {"gepa_autoresearch", "prime_rl"}
    ]
    all_runtimes = [runtime for _, runtime, _ in selected]

    platform_costs = dict(
        zip(platform, _allocate_decimal(budget.max_platform_cost_usd, len(platform)))
    )
    provider_costs = dict(
        zip(billable, _allocate_decimal(budget.max_provider_cost_usd, len(billable)))
    )
    gpu_seconds = dict(
        zip(gpu, _allocate_integer(budget.max_gpu_seconds, len(gpu)))
    )
    tokens = dict(zip(token, _allocate_integer(budget.max_tokens, len(token))))
    steps = dict(
        zip(all_runtimes, _allocate_integer(budget.max_steps, len(all_runtimes)))
    )

    return {
        runtime: {
            "max_cost_usd": provider_costs.get(runtime, Decimal("0.000000")),
            "max_platform_cost_usd": platform_costs.get(
                runtime, Decimal("0.000000")
            ),
            "max_gpu_seconds": gpu_seconds.get(runtime, 0),
            "max_tokens": tokens.get(runtime, 0),
            "max_steps": steps[runtime],
        }
        for runtime in all_runtimes
    }


def compile_optimization_sweep(
    inputs: PlanOptimizationSweepInput | Dict[str, Any],
) -> OptimizationSweepOutput:
    """Compile a deterministic, non-authorizing multi-runtime learning plan."""

    parsed = (
        inputs
        if isinstance(inputs, PlanOptimizationSweepInput)
        else PlanOptimizationSweepInput.model_validate(inputs)
    )
    selected = _selected_runtimes(parsed)
    allocations = _stage_allocations(selected, parsed.budget)
    stages: list[OptimizationSweepStage] = []
    predecessor: str | None = None
    for ordinal, (capability, runtime, rationale) in enumerate(selected, start=1):
        if runtime not in PROJECT_LEARNING_RUNTIMES:
            raise ValueError(f"Unsupported Project learning runtime: {runtime}")
        stage_id = f"stage_{ordinal:02d}_{runtime}"
        allocation = allocations[runtime]
        stage = OptimizationSweepStage(
            stage_id=stage_id,
            ordinal=ordinal,
            capability=capability,
            runtime=runtime,
            depends_on=[predecessor] if predecessor else [],
            rationale=rationale,
            preparation=LearningRunPreparationPlan(
                training_pack_receipt_id=parsed.training_pack_receipt_id,
                primary_metric=parsed.primary_metric,
                runtime=runtime,
                direction=parsed.direction,
                minimum_improvement=_decimal6(parsed.minimum_improvement),
                max_cost_usd=_decimal6(allocation["max_cost_usd"]),
                max_platform_cost_usd=_decimal6(
                    allocation["max_platform_cost_usd"]
                ),
                max_gpu_seconds=allocation["max_gpu_seconds"],
                max_tokens=allocation["max_tokens"],
                max_steps=allocation["max_steps"],
                max_attempts=parsed.budget.max_attempts,
                lease_seconds=parsed.budget.lease_seconds,
                preemptible=runtime != "spark_feature_matrix",
            ),
            capacity_runtime=PROJECT_CAPACITY_RUNTIMES[runtime],
            billable=runtime in PROJECT_BILLABLE_LEARNING_RUNTIMES,
            provider_account_binding_required=(
                runtime in PROJECT_BILLABLE_LEARNING_RUNTIMES
            ),
            operator_approval_required=(
                runtime in PROJECT_BILLABLE_LEARNING_RUNTIMES
            ),
            emits=[
                "project.learning_run.requested",
                "project.learning_run.admitted",
                "project.learning_run.execution_observed",
            ],
        )
        stages.append(stage)
        predecessor = stage_id

    if _spark_selected(parsed):
        feature_mode = "spark_feature_matrix"
    elif not parsed.include_feature_engineering:
        feature_mode = "not_requested"
    elif any(stage.runtime == "automl" for stage in stages):
        feature_mode = "automl_in_process"
    else:
        feature_mode = "training_pack_features"

    allocated_platform = sum(
        (
            Decimal(stage.preparation.max_platform_cost_usd)
            for stage in stages
        ),
        Decimal("0"),
    )
    allocated_provider = sum(
        (Decimal(stage.preparation.max_cost_usd) for stage in stages),
        Decimal("0"),
    )
    allocated_gpu = sum(
        stage.preparation.max_gpu_seconds for stage in stages
    )
    allocated_tokens = sum(
        stage.preparation.max_tokens for stage in stages
    )
    allocated_steps = sum(stage.preparation.max_steps for stage in stages)
    budget_ledger = OptimizationSweepBudgetLedger(
        requested=OptimizationSweepResourceTotals(
            platform_cost_usd=parsed.budget.max_platform_cost_usd,
            provider_cost_usd=parsed.budget.max_provider_cost_usd,
            gpu_seconds=parsed.budget.max_gpu_seconds,
            tokens=parsed.budget.max_tokens,
            steps=parsed.budget.max_steps,
        ),
        allocated=OptimizationSweepResourceTotals(
            platform_cost_usd=allocated_platform,
            provider_cost_usd=allocated_provider,
            gpu_seconds=allocated_gpu,
            tokens=allocated_tokens,
            steps=allocated_steps,
        ),
        unallocated=OptimizationSweepResourceTotals(
            platform_cost_usd=(
                parsed.budget.max_platform_cost_usd - allocated_platform
            ),
            provider_cost_usd=(
                parsed.budget.max_provider_cost_usd - allocated_provider
            ),
            gpu_seconds=parsed.budget.max_gpu_seconds - allocated_gpu,
            tokens=parsed.budget.max_tokens - allocated_tokens,
            steps=parsed.budget.max_steps - allocated_steps,
        ),
    )
    event_stream = LearningEventStreamContract(
        events=list(
            dict.fromkeys(
                event
                for stage in stages
                for event in stage.emits
            )
        )
    )
    safety = OptimizationSweepSafety()
    payload = {
        "objective": parsed.optimization_objective,
        "training_pack_receipt_id": str(parsed.training_pack_receipt_id),
        "primary_metric": parsed.primary_metric,
        "direction": parsed.direction,
        "target": parsed.target,
        "feature_engineering_mode": feature_mode,
        "stages": [
            stage.model_dump(mode="json")
            for stage in stages
        ],
        "budget_ledger": budget_ledger.model_dump(mode="json"),
        "event_stream": event_stream.model_dump(mode="json", by_alias=True),
        "next_actions": [
            "Review the runtime selection and bounded budgets.",
            "Verify training-pack ownership and required RBAC in Spring.",
            "Prepare each selected Project learning run with explicit confirm_prepare=True.",
            "Obtain server capacity and commercial admission before confirm_admission=True.",
            "Bind the real control-plane events to Kafka only through a separately governed adapter.",
            "Keep independent evaluation, human admission, shadow update, and promotion separate.",
        ],
        "safety": safety.model_dump(mode="json"),
    }
    digest = hashlib.sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()
    return OptimizationSweepOutput(
        plan_digest=digest,
        **payload,
    )


class PlanOptimizationSweepPrimitive(
    BusinessProcessPrimitive[PlanOptimizationSweepInput, OptimizationSweepOutput]
):
    """Choose and budget existing learning runtimes without starting them."""

    primitive_ref = "learning.plan_optimization_sweep"
    version = "1.0.0"
    title = "Plan optimization sweep"
    description = (
        "Select and budget AutoResearch, Spark, AutoML, PufferLib, and PRIME-RL "
        "runs from a business objective and bounded data profile."
    )
    input_model = PlanOptimizationSweepInput
    output_model = OptimizationSweepOutput
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs = {
        "training_pack_receipt_id": "00000000-0000-4000-8000-000000000001",
        "optimization_objective": (
            "Improve renewal decisions without increasing customer risk."
        ),
        "primary_metric": "retained_revenue",
        "target": "hybrid_agent",
        "data_profile": {
            "row_count": 500_000,
            "feature_count": 320,
            "streaming": True,
        },
        "include_auto_research": True,
        "budget": {
            "max_platform_cost_usd": "10.000000",
            "max_provider_cost_usd": "60.000000",
        },
    }

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: PlanOptimizationSweepInput,
    ) -> PrimitiveExecutionResult[OptimizationSweepOutput]:
        output = compile_optimization_sweep(inputs)
        provider_budget_missing = [
            stage.runtime
            for stage in output.stages
            if stage.billable
            and Decimal(stage.preparation.max_cost_usd) <= Decimal("0")
        ]
        platform_budget_missing = [
            stage.runtime
            for stage in output.stages
            if not stage.billable
            and Decimal(stage.preparation.max_platform_cost_usd) <= Decimal("0")
        ]
        blockers: list[PrimitiveBlocker] = []
        if provider_budget_missing:
            blockers.append(
                PrimitiveBlocker(
                    code="provider_budget_required",
                    field="budget.max_provider_cost_usd",
                    message=(
                        "Every selected billable lane needs a positive bounded "
                        "provider-cost allocation before preparation: "
                        + ", ".join(provider_budget_missing)
                    ),
                )
            )
        if platform_budget_missing:
            blockers.append(
                PrimitiveBlocker(
                    code="platform_budget_required",
                    field="budget.max_platform_cost_usd",
                    message=(
                        "Every selected platform lane needs a positive bounded "
                        "platform-cost allocation before preparation: "
                        + ", ".join(platform_budget_missing)
                    ),
                )
            )
        status = (
            PrimitiveExecutionStatus.NEEDS_INPUT
            if blockers
            else PrimitiveExecutionStatus.COMPLETED
        )
        event_type = (
            "learning.optimization_sweep_needs_input"
            if blockers
            else "learning.optimization_sweep_planned"
        )
        return PrimitiveExecutionResult[OptimizationSweepOutput](
            status=status,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                "Optimization sweep needs a positive cost allocation for every "
                "selected runtime."
                if blockers
                else f"Optimization sweep planned across {len(output.stages)} runtime stage(s)."
            ),
            output=output,
            events=[
                PrimitiveEvent(
                    type=event_type,
                    payload={
                        "plan_digest": output.plan_digest,
                        "stage_count": len(output.stages),
                        "runtimes": [stage.runtime for stage in output.stages],
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="learning_runtime_selection",
                    summary=(
                        "Runtime selection and total-budget allocation were "
                        "compiled locally without starting a paid or durable run."
                    ),
                    labels=[stage.runtime for stage in output.stages],
                    refs={"plan_digest": output.plan_digest},
                )
            ],
            blockers=blockers,
        )


__all__ = [
    "LEARNING_EVENT_STREAM_CONTRACT_SCHEMA",
    "OPTIMIZATION_SWEEP_PLAN_SCHEMA",
    "LearningDataProfile",
    "LearningEventStreamContract",
    "LearningRunPreparationPlan",
    "OptimizationSweepBudgetLedger",
    "OptimizationSweepBudget",
    "OptimizationSweepOutput",
    "OptimizationSweepResourceTotals",
    "OptimizationSweepSafety",
    "OptimizationSweepStage",
    "PlanOptimizationSweepInput",
    "PlanOptimizationSweepPrimitive",
    "compile_optimization_sweep",
]
