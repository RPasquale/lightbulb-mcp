"""Resumable trusted-host runner for materializable profit workflow actions.

The ten profit primitives remain proposal-only.  This module is the reusable
execution rail for the subset of their actions that have closed connector
argument models in :mod:`lightbulb.profit_materializer`.  It validates the
entire graph before the first dispatch, executes in signed dependency order,
stops at the first approval wait or failure, and resumes only from verified
action receipts.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Literal, Mapping

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from lightbulb.connector_execution import ConnectorExecutor, ExecutionScope
from lightbulb.dynamic_workflows import DynamicWorkflowScope
from lightbulb.profit_materializer import (
    ProfitActionApprovalGrant,
    ProfitActionMaterializationResult,
    materialize_profit_action,
)
from lightbulb.profit_workflow_blueprints import ProfitScopeKeyRing
from lightbulb.profit_workflow_runtime import (
    ProfitActionExecutionReceipt,
    ProfitWorkflowPlan,
    verify_profit_action_execution_receipt,
    verify_profit_workflow_plan,
)


PROFIT_WORKFLOW_EXECUTION_RUN_SCHEMA = "lightbulb.profit_workflow_execution_run.v1"

ProfitWorkflowExecutionStatus = Literal[
    "preview",
    "pending_approval",
    "completed",
    "blocked",
    "failed",
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


class ProfitWorkflowExecutionRun(_StrictModel):
    """Bounded result of one preview, execution, or receipt-backed resume."""

    schema_id: Literal["lightbulb.profit_workflow_execution_run.v1"] = Field(
        default=PROFIT_WORKFLOW_EXECUTION_RUN_SCHEMA,
        alias="schema",
    )
    status: ProfitWorkflowExecutionStatus
    workflow_id: str
    plan_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    run_ref: str
    iteration: int = Field(ge=1, le=4)
    action_results: tuple[ProfitActionMaterializationResult, ...] = Field(
        default_factory=tuple,
        max_length=10,
    )
    receipts: tuple[ProfitActionExecutionReceipt, ...] = Field(
        default_factory=tuple,
        max_length=10,
    )
    observation_not_before: str | None = None
    causal_claim_ready: Literal[False] = False
    summary: str = Field(min_length=1, max_length=1_000)

    @field_validator("action_results", "receipts", mode="before")
    @classmethod
    def _immutable_sequences(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("observation_not_before")
    @classmethod
    def _timestamp(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except (AttributeError, ValueError) as exc:
            raise ValueError("observation_not_before must be ISO-8601") from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("observation_not_before must include a UTC offset")
        return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    @model_validator(mode="after")
    def _status_contract(self) -> "ProfitWorkflowExecutionRun":
        if self.status == "completed":
            if not self.receipts or self.observation_not_before is None:
                raise ValueError(
                    "completed execution requires every receipt and an observation time"
                )
        elif self.observation_not_before is not None:
            raise ValueError(
                "incomplete execution cannot schedule post-action observation"
            )
        if self.status == "preview" and self.receipts:
            raise ValueError("preview execution cannot contain effect receipts")
        refs = [item.operation_ref for item in self.receipts]
        if len(refs) != len(set(refs)):
            raise ValueError("execution receipts must have unique operation refs")
        return self


def _scope(
    value: DynamicWorkflowScope | Mapping[str, Any],
) -> DynamicWorkflowScope:
    return (
        value
        if isinstance(value, DynamicWorkflowScope)
        else DynamicWorkflowScope.model_validate(value)
    )


def _receipt_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _validate_existing_receipt_graph(
    plan: ProfitWorkflowPlan,
    receipts: Mapping[str, ProfitActionExecutionReceipt],
) -> None:
    """Reject replay evidence that could not be a valid partial graph."""

    analysis_at = _receipt_time(plan.analysis_as_of)
    for action in plan.actions:
        receipt = receipts.get(action.operation_ref)
        if receipt is None:
            continue
        completed_at = _receipt_time(receipt.completed_at)
        if completed_at <= analysis_at:
            raise ValueError(
                "existing action receipt completion must follow the authenticated plan"
            )
        missing_dependencies = set(action.depends_on).difference(receipts)
        if missing_dependencies:
            raise ValueError(
                "existing action receipts must include every completed action dependency"
            )
        if any(
            completed_at < _receipt_time(receipts[dependency].completed_at)
            for dependency in action.depends_on
        ):
            raise ValueError(
                "existing action receipt completion must follow its dependencies"
            )


def run_profit_workflow_actions(
    plan_value: ProfitWorkflowPlan | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ProfitScopeKeyRing,
    execution_scope: ExecutionScope | Mapping[str, Any],
    executor: ConnectorExecutor,
    connector_arguments: Mapping[str, Mapping[str, Any] | BaseModel],
    run_ref: str,
    iteration: int = 1,
    preview_only: bool = True,
    approval_grants: Mapping[
        str,
        ProfitActionApprovalGrant | Mapping[str, Any],
    ]
    | None = None,
    existing_receipts: Iterable[ProfitActionExecutionReceipt | Mapping[str, Any]] = (),
) -> ProfitWorkflowExecutionRun:
    """Run every materializable connector action until a safe terminal state."""

    workflow_scope = _scope(scope)
    plan = verify_profit_workflow_plan(
        plan_value,
        scope=workflow_scope,
        scope_keyring=scope_keyring,
    )
    if plan.workflow_id == "commerce.recover_abandoned_revenue":
        raise ValueError(
            "abandoned-revenue actions require run_abandoned_revenue_recovery "
            "and a fresh dispatch safety attestation"
        )
    if not plan.actions:
        raise ValueError("profit workflow has no selected action to materialize")
    operation_refs = {item.operation_ref for item in plan.actions}
    if set(connector_arguments) != operation_refs:
        raise ValueError(
            "connector_arguments must contain exactly one payload per planned action"
        )
    grants = dict(approval_grants or {})
    if not set(grants).issubset(operation_refs):
        raise ValueError("approval_grants contains an unknown operation")

    receipts: dict[str, ProfitActionExecutionReceipt] = {}
    for raw_receipt in existing_receipts:
        if len(receipts) >= len(plan.actions):
            raise ValueError("too many existing action receipts")
        receipt = verify_profit_action_execution_receipt(
            raw_receipt,
            plan=plan,
            scope=workflow_scope,
            scope_keyring=scope_keyring,
        )
        if receipt.run_ref != run_ref or receipt.iteration != iteration:
            raise ValueError("existing action receipt run or iteration mismatch")
        if receipt.operation_ref in receipts:
            raise ValueError("existing action receipts must be unique")
        receipts[receipt.operation_ref] = receipt
    if not set(receipts).issubset(operation_refs):
        raise ValueError("existing action receipt names an unknown operation")
    _validate_existing_receipt_graph(plan, receipts)

    # Validate every payload and materializer adapter before the first live call.
    previews = tuple(
        materialize_profit_action(
            plan,
            scope=workflow_scope,
            scope_keyring=scope_keyring,
            execution_scope=execution_scope,
            executor=executor,
            operation_ref=action.operation_ref,
            connector_arguments=connector_arguments[action.operation_ref],
            run_ref=run_ref,
            iteration=iteration,
            preview_only=True,
            approval_grant=grants.get(action.operation_ref),
        )
        for action in plan.actions
    )
    if preview_only:
        return ProfitWorkflowExecutionRun(
            status="preview",
            workflow_id=plan.workflow_id,
            plan_digest=plan.plan_digest,
            run_ref=run_ref,
            iteration=iteration,
            action_results=previews,
            summary=(
                "Validated the complete materializable action graph; preview made "
                "zero connector calls."
            ),
        )

    results: list[ProfitActionMaterializationResult] = []
    terminal: ProfitWorkflowExecutionStatus = "completed"
    for action in plan.actions:
        if action.operation_ref in receipts:
            continue
        dependencies = tuple(
            receipts[dependency]
            for dependency in action.depends_on
            if dependency in receipts
        )
        result = materialize_profit_action(
            plan,
            scope=workflow_scope,
            scope_keyring=scope_keyring,
            execution_scope=execution_scope,
            executor=executor,
            operation_ref=action.operation_ref,
            connector_arguments=connector_arguments[action.operation_ref],
            run_ref=run_ref,
            iteration=iteration,
            preview_only=False,
            approval_grant=grants.get(action.operation_ref),
            dependency_receipts=dependencies,
        )
        results.append(result)
        if result.status == "completed" and result.receipt is not None:
            receipts[action.operation_ref] = result.receipt
            continue
        terminal = result.status
        break

    if terminal != "completed" or set(receipts) != operation_refs:
        return ProfitWorkflowExecutionRun(
            status=terminal,
            workflow_id=plan.workflow_id,
            plan_digest=plan.plan_digest,
            run_ref=run_ref,
            iteration=iteration,
            action_results=tuple(results),
            receipts=tuple(
                receipts[action.operation_ref]
                for action in plan.actions
                if action.operation_ref in receipts
            ),
            summary="Execution paused before the complete action graph finished.",
        )

    ordered_receipts = tuple(receipts[item.operation_ref] for item in plan.actions)
    latest_completion = max(
        datetime.fromisoformat(item.completed_at.replace("Z", "+00:00"))
        for item in ordered_receipts
    )
    not_before = latest_completion + timedelta(
        hours=plan.evaluation_loop.measurement_window_hours
    )
    return ProfitWorkflowExecutionRun(
        status="completed",
        workflow_id=plan.workflow_id,
        plan_digest=plan.plan_digest,
        run_ref=run_ref,
        iteration=iteration,
        action_results=tuple(results),
        receipts=ordered_receipts,
        observation_not_before=(
            not_before.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        ),
        summary=(
            "Completed the approved action graph. Outcome claims remain blocked "
            "until the trusted observation runtime evaluates the full window."
        ),
    )


__all__ = [
    "PROFIT_WORKFLOW_EXECUTION_RUN_SCHEMA",
    "ProfitWorkflowExecutionRun",
    "ProfitWorkflowExecutionStatus",
    "run_profit_workflow_actions",
]
