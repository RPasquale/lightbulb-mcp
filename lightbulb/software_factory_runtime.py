"""Durable orchestration facades that join effects to measured feedback loops.

The lower-level materializers and observation runtime deliberately remain
independent.  This module is the production-facing join: a successful,
receipt-backed storefront launch deterministically schedules its post-action
measurement before returning.  Re-running after a process crash reuses the
connector idempotency keys and the content-addressed observation checkpoint.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Callable, Iterable, Literal, Mapping
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from lightbulb.connector_execution import ConnectorExecutor, ExecutionScope
from lightbulb.dynamic_workflows import DynamicWorkflowScope
from lightbulb.abandoned_recovery import (
    AbandonedRecoveryCase,
    AbandonedRecoveryPlan,
    AbandonedRecoveryRun,
    RecoveryContactReservation,
    RecoveryContactReservationAuthority,
    RecoveryDispatchAttestation,
    RecoveryResolvedSecrets,
    run_abandoned_revenue_recovery,
    schedule_abandoned_recovery_observation,
)
from lightbulb.gtm_materializer import ProductLaunchApprovalGrant
from lightbulb.gtm_primitives import (
    ExactScopeDigestProvider,
    OmnichannelProductLaunchPlan,
)
from lightbulb.gtm_shopify_launch import (
    LandingReadinessVerifier,
    ShopifyLaunchRunResult,
    run_shopify_product_launch,
)
from lightbulb.observation_runtime import (
    ObservationRunResult,
    ObservationRuntime,
    ObservationWorker,
)
from lightbulb.profit_materializer import ProfitActionApprovalGrant
from lightbulb.profit_workflow_execution import (
    ProfitWorkflowExecutionRun,
    run_profit_workflow_actions,
)
from lightbulb.profit_workflow_runtime import (
    ProfitActionExecutionReceipt,
    ProfitScopeKeyRing,
    ProfitWorkflowEvaluation,
    ProfitWorkflowPlan,
)


SOFTWARE_FACTORY_STOREFRONT_LOOP_RESULT_SCHEMA = (
    "lightbulb.software_factory_storefront_loop_result.v1"
)
SOFTWARE_FACTORY_RECOVERY_LOOP_RESULT_SCHEMA = (
    "lightbulb.software_factory_recovery_loop_result.v1"
)
SOFTWARE_FACTORY_PROFIT_LOOP_RESULT_SCHEMA = (
    "lightbulb.software_factory_profit_loop_result.v1"
)

StorefrontLoopStatus = Literal[
    "launch_incomplete",
    "observation_scheduled",
    "observation_schedule_blocked",
]
RecoveryLoopStatus = Literal[
    "recovery_incomplete",
    "observation_scheduled",
    "observation_schedule_blocked",
]
ProfitLoopStatus = Literal[
    "execution_incomplete",
    "observation_scheduled",
    "observation_schedule_blocked",
]


class _FrozenModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        revalidate_instances="always",
        serialize_by_alias=True,
        strict=True,
    )


class StorefrontObservationRoute(_FrozenModel):
    """Exact governed analytics route selected by the authenticated host."""

    provider: Literal["shopify", "google_analytics"] = "shopify"
    connector_account_ref: str = Field(min_length=1, max_length=200)
    tenant_connector_id: UUID
    expected_tool_version: int = Field(ge=1)
    expected_route_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    max_attempts: int = Field(default=3, ge=1, le=10)

    @field_validator("connector_account_ref")
    @classmethod
    def _visible_account(cls, value: str) -> str:
        clean = value.strip()
        if clean != value or any(ord(character) < 33 for character in clean):
            raise ValueError("connector_account_ref must contain visible characters")
        return clean


class ProfitObservationRoute(_FrozenModel):
    """Exact governed or host observation route for one profit workflow."""

    provider: Literal["shopify", "google_analytics", "host"]
    source_capability: str = Field(min_length=3, max_length=200)
    expected_tool_version: int = Field(ge=1)
    expected_route_digest: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    connector_account_ref: str | None = Field(default=None, max_length=200)
    tenant_connector_id: UUID | None = None
    max_attempts: int = Field(default=3, ge=1, le=10)

    @field_validator("source_capability")
    @classmethod
    def _capability(cls, value: str) -> str:
        clean = value.strip()
        if clean != value or "." not in clean or any(ord(item) < 33 for item in clean):
            raise ValueError("source_capability must be a visible dotted key")
        return clean

    @field_validator("connector_account_ref")
    @classmethod
    def _account(cls, value: str | None) -> str | None:
        if value is None:
            return None
        clean = value.strip()
        if clean != value or any(ord(item) < 33 for item in clean):
            raise ValueError("connector_account_ref must contain visible characters")
        return clean

    @model_validator(mode="after")
    def _custody(self) -> "ProfitObservationRoute":
        connector_route = self.provider != "host"
        coordinates = (
            self.connector_account_ref,
            self.tenant_connector_id,
            self.expected_route_digest,
        )
        if (connector_route and any(item is None for item in coordinates)) or (
            not connector_route and any(item is not None for item in coordinates)
        ):
            raise ValueError(
                "connector observations require account, tenant connector, and route "
                "custody; host observations require none"
            )
        return self


class StorefrontLaunchLoopResult(_FrozenModel):
    """One launch/resume result plus its durable observation commitment."""

    schema_id: Literal["lightbulb.software_factory_storefront_loop_result.v1"] = Field(
        default=SOFTWARE_FACTORY_STOREFRONT_LOOP_RESULT_SCHEMA,
        alias="schema",
    )
    status: StorefrontLoopStatus
    launch: ShopifyLaunchRunResult
    observation_job_ref: str | None = Field(default=None, max_length=200)
    observation_due_at: str | None = None
    observation_job_digest: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    scheduling_error_code: str | None = Field(default=None, max_length=120)
    summary: str = Field(min_length=1, max_length=1_000)

    @model_validator(mode="after")
    def _status_matches_commitment(self) -> "StorefrontLaunchLoopResult":
        scheduled = self.status == "observation_scheduled"
        if scheduled != all(
            value is not None
            for value in (
                self.observation_job_ref,
                self.observation_due_at,
                self.observation_job_digest,
            )
        ):
            raise ValueError(
                "scheduled loop requires a complete observation commitment"
            )
        if scheduled and not self.launch.storefront_ready:
            raise ValueError("only a storefront-ready launch may schedule observation")
        if self.status == "launch_incomplete" and self.launch.storefront_ready:
            raise ValueError("storefront-ready launch cannot be reported incomplete")
        if self.status == "observation_schedule_blocked" and (
            not self.launch.storefront_ready or self.scheduling_error_code is None
        ):
            raise ValueError(
                "blocked scheduling requires a ready launch and error code"
            )
        if self.status != "observation_schedule_blocked" and (
            self.scheduling_error_code is not None
        ):
            raise ValueError("only blocked scheduling may expose an error code")
        return self

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


class RecoveryLoopResult(_FrozenModel):
    """One recovery/resume result plus its durable observation commitment."""

    schema_id: Literal["lightbulb.software_factory_recovery_loop_result.v1"] = Field(
        default=SOFTWARE_FACTORY_RECOVERY_LOOP_RESULT_SCHEMA,
        alias="schema",
    )
    status: RecoveryLoopStatus
    recovery: AbandonedRecoveryRun
    observation_job_ref: str | None = Field(default=None, max_length=200)
    observation_due_at: str | None = None
    observation_job_digest: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    scheduling_error_code: str | None = Field(default=None, max_length=120)
    summary: str = Field(min_length=1, max_length=1_000)

    @model_validator(mode="after")
    def _status_matches_commitment(self) -> "RecoveryLoopResult":
        scheduled = self.status == "observation_scheduled"
        if scheduled != all(
            value is not None
            for value in (
                self.observation_job_ref,
                self.observation_due_at,
                self.observation_job_digest,
            )
        ):
            raise ValueError(
                "scheduled recovery loop requires a complete observation commitment"
            )
        completed = self.recovery.status == "completed"
        if scheduled and not completed:
            raise ValueError("only completed recovery may schedule observation")
        if self.status == "recovery_incomplete" and completed:
            raise ValueError("completed recovery cannot be reported incomplete")
        if self.status == "observation_schedule_blocked" and (
            not completed or self.scheduling_error_code is None
        ):
            raise ValueError(
                "blocked scheduling requires completed recovery and an error code"
            )
        if self.status != "observation_schedule_blocked" and (
            self.scheduling_error_code is not None
        ):
            raise ValueError("only blocked scheduling may expose an error code")
        return self

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


class ProfitWorkflowLoopResult(_FrozenModel):
    """One adjacent workflow execution plus its durable learning commitment."""

    schema_id: Literal["lightbulb.software_factory_profit_loop_result.v1"] = Field(
        default=SOFTWARE_FACTORY_PROFIT_LOOP_RESULT_SCHEMA,
        alias="schema",
    )
    status: ProfitLoopStatus
    execution: ProfitWorkflowExecutionRun
    observation_job_ref: str | None = Field(default=None, max_length=200)
    observation_due_at: str | None = None
    observation_job_digest: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    scheduling_error_code: str | None = Field(default=None, max_length=120)
    summary: str = Field(min_length=1, max_length=1_000)

    @model_validator(mode="after")
    def _status_matches_commitment(self) -> "ProfitWorkflowLoopResult":
        scheduled = self.status == "observation_scheduled"
        if scheduled != all(
            item is not None
            for item in (
                self.observation_job_ref,
                self.observation_due_at,
                self.observation_job_digest,
            )
        ):
            raise ValueError(
                "scheduled profit loop requires a complete observation commitment"
            )
        completed = self.execution.status == "completed"
        if scheduled and not completed:
            raise ValueError("only completed execution may schedule observation")
        if self.status == "execution_incomplete" and completed:
            raise ValueError("completed execution cannot be reported incomplete")
        if self.status == "observation_schedule_blocked" and (
            not completed or self.scheduling_error_code is None
        ):
            raise ValueError(
                "blocked scheduling requires completed execution and an error code"
            )
        if self.status != "observation_schedule_blocked" and (
            self.scheduling_error_code is not None
        ):
            raise ValueError("only blocked scheduling may expose an error code")
        return self

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


class LightbulbSoftwareFactoryRuntime:
    """Join governed launches, durable observation jobs, and a bounded worker."""

    def __init__(
        self,
        observation_runtime: ObservationRuntime,
        *,
        observation_worker: ObservationWorker | None = None,
    ) -> None:
        self.observation_runtime = observation_runtime
        self.observation_worker = observation_worker

    def run_storefront_launch(
        self,
        plan: OmnichannelProductLaunchPlan | Mapping[str, Any],
        *,
        scope: DynamicWorkflowScope | Mapping[str, Any],
        scope_keyring: ExactScopeDigestProvider,
        execution_scope: ExecutionScope | Mapping[str, Any],
        executor: ConnectorExecutor,
        route: StorefrontObservationRoute | Mapping[str, Any],
        run_ref: str,
        iteration: int = 1,
        preview_only: bool = True,
        approval_grants: Iterable[ProductLaunchApprovalGrant | Mapping[str, Any]] = (),
        readiness_verifier: LandingReadinessVerifier | None = None,
    ) -> StorefrontLaunchLoopResult:
        """Run/resume Shopify and schedule measurement on exact readiness.

        A crash between the external effect and this return is recovered by
        invoking the same method again: connector writes retain their stable
        idempotency keys and ``schedule_storefront_phase`` is content-addressed.
        """

        workflow_scope = (
            scope
            if isinstance(scope, DynamicWorkflowScope)
            else DynamicWorkflowScope.model_validate(scope)
        )
        runtime_scope = (
            execution_scope
            if isinstance(execution_scope, ExecutionScope)
            else ExecutionScope.model_validate(execution_scope)
        )
        observation_route = (
            route
            if isinstance(route, StorefrontObservationRoute)
            else StorefrontObservationRoute.model_validate(route)
        )
        launch = run_shopify_product_launch(
            plan,
            scope=workflow_scope,
            scope_keyring=scope_keyring,
            execution_scope=runtime_scope,
            executor=executor,
            run_ref=run_ref,
            iteration=iteration,
            preview_only=preview_only,
            approval_grants=approval_grants,
            readiness_verifier=readiness_verifier,
        )
        if not launch.storefront_ready:
            return StorefrontLaunchLoopResult(
                status="launch_incomplete",
                launch=launch,
                summary=(
                    "The launch remains previewed, approval-blocked, or failed; "
                    "no post-action observation was scheduled."
                ),
            )
        if runtime_scope.project_id is None:
            return StorefrontLaunchLoopResult(
                status="observation_schedule_blocked",
                launch=launch,
                scheduling_error_code="authenticated_project_uuid_missing",
                summary=(
                    "Shopify readiness was proven, but observation scheduling "
                    "requires the authenticated project UUID."
                ),
            )
        try:
            checkpoint = self.observation_runtime.schedule_storefront_phase(
                plan,
                storefront_receipts=launch.receipts,
                scope=workflow_scope,
                project_id=runtime_scope.project_id,
                tenant_connector_id=observation_route.tenant_connector_id,
                connector_account_ref=observation_route.connector_account_ref,
                provider=observation_route.provider,
                query_arguments={},
                expected_tool_version=observation_route.expected_tool_version,
                expected_route_digest=observation_route.expected_route_digest,
                run_ref=run_ref,
                iteration=iteration,
                max_attempts=observation_route.max_attempts,
            )
            job = checkpoint.workflow_inputs["observation_job"]
            if not isinstance(job, Mapping):
                raise ValueError("observation checkpoint omitted its sealed job")
            return StorefrontLaunchLoopResult(
                status="observation_scheduled",
                launch=launch,
                observation_job_ref=checkpoint.run_ref,
                observation_due_at=str(job["due_at"]),
                observation_job_digest=str(job["job_digest"]),
                summary=(
                    "The exact Shopify storefront is ready and its post-action "
                    "measurement/evaluator job is durably scheduled."
                ),
            )
        except (KeyError, TypeError, ValueError):
            return StorefrontLaunchLoopResult(
                status="observation_schedule_blocked",
                launch=launch,
                scheduling_error_code="observation_schedule_rejected",
                summary=(
                    "Shopify readiness remains receipt-backed, but the observation "
                    "contract rejected scheduling; rerun after correcting the route."
                ),
            )

    def run_abandoned_recovery(
        self,
        recovery_plan: AbandonedRecoveryPlan | Mapping[str, Any],
        case: AbandonedRecoveryCase | Mapping[str, Any],
        *,
        resolved_secrets: RecoveryResolvedSecrets | Mapping[str, Any],
        scope: DynamicWorkflowScope | Mapping[str, Any],
        scope_keyring: ProfitScopeKeyRing,
        execution_scope: ExecutionScope | Mapping[str, Any],
        executor: ConnectorExecutor,
        experiment_ref: str,
        run_ref: str,
        iteration: int = 1,
        preview_only: bool = True,
        dispatch_at: datetime | None = None,
        dispatch_attestation: RecoveryDispatchAttestation
        | Mapping[str, Any]
        | None = None,
        contact_reservation: RecoveryContactReservation
        | Mapping[str, Any]
        | None = None,
        contact_reservation_authority: RecoveryContactReservationAuthority
        | None = None,
        approval_grants: Mapping[
            str,
            ProfitActionApprovalGrant | Mapping[str, Any],
        ]
        | None = None,
        existing_receipts: Iterable[
            ProfitActionExecutionReceipt | Mapping[str, Any]
        ] = (),
        expected_reader_version: int = 1,
        previous_evaluation: ProfitWorkflowEvaluation | None = None,
    ) -> RecoveryLoopResult:
        """Run/resume recovery and schedule its holdout evaluation on completion."""

        workflow_scope = (
            scope
            if isinstance(scope, DynamicWorkflowScope)
            else DynamicWorkflowScope.model_validate(scope)
        )
        runtime_scope = (
            execution_scope
            if isinstance(execution_scope, ExecutionScope)
            else ExecutionScope.model_validate(execution_scope)
        )
        recovery = run_abandoned_revenue_recovery(
            recovery_plan,
            case,
            resolved_secrets=resolved_secrets,
            scope=workflow_scope,
            scope_keyring=scope_keyring,
            execution_scope=runtime_scope,
            executor=executor,
            run_ref=run_ref,
            iteration=iteration,
            preview_only=preview_only,
            dispatch_at=dispatch_at,
            dispatch_attestation=dispatch_attestation,
            contact_reservation=contact_reservation,
            contact_reservation_authority=contact_reservation_authority,
            approval_grants=approval_grants,
            existing_receipts=existing_receipts,
        )
        if recovery.status != "completed":
            return RecoveryLoopResult(
                status="recovery_incomplete",
                recovery=recovery,
                summary=(
                    "Recovery remains previewed, approval-blocked, or failed; "
                    "no holdout observation was scheduled."
                ),
            )
        if runtime_scope.project_id is None:
            return RecoveryLoopResult(
                status="observation_schedule_blocked",
                recovery=recovery,
                scheduling_error_code="authenticated_project_uuid_missing",
                summary=(
                    "Recovery completed, but observation scheduling requires the "
                    "authenticated project UUID."
                ),
            )
        try:
            checkpoint = schedule_abandoned_recovery_observation(
                recovery_plan,
                recovery,
                runtime=self.observation_runtime,
                scope=workflow_scope,
                project_id=runtime_scope.project_id,
                experiment_ref=experiment_ref,
                expected_reader_version=expected_reader_version,
                previous_evaluation=previous_evaluation,
            )
            job = checkpoint.workflow_inputs["observation_job"]
            if not isinstance(job, Mapping):
                raise ValueError("observation checkpoint omitted its sealed job")
            return RecoveryLoopResult(
                status="observation_scheduled",
                recovery=recovery,
                observation_job_ref=checkpoint.run_ref,
                observation_due_at=str(job["due_at"]),
                observation_job_digest=str(job["job_digest"]),
                summary=(
                    "The approved recovery graph completed and its randomized "
                    "holdout evaluator job is durably scheduled."
                ),
            )
        except (KeyError, TypeError, ValueError):
            return RecoveryLoopResult(
                status="observation_schedule_blocked",
                recovery=recovery,
                scheduling_error_code="observation_schedule_rejected",
                summary=(
                    "Recovery completion remains receipt-backed, but the "
                    "observation contract rejected scheduling."
                ),
            )

    def run_profit_workflow(
        self,
        plan: ProfitWorkflowPlan | Mapping[str, Any],
        *,
        scope: DynamicWorkflowScope | Mapping[str, Any],
        scope_keyring: ProfitScopeKeyRing,
        execution_scope: ExecutionScope | Mapping[str, Any],
        executor: ConnectorExecutor,
        connector_arguments: Mapping[str, Mapping[str, Any] | BaseModel],
        route: ProfitObservationRoute | Mapping[str, Any],
        run_ref: str,
        iteration: int = 1,
        preview_only: bool = True,
        approval_grants: Mapping[
            str,
            ProfitActionApprovalGrant | Mapping[str, Any],
        ]
        | None = None,
        existing_receipts: Iterable[
            ProfitActionExecutionReceipt | Mapping[str, Any]
        ] = (),
        query_arguments: Mapping[str, Any] | None = None,
        previous_evaluation: ProfitWorkflowEvaluation | None = None,
    ) -> ProfitWorkflowLoopResult:
        """Run/resume a materializable adjacent workflow and schedule learning."""

        workflow_scope = (
            scope
            if isinstance(scope, DynamicWorkflowScope)
            else DynamicWorkflowScope.model_validate(scope)
        )
        runtime_scope = (
            execution_scope
            if isinstance(execution_scope, ExecutionScope)
            else ExecutionScope.model_validate(execution_scope)
        )
        observation_route = (
            route
            if isinstance(route, ProfitObservationRoute)
            else ProfitObservationRoute.model_validate(route)
        )
        execution = run_profit_workflow_actions(
            plan,
            scope=workflow_scope,
            scope_keyring=scope_keyring,
            execution_scope=runtime_scope,
            executor=executor,
            connector_arguments=connector_arguments,
            run_ref=run_ref,
            iteration=iteration,
            preview_only=preview_only,
            approval_grants=approval_grants,
            existing_receipts=existing_receipts,
        )
        if execution.status != "completed":
            return ProfitWorkflowLoopResult(
                status="execution_incomplete",
                execution=execution,
                summary=(
                    "The adjacent workflow remains previewed, approval-blocked, "
                    "or failed; no outcome observation was scheduled."
                ),
            )
        if runtime_scope.project_id is None:
            return ProfitWorkflowLoopResult(
                status="observation_schedule_blocked",
                execution=execution,
                scheduling_error_code="authenticated_project_uuid_missing",
                summary=(
                    "The action graph completed, but observation scheduling "
                    "requires the authenticated project UUID."
                ),
            )
        try:
            checkpoint = self.observation_runtime.schedule_profit(
                plan,
                action_receipts=execution.receipts,
                scope=workflow_scope,
                project_id=runtime_scope.project_id,
                provider=observation_route.provider,
                tenant_connector_id=observation_route.tenant_connector_id,
                connector_account_ref=observation_route.connector_account_ref,
                source_capability=observation_route.source_capability,
                query_arguments=dict(query_arguments or {}),
                expected_tool_version=observation_route.expected_tool_version,
                expected_route_digest=observation_route.expected_route_digest,
                run_ref=run_ref,
                iteration=iteration,
                previous_evaluation=previous_evaluation,
                max_attempts=observation_route.max_attempts,
            )
            job = checkpoint.workflow_inputs["observation_job"]
            if not isinstance(job, Mapping):
                raise ValueError("observation checkpoint omitted its sealed job")
            return ProfitWorkflowLoopResult(
                status="observation_scheduled",
                execution=execution,
                observation_job_ref=checkpoint.run_ref,
                observation_due_at=str(job["due_at"]),
                observation_job_digest=str(job["job_digest"]),
                summary=(
                    "The approved adjacent action graph completed and its exact "
                    "profit evaluator job is durably scheduled."
                ),
            )
        except (KeyError, TypeError, ValueError):
            return ProfitWorkflowLoopResult(
                status="observation_schedule_blocked",
                execution=execution,
                scheduling_error_code="observation_schedule_rejected",
                summary=(
                    "Action completion remains receipt-backed, but the observation "
                    "contract rejected scheduling."
                ),
            )

    def run_due_observations(
        self, *, now: datetime | None = None
    ) -> tuple[ObservationRunResult, ...]:
        if self.observation_worker is None:
            raise ValueError("software factory runtime has no observation worker")
        return self.observation_worker.run_once(now=now)

    def serve_observations(
        self,
        *,
        stop_requested: Callable[[], bool],
        max_cycles: int | None = None,
    ) -> int:
        """Run the bounded durable worker in an application-owned process."""

        if self.observation_worker is None:
            raise ValueError("software factory runtime has no observation worker")
        if not callable(stop_requested):
            raise ValueError("stop_requested must be callable")
        return self.observation_worker.serve(
            stop_requested=stop_requested,
            max_cycles=max_cycles,
        )


__all__ = [
    "SOFTWARE_FACTORY_PROFIT_LOOP_RESULT_SCHEMA",
    "SOFTWARE_FACTORY_RECOVERY_LOOP_RESULT_SCHEMA",
    "SOFTWARE_FACTORY_STOREFRONT_LOOP_RESULT_SCHEMA",
    "LightbulbSoftwareFactoryRuntime",
    "ProfitLoopStatus",
    "ProfitObservationRoute",
    "ProfitWorkflowLoopResult",
    "RecoveryLoopResult",
    "RecoveryLoopStatus",
    "StorefrontLaunchLoopResult",
    "StorefrontLoopStatus",
    "StorefrontObservationRoute",
]
