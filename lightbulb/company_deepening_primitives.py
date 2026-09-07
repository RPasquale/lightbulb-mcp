"""Executable primitives for the company runtime deepening: observation jobs, portfolio, plan migration, metering.

All four are previews: they compute sealed plans, assessments, proofs, and
receipts from inputs the caller already holds, and execute nothing.  The
platform performs the reads, persists the migrated state behind its own
fence, and records the worker outcome through the engine runtime.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import Field, field_validator

from lightbulb.company_cadence_primitives import example_cadence_inputs
from lightbulb.company_cadence_runner import CadenceBundle, CadenceTickPlan, plan_cadence_tick
from lightbulb.company_dispatch_metering import MeteredDispatch, MeteringError, meter_dispatch, outcome_receipt
from lightbulb.company_engine_core import BoundedText, OpaqueRef, ShortText, StrictModel, timestamp
from lightbulb.company_engine_primitives_base import EXAMPLE_ACTOR, EXAMPLE_SCOPE, EnginePrimitive, LazyExample, RequestScope, read_spec, request_digest, scope_matches
from lightbulb.company_observation_jobs import OBSERVATION_SOURCES, ObservationJobPlan, plan_observation_jobs
from lightbulb.company_operating_system import COMPANY_OS_GOLDEN_LOOP, compile_company_operating_blueprint
from lightbulb.company_plan_migration import ENGINE_LIFECYCLES, MigrationRefused, PlanMigration, lifecycle_for, migrate_state
from lightbulb.company_portfolio import CompanyPortfolioInput, PortfolioAssessment, assess_portfolio
from lightbulb.company_workforce import compile_workforce, standard_roster
from lightbulb.primitive_runtime import BusinessProcessPrimitive, PrimitiveExecutionContext, PrimitiveExecutionResult

DEEPENING_STAGES: tuple[str, ...] = ("plan_reads", "assess_portfolio", "migrate_plan", "meter_dispatch")
_PROFILES = ("b2b_saas", "dtc_commerce", "services_firm", "marketplace")


class _Examples:
    def __init__(self) -> None:
        self._built: dict[str, Any] | None = None

    def get(self) -> dict[str, Any]:
        if self._built is not None:
            return self._built
        cadence = example_cadence_inputs()["plan"]
        bundle = CadenceBundle.model_validate(cadence["bundle"])
        tick = plan_cadence_tick(bundle, {engine: list(records) for engine, records in cadence["states"].items()}, now=cadence["now"])
        operating = compile_company_operating_blueprint("b2b_saas")
        workforce = compile_workforce(operating, standard_roster("b2b_saas"))
        revised = compile_company_operating_blueprint("b2b_saas", {"operating_budget_per_period": "36000"})
        self._built = {
            "observe": {"scope": EXAMPLE_SCOPE, "requested_by_ref": EXAMPLE_ACTOR, "bundle": bundle.to_dict(), "tick_plan": tick.to_dict(), "window_start": bundle.start_at, "window_end": None},
            "portfolio": {"scope": EXAMPLE_SCOPE, "requested_by_ref": EXAMPLE_ACTOR, "assessed_at": cadence["now"], "companies": [{"company_ref": "maple", "name": "Maple SaaS", "operating_plan": operating.to_dict(), "workforce_plan": workforce.to_dict(), "cadence_status": "running", "cash_on_hand": "400000", "monthly_burn": "20000"}]},
            "migrate": {"scope": EXAMPLE_SCOPE, "requested_by_ref": EXAMPLE_ACTOR, "engine": "company_operating_system", "state": _example_period_state(operating), "from_plan": operating.to_dict(), "to_plan": revised.to_dict(), "migrated_at": "2026-10-07T00:00:00Z", "reason": "board raised the operating envelope"},
            "meter": {"scope": EXAMPLE_SCOPE, "requested_by_ref": EXAMPLE_ACTOR, "dispatch_ref": "trace:7d1f0a52-4d1e-4a2b-9f5e-1c2d3e4f5a6b", "instance": {"traceId": "7d1f0a52-4d1e-4a2b-9f5e-1c2d3e4f5a6b", "status": "COMPLETED", "completedAt": "2026-10-06T01:30:00", "telemetry": {"cost": 0.4321, "stepCount": 3}}, "currency": "CAD", "usd_rate": "1.36"},
        }
        return self._built


def _example_period_state(plan: Any) -> dict[str, Any]:
    from lightbulb.company_operating_system import open_period

    scope = {**EXAMPLE_SCOPE, "entity_ref": "period-example-1", "currency": plan.blueprint.currency}
    return open_period(plan, scope, period_start="2026-10-05T00:00:00Z", opened_at="2026-10-05T00:00:00Z", actor_ref=EXAMPLE_ACTOR).to_dict()


_EXAMPLES = _Examples()


def example_deepening_inputs() -> dict[str, Any]:
    return {key: dict(value) for key, value in _EXAMPLES.get().items()}


# --------------------------------------------------------------------------- #
# company.plan_observation_jobs
# --------------------------------------------------------------------------- #


class PlanObservationJobsInput(StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    bundle: CadenceBundle
    tick_plan: CadenceTickPlan
    window_start: str
    window_end: str | None = None

    @field_validator("window_start")
    @classmethod
    def _start(cls, value: str) -> str:
        return timestamp(value, field_name="window_start")

    @field_validator("window_end")
    @classmethod
    def _end(cls, value: str | None) -> str | None:
        return None if value is None else timestamp(value, field_name="window_end")


class PlanObservationJobsPrimitive(EnginePrimitive[Any, Any]):
    primitive_ref = "company.plan_observation_jobs"
    version = "0.1.0"
    title = "Plan the platform reads that satisfy a cadence tick's evidence"
    description = "Turn one cadence tick plan into the exact reads (tool, lane, arguments, window, adapter) that would satisfy its collect_evidence items and feed the bundle's engines; the lane comes from the governed-read allowlist and nothing is executed."
    input_model = PlanObservationJobsInput
    output_model = ObservationJobPlan
    risk_level = "low"
    operation_spec = read_spec("company_plan_observation_jobs", "sdk.company.plan_observation_jobs")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "observe")
    golden_loop = COMPANY_OS_GOLDEN_LOOP
    engine = "company_operating_system"
    loop_stages = DEEPENING_STAGES
    profiles = _PROFILES
    observation_tools = tuple(sorted(OBSERVATION_SOURCES))  # planned reads; the pack stays read-only with no connector tools bound
    hard_rules = {"lane_from_governed_allowlist": True, "reads_planned_never_executed": True, "one_job_per_evidence_item": True, "spend_supplied_with_receipt": True}
    authority_boundary = {"agent": "performs host-lane reads and hands back provenance", "sdk": "plans reads and converts receipts", "spring": "executes governed reads and journals them", "connectors": "Stripe, Shopify, Google Analytics, PostHog, GitHub reads", "mcp": "projects this primitive"}

    def _execute(self, context: PrimitiveExecutionContext, inputs: PlanObservationJobsInput) -> PrimitiveExecutionResult[ObservationJobPlan]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            plan = plan_observation_jobs(inputs.bundle, inputs.tick_plan, window_start=inputs.window_start, window_end=inputs.window_end)
        except ValueError as exc:
            return self.blocked(digest=digest, code="JOB_PLAN_INVALID", message=str(exc))
        return self.preview(output=plan, digest=digest, external_refs={"job_plan_digest": plan.plan_digest, "tick_plan_digest": plan.tick_plan_digest}, event_type="company.observation_jobs_planned", event_payload={"jobs": len(plan.jobs), "governed": len(plan.governed), "host": len(plan.host), "unsupported": len(plan.unsupported)}, evidence_kind="company_observation_job_plan", evidence_summary="Reads planned; none executed.", summary=f"{len(plan.jobs)} read(s) planned ({len(plan.governed)} governed, {len(plan.host)} host lane) for window {plan.window_start} to {plan.window_end}.")


# --------------------------------------------------------------------------- #
# company.assess_portfolio
# --------------------------------------------------------------------------- #


class AssessPortfolioInput(StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    companies: tuple[CompanyPortfolioInput, ...] = Field(min_length=1, max_length=60)
    assessed_at: str

    @field_validator("companies", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("assessed_at")
    @classmethod
    def _assessed(cls, value: str) -> str:
        return timestamp(value, field_name="assessed_at")


class AssessPortfolioPrimitive(EnginePrimitive[Any, Any]):
    primitive_ref = "company.assess_portfolio"
    version = "0.1.0"
    title = "Assess and rank every company an operator runs"
    description = "Assess each company's health, cadence, periods, approvals, workforce cost, and latest simulation from sealed inputs, and rank the portfolio by attention with a cited reason for every score; reads nothing and decides nothing."
    input_model = AssessPortfolioInput
    output_model = PortfolioAssessment
    risk_level = "low"
    operation_spec = read_spec("company_assess_portfolio", "sdk.company.assess_portfolio")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "portfolio")
    golden_loop = COMPANY_OS_GOLDEN_LOOP
    engine = "company_operating_system"
    loop_stages = DEEPENING_STAGES
    profiles = _PROFILES
    hard_rules = {"every_reason_cites_a_sealed_input": True, "deterministic_ranking": True, "no_execution_or_decision": True}
    authority_boundary = {"agent": "gathers the sealed inputs", "sdk": "assesses and ranks", "spring": "holds the states, inbox, and approvals", "connectors": "none", "mcp": "projects this primitive"}

    def _execute(self, context: PrimitiveExecutionContext, inputs: AssessPortfolioInput) -> PrimitiveExecutionResult[PortfolioAssessment]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            assessment = assess_portfolio(inputs.companies, assessed_at=inputs.assessed_at)
        except ValueError as exc:
            return self.blocked(digest=digest, code="PORTFOLIO_INVALID", message=str(exc))
        top = assessment.entry(assessment.ranked[0])
        assert top is not None
        return self.preview(output=assessment, digest=digest, external_refs={"assessment_digest": assessment.assessment_digest}, event_type="company.portfolio_assessed", event_payload={"companies": assessment.companies, "ranked": list(assessment.ranked), "reasons_by_code": dict(assessment.reasons_by_code)}, evidence_kind="company_portfolio_assessment", evidence_summary="Ranked assessment; nothing decided.", summary=f"{assessment.companies} company(ies) assessed; {assessment.ranked[0]} needs attention first (score {top.attention_score}); {len(assessment.quiet)} quiet.")


# --------------------------------------------------------------------------- #
# company.preview_plan_migration
# --------------------------------------------------------------------------- #


class PreviewPlanMigrationInput(StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    engine: ShortText
    state: dict[str, Any]
    from_plan: dict[str, Any]
    to_plan: dict[str, Any]
    migrated_at: str
    reason: BoundedText

    @field_validator("engine")
    @classmethod
    def _engine(cls, value: str) -> str:
        if value not in ENGINE_LIFECYCLES:
            raise ValueError(f"engine must be one of {sorted(ENGINE_LIFECYCLES)}")
        return value

    @field_validator("migrated_at")
    @classmethod
    def _migrated(cls, value: str) -> str:
        return timestamp(value, field_name="migrated_at")


class PreviewPlanMigrationPrimitive(EnginePrimitive[Any, Any]):
    primitive_ref = "company.preview_plan_migration"
    version = "0.1.0"
    title = "Replay an in-flight engine state under a revised plan and prove the migration"
    description = "Replay every retained transition of one engine state under a revised plan through the engine's own step function; return the sealed migration proof when the history survives, or the exact rejection and version when it does not. Nothing is persisted here; the store's migration fence accepts the proof."
    input_model = PreviewPlanMigrationInput
    output_model = PlanMigration
    risk_level = "medium"
    operation_spec = read_spec("company_preview_plan_migration", "sdk.company.preview_plan_migration")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "migrate")
    golden_loop = COMPANY_OS_GOLDEN_LOOP
    engine = "company_operating_system"
    loop_stages = DEEPENING_STAGES
    profiles = _PROFILES
    hard_rules = {"full_history_replayed_under_new_plan": True, "first_refusal_aborts": True, "version_and_status_preserved": True, "persist_only_with_proof": True}
    authority_boundary = {"agent": "proposes the revised plan", "sdk": "replays and proves", "spring": "admits the migrated state behind the proof fence", "connectors": "none", "mcp": "projects this primitive"}

    def _execute(self, context: PrimitiveExecutionContext, inputs: PreviewPlanMigrationInput) -> PrimitiveExecutionResult[PlanMigration]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        lifecycle = lifecycle_for(inputs.engine)
        try:
            result = migrate_state(lifecycle.spec, state=inputs.state, from_plan=inputs.from_plan, to_plan=inputs.to_plan, migrated_at=inputs.migrated_at, actor_ref=inputs.requested_by_ref, reason=inputs.reason)
        except MigrationRefused as exc:
            return self.blocked(digest=digest, code=exc.code, message=str(exc))
        except ValueError as exc:
            return self.blocked(digest=digest, code="MIGRATION_INPUT_INVALID", message=str(exc))
        proof = result.migration
        return self.preview(output=proof, digest=digest, external_refs={"migration_digest": proof.migration_digest, "to_state_digest": proof.to_state_digest, "to_plan_digest": proof.to_plan_digest}, event_type="company.plan_migration_previewed", event_payload={"engine": inputs.engine, "entity_ref": proof.entity_ref, "version": proof.version, "status": proof.status}, evidence_kind="company_plan_migration", evidence_summary="Proof computed; nothing persisted.", summary=f"{inputs.engine} {proof.entity_ref} replays cleanly under the revised plan at version {proof.version} ({proof.status}); persist with the proof.")


# --------------------------------------------------------------------------- #
# company.meter_dispatch
# --------------------------------------------------------------------------- #


class MeterDispatchInput(StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    dispatch_ref: OpaqueRef
    instance: dict[str, Any]
    currency: ShortText
    usd_rate: str | None = None


class MeterDispatchPrimitive(EnginePrimitive[Any, Any]):
    primitive_ref = "company.meter_dispatch"
    version = "0.1.0"
    title = "Meter a worker dispatch from the platform's workflow instance"
    description = "Seal the platform's own record of a dispatch (status and metered USD cost) and derive the worker record_outcome receipt in the blueprint currency at an explicit rate; a running instance yields no outcome and no cost is ever estimated."
    input_model = MeterDispatchInput
    output_model = MeteredDispatch
    risk_level = "low"
    operation_spec = read_spec("company_meter_dispatch", "sdk.company.meter_dispatch")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "meter")
    golden_loop = COMPANY_OS_GOLDEN_LOOP
    engine = "company_workforce"
    loop_stages = DEEPENING_STAGES
    profiles = _PROFILES
    hard_rules = {"cost_from_platform_telemetry_only": True, "running_yields_no_outcome": True, "explicit_rate_for_non_usd": True}
    authority_boundary = {"agent": "fetches the workflow instance", "sdk": "meters and derives the receipt", "spring": "meters the workflow and owns the cost record", "connectors": "none", "mcp": "projects this primitive"}

    def _execute(self, context: PrimitiveExecutionContext, inputs: MeterDispatchInput) -> PrimitiveExecutionResult[MeteredDispatch]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            metered = meter_dispatch(inputs.instance, dispatch_ref=inputs.dispatch_ref)
            receipt = outcome_receipt(metered, currency=inputs.currency, usd_rate=inputs.usd_rate) if metered.settled else None
        except MeteringError as exc:
            return self.blocked(digest=digest, code=exc.code, message=str(exc))
        except ValueError as exc:
            return self.blocked(digest=digest, code="METERING_INPUT_INVALID", message=str(exc))
        return self.preview(output=metered, digest=digest, external_refs={"metered_digest": metered.metered_digest, "trace_id": metered.trace_id}, event_type="company.dispatch_metered", event_payload={"outcome": metered.outcome, "cost_micro_usd": metered.cost_micro_usd, "record_outcome_receipt": receipt}, evidence_kind="company_metered_dispatch", evidence_summary="Metered from platform telemetry; nothing recorded.", summary=(f"{metered.trace_id} {metered.outcome}: {metered.cost_usd} USD metered; record_outcome receipt {receipt['actual_cost']} {inputs.currency}." if receipt else f"{metered.trace_id} is still {metered.workflow_status}; no outcome yet."))


DEEPENING_EXECUTABLE_PRIMITIVES: tuple[BusinessProcessPrimitive[Any, Any], ...] = (PlanObservationJobsPrimitive(), AssessPortfolioPrimitive(), PreviewPlanMigrationPrimitive(), MeterDispatchPrimitive())

DEEPENING_INTEGRATION_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.capability_pack_integration_manifest.v1",
    "capability_pack": "company_runtime_deepening",
    "golden_loop": COMPANY_OS_GOLDEN_LOOP,
    "engine": {"schema": "lightbulb.company_engine_manifest.v1", "engine": "company_runtime_deepening", "golden_loop": COMPANY_OS_GOLDEN_LOOP, "stages": list(DEEPENING_STAGES), "required_connectors": sorted(OBSERVATION_SOURCES), "hard_rules": ["reads are planned on the admitted lane and never executed here", "portfolio reasons cite sealed inputs", "a migration replays the whole history and persists only with its proof", "dispatch cost comes from platform telemetry at an explicit rate"]},
    "modules": {"observation_jobs": "lightbulb.company_observation_jobs", "portfolio": "lightbulb.company_portfolio", "plan_migration": "lightbulb.company_plan_migration", "dispatch_metering": "lightbulb.company_dispatch_metering", "hosted_scheduler": "lightbulb.company_hosted_scheduler", "primitives": "lightbulb.company_deepening_primitives"},
    "reuses": ["company_cadence_runner tick plans", "company_execution_bridge observation adapters", "company_operating_system health", "company_approval_inbox", "company_simulator", "company_engine_store fences", "sdk project runtime checkpoints"],
    "required_connectors": sorted(OBSERVATION_SOURCES),
    "primitive_refs": [item.primitive_ref for item in DEEPENING_EXECUTABLE_PRIMITIVES],
    "non_goals": ["no read executed here", "no state persisted here", "no certification or production-readiness claim"],
}

__all__ = [
    "DEEPENING_EXECUTABLE_PRIMITIVES",
    "DEEPENING_INTEGRATION_MANIFEST",
    "AssessPortfolioInput",
    "AssessPortfolioPrimitive",
    "MeterDispatchInput",
    "MeterDispatchPrimitive",
    "PlanObservationJobsInput",
    "PlanObservationJobsPrimitive",
    "PreviewPlanMigrationInput",
    "PreviewPlanMigrationPrimitive",
    "example_deepening_inputs",
]
