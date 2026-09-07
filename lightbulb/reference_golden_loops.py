"""Initial GTM Golden Loop candidates, classified without production claims.

These manifests deliberately describe the deepest honest terminal outcome the
repository can support today.  Every candidate remains QUARANTINED until its
listed blockers are closed and Spring/operator evidence satisfies all ten
certification gates.
"""

from __future__ import annotations

from typing import Iterable

from lightbulb.connector_execution import ConnectorEffect
from lightbulb.golden_loops import (
    AmbiguousOutcomePolicy,
    CapabilityLifecycleState,
    GoldenLoopCatalog,
    GoldenLoopPortfolioDomain,
    LoopArtifactRequirement,
    LoopCertificationGate,
    LoopCertificationManifest,
    LoopCertificationTest,
    LoopExecutionBudget,
    LoopExecutionPolicy,
    LoopHarnessPolicy,
    LoopImplementationBinding,
    LoopOutcomeMetric,
    LoopPrimitiveStep,
    LoopStateMachine,
    LoopSurface,
    LoopSurfaceProjection,
    LoopTerminalDisposition,
    LoopTerminalState,
    LoopToolRequirement,
    LoopTransition,
    LoopTrigger,
)
from lightbulb.golden_loop_workflow_registry import GoldenLoopWorkflowRegistryEntry
from lightbulb.reference_golden_loop_workflows import (
    CONTROL_SPEND_WORKFLOW,
    CONTRACT_TO_CASH_WORKFLOW,
    FINANCE_JOURNAL_WORKFLOW,
    PERIOD_RECONCILIATION_WORKFLOW,
    PERIOD_RECONCILIATION_WORKFLOW_V0_3,
    PROJECT_WORK_PACKET_WORKFLOW,
    REFERENCE_GOLDEN_LOOP_WORKFLOW_REGISTRY,
    REVENUE_VERIFIED_REPLY_WORKFLOW,
    SERVICE_VERIFIED_RESOLUTION_WORKFLOW,
    VERIFIED_IMPROVEMENT_WORKFLOW,
)


def _bounded_state_machine(
    states_and_events: tuple[tuple[str, str], ...],
    *,
    success_state: str,
    success_evidence: tuple[str, ...],
    ambiguous_effect_applicable: bool = True,
) -> LoopStateMachine:
    """Create an explicit happy path plus only the applicable bounded exits."""

    happy_states = tuple(item[0] for item in states_and_events) + (success_state,)
    failure_state = "failed_with_evidence"
    cancellation_state = "cancelled_with_evidence"
    reconciliation_state = "manual_reconciliation_required"
    transitions: list[LoopTransition] = []
    for index, (state, event_ref) in enumerate(states_and_events):
        transitions.append(
            LoopTransition(
                from_state=state,
                event_ref=event_ref,
                to_state=happy_states[index + 1],
            )
        )
        transitions.extend((
            LoopTransition(
                from_state=state,
                event_ref="loop.failed",
                to_state=failure_state,
            ),
            LoopTransition(
                from_state=state,
                event_ref="loop.cancelled",
                to_state=cancellation_state,
            ),
        ))
        if ambiguous_effect_applicable:
            transitions.append(LoopTransition(
                from_state=state,
                event_ref="loop.effect_ambiguous",
                to_state=reconciliation_state,
            ))
    terminal_states = [
        LoopTerminalState(
            state=success_state,
            disposition=LoopTerminalDisposition.SUCCEEDED,
            outcome_description=(
                "The manifest's precisely named outcome is supported by every "
                "required artifact and evidence reference."
            ),
            required_evidence_kinds=success_evidence,
        ),
        LoopTerminalState(
            state=failure_state,
            disposition=LoopTerminalDisposition.FAILED,
            outcome_description="The run failed and retained bounded failure evidence.",
            required_evidence_kinds=("failure_receipt",),
        ),
        LoopTerminalState(
            state=cancellation_state,
            disposition=LoopTerminalDisposition.CANCELLED,
            outcome_description="Spring fenced the run and retained cancellation evidence.",
            required_evidence_kinds=("cancellation_receipt",),
        ),
    ]
    if ambiguous_effect_applicable:
        terminal_states.append(LoopTerminalState(
            state=reconciliation_state,
            disposition=LoopTerminalDisposition.RECONCILIATION_REQUIRED,
            outcome_description=(
                "An external effect is uncertain; automatic replay is blocked and "
                "the exact request is visible for human reconciliation."
            ),
            required_evidence_kinds=("ambiguous_effect_receipt",),
        ))
    return LoopStateMachine(
        initial_state=happy_states[0],
        states=happy_states + (failure_state, cancellation_state) + (
            (reconciliation_state,) if ambiguous_effect_applicable else ()
        ),
        transitions=tuple(transitions),
        terminal_states=tuple(terminal_states),
    )


def _surface_projections(
    workflow: GoldenLoopWorkflowRegistryEntry,
) -> tuple[LoopSurfaceProjection, ...]:
    return tuple(
        LoopSurfaceProjection(
            surface=item.surface,
            entrypoint_ref=item.entrypoint_ref,
            lifecycle=CapabilityLifecycleState.QUARANTINED,
            participation=item.participation.value,
            blocker_code=item.blocker_code,
            optional=item.surface == LoopSurface.CHATGPT,
        )
        for item in workflow.surface_entrypoints
    )


def _implementation(
    workflow: GoldenLoopWorkflowRegistryEntry,
) -> LoopImplementationBinding:
    return LoopImplementationBinding(
        canonical_workflow_ref=workflow.workflow_ref,
        workflow_version=workflow.workflow_version,
        execution_loop_version=workflow.execution_loop_version,
        runtime_owner=workflow.runtime_owner,
        runtime_adapter_ref=workflow.runtime_adapter_ref,
        source_refs=workflow.runtime_adapter_source_refs,
    )


def _harness_policy(*, required: bool) -> LoopHarnessPolicy:
    return LoopHarnessPolicy(
        required=required,
        # These are the only launch harness identities accepted by the hosted
        # Project adapter authority. Access through ChatGPT remains independent
        # of which coding harness executes a bounded work packet.
        allowed_harnesses=("claude_code", "codex", "cursor"),
    )


def _certification_tests(loop_ref: str) -> tuple[LoopCertificationTest, ...]:
    environments = {
        LoopCertificationGate.TYPED_VERSIONED_CONTRACTS: "contract",
        LoopCertificationGate.PRODUCTION_SHAPED_COMPLETION: "production_shaped",
        LoopCertificationGate.SCOPE_ISOLATION_AND_RBAC: "integration",
        LoopCertificationGate.APPROVAL_AND_EFFECT_CONTROL: "integration",
        LoopCertificationGate.RESTART_REPLICA_AND_RECOVERY: "production_shaped",
        LoopCertificationGate.AMBIGUOUS_EFFECT_SAFETY: "sandbox",
        LoopCertificationGate.CROSS_SURFACE_PARITY: "production_shaped",
        LoopCertificationGate.HARNESS_CONFORMANCE: "production_shaped",
        LoopCertificationGate.LIVE_PROVIDER_CONFORMANCE: "canary",
        LoopCertificationGate.MEASURED_CUSTOMER_OUTCOME: "canary",
    }
    return tuple(
        LoopCertificationTest(
            test_ref=f"certification/{loop_ref}/{gate.value}",
            gate=gate,
            environment=environments[gate],  # type: ignore[arg-type]
            required_evidence_kind=f"{gate.value}_evidence",
        )
        for gate in LoopCertificationGate
    )


def _execution_policy() -> LoopExecutionPolicy:
    return LoopExecutionPolicy(
        ambiguous_effect_event_ref="loop.effect_ambiguous",
        ambiguous_effect_terminal_state="manual_reconciliation_required",
    )


def _artifacts(
    role_ref: str,
    *requirements: tuple[str, str, str],
) -> tuple[LoopArtifactRequirement, ...]:
    return tuple(
        LoopArtifactRequirement(
            artifact_ref=artifact_ref,
            evidence_kind=evidence_kind,
            produced_by_agent_role_ref=role_ref,
            accepted_by_role_ref=accepted_by,
        )
        for artifact_ref, evidence_kind, accepted_by in requirements
    )


GOVERNED_CRM_VERIFIED_REPLY = LoopCertificationManifest(
    loop_ref="revenue.governed_crm_turn_verified_reply",
    version="0.2.0",
    title="Governed CRM conversation turn to verified reply trace",
    portfolio_domain=GoldenLoopPortfolioDomain.REVENUE_ACQUISITION,
    buyer="Revenue operations and sales leadership",
    business_objective=(
        "Send one policy-compliant, approval-bound CRM conversation turn and "
        "retain an independently observed provider reply trace. This contract "
        "does not claim lead qualification, a booked meeting, pipeline movement, or revenue."
    ),
    lifecycle=CapabilityLifecycleState.QUARANTINED,
    triggers=(
        LoopTrigger(
            trigger_ref="crm.conversation_turn_requested",
            event_ref="crm.conversation_turn_requested",
            description="A scoped CRM contact is eligible for one governed conversation turn.",
            required_input_refs=(
                "contact_ref",
                "conversation_thread_ref",
                "message_objective",
                "channel_policy_ref",
            ),
        ),
    ),
    state_machine=LoopStateMachine(
        initial_state="admitted_draft",
        states=(
            "admitted_draft",
            "materialized",
            "approval_pending",
            "ready_to_dispatch",
            "dispatch_claimed",
            "dispatched",
            "dispatch_ambiguous",
            "observing_reply",
            "verified_reply_recorded",
            "no_verified_reply",
            "cancelled",
            "failed_pre_dispatch",
            "reconciliation_required",
            "reconciled_effect_confirmed",
        ),
        transitions=(
            LoopTransition(
                from_state="admitted_draft",
                event_ref="communication.source_materialized",
                to_state="materialized",
            ),
            LoopTransition(
                from_state="admitted_draft",
                event_ref="loop.cancelled",
                to_state="cancelled",
            ),
            LoopTransition(
                from_state="admitted_draft",
                event_ref="loop.failed",
                to_state="failed_pre_dispatch",
            ),
            LoopTransition(
                from_state="materialized",
                event_ref="communication.approval_requested",
                to_state="approval_pending",
            ),
            LoopTransition(
                from_state="materialized",
                event_ref="loop.cancelled",
                to_state="cancelled",
            ),
            LoopTransition(
                from_state="materialized",
                event_ref="loop.failed",
                to_state="failed_pre_dispatch",
            ),
            LoopTransition(
                from_state="approval_pending",
                event_ref="communication.approval_granted",
                to_state="ready_to_dispatch",
            ),
            LoopTransition(
                from_state="approval_pending",
                event_ref="loop.cancelled",
                to_state="cancelled",
            ),
            LoopTransition(
                from_state="approval_pending",
                event_ref="loop.failed",
                to_state="failed_pre_dispatch",
            ),
            LoopTransition(
                from_state="ready_to_dispatch",
                event_ref="communication.dispatch_claimed",
                to_state="dispatch_claimed",
            ),
            LoopTransition(
                from_state="ready_to_dispatch",
                event_ref="loop.cancelled",
                to_state="cancelled",
            ),
            LoopTransition(
                from_state="ready_to_dispatch",
                event_ref="loop.failed",
                to_state="failed_pre_dispatch",
            ),
            LoopTransition(
                from_state="dispatch_claimed",
                event_ref="communication.dispatch_succeeded",
                to_state="dispatched",
            ),
            LoopTransition(
                from_state="dispatch_claimed",
                event_ref="communication.dispatch_ambiguous",
                to_state="dispatch_ambiguous",
            ),
            LoopTransition(
                from_state="dispatch_claimed",
                event_ref="communication.dispatch_evidence_deadline_elapsed",
                to_state="reconciliation_required",
            ),
            LoopTransition(
                from_state="dispatch_ambiguous",
                event_ref="communication.dispatch_reconciled_applied",
                to_state="reconciled_effect_confirmed",
            ),
            LoopTransition(
                from_state="dispatch_ambiguous",
                event_ref="loop.effect_ambiguous",
                to_state="reconciliation_required",
            ),
            LoopTransition(
                from_state="dispatched",
                event_ref="communication.outbound_observed",
                to_state="observing_reply",
            ),
            LoopTransition(
                from_state="dispatched",
                event_ref="communication.outbound_observation_deadline_elapsed",
                to_state="reconciliation_required",
            ),
            LoopTransition(
                from_state="reconciliation_required",
                event_ref="communication.dispatch_reconciled_applied",
                to_state="reconciled_effect_confirmed",
                refinement_kind="append_only_settlement",
            ),
            LoopTransition(
                from_state="observing_reply",
                event_ref="communication.verified_reply_appended",
                to_state="verified_reply_recorded",
            ),
            LoopTransition(
                from_state="observing_reply",
                event_ref="communication.reply_window_exhausted",
                to_state="no_verified_reply",
            ),
        ),
        terminal_states=(
            LoopTerminalState(
                state="verified_reply_recorded",
                disposition=LoopTerminalDisposition.SUCCEEDED,
                outcome_description=(
                    "The approval-bound outbound effect has provider readback, a "
                    "causally matched verified reply, and an authoritative CRM append receipt."
                ),
                required_evidence_kinds=(
                    "verified_reply_trace",
                    "crm_touchpoint_append_receipt",
                ),
            ),
            LoopTerminalState(
                state="no_verified_reply",
                disposition=LoopTerminalDisposition.FAILED,
                outcome_description="The bounded reply window ended with durable exhaustion evidence.",
                required_evidence_kinds=("reply_window_exhaustion_receipt",),
            ),
            LoopTerminalState(
                state="failed_pre_dispatch",
                disposition=LoopTerminalDisposition.FAILED,
                outcome_description="The run failed before provider dispatch was claimed.",
                required_evidence_kinds=("failure_receipt",),
            ),
            LoopTerminalState(
                state="cancelled",
                disposition=LoopTerminalDisposition.CANCELLED,
                outcome_description="Spring fenced cancellation before the dispatch claim.",
                required_evidence_kinds=("cancellation_receipt",),
            ),
            LoopTerminalState(
                state="reconciliation_required",
                disposition=LoopTerminalDisposition.RECONCILIATION_REQUIRED,
                outcome_description=(
                    "Dispatch acceptance is unresolved; replay is blocked and the exact "
                    "effect is human-visible for reconciliation."
                ),
                required_evidence_kinds=("reconciliation_receipt",),
            ),
            LoopTerminalState(
                state="reconciled_effect_confirmed",
                disposition=LoopTerminalDisposition.FAILED,
                outcome_description=(
                    "Independent readback and separated approval confirmed the outbound "
                    "effect, but absent private provider-response custody prevents this "
                    "run from claiming reply observation or verified-reply success."
                ),
                required_evidence_kinds=("applied_reconciliation_receipt",),
            ),
        ),
    ),
    agent_role_refs=("revenue_operator", "communication_specialist"),
    primitive_steps=(
        LoopPrimitiveStep(
            step_ref="plan_conversation_turn",
            primitive_ref="communication.plan_crm_conversation_turn",
            primitive_version="1.0.0",
            agent_role_ref="revenue_operator",
            effect=ConnectorEffect.READ,
            approval_required=False,
            emits_event_ref="crm.context_resolved",
        ),
        LoopPrimitiveStep(
            step_ref="evaluate_channel_policy",
            primitive_ref="communication.evaluate_jurisdiction_channel_policy",
            primitive_version="1.0.0",
            agent_role_ref="communication_specialist",
            effect=ConnectorEffect.READ,
            approval_required=False,
            emits_event_ref="communication.policy_allowed",
        ),
        LoopPrimitiveStep(
            step_ref="resolve_identity",
            primitive_ref="communication.resolve_cross_channel_identity",
            primitive_version="1.0.0",
            agent_role_ref="communication_specialist",
            effect=ConnectorEffect.READ,
            approval_required=False,
            emits_event_ref="communication.identity_resolved",
        ),
        LoopPrimitiveStep(
            step_ref="dispatch_approved_turn",
            primitive_ref="communication.write_email",
            primitive_version="1.2.0",
            agent_role_ref="communication_specialist",
            effect=ConnectorEffect.WRITE,
            approval_required=True,
            tool_binding_refs=("approved_email_dispatch",),
            emits_event_ref="communication.dispatch_completed",
        ),
        LoopPrimitiveStep(
            step_ref="classify_verified_reply",
            primitive_ref="communication.classify_reply",
            primitive_version="1.0.0",
            agent_role_ref="revenue_operator",
            effect=ConnectorEffect.READ,
            approval_required=False,
            tool_binding_refs=("provider_thread_observation",),
            emits_event_ref="communication.reply_classified",
        ),
    ),
    tool_requirements=(
        LoopToolRequirement(
            binding_ref="approved_email_dispatch",
            acceptable_tools=(
                "gmail.send_email",
                "microsoft.send_email",
                "notifications.send_email",
                "ses.send_email",
            ),
            effect=ConnectorEffect.WRITE,
            approval_required=True,
            connector_account_binding_required=True,
            idempotency_required=True,
            ambiguous_outcome_policy=AmbiguousOutcomePolicy.STATUS_PROBE_THEN_RECONCILE,
        ),
        LoopToolRequirement(
            binding_ref="provider_thread_observation",
            acceptable_tools=("gmail.get_thread",),
            effect=ConnectorEffect.READ,
            approval_required=False,
            connector_account_binding_required=True,
            idempotency_required=False,
            ambiguous_outcome_policy=AmbiguousOutcomePolicy.NOT_APPLICABLE,
        ),
    ),
    artifact_requirements=_artifacts(
        "communication_specialist",
        ("approved_outbound_turn", "dispatch_receipt", "revenue_operator"),
        ("verified_inbound_reply", "verified_reply_trace", "revenue_operator"),
        ("crm_touchpoint_trace", "crm_touchpoint_append_receipt", "revenue_operator"),
    ),
    execution_policy=LoopExecutionPolicy(
        ambiguous_effect_event_ref="loop.effect_ambiguous",
        ambiguous_effect_terminal_state="reconciliation_required",
    ),
    budget=LoopExecutionBudget(
        max_elapsed_seconds=604_800,
        max_cost_microusd=25_000_000,
        max_primitive_steps=50,
        max_agent_turns=30,
    ),
    completion_slo_seconds=604_800,
    outcome_metrics=(
        LoopOutcomeMetric(
            metric_ref="verified_reply_rate",
            direction="increase",
            unit="percent",
            source_system_ref="spring-business-outcomes-ledger",
            required_sample_count=30,
            measurement_window_seconds=7_776_000,
            certification_target="15",
            certification_comparison="at_least",
        ),
        LoopOutcomeMetric(
            metric_ref="time_to_verified_reply_seconds",
            direction="decrease",
            unit="seconds",
            source_system_ref="spring-business-outcomes-ledger",
            required_sample_count=30,
            measurement_window_seconds=7_776_000,
            certification_target="604800",
            certification_comparison="at_most",
        ),
    ),
    surfaces=_surface_projections(REVENUE_VERIFIED_REPLY_WORKFLOW),
    harness_policy=_harness_policy(required=False),
    implementation=_implementation(REVENUE_VERIFIED_REPLY_WORKFLOW),
    required_operational_readiness_gates=(
        "hosted_writes",
        "publication_recovery",
        "connector_conformance",
        "transport_recovery",
        "replay_guarantees",
        "service_levels",
        "incident_response",
        "business_outcomes",
    ),
    certification_tests=_certification_tests(
        "revenue.governed_crm_turn_verified_reply"
    ),
    known_blockers=(
        "The Spring DB-clock sweep now bounds admission, approval, claimed, dispatched, ambiguous, and reply-observation stalls; its local PostgreSQL 17 rehearsal proves real ShedLock crash/takeover and both expired post-claim business transitions, but deployed multi-replica Spring-process evidence remains absent.",
        "A reviewer-approved RECONCILED_APPLIED Gmail ambiguity now closes as record-only RECONCILED_EFFECT_CONFIRMED without redispatch or false provider-response reconstruction; continuing into reply observation still requires a separately certified private observation-custody contract.",
        "GovernedRevenueLoopPanel now routes the CRM workspace through this authority, but no deployed browser journey or production visual/accessibility evidence is retained.",
        "No real Gmail or Outlook sandbox canary evidence is recorded.",
        "Legacy outreach and booking paths are not semantic projections of this run.",
        "No measured customer outcome, completion cost, or completion SLO is recorded.",
    ),
)


PROJECT_INDEPENDENT_ACCEPTANCE = LoopCertificationManifest(
    loop_ref="project.work_packet_independent_acceptance",
    version="0.2.0",
    title="Approved work packet to independent evidence-backed acceptance",
    portfolio_domain=GoldenLoopPortfolioDomain.PRODUCT_DELIVERY,
    buyer="Product and engineering leadership",
    business_objective=(
        "Turn an immutable approved work packet into content-addressed artifacts "
        "accepted criterion-by-criterion by a fresh evaluator. This contract does "
        "not claim a branch, commit, pull request, merge, deployment, release, or Project completion."
    ),
    lifecycle=CapabilityLifecycleState.QUARANTINED,
    triggers=(
        LoopTrigger(
            trigger_ref="project.work_packet_approved",
            event_ref="project.work_packet_approved",
            description="A scoped work packet and immutable acceptance contract are approved.",
            required_input_refs=(
                "work_packet_digest",
                "acceptance_contract_digest",
                "repository_binding_ref",
                "workspace_binding_ref",
                "selected_harness",
            ),
        ),
    ),
    state_machine=LoopStateMachine(
        initial_state="planning",
        states=(
            "planning",
            "building",
            "evaluating",
            "accepted",
            "rejected",
            "blocked",
            "budget_exhausted",
            "cancelled",
        ),
        transitions=(
            LoopTransition(
                from_state="planning",
                event_ref="dynamic_workflow.plan_accepted",
                to_state="building",
            ),
            LoopTransition(
                from_state="planning",
                event_ref="dynamic_workflow.budget_exhausted",
                to_state="budget_exhausted",
            ),
            LoopTransition(
                from_state="planning",
                event_ref="loop.cancelled",
                to_state="cancelled",
            ),
            LoopTransition(
                from_state="planning",
                event_ref="loop.effect_ambiguous",
                to_state="blocked",
            ),
            LoopTransition(
                from_state="building",
                event_ref="dynamic_workflow.builder_result_submitted",
                to_state="evaluating",
            ),
            LoopTransition(
                from_state="building",
                event_ref="dynamic_workflow.budget_exhausted",
                to_state="budget_exhausted",
            ),
            LoopTransition(
                from_state="building",
                event_ref="loop.cancelled",
                to_state="cancelled",
            ),
            LoopTransition(
                from_state="building",
                event_ref="loop.effect_ambiguous",
                to_state="blocked",
            ),
            LoopTransition(
                from_state="evaluating",
                event_ref="dynamic_workflow.evaluator_accepted",
                to_state="accepted",
            ),
            LoopTransition(
                from_state="evaluating",
                event_ref="dynamic_workflow.evaluator_rejected",
                to_state="rejected",
            ),
            LoopTransition(
                from_state="evaluating",
                event_ref="dynamic_workflow.evaluator_blocked",
                to_state="blocked",
            ),
            LoopTransition(
                from_state="evaluating",
                event_ref="dynamic_workflow.evaluator_retry_build",
                to_state="building",
            ),
            LoopTransition(
                from_state="evaluating",
                event_ref="dynamic_workflow.evaluator_revise_plan",
                to_state="planning",
            ),
            LoopTransition(
                from_state="evaluating",
                event_ref="dynamic_workflow.budget_exhausted",
                to_state="budget_exhausted",
            ),
            LoopTransition(
                from_state="evaluating",
                event_ref="loop.cancelled",
                to_state="cancelled",
            ),
            LoopTransition(
                from_state="evaluating",
                event_ref="loop.effect_ambiguous",
                to_state="blocked",
            ),
        ),
        terminal_states=(
            LoopTerminalState(
                state="accepted",
                disposition=LoopTerminalDisposition.SUCCEEDED,
                outcome_description=(
                    "A fresh evaluator accepted every immutable criterion against the "
                    "content-addressed builder artifact package."
                ),
                required_evidence_kinds=(
                    "builder_artifact_evidence",
                    "independent_evaluator_verdict",
                ),
            ),
            LoopTerminalState(
                state="rejected",
                disposition=LoopTerminalDisposition.FAILED,
                outcome_description="The independent evaluator terminally rejected the artifact package.",
                required_evidence_kinds=("independent_evaluator_verdict",),
            ),
            LoopTerminalState(
                state="budget_exhausted",
                disposition=LoopTerminalDisposition.FAILED,
                outcome_description="The bounded workflow exhausted its declared budget before acceptance.",
                required_evidence_kinds=("budget_exhaustion_receipt",),
            ),
            LoopTerminalState(
                state="cancelled",
                disposition=LoopTerminalDisposition.CANCELLED,
                outcome_description="Spring fenced the workflow and all outstanding harness leases.",
                required_evidence_kinds=("cancellation_receipt",),
            ),
            LoopTerminalState(
                state="blocked",
                disposition=LoopTerminalDisposition.RECONCILIATION_REQUIRED,
                outcome_description=(
                    "The evaluator or runtime found an unsafe or unresolved condition; "
                    "the exact workflow is terminal and human-visible."
                ),
                required_evidence_kinds=("blocked_workflow_receipt",),
            ),
        ),
    ),
    agent_role_refs=("project_agent", "planner", "builder", "independent_evaluator"),
    primitive_steps=(
        LoopPrimitiveStep(
            step_ref="create_approved_work_packet",
            primitive_ref="project.create_work_packet",
            primitive_version="1.0.0",
            agent_role_ref="project_agent",
            effect=ConnectorEffect.DRAFT,
            approval_required=True,
            emits_event_ref="project.work_packet_materialized",
        ),
    ),
    artifact_requirements=(
        LoopArtifactRequirement(
            artifact_ref="approved_work_packet",
            evidence_kind="work_packet_digest",
            produced_by_agent_role_ref="project_agent",
            accepted_by_role_ref="planner",
        ),
        LoopArtifactRequirement(
            artifact_ref="builder_artifact_package",
            evidence_kind="builder_artifact_evidence",
            produced_by_agent_role_ref="builder",
            accepted_by_role_ref="independent_evaluator",
        ),
        LoopArtifactRequirement(
            artifact_ref="evaluator_verdict",
            evidence_kind="independent_evaluator_verdict",
            produced_by_agent_role_ref="independent_evaluator",
            accepted_by_role_ref="project_agent",
        ),
    ),
    execution_policy=LoopExecutionPolicy(
        ambiguous_effect_event_ref="loop.effect_ambiguous",
        ambiguous_effect_terminal_state="blocked",
    ),
    budget=LoopExecutionBudget(
        max_elapsed_seconds=86_400,
        max_cost_microusd=100_000_000,
        max_primitive_steps=100,
        max_agent_turns=80,
    ),
    completion_slo_seconds=86_400,
    outcome_metrics=(
        LoopOutcomeMetric(
            metric_ref="independent_acceptance_rate",
            direction="increase",
            unit="percent",
            source_system_ref="spring-business-outcomes-ledger",
            required_sample_count=30,
            measurement_window_seconds=2_592_000,
            certification_target="90",
            certification_comparison="at_least",
        ),
        LoopOutcomeMetric(
            metric_ref=(
                "accepted_work_packet_mean_time_to_independent_acceptance_seconds"
            ),
            direction="decrease",
            unit="seconds",
            source_system_ref="spring-business-outcomes-ledger",
            required_sample_count=30,
            measurement_window_seconds=2_592_000,
            certification_target="86400",
            certification_comparison="at_most",
        ),
    ),
    surfaces=_surface_projections(PROJECT_WORK_PACKET_WORKFLOW),
    harness_policy=_harness_policy(required=True),
    implementation=_implementation(PROJECT_WORK_PACKET_WORKFLOW),
    required_operational_readiness_gates=(
        "bounded_loops",
        "publication_recovery",
        "replay_guarantees",
        "service_levels",
        "incident_response",
        "business_outcomes",
    ),
    certification_tests=_certification_tests(
        "project.work_packet_independent_acceptance"
    ),
    known_blockers=(
        "The signed Codex, Claude Code, and Cursor adapter assertion paths have no retained deployed-harness conformance evidence.",
        "Protocol 1.5 heartbeat, reconnect, cancellation, and deadline authority lack retained multi-replica and restart evidence with real advertised harnesses; the local scheduler now sources one PostgreSQL clock value per sweep, but no deployed multi-process business-transition rehearsal is retained.",
        "Returned repository and test artifacts are not provider-verified against work-packet and acceptance digests.",
        "The V1868/V1871 PostgreSQL authority and adapter-key rotation have not passed the production topology rehearsal.",
        "No thirty-run accepted-artifact outcome sample is recorded.",
    ),
)


CONTRACT_TO_CASH_COLLECTED_CASH = LoopCertificationManifest(
    loop_ref="finance.contract_to_cash_collected_cash",
    version="0.2.0",
    title="Executed commercial agreement to independently verified collected cash",
    portfolio_domain=GoldenLoopPortfolioDomain.FINANCE_OPERATIONS,
    buyer="Services leadership, revenue operations, and finance leadership",
    business_objective=(
        "Bind an independently observed executed commercial agreement to one approved "
        "QuickBooks invoice, verify exact provider issuance, verify full invoice payment "
        "application, and terminalize only after a distinct Stripe paid-payout observation "
        "has passed its reversal window. Provider acceptance and invoice payment alone are "
        "explicitly non-terminal."
    ),
    lifecycle=CapabilityLifecycleState.QUARANTINED,
    triggers=(
        LoopTrigger(
            trigger_ref="commercial.executed_agreement_observed",
            event_ref="commercial.executed_agreement_observed",
            description=(
                "Two exact governed DocuSign reads prove a completed envelope and its "
                "signed document inside one tenant/company/project scope."
            ),
            required_input_refs=(
                "agreement_connector_account_ref",
                "envelope_observation_journal_id",
                "document_observation_journal_id",
                "invoice_connector_account_ref",
                "settlement_connector_account_ref",
            ),
        ),
    ),
    state_machine=_bounded_state_machine(
        (
            ("agreement_evidence_pending", "commercial.executed_agreement_custodied"),
            ("agreement_effective", "finance.invoice_proposal_sealed"),
            ("invoice_prepared", "finance.invoice_write_reconciled_applied"),
            ("invoice_write_observed", "finance.invoice_issued_custodied"),
            ("invoice_issued", "finance.invoice_payment_applied_observed"),
            ("payment_applied", "finance.cash_settlement_observed"),
        ),
        success_state="cash_collected",
        success_evidence=(
            "executed_customer_agreement",
            "contract_to_cash_invoice_proposal_receipt",
            "issued_customer_invoice",
            "governed_invoice_payment_observation",
            "governed_cash_settlement_observation",
            "settled_cash_receipt",
        ),
    ),
    agent_role_refs=(
        "accountant",
        "independent_finance_reviewer",
    ),
    primitive_steps=(
        LoopPrimitiveStep(
            step_ref="prepare_agreement_bound_invoice",
            primitive_ref="finance.create_invoice",
            primitive_version="1.0.0",
            agent_role_ref="accountant",
            effect=ConnectorEffect.WRITE,
            approval_required=True,
            tool_binding_refs=("invoice_write",),
            emits_event_ref="finance.invoice_write_reported",
        ),
        LoopPrimitiveStep(
            step_ref="observe_invoice_issuance",
            primitive_ref="finance.observe_invoice_issued",
            primitive_version="1.0.0",
            agent_role_ref="independent_finance_reviewer",
            effect=ConnectorEffect.READ,
            approval_required=False,
            tool_binding_refs=("invoice_issuance_observer",),
            emits_event_ref="finance.invoice_issued_observed",
        ),
        LoopPrimitiveStep(
            step_ref="observe_full_invoice_payment",
            primitive_ref="finance.observe_invoice_payment_applied",
            primitive_version="1.0.0",
            agent_role_ref="independent_finance_reviewer",
            effect=ConnectorEffect.READ,
            approval_required=False,
            tool_binding_refs=("invoice_payment_observer",),
            emits_event_ref="finance.invoice_payment_applied_observed",
        ),
        LoopPrimitiveStep(
            step_ref="observe_paid_payout_settlement",
            primitive_ref="finance.observe_cash_settlement",
            primitive_version="1.0.0",
            agent_role_ref="independent_finance_reviewer",
            effect=ConnectorEffect.READ,
            approval_required=False,
            tool_binding_refs=("cash_settlement_observer",),
            emits_event_ref="finance.cash_settlement_observed",
        ),
    ),
    tool_requirements=(
        LoopToolRequirement(
            binding_ref="executed_envelope_observer",
            acceptable_tools=("signing.get_envelope",),
            effect=ConnectorEffect.READ,
            approval_required=False,
            connector_account_binding_required=True,
            idempotency_required=False,
            ambiguous_outcome_policy=AmbiguousOutcomePolicy.NOT_APPLICABLE,
        ),
        LoopToolRequirement(
            binding_ref="signed_document_observer",
            acceptable_tools=("signing.download_document",),
            effect=ConnectorEffect.READ,
            approval_required=False,
            connector_account_binding_required=True,
            idempotency_required=False,
            ambiguous_outcome_policy=AmbiguousOutcomePolicy.NOT_APPLICABLE,
        ),
        LoopToolRequirement(
            binding_ref="invoice_write",
            acceptable_tools=("quickbooks.create_invoice",),
            effect=ConnectorEffect.WRITE,
            approval_required=True,
            connector_account_binding_required=True,
            idempotency_required=True,
            ambiguous_outcome_policy=AmbiguousOutcomePolicy.STATUS_PROBE_THEN_RECONCILE,
        ),
        LoopToolRequirement(
            binding_ref="invoice_issuance_observer",
            acceptable_tools=("quickbooks.observe_invoice_issued",),
            effect=ConnectorEffect.READ,
            approval_required=False,
            connector_account_binding_required=True,
            idempotency_required=False,
            ambiguous_outcome_policy=AmbiguousOutcomePolicy.NOT_APPLICABLE,
        ),
        LoopToolRequirement(
            binding_ref="invoice_payment_observer",
            acceptable_tools=("quickbooks.observe_invoice_payment_applied",),
            effect=ConnectorEffect.READ,
            approval_required=False,
            connector_account_binding_required=True,
            idempotency_required=False,
            ambiguous_outcome_policy=AmbiguousOutcomePolicy.NOT_APPLICABLE,
        ),
        LoopToolRequirement(
            binding_ref="cash_settlement_observer",
            acceptable_tools=("stripe.observe_cash_settlement",),
            effect=ConnectorEffect.READ,
            approval_required=False,
            connector_account_binding_required=True,
            idempotency_required=False,
            ambiguous_outcome_policy=AmbiguousOutcomePolicy.NOT_APPLICABLE,
        ),
    ),
    artifact_requirements=_artifacts(
        "accountant",
        (
            "executed_customer_agreement",
            "executed_customer_agreement",
            "independent_finance_reviewer",
        ),
        (
            "invoice_proposal_receipt",
            "contract_to_cash_invoice_proposal_receipt",
            "independent_finance_reviewer",
        ),
        (
            "issued_customer_invoice",
            "issued_customer_invoice",
            "independent_finance_reviewer",
        ),
        (
            "invoice_payment_observation",
            "governed_invoice_payment_observation",
            "independent_finance_reviewer",
        ),
        (
            "cash_settlement_observation",
            "governed_cash_settlement_observation",
            "independent_finance_reviewer",
        ),
        (
            "settled_cash_receipt",
            "settled_cash_receipt",
            "independent_finance_reviewer",
        ),
    ),
    execution_policy=_execution_policy(),
    budget=LoopExecutionBudget(
        max_elapsed_seconds=15_552_000,
        max_cost_microusd=50_000_000,
        max_primitive_steps=100,
        max_agent_turns=50,
    ),
    completion_slo_seconds=15_552_000,
    outcome_metrics=(
        LoopOutcomeMetric(
            metric_ref="agreement_to_collected_cash_rate",
            direction="increase",
            unit="percent",
            source_system_ref="spring-business-outcomes-ledger",
            required_sample_count=30,
            measurement_window_seconds=15_552_000,
            certification_target="80",
            certification_comparison="at_least",
        ),
        LoopOutcomeMetric(
            metric_ref="time_to_collected_cash_seconds",
            direction="decrease",
            unit="seconds",
            source_system_ref="spring-business-outcomes-ledger",
            required_sample_count=30,
            measurement_window_seconds=15_552_000,
            certification_target="15552000",
            certification_comparison="at_most",
        ),
        LoopOutcomeMetric(
            metric_ref="duplicate_invoice_or_payment_effect_rate",
            direction="decrease",
            unit="percent",
            source_system_ref="spring-business-outcomes-ledger",
            required_sample_count=100,
            measurement_window_seconds=15_552_000,
            certification_target="0",
            certification_comparison="at_most",
        ),
    ),
    surfaces=_surface_projections(CONTRACT_TO_CASH_WORKFLOW),
    harness_policy=_harness_policy(required=False),
    implementation=_implementation(CONTRACT_TO_CASH_WORKFLOW),
    required_operational_readiness_gates=(
        "hosted_writes",
        "connector_conformance",
        "transport_recovery",
        "replay_guarantees",
        "service_levels",
        "incident_response",
        "business_outcomes",
    ),
    certification_tests=_certification_tests(
        "finance.contract_to_cash_collected_cash"
    ),
    known_blockers=(
        "The managed-Agent native-MCP projection is locally implemented but has not passed deployed runtime and reconnect conformance.",
        "The contract-to-cash custody chain has not run against real DocuSign, QuickBooks, and Stripe sandbox accounts.",
        "No multi-replica restart or ambiguous invoice-write rehearsal has been retained for this whole continuation.",
        "No design-partner agreement-to-collected-cash outcome sample, cost, or completion SLO is recorded.",
    ),
)


FINANCE_JOURNAL_READBACK_SETTLEMENT = LoopCertificationManifest(
    loop_ref="finance.journal_post_readback_settlement",
    version="0.3.0",
    title="Governed QuickBooks journal to verified applied settlement",
    portfolio_domain=GoldenLoopPortfolioDomain.FINANCE_OPERATIONS,
    buyer="Controller and accounting operations leadership",
    business_objective=(
        "Post one approved QuickBooks journal entry, independently observe its exact "
        "correlation-bound effect, and terminalize an evidence-bound applied settlement. "
        "An ambiguous dispatch is never replayed automatically: it requires independent "
        "readback and a distinct reconciliation approval before the original journal may "
        "be recorded as applied. This bounded contract does not claim a period close or "
        "full-book reconciliation."
    ),
    lifecycle=CapabilityLifecycleState.QUARANTINED,
    triggers=(
        LoopTrigger(
            trigger_ref="finance.journal_post_requested",
            event_ref="finance.journal_post_requested",
            description="A scoped balanced journal candidate requires governed posting.",
            required_input_refs=(
                "ledger_ref",
                "journal_candidate_ref",
                "approval_policy_ref",
                "connector_account_ref",
            ),
        ),
    ),
    state_machine=LoopStateMachine(
        initial_state="approval_pending",
        states=(
            "approval_pending",
            "write_dispatch_claimed",
            "readback_pending_succeeded",
            "readback_pending_ambiguous",
            "reconciliation_approval_pending",
            "settled_applied",
            "failed_before_effect",
            "cancelled_before_dispatch",
            "manual_reconciliation_required",
        ),
        transitions=(
            LoopTransition(
                from_state="approval_pending",
                event_ref="finance.write_dispatch_claimed",
                to_state="write_dispatch_claimed",
            ),
            LoopTransition(
                from_state="approval_pending",
                event_ref="loop.failed",
                to_state="failed_before_effect",
            ),
            LoopTransition(
                from_state="approval_pending",
                event_ref="loop.cancelled",
                to_state="cancelled_before_dispatch",
            ),
            LoopTransition(
                from_state="approval_pending",
                event_ref="loop.effect_ambiguous",
                to_state="manual_reconciliation_required",
            ),
            LoopTransition(
                from_state="write_dispatch_claimed",
                event_ref="finance.write_succeeded",
                to_state="readback_pending_succeeded",
            ),
            LoopTransition(
                from_state="write_dispatch_claimed",
                event_ref="finance.write_ambiguous",
                to_state="readback_pending_ambiguous",
            ),
            LoopTransition(
                from_state="write_dispatch_claimed",
                event_ref="loop.failed",
                to_state="failed_before_effect",
            ),
            LoopTransition(
                from_state="write_dispatch_claimed",
                event_ref="loop.effect_ambiguous",
                to_state="manual_reconciliation_required",
            ),
            LoopTransition(
                from_state="readback_pending_succeeded",
                event_ref="finance.independent_readback_applied",
                to_state="settled_applied",
            ),
            LoopTransition(
                from_state="readback_pending_succeeded",
                event_ref="loop.effect_ambiguous",
                to_state="manual_reconciliation_required",
            ),
            LoopTransition(
                from_state="readback_pending_ambiguous",
                event_ref="finance.independent_readback_applied",
                to_state="reconciliation_approval_pending",
            ),
            LoopTransition(
                from_state="readback_pending_ambiguous",
                event_ref="loop.effect_ambiguous",
                to_state="manual_reconciliation_required",
            ),
            LoopTransition(
                from_state="reconciliation_approval_pending",
                event_ref="finance.applied_reconciliation_approved",
                to_state="settled_applied",
            ),
            LoopTransition(
                from_state="reconciliation_approval_pending",
                event_ref="loop.effect_ambiguous",
                to_state="manual_reconciliation_required",
            ),
        ),
        terminal_states=(
            LoopTerminalState(
                state="settled_applied",
                disposition=LoopTerminalDisposition.SUCCEEDED,
                outcome_description=(
                    "The exact approved journal has an authoritative GCE write journal, "
                    "an independent correlation-bound provider observation, and a "
                    "content-bound Spring settlement receipt."
                ),
                required_evidence_kinds=(
                    "journal_post_receipt",
                    "journal_applied_observation",
                    "applied_settlement_receipt",
                ),
            ),
            LoopTerminalState(
                state="failed_before_effect",
                disposition=LoopTerminalDisposition.FAILED,
                outcome_description=(
                    "The run failed before any governed provider effect was claimed."
                ),
                required_evidence_kinds=("failure_receipt",),
            ),
            LoopTerminalState(
                state="cancelled_before_dispatch",
                disposition=LoopTerminalDisposition.CANCELLED,
                outcome_description=(
                    "Spring rejected the undecided approval and proved that no exact "
                    "write journal or consumed approval existed."
                ),
                required_evidence_kinds=("cancellation_receipt",),
            ),
            LoopTerminalState(
                state="manual_reconciliation_required",
                disposition=LoopTerminalDisposition.RECONCILIATION_REQUIRED,
                outcome_description=(
                    "The effect or its independent evidence is not safe to settle; "
                    "automatic replay is fenced and the exact run is human-visible."
                ),
                required_evidence_kinds=("ambiguous_effect_receipt",),
            ),
        ),
    ),
    agent_role_refs=("accountant", "independent_finance_reviewer"),
    primitive_steps=(
        LoopPrimitiveStep(
            step_ref="discover_ledger_accounts",
            primitive_ref="finance.discover_ledger_accounts",
            primitive_version="2.0.0",
            agent_role_ref="accountant",
            effect=ConnectorEffect.READ,
            approval_required=False,
            tool_binding_refs=("ledger_account_read",),
            emits_event_ref="finance.ledger_accounts_discovered",
        ),
        LoopPrimitiveStep(
            step_ref="prepare_journal",
            primitive_ref="finance.prepare_journal_entry",
            primitive_version="1.0.0",
            agent_role_ref="accountant",
            effect=ConnectorEffect.DRAFT,
            approval_required=False,
            emits_event_ref="finance.journal_entry_prepared",
        ),
        LoopPrimitiveStep(
            step_ref="evaluate_journal_controls",
            primitive_ref="finance.evaluate_journal_entry_controls",
            primitive_version="1.0.0",
            agent_role_ref="independent_finance_reviewer",
            effect=ConnectorEffect.READ,
            approval_required=False,
            emits_event_ref="finance.journal_controls_passed",
        ),
        LoopPrimitiveStep(
            step_ref="post_approved_journal",
            primitive_ref="finance.post_journal_entry",
            primitive_version="2.0.0",
            agent_role_ref="accountant",
            effect=ConnectorEffect.WRITE,
            approval_required=True,
            tool_binding_refs=("journal_post",),
            emits_event_ref="finance.journal_post_reported",
        ),
        LoopPrimitiveStep(
            step_ref="reconcile_journal_post",
            primitive_ref="finance.reconcile_journal_post",
            primitive_version="2.0.0",
            agent_role_ref="independent_finance_reviewer",
            effect=ConnectorEffect.READ,
            approval_required=False,
            tool_binding_refs=("journal_readback",),
            emits_event_ref="finance.independent_readback_applied",
        ),
    ),
    tool_requirements=(
        LoopToolRequirement(
            binding_ref="ledger_account_read",
            acceptable_tools=("quickbooks.list_accounts",),
            effect=ConnectorEffect.READ,
            approval_required=False,
            connector_account_binding_required=True,
            idempotency_required=False,
            ambiguous_outcome_policy=AmbiguousOutcomePolicy.NOT_APPLICABLE,
        ),
        LoopToolRequirement(
            binding_ref="journal_post",
            acceptable_tools=("quickbooks.create_journal_entry",),
            effect=ConnectorEffect.WRITE,
            approval_required=True,
            connector_account_binding_required=True,
            idempotency_required=True,
            ambiguous_outcome_policy=AmbiguousOutcomePolicy.MANUAL_RECONCILIATION_NO_REPLAY,
        ),
        LoopToolRequirement(
            binding_ref="journal_readback",
            acceptable_tools=("quickbooks.get_journal_entry",),
            effect=ConnectorEffect.READ,
            approval_required=False,
            connector_account_binding_required=True,
            idempotency_required=False,
            ambiguous_outcome_policy=AmbiguousOutcomePolicy.NOT_APPLICABLE,
        ),
    ),
    artifact_requirements=(
        LoopArtifactRequirement(
            artifact_ref="approved_journal_candidate",
            evidence_kind="journal_candidate_digest",
            produced_by_agent_role_ref="accountant",
            accepted_by_role_ref="independent_finance_reviewer",
        ),
        LoopArtifactRequirement(
            artifact_ref="journal_post_receipt",
            evidence_kind="journal_post_receipt",
            produced_by_agent_role_ref="accountant",
            accepted_by_role_ref="independent_finance_reviewer",
        ),
        LoopArtifactRequirement(
            artifact_ref="journal_applied_observation",
            evidence_kind="journal_applied_observation",
            produced_by_agent_role_ref="independent_finance_reviewer",
            accepted_by_role_ref="accountant",
        ),
        LoopArtifactRequirement(
            artifact_ref="applied_settlement_receipt",
            evidence_kind="applied_settlement_receipt",
            produced_by_agent_role_ref="independent_finance_reviewer",
            accepted_by_role_ref="accountant",
        ),
    ),
    execution_policy=_execution_policy(),
    budget=LoopExecutionBudget(
        max_elapsed_seconds=14_400,
        max_cost_microusd=10_000_000,
        max_primitive_steps=50,
        max_agent_turns=20,
    ),
    completion_slo_seconds=14_400,
    outcome_metrics=(
        LoopOutcomeMetric(
            metric_ref="journal_applied_settlement_rate",
            direction="increase",
            unit="percent",
            source_system_ref="spring-business-outcomes-ledger",
            required_sample_count=30,
            measurement_window_seconds=2_592_000,
            certification_target="99",
            certification_comparison="at_least",
        ),
        LoopOutcomeMetric(
            metric_ref="duplicate_journal_effect_rate",
            direction="decrease",
            unit="percent",
            source_system_ref="spring-business-outcomes-ledger",
            required_sample_count=100,
            measurement_window_seconds=2_592_000,
            certification_target="0",
            certification_comparison="at_most",
        ),
    ),
    surfaces=_surface_projections(FINANCE_JOURNAL_WORKFLOW),
    harness_policy=_harness_policy(required=False),
    implementation=_implementation(FINANCE_JOURNAL_WORKFLOW),
    required_operational_readiness_gates=(
        "hosted_writes",
        "publication_recovery",
        "connector_conformance",
        "replay_guarantees",
        "service_levels",
        "incident_response",
        "business_outcomes",
    ),
    certification_tests=_certification_tests(
        "finance.journal_post_readback_settlement"
    ),
    known_blockers=(
        "The exact QuickBooks WRITE/READ pair lacks a production canary certification packet and operator countersignature.",
        "Xero remains outside this correlation-bound journal observation contract.",
        "The managed Finance Agent now projects canonical START, but the primary finance UI still composes a separate lifecycle.",
        "The V1873 pair-route authority has a fresh local PostgreSQL 17 fixture rehearsal, but no sandbox provider or deployed-topology rehearsal.",
        "No live QuickBooks canary or accountant-accepted outcome is recorded.",
    ),
)


SERVICE_CASE_VERIFIED_RESOLUTION = LoopCertificationManifest(
    loop_ref="service.case_customer_verified_resolution",
    version="0.3.0",
    title="Freshservice case to customer-confirmed, provider-verified closure",
    portfolio_domain=GoldenLoopPortfolioDomain.SERVICE_RETENTION,
    buyer="Customer support and customer success leadership",
    business_objective=(
        "Send one independently approved public Freshservice reply, observe a unique "
        "customer confirmation, obtain a separate closure approval, close the same "
        "ticket, and independently read back its closed provider state. This bounded "
        "contract does not claim customer retention or CSAT improvement."
    ),
    lifecycle=CapabilityLifecycleState.QUARANTINED,
    triggers=(
        LoopTrigger(
            trigger_ref="service.case_received",
            event_ref="service.case_received",
            description=(
                "A scoped, content-bound Freshservice resolution candidate enters the "
                "Spring-owned service-case authority."
            ),
            required_input_refs=(
                "candidate_ref",
                "candidate_sha256",
                "connector_account_ref",
                "ticket_ref",
                "requester_ref",
                "classification_sha256",
                "routing_sha256",
                "resolution_sha256",
                "contact_policy_decision_ref",
                "contact_policy_sha256",
                "contact_policy_expires_at",
                "reply_body",
                "idempotency_key",
            ),
        ),
    ),
    state_machine=LoopStateMachine(
        initial_state="reply_approval_pending",
        states=(
            "reply_approval_pending",
            "customer_confirmation_pending",
            "closure_approval_pending",
            "close_readback_pending",
            "closed_verified",
            "resolution_rejected",
            "closure_rejected",
            "customer_unreachable",
            "failed_before_effect",
            "manual_reconciliation_required",
            "cancelled_before_effect",
            "reopened",
        ),
        transitions=(
            LoopTransition(
                from_state="reply_approval_pending",
                event_ref="service.case_resolution.public_reply_observed",
                to_state="customer_confirmation_pending",
            ),
            LoopTransition(
                from_state="reply_approval_pending",
                event_ref="service.case_resolution.failed_before_effect",
                to_state="failed_before_effect",
            ),
            LoopTransition(
                from_state="reply_approval_pending",
                event_ref="service.case_resolution.cancelled_before_effect",
                to_state="cancelled_before_effect",
            ),
            LoopTransition(
                from_state="reply_approval_pending",
                event_ref="loop.effect_ambiguous",
                to_state="manual_reconciliation_required",
            ),
            LoopTransition(
                from_state="customer_confirmation_pending",
                event_ref="service.case_resolution.closure_approval_proposed",
                to_state="closure_approval_pending",
            ),
            LoopTransition(
                from_state="customer_confirmation_pending",
                event_ref="service.case_resolution.resolution_rejected",
                to_state="resolution_rejected",
            ),
            LoopTransition(
                from_state="customer_confirmation_pending",
                event_ref="service.case_resolution.customer_unreachable",
                to_state="customer_unreachable",
            ),
            LoopTransition(
                from_state="customer_confirmation_pending",
                event_ref="loop.effect_ambiguous",
                to_state="manual_reconciliation_required",
            ),
            LoopTransition(
                from_state="closure_approval_pending",
                event_ref="service.case_resolution.close_accepted",
                to_state="close_readback_pending",
            ),
            LoopTransition(
                from_state="closure_approval_pending",
                event_ref="service.case_resolution.closure_rejected",
                to_state="closure_rejected",
            ),
            LoopTransition(
                from_state="closure_approval_pending",
                event_ref="loop.effect_ambiguous",
                to_state="manual_reconciliation_required",
            ),
            LoopTransition(
                from_state="close_readback_pending",
                event_ref="service.case_resolution.closed_verified",
                to_state="closed_verified",
            ),
            LoopTransition(
                from_state="close_readback_pending",
                event_ref="service.case_resolution.reopened",
                to_state="reopened",
            ),
            LoopTransition(
                from_state="close_readback_pending",
                event_ref="loop.effect_ambiguous",
                to_state="manual_reconciliation_required",
            ),
        ),
        terminal_states=(
            LoopTerminalState(
                state="closed_verified",
                disposition=LoopTerminalDisposition.SUCCEEDED,
                outcome_description=(
                    "The customer confirmation is causally bound to the approved public "
                    "reply, the same ticket was independently approved for closure, and "
                    "a post-write Freshservice readback proves it closed."
                ),
                required_evidence_kinds=(
                    "reply_approval_receipt",
                    "public_reply_write_receipt",
                    "customer_confirmation_observation",
                    "closure_approval_receipt",
                    "ticket_close_write_receipt",
                    "provider_close_readback",
                    "service_case_resolution_receipt",
                ),
            ),
            LoopTerminalState(
                state="resolution_rejected",
                disposition=LoopTerminalDisposition.FAILED,
                outcome_description="The customer explicitly rejected or reopened the proposed resolution.",
                required_evidence_kinds=("service_case_resolution_receipt",),
            ),
            LoopTerminalState(
                state="closure_rejected",
                disposition=LoopTerminalDisposition.FAILED,
                outcome_description="The independent closure approval was rejected or expired.",
                required_evidence_kinds=("service_case_resolution_receipt",),
            ),
            LoopTerminalState(
                state="customer_unreachable",
                disposition=LoopTerminalDisposition.FAILED,
                outcome_description="No unique customer confirmation was observed within the bounded window.",
                required_evidence_kinds=("service_case_resolution_receipt",),
            ),
            LoopTerminalState(
                state="failed_before_effect",
                disposition=LoopTerminalDisposition.FAILED,
                outcome_description="The run failed before a public reply provider effect was safely claimed.",
                required_evidence_kinds=("service_case_resolution_receipt",),
            ),
            LoopTerminalState(
                state="reopened",
                disposition=LoopTerminalDisposition.FAILED,
                outcome_description="A post-close provider readback proves the ticket was reopened.",
                required_evidence_kinds=("service_case_resolution_receipt",),
            ),
            LoopTerminalState(
                state="cancelled_before_effect",
                disposition=LoopTerminalDisposition.CANCELLED,
                outcome_description="Spring rejected the undecided reply approval before any public reply write.",
                required_evidence_kinds=("service_case_resolution_receipt",),
            ),
            LoopTerminalState(
                state="manual_reconciliation_required",
                disposition=LoopTerminalDisposition.RECONCILIATION_REQUIRED,
                outcome_description=(
                    "A reply, close, or observation outcome is unsafe to replay; the "
                    "exact run is terminal and human-visible for reconciliation."
                ),
                required_evidence_kinds=("service_case_resolution_receipt",),
            ),
        ),
    ),
    agent_role_refs=("service_agent", "customer_outcome_verifier"),
    primitive_steps=(
        LoopPrimitiveStep(
            step_ref="intake_and_classify",
            primitive_ref="service.intake_and_classify_case",
            primitive_version="1.0.0",
            agent_role_ref="service_agent",
            effect=ConnectorEffect.READ,
            approval_required=False,
            tool_binding_refs=("ticket_read",),
            emits_event_ref="service.case_resolution.reply_approval_proposed",
        ),
        LoopPrimitiveStep(
            step_ref="route_and_escalate",
            primitive_ref="service.route_and_escalate_case",
            primitive_version="1.0.0",
            agent_role_ref="service_agent",
            effect=ConnectorEffect.READ,
            approval_required=False,
            emits_event_ref="service.case_assigned_or_escalated",
        ),
        LoopPrimitiveStep(
            step_ref="submit_resolution",
            primitive_ref="service.submit_resolution_for_verification",
            primitive_version="1.0.0",
            agent_role_ref="service_agent",
            effect=ConnectorEffect.DRAFT,
            approval_required=False,
            emits_event_ref="service.resolution_submitted",
        ),
        LoopPrimitiveStep(
            step_ref="evaluate_resolution_controls",
            primitive_ref="service.evaluate_case_resolution_controls",
            primitive_version="1.0.0",
            agent_role_ref="customer_outcome_verifier",
            effect=ConnectorEffect.READ,
            approval_required=False,
            emits_event_ref="service.resolution_controls_evaluated",
        ),
        LoopPrimitiveStep(
            step_ref="verify_customer_confirmation",
            primitive_ref="service.verify_case_resolution",
            primitive_version="1.0.0",
            agent_role_ref="customer_outcome_verifier",
            effect=ConnectorEffect.READ,
            approval_required=False,
            tool_binding_refs=("customer_confirmation_observer",),
            emits_event_ref="service.case_resolution.closure_approval_proposed",
        ),
        LoopPrimitiveStep(
            step_ref="propose_resolution_authorization",
            primitive_ref="service.propose_remedy_authorization",
            primitive_version="1.0.0",
            agent_role_ref="service_agent",
            effect=ConnectorEffect.DRAFT,
            approval_required=True,
            emits_event_ref="service.resolution_authorization_proposed",
        ),
    ),
    tool_requirements=(
        LoopToolRequirement(
            binding_ref="ticket_read",
            acceptable_tools=("freshservice.get_ticket",),
            effect=ConnectorEffect.READ,
            approval_required=False,
            connector_account_binding_required=True,
            idempotency_required=False,
            ambiguous_outcome_policy=AmbiguousOutcomePolicy.NOT_APPLICABLE,
        ),
        LoopToolRequirement(
            binding_ref="public_reply_write",
            acceptable_tools=("freshservice.reply_ticket_public",),
            effect=ConnectorEffect.WRITE,
            approval_required=True,
            connector_account_binding_required=True,
            idempotency_required=True,
            ambiguous_outcome_policy=AmbiguousOutcomePolicy.MANUAL_RECONCILIATION_NO_REPLAY,
        ),
        LoopToolRequirement(
            binding_ref="customer_confirmation_observer",
            acceptable_tools=("freshservice.observe_customer_confirmation",),
            effect=ConnectorEffect.READ,
            approval_required=False,
            connector_account_binding_required=True,
            idempotency_required=False,
            ambiguous_outcome_policy=AmbiguousOutcomePolicy.NOT_APPLICABLE,
        ),
        LoopToolRequirement(
            binding_ref="ticket_close_write",
            acceptable_tools=("freshservice.close_ticket",),
            effect=ConnectorEffect.WRITE,
            approval_required=True,
            connector_account_binding_required=True,
            idempotency_required=True,
            ambiguous_outcome_policy=AmbiguousOutcomePolicy.MANUAL_RECONCILIATION_NO_REPLAY,
        ),
        LoopToolRequirement(
            binding_ref="ticket_close_readback",
            acceptable_tools=("freshservice.get_ticket_status",),
            effect=ConnectorEffect.READ,
            approval_required=False,
            connector_account_binding_required=True,
            idempotency_required=False,
            ambiguous_outcome_policy=AmbiguousOutcomePolicy.NOT_APPLICABLE,
        ),
    ),
    artifact_requirements=(
        LoopArtifactRequirement(
            artifact_ref="service_case_candidate",
            evidence_kind="candidate_sha256",
            produced_by_agent_role_ref="service_agent",
            accepted_by_role_ref="customer_outcome_verifier",
        ),
        LoopArtifactRequirement(
            artifact_ref="ticket_snapshot",
            evidence_kind="ticket_read_receipt",
            produced_by_agent_role_ref="service_agent",
            accepted_by_role_ref="customer_outcome_verifier",
        ),
        LoopArtifactRequirement(
            artifact_ref="approved_public_reply",
            evidence_kind="reply_approval_receipt",
            produced_by_agent_role_ref="customer_outcome_verifier",
            accepted_by_role_ref="service_agent",
        ),
        LoopArtifactRequirement(
            artifact_ref="public_reply_delivery",
            evidence_kind="public_reply_write_receipt",
            produced_by_agent_role_ref="service_agent",
            accepted_by_role_ref="customer_outcome_verifier",
        ),
        LoopArtifactRequirement(
            artifact_ref="customer_confirmation",
            evidence_kind="customer_confirmation_observation",
            produced_by_agent_role_ref="customer_outcome_verifier",
            accepted_by_role_ref="service_agent",
        ),
        LoopArtifactRequirement(
            artifact_ref="closure_authorization",
            evidence_kind="closure_approval_receipt",
            produced_by_agent_role_ref="customer_outcome_verifier",
            accepted_by_role_ref="service_agent",
        ),
        LoopArtifactRequirement(
            artifact_ref="ticket_close_delivery",
            evidence_kind="ticket_close_write_receipt",
            produced_by_agent_role_ref="service_agent",
            accepted_by_role_ref="customer_outcome_verifier",
        ),
        LoopArtifactRequirement(
            artifact_ref="ticket_close_readback",
            evidence_kind="provider_close_readback",
            produced_by_agent_role_ref="customer_outcome_verifier",
            accepted_by_role_ref="service_agent",
        ),
        LoopArtifactRequirement(
            artifact_ref="service_resolution_receipt",
            evidence_kind="service_case_resolution_receipt",
            produced_by_agent_role_ref="customer_outcome_verifier",
            accepted_by_role_ref="service_agent",
        ),
    ),
    execution_policy=_execution_policy(),
    budget=LoopExecutionBudget(
        max_elapsed_seconds=604_800,
        max_cost_microusd=25_000_000,
        max_primitive_steps=100,
        max_agent_turns=50,
    ),
    completion_slo_seconds=604_800,
    outcome_metrics=(
        LoopOutcomeMetric(
            metric_ref="customer_confirmed_provider_closed_rate",
            direction="increase",
            unit="percent",
            source_system_ref="spring-business-outcomes-ledger",
            required_sample_count=30,
            measurement_window_seconds=7_776_000,
            certification_target="90",
            certification_comparison="at_least",
        ),
        LoopOutcomeMetric(
            metric_ref="time_to_customer_confirmed_provider_close_seconds",
            direction="decrease",
            unit="seconds",
            source_system_ref="spring-business-outcomes-ledger",
            required_sample_count=30,
            measurement_window_seconds=7_776_000,
            certification_target="604800",
            certification_comparison="at_most",
        ),
        LoopOutcomeMetric(
            metric_ref="case_reopen_rate",
            direction="decrease",
            unit="percent",
            source_system_ref="spring-business-outcomes-ledger",
            required_sample_count=30,
            measurement_window_seconds=7_776_000,
            certification_target="10",
            certification_comparison="at_most",
        ),
        LoopOutcomeMetric(
            metric_ref="service_manual_reconciliation_rate",
            direction="decrease",
            unit="percent",
            source_system_ref="spring-business-outcomes-ledger",
            required_sample_count=30,
            measurement_window_seconds=7_776_000,
            certification_target="5",
            certification_comparison="at_most",
        ),
    ),
    surfaces=_surface_projections(SERVICE_VERIFIED_RESOLUTION_WORKFLOW),
    harness_policy=_harness_policy(required=False),
    implementation=_implementation(SERVICE_VERIFIED_RESOLUTION_WORKFLOW),
    required_operational_readiness_gates=(
        "publication_recovery",
        "connector_conformance",
        "transport_recovery",
        "replay_guarantees",
        "service_levels",
        "incident_response",
        "business_outcomes",
    ),
    certification_tests=_certification_tests(
        "service.case_customer_verified_resolution"
    ),
    known_blockers=(
        "A narrow reviewed HTTP GovernedFreshserviceTransport is source-complete and default-dark; no admitted provider-pair route or sandbox conformance packet is available.",
        "The current V1872 PostgreSQL integration report is skipped, so the exact current-source database authority still lacks a retained fresh-PostgreSQL pass.",
        "No multi-replica, restart, or lost-response rehearsal has run against a real Freshservice sandbox.",
        "Production continuation remains hard-disabled pending transport and topology evidence.",
        "No live Freshservice canary, customer-confirmed outcome sample, cost, or completion SLO is recorded.",
    ),
)


CONTROLLED_SPEND_MATCHED_CLOSE = LoopCertificationManifest(
    loop_ref="procurement.approved_commitment_to_matched_close",
    version="0.3.0",
    title="Approved spend commitment to independently matched procurement close",
    portfolio_domain=GoldenLoopPortfolioDomain.FINANCE_OPERATIONS,
    buyer="Finance leadership, procurement leadership, and operating executives",
    business_objective=(
        "Approve a bounded requisition before commitment, issue one content-bound purchase "
        "order, retain goods-receipt evidence, independently three-way match the supplier "
        "invoice, and close only the matched procurement obligation. This contract does not "
        "claim supplier payment or cash settlement."
    ),
    lifecycle=CapabilityLifecycleState.QUARANTINED,
    triggers=(
        LoopTrigger(
            trigger_ref="procurement.requisition_requested",
            event_ref="procurement.requisition_requested",
            description="A scoped company need has a bounded supplier and budget proposal.",
            required_input_refs=(
                "requisition_ref", "supplier_ref", "cost_center_ref", "currency",
                "requested_lines", "budget_policy_ref",
            ),
        ),
    ),
    state_machine=_bounded_state_machine(
        (
            ("requisition_draft", "procurement.requisition_submitted"),
            ("requisition_pending_approval", "procurement.requisition_approved"),
            ("spend_commitment_approved", "procurement.purchase_order_issued"),
            ("purchase_order_issued", "procurement.goods_fully_received"),
            ("goods_received", "procurement.three_way_match_verified"),
        ),
        success_state="matched_procurement_closed",
        success_evidence=(
            "approved_spend_commitment", "issued_purchase_order",
            "purchase_order_provider_readback", "goods_receipt_evidence",
            "supplier_invoice_evidence", "three_way_match_evidence",
            "procurement_close_receipt",
        ),
    ),
    agent_role_refs=(
        "procurement_operator",
        "independent_spend_approver",
        "independent_procurement_close_reviewer",
    ),
    primitive_steps=(
        LoopPrimitiveStep(
            step_ref="plan_governed_procurement_lifecycle",
            primitive_ref="procurement.plan_approved_commitment_to_matched_close",
            primitive_version="0.3.0",
            agent_role_ref="procurement_operator",
            effect=ConnectorEffect.READ,
            approval_required=True,
            emits_event_ref="procurement.approved_commitment_stage_planned",
        ),
    ),
    tool_requirements=(
        LoopToolRequirement(
            binding_ref="xero_purchase_order_write",
            acceptable_tools=("xero.create_purchase_order",),
            effect=ConnectorEffect.WRITE,
            approval_required=True,
            connector_account_binding_required=True,
            idempotency_required=True,
            ambiguous_outcome_policy=(
                AmbiguousOutcomePolicy.MANUAL_RECONCILIATION_NO_REPLAY
            ),
        ),
        LoopToolRequirement(
            binding_ref="xero_purchase_order_readback",
            acceptable_tools=("xero.get_purchase_order",),
            effect=ConnectorEffect.READ,
            approval_required=False,
            connector_account_binding_required=True,
            idempotency_required=False,
            ambiguous_outcome_policy=AmbiguousOutcomePolicy.NOT_APPLICABLE,
        ),
    ),
    artifact_requirements=_artifacts(
        "procurement_operator",
        ("approved_spend_commitment", "approved_spend_commitment", "independent_spend_approver"),
        ("issued_purchase_order", "issued_purchase_order", "independent_procurement_close_reviewer"),
        ("purchase_order_provider_readback", "purchase_order_provider_readback", "independent_procurement_close_reviewer"),
        ("goods_receipt_package", "goods_receipt_evidence", "independent_procurement_close_reviewer"),
        ("supplier_invoice_package", "supplier_invoice_evidence", "independent_procurement_close_reviewer"),
        ("matched_supplier_invoice", "three_way_match_evidence", "independent_procurement_close_reviewer"),
        ("procurement_close_receipt", "procurement_close_receipt", "independent_procurement_close_reviewer"),
    ),
    execution_policy=_execution_policy(),
    budget=LoopExecutionBudget(
        max_elapsed_seconds=7_776_000,
        max_cost_microusd=25_000_000,
        max_primitive_steps=128,
        max_agent_turns=64,
    ),
    completion_slo_seconds=7_776_000,
    outcome_metrics=(
        LoopOutcomeMetric(
            metric_ref="spend_policy_compliance_rate", direction="increase", unit="percent",
            source_system_ref="spring-business-outcomes-ledger", required_sample_count=30,
            measurement_window_seconds=15_552_000,
            certification_target="95", certification_comparison="at_least",
        ),
        LoopOutcomeMetric(
            metric_ref="matched_procurement_close_rate", direction="increase", unit="percent",
            source_system_ref="spring-business-outcomes-ledger", required_sample_count=30,
            measurement_window_seconds=15_552_000,
            certification_target="90", certification_comparison="at_least",
        ),
        LoopOutcomeMetric(
            metric_ref="duplicate_purchase_order_effect_rate", direction="decrease", unit="percent",
            source_system_ref="spring-business-outcomes-ledger", required_sample_count=100,
            measurement_window_seconds=15_552_000,
            certification_target="0", certification_comparison="at_most",
        ),
    ),
    surfaces=_surface_projections(CONTROL_SPEND_WORKFLOW),
    harness_policy=_harness_policy(required=False),
    implementation=_implementation(CONTROL_SPEND_WORKFLOW),
    required_operational_readiness_gates=(
        "publication_recovery", "connector_conformance", "transport_recovery",
        "replay_guarantees", "service_levels", "incident_response", "business_outcomes",
    ),
    certification_tests=_certification_tests(
        "procurement.approved_commitment_to_matched_close"
    ),
    known_blockers=(
        "V1917 source custody and customer-outcome/provider facts have a retained fresh-PostgreSQL local migration pass; this is not deployed or provider evidence.",
        "No live Xero provider-pair canary, lost-response rehearsal, or multi-replica recovery packet is retained.",
        "Dedicated authenticated REST, synchronous and asynchronous SDK, 14 host-neutral MCP tools, the managed-Agent projection, and optional ChatGPT dispatch are source-complete locally over one Spring Procurement authority; current-source focused and fresh-PostgreSQL checks are retained, but deployed-host evidence remains absent and none is production-promoted.",
        "No design-partner outcome cohort satisfies the declared sample counts or completion SLO.",
    ),
)


_PERIOD_RECONCILIATION_STATES_AND_EVENTS = (
    ("period_open_evidence_pending", "finance.period_open_evidence_validated"),
    ("period_open_validated", "finance.trial_balance_validated"),
    ("trial_balance_validated", "finance.reconciliations_validated"),
    ("reconciliations_validated", "finance.exception_disposition_retained"),
    (
        "exception_disposition_retained",
        "finance.reconciliation_evidence_custody_sealed",
    ),
    (
        "reconciliation_evidence_custody_sealed",
        "finance.approved_close_review_packet_retained",
    ),
    (
        "approved_close_review_packet_retained",
        "finance.close_approval_validated",
    ),
)


PERIOD_RECONCILIATION_APPROVED_CLOSE_CANDIDATE_V0_3 = LoopCertificationManifest(
    loop_ref="finance.period_reconciliation_approved_close_candidate",
    version="0.3.0",
    title="Complete period reconciliation to independently approved close candidate",
    portfolio_domain=GoldenLoopPortfolioDomain.FINANCE_OPERATIONS,
    buyer="Controller, finance leadership, and independent close reviewers",
    business_objective=(
        "Bind the exact trial balance, retained journal/subledger/cash/AR/AP evidence, "
        "deterministic variance and exception disposition, a source-bound custody/review "
        "packet, and independent approval into one close candidate. This does not claim a "
        "provider write, subledger lock, consolidation action, or closed ledger period."
    ),
    lifecycle=CapabilityLifecycleState.QUARANTINED,
    triggers=(
        LoopTrigger(
            trigger_ref="finance.period_close_requested",
            event_ref="finance.period_close_requested",
            description="A fiscal period ended and its exact ledger scope is ready for review.",
            required_input_refs=(
                "fiscal_period_ref", "ledger_ref", "entity_or_group_ref",
                "currency", "materiality_policy_ref", "close_calendar_ref",
            ),
        ),
    ),
    state_machine=_bounded_state_machine(
        _PERIOD_RECONCILIATION_STATES_AND_EVENTS,
        success_state="approved_close_candidate",
        success_evidence=(
            "period_calendar", "trial_balance_extract", "reconciled_period_books",
            "bounded_exception_disposition", "reconciliation_evidence_custody_seal",
            "approved_close_review_packet", "independent_close_approval",
        ),
    ),
    agent_role_refs=("accountant", "independent_finance_reviewer"),
    primitive_steps=(
        LoopPrimitiveStep(
            step_ref="bind_exact_period_and_scope",
            primitive_ref="finance.propose_period_close_transition",
            primitive_version="1.1.0",
            agent_role_ref="accountant",
            effect=ConnectorEffect.READ,
            approval_required=False,
            emits_event_ref="finance.period_scope_bound",
        ),
        LoopPrimitiveStep(
            step_ref="evaluate_source_bound_period_reconciliation",
            primitive_ref="finance.evaluate_period_reconciliation",
            primitive_version="0.3.0",
            agent_role_ref="accountant",
            effect=ConnectorEffect.READ,
            approval_required=False,
            tool_binding_refs=(
                "quickbooks_trial_balance_read",
                "quickbooks_balance_sheet_read",
                "quickbooks_cash_flow_read",
                "quickbooks_aged_receivable_read",
                "quickbooks_aged_payable_read",
            ),
            emits_event_ref="finance.period_reconciliation_evaluated",
        ),
        LoopPrimitiveStep(
            step_ref="independently_review_approved_close_candidate",
            primitive_ref="finance.evaluate_period_close_readiness",
            primitive_version="1.0.0",
            agent_role_ref="independent_finance_reviewer",
            effect=ConnectorEffect.READ,
            approval_required=True,
            emits_event_ref="finance.close_approval_validated",
        ),
    ),
    tool_requirements=(
        LoopToolRequirement(
            binding_ref="quickbooks_trial_balance_read",
            acceptable_tools=("quickbooks.trial_balance_report",),
            effect=ConnectorEffect.READ,
            approval_required=False,
            connector_account_binding_required=True,
            idempotency_required=False,
            ambiguous_outcome_policy=AmbiguousOutcomePolicy.NOT_APPLICABLE,
        ),
        LoopToolRequirement(
            binding_ref="quickbooks_balance_sheet_read",
            acceptable_tools=("quickbooks.balance_sheet_report",),
            effect=ConnectorEffect.READ,
            approval_required=False,
            connector_account_binding_required=True,
            idempotency_required=False,
            ambiguous_outcome_policy=AmbiguousOutcomePolicy.NOT_APPLICABLE,
        ),
        LoopToolRequirement(
            binding_ref="quickbooks_cash_flow_read",
            acceptable_tools=("quickbooks.cash_flow_report",),
            effect=ConnectorEffect.READ,
            approval_required=False,
            connector_account_binding_required=True,
            idempotency_required=False,
            ambiguous_outcome_policy=AmbiguousOutcomePolicy.NOT_APPLICABLE,
        ),
        LoopToolRequirement(
            binding_ref="quickbooks_aged_receivable_read",
            acceptable_tools=("quickbooks.aged_receivable_report",),
            effect=ConnectorEffect.READ,
            approval_required=False,
            connector_account_binding_required=True,
            idempotency_required=False,
            ambiguous_outcome_policy=AmbiguousOutcomePolicy.NOT_APPLICABLE,
        ),
        LoopToolRequirement(
            binding_ref="quickbooks_aged_payable_read",
            acceptable_tools=("quickbooks.aged_payable_report",),
            effect=ConnectorEffect.READ,
            approval_required=False,
            connector_account_binding_required=True,
            idempotency_required=False,
            ambiguous_outcome_policy=AmbiguousOutcomePolicy.NOT_APPLICABLE,
        ),
    ),
    artifact_requirements=_artifacts(
        "accountant",
        ("exact_period_scope", "period_calendar", "independent_finance_reviewer"),
        ("period_open_evidence", "period_open_evidence", "independent_finance_reviewer"),
        ("trial_balance_package", "trial_balance_extract", "independent_finance_reviewer"),
        ("journal_subledger_cash_ar_ap_package", "reconciled_period_books", "independent_finance_reviewer"),
        ("bounded_exception_disposition", "bounded_exception_disposition", "independent_finance_reviewer"),
        ("reconciliation_evidence_custody_seal", "reconciliation_evidence_custody_seal", "independent_finance_reviewer"),
        ("approved_close_review_packet", "approved_close_review_packet", "independent_finance_reviewer"),
        ("approved_close_candidate", "independent_close_approval", "independent_finance_reviewer"),
    ),
    execution_policy=_execution_policy(),
    budget=LoopExecutionBudget(
        max_elapsed_seconds=1_209_600,
        max_cost_microusd=50_000_000,
        max_primitive_steps=80,
        max_agent_turns=80,
    ),
    completion_slo_seconds=1_209_600,
    outcome_metrics=(
        LoopOutcomeMetric(
            metric_ref="period_reconciliation_completion_rate", direction="increase", unit="percent",
            source_system_ref="spring-business-outcomes-ledger", required_sample_count=12,
            measurement_window_seconds=31_536_000,
            certification_target="95", certification_comparison="at_least",
        ),
        LoopOutcomeMetric(
            metric_ref="unreconciled_balance_rate", direction="decrease", unit="percent",
            source_system_ref="spring-business-outcomes-ledger", required_sample_count=12,
            measurement_window_seconds=31_536_000,
            certification_target="5", certification_comparison="at_most",
        ),
        LoopOutcomeMetric(
            metric_ref="time_to_approved_close_candidate_seconds", direction="decrease", unit="seconds",
            source_system_ref="spring-business-outcomes-ledger", required_sample_count=12,
            measurement_window_seconds=31_536_000,
            certification_target="1209600", certification_comparison="at_most",
        ),
    ),
    surfaces=_surface_projections(PERIOD_RECONCILIATION_WORKFLOW_V0_3),
    harness_policy=_harness_policy(required=False),
    implementation=_implementation(PERIOD_RECONCILIATION_WORKFLOW_V0_3),
    required_operational_readiness_gates=(
        "publication_recovery", "connector_conformance", "transport_recovery",
        "replay_guarantees", "service_levels", "incident_response",
        "business_outcomes",
    ),
    certification_tests=_certification_tests(
        "finance.period_reconciliation_approved_close_candidate"
    ),
    known_blockers=(
        "Canonical Period source and successor authority depends on quarantined migrations "
        "and unavailable finance settlement/certification evidence; Agents, SDK, MCP, and "
        "ChatGPT lifecycle projections are blocked with "
        "golden_loop.finance.canonical_runtime_not_bound.",
        "QuickBooks report READ conformance remains applicable; no live provider read canary or retained production close packet exists.",
        "Provider write and ambiguous provider-write gates are explicitly not applicable because this loop neither closes books nor dispatches a ledger write.",
        "No retained current-source or fresh-PostgreSQL Period authority pass applies to this candidate; the closed Spring routes perform no scope, database, connector, or provider access.",
        "No design-partner monthly-close cohort satisfies the three declared measured-outcome sample counts.",
    ),
)

_period_reconciliation_v0_4_payload = (
    PERIOD_RECONCILIATION_APPROVED_CLOSE_CANDIDATE_V0_3.model_dump(
        mode="python",
        exclude={"declaration_digest"},
    )
)
_period_reconciliation_v0_4_payload.update(
    version="0.4.0",
    state_machine=_bounded_state_machine(
        _PERIOD_RECONCILIATION_STATES_AND_EVENTS,
        success_state="approved_close_candidate",
        success_evidence=(
            "period_calendar",
            "trial_balance_extract",
            "reconciled_period_books",
            "bounded_exception_disposition",
            "reconciliation_evidence_custody_seal",
            "approved_close_review_packet",
            "independent_close_approval",
        ),
        ambiguous_effect_applicable=False,
    ),
    execution_policy=LoopExecutionPolicy(),
    surfaces=_surface_projections(PERIOD_RECONCILIATION_WORKFLOW),
    implementation=_implementation(PERIOD_RECONCILIATION_WORKFLOW),
)
PERIOD_RECONCILIATION_APPROVED_CLOSE_CANDIDATE = (
    LoopCertificationManifest.model_validate(_period_reconciliation_v0_4_payload)
)
del _period_reconciliation_v0_4_payload


VERIFIED_EVIDENCE_TO_PUBLISH_APPROVAL = LoopCertificationManifest(
    loop_ref="workflow.verified_evidence_to_publish_approval",
    version="0.3.0",
    title="Verified operating evidence to independently approved capability publication",
    portfolio_domain=GoldenLoopPortfolioDomain.PRODUCT_DELIVERY,
    buyer="Company operators, product leadership, and capability owners",
    business_objective=(
        "Convert retained outcome evidence into one bounded improvement packet, implement it "
        "through the selected coding harness, independently verify acceptance and staging canary "
        "results, and terminalize at a separate publish approval. Deployment remains a separate "
        "human decision and is not claimed."
    ),
    lifecycle=CapabilityLifecycleState.QUARANTINED,
    triggers=(
        LoopTrigger(
            trigger_ref="workflow.verified_outcome_gap_detected",
            event_ref="workflow.verified_outcome_gap_detected",
            description="Retained loop outcomes show a bounded, measurable capability gap.",
            required_input_refs=(
                "measurement_set_id",
                "project_scope_ref",
            ),
        ),
    ),
    state_machine=_bounded_state_machine(
        (
            ("verified_gap_identified", "workflow.improvement_packet_proposed"),
            ("packet_proposed", "workflow.implementation_approved"),
            ("implementation_approved", "workflow.harness_artifact_returned"),
            ("artifact_returned", "workflow.independent_acceptance_recorded"),
            ("independent_acceptance_recorded", "workflow.staging_canary_passed"),
            ("staging_canary_passed", "workflow.publish_approved"),
        ),
        success_state="capability_publish_approved",
        success_evidence=(
            "verified_outcome_evidence", "improvement_work_packet",
            "implementation_approval_receipt", "signed_harness_lifecycle_receipts",
            "builder_artifact_evidence", "independent_evaluator_verdict",
            "staging_canary_comparison", "separate_publish_approval",
            "approved_publication_candidate",
        ),
    ),
    agent_role_refs=(
        "improvement_operator", "project_agent", "implementation_approver",
        "builder", "independent_evaluator", "canary_evaluator",
        "publish_approver",
    ),
    primitive_steps=(
        LoopPrimitiveStep(
            step_ref="plan_evidence_bound_improvement",
            primitive_ref="learning.plan_optimization_sweep",
            primitive_version="1.0.0",
            agent_role_ref="improvement_operator",
            effect=ConnectorEffect.READ,
            approval_required=False,
            emits_event_ref="learning.optimization_sweep_planned",
        ),
        LoopPrimitiveStep(
            step_ref="create_bounded_work_packet",
            primitive_ref="project.create_work_packet",
            primitive_version="1.0.0",
            agent_role_ref="project_agent",
            effect=ConnectorEffect.READ,
            approval_required=True,
            emits_event_ref="workflow.improvement_packet_proposed",
        ),
        LoopPrimitiveStep(
            step_ref="approve_bounded_implementation",
            primitive_ref="approval.request_decision",
            primitive_version="1.0.0",
            agent_role_ref="implementation_approver",
            effect=ConnectorEffect.READ,
            approval_required=True,
            emits_event_ref="workflow.implementation_approved",
        ),
        LoopPrimitiveStep(
            step_ref="execute_in_user_selected_harness",
            primitive_ref="project.execute_approved_work_packet",
            primitive_version="1.0.0",
            agent_role_ref="builder",
            effect=ConnectorEffect.READ,
            approval_required=True,
            emits_event_ref="workflow.harness_artifact_returned",
        ),
        LoopPrimitiveStep(
            step_ref="independently_evaluate_artifact",
            primitive_ref="project.evaluate_work_packet_artifact",
            primitive_version="1.0.0",
            agent_role_ref="independent_evaluator",
            effect=ConnectorEffect.READ,
            approval_required=False,
            emits_event_ref="workflow.independent_acceptance_recorded",
        ),
        LoopPrimitiveStep(
            step_ref="evaluate_source_bound_staging_canary",
            primitive_ref="workflow.evaluate_staging_canary",
            primitive_version="1.0.0",
            agent_role_ref="canary_evaluator",
            effect=ConnectorEffect.READ,
            approval_required=False,
            emits_event_ref="workflow.staging_canary_passed",
        ),
        LoopPrimitiveStep(
            step_ref="approve_publication_candidate",
            primitive_ref="approval.request_decision",
            primitive_version="1.0.0",
            agent_role_ref="publish_approver",
            effect=ConnectorEffect.READ,
            approval_required=True,
            emits_event_ref="workflow.publish_approved",
        ),
    ),
    artifact_requirements=(
        LoopArtifactRequirement(
            artifact_ref="verified_outcome_evidence",
            evidence_kind="verified_outcome_evidence",
            produced_by_agent_role_ref="improvement_operator",
            accepted_by_role_ref="independent_evaluator",
        ),
        LoopArtifactRequirement(
            artifact_ref="improvement_work_packet",
            evidence_kind="improvement_work_packet",
            produced_by_agent_role_ref="project_agent",
            accepted_by_role_ref="independent_evaluator",
        ),
        LoopArtifactRequirement(
            artifact_ref="implementation_approval",
            evidence_kind="implementation_approval_receipt",
            produced_by_agent_role_ref="implementation_approver",
            accepted_by_role_ref="project_agent",
        ),
        LoopArtifactRequirement(
            artifact_ref="signed_harness_receipt_set",
            evidence_kind="signed_harness_lifecycle_receipts",
            produced_by_agent_role_ref="builder",
            accepted_by_role_ref="independent_evaluator",
        ),
        LoopArtifactRequirement(
            artifact_ref="builder_artifact_package",
            evidence_kind="builder_artifact_evidence",
            produced_by_agent_role_ref="builder",
            accepted_by_role_ref="independent_evaluator",
        ),
        LoopArtifactRequirement(
            artifact_ref="independent_evaluator_verdict",
            evidence_kind="independent_evaluator_verdict",
            produced_by_agent_role_ref="independent_evaluator",
            accepted_by_role_ref="project_agent",
        ),
        LoopArtifactRequirement(
            artifact_ref="staging_canary_comparison",
            evidence_kind="staging_canary_comparison",
            produced_by_agent_role_ref="canary_evaluator",
            accepted_by_role_ref="publish_approver",
        ),
        LoopArtifactRequirement(
            artifact_ref="publish_approval",
            evidence_kind="separate_publish_approval",
            produced_by_agent_role_ref="publish_approver",
            accepted_by_role_ref="independent_evaluator",
        ),
        LoopArtifactRequirement(
            artifact_ref="approved_publication_candidate",
            evidence_kind="approved_publication_candidate",
            produced_by_agent_role_ref="project_agent",
            accepted_by_role_ref="publish_approver",
        ),
    ),
    execution_policy=_execution_policy(),
    budget=LoopExecutionBudget(
        max_elapsed_seconds=1_209_600,
        max_cost_microusd=100_000_000,
        max_primitive_steps=200,
        max_agent_turns=200,
    ),
    completion_slo_seconds=1_209_600,
    outcome_metrics=(
        LoopOutcomeMetric(
            metric_ref="verified_improvement_adoption_rate", direction="increase", unit="percent",
            source_system_ref="spring-business-outcomes-ledger", required_sample_count=12,
            measurement_window_seconds=15_552_000,
            certification_target="80", certification_comparison="at_least",
        ),
        LoopOutcomeMetric(
            metric_ref="artifact_correction_rate", direction="decrease", unit="percent",
            source_system_ref="spring-business-outcomes-ledger", required_sample_count=30,
            measurement_window_seconds=15_552_000,
            certification_target="20", certification_comparison="at_most",
        ),
        LoopOutcomeMetric(
            metric_ref="time_to_publish_approval_seconds", direction="decrease", unit="seconds",
            source_system_ref="spring-business-outcomes-ledger", required_sample_count=12,
            measurement_window_seconds=15_552_000,
            certification_target="1209600", certification_comparison="at_most",
        ),
    ),
    surfaces=_surface_projections(VERIFIED_IMPROVEMENT_WORKFLOW),
    harness_policy=_harness_policy(required=True),
    implementation=_implementation(VERIFIED_IMPROVEMENT_WORKFLOW),
    required_operational_readiness_gates=(
        "publication_recovery", "transport_recovery", "replay_guarantees",
        "service_levels", "incident_response", "business_outcomes",
    ),
    certification_tests=_certification_tests(
        "workflow.verified_evidence_to_publish_approval"
    ),
    known_blockers=(
        "The reviewed source-authority migration is quarantined because it depends on removed measurement, coding-harness proof, and certification-campaign authority.",
        "SDK, Agents, MCP, ChatGPT, and the hosted HTTP lifecycle are blocked until a smaller source authority is independently designed and migrated.",
        "No merge, deployment, external publication, connector grant, provider effect, or reference-company binding is authorized.",
        "No production-mode design-partner outcome sample has met the declared measurement thresholds.",
    ),
)


INITIAL_GTM_GOLDEN_LOOP_CATALOG = GoldenLoopCatalog(
    manifests=tuple(
        sorted(
            (
                GOVERNED_CRM_VERIFIED_REPLY,
                PROJECT_INDEPENDENT_ACCEPTANCE,
                CONTRACT_TO_CASH_COLLECTED_CASH,
                CONTROLLED_SPEND_MATCHED_CLOSE,
                FINANCE_JOURNAL_READBACK_SETTLEMENT,
                PERIOD_RECONCILIATION_APPROVED_CLOSE_CANDIDATE,
                SERVICE_CASE_VERIFIED_RESOLUTION,
                VERIFIED_EVIDENCE_TO_PUBLISH_APPROVAL,
            ),
            key=lambda item: (item.loop_ref, item.version),
        )
    )
)
INITIAL_GTM_GOLDEN_LOOP_CATALOG.assert_initial_gtm_coverage()
REFERENCE_GOLDEN_LOOP_WORKFLOW_REGISTRY.assert_manifest_set(
    INITIAL_GTM_GOLDEN_LOOP_CATALOG.manifests,
    require_exact_coverage=True,
)


def initial_gtm_golden_loops() -> tuple[LoopCertificationManifest, ...]:
    """Return the immutable multi-loop GTM candidate portfolio in canonical order."""

    return INITIAL_GTM_GOLDEN_LOOP_CATALOG.manifests


def referenced_primitive_refs(
    manifests: Iterable[LoopCertificationManifest] | None = None,
) -> tuple[str, ...]:
    selected = tuple(manifests or initial_gtm_golden_loops())
    return tuple(
        sorted(
            {
                step.primitive_ref
                for manifest in selected
                for step in manifest.primitive_steps
            }
        )
    )


__all__ = [
    "CONTRACT_TO_CASH_COLLECTED_CASH",
    "CONTROLLED_SPEND_MATCHED_CLOSE",
    "FINANCE_JOURNAL_READBACK_SETTLEMENT",
    "GOVERNED_CRM_VERIFIED_REPLY",
    "INITIAL_GTM_GOLDEN_LOOP_CATALOG",
    "PROJECT_INDEPENDENT_ACCEPTANCE",
    "PERIOD_RECONCILIATION_APPROVED_CLOSE_CANDIDATE",
    "PERIOD_RECONCILIATION_APPROVED_CLOSE_CANDIDATE_V0_3",
    "SERVICE_CASE_VERIFIED_RESOLUTION",
    "VERIFIED_EVIDENCE_TO_PUBLISH_APPROVAL",
    "initial_gtm_golden_loops",
    "referenced_primitive_refs",
]
