"""Truthful, read-only campaign projections for human and agent project workers.

This module turns already-observed project-plan data into one shared campaign
map. It deliberately does not fetch data, dispatch workers, execute tools,
authenticate claimed outcome references, choose tournament winners, or grant
approval. Those boundaries let agents orient themselves without confusing a
helpful projection with runtime authority.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping
from typing import Any


PROJECT_GAME_CAMPAIGN_SCHEMA = "lightbulb.project_game_campaign.v1"
PROJECT_GAME_CHECKPOINT_SCHEMA = "lightbulb.project_game_checkpoint.v1"
PROJECT_MISSION_DEBRIEF_SCHEMA = "lightbulb.project_mission_debrief.v1"
PROJECT_MISSION_BRIEFING_SCHEMA = "lightbulb.project_mission_briefing.v1"
PROJECT_MISSION_RUN_LEDGER_SCHEMA = "lightbulb.project_mission_run_ledger.v1"
PROJECT_LEARNING_REVIEW_REQUEST_SCHEMA = "lightbulb.project_learning_review_request.v1"
PROJECT_LEARNING_REVIEW_RECEIPT_SCHEMA = "lightbulb.project_learning_review_receipt.v1"
PROJECT_LEARNING_REVIEW_LEDGER_SCHEMA = "lightbulb.project_learning_review_ledger.v1"
PROJECT_LEARNING_REVIEW_SCHEMA = "lightbulb.project_learning_review.v1"
PROJECT_SKILL_MATCH_RECEIPT_SCHEMA = "lightbulb.project_skill_match_receipt.v1"
PROJECT_SKILL_MATCH_LEDGER_SCHEMA = "lightbulb.project_skill_match_ledger.v1"
PROJECT_TRAINING_PACK_RECEIPT_SCHEMA = "lightbulb.project_training_pack_receipt.v1"
PROJECT_TRAINING_PACK_SCHEMA = "lightbulb.project_training_pack.v1"
PROJECT_LEARNING_RUN_ADMISSION_PLAN_SCHEMA = "lightbulb.project_learning_run_admission_plan.v1"
PROJECT_TRAINING_PACK_LEDGER_SCHEMA = "lightbulb.project_training_pack_ledger.v1"
PROJECT_LEARNING_LAB_SCHEMA = "lightbulb.project_learning_lab.v1"
PROJECT_LEARNING_RUN_RECEIPT_SCHEMA = "lightbulb.project_learning_run_receipt.v1"
PROJECT_LEARNING_RUN_ADMISSION_RECEIPT_SCHEMA = "lightbulb.project_learning_run_admission_receipt.v1"
PROJECT_LEARNING_RUN_EXECUTION_RECEIPT_SCHEMA = "lightbulb.project_learning_run_execution_receipt.v1"
PROJECT_LEARNING_RUN_EXECUTION_SNAPSHOT_SCHEMA = "lightbulb.project_learning_run_execution_snapshot.v1"
PROJECT_LEARNING_RUN_LEDGER_SCHEMA = "lightbulb.project_learning_run_ledger.v1"
PROJECT_LEARNING_QUEST_SCHEMA = "lightbulb.project_learning_quest.v1"
PROJECT_LEARNING_RESULT_EVALUATION_RECEIPT_SCHEMA = "lightbulb.project_learning_result_evaluation_record_receipt.v1"
PROJECT_LEARNING_RESULT_EVALUATION_LEDGER_SCHEMA = "lightbulb.project_learning_result_evaluation_ledger.v1"
PROJECT_LEARNING_RESULT_ADMISSION_RECEIPT_SCHEMA = "lightbulb.project_learning_result_admission_receipt.v1"
PROJECT_SHADOW_LEARNER_UPDATE_RECEIPT_SCHEMA = "lightbulb.project_shadow_learner_update_receipt.v1"
PROJECT_SHADOW_LEARNER_ROLLBACK_RECEIPT_SCHEMA = "lightbulb.project_shadow_learner_rollback_receipt.v1"
PROJECT_SHADOW_LEARNER_UPDATE_LEDGER_SCHEMA = "lightbulb.project_shadow_learner_update_ledger.v1"
PROJECT_BUSINESS_OUTCOME_OBSERVATION_SCHEMA = "lightbulb.project_business_outcome_observation.v1"
PROJECT_BUSINESS_OUTCOME_RECEIPT_SCHEMA = "lightbulb.project_business_outcome_receipt.v1"
PROJECT_BUSINESS_OUTCOME_LEDGER_SCHEMA = "lightbulb.project_business_outcome_ledger.v1"
PROJECT_POLICY_ASSIGNMENT_OBSERVATION_SCHEMA = "lightbulb.project_policy_assignment_observation.v1"
PROJECT_POLICY_ASSIGNMENT_RECEIPT_SCHEMA = "lightbulb.project_policy_assignment_receipt.v1"
PROJECT_POLICY_OFFLINE_EVALUATION_PAIR_REQUEST_SCHEMA = "lightbulb.project_policy_offline_evaluation_pair_request.v1"
PROJECT_POLICY_OFFLINE_EVALUATION_RECEIPT_SCHEMA = "lightbulb.project_policy_offline_evaluation_receipt.v1"
PROJECT_STRATEGY_LAB_SCHEMA = "lightbulb.project_strategy_lab.v1"
PROJECT_SCIENCE_EVIDENCE_OBSERVATION_SCHEMA = "lightbulb.project_science_evidence_observation.v1"
PROJECT_SCIENCE_EVIDENCE_RECEIPT_SCHEMA = "lightbulb.project_science_evidence_receipt.v1"
PROJECT_SCIENCE_LEDGER_SCHEMA = "lightbulb.project_science_ledger.v1"
PROJECT_SCIENCE_LAB_SCHEMA = "lightbulb.project_science_lab.v1"
SKILL_TOURNAMENT_SCHEMA = "lightbulb.skill_tournament.v1"
SKILL_TOURNAMENT_EVALUATION_REQUEST_SCHEMA = "lightbulb.skill_tournament_evaluation_request.v1"
SKILL_TOURNAMENT_EVALUATION_RECEIPT_SCHEMA = "lightbulb.skill_tournament_evaluation_receipt.v1"
SKILL_TOURNAMENT_CAPTURE_REQUEST_SCHEMA = "lightbulb.skill_tournament_shadow_capture_request.v1"
SKILL_TOURNAMENT_CAPTURE_BUNDLE_SCHEMA = "lightbulb.skill_tournament_shadow_capture_bundle.v1"
SKILL_TOURNAMENT_EPISODE_RECEIPT_SCHEMA = "lightbulb.skill_tournament_shadow_episode_receipt.v1"
SKILL_TOURNAMENT_CAPTURE_VERIFICATION_SCHEMA = "lightbulb.skill_tournament_shadow_capture_verification.v1"
SKILL_TOURNAMENT_APPLICATION_TRACE_SCHEMA = "lightbulb.skill_tournament_application_trace.v1"
SKILL_TOURNAMENT_RUNTIME_CONTRACT_SCHEMA = "lightbulb.skill_tournament_runtime_contract.v1"
SKILL_TOURNAMENT_ORCHESTRATION_RECEIPT_SCHEMA = "lightbulb.skill_tournament_orchestration_receipt.v1"
PROJECT_GAME_CAMPAIGN_MAX_JSON_BYTES = 256 * 1024
PROJECT_PLAY_STYLE_DEFAULT = "guided_human_in_the_loop"
PROJECT_PLAY_STYLE_IDS = (
    PROJECT_PLAY_STYLE_DEFAULT,
    "proactive_copilot",
    "autonomous_shadow",
)
_PROJECT_PLAY_STYLE_DEFINITIONS: dict[str, dict[str, str]] = {
    PROJECT_PLAY_STYLE_DEFAULT: {
        "label": "Guided run",
        "player_promise": "You start every mission.",
        "description": (
            "Agents explain the next move and wait for you to start each mission."
        ),
        "initiative": "wait_for_each_mission",
        "science_cadence": "manual",
    },
    "proactive_copilot": {
        "label": "Co-op run",
        "player_promise": "Agents bring you prepared next moves.",
        "description": (
            "When separately authorized, agents prepare read-only evidence and "
            "propose the next move; live changes still wait for approval."
        ),
        "initiative": "propose_and_prepare",
        "science_cadence": "event_prompted",
    },
    "autonomous_shadow": {
        "label": "Autopilot (shadow)",
        "player_promise": "Agents keep scouting in shadow.",
        "description": (
            "When separately authorized, agents run read-only or sandbox learning "
            "quests on a schedule; live changes still wait for approval."
        ),
        "initiative": "run_read_only_shadow_quests",
        "science_cadence": "shadow_scheduled",
    },
}


def normalize_project_play_style(
    value: object,
    *,
    legacy_fallback: bool = False,
) -> str:
    """Validate a creation preference or safely read a legacy plan value."""
    if isinstance(value, str) and value in PROJECT_PLAY_STYLE_IDS:
        return value
    if legacy_fallback:
        return PROJECT_PLAY_STYLE_DEFAULT
    raise ValueError("play_style is not supported")


def project_play_style_mode(
    value: object = PROJECT_PLAY_STYLE_DEFAULT,
    *,
    legacy_fallback: bool = False,
) -> dict[str, Any]:
    style_id = normalize_project_play_style(value, legacy_fallback=legacy_fallback)
    return {
        "id": style_id,
        **_PROJECT_PLAY_STYLE_DEFINITIONS[style_id],
        "initiative_contract_status": "preference_only",
        "runtime_activation_requires_separate_authority": True,
        "changes_authority": False,
        "worker_dispatch_authorized": False,
        "live_actions_authorized": False,
        "production_writes_authorized": False,
    }


_DEFAULT_PHASES: tuple[dict[str, str], ...] = (
    {"id": "hypothesis", "label": "Hypothesis", "act": "Discover", "specialist_role": "data_scientist"},
    {"id": "search", "label": "Search", "act": "Discover", "specialist_role": "search_data_engineer"},
    {"id": "data_engineering", "label": "Data pipelines", "act": "Prepare", "specialist_role": "search_data_engineer"},
    {"id": "machine_learning_and_serving", "label": "Train + serve", "act": "Learn", "specialist_role": "ml_engineer"},
    {"id": "solver_and_optimal_control", "label": "Find best policy", "act": "Decide", "specialist_role": "rl_control_engineer"},
    {"id": "simulation_and_offline_evaluation", "label": "Simulate safely", "act": "Decide", "specialist_role": "rl_control_engineer"},
    {"id": "authority_review", "label": "Human review", "act": "Authorize", "specialist_role": "project_agent"},
    {"id": "action", "label": "Take action", "act": "Operate", "specialist_role": "project_agent"},
    {"id": "authenticated_outcome", "label": "Measure outcome", "act": "Learn", "specialist_role": "data_scientist"},
    {"id": "governed_improvement", "label": "Improve safely", "act": "Evolve", "specialist_role": "project_agent"},
)

_SCIENCE_STAGES: tuple[dict[str, str], ...] = (
    {
        "id": "hypothesis",
        "label": "Choose a testable idea",
        "responsibility": "Data Scientist",
        "next_quest": "Write one falsifiable idea tied to the business score.",
    },
    {
        "id": "search",
        "label": "Find trustworthy sources",
        "responsibility": "Search + Data Engineer",
        "next_quest": "Find and cite evidence that could confirm or reject the idea.",
    },
    {
        "id": "data_engineering",
        "label": "Build usable data",
        "responsibility": "Search + Data Engineer",
        "next_quest": "Register a governed dataset with reproducible provenance.",
    },
    {
        "id": "machine_learning_and_serving",
        "label": "Train and check a model",
        "responsibility": "ML Engineer",
        "next_quest": "Train a governed baseline and record its held-out evidence.",
    },
    {
        "id": "solver_and_optimal_control",
        "label": "Propose the best safe move",
        "responsibility": "RL + Control Engineer",
        "next_quest": "Use the model and constraints to propose a shadow policy.",
    },
)

_SPECIALIST_ROLES: tuple[dict[str, str], ...] = (
    {
        "id": "data_scientist",
        "label": "Data Scientist",
        "responsibility": "Turns business questions and outcomes into testable hypotheses.",
    },
    {
        "id": "search_data_engineer",
        "label": "Search + Data Engineer",
        "responsibility": "Finds sources, builds governed ETL, and keeps context usable.",
    },
    {
        "id": "ml_engineer",
        "label": "ML Engineer",
        "responsibility": "Prepares training data, learns models, and serves inference.",
    },
    {
        "id": "rl_control_engineer",
        "label": "RL + Control Engineer",
        "responsibility": "Uses solvers, simulation, and outcomes to recommend safe actions.",
    },
)

_MISSION_PHASE_BRIEFINGS: dict[str, dict[str, Any]] = {
    "hypothesis": {
        "why_it_matters": "A testable idea connects the business goal to evidence.",
        "expected_result": "testable_hypothesis",
        "done_when": [
            "One falsifiable hypothesis names the expected business-metric movement.",
            "A scoped hypothesis artifact is ready for a Science Ledger receipt.",
        ],
        "completion_receipt": "project_science_evidence:hypothesis",
    },
    "search": {
        "why_it_matters": "Trustworthy sources keep the project from learning from guesses.",
        "expected_result": "cited_source_evidence",
        "done_when": [
            "Relevant sources are cited and bounded to the question being tested.",
            "A search artifact is ready for a Science Ledger receipt.",
        ],
        "completion_receipt": "project_science_evidence:search",
    },
    "data_engineering": {
        "why_it_matters": "Reproducible data turns research into something models and people can trust.",
        "expected_result": "governed_dataset",
        "done_when": [
            "The dataset has reproducible provenance, schema, and quality checks.",
            "The data artifact references the exact search receipt it follows.",
        ],
        "completion_receipt": "project_science_evidence:data_engineering",
    },
    "machine_learning_and_serving": {
        "why_it_matters": "A governed baseline shows whether prediction adds value before it drives a decision.",
        "expected_result": "served_model_candidate",
        "done_when": [
            "A baseline and candidate are compared on held-out evidence.",
            "The model artifact, serving contract, and predecessor data receipt are recorded.",
        ],
        "completion_receipt": "project_science_evidence:machine_learning_and_serving",
    },
    "solver_and_optimal_control": {
        "why_it_matters": "Models become useful when constraints turn predictions into safe candidate actions.",
        "expected_result": "shadow_policy_candidate",
        "done_when": [
            "The objective, constraints, alternatives, and recommended shadow policy are explicit.",
            "The control artifact references the exact model receipt it uses.",
        ],
        "completion_receipt": "project_science_evidence:solver_and_optimal_control",
    },
    "simulation_and_offline_evaluation": {
        "why_it_matters": "Offline evaluation rejects weak policies before they can affect the business.",
        "expected_result": "offline_policy_evaluation",
        "done_when": [
            "Assignment probabilities were logged before outcomes were known.",
            "Exact assignment, action, and outcome receipts pass control-plane verification.",
        ],
        "completion_receipt": "project_policy_offline_evaluation_receipt",
    },
    "authority_review": {
        "why_it_matters": "A person must decide whether the evidence and downside justify a live move.",
        "expected_result": "human_authority_decision",
        "done_when": [
            "Evidence, assumptions, risks, rollback, and requested scope are reviewable.",
            "The authorized decision is recorded through the approval workflow.",
        ],
        "completion_receipt": "approval_decision_receipt",
    },
    "action": {
        "why_it_matters": "Only an approved, traceable action can connect a policy to a real outcome.",
        "expected_result": "approved_action_event",
        "done_when": [
            "The action stays inside its approved scope and idempotency boundary.",
            "A same-project action event exists for later outcome binding.",
        ],
        "completion_receipt": "same_scope_project_action_event",
    },
    "authenticated_outcome": {
        "why_it_matters": "Real business measurements replace pretend points and reveal what actually changed.",
        "expected_result": "authenticated_business_outcome",
        "done_when": [
            "Before and after values, direction, unit, source, and metric identity are recorded.",
            "The outcome receipt is bound to the exact project and action when an agent acted.",
        ],
        "completion_receipt": "project_business_outcome_receipt",
    },
    "governed_improvement": {
        "why_it_matters": "Reflection should improve skills and policies only when evidence survives review.",
        "expected_result": "human_reviewed_learning_decision",
        "done_when": [
            "No-skill, single-skill, and skill-combination evidence is compared on one useful suite.",
            "A person admits or rejects learning without silently activating a live policy.",
        ],
        "completion_receipt": "learning_admission_or_rejection_receipt",
    },
}

_MISSION_INITIATIVE: dict[str, dict[str, str]] = {
    "guided_human_in_the_loop": {
        "activation_state": "waiting_for_player_start",
        "player_message": "You choose when this mission starts. Agents explain the plan and wait.",
        "player_action_label": "Start mission in chat",
    },
    "proactive_copilot": {
        "activation_state": "separate_read_only_preparation_authority_required",
        "player_message": "Agents may prepare a read-only proposal only after separate runtime authority; live changes still wait for you.",
        "player_action_label": "Review co-op plan",
    },
    "autonomous_shadow": {
        "activation_state": "separate_shadow_schedule_authority_required",
        "player_message": "Agents may enter this mission into a read-only or sandbox shadow schedule only after separate runtime authority.",
        "player_action_label": "Review shadow setup",
    },
}

_CAPABILITY_ROUTES: dict[str, dict[str, Any]] = {
    "hypothesis": {
        "runtime_domain": "automl",
        "contract_status": "available",
        "mcp_entrypoint": "backbone_execute",
        "supplemental_mcp_tools": ["list_project_science_evidence", "record_project_science_evidence"],
        "worker_tools": [
            "run_domain_learning_loop",
            "autoresearch_plan_next_loop",
            "list_project_science_evidence",
            "record_project_science_evidence",
        ],
        "evidence_contract": "scope_verified_science_receipt_required_for_campaign_evidence",
        "missing_contract": None,
        "human_gate_required": False,
    },
    "search": {
        "runtime_domain": "automl",
        "contract_status": "available",
        "mcp_entrypoint": "backbone_execute",
        "supplemental_mcp_tools": ["list_project_science_evidence", "record_project_science_evidence"],
        "worker_tools": [
            "agentic_data_search",
            "discover_extract_ingest_public_sources",
            "list_project_science_evidence",
            "record_project_science_evidence",
        ],
        "evidence_contract": "scope_verified_science_receipt_required_for_campaign_evidence",
        "missing_contract": None,
        "human_gate_required": False,
    },
    "data_engineering": {
        "runtime_domain": "automl",
        "contract_status": "available",
        "mcp_entrypoint": "backbone_execute",
        "supplemental_mcp_tools": ["list_project_science_evidence", "record_project_science_evidence"],
        "worker_tools": [
            "automl_register_dataset",
            "automl_register_dataset_rows",
            "automl_record_section_artifact",
            "list_project_science_evidence",
            "record_project_science_evidence",
        ],
        "evidence_contract": "scope_verified_science_receipt_required_for_campaign_evidence",
        "missing_contract": None,
        "human_gate_required": False,
    },
    "machine_learning_and_serving": {
        "runtime_domain": "automl",
        "contract_status": "available_approval_gated",
        "mcp_entrypoint": "backbone_execute",
        "supplemental_mcp_tools": ["list_project_science_evidence", "record_project_science_evidence"],
        "worker_tools": [
            "automl_create_experiment",
            "automl_propose_training",
            "automl_record_model_trials_artifact",
            "automl_record_model_candidate",
            "automl_propose_deployment",
            "automl_run_inference",
            "list_project_science_evidence",
            "record_project_science_evidence",
        ],
        "evidence_contract": "scope_verified_science_receipt_required_for_campaign_evidence",
        "missing_contract": None,
        "human_gate_required": True,
    },
    "solver_and_optimal_control": {
        "runtime_domain": "automl",
        "contract_status": "available",
        "mcp_entrypoint": "backbone_execute",
        "supplemental_mcp_tools": ["list_project_science_evidence", "record_project_science_evidence"],
        "worker_tools": [
            "build_control_optimization_model",
            "optimization_validate",
            "optimization_solve",
            "list_project_science_evidence",
            "record_project_science_evidence",
        ],
        "evidence_contract": "scope_verified_science_receipt_required_for_campaign_evidence",
        "missing_contract": None,
        "human_gate_required": False,
    },
    "simulation_and_offline_evaluation": {
        "runtime_domain": "automl",
        "contract_status": "available_control_plane_verified_shadow_only",
        "mcp_entrypoint": "evaluate_project_offline_policy",
        "supplemental_mcp_tools": [
            "record_project_policy_assignment",
            "list_project_policy_assignments",
            "list_project_policy_evaluations",
        ],
        "worker_tools": [
            "record_project_policy_assignment",
            "evaluate_project_offline_policy",
            "build_control_optimization_model",
            "optimization_validate",
        ],
        "missing_contract": None,
        "evidence_boundary": "assignment_action_outcome_receipt_pairs_verified_by_control_plane",
        "admission_boundary": "shadow_candidate_requires_separate_human_review",
        "human_gate_required": True,
    },
    "authority_review": {
        "runtime_domain": "governance",
        "contract_status": "available_human_gated",
        "mcp_entrypoint": "list_pending_approvals",
        "worker_tools": ["request_artifact_approval", "check_artifact_approval", "record_approval_reply"],
        "missing_contract": None,
        "human_gate_required": True,
    },
    "action": {
        "runtime_domain": "project",
        "contract_status": "available_approval_gated_receipt_bindable",
        "mcp_entrypoint": "backbone_execute",
        "supplemental_mcp_tools": ["bind_project_mission_action"],
        "worker_tools": ["execute_connector_action", "bind_project_mission_action"],
        "missing_contract": None,
        "human_gate_required": True,
    },
    "authenticated_outcome": {
        "runtime_domain": "project",
        "contract_status": "available_trust_tiered_observation_ledger",
        "mcp_entrypoint": "backbone_execute",
        "supplemental_mcp_tools": [
            "record_project_business_outcome",
            "list_project_business_outcomes",
            "list_project_mission_runs",
            "post_aoc_task_event",
        ],
        "worker_tools": [
            "list_project_mission_runs",
            "record_project_business_outcome",
            "record_skill_outcome",
        ],
        "missing_contract": None,
        "source_truth_boundary": "actor_authentication_or_exact_mission_action_scope_binding_not_causality",
        "human_gate_required": False,
    },
    "governed_improvement": {
        "runtime_domain": "automl",
        "contract_status": "available_fenced_learning_run_execution_receipts",
        "mcp_entrypoint": "backbone_execute",
        "supplemental_mcp_tools": [
            "list_project_skill_matches",
            "list_project_training_packs",
            "list_project_learning_runs",
        ],
        "worker_tools": [
            "autoresearch_plan_next_loop",
            "automl_create_skill",
            "automl_run_skill_tournament",
            "automl_evaluate_skill_tournament",
            "record_project_skill_match",
            "list_project_skill_matches",
            "record_project_training_pack",
            "list_project_training_packs",
            "prepare_project_learning_run",
            "admit_project_learning_run",
            "claim_project_learning_run",
            "heartbeat_project_learning_run",
            "checkpoint_project_learning_run",
            "finish_project_learning_run",
            "synchronize_project_learning_execution",
            "list_project_learning_runs",
            "automl_train_skill",
            "compute_skill_drift",
            "request_skill_retrain",
        ],
        "training_boundary": "runtime_result_is_not_independent_evaluation_learning_admission_or_promotion",
        "missing_contract": "independent_training_result_evaluation_and_governed_learning_admission_bridge",
        "human_gate_required": True,
    },
}

_TOURNAMENT_ARMS: tuple[dict[str, Any], ...] = (
    {
        "id": "no_skill",
        "label": "No-skill baseline",
        "runtime_support": {
            "status": "available_domain_worker_authenticated_orchestrator_configuration_gated",
            "tools": ["automl_run_skill_tournament", "automl_evaluate_skill_tournament"],
            "orchestrator_tool": "automl_run_skill_tournament",
            "evaluator_tool": "automl_evaluate_skill_tournament",
            "capture_status": "authenticated_domain_orchestrator_available_configuration_gated",
            "capture_runtime_library": "agents.tools.skill_tournament_shadow_capture",
            "agent_executor_library": "agents.tools.skill_tournament_agent_executor",
            "orchestration_runtime_library": "agents.tools.skill_tournament_orchestrator",
            "capture_bundle_schema": SKILL_TOURNAMENT_CAPTURE_BUNDLE_SCHEMA,
            "worker_application_trace_schema": SKILL_TOURNAMENT_APPLICATION_TRACE_SCHEMA,
            "runtime_contract_schema": SKILL_TOURNAMENT_RUNTIME_CONTRACT_SCHEMA,
            "orchestration_receipt_schema": SKILL_TOURNAMENT_ORCHESTRATION_RECEIPT_SCHEMA,
            "evaluator_accepts_authenticated_capture": True,
            "authenticated_capture_orchestrator_available": True,
            "authenticated_capture_orchestrator_scope": "claude_domain_provider_only",
            "agent_context_executor_adapter_available": True,
            "exact_skill_selection_contract_available": True,
            "runtime_contract_binding_available": True,
            "trusted_runtime_evidence_probe_required": True,
            "trusted_runtime_evidence_probe_binding_available": True,
            "runtime_evidence_probe_binding_scope": "claude_domain_provider_only",
            "runtime_evidence_coverage_id": "lightbulb.claude-domain-tournament-provider-only.v1",
            "broader_worker_runtime_coverage_available": False,
            "trusted_producer_key_required": True,
            "trusted_producer_key_configuration_verified_by_projection": False,
            "artifact_trust_store_configuration_verified_by_projection": False,
            "live_episode_executor_binding_available": True,
            "live_provider_exercised_by_projection": False,
            "missing_contract": "trusted_key_provisioning_and_non_domain_worker_runtime_coverage",
        },
    },
    {
        "id": "single_skill",
        "label": "Single skill",
        "runtime_support": {
            "status": "available_domain_worker_authenticated_orchestrator_configuration_gated",
            "tools": ["automl_train_skill", "automl_run_skill_tournament", "automl_evaluate_skill_tournament"],
            "orchestrator_tool": "automl_run_skill_tournament",
            "evaluator_tool": "automl_evaluate_skill_tournament",
            "capture_status": "authenticated_domain_orchestrator_available_configuration_gated",
            "capture_runtime_library": "agents.tools.skill_tournament_shadow_capture",
            "agent_executor_library": "agents.tools.skill_tournament_agent_executor",
            "orchestration_runtime_library": "agents.tools.skill_tournament_orchestrator",
            "capture_bundle_schema": SKILL_TOURNAMENT_CAPTURE_BUNDLE_SCHEMA,
            "worker_application_trace_schema": SKILL_TOURNAMENT_APPLICATION_TRACE_SCHEMA,
            "runtime_contract_schema": SKILL_TOURNAMENT_RUNTIME_CONTRACT_SCHEMA,
            "orchestration_receipt_schema": SKILL_TOURNAMENT_ORCHESTRATION_RECEIPT_SCHEMA,
            "evaluator_accepts_authenticated_capture": True,
            "authenticated_capture_orchestrator_available": True,
            "authenticated_capture_orchestrator_scope": "claude_domain_provider_only",
            "agent_context_executor_adapter_available": True,
            "exact_skill_selection_contract_available": True,
            "runtime_contract_binding_available": True,
            "trusted_runtime_evidence_probe_required": True,
            "trusted_runtime_evidence_probe_binding_available": True,
            "runtime_evidence_probe_binding_scope": "claude_domain_provider_only",
            "runtime_evidence_coverage_id": "lightbulb.claude-domain-tournament-provider-only.v1",
            "broader_worker_runtime_coverage_available": False,
            "trusted_producer_key_required": True,
            "trusted_producer_key_configuration_verified_by_projection": False,
            "artifact_trust_store_configuration_verified_by_projection": False,
            "live_episode_executor_binding_available": True,
            "live_provider_exercised_by_projection": False,
            "missing_contract": "trusted_key_provisioning_and_non_domain_worker_runtime_coverage",
        },
    },
    {
        "id": "skill_combination",
        "label": "Skill combination",
        "runtime_support": {
            "status": "available_domain_worker_authenticated_orchestrator_configuration_gated",
            "tools": ["plan_with_skills", "answer_task_with_skill", "automl_run_skill_tournament", "automl_evaluate_skill_tournament"],
            "orchestrator_tool": "automl_run_skill_tournament",
            "evaluator_tool": "automl_evaluate_skill_tournament",
            "capture_status": "authenticated_domain_orchestrator_available_configuration_gated",
            "capture_runtime_library": "agents.tools.skill_tournament_shadow_capture",
            "agent_executor_library": "agents.tools.skill_tournament_agent_executor",
            "orchestration_runtime_library": "agents.tools.skill_tournament_orchestrator",
            "capture_bundle_schema": SKILL_TOURNAMENT_CAPTURE_BUNDLE_SCHEMA,
            "worker_application_trace_schema": SKILL_TOURNAMENT_APPLICATION_TRACE_SCHEMA,
            "runtime_contract_schema": SKILL_TOURNAMENT_RUNTIME_CONTRACT_SCHEMA,
            "orchestration_receipt_schema": SKILL_TOURNAMENT_ORCHESTRATION_RECEIPT_SCHEMA,
            "evaluator_accepts_authenticated_capture": True,
            "authenticated_capture_orchestrator_available": True,
            "authenticated_capture_orchestrator_scope": "claude_domain_provider_only",
            "agent_context_executor_adapter_available": True,
            "exact_skill_selection_contract_available": True,
            "runtime_contract_binding_available": True,
            "trusted_runtime_evidence_probe_required": True,
            "trusted_runtime_evidence_probe_binding_available": True,
            "runtime_evidence_probe_binding_scope": "claude_domain_provider_only",
            "runtime_evidence_coverage_id": "lightbulb.claude-domain-tournament-provider-only.v1",
            "broader_worker_runtime_coverage_available": False,
            "trusted_producer_key_required": True,
            "trusted_producer_key_configuration_verified_by_projection": False,
            "artifact_trust_store_configuration_verified_by_projection": False,
            "live_episode_executor_binding_available": True,
            "live_provider_exercised_by_projection": False,
            "missing_contract": "trusted_key_provisioning_and_non_domain_worker_runtime_coverage",
        },
    },
)


def _canonical_object(value: object, label: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise TypeError(f"{label} must be a JSON object")
    try:
        serialized = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must contain finite JSON values") from exc
    if len(serialized.encode("utf-8")) > PROJECT_GAME_CAMPAIGN_MAX_JSON_BYTES:
        raise ValueError(
            f"{label} must be at most {PROJECT_GAME_CAMPAIGN_MAX_JSON_BYTES} UTF-8 JSON bytes"
        )
    parsed = json.loads(serialized)
    if not isinstance(parsed, dict):
        raise TypeError(f"{label} must be a JSON object")
    return parsed


def _object(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _array(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def _text(value: object, maximum: int = 2_000) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return ""
    return str(value).strip()[:maximum]


def _field(value: object, *keys: str) -> Any:
    source = _object(value)
    for key in keys:
        if key in source and source[key] is not None:
            return source[key]
    return None


def _first_object(*values: object) -> dict[str, Any]:
    for value in values:
        item = _object(value)
        if item:
            return item
    return {}


def _first_array(*values: object) -> list[Any]:
    for value in values:
        items = _array(value)
        if items:
            return items
    return []


def _explicit_boolean(value: object, *keys: str) -> bool | None:
    raw = _field(value, *keys)
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str):
        normalized = raw.strip().lower()
        if normalized == "true":
            return True
        if normalized == "false":
            return False
    return None


def _primitive_display_value(value: object) -> str:
    if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value):
        return str(value)
    if isinstance(value, str) and value.strip():
        return value.strip()[:240]
    return ""


def _record_list(value: object) -> list[Any]:
    records: list[Any] = []
    for item in _array(value):
        if isinstance(item, str) and item.strip():
            records.append(item)
        elif isinstance(item, dict) and item:
            records.append(item)
    return records


def _evidence_from(*signals: tuple[str, object]) -> list[dict[str, Any]]:
    return [
        {"source_ref": source_ref, "count": len(records)}
        for source_ref, value in signals
        if (records := _record_list(value))
    ]


def _non_negative_integer(value: object, fallback: int = 0) -> int:
    if (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and value >= 0
    ):
        return int(value)
    return fallback


def _unique_text_list(value: object, maximum: int = 50) -> list[str]:
    return list(dict.fromkeys(
        text
        for item in _array(value)
        if (text := _text(item, 240))
    ))[:maximum]


def _science_stage_evidence(
    science_lab: dict[str, Any], stage_id: str
) -> list[dict[str, Any]]:
    stage = next(
        (
            _object(item)
            for item in _array(_field(science_lab, "stages"))
            if _text(_field(item, "id"), 120) == stage_id
        ),
        {},
    )
    count = _non_negative_integer(
        _field(stage, "verified_receipt_count", "verifiedReceiptCount")
    )
    return (
        [{"source_ref": f"business_cockpit.science_lab.stages.{stage_id}", "count": count}]
        if count > 0
        else []
    )


def _phase_evidence(
    plan: dict[str, Any],
    business_cockpit: dict[str, Any],
    science_lab: dict[str, Any],
) -> dict[str, dict[str, list[dict[str, Any]]]]:
    analysis_engine = _object(_field(plan, "analysis_engine", "analysisEngine"))
    research = _object(_field(plan, "research"))
    data_engineering = _object(_field(plan, "data_engineering", "dataEngineering"))
    data_lake = _object(_field(plan, "data_lake", "dataLake"))
    automl = _object(_field(plan, "automl", "auto_ml", "autoMl"))
    ml_engineering = _object(_field(plan, "ml_engineering", "mlEngineering"))
    model_registry = _object(_field(plan, "model_registry", "modelRegistry"))
    solver = _object(_field(plan, "solver", "optimal_control", "optimalControl"))
    offline_evaluation = _object(_field(plan, "offline_evaluation", "offlineEvaluation"))
    simulation = _object(_field(plan, "simulation"))
    delivery_loop = _object(_field(plan, "delivery_loop", "deliveryLoop"))
    outcome_ledger = _object(_field(business_cockpit, "outcome_ledger", "outcomeLedger"))
    strategy_lab = _object(_field(business_cockpit, "strategy_lab", "strategyLab"))
    policy_evaluations = _object(
        _field(strategy_lab, "offline_evaluation_ledger", "offlineEvaluationLedger")
    )
    return {
        "hypothesis": {
            "verified": _science_stage_evidence(science_lab, "hypothesis"),
            "claimed": _evidence_from(
                ("research_hypotheses", _field(plan, "research_hypotheses", "researchHypotheses", "hypotheses")),
                ("analysis_engine.hypotheses", _field(analysis_engine, "hypotheses")),
            ),
        },
        "search": {
            "verified": _science_stage_evidence(science_lab, "search"),
            "claimed": _evidence_from(
                ("search_results", _field(plan, "search_results", "searchResults", "search_evidence", "searchEvidence")),
                ("research.search_results", _field(research, "search_results", "searchResults")),
            ),
        },
        "data_engineering": {
            "verified": _science_stage_evidence(science_lab, "data_engineering"),
            "claimed": _evidence_from(
                ("data_engineering.pipelines", _field(data_engineering, "pipelines", "etl_pipelines", "etlPipelines")),
                ("data_pipelines", _field(plan, "data_pipelines", "dataPipelines", "etl_pipelines", "etlPipelines")),
                ("data_lake.datasets", _field(data_lake, "datasets")),
            ),
        },
        "machine_learning_and_serving": {
            "verified": _science_stage_evidence(science_lab, "machine_learning_and_serving"),
            "claimed": _evidence_from(
                ("automl.learning_runs", _field(automl, "learning_runs", "learningRuns", "training_runs", "trainingRuns")),
                ("automl.serving_endpoints", _field(automl, "serving_endpoints", "servingEndpoints", "deployments")),
                ("ml_engineering.training_runs", _field(ml_engineering, "training_runs", "trainingRuns")),
                ("model_registry.models", _field(model_registry, "models")),
            ),
        },
        "solver_and_optimal_control": {
            "verified": _science_stage_evidence(science_lab, "solver_and_optimal_control"),
            "claimed": _evidence_from(
                ("solver.policy_candidates", _field(solver, "policy_candidates", "policyCandidates")),
                ("solver.runs", _field(solver, "runs", "solver_runs", "solverRuns")),
                ("optimal_policies", _field(plan, "optimal_policies", "optimalPolicies")),
            ),
        },
        "simulation_and_offline_evaluation": {
            "verified": _evidence_from(
                (
                    "business_cockpit.strategy_lab.offline_evaluation_ledger.receipts",
                    _field(policy_evaluations, "receipts"),
                ),
            ),
            "claimed": _evidence_from(
                ("offline_evaluation.evaluations", _field(offline_evaluation, "evaluations", "runs")),
                ("simulation.runs", _field(simulation, "runs", "simulation_runs", "simulationRuns")),
                ("ope_results", _field(plan, "ope_results", "opeResults")),
            ),
        },
        "authority_review": {
            "verified": [],
            "claimed": _evidence_from(
                ("delivery_loop.approval_queue", _field(delivery_loop, "approval_queue", "approvalQueue")),
                ("policy_approval_queue", _field(plan, "policy_approval_queue", "policyApprovalQueue")),
            ),
        },
        "action": {
            "verified": [],
            "claimed": _evidence_from(
                ("action_receipts", _field(plan, "action_receipts", "actionReceipts")),
                ("delivery_loop.action_receipts", _field(delivery_loop, "action_receipts", "actionReceipts")),
                ("delivery_loop.shipped_releases", _field(delivery_loop, "shipped_releases", "shippedReleases")),
            ),
        },
        "authenticated_outcome": {
            "verified": _evidence_from(
                ("business_cockpit.outcome_ledger.receipts", _field(outcome_ledger, "receipts")),
            ),
            "claimed": _evidence_from(
                ("authenticated_outcomes", _field(plan, "authenticated_outcomes", "authenticatedOutcomes")),
                ("outcome_receipts", _field(plan, "outcome_receipts", "outcomeReceipts")),
                ("delivery_loop.authenticated_outcomes", _field(delivery_loop, "authenticated_outcomes", "authenticatedOutcomes")),
            ),
        },
        "governed_improvement": {
            "verified": [],
            "claimed": _evidence_from(
                ("governed_improvements", _field(plan, "governed_improvements", "governedImprovements")),
                ("governed_learning_runs", _field(plan, "governed_learning_runs", "governedLearningRuns")),
                ("skill_promotion_decisions", _field(plan, "skill_promotion_decisions", "skillPromotionDecisions")),
            ),
        },
    }


def _phase_for_mission(mission: dict[str, Any]) -> str:
    if _text(mission.get("id")).lower() == "map_first_workflow":
        return "hypothesis"
    text = " ".join(
        _text(mission.get(key)).lower() for key in ("id", "title", "prompt")
    )
    checks = (
        (r"approv|review|authority|decision|gate", "authority_review"),
        (r"authenticated outcome|outcome|receipt|measure result", "authenticated_outcome"),
        (r"improv|promot|reflect|learn from", "governed_improvement"),
        (r"simulat|offline eval|\bope\b|counterfactual", "simulation_and_offline_evaluation"),
        (r"solver|optimal|policy|control|recommend action", "solver_and_optimal_control"),
        (r"automl|model|train|inference|serv|deploy", "machine_learning_and_serving"),
        (r"etl|pipeline|lake|warehouse|wrangl|dataset", "data_engineering"),
        (r"search|source|research|find data", "search"),
        (r"execute|take action|ship|launch|run action", "action"),
    )
    for pattern, phase in checks:
        if re.search(pattern, text):
            return phase
    return "hypothesis"


def _current_mission(
    plan: dict[str, Any],
    game_start: dict[str, Any],
    science_lab: dict[str, Any],
) -> dict[str, Any]:
    delivery_readiness = _object(_field(plan, "delivery_readiness", "deliveryReadiness"))
    primary_next_action = _object(_field(delivery_readiness, "primary_next_action", "primaryNextAction"))
    next_question_raw = _field(plan, "next_best_question", "nextBestQuestion")
    next_question = (
        {"id": "answer_next_best_question", "title": "Answer the next question", "prompt": next_question_raw}
        if isinstance(next_question_raw, str)
        else _object(next_question_raw)
    )
    first_mission = _object(_field(game_start, "first_mission", "firstMission"))
    source = first_mission
    source_ref = "game_start.first_mission"
    science_next_quest = _object(
        _field(science_lab, "next_quest", "nextQuest")
    )
    science_stage = _text(_field(science_next_quest, "stage"), 120)
    if (
        _non_negative_integer(
            _field(
                science_lab,
                "verified_receipt_count",
                "verifiedReceiptCount",
            )
        )
        > 0
        and science_stage
    ):
        source = {
            "id": f"science_quest_{science_stage}",
            "title": "Continue the Science Quest",
            "prompt": _text(_field(science_next_quest, "label")),
            "status": "ready",
            "human_action_required": False,
        }
        source_ref = "science_lab.next_quest"
    if next_question:
        source = next_question
        source_ref = "next_best_question"
    if primary_next_action:
        source = primary_next_action
        source_ref = "delivery_readiness.primary_next_action"
    fallback = _object(_field(game_start, "next_action", "nextAction"))
    mission = {
        "id": _text(_field(source, "id", "code", "action_id", "actionId") or _field(fallback, "code")) or "define_first_mission",
        "title": _text(_field(source, "title", "label", "question") or _field(fallback, "label")) or "Define the first mission",
        "prompt": _text(_field(source, "prompt", "description", "summary", "question"))
        or "Tell the Project Agent what success looks like and map the first workflow.",
        "status": _text(_field(source, "status"))
        or ("ready" if source_ref == "delivery_readiness.primary_next_action" else "not_started"),
        "source_ref": source_ref,
        "human_action_required": _explicit_boolean(source, "human_action_required", "humanActionRequired"),
        "mutation_authorized_by_projection": False,
    }
    if mission["human_action_required"] is None:
        mission["human_action_required"] = True
    mission["phase"] = _phase_for_mission(mission)
    return mission


def _primary_metric(plan: dict[str, Any], business_cockpit: dict[str, Any]) -> tuple[dict[str, Any], str | None]:
    outcome_ledger = _object(_field(business_cockpit, "outcome_ledger", "outcomeLedger"))
    latest_receipt = _object(_field(outcome_ledger, "latest_receipt", "latestReceipt"))
    receipt_metric = _object(_field(latest_receipt, "metric"))
    if receipt_metric:
        metric = dict(receipt_metric)
        metric["current_value"] = _field(receipt_metric, "observed_value", "observedValue")
        metric["baseline"] = _field(receipt_metric, "baseline_value", "baselineValue")
        return metric, "business_cockpit.outcome_ledger.latest_receipt.metric"
    plan_metrics = _first_array(
        _field(plan, "business_metrics", "businessMetrics"),
        _field(plan, "success_metrics", "successMetrics"),
    )
    cockpit_metrics = _first_array(
        _field(business_cockpit, "business_metrics", "businessMetrics"),
        _field(business_cockpit, "metrics"),
        _field(_object(_field(business_cockpit, "scoreboard")), "metrics"),
    )
    values = cockpit_metrics if cockpit_metrics else plan_metrics
    metric = _object(values[0]) if values else {}
    source = (
        "business_cockpit.business_metrics[0]"
        if cockpit_metrics
        else "plan.business_metrics[0]"
        if plan_metrics
        else None
    )
    return metric, source


def _scoreboard(
    project: dict[str, Any],
    plan: dict[str, Any],
    business_cockpit: dict[str, Any],
    game_start: dict[str, Any],
) -> dict[str, Any]:
    win_condition = _object(_field(game_start, "win_condition", "winCondition"))
    metric, source = _primary_metric(plan, business_cockpit)
    current_value = _primitive_display_value(_field(metric, "current_value", "currentValue", "value"))
    metric_id = _text(_field(metric, "id", "metric_id", "metricId"))
    metric_label = _text(_field(metric, "label", "name", "title"))
    measured = bool(metric_label and current_value)
    outcome_ledger = _object(_field(business_cockpit, "outcome_ledger", "outcomeLedger"))
    latest_receipt = _object(_field(outcome_ledger, "latest_receipt", "latestReceipt"))
    receipt_source = _object(_field(latest_receipt, "source"))
    receipt_count_raw = _field(outcome_ledger, "receipt_count", "receiptCount")
    receipt_count = (
        int(receipt_count_raw)
        if isinstance(receipt_count_raw, (int, float))
        and not isinstance(receipt_count_raw, bool)
        and math.isfinite(receipt_count_raw)
        and receipt_count_raw >= 0
        else 0
    )
    receipt_measured = bool(latest_receipt and source and source.startswith("business_cockpit.outcome_ledger"))
    return {
        "win_condition": _text(_field(win_condition, "statement"))
        or _text(_field(plan, "product_goal", "productGoal"))
        or _text(_field(project, "name", "title"))
        or "Define what winning means for this project.",
        "metric_id": metric_id or None,
        "metric_label": metric_label or "Business score",
        "display_value": current_value if measured else "Set metric + baseline + target",
        "baseline": _primitive_display_value(_field(metric, "baseline")) or None,
        "target": _primitive_display_value(_field(metric, "target")) or None,
        "horizon": _primitive_display_value(_field(metric, "horizon", "target_horizon", "targetHorizon")) or None,
        "measurement_status": (
            "measured_from_same_scope_event_bound_receipt"
            if receipt_measured and _explicit_boolean(receipt_source, "scope_bound", "scopeBound") is True
            else "measured_from_authenticated_actor_receipt"
            if receipt_measured
            else
            "measured_from_business_cockpit"
            if measured and source and source.startswith("business_cockpit")
            else "measured_from_project_plan"
            if measured
            else _text(_field(win_condition, "measurement_status", "measurementStatus"))
            or "needs_metric_baseline_target_and_horizon"
        ),
        "source_ref": source if measured else _text(_field(win_condition, "source")) or "project.product_goal",
        "movement": _text(_field(latest_receipt, "movement")) or None,
        "receipt_id": _text(_field(latest_receipt, "receipt_id", "receiptId")) or None,
        "receipt_count": receipt_count,
        "receipt_trust_tier": _text(_field(receipt_source, "trust_tier", "trustTier")) or None,
        "receipt_scope_bound": _explicit_boolean(receipt_source, "scope_bound", "scopeBound") is True,
        "causality_proven": False,
        "learning_admitted": False,
        "numeric_score_generated": False,
    }


def _outcome_ledger_projection(business_cockpit: dict[str, Any]) -> dict[str, Any]:
    ledger = _object(_field(business_cockpit, "outcome_ledger", "outcomeLedger"))
    receipts = _array(_field(ledger, "receipts"))
    latest = _object(_field(ledger, "latest_receipt", "latestReceipt"))
    return {
        "schema": PROJECT_BUSINESS_OUTCOME_LEDGER_SCHEMA,
        "status": _text(_field(ledger, "status")) or ("observations_recorded" if receipts else "empty"),
        "receipt_count": len(receipts),
        "latest_receipt": latest,
        "receipts": receipts,
        "latest_receipt_id": _text(_field(latest, "receipt_id", "receiptId")) or None,
        "latest_movement": _text(_field(latest, "movement")) or None,
        "external_source_truth_verified": False,
        "causality_proven": False,
        "learning_admitted": False,
        "policy_promotion_authorized": False,
        "action_authorized": False,
        "contract": {
            "observation_schema": PROJECT_BUSINESS_OUTCOME_OBSERVATION_SCHEMA,
            "receipt_schema": PROJECT_BUSINESS_OUTCOME_RECEIPT_SCHEMA,
            "human_api": "POST /api/projects/{project_id}/business-outcomes",
            "agent_worker_tool": "record_project_business_outcome",
            "mcp_record_tool": "record_project_business_outcome",
            "mcp_list_tool": "list_project_business_outcomes",
            "actor_authentication_available": True,
            "same_scope_project_event_binding_available": True,
            "external_source_truth_verified_by_general_contract": False,
            "causality_proven_by_general_contract": False,
            "learning_admitted_by_receipt": False,
            "policy_promotion_authorized_by_receipt": False,
            "action_authorized_by_receipt": False,
        },
    }


def _science_lab_projection(business_cockpit: dict[str, Any]) -> dict[str, Any]:
    ledger = _object(_field(business_cockpit, "science_lab", "scienceLab"))
    ledger_schema_valid = _text(_field(ledger, "schema")) == PROJECT_SCIENCE_LEDGER_SCHEMA
    receipts = [_object(item) for item in _array(_field(ledger, "receipts"))]
    raw_stages = [_object(item) for item in _array(_field(ledger, "stages"))]
    latest_by_stage = _object(_field(ledger, "latest_by_stage", "latestByStage"))
    truth = _object(_field(ledger, "truth_boundary", "truthBoundary"))
    receipt_identity_verified = (
        ledger_schema_valid
        and _explicit_boolean(
            truth, "receipt_identity_verified", "receiptIdentityVerified"
        )
        is True
    )
    predecessor_scope_verified = (
        ledger_schema_valid
        and _explicit_boolean(
            truth, "predecessor_scope_verified", "predecessorScopeVerified"
        )
        is True
    )
    scope_verified = receipt_identity_verified and predecessor_scope_verified

    stages: list[dict[str, Any]] = []
    for definition in _SCIENCE_STAGES:
        raw_stage = next(
            (
                item
                for item in raw_stages
                if _text(_field(item, "id"), 120) == definition["id"]
            ),
            {},
        )
        matching_receipts = [
            receipt
            for receipt in receipts
            if _text(_field(receipt, "stage"), 120) == definition["id"]
        ]
        latest = _first_object(
            _field(raw_stage, "latest_receipt", "latestReceipt"),
            _field(latest_by_stage, definition["id"]),
            matching_receipts[0] if matching_receipts else None,
        )
        supplied_count = _non_negative_integer(
            _field(raw_stage, "receipt_count", "receiptCount"),
            len(matching_receipts) or (1 if latest else 0),
        )
        verified_count = supplied_count if scope_verified else 0
        stages.append(
            {
                **definition,
                "receipt_count": supplied_count,
                "verified_receipt_count": verified_count,
                "state": (
                    "evidence_recorded"
                    if verified_count > 0
                    else "supplied_unverified"
                    if supplied_count > 0
                    else "not_started"
                ),
                "latest_receipt_id": _text(
                    _field(latest, "receipt_id", "receiptId")
                )
                or None,
                "scope_verified": verified_count > 0,
                "completion_inferred": False,
            }
        )

    supplied_stage_receipt_count = sum(stage["receipt_count"] for stage in stages)
    verified_receipt_count = sum(
        stage["verified_receipt_count"] for stage in stages
    )
    receipt_count = _non_negative_integer(
        _field(ledger, "receipt_count", "receiptCount"),
        len(receipts) or supplied_stage_receipt_count,
    )
    raw_next_quest = _object(_field(ledger, "next_quest", "nextQuest"))
    requested_next_stage = (
        _text(_field(raw_next_quest, "stage"), 120) if scope_verified else ""
    )
    next_stage = next(
        (
            stage
            for stage in _SCIENCE_STAGES
            if stage["id"] == requested_next_stage
        ),
        None,
    )
    if next_stage is None:
        next_stage = next(
            (
                definition
                for definition in _SCIENCE_STAGES
                if next(
                    stage["verified_receipt_count"]
                    for stage in stages
                    if stage["id"] == definition["id"]
                )
                == 0
            ),
            None,
        )
    next_quest_label = (
        (_text(_field(raw_next_quest, "label")) if scope_verified else "")
        or (next_stage or {}).get("next_quest")
        or "Take the policy candidate to Strategy Lab before any live change."
    )
    solver_stage = next(
        stage
        for stage in stages
        if stage["id"] == "solver_and_optimal_control"
    )
    scope_verified_lineage = (
        scope_verified
        and solver_stage["verified_receipt_count"] > 0
        and _explicit_boolean(
            ledger,
            "scope_verified_lineage_to_policy_candidate",
            "scopeVerifiedLineageToPolicyCandidate",
        )
        is True
    )
    return {
        "schema": PROJECT_SCIENCE_LAB_SCHEMA,
        "ledger_schema": PROJECT_SCIENCE_LEDGER_SCHEMA,
        "status": (
            "scope_verified_policy_candidate_ready_for_strategy_lab"
            if verified_receipt_count > 0 and scope_verified_lineage
            else "building_scope_verified_lineage"
            if verified_receipt_count > 0
            else "supplied_ledger_not_scope_verified"
            if receipt_count > 0
            else "not_started"
        ),
        "receipt_count": receipt_count,
        "verified_receipt_count": verified_receipt_count,
        "stages": stages,
        "next_quest": {
            "stage": (next_stage or {}).get(
                "id", "simulation_and_offline_evaluation"
            ),
            "label": next_quest_label,
            "mutation_authorized": False,
        },
        "tools_used": _unique_text_list(
            _field(ledger, "tools_used", "toolsUsed")
        ),
        "skills_used": _unique_text_list(
            _field(ledger, "skills_used", "skillsUsed")
        ),
        "method_runtime_attested": False,
        "scope_verified_lineage_to_policy_candidate": scope_verified_lineage,
        "truth_boundary": {
            "receipt_identity_verified": receipt_identity_verified,
            "predecessor_scope_verified": predecessor_scope_verified,
            "producer_runtime_attested": False,
            "external_artifact_contents_verified": False,
            "hypothesis_confirmed": False,
            "scientific_validity_proven": False,
            "model_quality_verified": False,
            "policy_optimality_verified": False,
            "causality_proven": False,
            "learning_admitted": False,
            "action_authorized": False,
        },
        "authority": {
            "dataset_registration_authorized": False,
            "training_authorized": False,
            "deployment_authorized": False,
            "policy_activation_authorized": False,
            "production_action_authorized": False,
            "skill_confidence_update_authorized": False,
        },
        "contract": {
            "observation_schema": PROJECT_SCIENCE_EVIDENCE_OBSERVATION_SCHEMA,
            "receipt_schema": PROJECT_SCIENCE_EVIDENCE_RECEIPT_SCHEMA,
            "ledger_schema": PROJECT_SCIENCE_LEDGER_SCHEMA,
            "human_api": "GET|POST /api/projects/{project_id}/science-evidence",
            "agent_list_tool": "list_project_science_evidence",
            "agent_record_tool": "record_project_science_evidence",
            "mcp_list_tool": "list_project_science_evidence",
            "mcp_record_tool": "record_project_science_evidence",
            "exact_predecessor_receipt_required": True,
            "scope_verified_receipt_required_for_campaign_evidence": True,
        },
    }


def _strategy_lab_projection(business_cockpit: dict[str, Any]) -> dict[str, Any]:
    lab = _object(_field(business_cockpit, "strategy_lab", "strategyLab"))
    assignments = _object(
        _field(lab, "assignment_ledger", "assignmentLedger")
    )
    evaluations = _object(
        _field(lab, "offline_evaluation_ledger", "offlineEvaluationLedger")
    )
    assignment_receipts = _array(_field(assignments, "receipts"))
    evaluation_receipts = _array(_field(evaluations, "receipts"))
    latest = _object(_field(evaluations, "latest_receipt", "latestReceipt"))
    readiness = _object(_field(latest, "readiness"))
    estimates = _object(_field(latest, "estimates"))
    diagnostics = _object(_field(latest, "diagnostics"))
    pair_integrity = _object(_field(latest, "pair_integrity", "pairIntegrity"))

    raw_assignment_count = _field(assignments, "receipt_count", "receiptCount")
    assignment_count = (
        int(raw_assignment_count)
        if isinstance(raw_assignment_count, (int, float))
        and not isinstance(raw_assignment_count, bool)
        and math.isfinite(raw_assignment_count)
        and raw_assignment_count >= 0
        else len(assignment_receipts)
    )
    raw_evaluation_count = _field(evaluations, "receipt_count", "receiptCount")
    evaluation_count = (
        int(raw_evaluation_count)
        if isinstance(raw_evaluation_count, (int, float))
        and not isinstance(raw_evaluation_count, bool)
        and math.isfinite(raw_evaluation_count)
        and raw_evaluation_count >= 0
        else len(evaluation_receipts)
    )
    candidate = _field(readiness, "shadow_learning_candidate", "shadowLearningCandidate") is True
    status = _text(_field(lab, "status")) or (
        "shadow_learning_candidate_waiting_for_human_admission"
        if candidate
        else "more_or_better_evidence_required"
        if evaluation_count > 0
        else "collecting_action_outcome_pairs"
        if assignment_count > 0
        else "policy_assignment_required"
    )
    stage_copy = {
        "policy_assignment_required": (
            "Log the strategy before acting",
            "Record the options and their probabilities while the result is still unknown.",
        ),
        "collecting_action_outcome_pairs": (
            "Collect real plays and results",
            "Approved actions now need matching business-score receipts.",
        ),
        "more_or_better_evidence_required": (
            "More or better evidence needed",
            "The safe comparison ran, but its overlap, sample size, or uncertainty is not strong enough.",
        ),
        "shadow_learning_candidate_waiting_for_human_admission": (
            "Promising strategy found in shadow",
            "A human must review assumptions before this can teach the system or change a live policy.",
        ),
    }
    stage_label, player_message = stage_copy.get(
        status,
        ("Strategy evidence available", "Review the receipts and next action before continuing."),
    )
    return {
        "schema": PROJECT_STRATEGY_LAB_SCHEMA,
        "status": status,
        "stage_label": stage_label,
        "player_message": player_message,
        "assignment_receipt_count": assignment_count,
        "offline_evaluation_receipt_count": evaluation_count,
        "latest_evaluation_receipt_id": _text(
            _field(latest, "receipt_id", "receiptId")
        )
        or None,
        "behavior_policy_id": _text(
            _field(latest, "behavior_policy_id", "behaviorPolicyId")
        )
        or None,
        "candidate_policy_id": _text(
            _field(latest, "candidate_policy_id", "candidatePolicyId")
        )
        or None,
        "episode_count": _field(estimates, "episode_count", "episodeCount"),
        "estimated_directional_lift": _field(
            estimates, "estimated_directional_lift", "estimatedDirectionalLift"
        ),
        "lift_confidence_interval_95": _object(
            _field(estimates, "lift_confidence_interval_95", "liftConfidenceInterval95")
        ),
        "effective_sample_size": _field(
            diagnostics, "effective_sample_size", "effectiveSampleSize"
        ),
        "support_coverage": _field(diagnostics, "support_coverage", "supportCoverage"),
        "shadow_learning_candidate": candidate,
        "next_action": _text(_field(lab, "next_action", "nextAction"))
        or _text(_field(readiness, "next_action", "nextAction"))
        or None,
        "receipt_pairs_verified_by_control_plane": (
            _field(
                pair_integrity,
                "pairs_verified_by_control_plane",
                "pairsVerifiedByControlPlane",
            )
            is True
        ),
        "causality_proven": False,
        "identification_assumptions_proven": False,
        "learning_admitted": False,
        "skill_confidence_updated": False,
        "policy_promoted": False,
        "policy_activated": False,
        "action_authorized": False,
        "contract": {
            "assignment_observation_schema": PROJECT_POLICY_ASSIGNMENT_OBSERVATION_SCHEMA,
            "assignment_receipt_schema": PROJECT_POLICY_ASSIGNMENT_RECEIPT_SCHEMA,
            "evaluation_pair_request_schema": PROJECT_POLICY_OFFLINE_EVALUATION_PAIR_REQUEST_SCHEMA,
            "evaluation_receipt_schema": PROJECT_POLICY_OFFLINE_EVALUATION_RECEIPT_SCHEMA,
            "human_assignment_api": "POST /api/projects/{project_id}/policy-assignments",
            "human_evaluation_api": "POST /api/projects/{project_id}/policy-evaluations",
            "agent_assignment_tool": "record_project_policy_assignment",
            "agent_evaluation_tool": "evaluate_project_offline_policy",
            "mcp_assignment_tool": "record_project_policy_assignment",
            "mcp_evaluation_tool": "evaluate_project_offline_policy",
            "minimum_receipt_pairs": 20,
            "control_plane_pair_verification_available": True,
            "deterministic_ips_snips_available": True,
            "human_learning_admission_required": True,
        },
    }


def _context_projection(plan: dict[str, Any]) -> dict[str, Any]:
    launch_context = _object(_field(plan, "project_agent_launch_context", "projectAgentLaunchContext"))
    inventory = _first_object(
        _field(plan, "project_live_context_data_inventory", "projectLiveContextDataInventory"),
        _field(launch_context, "project_live_context_data_inventory", "projectLiveContextDataInventory"),
    )
    covered_sources = [
        _text(item, 240)
        for item in _first_array(
            _field(inventory, "covered_sources", "coveredSources"),
            _field(inventory, "data_sources", "dataSources"),
        )
        if _text(item, 240)
    ]
    raw_count = _field(inventory, "source_count", "sourceCount")
    explicit_count = (
        int(raw_count)
        if isinstance(raw_count, (int, float))
        and not isinstance(raw_count, bool)
        and math.isfinite(raw_count)
        and raw_count >= 0
        else None
    )
    project_file_source = _object(_field(plan, "project_file_source", "projectFileSource"))
    freshness = _first_object(
        _field(plan, "project_live_context_freshness_contract", "projectLiveContextFreshnessContract"),
        _field(launch_context, "project_live_context_freshness_contract", "projectLiveContextFreshnessContract"),
    )
    observed = bool(inventory or project_file_source)
    return {
        "status": "observed" if observed else "needs_setup",
        "inventory_status": _text(_field(inventory, "status")) or None,
        "source_count": explicit_count if explicit_count is not None else len(covered_sources),
        "source_count_source": (
            "project_live_context_data_inventory.source_count"
            if explicit_count is not None
            else "project_live_context_data_inventory.covered_sources.length"
            if covered_sources
            else None
        ),
        "covered_sources": covered_sources[:20],
        "freshness_status": _text(_field(freshness, "status")) or None,
        "project_file_validation_status": _text(_field(project_file_source, "validation_status", "validationStatus")) or None,
        "percentage_generated": False,
    }


def _party_projection(plan: dict[str, Any], game_start: dict[str, Any]) -> dict[str, Any]:
    starter = _object(_field(game_start, "starter_loadout", "starterLoadout"))
    observed_workers = _first_array(
        _field(plan, "agent_workers", "agentWorkers"),
        _field(plan, "agent_roster", "agentRoster"),
        _field(_object(_field(plan, "party")), "workers"),
    )
    seeded_workers = _array(_field(starter, "workers"))
    worker_source = "project_plan.agent_workers" if observed_workers else "game_start.starter_loadout.workers"
    fallback_status = _text(_field(starter, "status")) or "planned_not_dispatched"
    workers: list[dict[str, Any]] = []
    for index, worker in enumerate(observed_workers or seeded_workers):
        source = _object(worker)
        workers.append(
            {
                "worker_id": _text(_field(source, "worker_id", "workerId", "id")) or f"worker-{index + 1}",
                "label": _text(_field(source, "label", "name", "title")) or "Agent worker",
                "responsibility": _text(_field(source, "responsibility", "objective", "role")) or None,
                "status": _text(_field(source, "status")) or fallback_status,
                "source_ref": worker_source,
            }
        )
    return {
        "status": "observed_from_project_plan" if observed_workers else fallback_status,
        "workers": workers,
        "specialist_roles": [
            {
                **role,
                "status": "capability_role_not_dispatch_evidence",
                "dispatch_inferred": False,
            }
            for role in _SPECIALIST_ROLES
        ],
        "dispatch_authorized": False,
        "reported_dispatch_authorized": _explicit_boolean(
            starter, "dispatch_authorized", "dispatchAuthorized"
        )
        is True,
        "worker_dispatch_inferred": False,
    }


def _capability_route(phase_id: str) -> dict[str, Any]:
    route = _CAPABILITY_ROUTES.get(
        phase_id,
        {
            "runtime_domain": "project",
            "contract_status": "unmapped_contract",
            "mcp_entrypoint": "backbone_execute",
            "worker_tools": [],
            "missing_contract": f"campaign_phase_route:{phase_id}",
            "human_gate_required": True,
        },
    )
    mission_lifecycle_tools = [
        "list_project_mission_runs",
        "start_project_mission_run",
        "bind_project_mission_action",
    ]
    return {
        **route,
        "worker_tools": list(
            dict.fromkeys([*mission_lifecycle_tools, *route["worker_tools"]])
        ),
        "supplemental_mcp_tools": list(
            dict.fromkeys(
                [*mission_lifecycle_tools, *route.get("supplemental_mcp_tools", [])]
            )
        ),
        "execution_authorized_by_projection": False,
        "dispatch_authorized_by_projection": False,
    }


def _verified_project_skill_match(
    business_cockpit: dict[str, Any],
) -> dict[str, Any] | None:
    cockpit = _object(business_cockpit)
    ledger = _object(_field(cockpit, "skill_match_ledger", "skillMatchLedger"))
    scope_fields = ("tenant_id", "company_id", "project_id")
    scope_matches = all(
        _text(_field(ledger, key))
        and _text(_field(ledger, key)) == _text(_field(cockpit, key))
        for key in scope_fields
    )
    ledger_truth = _object(_field(ledger, "truth_boundary", "truthBoundary"))
    ledger_false_fields = (
        "project_control_plane_reverified_artifact_signature",
        "business_outcomes_authenticated",
        "causality_proven",
        "skill_attribution_proven",
        "training_authorized",
        "production_promotion_authorized",
    )
    matches = _array(_field(ledger, "matches"))
    latest = _object(_field(ledger, "latest_match", "latestMatch"))
    count = _field(ledger, "match_count", "matchCount")
    if (
        _field(ledger, "schema") != PROJECT_SKILL_MATCH_LEDGER_SCHEMA
        or not scope_matches
        or _field(
            ledger_truth,
            "worker_scope_verification_available",
            "workerScopeVerificationAvailable",
        )
        is not True
        or any(_field(ledger_truth, key) is not False for key in ledger_false_fields)
        or not isinstance(count, int)
        or isinstance(count, bool)
        or count < 1
        or count != len(matches)
        or _field(ledger, "status") != "worker_verified_shadow_match_recorded"
        or not latest
    ):
        return None

    def verify_receipt(value: Any) -> dict[str, Any] | None:
        receipt = _object(value)
        actor = _object(_field(receipt, "actor"))
        mission_run = _object(_field(receipt, "mission_run", "missionRun"))
        orchestration = _object(_field(receipt, "orchestration"))
        integrity = _object(_field(receipt, "integrity"))
        truth = _object(_field(receipt, "truth_boundary", "truthBoundary"))
        authority = _object(_field(receipt, "authority"))
        match = _object(_field(receipt, "match"))
        raw_arms = _array(_field(match, "arms"))
        truth_false_fields = (
            "project_control_plane_reverified_artifact_signature",
            "business_outcome_linked",
            "causality_proven",
            "skill_attribution_proven",
            "training_dataset_ready",
        )
        authority_false_fields = (
            "skill_training_authorized",
            "live_skill_confidence_mutation_authorized",
            "routing_update_authorized",
            "production_skill_promotion_authorized",
            "policy_activation_authorized",
            "dispatch_or_action_authorized",
            "production_write_authorized",
        )
        if (
            _field(receipt, "schema") != PROJECT_SKILL_MATCH_RECEIPT_SCHEMA
            or not all(
                _text(_field(receipt, key)) == _text(_field(cockpit, key))
                for key in scope_fields
            )
            or _field(receipt, "status") != "worker_verified_shadow_match_recorded"
            or _text(_field(actor, "kind")) != "agent_worker"
            or _field(actor, "authenticated") is not True
            or _field(actor, "scope_bound", "scopeBound") is not True
            or not _text(_field(actor, "user_id", "userId"))
            or not _text(_field(receipt, "receipt_id", "receiptId"))
            or re.fullmatch(
                r"[a-f0-9]{64}",
                _text(_field(receipt, "receipt_sha256", "receiptSha256"), 64),
            )
            is None
            or not _text(_field(mission_run, "receipt_id", "receiptId"))
            or _field(
                mission_run,
                "loadout_matches_arena",
                "loadoutMatchesArena",
            )
            is not True
            or re.fullmatch(
                r"[a-f0-9]{64}", _text(_field(orchestration, "sha256"), 64)
            )
            is None
            or _field(orchestration, "scope_verified", "scopeVerified") is not True
            or _field(
                integrity,
                "worker_verified_authenticated_capture",
                "workerVerifiedAuthenticatedCapture",
            )
            is not True
            or _field(
                integrity, "runtime_contract_verified", "runtimeContractVerified"
            )
            is not True
            or _field(integrity, "common_suite_verified", "commonSuiteVerified")
            is not True
            or _field(
                integrity,
                "project_control_plane_reverified_artifact_signature",
                "projectControlPlaneReverifiedArtifactSignature",
            )
            is not False
            or any(_field(truth, key) is not False for key in truth_false_fields)
            or any(_field(authority, key) is not False for key in authority_false_fields)
            or _field(
                match,
                "business_outcomes_authenticated",
                "businessOutcomesAuthenticated",
            )
            is not False
            or _field(match, "production_winner", "productionWinner") is not False
            or len(raw_arms) != len(_TOURNAMENT_ARMS)
        ):
            return None

        common_task_count: int | None = None
        arms: list[dict[str, Any]] = []
        for index, raw_arm in enumerate(raw_arms):
            arm = _object(raw_arm)
            arm_id = _text(_field(arm, "arm_id", "armId"), 120)
            skills = [
                _text(item, 240)
                for item in _array(_field(arm, "skill_ids", "skillIds"))
                if _text(item, 240)
            ]
            score = _field(arm, "score")
            task_count = _field(arm, "task_count", "taskCount")
            cardinality_matches = (
                (arm_id == "no_skill" and len(skills) == 0)
                or (arm_id == "single_skill" and len(skills) == 1)
                or (
                    arm_id == "skill_combination"
                    and 2 <= len(skills) <= 4
                )
            )
            if (
                arm_id != _TOURNAMENT_ARMS[index]["id"]
                or not cardinality_matches
                or len(set(skills)) != len(skills)
                or not isinstance(score, (int, float))
                or isinstance(score, bool)
                or not math.isfinite(score)
                or not 0 <= score <= 1
                or not isinstance(task_count, int)
                or isinstance(task_count, bool)
                or not 1 <= task_count <= 12
                or (
                    common_task_count is not None
                    and common_task_count != task_count
                )
            ):
                return None
            common_task_count = task_count
            definition = _TOURNAMENT_ARMS[index]
            runtime_support = _object(definition["runtime_support"])
            arms.append(
                {
                    **definition,
                    "runtime_support": {
                        **runtime_support,
                        "tools": list(_array(runtime_support.get("tools"))),
                    },
                    "trial_count": task_count,
                    "selected_skill_ids": skills,
                    "score": score,
                    "task_count": task_count,
                    "claimed_outcome_ref_count": 0,
                    "authenticated_outcomes_verified_by_projection": False,
                    "evidence_source_ref": "skill_match_ledger.latest_match",
                }
            )
        if arms[2]["selected_skill_ids"][0] != arms[1]["selected_skill_ids"][0]:
            return None

        leader = _object(_field(match, "leader"))
        leader_status = _text(_field(leader, "status"), 120)
        leader_id = _text(_field(leader, "arm_id", "armId"), 120) or None
        leader_score = _field(leader, "score")
        leader_arm = next((arm for arm in arms if arm["id"] == leader_id), None)
        leader_valid = (
            leader_status == "authenticated_shadow_suite_leader"
            and leader_arm is not None
            and leader_arm["score"] == leader_score
        ) or (leader_status == "tie" and leader_id is None)
        if (
            not leader_valid
            or not isinstance(leader_score, (int, float))
            or isinstance(leader_score, bool)
            or not math.isfinite(leader_score)
            or _field(
                leader,
                "business_outcomes_authenticated",
                "businessOutcomesAuthenticated",
            )
            is not False
            or _field(leader, "production_winner", "productionWinner") is not False
        ):
            return None
        return {
            "receipt": receipt,
            "arms": arms,
            "leader": {
                "status": leader_status,
                "arm_id": leader_id,
                "tied_arm_ids": list(
                    _array(_field(leader, "tied_arm_ids", "tiedArmIds"))
                ),
                "score": leader_score,
            },
        }

    verified_latest = verify_receipt(latest)
    if verified_latest is None:
        return None
    latest_id = _text(_field(latest, "receipt_id", "receiptId"))
    if not any(
        _text(_field(_object(receipt), "receipt_id", "receiptId")) == latest_id
        and verify_receipt(receipt) is not None
        for receipt in matches
    ):
        return None
    return verified_latest


def _skill_tournament_projection(
    plan: dict[str, Any],
    scoreboard: dict[str, Any],
    business_cockpit: dict[str, Any],
) -> dict[str, Any]:
    config = _object(_field(plan, "skill_tournament", "skillTournament"))
    objective = _object(_field(config, "objective_metric", "objectiveMetric"))
    autoresearch = _object(_field(plan, "autoresearch_loop_report", "autoresearchLoopReport"))
    global_results = _object(_field(autoresearch, "global_results", "globalResults"))
    telemetry = _first_object(
        _field(plan, "skill_telemetry", "skillTelemetry"),
        _field(autoresearch, "skill_telemetry", "skillTelemetry"),
        _field(global_results, "skill_telemetry", "skillTelemetry"),
    )
    evidence = [
        _object(item)
        for item in _first_array(
            _field(telemetry, "execution_evidence", "executionEvidence", "executions"),
            _field(config, "trials"),
        )
    ]
    allowed = {arm["id"] for arm in _TOURNAMENT_ARMS}
    explicit = [
        item
        for item in evidence
        if _text(_field(item, "comparison_arm", "comparisonArm", "arm"), 120)
        in allowed
    ]
    arms: list[dict[str, Any]] = []
    for definition in _TOURNAMENT_ARMS:
        records = [
            item
            for item in explicit
            if _text(_field(item, "comparison_arm", "comparisonArm", "arm"), 120)
            == definition["id"]
        ]
        skill_ids: list[str] = []
        claimed_outcome_refs: list[str] = []
        for item in records:
            values = [*_array(_field(item, "skill_ids", "skillIds"))]
            values.append(_field(item, "skill_id", "skillId"))
            for value in values:
                normalized = _text(value, 240)
                if normalized and normalized not in skill_ids:
                    skill_ids.append(normalized)
            outcome_ref = _text(
                _field(
                    item,
                    "authenticated_outcome_id",
                    "authenticatedOutcomeId",
                    "outcome_receipt_id",
                    "outcomeReceiptId",
                ),
                240,
            )
            if outcome_ref:
                claimed_outcome_refs.append(outcome_ref)
        runtime_support = _object(definition["runtime_support"])
        arms.append(
            {
                "id": definition["id"],
                "label": definition["label"],
                "runtime_support": {
                    **runtime_support,
                    "tools": list(_array(runtime_support.get("tools"))),
                },
                "trial_count": len(records),
                "selected_skill_ids": skill_ids,
                "claimed_outcome_ref_count": len(claimed_outcome_refs),
                "authenticated_outcomes_verified_by_projection": False,
                "evidence_source_ref": "skill_telemetry.execution_evidence" if records else None,
            }
        )
    observed_count = sum(arm["trial_count"] for arm in arms)
    next_arm = next((arm["id"] for arm in arms if arm["trial_count"] == 0), None)
    all_observed = all(arm["trial_count"] > 0 for arm in arms)
    metric_id = _text(_field(objective, "metric_id", "metricId"), 240) or None
    direction = _text(_field(objective, "direction"), 40) or None
    verified_match = _verified_project_skill_match(business_cockpit)
    projected_arms = verified_match["arms"] if verified_match else arms
    projected_count = (
        sum(arm["trial_count"] for arm in projected_arms)
        if verified_match
        else observed_count
    )
    return {
        "schema": SKILL_TOURNAMENT_SCHEMA,
        "status": (
            "worker_verified_shadow_match_recorded"
            if verified_match
            else "not_started"
            if observed_count == 0
            else "shadow_evidence_recorded"
            if all_observed
            else "collecting_shadow_evidence"
        ),
        "evaluation_mode": "shadow_only",
        "runtime_evaluator": {
            "status": "available_authenticated_capture_evaluator_with_domain_orchestrator",
            "tool": "automl_evaluate_skill_tournament",
            "orchestrator_tool": "automl_run_skill_tournament",
            "request_schema": SKILL_TOURNAMENT_EVALUATION_REQUEST_SCHEMA,
            "receipt_schema": SKILL_TOURNAMENT_EVALUATION_RECEIPT_SCHEMA,
            "capture_request_schema": SKILL_TOURNAMENT_CAPTURE_REQUEST_SCHEMA,
            "capture_bundle_schema": SKILL_TOURNAMENT_CAPTURE_BUNDLE_SCHEMA,
            "episode_receipt_schema": SKILL_TOURNAMENT_EPISODE_RECEIPT_SCHEMA,
            "capture_verification_schema": SKILL_TOURNAMENT_CAPTURE_VERIFICATION_SCHEMA,
            "worker_application_trace_schema": SKILL_TOURNAMENT_APPLICATION_TRACE_SCHEMA,
            "runtime_contract_schema": SKILL_TOURNAMENT_RUNTIME_CONTRACT_SCHEMA,
            "orchestration_receipt_schema": SKILL_TOURNAMENT_ORCHESTRATION_RECEIPT_SCHEMA,
            "executes_arms": False,
            "calls_model_provider": False,
            "production_writes": False,
            "orchestrator_executes_arms": True,
            "orchestrator_calls_model_provider": True,
            "orchestrator_production_writes": False,
            "authenticated_episode_capture_contract_available": True,
            "authenticated_episode_capture_orchestrator_available": True,
            "authenticated_episode_capture_available": verified_match is not None,
            "agent_context_executor_adapter_available": True,
            "exact_skill_selection_contract_available": True,
            "runtime_contract_binding_available": True,
            "trusted_runtime_evidence_probe_required": True,
            "trusted_runtime_evidence_probe_binding_available": True,
            "runtime_evidence_probe_binding_scope": "claude_domain_provider_only",
            "runtime_evidence_coverage_id": "lightbulb.claude-domain-tournament-provider-only.v1",
            "broader_worker_runtime_coverage_available": False,
            "live_episode_executor_binding_available": True,
            "live_provider_exercised_by_projection": False,
            "trusted_producer_key_required": True,
            "trusted_producer_key_configuration_verified_by_projection": False,
            "artifact_trust_store_configuration_verified_by_projection": False,
            "missing_contract": "trusted_key_provisioning_and_non_domain_worker_runtime_coverage",
        },
        "objective": {
            "metric_id": metric_id,
            "direction": direction,
            "source_ref": "skill_tournament.objective_metric" if metric_id else None,
            "status": "configured_not_verified" if metric_id else "needs_explicit_metric_and_direction",
            "suggested_business_metric_id": scoreboard["metric_id"],
            "comparable_outcomes_verified": False,
        },
        "arms": projected_arms,
        "observed_trial_count": projected_count,
        "ignored_unrecognized_arm_count": len(evidence) - len(explicit),
        "next_shadow_arm": next_arm,
        "winner": None,
        "shadow_leader": verified_match["leader"] if verified_match else None,
        "winner_selection_status": (
            "worker_verified_shadow_leader_not_production_winner"
            if verified_match
            else "not_evaluated_from_read_only_projection"
        ),
        "winner_selection_authorized_by_projection": False,
        "comparison_integrity": {
            "common_suite_evaluator_available": True,
            "runtime_contract_supported": True,
            "authenticated_orchestrator_available": True,
            "same_task_suite_verified": verified_match is not None,
            "comparable_inputs_verified": verified_match is not None,
            "shadow_episode_receipts_authenticated": verified_match is not None,
            "project_control_plane_reverified_artifact_signature": False,
            "authenticated_outcomes_verified": False,
        },
        "promotion_requires": [
            "authenticated_shadow_episode_receipts",
            "authenticated_outcome_evidence",
            "explicit_human_approval",
        ],
        "production_promotion_authorized": False,
        "execution_authorized_by_projection": False,
    }


def _skill_lab_projection(
    plan: dict[str, Any],
    game_start: dict[str, Any],
    scoreboard: dict[str, Any],
    business_cockpit: dict[str, Any],
) -> dict[str, Any]:
    learning_campaign = _object(_field(game_start, "learning_campaign", "learningCampaign"))
    trials = _object(_field(learning_campaign, "skill_trials", "skillTrials"))
    flywheel = _object(_field(plan, "sdlc_flywheel", "sdlcFlywheel"))
    selected_skills = [
        _text(item, 240)
        for item in _first_array(
            _field(plan, "selected_platform_skill_ids", "selectedPlatformSkillIds"),
            _field(flywheel, "selected_platform_skill_ids", "selectedPlatformSkillIds"),
            _field(_object(_field(game_start, "starter_loadout", "starterLoadout")), "selected_skill_ids", "selectedSkillIds"),
        )
        if _text(item, 240)
    ]
    tournament = _skill_tournament_projection(plan, scoreboard, business_cockpit)
    configured_arms = [
        _text(item, 120)
        for item in _first_array(_field(trials, "comparison_arms", "comparisonArms"))
        if _text(item, 120)
    ]
    promotion_requires = [
        _text(item, 160)
        for item in _first_array(_field(trials, "promotion_requires", "promotionRequires"))
        if _text(item, 160)
    ]
    return {
        "status": tournament["status"]
        if tournament["status"] != "not_started"
        else _text(_field(trials, "status"))
        or "not_started",
        "evaluation_mode": _text(_field(trials, "evaluation_mode", "evaluationMode")) or "shadow_only",
        "comparison_arms": configured_arms or [arm["id"] for arm in _TOURNAMENT_ARMS],
        "selected_skill_ids": selected_skills,
        "promotion_requires": promotion_requires,
        "production_promotion_authorized": False,
        "reported_production_promotion_authorized": _explicit_boolean(
            trials, "production_promotion_authorized", "productionPromotionAuthorized"
        )
        is True,
        "policy_learning_status": _text(_field(learning_campaign, "policy_learning_status", "policyLearningStatus"))
        or "not_admitted",
        "capability_ref": _text(_field(learning_campaign, "capability_ref", "capabilityRef"))
        or "analysis_engine.autoresearch_to_automl_to_solver",
        "authenticated_outcomes_required": True,
        "explicit_human_approval_required": True,
        "tournament": tournament,
    }


def _mission_briefing(
    *,
    mission: dict[str, Any],
    mode: dict[str, Any],
    context: dict[str, Any],
    campaign_phase: dict[str, Any],
    skill_lab: dict[str, Any],
) -> dict[str, Any]:
    phase_definition = next(
        (phase for phase in _DEFAULT_PHASES if phase["id"] == mission["phase"]),
        {"specialist_role": "project_agent"},
    )
    lead_role = next(
        (
            role
            for role in _SPECIALIST_ROLES
            if role["id"] == phase_definition["specialist_role"]
        ),
        {"id": "project_agent", "label": "Project Agent"},
    )
    phase_briefing = _MISSION_PHASE_BRIEFINGS.get(
        mission["phase"],
        {
            "why_it_matters": "This mission connects current project state to the next verified outcome.",
            "expected_result": "verified_mission_artifact",
            "done_when": [
                "The expected artifact is recorded with exact project scope.",
                "Any required human gate is satisfied separately.",
            ],
            "completion_receipt": "mission_specific_receipt_required",
        },
    )
    initiative = _MISSION_INITIATIVE.get(
        mode["id"], _MISSION_INITIATIVE[PROJECT_PLAY_STYLE_DEFAULT]
    )
    tournament = _object(_field(skill_lab, "tournament"))
    arms = _array(_field(tournament, "arms"))
    raw_next_shadow_arm = _field(tournament, "next_shadow_arm", "nextShadowArm")
    next_shadow_arm = (
        _text(raw_next_shadow_arm) or None
        if isinstance(raw_next_shadow_arm, str)
        else None
    )
    next_arm = next(
        (
            _object(arm)
            for arm in arms
            if next_shadow_arm
            and _text(_field(_object(arm), "id")) == next_shadow_arm
        ),
        {},
    )
    next_shadow_arm_label = _text(_field(next_arm, "label")) or (
        next_shadow_arm.replace("_", " ")
        if next_shadow_arm
        else "All three arms observed"
    )
    route = dict(
        _object(_field(campaign_phase, "capability_route", "capabilityRoute"))
    )
    route["worker_tools"] = list(
        _array(_field(route, "worker_tools", "workerTools"))
    )
    route["supplemental_mcp_tools"] = list(
        _array(
            _field(route, "supplemental_mcp_tools", "supplementalMcpTools")
        )
    )

    return {
        "schema": PROJECT_MISSION_BRIEFING_SCHEMA,
        "status": initiative["activation_state"],
        "state_semantics": "derived_read_only_briefing_rebuilt_from_current_campaign_state",
        "mission": {
            "id": mission["id"],
            "title": mission["title"],
            "phase": mission["phase"],
            "source_ref": mission["source_ref"],
            "lead_role": {"id": lead_role["id"], "label": lead_role["label"]},
        },
        "player": {
            "why_it_matters": phase_briefing["why_it_matters"],
            "expected_result": phase_briefing["expected_result"],
            "done_when": list(phase_briefing["done_when"]),
        },
        "initiative": {
            "mode_id": mode["id"],
            "posture": mode["initiative"],
            "activation_state": initiative["activation_state"],
            "player_message": initiative["player_message"],
            "player_action_label": initiative["player_action_label"],
            "runtime_activation_authorized": False,
        },
        "agent": {
            "objective": mission["prompt"],
            "context": {
                "status": context["status"],
                "source_count": context["source_count"],
                "covered_sources": list(_array(context["covered_sources"])),
                "must_inspect_before_work": True,
                "may_invent_missing_context": False,
            },
            "capability_route": route,
            "skill_trial": {
                "policy": "test_before_trust",
                "evaluation_mode": skill_lab["evaluation_mode"],
                "comparison_arms": [arm["id"] for arm in _TOURNAMENT_ARMS],
                "selected_skill_ids": list(
                    _array(
                        _field(
                            skill_lab,
                            "selected_skill_ids",
                            "selectedSkillIds",
                        )
                    )
                ),
                "next_shadow_arm": next_shadow_arm,
                "next_shadow_arm_label": next_shadow_arm_label,
                "winner": None,
                "winner_selection_authorized_by_briefing": False,
                "execution_authorized_by_briefing": False,
                "promotion_authorized_by_briefing": False,
            },
        },
        "evidence": {
            "expected_artifact_type": phase_briefing["expected_result"],
            "completion_receipt": phase_briefing["completion_receipt"],
            "verified_evidence_count": _non_negative_integer(
                _field(
                    campaign_phase,
                    "verified_evidence_count",
                    "verifiedEvidenceCount",
                )
            ),
            "claimed_evidence_count": _non_negative_integer(
                _field(
                    campaign_phase,
                    "claimed_evidence_count",
                    "claimedEvidenceCount",
                )
            ),
            "completion_inferred": False,
            "real_outcome_required_before_learning": True,
        },
        "authority": {
            "briefing_grants_authority": False,
            "read_only_preparation_authorized_by_briefing": False,
            "shadow_schedule_authorized_by_briefing": False,
            "worker_dispatch_authorized": False,
            "live_action_authorized": False,
            "production_write_authorized": False,
        },
    }


def _mission_run_projection(
    *,
    mission: dict[str, Any],
    briefing: dict[str, Any],
    business_cockpit: dict[str, Any],
) -> dict[str, Any]:
    ledger = _object(
        _field(business_cockpit, "mission_run_ledger", "missionRunLedger")
    )
    briefing_player = _object(_field(briefing, "player"))
    briefing_evidence = _object(_field(briefing, "evidence"))
    expected_mission = {
        "id": mission["id"],
        "title": mission["title"],
        "phase": mission["phase"],
        "source_ref": mission["source_ref"],
        "briefing_schema": PROJECT_MISSION_BRIEFING_SCHEMA,
        "expected_result": _text(
            _field(briefing_player, "expected_result", "expectedResult")
        ),
        "completion_receipt": _text(
            _field(
                briefing_evidence,
                "completion_receipt",
                "completionReceipt",
            )
        ),
    }

    def matches_current(receipt: dict[str, Any]) -> bool:
        bound_mission = _object(_field(receipt, "mission"))
        return all(
            _text(_field(bound_mission, key)) == _text(value)
            for key, value in expected_mission.items()
        )

    run_receipts = _array(_field(ledger, "run_receipts", "runReceipts"))
    action_receipts = _array(
        _field(ledger, "action_receipts", "actionReceipts")
    )
    latest_run = _object(
        _field(ledger, "latest_run_receipt", "latestRunReceipt")
    )
    latest_action = _object(
        _field(ledger, "latest_action_receipt", "latestActionReceipt")
    )
    matching_runs = [
        receipt
        for value in (run_receipts or ([latest_run] if latest_run else []))
        if (receipt := _object(value)) and matches_current(receipt)
    ]
    matching_actions = [
        receipt
        for value in (action_receipts or ([latest_action] if latest_action else []))
        if (receipt := _object(value)) and matches_current(receipt)
    ]
    action_receipt = matching_actions[0] if matching_actions else {}
    run_receipt = next(
        (
            receipt
            for receipt in matching_runs
            if not action_receipt
            or _text(_field(receipt, "receipt_id", "receiptId"))
            == _text(
                _field(
                    action_receipt,
                    "mission_run_receipt_id",
                    "missionRunReceiptId",
                )
            )
        ),
        matching_runs[0] if matching_runs else {},
    )
    status = (
        "action_bound_waiting_for_outcome"
        if action_receipt
        else "briefing_locked_waiting_for_separate_authority"
        if run_receipt
        else "not_started"
    )
    timeline = _object(_field(action_receipt, "timeline"))
    return {
        "schema": PROJECT_MISSION_RUN_LEDGER_SCHEMA,
        "status": status,
        "current_mission_contract_matches": bool(run_receipt),
        "mission_run_receipt_id": _text(
            _field(run_receipt, "receipt_id", "receiptId")
        )
        or None,
        "mission_action_receipt_id": _text(
            _field(action_receipt, "receipt_id", "receiptId")
        )
        or None,
        "mission_locked_before_action": _field(
            timeline,
            "mission_locked_before_action",
            "missionLockedBeforeAction",
        )
        is True,
        "server_currentness_verified": False,
        "truth_boundary": {
            "action_semantics_verified": False,
            "external_effect_verified": False,
            "mission_completion_inferred": False,
            "causality_proven": False,
            "learning_admitted": False,
            "action_authorized": False,
        },
    }


def _mission_debrief(
    *,
    mission: dict[str, Any],
    briefing: dict[str, Any],
    outcome_ledger: dict[str, Any],
) -> dict[str, Any]:
    briefing_player = _object(_field(briefing, "player"))
    briefing_evidence = _object(_field(briefing, "evidence"))
    receipts = _array(_field(outcome_ledger, "receipts"))
    latest_receipt = _object(
        _field(outcome_ledger, "latest_receipt", "latestReceipt")
    )
    candidates = receipts or ([latest_receipt] if latest_receipt else [])
    expected_contract = {
        "id": mission["id"],
        "title": mission["title"],
        "phase": mission["phase"],
        "source_ref": mission["source_ref"],
        "briefing_schema": PROJECT_MISSION_BRIEFING_SCHEMA,
        "expected_result": _text(
            _field(briefing_player, "expected_result", "expectedResult")
        ),
        "completion_receipt": _text(
            _field(
                briefing_evidence,
                "completion_receipt",
                "completionReceipt",
            )
        ),
    }
    receipt: dict[str, Any] = {}
    for candidate in candidates:
        safe_candidate = _object(candidate)
        source = _object(_field(safe_candidate, "source"))
        binding = _object(
            _field(safe_candidate, "mission_binding", "missionBinding")
        )
        bound_mission = _object(_field(binding, "mission"))
        if (
            _field(source, "scope_bound", "scopeBound") is True
            and _text(_field(source, "trust_tier", "trustTier"))
            == "mission_action_same_scope_bound"
            and _field(
                binding,
                "mission_locked_before_action",
                "missionLockedBeforeAction",
            )
            is True
            and _text(
                _field(
                    binding,
                    "mission_run_receipt_id",
                    "missionRunReceiptId",
                )
            )
            and _text(
                _field(
                    binding,
                    "mission_action_receipt_id",
                    "missionActionReceiptId",
                )
            )
            and all(
                _text(_field(bound_mission, key)) == _text(value)
                for key, value in expected_contract.items()
            )
        ):
            receipt = safe_candidate
            break

    if not receipt:
        return {
            "schema": PROJECT_MISSION_DEBRIEF_SCHEMA,
            "status": "waiting_for_bound_result",
            "state_semantics": "derived_read_only_debrief_from_exact_receipt_chain",
            "mission": {
                "id": mission["id"],
                "title": mission["title"],
                "phase": mission["phase"],
                "contract_matches_current_projection": False,
                "server_currentness_verified": False,
            },
            "player": {
                "headline": "Mission result still waiting",
                "message": "Lock the briefing before action, bind the action event, then return with a real-score receipt.",
            },
            "evidence_chain": {
                "mission_run_receipt_id": None,
                "mission_action_receipt_id": None,
                "outcome_receipt_id": None,
                "mission_locked_before_action": False,
                "exact_scope_chain_verified": False,
            },
            "result": {
                "metric_id": None,
                "metric_label": None,
                "baseline_value": None,
                "observed_value": None,
                "movement": None,
                "mission_completed": False,
                "mission_won": False,
                "causality_proven": False,
                "learning_admitted": False,
            },
            "authority": {
                "debrief_grants_authority": False,
                "live_action_authorized": False,
                "production_write_authorized": False,
                "learning_admission_authorized": False,
                "skill_or_policy_promotion_authorized": False,
            },
        }

    binding = _object(_field(receipt, "mission_binding", "missionBinding"))
    metric = _object(_field(receipt, "metric"))
    return {
        "schema": PROJECT_MISSION_DEBRIEF_SCHEMA,
        "status": "evidence_returned",
        "state_semantics": "derived_read_only_debrief_from_exact_receipt_chain",
        "mission": {
            "id": mission["id"],
            "title": mission["title"],
            "phase": mission["phase"],
            "contract_matches_current_projection": True,
            "server_currentness_verified": False,
        },
        "player": {
            "headline": "Evidence returned",
            "message": "This mission has an exact briefing, action, and outcome receipt chain. Review what changed without treating it as causal proof.",
        },
        "evidence_chain": {
            "mission_run_receipt_id": _text(
                _field(
                    binding,
                    "mission_run_receipt_id",
                    "missionRunReceiptId",
                )
            ),
            "mission_action_receipt_id": _text(
                _field(
                    binding,
                    "mission_action_receipt_id",
                    "missionActionReceiptId",
                )
            ),
            "outcome_receipt_id": _text(
                _field(receipt, "receipt_id", "receiptId")
            ),
            "mission_locked_before_action": True,
            "exact_scope_chain_verified": True,
        },
        "result": {
            "metric_id": _text(_field(metric, "id")) or None,
            "metric_label": _text(_field(metric, "label")) or "Business score",
            "baseline_value": _field(
                metric, "baseline_value", "baselineValue"
            ),
            "observed_value": _field(
                metric, "observed_value", "observedValue"
            ),
            "movement": _text(_field(receipt, "movement")) or "observed",
            "mission_completed": False,
            "mission_won": False,
            "causality_proven": False,
            "learning_admitted": False,
        },
        "skill_trial": {
            **_object(_field(binding, "skill_trial", "skillTrial")),
            "result_attributed_to_skill": False,
            "confidence_updated": False,
        },
        "reflection": {
            "instruction": "Compare the result with the hypothesis, cite all three receipts, and propose the next evidence-gathering quest.",
            "may_claim_mission_success": False,
            "may_claim_causal_effect": False,
            "may_admit_learning": False,
        },
        "authority": {
            "debrief_grants_authority": False,
            "live_action_authorized": False,
            "production_write_authorized": False,
            "learning_admission_authorized": False,
            "skill_or_policy_promotion_authorized": False,
        },
    }


def _learning_review_projection(
    *,
    debrief: dict[str, Any],
    business_cockpit: dict[str, Any],
) -> dict[str, Any]:
    evidence_chain = _object(_field(debrief, "evidence_chain", "evidenceChain"))
    skill_trial = _object(_field(debrief, "skill_trial", "skillTrial"))
    ledger = _object(
        _field(
            business_cockpit,
            "learning_review_ledger",
            "learningReviewLedger",
        )
    )
    ledger_truth = _object(
        _field(ledger, "truth_boundary", "truthBoundary")
    )
    ledger_verified = (
        _field(ledger, "schema") == PROJECT_LEARNING_REVIEW_LEDGER_SCHEMA
        and _field(
            ledger_truth,
            "receipt_chain_verification_available",
            "receiptChainVerificationAvailable",
        )
        is True
        and _field(
            ledger_truth,
            "human_review_required",
            "humanReviewRequired",
        )
        is True
        and all(
            _field(ledger_truth, key) is False
            for key in (
                "external_outcome_truth_verified",
                "causality_proven",
                "skill_attribution_proven",
                "live_skill_confidence_mutation_authorized",
                "online_learner_update_authorized",
                "routing_update_authorized",
                "production_promotion_authorized",
            )
        )
    )
    reviews = [_object(item) for item in _array(_field(ledger, "reviews"))]
    latest_review = _object(
        _field(ledger, "latest_review", "latestReview")
    )
    supplied_candidates = reviews or ([latest_review] if latest_review else [])
    expected_chain = {
        "mission_run_receipt_id": _text(
            _field(
                evidence_chain,
                "mission_run_receipt_id",
                "missionRunReceiptId",
            )
        ),
        "mission_action_receipt_id": _text(
            _field(
                evidence_chain,
                "mission_action_receipt_id",
                "missionActionReceiptId",
            )
        ),
        "outcome_receipt_id": _text(
            _field(
                evidence_chain,
                "outcome_receipt_id",
                "outcomeReceiptId",
            )
        ),
    }
    chain_ready = (
        debrief.get("status") == "evidence_returned"
        and _field(
            evidence_chain,
            "exact_scope_chain_verified",
            "exactScopeChainVerified",
        )
        is True
        and all(expected_chain.values())
    )
    expected_admission = {
        "admit_shadow_training_observation": "admitted_shadow_training_observation",
        "reject_learning_candidate": "rejected_not_training_data",
        "defer_for_more_evidence": "deferred_more_evidence",
    }

    def verified_candidate(candidate: dict[str, Any]) -> bool:
        chain = _object(_field(candidate, "mission_chain", "missionChain"))
        actor = _object(_field(candidate, "actor"))
        truth = _object(
            _field(candidate, "truth_boundary", "truthBoundary")
        )
        authority = _object(_field(candidate, "authority"))
        candidate_decision = _text(_field(candidate, "decision"))
        expected_available = (
            candidate_decision == "admit_shadow_training_observation"
        )
        return (
            _field(candidate, "schema") == PROJECT_LEARNING_REVIEW_RECEIPT_SCHEMA
            and _field(actor, "kind") == "human_user"
            and _field(actor, "authenticated") is True
            and _field(chain, "scope_verified", "scopeVerified") is True
            and _field(chain, "linkage_verified", "linkageVerified") is True
            and _field(chain, "chronology_verified", "chronologyVerified")
            is True
            and _field(
                truth,
                "external_outcome_truth_verified",
                "externalOutcomeTruthVerified",
            )
            is False
            and _field(truth, "causality_proven", "causalityProven") is False
            and _field(
                truth,
                "skill_attribution_proven",
                "skillAttributionProven",
            )
            is False
            and bool(authority)
            and all(value is False for value in authority.values())
            and expected_admission.get(candidate_decision)
            == _text(
                _field(
                    candidate,
                    "learning_admission_status",
                    "learningAdmissionStatus",
                )
            )
            and _field(
                candidate,
                "training_observation_available",
                "trainingObservationAvailable",
            )
            is expected_available
        )

    candidates = (
        [candidate for candidate in supplied_candidates if verified_candidate(candidate)]
        if ledger_verified
        else []
    )
    matching_review: dict[str, Any] = {}
    if chain_ready:
        matching_review = next(
            (
                candidate
                for candidate in candidates
                if all(
                    _text(
                        _field(
                            _object(
                                _field(
                                    candidate,
                                    "mission_chain",
                                    "missionChain",
                                )
                            ),
                            key,
                        )
                    )
                    == expected
                    for key, expected in expected_chain.items()
                )
            ),
            {},
        )
    decision = _text(_field(matching_review, "decision")) or None
    status_by_decision = {
        "admit_shadow_training_observation": "shadow_training_observation_admitted",
        "reject_learning_candidate": "candidate_rejected",
        "defer_for_more_evidence": "more_evidence_requested",
    }
    status = (
        "waiting_for_mission_evidence"
        if not chain_ready
        else "ready_for_human_review"
        if not decision
        else status_by_decision.get(decision, "review_state_unrecognized")
    )
    can_record = chain_ready and (
        not decision or decision == "defer_for_more_evidence"
    )
    player_copy = {
        "waiting_for_mission_evidence": {
            "headline": "Finish the evidence chain",
            "message": "Return with one exact mission, action, and outcome receipt chain before reviewing a lesson.",
            "action_label": "Waiting for evidence",
        },
        "ready_for_human_review": {
            "headline": "Choose what this run teaches",
            "message": "Grade this exact run for future shadow training without changing live behavior.",
            "action_label": "Review evidence",
        },
        "shadow_training_observation_admitted": {
            "headline": "Shadow lesson saved",
            "message": "This example may inform future training. No live level-up or policy activation occurred.",
            "action_label": "Reviewed",
        },
        "candidate_rejected": {
            "headline": "Learning candidate discarded",
            "message": "This receipt chain remains evidence, but it will not become a shadow-training lesson.",
            "action_label": "Reviewed",
        },
        "more_evidence_requested": {
            "headline": "More evidence requested",
            "message": "The chain remains open for a later human decision after stronger evidence arrives.",
            "action_label": "Review again",
        },
    }
    return {
        "schema": PROJECT_LEARNING_REVIEW_SCHEMA,
        "status": status,
        "can_record_human_review": can_record,
        "current_chain_reviewed": bool(decision),
        "evidence_chain": {
            **expected_chain,
            "exact_scope_chain_verified": chain_ready,
        },
        "skill_trial": {
            "arm": _text(_field(skill_trial, "arm")) or "no_skill",
            "selected_skill_ids": _unique_text_list(
                _field(
                    skill_trial,
                    "selected_skill_ids",
                    "selectedSkillIds",
                )
            ),
            "result_attributed_to_skill": False,
        },
        "latest_review_receipt_id": _text(
            _field(matching_review, "receipt_id", "receiptId")
        )
        or None,
        "latest_decision": decision,
        "label": _text(_field(matching_review, "label")) or None,
        "reason": _text(_field(matching_review, "reason"), 1000) or None,
        "training_observation_available": (
            _field(
                matching_review,
                "training_observation_available",
                "trainingObservationAvailable",
            )
            is True
            and decision == "admit_shadow_training_observation"
        ),
        "player": player_copy.get(
            status,
            {
                "headline": "Review state needs attention",
                "message": "Inspect the learning review receipt before continuing.",
                "action_label": "Inspect receipt",
            },
        ),
        "truth_boundary": {
            "human_review_verified_by_projection": bool(decision),
            "supplied_ledger_verified": ledger_verified,
            "ignored_unverified_review_count": len(supplied_candidates)
            - len(candidates),
            "external_outcome_truth_verified": False,
            "causality_proven": False,
            "skill_attribution_proven": False,
        },
        "authority": {
            "learning_review_grants_live_authority": False,
            "live_skill_confidence_mutation_authorized": False,
            "online_learner_update_authorized": False,
            "routing_update_authorized": False,
            "policy_activation_authorized": False,
            "production_promotion_authorized": False,
        },
        "contract": {
            "request_schema": PROJECT_LEARNING_REVIEW_REQUEST_SCHEMA,
            "human_api": "GET|POST /api/projects/{project_id}/learning-reviews",
            "agent_list_tool": "list_project_learning_reviews",
            "agent_record_tool": None,
            "mcp_list_tool": "list_project_learning_reviews",
            "mcp_record_tool": "record_project_learning_review",
            "exact_receipt_chain_required": True,
            "human_review_required": True,
            "shadow_training_only": True,
        },
    }


def _learning_result_evaluation_projection(
    *,
    cockpit: dict[str, Any],
    run_id: str,
) -> dict[str, Any]:
    ledger = _object(
        _field(
            cockpit,
            "learning_result_evaluation_ledger",
            "learningResultEvaluationLedger",
        )
    )
    scope_fields = ("tenant_id", "company_id", "project_id")
    scope_matches = all(
        bool(_text(_field(ledger, key)))
        and _text(_field(ledger, key)) == _text(_field(cockpit, key))
        for key in scope_fields
    )
    truth = _object(_field(ledger, "truth_boundary", "truthBoundary"))
    supplied_evaluations = [
        _object(item) for item in _array(_field(ledger, "evaluations"))
    ]
    supplied_admissions = [
        _object(item) for item in _array(_field(ledger, "admissions"))
    ]
    evaluation_count = _field(ledger, "evaluation_count", "evaluationCount")
    admission_count = _field(ledger, "admission_count", "admissionCount")
    initial_ledger_verified = (
        _field(ledger, "schema")
        == PROJECT_LEARNING_RESULT_EVALUATION_LEDGER_SCHEMA
        and scope_matches
        and _field(
            truth,
            "independent_evaluations_available",
            "independentEvaluationsAvailable",
        )
        is True
        and _field(
            truth,
            "human_admission_receipts_available",
            "humanAdmissionReceiptsAvailable",
        )
        is True
        and _field(truth, "learner_update_inferred", "learnerUpdateInferred")
        is False
        and _field(
            truth,
            "business_effectiveness_proven",
            "businessEffectivenessProven",
        )
        is False
        and _field(
            truth,
            "production_promotion_authorized",
            "productionPromotionAuthorized",
        )
        is False
        and isinstance(evaluation_count, int)
        and not isinstance(evaluation_count, bool)
        and evaluation_count >= 0
        and evaluation_count == len(supplied_evaluations)
        and isinstance(admission_count, int)
        and not isinstance(admission_count, bool)
        and admission_count >= 0
        and admission_count == len(supplied_admissions)
    )
    evaluation_authority = (
        "learner_update_authorized",
        "skill_confidence_update_authorized",
        "routing_update_authorized",
        "model_or_policy_promotion_authorized",
        "policy_activation_authorized",
        "dispatch_or_action_authorized",
        "production_write_authorized",
    )

    def all_false_evaluation_authority(value: Any) -> bool:
        authority = _object(value)
        return len(authority) == len(evaluation_authority) and all(
            _field(authority, key) is False for key in evaluation_authority
        )

    def verify_evaluation(value: Any) -> dict[str, Any] | None:
        receipt = _object(value)
        actor = _object(_field(receipt, "actor"))
        integrity = _object(_field(receipt, "integrity"))
        boundary = _object(
            _field(receipt, "truth_boundary", "truthBoundary")
        )
        artifact_evaluation = _object(_field(receipt, "evaluation"))
        candidate = _object(
            _field(receipt, "candidate_artifact", "candidateArtifact")
        )
        status = _text(_field(receipt, "status"))
        supported = status == "independent_shadow_candidate_supported"
        valid_status = supported or status == (
            "independent_candidate_technical_gate_failed"
        )
        valid = (
            _field(receipt, "schema")
            == PROJECT_LEARNING_RESULT_EVALUATION_RECEIPT_SCHEMA
            and all(
                _text(_field(receipt, key)) == _text(_field(cockpit, key))
                for key in scope_fields
            )
            and _text(_field(actor, "kind")) == "agent_worker"
            and _field(actor, "authenticated") is True
            and _field(actor, "scope_bound", "scopeBound") is True
            and valid_status
            and _field(artifact_evaluation, "schema")
            == "lightbulb.project_learning_result_evaluation_receipt.v1"
            and _field(artifact_evaluation, "supported") is supported
            and _text(_field(artifact_evaluation, "status"))
            == (
                "shadow_learning_candidate_supported"
                if supported
                else "candidate_technical_gate_failed"
            )
            and re.fullmatch(
                r"[a-f0-9]{64}",
                _text(_field(candidate, "sha256"), 64),
            )
            is not None
            and re.fullmatch(
                r"[a-f0-9]{64}",
                _text(
                    _field(candidate, "metadata_sha256", "metadataSha256"),
                    64,
                ),
            )
            is not None
            and all(
                _field(integrity, key) is True
                for key in (
                    "exact_scope_verified",
                    "terminal_success_receipt_verified",
                    "candidate_output_lineage_verified",
                    "locked_suite_manifest_verified",
                    "artifact_receipt_digest_recomputed",
                    "independent_evaluator_attestation_verified",
                    "training_and_evaluator_workers_distinct",
                )
            )
            and _field(
                boundary,
                "technical_holdout_replayed",
                "technicalHoldoutReplayed",
            )
            is True
            and isinstance(
                _field(
                    boundary,
                    "technical_candidate_non_regression_observed",
                    "technicalCandidateNonRegressionObserved",
                ),
                bool,
            )
            and all(
                _field(boundary, key) is False
                for key in (
                    "training_effectiveness_proven",
                    "business_effectiveness_proven",
                    "causal_business_value_proven",
                    "learner_update_admitted",
                    "model_or_policy_updated",
                    "production_promotion_authorized",
                )
            )
            and all_false_evaluation_authority(_field(receipt, "authority"))
            and bool(_text(_field(receipt, "receipt_id", "receiptId")))
            and re.fullmatch(
                r"[a-f0-9]{64}",
                _text(_field(receipt, "receipt_sha256", "receiptSha256"), 64),
            )
            is not None
        )
        if not valid:
            return None
        return {
            "receipt": receipt,
            "supported": supported,
            "boundary": boundary,
            "artifact_evaluation": artifact_evaluation,
        }

    verified_evaluations = (
        [
            verified
            for candidate in supplied_evaluations
            if (verified := verify_evaluation(candidate)) is not None
        ]
        if initial_ledger_verified
        else []
    )
    latest_evaluation = _object(
        _field(ledger, "latest_evaluation", "latestEvaluation")
    )
    latest_evaluation_matches = (
        not latest_evaluation
        if not supplied_evaluations
        else _text(_field(latest_evaluation, "receipt_id", "receiptId"))
        == _text(_field(supplied_evaluations[0], "receipt_id", "receiptId"))
    )

    def verify_admission(value: Any) -> dict[str, Any] | None:
        receipt = _object(value)
        actor = _object(_field(receipt, "actor"))
        boundary = _object(
            _field(receipt, "truth_boundary", "truthBoundary")
        )
        authority = _object(_field(receipt, "authority"))
        decision = _text(_field(receipt, "decision"))
        admitted = decision == "admit_shadow_learning_candidate"
        valid_decision = admitted or decision == "reject_learning_candidate"
        status = _text(_field(receipt, "status"))
        evaluation_receipt_id = _text(
            _field(
                receipt,
                "evaluation_receipt_id",
                "evaluationReceiptId",
            )
        )
        source = next(
            (
                item
                for item in verified_evaluations
                if _text(
                    _field(item["receipt"], "receipt_id", "receiptId")
                )
                == evaluation_receipt_id
            ),
            None,
        )
        valid = (
            _field(receipt, "schema")
            == PROJECT_LEARNING_RESULT_ADMISSION_RECEIPT_SCHEMA
            and all(
                _text(_field(receipt, key)) == _text(_field(cockpit, key))
                for key in scope_fields
            )
            and source is not None
            and _text(_field(actor, "kind")) == "human_user"
            and _field(actor, "authenticated") is True
            and _field(actor, "scope_bound", "scopeBound") is True
            and valid_decision
            and status
            == (
                "admitted_shadow_learning_candidate"
                if admitted
                else "rejected_learning_candidate"
            )
            and (not admitted or bool(source and source["supported"]))
            and _field(
                boundary,
                "independent_technical_evaluation_completed",
                "independentTechnicalEvaluationCompleted",
            )
            is True
            and _field(
                boundary,
                "technical_candidate_supported",
                "technicalCandidateSupported",
            )
            is bool(source and source["supported"])
            and _field(
                boundary,
                "human_admission_decided",
                "humanAdmissionDecided",
            )
            is True
            and _field(
                boundary,
                "shadow_learning_candidate_admitted",
                "shadowLearningCandidateAdmitted",
            )
            is admitted
            and all(
                _field(boundary, key) is False
                for key in (
                    "learner_update_applied",
                    "business_effectiveness_proven",
                    "causal_business_value_proven",
                    "model_or_policy_updated",
                    "production_promotion_authorized",
                )
            )
            and len(authority) == len(evaluation_authority) + 1
            and all(
                _field(authority, key) is False
                for key in evaluation_authority
            )
            and _field(
                authority,
                "bounded_shadow_learner_update_request_authorized",
                "boundedShadowLearnerUpdateRequestAuthorized",
            )
            is admitted
            and bool(_text(_field(receipt, "receipt_id", "receiptId")))
            and re.fullmatch(
                r"[a-f0-9]{64}",
                _text(_field(receipt, "receipt_sha256", "receiptSha256"), 64),
            )
            is not None
        )
        if not valid or source is None:
            return None
        return {"receipt": receipt, "admitted": admitted, "source": source}

    verified_admissions = (
        [
            verified
            for candidate in supplied_admissions
            if (verified := verify_admission(candidate)) is not None
        ]
        if initial_ledger_verified
        else []
    )
    latest_admission = _object(
        _field(ledger, "latest_admission", "latestAdmission")
    )
    latest_admission_matches = (
        not latest_admission
        if not supplied_admissions
        else _text(_field(latest_admission, "receipt_id", "receiptId"))
        == _text(_field(supplied_admissions[0], "receipt_id", "receiptId"))
    )
    ledger_verified = (
        initial_ledger_verified
        and len(verified_evaluations) == len(supplied_evaluations)
        and len(verified_admissions) == len(supplied_admissions)
        and latest_evaluation_matches
        and latest_admission_matches
    )
    current_evaluations = (
        [
            item
            for item in verified_evaluations
            if _text(
                _field(item["receipt"], "learning_run_id", "learningRunId")
            )
            == run_id
        ]
        if ledger_verified
        else []
    )
    evaluation = current_evaluations[0] if current_evaluations else None
    admission = (
        next(
            (
                item
                for item in verified_admissions
                if item["source"] is evaluation
            ),
            None,
        )
        if ledger_verified and evaluation is not None
        else None
    )
    return {
        "ledger_verified": ledger_verified,
        "ignored_unverified_evaluation_count": len(supplied_evaluations)
        - len(verified_evaluations),
        "ignored_unverified_admission_count": len(supplied_admissions)
        - len(verified_admissions),
        "evaluation": evaluation,
        "admission": admission,
    }


def _shadow_learner_update_projection(
    *,
    cockpit: dict[str, Any],
    run_id: str,
    evaluation: dict[str, Any] | None,
    admission: dict[str, Any] | None,
) -> dict[str, Any]:
    ledger = _object(
        _field(
            cockpit,
            "shadow_learner_update_ledger",
            "shadowLearnerUpdateLedger",
        )
    )
    scope_fields = ("tenant_id", "company_id", "project_id")
    scope_matches = all(
        bool(_text(_field(ledger, key)))
        and _text(_field(ledger, key)) == _text(_field(cockpit, key))
        for key in scope_fields
    )
    supplied_updates = [_object(item) for item in _array(_field(ledger, "updates"))]
    supplied_rollbacks = [
        _object(item) for item in _array(_field(ledger, "rollbacks"))
    ]
    supplied_current = [
        _object(item)
        for item in _array(
            _field(ledger, "current_updates", "currentUpdates")
        )
    ]
    update_count = _field(ledger, "update_count", "updateCount")
    rollback_count = _field(ledger, "rollback_count", "rollbackCount")
    current_count = _field(
        ledger, "current_update_count", "currentUpdateCount"
    )
    truth = _object(_field(ledger, "truth_boundary", "truthBoundary"))
    initial_ledger_verified = (
        _field(ledger, "schema") == PROJECT_SHADOW_LEARNER_UPDATE_LEDGER_SCHEMA
        and scope_matches
        and isinstance(update_count, int)
        and not isinstance(update_count, bool)
        and update_count == len(supplied_updates)
        and isinstance(rollback_count, int)
        and not isinstance(rollback_count, bool)
        and rollback_count == len(supplied_rollbacks)
        and isinstance(current_count, int)
        and not isinstance(current_count, bool)
        and current_count == len(supplied_current)
        and _field(
            truth,
            "shadow_update_receipts_available",
            "shadowUpdateReceiptsAvailable",
        )
        is True
        and _field(
            truth,
            "rollback_receipts_available",
            "rollbackReceiptsAvailable",
        )
        is True
        and all(
            _field(truth, key) is False
            for key in (
                "active_learner_update_inferred",
                "business_effectiveness_proven",
                "production_promotion_authorized",
            )
        )
    )
    allowed_paths = [
        "skill_template.project_shadow_learning",
        "last_validated_at",
        "updated_at",
    ]
    authority_fields = (
        "active_learner_update_authorized",
        "routing_update_authorized",
        "model_or_policy_promotion_authorized",
        "policy_activation_authorized",
        "dispatch_or_action_authorized",
        "production_write_authorized",
    )
    worker_actor_fields = (
        "kind",
        "user_id",
        "authenticated",
        "scope_bound",
        "agent_context_permission_checked",
        "explicit_confirmation_checked",
    )

    def valid_sha(value: Any) -> bool:
        return re.fullmatch(r"[a-f0-9]{64}", _text(value, 64)) is not None

    def all_false_authority(value: Any) -> bool:
        authority = _object(value)
        return len(authority) == len(authority_fields) and all(
            _field(authority, key) is False for key in authority_fields
        )

    def verify_target(value: Any) -> dict[str, Any] | None:
        target = _object(value)
        expected_fields = {
            "kind",
            "skill_id",
            "skill_handle",
            "expected_active_skill_revision",
            "expected_active_instruction_sha256",
            "expected_champion_candidate_id",
            "expected_champion_instruction_sha256",
            "environment",
            "max_shadow_revision_delta",
            "allowed_mutation_paths",
        }
        valid = (
            set(target) == expected_fields
            and _field(target, "kind") == "memory_gepa_skill_instruction"
            and bool(_text(_field(target, "skill_id", "skillId")))
            and bool(_text(_field(target, "skill_handle", "skillHandle")))
            and isinstance(
                _field(
                    target,
                    "expected_active_skill_revision",
                    "expectedActiveSkillRevision",
                ),
                int,
            )
            and not isinstance(
                _field(
                    target,
                    "expected_active_skill_revision",
                    "expectedActiveSkillRevision",
                ),
                bool,
            )
            and _field(
                target,
                "expected_active_skill_revision",
                "expectedActiveSkillRevision",
            )
            >= 1
            and valid_sha(
                _field(
                    target,
                    "expected_active_instruction_sha256",
                    "expectedActiveInstructionSha256",
                )
            )
            and bool(
                _text(
                    _field(
                        target,
                        "expected_champion_candidate_id",
                        "expectedChampionCandidateId",
                    )
                )
            )
            and valid_sha(
                _field(
                    target,
                    "expected_champion_instruction_sha256",
                    "expectedChampionInstructionSha256",
                )
            )
            and _field(target, "environment") == "shadow"
            and _field(
                target,
                "max_shadow_revision_delta",
                "maxShadowRevisionDelta",
            )
            == 1
            and _array(
                _field(
                    target,
                    "allowed_mutation_paths",
                    "allowedMutationPaths",
                )
            )
            == allowed_paths
        )
        return target if valid else None

    def verify_mutation(value: Any, *, rollback: bool) -> dict[str, Any] | None:
        mutation = _object(value)
        changed_paths = _array(
            _field(mutation, "changed_paths", "changedPaths")
        )
        changed_now = changed_paths == allowed_paths
        before_revision = _field(
            mutation, "shadow_revision_before", "shadowRevisionBefore"
        )
        after_revision = _field(
            mutation, "shadow_revision_after", "shadowRevisionAfter"
        )
        before_state = _text(
            _field(mutation, "before_state_sha256", "beforeStateSha256"), 64
        )
        after_state = _text(
            _field(mutation, "after_state_sha256", "afterStateSha256"), 64
        )
        valid = (
            _field(mutation, "environment") == "shadow"
            and _array(
                _field(
                    mutation,
                    "allowed_mutation_paths",
                    "allowedMutationPaths",
                )
            )
            == allowed_paths
            and changed_paths in ([], allowed_paths)
            and isinstance(before_revision, int)
            and not isinstance(before_revision, bool)
            and isinstance(after_revision, int)
            and not isinstance(after_revision, bool)
            and after_revision - before_revision == (1 if changed_now else 0)
            and valid_sha(before_state)
            and valid_sha(after_state)
            and ((before_state != after_state) is changed_now)
            and _field(
                mutation,
                "active_skill_revision_before",
                "activeSkillRevisionBefore",
            )
            == _field(
                mutation,
                "active_skill_revision_after",
                "activeSkillRevisionAfter",
            )
            and valid_sha(
                _field(
                    mutation,
                    "active_instruction_sha256_before",
                    "activeInstructionSha256Before",
                )
            )
            and _field(
                mutation,
                "active_instruction_sha256_before",
                "activeInstructionSha256Before",
            )
            == _field(
                mutation,
                "active_instruction_sha256_after",
                "activeInstructionSha256After",
            )
            and _field(mutation, "rollback_available", "rollbackAvailable")
            is (not rollback)
        )
        return mutation if valid else None

    def verify_memory(value: Any, *, rollback: bool, claimed_sha: Any) -> bool:
        receipt = _object(value)
        boundary = _object(
            _field(receipt, "truth_boundary", "truthBoundary")
        )
        return (
            _field(receipt, "schema")
            == (
                "lightbulb.project_shadow_learner_memory_rollback_receipt.v1"
                if rollback
                else "lightbulb.project_shadow_learner_memory_apply_receipt.v1"
            )
            and _field(receipt, "status")
            in (
                ("rolled_back", "already_rolled_back")
                if rollback
                else ("applied", "already_applied")
            )
            and valid_sha(_field(receipt, "receipt_sha256", "receiptSha256"))
            and _field(receipt, "receipt_sha256", "receiptSha256") == claimed_sha
            and all_false_authority(_field(receipt, "authority"))
            and _field(boundary, "active_learner_updated", "activeLearnerUpdated")
            is False
            and _field(boundary, "routing_updated", "routingUpdated") is False
            and _field(
                boundary,
                "business_effectiveness_proven",
                "businessEffectivenessProven",
            )
            is False
            and _field(
                boundary,
                "production_promotion_authorized",
                "productionPromotionAuthorized",
            )
            is False
        )

    def verify_actor(value: Any, receipt: dict[str, Any]) -> bool:
        actor = _object(value)
        return (
            set(actor) == set(worker_actor_fields)
            and _field(actor, "kind") == "agent_worker"
            and _field(actor, "authenticated") is True
            and _field(actor, "scope_bound", "scopeBound") is True
            and _field(
                actor,
                "agent_context_permission_checked",
                "agentContextPermissionChecked",
            )
            is True
            and _field(
                actor,
                "explicit_confirmation_checked",
                "explicitConfirmationChecked",
            )
            is True
            and _text(_field(actor, "user_id", "userId"))
            == _text(_field(receipt, "user_id", "userId"))
        )

    def verify_update(value: Any) -> dict[str, Any] | None:
        receipt = _object(value)
        source = _object(_field(receipt, "source_chain", "sourceChain"))
        target = verify_target(_field(receipt, "target"))
        mutation = verify_mutation(_field(receipt, "mutation"), rollback=False)
        integrity = _object(_field(receipt, "integrity"))
        boundary = _object(
            _field(receipt, "truth_boundary", "truthBoundary")
        )
        memory_sha = _field(
            receipt, "memory_receipt_sha256", "memoryReceiptSha256"
        )
        integrity_fields = {
            "prepared_run_receipt_verified",
            "execution_receipt_verified",
            "independent_evaluation_receipt_verified",
            "human_admission_receipt_verified",
            "terminal_gepa_run_verified",
            "memory_receipt_digest_recomputed",
            "active_skill_state_unchanged",
            "mutation_ceiling_verified",
        }
        valid = (
            _field(receipt, "schema")
            == PROJECT_SHADOW_LEARNER_UPDATE_RECEIPT_SCHEMA
            and _field(receipt, "status")
            == "bounded_shadow_learner_update_applied"
            and all(
                _text(_field(receipt, key)) == _text(_field(cockpit, key))
                for key in scope_fields
            )
            and verify_actor(_field(receipt, "actor"), receipt)
            and target is not None
            and mutation is not None
            and bool(_text(_field(receipt, "update_id", "updateId")))
            and bool(_text(_field(receipt, "receipt_id", "receiptId")))
            and valid_sha(_field(receipt, "receipt_sha256", "receiptSha256"))
            and valid_sha(memory_sha)
            and verify_memory(
                _field(receipt, "memory_receipt", "memoryReceipt"),
                rollback=False,
                claimed_sha=memory_sha,
            )
            and set(integrity) == integrity_fields
            and all(_field(integrity, key) is True for key in integrity_fields)
            and _field(
                boundary,
                "shadow_learning_candidate_human_admitted",
                "shadowLearningCandidateHumanAdmitted",
            )
            is True
            and _field(
                boundary,
                "shadow_learner_updated",
                "shadowLearnerUpdated",
            )
            is True
            and _field(
                boundary,
                "shadow_learner_currently_updated",
                "shadowLearnerCurrentlyUpdated",
            )
            is True
            and all(
                _field(boundary, key) is False
                for key in (
                    "active_learner_updated",
                    "routing_updated",
                    "business_effectiveness_proven",
                    "causal_business_value_proven",
                    "production_promotion_authorized",
                )
            )
            and all_false_authority(_field(receipt, "authority"))
        )
        if not valid or target is None:
            return None
        return {
            "receipt": receipt,
            "source": source,
            "target": target,
            "mutation": mutation,
        }

    verified_updates = (
        [
            verified
            for candidate in supplied_updates
            if (verified := verify_update(candidate)) is not None
        ]
        if initial_ledger_verified
        else []
    )
    updates_by_receipt = {
        _text(_field(item["receipt"], "receipt_id", "receiptId")): item
        for item in verified_updates
    }

    def verify_rollback(value: Any) -> dict[str, Any] | None:
        receipt = _object(value)
        update_receipt_id = _text(
            _field(receipt, "update_receipt_id", "updateReceiptId")
        )
        update = updates_by_receipt.get(update_receipt_id)
        target = verify_target(_field(receipt, "target"))
        mutation = verify_mutation(_field(receipt, "mutation"), rollback=True)
        integrity = _object(_field(receipt, "integrity"))
        boundary = _object(
            _field(receipt, "truth_boundary", "truthBoundary")
        )
        memory_sha = _field(
            receipt, "memory_receipt_sha256", "memoryReceiptSha256"
        )
        integrity_fields = {
            "apply_receipt_digest_verified",
            "memory_receipt_digest_recomputed",
            "current_shadow_state_digest_verified",
            "rollback_snapshot_digest_verified",
            "active_skill_state_unchanged",
            "mutation_ceiling_verified",
        }
        valid = (
            _field(receipt, "schema")
            == PROJECT_SHADOW_LEARNER_ROLLBACK_RECEIPT_SCHEMA
            and _field(receipt, "status")
            == "bounded_shadow_learner_update_rolled_back"
            and all(
                _text(_field(receipt, key)) == _text(_field(cockpit, key))
                for key in scope_fields
            )
            and verify_actor(_field(receipt, "actor"), receipt)
            and update is not None
            and _field(
                receipt,
                "update_receipt_sha256",
                "updateReceiptSha256",
            )
            == _field(
                update["receipt"], "receipt_sha256", "receiptSha256"
            )
            and target == update["target"]
            and mutation is not None
            and _field(mutation, "rolled_back_update_id", "rolledBackUpdateId")
            == _field(update["receipt"], "update_id", "updateId")
            and bool(_text(_field(receipt, "rollback_id", "rollbackId")))
            and bool(_text(_field(receipt, "receipt_id", "receiptId")))
            and valid_sha(_field(receipt, "receipt_sha256", "receiptSha256"))
            and valid_sha(memory_sha)
            and verify_memory(
                _field(receipt, "memory_receipt", "memoryReceipt"),
                rollback=True,
                claimed_sha=memory_sha,
            )
            and set(integrity) == integrity_fields
            and all(_field(integrity, key) is True for key in integrity_fields)
            and _field(
                boundary,
                "shadow_learning_candidate_human_admitted",
                "shadowLearningCandidateHumanAdmitted",
            )
            is True
            and _field(
                boundary,
                "shadow_learner_update_previously_applied",
                "shadowLearnerUpdatePreviouslyApplied",
            )
            is True
            and _field(
                boundary,
                "shadow_learner_currently_updated",
                "shadowLearnerCurrentlyUpdated",
            )
            is False
            and all(
                _field(boundary, key) is False
                for key in (
                    "active_learner_updated",
                    "routing_updated",
                    "business_effectiveness_proven",
                    "causal_business_value_proven",
                    "production_promotion_authorized",
                )
            )
            and all_false_authority(_field(receipt, "authority"))
        )
        if not valid or update is None:
            return None
        return {"receipt": receipt, "update": update}

    verified_rollbacks = (
        [
            verified
            for candidate in supplied_rollbacks
            if (verified := verify_rollback(candidate)) is not None
        ]
        if initial_ledger_verified
        else []
    )
    rolled_back_ids = {
        _text(
            _field(
                item["receipt"],
                "update_receipt_id",
                "updateReceiptId",
            )
        )
        for item in verified_rollbacks
    }
    derived_current_ids = set(updates_by_receipt) - rolled_back_ids
    supplied_current_ids = {
        _text(_field(item, "receipt_id", "receiptId"))
        for item in supplied_current
    }
    latest_checks = all(
        (
            not entries
            and not _object(_field(ledger, snake, camel))
        )
        or (
            bool(entries)
            and _text(
                _field(
                    _object(_field(ledger, snake, camel)),
                    "receipt_id",
                    "receiptId",
                )
            )
            == _text(_field(entries[0]["receipt"], "receipt_id", "receiptId"))
        )
        for snake, camel, entries in (
            ("latest_update", "latestUpdate", verified_updates),
            ("latest_rollback", "latestRollback", verified_rollbacks),
            (
                "latest_current_update",
                "latestCurrentUpdate",
                [
                    item
                    for item in verified_updates
                    if _text(
                        _field(item["receipt"], "receipt_id", "receiptId")
                    )
                    in derived_current_ids
                ],
            ),
        )
    )
    expected_status = (
        "shadow_update_applied"
        if derived_current_ids
        else "shadow_update_rolled_back"
        if verified_rollbacks
        else "not_applied"
    )
    ledger_verified = (
        initial_ledger_verified
        and len(verified_updates) == len(supplied_updates)
        and len(verified_rollbacks) == len(supplied_rollbacks)
        and supplied_current_ids == derived_current_ids
        and current_count == len(derived_current_ids)
        and _field(ledger, "status") == expected_status
        and _field(
            truth,
            "shadow_learner_currently_updated_from_receipts",
            "shadowLearnerCurrentlyUpdatedFromReceipts",
        )
        is bool(derived_current_ids)
        and latest_checks
    )
    if not ledger_verified:
        verified_updates = []
        verified_rollbacks = []
        derived_current_ids = set()

    expected_evaluation_id = (
        _text(
            _field(evaluation["receipt"], "receipt_id", "receiptId")
        )
        if evaluation
        else ""
    )
    expected_admission_id = (
        _text(_field(admission["receipt"], "receipt_id", "receiptId"))
        if admission
        else ""
    )
    expected_candidate = (
        _object(
            _field(
                evaluation["receipt"],
                "candidate_artifact",
                "candidateArtifact",
            )
        )
        if evaluation
        else {}
    )

    def matches_current_chain(item: dict[str, Any]) -> bool:
        source = item["source"]
        candidate = _object(
            _field(source, "candidate_artifact", "candidateArtifact")
        )
        return (
            bool(run_id)
            and bool(expected_evaluation_id)
            and bool(expected_admission_id)
            and _text(
                _field(source, "learning_run_id", "learningRunId")
            )
            == run_id
            and _text(
                _field(
                    source,
                    "evaluation_receipt_id",
                    "evaluationReceiptId",
                )
            )
            == expected_evaluation_id
            and _text(
                _field(
                    source,
                    "admission_receipt_id",
                    "admissionReceiptId",
                )
            )
            == expected_admission_id
            and _text(_field(candidate, "kind"))
            == "gepa_champion_manifest"
            and _text(_field(expected_candidate, "kind"))
            == "gepa_champion_manifest"
            and all(
                _field(candidate, snake, camel)
                == _field(expected_candidate, snake, camel)
                for snake, camel in (
                    ("uri", "uri"),
                    ("sha256", "sha256"),
                    ("kind", "kind"),
                    ("size_bytes", "sizeBytes"),
                    ("metadata_sha256", "metadataSha256"),
                    ("metadata_key_count", "metadataKeyCount"),
                )
            )
        )

    update = next(
        (item for item in verified_updates if matches_current_chain(item)),
        None,
    )
    update_receipt_id = (
        _text(_field(update["receipt"], "receipt_id", "receiptId"))
        if update
        else ""
    )
    rollback = next(
        (
            item
            for item in verified_rollbacks
            if _text(
                _field(
                    item["receipt"],
                    "update_receipt_id",
                    "updateReceiptId",
                )
            )
            == update_receipt_id
        ),
        None,
    )
    currently_updated = bool(update and update_receipt_id in derived_current_ids)
    return {
        "ledger_verified": ledger_verified,
        "ignored_unverified_update_count": len(supplied_updates)
        - len(verified_updates),
        "ignored_unverified_rollback_count": len(supplied_rollbacks)
        - len(verified_rollbacks),
        "update": update,
        "rollback": rollback,
        "update_receipt_verified": update is not None,
        "currently_updated": currently_updated,
        "rolled_back": update is not None and rollback is not None,
    }


def _learning_run_quest_projection(
    *,
    cockpit: dict[str, Any],
    verified_pack_receipt_ids: set[str],
    pack_available: bool,
) -> dict[str, Any]:
    ledger = _object(
        _field(cockpit, "learning_run_ledger", "learningRunLedger")
    )
    scope_fields = ("tenant_id", "company_id", "project_id")
    scope_matches = all(
        bool(_text(_field(ledger, key)))
        and _text(_field(ledger, key)) == _text(_field(cockpit, key))
        for key in scope_fields
    )
    truth = _object(_field(ledger, "truth_boundary", "truthBoundary"))
    supplied_runs = [_object(item) for item in _array(_field(ledger, "runs"))]
    run_count = _field(ledger, "run_count", "runCount")
    admitted_count = _field(ledger, "admitted_count", "admittedCount")
    execution_count = _field(
        ledger, "execution_observation_count", "executionObservationCount"
    )
    terminal_count = _field(
        ledger, "terminal_result_count", "terminalResultCount"
    )
    initial_ledger_verified = (
        _field(ledger, "schema") == PROJECT_LEARNING_RUN_LEDGER_SCHEMA
        and scope_matches
        and _field(
            truth,
            "dataset_custody_and_memory_run_receipts_available",
            "datasetCustodyAndMemoryRunReceiptsAvailable",
        )
        is True
        and _field(
            truth,
            "memory_execution_receipts_available",
            "memoryExecutionReceiptsAvailable",
        )
        is True
        and _field(
            truth,
            "statuses_are_last_observed_not_live_worker_telemetry",
            "statusesAreLastObservedNotLiveWorkerTelemetry",
        )
        is True
        and _field(
            truth,
            "raw_lease_tokens_exposed",
            "rawLeaseTokensExposed",
        )
        is False
        and all(
            _field(truth, key) is False
            for key in (
                "worker_claim_inferred",
                "training_execution_inferred",
                "independent_evaluation_completed",
                "learner_update_admitted",
                "model_or_policy_update_inferred",
                "causal_business_value_proven",
                "production_promotion_authorized",
            )
        )
        and isinstance(run_count, int)
        and not isinstance(run_count, bool)
        and run_count >= 0
        and run_count == len(supplied_runs)
        and isinstance(admitted_count, int)
        and not isinstance(admitted_count, bool)
        and 0 <= admitted_count <= run_count
        and isinstance(execution_count, int)
        and not isinstance(execution_count, bool)
        and 0 <= execution_count <= run_count
        and isinstance(terminal_count, int)
        and not isinstance(terminal_count, bool)
        and 0 <= terminal_count <= execution_count
    )
    authority_fields = (
        "caller_worker_claim_authorized",
        "training_execution_authorized",
        "online_learner_update_authorized",
        "routing_update_authorized",
        "production_skill_or_policy_promotion_authorized",
        "policy_activation_authorized",
        "dispatch_or_action_authorized",
        "production_write_authorized",
    )

    def authority_valid(value: Any) -> bool:
        authority = _object(value)
        return len(authority) == len(authority_fields) and all(
            _field(authority, key) is False for key in authority_fields
        )

    def quest_valid(value: Any) -> bool:
        quest = _object(value)
        stages = [_object(item) for item in _array(_field(quest, "stages"))]
        return (
            _field(quest, "schema") == PROJECT_LEARNING_QUEST_SCHEMA
            and bool(_text(_field(quest, "status")))
            and bool(_text(_field(quest, "next_action", "nextAction")))
            and all(
                bool(_text(_field(stage, "id")))
                and isinstance(_field(stage, "complete"), bool)
                for stage in stages
            )
        )

    def verified_memory_run(value: Any, expected_statuses: set[str]) -> dict[str, Any] | None:
        run = _object(value)
        lineage = [_object(item) for item in _array(_field(run, "input_lineage", "inputLineage"))]
        status = _text(_field(run, "status"))
        valid = (
            _field(run, "schema") == "lightbulb.learning-run.v1"
            and all(
                _text(_field(run, key)) == _text(_field(cockpit, key))
                for key in scope_fields
            )
            and bool(_text(_field(run, "user_id", "userId")))
            and bool(_text(_field(run, "id")))
            and bool(_text(_field(run, "runtime")))
            and _field(run, "workload_type", "workloadType")
            == "project_skill_policy_learning"
            and status in expected_statuses
            and any(
                _field(item, "kind") == "project_training_dataset"
                and _text(_field(item, "uri")).startswith(
                    "artifact://run_project_learning_"
                )
                and re.fullmatch(
                    r"[a-f0-9]{64}", _text(_field(item, "sha256"), 64)
                )
                is not None
                for item in lineage
            )
        )
        return dict(run) if valid else None

    def verified_prepare(candidate: dict[str, Any]) -> dict[str, Any] | None:
        actor = _object(_field(candidate, "actor"))
        custody = _object(
            _field(candidate, "dataset_custody", "datasetCustody")
        )
        evaluation = _object(
            _field(candidate, "evaluation_plan", "evaluationPlan")
        )
        candidate_truth = _object(
            _field(candidate, "truth_boundary", "truthBoundary")
        )
        pack_receipt_id = _text(
            _field(
                candidate,
                "training_pack_receipt_id",
                "trainingPackReceiptId",
            )
        )
        receipt_sha = _text(
            _field(candidate, "receipt_sha256", "receiptSha256"), 64
        )
        run = verified_memory_run(
            _field(candidate, "learning_run", "learningRun"),
            {"queued", "admitted", "running", "succeeded", "failed", "cancelled"},
        )
        valid = (
            _field(candidate, "schema") == PROJECT_LEARNING_RUN_RECEIPT_SCHEMA
            and all(
                _text(_field(candidate, key)) == _text(_field(cockpit, key))
                for key in scope_fields
            )
            and bool(_text(_field(candidate, "user_id", "userId")))
            and _field(actor, "authenticated") is True
            and _field(actor, "scope_bound", "scopeBound") is True
            and _text(_field(actor, "kind")) in {"human_user", "agent_worker"}
            and bool(_text(_field(actor, "user_id", "userId")))
            and pack_receipt_id in verified_pack_receipt_ids
            and _field(custody, "status") == "verified_immutable_artifact"
            and _field(custody, "custody_verified", "custodyVerified") is True
            and _text(_field(custody, "artifact_uri", "artifactUri")).startswith(
                "artifact://run_project_learning_"
            )
            and re.fullmatch(
                r"[a-f0-9]{64}",
                _text(_field(custody, "artifact_sha256", "artifactSha256"), 64),
            )
            is not None
            and _field(evaluation, "status") == "locked"
            and _field(evaluation, "strategy") == "fixed_common_suite_holdout"
            and _field(
                evaluation,
                "training_rows_excluded_from_evaluation",
                "trainingRowsExcludedFromEvaluation",
            )
            is True
            and run is not None
            and all(
                _field(candidate_truth, key) is True
                for key in (
                    "training_pack_reverified",
                    "dataset_custody_verified",
                    "holdout_evaluation_plan_locked",
                    "budget_declared",
                    "durable_learning_run_created",
                )
            )
            and all(
                _field(candidate_truth, key) is False
                for key in (
                    "worker_claim_completed",
                    "training_executed",
                    "checkpoint_published",
                    "model_or_policy_updated",
                    "causal_business_value_proven",
                    "production_promotion_authorized",
                )
            )
            and authority_valid(_field(candidate, "authority"))
            and quest_valid(_field(candidate, "quest"))
            and bool(_text(_field(candidate, "receipt_id", "receiptId")))
            and re.fullmatch(r"[a-f0-9]{64}", receipt_sha) is not None
        )
        if not valid or run is None:
            return None
        return {
            "receipt": candidate,
            "run": run,
            "custody": custody,
            "evaluation": evaluation,
        }

    def verified_admission(
        value: Any,
        prepared_run: dict[str, Any],
    ) -> dict[str, Any] | None:
        admission_receipt = _object(value)
        if not admission_receipt:
            return None
        actor = _object(_field(admission_receipt, "actor"))
        admission = _object(_field(admission_receipt, "admission"))
        admission_truth = _object(
            _field(admission_receipt, "truth_boundary", "truthBoundary")
        )
        admitted_run = verified_memory_run(
            _field(admission_receipt, "learning_run", "learningRun"),
            {"admitted"},
        )
        receipt_sha = _text(
            _field(admission_receipt, "receipt_sha256", "receiptSha256"), 64
        )
        run_id = _text(_field(prepared_run, "id"))
        valid = (
            _field(admission_receipt, "schema")
            == PROJECT_LEARNING_RUN_ADMISSION_RECEIPT_SCHEMA
            and all(
                _text(_field(admission_receipt, key))
                == _text(_field(cockpit, key))
                for key in scope_fields
            )
            and bool(_text(_field(admission_receipt, "user_id", "userId")))
            and _field(actor, "authenticated") is True
            and _field(actor, "scope_bound", "scopeBound") is True
            and _text(_field(actor, "kind")) in {"human_user", "agent_worker"}
            and _text(
                _field(
                    admission_receipt,
                    "learning_run_id",
                    "learningRunId",
                )
            )
            == run_id
            and _field(admission, "capacity_admitted", "capacityAdmitted") is True
            and _field(
                admission,
                "commercially_reserved",
                "commerciallyReserved",
            )
            is True
            and _field(admission, "memory_status", "memoryStatus") == "admitted"
            and admitted_run is not None
            and _text(_field(admitted_run or {}, "id")) == run_id
            and all(
                _field(admission_truth, key) is True
                for key in (
                    "dataset_custody_verified",
                    "durable_learning_run_created",
                    "capacity_admitted",
                    "commercially_reserved",
                    "memory_claim_candidate",
                )
            )
            and all(
                _field(admission_truth, key) is False
                for key in (
                    "worker_claim_completed",
                    "training_executed",
                    "checkpoint_published",
                    "model_or_policy_updated",
                    "causal_business_value_proven",
                    "production_promotion_authorized",
                )
            )
            and authority_valid(_field(admission_receipt, "authority"))
            and quest_valid(_field(admission_receipt, "quest"))
            and bool(_text(_field(admission_receipt, "receipt_id", "receiptId")))
            and re.fullmatch(r"[a-f0-9]{64}", receipt_sha) is not None
        )
        return dict(admission_receipt) if valid else None

    def contains_execution_secret(value: Any) -> bool:
        if isinstance(value, Mapping):
            return any(
                str(key) in {"lease_token", "token_hash"}
                or contains_execution_secret(item)
                for key, item in value.items()
            )
        if isinstance(value, (list, tuple)):
            return any(contains_execution_secret(item) for item in value)
        return False

    def execution_artifact_valid(value: Any, *, checkpoint: bool) -> bool:
        artifact = _object(value)
        uri = _text(_field(artifact, "uri"), 2048)
        sha = _text(_field(artifact, "sha256"), 64)
        metadata_sha = _text(
            _field(artifact, "metadata_sha256", "metadataSha256"), 64
        )
        metadata_count = _field(
            artifact, "metadata_key_count", "metadataKeyCount"
        )
        size = _field(artifact, "size_bytes", "sizeBytes")
        base_valid = (
            (uri.startswith("artifact://") or uri.startswith("s3://"))
            and ".." not in uri
            and re.fullmatch(r"[a-f0-9]{64}", sha) is not None
            and bool(_text(_field(artifact, "kind"), 64))
            and re.fullmatch(r"[a-f0-9]{64}", metadata_sha) is not None
            and isinstance(metadata_count, int)
            and not isinstance(metadata_count, bool)
            and 0 <= metadata_count <= 64
            and (
                size is None
                or (
                    isinstance(size, int)
                    and not isinstance(size, bool)
                    and size >= 0
                )
            )
        )
        if not checkpoint:
            return base_valid
        step = _field(artifact, "step")
        attempt = _field(artifact, "attempt")
        return (
            base_valid
            and isinstance(step, int)
            and not isinstance(step, bool)
            and step >= 0
            and isinstance(attempt, int)
            and not isinstance(attempt, bool)
            and 1 <= attempt <= 10
            and bool(_text(_field(artifact, "created_at", "createdAt")))
        )

    def verified_execution(
        value: Any,
        prepared: dict[str, Any],
        admission_receipt: dict[str, Any] | None,
    ) -> dict[str, Any] | None:
        receipt = _object(value)
        if not receipt or admission_receipt is None or contains_execution_secret(receipt):
            return None
        actor = _object(_field(receipt, "actor"))
        execution = _object(_field(receipt, "execution"))
        execution_truth = _object(
            _field(receipt, "truth_boundary", "truthBoundary")
        )
        worker_claim = _object(
            _field(execution, "worker_claim", "workerClaim")
        )
        checkpoints = [
            _object(item) for item in _array(_field(execution, "checkpoints"))
        ]
        output_lineage = [
            _object(item)
            for item in _array(
                _field(execution, "output_lineage", "outputLineage")
            )
        ]
        checkpoint_count = _field(
            execution, "checkpoint_count", "checkpointCount"
        )
        output_count = _field(
            execution, "output_artifact_count", "outputArtifactCount"
        )
        attempt = _field(execution, "attempt")
        try:
            progress = float(_field(execution, "progress"))
        except (TypeError, ValueError):
            progress = math.nan
        memory_status = _text(
            _field(execution, "memory_status", "memoryStatus"), 64
        )
        terminal = memory_status in {"succeeded", "failed", "cancelled"}
        checkpoint_observed = (
            isinstance(checkpoint_count, int)
            and not isinstance(checkpoint_count, bool)
            and checkpoint_count > 0
        )
        expected_receipt_status = (
            "training_result_observed"
            if terminal
            else "fenced_worker_checkpoint_observed"
            if checkpoint_observed
            else "fenced_worker_claim_observed"
        )
        run = verified_memory_run(
            _field(receipt, "learning_run", "learningRun"),
            {
                "running",
                "cancel_requested",
                "retry_scheduled",
                "succeeded",
                "failed",
                "cancelled",
            },
        )
        run_id = _text(_field(prepared["run"], "id"))
        receipt_sha = _text(
            _field(receipt, "receipt_sha256", "receiptSha256"), 64
        )
        snapshot_sha = _text(
            _field(receipt, "memory_snapshot_sha256", "memorySnapshotSha256"),
            64,
        )
        truth_true = (
            "memory_runtime_receipt_verified",
            "fenced_worker_claim_observed",
        )
        truth_false = (
            "independent_evaluation_completed",
            "training_effectiveness_proven",
            "learner_update_admitted",
            "model_or_policy_updated",
            "causal_business_value_proven",
            "production_promotion_authorized",
            "raw_lease_token_exposed",
        )
        valid = (
            _field(receipt, "schema")
            == PROJECT_LEARNING_RUN_EXECUTION_RECEIPT_SCHEMA
            and all(
                _text(_field(receipt, key)) == _text(_field(cockpit, key))
                for key in scope_fields
            )
            and bool(_text(_field(receipt, "user_id", "userId")))
            and _text(_field(actor, "kind")) == "memory_runtime"
            and _field(actor, "authenticated") is True
            and _field(actor, "scope_bound", "scopeBound") is True
            and _field(
                actor, "worker_identity_exposed", "workerIdentityExposed"
            )
            is False
            and _text(
                _field(receipt, "learning_run_id", "learningRunId")
            )
            == run_id
            and _text(
                _field(
                    receipt,
                    "prepared_run_receipt_id",
                    "preparedRunReceiptId",
                )
            )
            == _text(_field(prepared["receipt"], "receipt_id", "receiptId"))
            and _text(
                _field(
                    receipt,
                    "admission_receipt_id",
                    "admissionReceiptId",
                )
            )
            == _text(
                _field(admission_receipt, "receipt_id", "receiptId")
            )
            and re.fullmatch(r"[a-f0-9]{64}", receipt_sha) is not None
            and re.fullmatch(r"[a-f0-9]{64}", snapshot_sha) is not None
            and _field(execution, "schema")
            == PROJECT_LEARNING_RUN_EXECUTION_SNAPSHOT_SCHEMA
            and memory_status
            in {
                "running",
                "cancel_requested",
                "retry_scheduled",
                "succeeded",
                "failed",
                "cancelled",
            }
            and run is not None
            and _text(_field(run or {}, "id")) == run_id
            and _text(_field(run or {}, "status")) == memory_status
            and isinstance(attempt, int)
            and not isinstance(attempt, bool)
            and 1 <= attempt <= 10
            and math.isfinite(progress)
            and 0 <= progress <= 1
            and _field(
                execution, "worker_claim_observed", "workerClaimObserved"
            )
            is True
            and re.fullmatch(
                r"[a-f0-9]{64}",
                _text(_field(worker_claim, "worker_hash", "workerHash"), 64),
            )
            is not None
            and re.fullmatch(
                r"[a-f0-9]{64}",
                _text(_field(worker_claim, "event_hash", "eventHash"), 64),
            )
            is not None
            and bool(
                _text(_field(worker_claim, "claimed_at", "claimedAt"))
            )
            and _field(
                worker_claim,
                "worker_identity_exposed",
                "workerIdentityExposed",
            )
            is False
            and _field(
                execution, "raw_lease_token_exposed", "rawLeaseTokenExposed"
            )
            is False
            and isinstance(checkpoint_count, int)
            and not isinstance(checkpoint_count, bool)
            and checkpoint_count == len(checkpoints)
            and all(
                execution_artifact_valid(item, checkpoint=True)
                for item in checkpoints
            )
            and isinstance(output_count, int)
            and not isinstance(output_count, bool)
            and output_count == len(output_lineage)
            and all(
                execution_artifact_valid(item, checkpoint=False)
                for item in output_lineage
            )
            and _field(
                execution,
                "terminal_result_observed",
                "terminalResultObserved",
            )
            is terminal
            and (memory_status != "succeeded" or output_count > 0)
            and _field(receipt, "status") == expected_receipt_status
            and all(_field(execution_truth, key) is True for key in truth_true)
            and all(_field(execution_truth, key) is False for key in truth_false)
            and _field(
                execution_truth,
                "checkpoint_receipt_observed",
                "checkpointReceiptObserved",
            )
            is checkpoint_observed
            and _field(
                execution_truth,
                "terminal_result_observed",
                "terminalResultObserved",
            )
            is terminal
            and _field(
                execution_truth,
                "runtime_reported_success",
                "runtimeReportedSuccess",
            )
            is (memory_status == "succeeded")
            and authority_valid(_field(receipt, "authority"))
            and quest_valid(_field(receipt, "quest"))
        )
        if not valid or run is None:
            return None
        return {"receipt": receipt, "execution": execution, "run": run}

    verified_runs = (
        [
            verified
            for candidate in supplied_runs
            if (verified := verified_prepare(candidate)) is not None
        ]
        if initial_ledger_verified
        else []
    )
    for verified in verified_runs:
        admission = verified_admission(
            _field(
                verified["receipt"],
                "latest_admission",
                "latestAdmission",
            ),
            verified["run"],
        )
        verified["admission"] = admission
        verified["execution"] = verified_execution(
            _field(
                verified["receipt"],
                "latest_execution",
                "latestExecution",
            ),
            verified,
            admission,
        )
    actual_admitted_count = sum(
        1 for verified in verified_runs if verified.get("admission") is not None
    )
    actual_execution_count = sum(
        1 for verified in verified_runs if verified.get("execution") is not None
    )
    actual_terminal_count = sum(
        1
        for verified in verified_runs
        if verified.get("execution") is not None
        and _field(
            verified["execution"]["execution"],
            "terminal_result_observed",
            "terminalResultObserved",
        )
        is True
    )
    ledger_verified = (
        initial_ledger_verified
        and len(verified_runs) == len(supplied_runs)
        and actual_admitted_count == admitted_count
        and actual_execution_count == execution_count
        and actual_terminal_count == terminal_count
    )
    if not ledger_verified:
        verified_runs = []
        actual_admitted_count = 0
        actual_execution_count = 0
        actual_terminal_count = 0
    latest = _object(_field(ledger, "latest_run", "latestRun"))
    latest_id = _text(_field(latest, "receipt_id", "receiptId"))
    current = next(
        (
            item
            for item in verified_runs
            if _text(_field(item["receipt"], "receipt_id", "receiptId"))
            == latest_id
        ),
        None,
    ) if latest_id else None
    current = current or (verified_runs[0] if verified_runs else None)
    current_run_id = (
        _text(_field(current["run"], "id")) if current is not None else ""
    )
    result_evaluation = _learning_result_evaluation_projection(
        cockpit=cockpit,
        run_id=current_run_id,
    )
    shadow_update = _shadow_learner_update_projection(
        cockpit=cockpit,
        run_id=current_run_id,
        evaluation=result_evaluation["evaluation"],
        admission=result_evaluation["admission"],
    )
    if current:
        admission = current.get("admission")
        execution_receipt = current.get("execution")
        observed_run = (
            execution_receipt["run"]
            if execution_receipt
            else _object(_field(admission, "learning_run", "learningRun"))
            if admission
            else current["run"]
        )
        observed_status = _text(_field(observed_run, "status"))
        capacity_admitted = admission is not None
        execution_snapshot = (
            execution_receipt["execution"] if execution_receipt else {}
        )
        worker_claim_observed = execution_receipt is not None
        checkpoint_count = (
            _field(
                execution_snapshot,
                "checkpoint_count",
                "checkpointCount",
            )
            if worker_claim_observed
            else 0
        )
        terminal_result_observed = (
            _field(
                execution_snapshot,
                "terminal_result_observed",
                "terminalResultObserved",
            )
            is True
        )
        runtime_reported_success = (
            terminal_result_observed and observed_status == "succeeded"
        )
        evaluation_receipt = result_evaluation["evaluation"]
        admission_receipt = result_evaluation["admission"]
        independent_evaluation_completed = evaluation_receipt is not None
        technical_candidate_supported = bool(
            evaluation_receipt
            and evaluation_receipt["supported"] is True
        )
        technical_non_regression_observed = bool(
            independent_evaluation_completed
            and _field(
                evaluation_receipt["boundary"],
                "technical_candidate_non_regression_observed",
                "technicalCandidateNonRegressionObserved",
            )
            is True
        )
        learning_admission_decided = admission_receipt is not None
        shadow_learning_candidate_admitted = bool(
            admission_receipt and admission_receipt["admitted"] is True
        )
        shadow_update_receipt_verified = shadow_update[
            "update_receipt_verified"
        ]
        shadow_learner_currently_updated = shadow_update["currently_updated"]
        shadow_update_rolled_back = shadow_update["rolled_back"]
        evaluation_receipt_id = (
            _text(
                _field(
                    evaluation_receipt["receipt"],
                    "receipt_id",
                    "receiptId",
                )
            )
            if independent_evaluation_completed
            else None
        )
        admission_receipt_id = (
            _text(
                _field(
                    admission_receipt["receipt"],
                    "receipt_id",
                    "receiptId",
                )
            )
            if learning_admission_decided
            else None
        )
        evaluation_scores = (
            _object(
                _field(
                    evaluation_receipt["artifact_evaluation"],
                    "scores",
                )
            )
            if independent_evaluation_completed
            else {}
        )
        artifact_uri = _text(
            _field(current["custody"], "artifact_uri", "artifactUri")
        )
        artifact_sha = _text(
            _field(current["custody"], "artifact_sha256", "artifactSha256")
        )
        run_projection = {
            "id": _text(_field(observed_run, "id")),
            "runtime": _text(_field(observed_run, "runtime")),
            "status": observed_status,
            "dataset_artifact_uri": artifact_uri,
            "dataset_artifact_sha256": artifact_sha,
            "durable_run_created": True,
            "capacity_admitted": capacity_admitted,
            "commercially_reserved": capacity_admitted,
            "claimable": capacity_admitted and not worker_claim_observed,
            "worker_claim_observed": worker_claim_observed,
            "checkpoint_count": checkpoint_count,
            "training_result_observed": terminal_result_observed,
            "runtime_reported_success": runtime_reported_success,
            "independent_evaluation_completed": independent_evaluation_completed,
            "technical_candidate_supported": technical_candidate_supported,
            "technical_candidate_non_regression_observed": (
                technical_non_regression_observed
            ),
            "learning_admission_decided": learning_admission_decided,
            "shadow_learning_candidate_admitted": (
                shadow_learning_candidate_admitted
            ),
            "bounded_shadow_update_request_authorized": (
                shadow_learning_candidate_admitted
            ),
            "learner_update_applied": False,
            "shadow_learner_update_applied": shadow_update_receipt_verified,
            "shadow_learner_currently_updated": (
                shadow_learner_currently_updated
            ),
            "shadow_learner_update_rolled_back": shadow_update_rolled_back,
            "active_learner_updated": False,
            "shadow_update_receipt_id": (
                _text(
                    _field(
                        shadow_update["update"]["receipt"],
                        "receipt_id",
                        "receiptId",
                    )
                )
                if shadow_update["update"]
                else None
            ),
            "shadow_rollback_receipt_id": (
                _text(
                    _field(
                        shadow_update["rollback"]["receipt"],
                        "receipt_id",
                        "receiptId",
                    )
                )
                if shadow_update["rollback"]
                else None
            ),
            "evaluation_receipt_id": evaluation_receipt_id,
            "evaluation_scores": {
                "baseline_score": _field(
                    evaluation_scores,
                    "replayed_baseline_score",
                    "replayedBaselineScore",
                ),
                "candidate_score": _field(
                    evaluation_scores,
                    "candidate_score",
                    "candidateScore",
                ),
                "candidate_delta": _field(
                    evaluation_scores,
                    "candidate_delta",
                    "candidateDelta",
                ),
                "required_failure_count": _field(
                    evaluation_scores,
                    "required_failure_count",
                    "requiredFailureCount",
                ),
            },
            "admission_receipt_id": admission_receipt_id,
            "learning_admission_decision": (
                _text(_field(admission_receipt["receipt"], "decision"))
                if learning_admission_decided
                else None
            ),
        }
        stage_status = [
            ("learning_pack", True, "Learning Lab pack verified"),
            ("dataset_custody", True, "Immutable dataset verified"),
            ("runtime_selected", True, "Learning runtime selected"),
            ("evaluation_locked", True, "Common-suite holdout locked"),
            ("budget_declared", True, "Cost and compute ceilings declared"),
            ("durable_run", True, "Durable Memory run created"),
            (
                "capacity_and_commercial_admission",
                capacity_admitted,
                "Capacity and budget admitted"
                if capacity_admitted
                else "Waiting for capacity and budget admission",
            ),
            (
                "worker_claim",
                worker_claim_observed,
                (
                    f"Fenced worker claimed; {checkpoint_count} checkpoint"
                    f"{'s' if checkpoint_count != 1 else ''} saved"
                    if worker_claim_observed and checkpoint_count > 0
                    else "A fenced Memory worker claim receipt was observed"
                    if worker_claim_observed
                    else "No fenced worker claim receipt observed"
                ),
            ),
            (
                "training_result",
                terminal_result_observed,
                (
                    "Runtime reported success; independent evaluation still required"
                    if runtime_reported_success
                    else "A fenced terminal result was observed; review before retry or stop"
                    if terminal_result_observed
                    else "No terminal training result observed"
                ),
            ),
            (
                "independent_evaluation",
                independent_evaluation_completed,
                (
                    "Independent replay passed every technical gate"
                    if technical_candidate_supported
                    else "Score held, but another required technical gate failed"
                    if independent_evaluation_completed
                    and technical_non_regression_observed
                    else "Independent replay rejected the candidate"
                    if independent_evaluation_completed
                    else "No independent candidate replay observed"
                ),
            ),
            (
                "learning_admission",
                learning_admission_decided,
                (
                    "A human admitted the candidate to a future bounded shadow-update request"
                    if shadow_learning_candidate_admitted
                    else "A human rejected the candidate; no learning update is allowed"
                    if learning_admission_decided
                    else "Waiting for a human admit-or-reject decision"
                    if technical_candidate_supported
                    else "Human admission is unavailable until the technical gate passes"
                ),
            ),
            (
                "shadow_update",
                shadow_update_receipt_verified,
                (
                    "Shadow learner updated; active behavior remains unchanged"
                    if shadow_learner_currently_updated
                    else "Shadow learner update verified, then rolled back; active behavior remains unchanged"
                    if shadow_update_rolled_back
                    else "Shadow update request is unlocked; no learner update receipt exists yet"
                    if shadow_learning_candidate_admitted
                    else "No shadow learner update is authorized or applied"
                ),
            ),
        ]
        quest = {
            "schema": PROJECT_LEARNING_QUEST_SCHEMA,
            "status": (
                "shadow_learner_currently_updated"
                if shadow_learner_currently_updated
                else "shadow_learner_update_rolled_back"
                if shadow_update_rolled_back
                else observed_status
            ),
            "next_action": (
                "obtain_capacity_and_commercial_admission"
                if not capacity_admitted
                else "await_fenced_worker_claim"
                if not worker_claim_observed
                else "await_budgeted_retry_window"
                if observed_status == "retry_scheduled"
                else "independently_evaluate_training_result"
                if runtime_reported_success
                and not independent_evaluation_completed
                else "refine_candidate_after_failed_technical_gate"
                if independent_evaluation_completed
                and not technical_candidate_supported
                else "request_human_learning_admission_decision"
                if technical_candidate_supported
                and not learning_admission_decided
                else "candidate_rejected_collect_new_evidence"
                if learning_admission_decided
                and not shadow_learning_candidate_admitted
                else "observe_shadow_learner_without_production_promotion"
                if shadow_learner_currently_updated
                else "prepare_new_candidate_after_shadow_rollback"
                if shadow_update_rolled_back
                else "request_separate_bounded_shadow_learner_update"
                if shadow_learning_candidate_admitted
                else "review_failure_before_retry_or_stop"
                if terminal_result_observed
                else "monitor_training_with_budget_and_lease_fences"
            ),
            "stages": [
                {"id": stage_id, "complete": complete, "message": message}
                for stage_id, complete, message in stage_status
            ],
        }
    else:
        run_projection = None
        stage_status = [
            (
                "learning_pack",
                pack_available,
                "Learning Lab pack verified"
                if pack_available
                else "Waiting for an exact Learning Lab pack",
            ),
            ("dataset_custody", False, "No immutable dataset receipt observed"),
            ("runtime_selected", False, "No learning runtime selected"),
            ("evaluation_locked", False, "No common-suite holdout locked"),
            ("budget_declared", False, "No cost and compute ceilings declared"),
            ("durable_run", False, "No durable Memory run observed"),
            (
                "capacity_and_commercial_admission",
                False,
                "No capacity and budget admission observed",
            ),
            ("worker_claim", False, "No fenced worker claim receipt observed"),
            ("training_result", False, "No training result receipt observed"),
            (
                "independent_evaluation",
                False,
                "No independent candidate replay observed",
            ),
            (
                "learning_admission",
                False,
                "No human learning admission decision observed",
            ),
            (
                "shadow_update",
                False,
                "No shadow learner update is authorized or applied",
            ),
        ]
        quest = {
            "schema": PROJECT_LEARNING_QUEST_SCHEMA,
            "status": (
                "waiting_for_learning_run_preparation"
                if pack_available
                else "collect_learning_lab_pack"
            ),
            "next_action": (
                "publish_dataset_and_create_queued_learning_run"
                if pack_available
                else "package_verified_arena_and_human_review_evidence"
            ),
            "stages": [
                {"id": stage_id, "complete": complete, "message": message}
                for stage_id, complete, message in stage_status
            ],
        }
    return {
        "ledger_verified": ledger_verified,
        "ignored_unverified_run_count": len(supplied_runs) - len(verified_runs),
        "run_count": len(verified_runs),
        "admitted_count": actual_admitted_count,
        "execution_observation_count": actual_execution_count,
        "terminal_result_count": actual_terminal_count,
        "status": (
            _text(_field(ledger, "status"))
            if current
            else quest["status"]
        ),
        "learning_run": run_projection,
        "quest": quest,
        "result_evaluation": result_evaluation,
        "shadow_learner_update": shadow_update,
    }


def _learning_lab_projection(
    *,
    business_cockpit: dict[str, Any],
) -> dict[str, Any]:
    cockpit = _object(business_cockpit)
    ledger = _object(
        _field(cockpit, "training_pack_ledger", "trainingPackLedger")
    )
    scope_fields = ("tenant_id", "company_id", "project_id")
    scope_matches = all(
        bool(_text(_field(ledger, key)))
        and _text(_field(ledger, key)) == _text(_field(cockpit, key))
        for key in scope_fields
    )
    ledger_truth = _object(
        _field(ledger, "truth_boundary", "truthBoundary")
    )
    ledger_false_fields = (
        "training_dataset_ready",
        "durable_learning_run_created",
        "capacity_or_commercial_admission_complete",
        "training_executed",
        "online_learning_updated",
        "production_promotion_authorized",
    )
    supplied_packs = [
        _object(item) for item in _array(_field(ledger, "packs"))
    ]
    supplied_latest = _object(
        _field(ledger, "latest_pack", "latestPack")
    )
    count = _field(ledger, "pack_count", "packCount")
    ledger_verified = (
        _field(ledger, "schema") == PROJECT_TRAINING_PACK_LEDGER_SCHEMA
        and scope_matches
        and _field(
            ledger_truth,
            "exact_receipt_pair_verification_available",
            "exactReceiptPairVerificationAvailable",
        )
        is True
        and _field(
            ledger_truth,
            "candidate_observations_only",
            "candidateObservationsOnly",
        )
        is True
        and all(
            _field(ledger_truth, key) is False
            for key in ledger_false_fields
        )
        and isinstance(count, int)
        and not isinstance(count, bool)
        and count >= 0
        and count == len(supplied_packs)
    )

    authority_false_fields = (
        "dataset_registration_authorized",
        "durable_learning_run_creation_authorized",
        "capacity_or_commercial_admission_authorized",
        "training_execution_authorized",
        "online_learner_update_authorized",
        "routing_update_authorized",
        "production_skill_or_policy_promotion_authorized",
        "policy_activation_authorized",
        "dispatch_or_action_authorized",
        "production_write_authorized",
    )
    plan_false_fields = (
        "runtime_selected",
        "dataset_artifact_published",
        "holdout_and_evaluation_plan_verified",
        "budget_declared",
        "durable_run_created",
        "capacity_admitted",
        "commercially_reserved",
        "operator_approved",
        "claimable",
    )
    truth_true_fields = (
        "arena_match_worker_verified",
        "human_shadow_observation_admitted",
        "exact_receipt_pair_linked",
    )
    truth_false_fields = (
        "external_outcome_truth_verified",
        "causality_proven",
        "skill_attribution_proven",
        "training_dataset_ready",
        "durable_learning_run_created",
        "online_learning_updated",
    )
    evidence_true_fields = (
        "exact_scope_verified",
        "same_mission_run_verified",
        "exact_skill_loadout_verified",
        "arena_match_verified",
        "human_lesson_admitted",
    )

    def verified_pack(candidate: dict[str, Any]) -> dict[str, Any] | None:
        actor = _object(_field(candidate, "actor"))
        evidence = _object(
            _field(candidate, "evidence_pair", "evidencePair")
        )
        pack = _object(
            _field(candidate, "training_pack", "trainingPack")
        )
        skill_trial = _object(
            _field(pack, "skill_trial", "skillTrial")
        )
        graded_observation = _object(
            _field(pack, "graded_observation", "gradedObservation")
        )
        selected = _unique_text_list(
            _field(
                skill_trial,
                "selected_skill_ids",
                "selectedSkillIds",
            ),
            4,
        )
        arm = _text(_field(skill_trial, "arm"))
        cardinality_matches = (
            (arm == "no_skill" and len(selected) == 0)
            or (arm == "single_skill" and len(selected) == 1)
            or (arm == "skill_combination" and len(selected) >= 2)
        )
        lineage = [
            _object(item) for item in _array(_field(pack, "lineage"))
        ]
        plan = _object(
            _field(candidate, "learning_run_plan", "learningRunPlan")
        )
        truth = _object(
            _field(candidate, "truth_boundary", "truthBoundary")
        )
        authority = _object(_field(candidate, "authority"))
        receipt_ids_valid = all(
            bool(_text(_field(evidence, key)))
            for key in (
                "skill_match_receipt_id",
                "learning_review_receipt_id",
                "mission_run_receipt_id",
                "mission_action_receipt_id",
                "outcome_receipt_id",
            )
        )
        receipt_sha256 = _text(
            _field(candidate, "receipt_sha256", "receiptSha256"),
            64,
        )
        pack_sha256 = _text(
            _field(
                pack,
                "training_pack_sha256",
                "trainingPackSha256",
            ),
            64,
        )
        valid = (
            _field(candidate, "schema")
            == PROJECT_TRAINING_PACK_RECEIPT_SCHEMA
            and all(
                _text(_field(candidate, key))
                == _text(_field(cockpit, key))
                for key in scope_fields
            )
            and _field(candidate, "status")
            == "shadow_training_candidate_packaged"
            and _text(_field(actor, "kind")) == "agent_worker"
            and _field(actor, "authenticated") is True
            and _field(actor, "scope_bound", "scopeBound") is True
            and bool(_text(_field(actor, "user_id", "userId")))
            and bool(_text(_field(candidate, "receipt_id", "receiptId")))
            and re.fullmatch(r"[a-f0-9]{64}", receipt_sha256) is not None
            and receipt_ids_valid
            and all(
                _field(evidence, key) is True
                for key in evidence_true_fields
            )
            and _field(pack, "schema") == PROJECT_TRAINING_PACK_SCHEMA
            and _field(pack, "status")
            == "reproducible_shadow_training_candidate_packaged"
            and _field(pack, "dataset_role", "datasetRole")
            == "project_skill_policy_candidate_observation"
            and _field(pack, "observation_count", "observationCount") == 1
            and _field(graded_observation, "schema")
            == "lightbulb.project_shadow_training_observation.v1"
            and _field(graded_observation, "available") is True
            and _field(graded_observation, "dataset_role", "datasetRole")
            == "human_graded_project_mission_shadow_observation"
            and bool(
                _text(
                    _field(graded_observation, "metric_id", "metricId")
                )
            )
            and bool(_text(_field(graded_observation, "label")))
            and bool(
                _text(
                    _field(
                        graded_observation,
                        "observed_movement",
                        "observedMovement",
                    )
                )
            )
            and cardinality_matches
            and len(lineage) == 2
            and all(
                bool(_text(_field(item, "receipt_id", "receiptId")))
                and re.fullmatch(
                    r"[a-f0-9]{64}",
                    _text(_field(item, "sha256"), 64),
                )
                is not None
                for item in lineage
            )
            and re.fullmatch(r"[a-f0-9]{64}", pack_sha256) is not None
            and _field(plan, "schema")
            == PROJECT_LEARNING_RUN_ADMISSION_PLAN_SCHEMA
            and _field(plan, "status")
            == "evidence_pack_ready_admission_not_requested"
            and all(
                _field(plan, key) is False for key in plan_false_fields
            )
            and all(
                _field(truth, key) is True for key in truth_true_fields
            )
            and all(
                _field(truth, key) is False for key in truth_false_fields
            )
            and len(authority) == len(authority_false_fields)
            and all(
                _field(authority, key) is False
                for key in authority_false_fields
            )
        )
        if not valid:
            return None
        return {
            "receipt": candidate,
            "evidence_pair": evidence,
            "training_pack": pack,
            "skill_trial": {
                "arm": arm,
                "selected_skill_ids": selected,
            },
            "training_target": {
                "metric_id": _text(
                    _field(graded_observation, "metric_id", "metricId")
                ),
                "label": _text(_field(graded_observation, "label")),
                "observed_movement": _text(
                    _field(
                        graded_observation,
                        "observed_movement",
                        "observedMovement",
                    )
                ),
            },
            "learning_run": plan,
        }

    verified_packs = (
        [
            verified
            for candidate in supplied_packs
            if (verified := verified_pack(candidate)) is not None
        ]
        if ledger_verified
        else []
    )
    latest_id = _text(
        _field(supplied_latest, "receipt_id", "receiptId")
    )
    latest = next(
        (
            item
            for item in verified_packs
            if _text(
                _field(item["receipt"], "receipt_id", "receiptId")
            )
            == latest_id
        ),
        None,
    ) if latest_id else None
    current = latest or (verified_packs[0] if verified_packs else None)
    learning_run_quest = _learning_run_quest_projection(
        cockpit=cockpit,
        verified_pack_receipt_ids={
            _text(_field(item["receipt"], "receipt_id", "receiptId"))
            for item in verified_packs
            if _text(_field(item["receipt"], "receipt_id", "receiptId"))
        },
        pack_available=current is not None,
    )
    status = (
        learning_run_quest["status"]
        if learning_run_quest["learning_run"] is not None
        else (
            "shadow_training_candidate_packaged"
            if current
            else "awaiting_verified_evidence_pair"
        )
    )
    return {
        "schema": PROJECT_LEARNING_LAB_SCHEMA,
        "status": status,
        "pack_count": len(verified_packs),
        "observation_count": (
            _field(
                current["training_pack"],
                "observation_count",
                "observationCount",
            )
            if current
            else 0
        ),
        "latest_pack_receipt_id": (
            _text(
                _field(current["receipt"], "receipt_id", "receiptId")
            )
            if current
            else None
        ),
        "skill_trial": (
            current["skill_trial"]
            if current
            else {"arm": None, "selected_skill_ids": []}
        ),
        "training_target": (
            current["training_target"]
            if current
            else {
                "metric_id": None,
                "label": None,
                "observed_movement": None,
            }
        ),
        "evidence_pair": (
            {
                "arena_match_verified": True,
                "human_lesson_admitted": True,
                "exact_mission_and_loadout_verified": True,
                "skill_match_receipt_id": _text(
                    _field(
                        current["evidence_pair"],
                        "skill_match_receipt_id",
                    )
                ),
                "learning_review_receipt_id": _text(
                    _field(
                        current["evidence_pair"],
                        "learning_review_receipt_id",
                    )
                ),
                "mission_run_receipt_id": _text(
                    _field(
                        current["evidence_pair"],
                        "mission_run_receipt_id",
                    )
                ),
            }
            if current
            else {
                "arena_match_verified": False,
                "human_lesson_admitted": False,
                "exact_mission_and_loadout_verified": False,
            }
        ),
        "learning_run": (
            learning_run_quest["learning_run"]
            if learning_run_quest["learning_run"] is not None
            else (
            {
                "status": _text(_field(current["learning_run"], "status")),
                "durable_run_created": False,
                "capacity_admitted": False,
                "commercially_reserved": False,
                "claimable": False,
            }
            if current
            else {
                "status": "waiting_for_training_candidate_pack",
                "durable_run_created": False,
                "capacity_admitted": False,
                "commercially_reserved": False,
                "claimable": False,
            }
            )
        ),
        "training_quest": learning_run_quest["quest"],
        "truth_boundary": {
            "supplied_ledger_verified": ledger_verified,
            "ignored_unverified_pack_count": len(supplied_packs)
            - len(verified_packs),
            "learning_run_ledger_verified": learning_run_quest["ledger_verified"],
            "ignored_unverified_run_count": learning_run_quest[
                "ignored_unverified_run_count"
            ],
            "candidate_observation_only": True,
            "training_dataset_ready": learning_run_quest["learning_run"]
            is not None,
            "durable_learning_run_created": learning_run_quest["learning_run"]
            is not None,
            "capacity_and_commercial_admission_verified": learning_run_quest[
                "admitted_count"
            ]
            > 0,
            "worker_claim_inferred": False,
            "worker_claim_observed": _field(
                learning_run_quest["learning_run"],
                "worker_claim_observed",
                "workerClaimObserved",
            )
            is True,
            "checkpoint_observed": (
                _field(
                    learning_run_quest["learning_run"],
                    "checkpoint_count",
                    "checkpointCount",
                )
                or 0
            )
            > 0,
            "terminal_result_observed": _field(
                learning_run_quest["learning_run"],
                "training_result_observed",
                "trainingResultObserved",
            )
            is True,
            "runtime_reported_success": _field(
                learning_run_quest["learning_run"],
                "runtime_reported_success",
                "runtimeReportedSuccess",
            )
            is True,
            "training_executed": _field(
                learning_run_quest["learning_run"],
                "training_result_observed",
                "trainingResultObserved",
            )
            is True,
            "independent_evaluation_ledger_verified": learning_run_quest[
                "result_evaluation"
            ]["ledger_verified"],
            "independent_evaluation_completed": _field(
                learning_run_quest["learning_run"],
                "independent_evaluation_completed",
                "independentEvaluationCompleted",
            )
            is True,
            "technical_candidate_supported": _field(
                learning_run_quest["learning_run"],
                "technical_candidate_supported",
                "technicalCandidateSupported",
            )
            is True,
            "technical_candidate_non_regression_observed": _field(
                learning_run_quest["learning_run"],
                "technical_candidate_non_regression_observed",
                "technicalCandidateNonRegressionObserved",
            )
            is True,
            "human_learning_admission_decided": _field(
                learning_run_quest["learning_run"],
                "learning_admission_decided",
                "learningAdmissionDecided",
            )
            is True,
            "shadow_learning_candidate_admitted": _field(
                learning_run_quest["learning_run"],
                "shadow_learning_candidate_admitted",
                "shadowLearningCandidateAdmitted",
            )
            is True,
            "shadow_update_ledger_verified": learning_run_quest[
                "shadow_learner_update"
            ]["ledger_verified"],
            "shadow_update_receipt_verified": learning_run_quest[
                "shadow_learner_update"
            ]["update_receipt_verified"],
            "shadow_learner_currently_updated": learning_run_quest[
                "shadow_learner_update"
            ]["currently_updated"],
            "shadow_learner_update_rolled_back": learning_run_quest[
                "shadow_learner_update"
            ]["rolled_back"],
            "active_learner_updated": False,
            "training_effectiveness_proven": False,
            "raw_lease_token_exposed": False,
            "online_learning_updated": False,
        },
        "authority": {
            key: False for key in authority_false_fields
        },
        "contract": {
            "human_api": "GET /api/projects/{project_id}/training-packs",
            "internal_worker_api": "GET|POST /api/internal/projects/{project_id}/training-packs",
            "agent_list_tool": "list_project_training_packs",
            "agent_record_tool": "record_project_training_pack",
            "mcp_list_tool": "list_project_training_packs",
            "mcp_record_tool": None,
            "learning_run_api": "GET|POST /api/projects/{project_id}/learning-runs",
            "internal_learning_run_api": "GET|POST /api/internal/projects/{project_id}/learning-runs",
            "internal_execution_sync_api": "POST /api/internal/projects/{project_id}/learning-runs/{run_id}/execution/synchronize",
            "learning_result_evaluation_api": "GET /api/projects/{project_id}/learning-result-evaluations",
            "human_learning_result_admission_api": "POST /api/projects/{project_id}/learning-result-evaluations/{evaluation_receipt_id}/admission",
            "internal_learning_result_evaluation_api": "POST /api/internal/projects/{project_id}/learning-runs/{run_id}/result-evaluations",
            "shadow_learner_update_api": "GET /api/projects/{project_id}/shadow-learner-updates",
            "internal_shadow_learner_update_api": "GET|POST /api/internal/projects/{project_id}/shadow-learner-updates",
            "agent_shadow_learner_tools": [
                "list_project_shadow_learner_updates",
                "apply_project_shadow_learner_update",
                "rollback_project_shadow_learner_update",
            ],
            "mcp_shadow_learner_list_tool": "list_project_shadow_learner_updates",
            "mcp_shadow_learner_mutation_tool": None,
            "agent_learning_run_tools": [
                "list_project_learning_runs",
                "prepare_project_learning_run",
                "admit_project_learning_run",
                "claim_project_learning_run",
                "heartbeat_project_learning_run",
                "checkpoint_project_learning_run",
                "finish_project_learning_run",
                "synchronize_project_learning_execution",
            ],
            "mcp_learning_run_list_tool": "list_project_learning_runs",
            "mcp_learning_run_mutations_private_opt_in": True,
            "worker_execution_uses_opaque_local_lease_handle": True,
            "raw_lease_credential_exposed_to_agent_or_mcp": False,
            "technical_gate_is_not_business_value_proof": True,
            "admitted_candidate_requires_separate_shadow_update_receipt": True,
            "shadow_update_changes_active_learner": False,
            "memory_learning_run_ledger_required_next": learning_run_quest[
                "learning_run"
            ]
            is None,
        },
    }


def _game_checkpoint(
    *,
    mission: dict[str, Any],
    briefing: dict[str, Any],
    debrief: dict[str, Any],
    scoreboard: dict[str, Any],
    outcome_ledger: dict[str, Any],
    science_lab: dict[str, Any],
    strategy_lab: dict[str, Any],
    skill_lab: dict[str, Any],
    campaign_map: list[dict[str, Any]],
) -> dict[str, Any]:
    tournament = _object(_field(skill_lab, "tournament"))
    arms = [_object(item) for item in _array(_field(tournament, "arms"))]
    observed_arms = [
        _text(_field(arm, "id"), 120)
        for arm in arms
        if _non_negative_integer(_field(arm, "trial_count", "trialCount")) > 0
        and _text(_field(arm, "id"), 120)
    ]
    next_shadow_arm = (
        _text(_field(tournament, "next_shadow_arm", "nextShadowArm"), 120)
        or None
    )
    next_shadow_arm_definition = next(
        (
            arm
            for arm in arms
            if _text(_field(arm, "id"), 120) == next_shadow_arm
        ),
        {},
    )
    outcome_count = _non_negative_integer(
        _field(outcome_ledger, "receipt_count", "receiptCount")
    )
    verified_science_count = _non_negative_integer(
        _field(science_lab, "verified_receipt_count", "verifiedReceiptCount")
    )
    supplied_science_count = _non_negative_integer(
        _field(science_lab, "receipt_count", "receiptCount")
    )
    policy_evaluation_count = _non_negative_integer(
        _field(
            strategy_lab,
            "offline_evaluation_receipt_count",
            "offlineEvaluationReceiptCount",
        )
    )
    policy_assignment_count = _non_negative_integer(
        _field(
            strategy_lab,
            "assignment_receipt_count",
            "assignmentReceiptCount",
        )
    )
    shadow_skill_trial_count = sum(
        _non_negative_integer(_field(arm, "trial_count", "trialCount"))
        for arm in arms
    )
    verified_campaign_phase_ids = [
        _text(_field(phase, "id"), 120)
        for phase in campaign_map
        if _non_negative_integer(
            _field(
                phase,
                "verified_evidence_count",
                "verifiedEvidenceCount",
            )
        )
        > 0
        and _text(_field(phase, "id"), 120)
    ]

    status = "awaiting_first_verified_result"
    if supplied_science_count > 0 and verified_science_count == 0:
        status = "supplied_evidence_needs_verification"
    if shadow_skill_trial_count > 0:
        status = "shadow_skill_evidence_recorded"
    if verified_science_count > 0:
        status = "verified_science_progress_recorded"
    if policy_assignment_count > 0:
        status = "shadow_strategy_evidence_collecting"
    if policy_evaluation_count > 0:
        status = "shadow_strategy_evidence_recorded"
    if _field(strategy_lab, "shadow_learning_candidate", "shadowLearningCandidate") is True:
        status = "shadow_strategy_candidate_ready_for_review"
    if outcome_count > 0:
        status = "business_result_observed"

    copy: dict[str, tuple[str, str]] = {
        "awaiting_first_verified_result": (
            "No verified result yet",
            "Finish the current mission and return with a receipt.",
        ),
        "supplied_evidence_needs_verification": (
            "Evidence supplied, verification still needed",
            "Scope-check the receipt before the campaign advances.",
        ),
        "shadow_skill_evidence_recorded": (
            "Agent training observations recorded",
            "Keep the task suite fixed and test the next skill loadout.",
        ),
        "verified_science_progress_recorded": (
            "Verified science progress recorded",
            "The evidence chain advanced; continue to the next missing stage.",
        ),
        "shadow_strategy_evidence_collecting": (
            "Strategy evidence is being collected",
            "Match each approved play to a real business-score receipt.",
        ),
        "shadow_strategy_evidence_recorded": (
            "Shadow strategy evidence recorded",
            "Review evidence quality before proposing any learning.",
        ),
        "shadow_strategy_candidate_ready_for_review": (
            "Promising strategy ready for review",
            "A human must review assumptions before learning can be admitted.",
        ),
        "business_result_observed": (
            "Business score movement observed",
            "The latest "
            f"{scoreboard.get('metric_label') or 'business score'} receipt was "
            f"{scoreboard.get('movement') or 'observed'}. It does not prove "
            "this mission caused the movement.",
        ),
    }
    headline, player_message = copy[status]
    briefing_initiative = _object(_field(briefing, "initiative"))
    briefing_evidence = _object(_field(briefing, "evidence"))
    comparison_integrity = _object(
        _field(tournament, "comparison_integrity", "comparisonIntegrity")
    )

    return {
        "schema": PROJECT_GAME_CHECKPOINT_SCHEMA,
        "status": status,
        "state_semantics": "derived_read_only_checkpoint_from_current_project_evidence",
        "player": {
            "headline": headline,
            "message": player_message,
            "not_a_mission_win_yet": True,
            "no_agent_level_up_yet": True,
        },
        "progress": {
            "current_phase": mission["phase"],
            "verified_campaign_phase_count": len(verified_campaign_phase_ids),
            "verified_campaign_phase_ids": verified_campaign_phase_ids,
            "verified_science_receipt_count": verified_science_count,
            "business_outcome_receipt_count": outcome_count,
            "shadow_policy_assignment_receipt_count": policy_assignment_count,
            "shadow_policy_evaluation_receipt_count": policy_evaluation_count,
            "shadow_skill_trial_count": shadow_skill_trial_count,
        },
        "business_score": {
            "observation_present": outcome_count > 0,
            "metric_id": scoreboard["metric_id"],
            "metric_label": scoreboard["metric_label"],
            "display_value": scoreboard["display_value"],
            "movement": scoreboard["movement"],
            "receipt_id": scoreboard["receipt_id"],
            "receipt_trust_tier": scoreboard["receipt_trust_tier"],
            "receipt_scope_bound": scoreboard["receipt_scope_bound"],
            "caused_by_current_mission": False,
            "causality_proven": False,
        },
        "skill_training": {
            "status": _text(_field(tournament, "status")) or "not_started",
            "observed_arms": observed_arms,
            "next_shadow_arm": next_shadow_arm,
            "next_shadow_arm_label": _text(
                _field(next_shadow_arm_definition, "label")
            )
            or (
                next_shadow_arm.replace("_", " ")
                if next_shadow_arm
                else "All three arms observed"
            ),
            "winner": None,
            "same_task_suite_verified": _field(
                comparison_integrity,
                "same_task_suite_verified",
                "sameTaskSuiteVerified",
            )
            is True,
            "shadow_episode_receipts_authenticated": _field(
                comparison_integrity,
                "shadow_episode_receipts_authenticated",
                "shadowEpisodeReceiptsAuthenticated",
            )
            is True,
            "evidence_trust_status": (
                "authenticated_shadow_episode_receipts"
                if _field(
                    comparison_integrity,
                    "shadow_episode_receipts_authenticated",
                    "shadowEpisodeReceiptsAuthenticated",
                )
                is True
                else "reported_shadow_observations_not_authenticated"
            ),
            "authenticated_outcomes_verified": False,
            "result_attributed_to_skill": False,
            "skill_confidence_updated": False,
        },
        "science_progress": {
            "status": science_lab["status"],
            "verified_receipt_count": verified_science_count,
            "next_stage": _field(
                _object(_field(science_lab, "next_quest", "nextQuest")),
                "stage",
            )
            or None,
            "scientific_validity_proven": False,
        },
        "strategy_learning": {
            "status": strategy_lab["status"],
            "shadow_learning_candidate": strategy_lab["shadow_learning_candidate"]
            is True,
            "learning_admitted": False,
            "policy_activated": False,
        },
        "next_quest": {
            "source_ref": "mission_briefing",
            "mission_id": mission["id"],
            "title": mission["title"],
            "phase": mission["phase"],
            "player_action_label": _text(
                _field(
                    briefing_initiative,
                    "player_action_label",
                    "playerActionLabel",
                )
            ),
            "completion_receipt": _text(
                _field(
                    briefing_evidence,
                    "completion_receipt",
                    "completionReceipt",
                )
            ),
        },
        "result_binding": {
            "scope": (
                "current_mission_evidence_chain_bound"
                if debrief["status"] == "evidence_returned"
                else "project_checkpoint_not_single_mission_debrief"
            ),
            "current_mission_id": mission["id"],
            "mission_evidence_chain_available": debrief["status"]
            == "evidence_returned",
            "single_mission_attribution_available": False,
            "current_mission_completion_inferred": False,
            "business_result_caused_by_current_mission": False,
            "missing_contract": (
                None
                if debrief["status"] == "evidence_returned"
                else "mission_action_outcome_receipt_binding"
            ),
        },
        "agent_reflection": {
            "instruction": "Separate observed project evidence from mission attribution and learning; cite receipt IDs before recommending the next action.",
            "must_cite_receipts": True,
            "may_claim_mission_success": False,
            "may_attribute_business_movement_to_mission": False,
            "may_update_skill_confidence": False,
        },
        "authority": {
            "checkpoint_grants_authority": False,
            "worker_dispatch_authorized": False,
            "live_action_authorized": False,
            "production_write_authorized": False,
            "learning_admission_authorized": False,
            "skill_or_policy_promotion_authorized": False,
        },
    }


def inspect_project_game_campaign(
    *,
    project: object = None,
    plan: object = None,
    business_cockpit: object = None,
) -> dict[str, Any]:
    """Build a bounded local campaign manifest from observed JSON objects.

    The result is orientation-only. It does not call an endpoint or infer
    authority, dispatch, phase completion, authenticated outcomes, tournament
    comparability, a winner, policy admission, or production promotion.
    """

    safe_project = _canonical_object(project, "project")
    safe_plan = _canonical_object(plan, "plan")
    safe_cockpit = _canonical_object(business_cockpit, "business_cockpit")
    game_start = _object(_field(safe_plan, "game_start", "gameStart"))
    science_lab = _science_lab_projection(safe_cockpit)
    mission = _current_mission(safe_plan, game_start, science_lab)
    evidence = _phase_evidence(safe_plan, safe_cockpit, science_lab)
    scoreboard = _scoreboard(safe_project, safe_plan, safe_cockpit, game_start)
    reported_mode = _object(_field(game_start, "mode"))
    mode = project_play_style_mode(
        _text(_field(reported_mode, "id")),
        legacy_fallback=True,
    )
    context = _context_projection(safe_plan)
    party = _party_projection(safe_plan, game_start)
    skill_lab = _skill_lab_projection(
        safe_plan,
        game_start,
        scoreboard,
        safe_cockpit,
    )
    learning_campaign = _object(_field(game_start, "learning_campaign", "learningCampaign"))
    configured_phases = [
        _text(item, 120)
        for item in _first_array(_field(learning_campaign, "phases"))
        if _text(item, 120)
    ]
    phase_ids = configured_phases or [phase["id"] for phase in _DEFAULT_PHASES]
    definitions = {phase["id"]: phase for phase in _DEFAULT_PHASES}
    campaign_map: list[dict[str, Any]] = []
    for phase_id in phase_ids:
        definition = definitions.get(
            phase_id,
            {
                "id": phase_id,
                "label": phase_id.replace("_", " "),
                "act": "Campaign",
                "specialist_role": "project_agent",
            },
        )
        phase_signals = _object(evidence.get(phase_id))
        verified_refs = _array(_field(phase_signals, "verified"))
        claimed_refs = _array(_field(phase_signals, "claimed"))
        verified_count = sum(int(item["count"]) for item in verified_refs)
        claimed_count = sum(int(item["count"]) for item in claimed_refs)
        campaign_map.append(
            {
                **definition,
                "state": "current"
                if mission["phase"] == phase_id
                else "evidence_recorded"
                if verified_count > 0
                else "claimed_evidence_present"
                if claimed_count > 0
                else "planned",
                "evidence_count": verified_count,
                "verified_evidence_count": verified_count,
                "claimed_evidence_count": claimed_count,
                "evidence_refs": verified_refs,
                "claimed_evidence_refs": claimed_refs,
                "evidence_class": (
                    "scope_or_control_plane_verified_receipt"
                    if verified_count > 0
                    else "unverified_plan_claim"
                    if claimed_count > 0
                    else "none"
                ),
                "completion_inferred": False,
                "capability_route": _capability_route(phase_id),
            }
        )
    total_verified_evidence = sum(
        phase["verified_evidence_count"] for phase in campaign_map
    )
    total_claimed_evidence = sum(
        phase["claimed_evidence_count"] for phase in campaign_map
    )
    game_status = _text(_field(game_start, "status")) or "not_started"
    status = (
        "in_progress"
        if total_verified_evidence > 0
        or total_claimed_evidence > 0
        or mission["source_ref"] != "game_start.first_mission"
        else game_status
    )
    delivery_loop = _object(_field(safe_plan, "delivery_loop", "deliveryLoop"))
    approval_queue = _record_list(_field(delivery_loop, "approval_queue", "approvalQueue"))
    delivery_readiness = _object(_field(safe_plan, "delivery_readiness", "deliveryReadiness"))
    briefing = _mission_briefing(
        mission=mission,
        mode=mode,
        context=context,
        campaign_phase=next(
            (phase for phase in campaign_map if phase["id"] == mission["phase"]),
            {},
        ),
        skill_lab=skill_lab,
    )
    outcome_ledger = _outcome_ledger_projection(safe_cockpit)
    strategy_lab = _strategy_lab_projection(safe_cockpit)
    mission_run = _mission_run_projection(
        mission=mission,
        briefing=briefing,
        business_cockpit=safe_cockpit,
    )
    debrief = _mission_debrief(
        mission=mission,
        briefing=briefing,
        outcome_ledger=outcome_ledger,
    )
    learning_review = _learning_review_projection(
        debrief=debrief,
        business_cockpit=safe_cockpit,
    )
    learning_lab = _learning_lab_projection(
        business_cockpit=safe_cockpit,
    )
    checkpoint = _game_checkpoint(
        mission=mission,
        briefing=briefing,
        debrief=debrief,
        scoreboard=scoreboard,
        outcome_ledger=outcome_ledger,
        science_lab=science_lab,
        strategy_lab=strategy_lab,
        skill_lab=skill_lab,
        campaign_map=campaign_map,
    )
    return {
        "schema": PROJECT_GAME_CAMPAIGN_SCHEMA,
        "status": status,
        "state_semantics": "read_only_projection_from_observed_project_state",
        "project": {
            "id": _text(_field(safe_project, "id", "project_id", "projectId")) or None,
            "name": _text(_field(safe_project, "name", "title")) or "Project",
        },
        "mode": mode,
        "scoreboard": scoreboard,
        "outcome_ledger": outcome_ledger,
        "science_lab": science_lab,
        "strategy_lab": strategy_lab,
        "context": context,
        "current_mission": mission,
        "mission_briefing": briefing,
        "mission_run": mission_run,
        "mission_debrief": debrief,
        "learning_review": learning_review,
        "learning_lab": learning_lab,
        "game_checkpoint": checkpoint,
        "campaign_map": campaign_map,
        "party": party,
        "skill_lab": skill_lab,
        "authority": {
            "pending_approval_count": len(approval_queue),
            "human_gate_required": True,
            "delivery_readiness_status": _text(_field(delivery_readiness, "status")) or None,
            "workflow_gates": _object(_field(delivery_readiness, "workflow_gates", "workflowGates")),
            "execution_gates": _object(_field(delivery_readiness, "execution_gates", "executionGates")),
            "projection_grants_authority": False,
            "mutation_authorized_by_projection": False,
            "dispatch_authorized_by_projection": False,
        },
        "agent_protocol": {
            "orientation_only": True,
            "objective_source": "scoreboard.win_condition",
            "current_mission_source": "current_mission",
            "mission_briefing_source": "mission_briefing",
            "mission_run_source": "mission_run",
            "mission_debrief_source": "mission_debrief",
            "learning_review_source": "learning_review",
            "learning_lab_source": "learning_lab",
            "game_checkpoint_source": "game_checkpoint",
            "initiative_source": "mode.initiative",
            "science_cadence_source": "mode.science_cadence",
            "context_source": "context",
            "capability_pipeline_source": "campaign_map",
            "skill_tournament_source": "skill_lab.tournament",
            "science_lab_source": "science_lab",
            "strategy_lab_source": "strategy_lab",
            "rules": [
                "Treat play style as an initiative preference only; it never grants worker dispatch, live-action, or production-write authority.",
                "Use mission_briefing as the fresh human/agent handoff: inspect its context, capability route, skill trial, evidence contract, and authority boundary before work.",
                "Lock mission_briefing in mission_run before any separately authorized action, then bind only a later same-project action event; neither receipt grants authority or proves external effect.",
                "Use mission_debrief only when its briefing, action, and outcome receipt chain matches the current mission; evidence_returned is not causal proof, victory, learning admission, or new authority.",
                "Use only a human-admitted learning_review as graded future shadow-training input; never infer causality or skill attribution, mutate live confidence/routing/policy, or call record_skill_outcome for project mission evidence.",
                "Use learning_lab only after an exact Arena match and human-admitted mission lesson are paired. A pack is one candidate observation, not a dataset, durable learning run, admission, training result, promotion, or new authority.",
                "Follow learning_lab.training_quest after a verified pack. Preparation may verify immutable dataset custody and create a durable queued run; admission may verify capacity and commercial reservation. Only a sanitized Memory execution receipt may prove a fenced worker claim, checkpoint, or terminal runtime result. A result still does not prove independent evaluation, learner update, promotion, or business value.",
                "Use game_checkpoint after evidence changes: separate project-level observations from mission attribution, cite receipts, and never infer a mission win, causal effect, learning admission, or agent level-up.",
                "Use the scoreboard as the business objective; do not invent a reward or score.",
                "Use context evidence before forming hypotheses, training models, or recommending actions.",
                "Inspect the Project Science Ledger before research, data, AutoML, model-serving, solver, or control work.",
                "After each real science artifact is durably recorded, append its exact-scope receipt with the required predecessor receipt, tools, and skills; plan fields remain claims until that receipt exists.",
                "A Science Ledger receipt verifies artifact identity and predecessor scope only; it does not prove scientific validity, model quality, policy optimality, causality, learning admission, or action authority.",
                "Compare no-skill, single-skill, and skill-combination arms in shadow evaluation.",
                "Use the AgentContext shadow adapter and signed capture harness before the evaluator; the provider-only Claude domain lane has episode-scoped runtime evidence, but capture orchestration and trusted producer key provisioning must still be configured.",
                "Without a verified capture bundle, treat evaluator inputs as supplied unauthenticated observations.",
                "Do not extend the Claude domain runtime-evidence claim to Coding, Backbone, Codex, Cursor, direct connector, or offline-policy paths until each has its own covered binding.",
                "Record real score movement with the Project Outcome Ledger. Actor authentication or same-scope event binding does not prove causality and does not admit learning.",
                "Log policy probabilities before the outcome, bind the exact assignment, action event, and outcome receipt, then use Strategy Lab OPE only as shadow evidence waiting for separate human-reviewed learning admission.",
                "Sequence the governed loop as Science Quest evidence, pre-action policy assignment, approved action, real outcome receipt, offline evaluation, then separate human-reviewed learning admission.",
                "Do not promote a skill or policy without authenticated outcomes and explicit human approval.",
                "Follow authoritative workflow gates; this projection grants no mutation or dispatch authority.",
            ],
        },
    }


__all__ = [
    "PROJECT_GAME_CAMPAIGN_MAX_JSON_BYTES",
    "PROJECT_GAME_CAMPAIGN_SCHEMA",
    "PROJECT_GAME_CHECKPOINT_SCHEMA",
    "PROJECT_MISSION_DEBRIEF_SCHEMA",
    "PROJECT_MISSION_BRIEFING_SCHEMA",
    "PROJECT_MISSION_RUN_LEDGER_SCHEMA",
    "PROJECT_LEARNING_REVIEW_REQUEST_SCHEMA",
    "PROJECT_LEARNING_REVIEW_SCHEMA",
    "PROJECT_LEARNING_RUN_ADMISSION_PLAN_SCHEMA",
    "PROJECT_LEARNING_RUN_ADMISSION_RECEIPT_SCHEMA",
    "PROJECT_LEARNING_RUN_EXECUTION_RECEIPT_SCHEMA",
    "PROJECT_LEARNING_RUN_EXECUTION_SNAPSHOT_SCHEMA",
    "PROJECT_LEARNING_RUN_LEDGER_SCHEMA",
    "PROJECT_LEARNING_RUN_RECEIPT_SCHEMA",
    "PROJECT_LEARNING_QUEST_SCHEMA",
    "PROJECT_LEARNING_LAB_SCHEMA",
    "PROJECT_SKILL_MATCH_LEDGER_SCHEMA",
    "PROJECT_SKILL_MATCH_RECEIPT_SCHEMA",
    "PROJECT_TRAINING_PACK_LEDGER_SCHEMA",
    "PROJECT_TRAINING_PACK_RECEIPT_SCHEMA",
    "PROJECT_TRAINING_PACK_SCHEMA",
    "PROJECT_PLAY_STYLE_DEFAULT",
    "PROJECT_PLAY_STYLE_IDS",
    "PROJECT_BUSINESS_OUTCOME_LEDGER_SCHEMA",
    "PROJECT_BUSINESS_OUTCOME_OBSERVATION_SCHEMA",
    "PROJECT_BUSINESS_OUTCOME_RECEIPT_SCHEMA",
    "PROJECT_POLICY_ASSIGNMENT_OBSERVATION_SCHEMA",
    "PROJECT_POLICY_ASSIGNMENT_RECEIPT_SCHEMA",
    "PROJECT_POLICY_OFFLINE_EVALUATION_PAIR_REQUEST_SCHEMA",
    "PROJECT_POLICY_OFFLINE_EVALUATION_RECEIPT_SCHEMA",
    "PROJECT_SCIENCE_EVIDENCE_OBSERVATION_SCHEMA",
    "PROJECT_SCIENCE_EVIDENCE_RECEIPT_SCHEMA",
    "PROJECT_SCIENCE_LAB_SCHEMA",
    "PROJECT_SCIENCE_LEDGER_SCHEMA",
    "PROJECT_STRATEGY_LAB_SCHEMA",
    "SKILL_TOURNAMENT_CAPTURE_BUNDLE_SCHEMA",
    "SKILL_TOURNAMENT_CAPTURE_REQUEST_SCHEMA",
    "SKILL_TOURNAMENT_CAPTURE_VERIFICATION_SCHEMA",
    "SKILL_TOURNAMENT_APPLICATION_TRACE_SCHEMA",
    "SKILL_TOURNAMENT_EVALUATION_RECEIPT_SCHEMA",
    "SKILL_TOURNAMENT_EVALUATION_REQUEST_SCHEMA",
    "SKILL_TOURNAMENT_EPISODE_RECEIPT_SCHEMA",
    "SKILL_TOURNAMENT_SCHEMA",
    "normalize_project_play_style",
    "project_play_style_mode",
    "inspect_project_game_campaign",
]
