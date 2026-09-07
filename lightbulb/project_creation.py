"""Typed, fail-closed contracts for the project-creation preflight journey.

The preflight result is model-authored, but the execution receipt is not.  A
receipt in this module is therefore assembled only from a typed preflight SSE
event plus a UUID observed on the distinct ``execution`` SSE event.  The
original normalized draft is retained (and digested) so the later create call
cannot silently substitute a different project brief.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Annotated, Any, Iterable, Literal
from urllib.parse import urlparse

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)


PROJECT_CREATION_PREFLIGHT_SCHEMA = "project_creation_preflight.v1"
PROJECT_CREATION_PREFLIGHT_RECEIPT_SCHEMA = "project_creation_preflight_receipt.v1"
PROJECT_CREATION_DRAFT_SCHEMA = "project_creation_draft.v1"
PROJECT_CREATION_PREFLIGHT_REQUEST_SCHEMA = "project_creation_preflight_request.v1"
PROJECT_CREATION_PREFLIGHT_REFINEMENT_REQUEST_SCHEMA = (
    "project_creation_preflight_refinement_request.v1"
)
AGENT_EPISODE_SCHEMA = "lightbulb.agent_episode.v1"
PROJECT_START_READINESS_SCHEMA = "lightbulb.project_start_readiness.v1"
PROJECT_GAME_START_SCHEMA = "lightbulb.project_game_start.v1"
PROJECT_GAME_START_FIRST_MISSION_PROMPT = (
    "Map the first workflow: trigger, owner, systems, handoffs, pain point, "
    "approver, and proof it worked."
)
from lightbulb.project_game import (
    PROJECT_PLAY_STYLE_DEFAULT,
    PROJECT_PLAY_STYLE_IDS,
    PROJECT_GAME_CAMPAIGN_SCHEMA,
    PROJECT_GAME_CHECKPOINT_SCHEMA,
    PROJECT_LEARNING_LAB_SCHEMA,
    PROJECT_LEARNING_QUEST_SCHEMA,
    PROJECT_LEARNING_RUN_ADMISSION_RECEIPT_SCHEMA,
    PROJECT_LEARNING_RUN_EXECUTION_RECEIPT_SCHEMA,
    PROJECT_LEARNING_RUN_EXECUTION_SNAPSHOT_SCHEMA,
    PROJECT_LEARNING_RUN_LEDGER_SCHEMA,
    PROJECT_LEARNING_RUN_RECEIPT_SCHEMA,
    PROJECT_LEARNING_REVIEW_SCHEMA,
    PROJECT_MISSION_DEBRIEF_SCHEMA,
    PROJECT_MISSION_BRIEFING_SCHEMA,
    PROJECT_SCIENCE_LAB_SCHEMA,
    SKILL_TOURNAMENT_APPLICATION_TRACE_SCHEMA,
    SKILL_TOURNAMENT_CAPTURE_BUNDLE_SCHEMA,
    SKILL_TOURNAMENT_CAPTURE_REQUEST_SCHEMA,
    SKILL_TOURNAMENT_CAPTURE_VERIFICATION_SCHEMA,
    SKILL_TOURNAMENT_EVALUATION_RECEIPT_SCHEMA,
    SKILL_TOURNAMENT_EVALUATION_REQUEST_SCHEMA,
    SKILL_TOURNAMENT_EPISODE_RECEIPT_SCHEMA,
    SKILL_TOURNAMENT_ORCHESTRATION_RECEIPT_SCHEMA,
    SKILL_TOURNAMENT_RUNTIME_CONTRACT_SCHEMA,
    SKILL_TOURNAMENT_SCHEMA,
    inspect_project_game_campaign,
    normalize_project_play_style,
    project_play_style_mode,
)

PROJECT_NAME_MAX_CHARS = 240
PROJECT_INSTRUCTIONS_MAX_CHARS = 10_000
PROJECT_PREFLIGHT_ANSWER_MAX_CHARS = 2_000
PROJECT_PREFLIGHT_MAX_EVENTS = 512
PROJECT_PREFLIGHT_MAX_REFINEMENT_DEPTH = 4
PROJECT_CODING_HARNESS_IDS = ("codex", "claude_code", "cursor")

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_EPISODE_ID_RE = re.compile(r"^ep_[0-9a-f]{32}$")
_DRAFT_SPAN_REFERENCE_RE = re.compile(
    r"^draft_span:([a-z_]+):instructions:(0|[1-9][0-9]*):"
    r"(0|[1-9][0-9]*):([0-9a-f]{64})$"
)
_DRAFT_SPAN_SIGNAL_PATTERNS = {
    "outcome": (
        r"\b(?:build|create|deliver|launch|reduce|increase|improve|"
        r"migrate|automate|replace|enable|produce|design)\b",
    ),
    "users_stakeholders": (
        r"\b(?:users?|customers?|clients?|employees?|operators?|"
        r"stakeholders?|buyers?|teams?)\b",
    ),
    "current_state_evidence": (
        r"\b(?:currently|today|as[- ]is|baseline|existing)\b.{0,100}"
        r"\b(?:metric|data|report|workflow|process|system|implementation|"
        r"evidence|source|document)\b",
        r"\b(?:metric|data|report|workflow|process|system|implementation|"
        r"evidence|source|document)\b.{0,100}"
        r"\b(?:currently|today|as[- ]is|baseline|existing)\b",
    ),
    "measurable_success": (
        r"\b(?:by|within|under|over|at\s+least|no\s+more\s+than|"
        r"fewer\s+than|from)\s+\$?\d+(?:\.\d+)?",
        r"\b\d+(?:\.\d+)?\s*(?:%|seconds?|minutes?|hours?|days?|weeks?|"
        r"months?|users?|customers?|orders?|tickets?|errors?|dollars?)\b",
    ),
    "scope": (
        r"\b(?:first\s+(?:slice|release|phase|version|workflow|operation|use\s+case)|"
        r"mvp|minimum\s+viable|in\s+scope|out\s+of\s+scope|narrow|"
        r"before\s+scaling|pilot)\b",
    ),
    "constraints_risk_cost": (
        r"\b(?:cost|budget|risk|policy|approval|security|privacy|tenant|"
        r"rbac|deadline|constraint|must\s+not|without)\b",
    ),
    "decision_owner": (
        r"\b(?:decision\s+owner|approver\s+is|approved\s+by|sign[- ]off\s+by|"
        r"authority\s+is|owns?\s+the\s+decision)\b",
    ),
    "research_provenance": (
        r"\b(?:research|source|citation|provenance|verify|verification)\b",
    ),
}


def normalize_project_coding_harness(value: object) -> str:
    """Return the canonical harness id required by project creation."""
    if not isinstance(value, str):
        raise ValueError(
            "coding_harness must be codex, claude_code, or cursor; "
            "ChatGPT is an optional Lightbulb access surface, not a coding harness"
        )
    harness = value.strip().lower()
    if harness not in PROJECT_CODING_HARNESS_IDS:
        raise ValueError(
            "coding_harness must be codex, claude_code, or cursor; "
            "ChatGPT is an optional Lightbulb access surface, not a coding harness"
        )
    return harness
_PREFLIGHT_EVENT_TYPES = frozenset({"project_preflight", "project_creation_preflight"})
_UNTRUSTED_RECEIPT_KEYS = frozenset(
    {
        "preflight_execution_id",
        "preflightExecutionId",
        "execution_id",
        "executionId",
        "episode_id",
        "episodeId",
    }
)

CoverageField = Literal[
    "outcome",
    "users_stakeholders",
    "current_state_evidence",
    "measurable_success",
    "scope",
    "constraints_risk_cost",
    "decision_owner",
    "research_provenance",
]
GapField = Literal[
    "outcome",
    "users_stakeholders",
    "current_state_evidence",
    "measurable_success",
    "scope",
    "constraints_risk_cost",
    "decision_owner",
    "research_provenance",
    "high_impact_assumption",
    "high_severity_conflict",
    "assumption",
]


def _draft_span_reference_parts(
    reference: str,
) -> tuple[str, int, int, str] | None:
    match = _DRAFT_SPAN_REFERENCE_RE.fullmatch(reference)
    if match is None:
        return None
    return match.group(1), int(match.group(2)), int(match.group(3)), match.group(4)


def _draft_span_reference_resolves(
    reference: str,
    *,
    field: str,
    instructions: str,
) -> bool:
    parts = _draft_span_reference_parts(reference)
    patterns = _DRAFT_SPAN_SIGNAL_PATTERNS.get(field)
    if parts is None or patterns is None or parts[0] != field:
        return False
    _, start, end, expected_digest = parts
    draft_bytes = instructions.encode("utf-8")
    if start < 0 or start >= end or end > len(draft_bytes):
        return False
    span_bytes = draft_bytes[start:end]
    try:
        span = span_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return (
        len(span.split()) >= 4
        and hashlib.sha256(span_bytes).hexdigest() == expected_digest
        and any(
            re.search(pattern, span, flags=re.IGNORECASE | re.DOTALL)
            for pattern in patterns
        )
    )

def _utf16_code_units(value: str) -> int:
    """Match JavaScript/Java string bounds without altering the input."""
    return sum(2 if ord(character) > 0xFFFF else 1 for character in value)


def _utf16_maximum(maximum: int) -> AfterValidator:
    def validate(value: str) -> str:
        if _utf16_code_units(value) > maximum:
            raise ValueError(f"text exceeds {maximum} UTF-16 code units")
        return value

    return AfterValidator(validate)


NonEmpty300 = Annotated[
    str,
    StringConstraints(min_length=1, max_length=300),
    _utf16_maximum(300),
]
Optional300 = Annotated[
    str,
    StringConstraints(max_length=300),
    _utf16_maximum(300),
]
NonEmpty500 = Annotated[
    str,
    StringConstraints(min_length=1, max_length=500),
    _utf16_maximum(500),
]
Optional500 = Annotated[
    str,
    StringConstraints(max_length=500),
    _utf16_maximum(500),
]
NonEmpty600 = Annotated[
    str,
    StringConstraints(min_length=40, max_length=600),
    _utf16_maximum(600),
]
NonEmpty1000 = Annotated[
    str,
    StringConstraints(min_length=1, max_length=1_000),
    _utf16_maximum(1_000),
]
NonEmpty2000 = Annotated[
    str,
    StringConstraints(min_length=1, max_length=2_000),
    _utf16_maximum(2_000),
]
NonEmpty10100 = Annotated[
    str,
    StringConstraints(min_length=1, max_length=10_100),
    _utf16_maximum(10_100),
]


class ProjectCreationPreflightError(ValueError):
    """The preflight stream or receipt failed authoritative validation."""


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        serialize_by_alias=True,
        strict=True,
        str_strip_whitespace=True,
    )


def _reject_controls(value: str, *, label: str, allow_layout: bool = True) -> str:
    allowed = {"\n", "\r", "\t"} if allow_layout else set()
    if any((ord(char) < 32 or ord(char) == 127) and char not in allowed for char in value):
        raise ValueError(f"{label} must not contain control characters")
    return value


def normalize_project_uuid(value: object, label: str) -> str:
    """Return a canonical lowercase UUID without accepting loose UUID syntax."""
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a UUID string")
    normalized = value.strip()
    if not _UUID_RE.fullmatch(normalized):
        raise ValueError(f"{label} must be a valid UUID")
    return normalized.lower()


class ProjectCreationDraft(_StrictModel):
    """The only user-authored fields accepted by the preflight request."""

    schema_: Literal["project_creation_draft.v1"] = Field(
        default=PROJECT_CREATION_DRAFT_SCHEMA,
        alias="schema",
    )
    name: Annotated[str, StringConstraints(min_length=1, max_length=PROJECT_NAME_MAX_CHARS)]
    instructions: Annotated[str, StringConstraints(max_length=PROJECT_INSTRUCTIONS_MAX_CHARS)] = ""

    @field_validator("name", mode="before")
    @classmethod
    def _validate_name(cls, value: Any) -> str:
        if not isinstance(value, str):
            raise ValueError("name must be a string")
        normalized = _reject_controls(value.strip(), label="name", allow_layout=False)
        if _utf16_code_units(normalized) > PROJECT_NAME_MAX_CHARS:
            raise ValueError(
                f"name exceeds {PROJECT_NAME_MAX_CHARS} UTF-16 code units"
            )
        return normalized

    @field_validator("instructions", mode="before")
    @classmethod
    def _validate_instructions(cls, value: Any) -> str:
        if not isinstance(value, str):
            raise ValueError("instructions must be a string")
        normalized = _reject_controls(value.strip(), label="instructions")
        if _utf16_code_units(normalized) > PROJECT_INSTRUCTIONS_MAX_CHARS:
            raise ValueError(
                "instructions exceeds "
                f"{PROJECT_INSTRUCTIONS_MAX_CHARS} UTF-16 code units"
            )
        return normalized

    @property
    def sha256(self) -> str:
        payload = {"instructions": self.instructions, "name": self.name}
        canonical = json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()


def _project_start_next_action(blockers: list[str]) -> dict[str, str]:
    if "project_draft" in blockers:
        return {"code": "name_project", "label": "Name the project"}
    if "company_scope" in blockers:
        return {"code": "select_company", "label": "Select a company"}
    if "secure_receipt_verification" in blockers:
        return {
            "code": "open_secure_lightbulb",
            "label": "Open secure Lightbulb",
        }
    return {"code": "review_project", "label": "Review project"}


def _project_game_start(
    draft: ProjectCreationDraft | None,
    play_style: str = PROJECT_PLAY_STYLE_DEFAULT,
) -> dict[str, Any]:
    win_condition = (
        draft.instructions or draft.name
        if draft is not None
        else "Name the project to reveal its win condition."
    )
    return {
        "schema": PROJECT_GAME_START_SCHEMA,
        "status": "not_started",
        "state_semantics": "initial_seed_not_live_runtime_state",
        "win_condition": {
            "statement": win_condition,
            "source": "project_name_and_instructions",
            "measurement_status": "needs_metric_baseline_target_and_horizon",
        },
        "mode": project_play_style_mode(play_style),
        "starter_loadout": {
            "status": "planned_not_dispatched",
            "workers": [
                {
                    "worker_id": "project_agent",
                    "label": "Project Agent",
                    "responsibility": (
                        "Keep the win condition, context, intake, and missions aligned."
                    ),
                }
            ],
            "selected_skill_ids": [],
            "dispatch_authorized": False,
        },
        "first_mission": {
            "id": "map_first_workflow",
            "title": "Map the first workflow",
            "prompt": PROJECT_GAME_START_FIRST_MISSION_PROMPT,
            "status": "not_started",
            "mutation_allowed": False,
        },
        "learning_campaign": {
            "status": "planned_not_started",
            "capability_ref": "analysis_engine.autoresearch_to_automl_to_solver",
            "policy_learning_status": "not_admitted",
            "phases": [
                "hypothesis",
                "search",
                "data_engineering",
                "machine_learning_and_serving",
                "solver_and_optimal_control",
                "simulation_and_offline_evaluation",
                "authority_review",
                "action",
                "authenticated_outcome",
                "governed_improvement",
            ],
            "skill_trials": {
                "status": "not_started",
                "evaluation_mode": "shadow_only",
                "comparison_arms": [
                    "no_skill",
                    "single_skill",
                    "skill_combination",
                ],
                "promotion_requires": [
                    "authenticated_outcome_evidence",
                    "explicit_human_approval",
                ],
                "production_promotion_authorized": False,
            },
        },
        "next_action": {
            "code": "map_first_workflow",
            "label": "Map the first workflow",
        },
    }


def inspect_project_creation_world_ready(
    *,
    name: str = "",
    instructions: str = "",
    tenant_id: object = None,
    company_id: object = None,
    project_id: object = None,
    participant_role: str = "agent_worker",
    experience_lens: str = "agent_protocol",
    play_style: str = PROJECT_PLAY_STYLE_DEFAULT,
    secure_receipt_verification: bool = True,
) -> dict[str, Any]:
    """Return a local, non-sensitive readiness manifest for project review.

    The manifest answers only whether the draft can enter the read-only review
    route. Participant and experience choices are presentation/protocol hints;
    they never grant project creation or downstream action authority.
    """
    if participant_role not in {"human_operator", "agent_worker"}:
        raise ValueError("participant_role is not supported")
    if experience_lens not in {"game", "operator", "agent_protocol"}:
        raise ValueError("experience_lens is not supported")
    selected_play_style = normalize_project_play_style(play_style)
    if not isinstance(secure_receipt_verification, bool):
        raise TypeError("secure_receipt_verification must be a boolean")

    try:
        draft = ProjectCreationDraft(name=name, instructions=instructions)
        draft_ready = True
    except (TypeError, ValueError):
        draft = None
        draft_ready = False

    def canonical_scope_uuid(value: object) -> bool:
        return (
            isinstance(value, str)
            and value == value.strip().lower()
            and bool(_UUID_RE.fullmatch(value))
        )

    scope_ready = (
        canonical_scope_uuid(tenant_id)
        and canonical_scope_uuid(company_id)
        and not project_id
    )
    checks: list[dict[str, Any]] = [
        {
            "id": "project_draft",
            "label": "Project draft",
            "state": "ready" if draft_ready else "blocked",
            "blocking": True,
            "detail": (
                "Name is ready; review can sharpen the win condition."
                if draft_ready
                else "Name this project before review."
            ),
        },
        {
            "id": "company_scope",
            "label": "Company world",
            "state": "ready" if scope_ready else "blocked",
            "blocking": True,
            "detail": (
                "One company world is selected."
                if scope_ready
                else "Select one company before review."
            ),
        },
        {
            "id": "secure_receipt_verification",
            "label": "Secure receipts",
            "state": "ready" if secure_receipt_verification else "blocked",
            "blocking": True,
            "detail": (
                "Trusted receipt verification is available."
                if secure_receipt_verification
                else "Open Lightbulb over HTTPS or a supported local address."
            ),
            **(
                {}
                if secure_receipt_verification
                else {"reason_code": "runtime_crypto_unavailable"}
            ),
        },
        {
            "id": "authority_boundary",
            "label": "Starting authority",
            "state": "locked",
            "blocking": False,
            "detail": (
                "Review is read-only. Creation and downstream actions stay separate."
            ),
        },
    ]
    blockers = [
        check["id"]
        for check in checks
        if check["blocking"] and check["state"] != "ready"
    ]
    return {
        "schema": PROJECT_START_READINESS_SCHEMA,
        "ready_for": "read_only_project_review",
        "ready": not blockers,
        "participant": {"role": participant_role},
        "experience": {"lens": experience_lens},
        "authority": {
            "requested_policy": "review_then_explicit_create",
            "effective_policy": "review_then_explicit_create",
            "basis": "route_invariant_only",
            "backend_grant_present": False,
            "project_create_authorized": False,
            "downstream_actions_authorized": False,
        },
        "game_start": _project_game_start(draft, selected_play_style),
        "checks": checks,
        "blockers": blockers,
        "next_action": _project_start_next_action(blockers),
    }


class PreflightFact(_StrictModel):
    statement: NonEmpty10100
    provenance: Literal["user_input"]
    confidence: float = Field(ge=0.0, le=1.0, allow_inf_nan=False)


class PreflightAssumption(_StrictModel):
    statement: NonEmpty500
    provenance: Literal["inference"]
    basis: NonEmpty300
    confidence: float = Field(ge=0.0, le=0.75, allow_inf_nan=False)


class PreflightConflict(_StrictModel):
    statement: NonEmpty500
    severity: Literal["low", "medium", "high"]
    provenance: Literal["agent_analysis"]


_PROJECT_PREFLIGHT_LEGACY_BLOCKING_FIELDS = frozenset(
    {
        "measurable_success",
        "decision_owner",
        "high_impact_assumption",
        "high_severity_conflict",
    }
)


class PreflightCriticalityFinding(_StrictModel):
    """Compiler-owned explanation for why uncertainty blocks, warns, or does not."""

    field: GapField
    finding: NonEmpty500
    plan_impact: NonEmpty500
    evidence_refs: list[NonEmpty1000] = Field(min_length=1, max_length=5)
    confidence: float = Field(ge=0.0, le=1.0, allow_inf_nan=False)
    resolution_prompt: Optional500
    resolution_mode: Literal[
        "ask_user",
        "bounded_public_research",
        "state_assumption",
        "none",
    ]
    resolution_cost: Literal[
        "one_user_answer",
        "one_bounded_research_pass",
        "no_external_call",
        "none",
    ]
    disposition: Literal["block", "warn", "assume", "ignore"]

    @model_validator(mode="after")
    def _validate_criticality_policy(self) -> "PreflightCriticalityFinding":
        if len(set(self.evidence_refs)) != len(self.evidence_refs):
            raise ValueError("criticality evidence references must be unique")
        expected_pair = {
            "ask_user": "one_user_answer",
            "bounded_public_research": "one_bounded_research_pass",
            "state_assumption": "no_external_call",
            "none": "none",
        }
        if self.resolution_cost != expected_pair[self.resolution_mode]:
            raise ValueError("criticality resolution mode and cost are inconsistent")
        allowed_modes = {
            "block": {"ask_user"},
            "warn": {"ask_user", "bounded_public_research"},
            "assume": {"state_assumption"},
            "ignore": {"none"},
        }
        if self.resolution_mode not in allowed_modes[self.disposition]:
            raise ValueError("criticality resolution is inconsistent with disposition")
        if self.disposition in {"block", "warn"} and not self.resolution_prompt:
            raise ValueError("block and warn findings require a resolution prompt")
        if self.disposition in {"assume", "ignore"} and self.resolution_prompt:
            raise ValueError("assume and ignore findings cannot create an open question")
        if (
            self.disposition == "block"
            and self.field not in _PROJECT_PREFLIGHT_LEGACY_BLOCKING_FIELDS
        ):
            raise ValueError("criticality finding field is not allowed to block")
        if self.resolution_mode == "bounded_public_research" and self.field not in {
            "users_stakeholders",
            "current_state_evidence",
            "research_provenance",
        }:
            raise ValueError("criticality finding is not publicly researchable")
        if self.disposition == "assume" and self.field != "assumption":
            raise ValueError("assume disposition is restricted to explicit assumptions")
        if self.disposition == "ignore" and not any(
            (parts := _draft_span_reference_parts(reference)) is not None
            and parts[0] == self.field
            for reference in self.evidence_refs
        ):
            raise ValueError("ignore requires a matching draft span evidence reference")
        return self


class PreflightCriticalGap(_StrictModel):
    field: GapField
    question: NonEmpty500
    reason: NonEmpty500
    blocking: bool
    researchable: bool


class PreflightOpenQuestion(_StrictModel):
    target_field: GapField
    question_text: NonEmpty500
    reason: NonEmpty500
    blocking: bool
    researchable: bool


class PreflightCoverage(_StrictModel):
    outcome: bool
    users_stakeholders: bool
    current_state_evidence: bool
    measurable_success: bool
    scope: bool
    constraints_risk_cost: bool
    decision_owner: bool
    research_provenance: bool


class PreflightCoverageEntry(_StrictModel):
    field: CoverageField
    covered: bool
    provenance: Literal[
        "deterministic_text_signals",
        "deterministic_readiness_policy",
        "model_review",
    ]

    @model_validator(mode="after")
    def _restrict_readiness_policy_provenance(self) -> "PreflightCoverageEntry":
        if (
            self.provenance == "deterministic_readiness_policy"
            and self.field not in {"measurable_success", "decision_owner"}
        ):
            raise ValueError(
                "deterministic_readiness_policy provenance is restricted to readiness-gated fields"
            )
        return self


class PreflightResearchQuery(_StrictModel):
    gap_field: Literal[
        "users_stakeholders",
        "current_state_evidence",
        "research_provenance",
    ]
    query: NonEmpty500
    why_public_evidence_helps: Optional300


class PreflightResearchSource(_StrictModel):
    title: NonEmpty300
    url: NonEmpty1000

    @field_validator("url")
    @classmethod
    def _public_http_url(cls, value: str) -> str:
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("research source URL must be an absolute HTTP(S) URL")
        if parsed.username or parsed.password:
            raise ValueError("research source URL must not contain credentials")
        if parsed.query or parsed.fragment:
            raise ValueError("research source URL must be canonical without query or fragment")
        return value


class PreflightResearchFinding(_StrictModel):
    statement: NonEmpty600
    provenance: Literal["public_research_excerpt"]
    source_refs: list[NonEmpty1000] = Field(
        min_length=1,
        max_length=5,
    )


class PreflightResearch(_StrictModel):
    status: Literal["not_requested", "completed", "unavailable", "unavailable_budget"]
    sources: list[PreflightResearchSource] = Field(max_length=5)
    findings: list[PreflightResearchFinding] = Field(max_length=5)
    confidence: Literal["low", "not_assessed"]
    reason: Optional500 | None = None

    @model_validator(mode="after")
    def _validate_provenance(self) -> "PreflightResearch":
        source_urls = {source.url for source in self.sources}
        if self.status == "completed" and not source_urls:
            raise ValueError("completed research requires at least one verified source")
        if self.status != "completed" and (self.sources or self.findings):
            raise ValueError("non-completed research must not contain sources or findings")
        for finding in self.findings:
            if any(reference not in source_urls for reference in finding.source_refs):
                raise ValueError("research finding references an unverified source")
        if self.findings and self.confidence == "not_assessed":
            raise ValueError("cited research findings require an assessed confidence")
        if not self.findings and self.confidence != "not_assessed":
            raise ValueError("research confidence cannot be assessed without cited findings")
        return self


class PreflightSafety(_StrictModel):
    mode: Literal["shadow_read_only"]
    project_created: Literal[False]
    action_dispatch_allowed: Literal[False]
    external_writes_allowed: Literal[False]
    memory_persistence_allowed: Literal[False]
    approval_state_accepted_from_model: Literal[False]


class PreflightCostPolicy(_StrictModel):
    max_research_passes: Literal[1]
    research_depth: Literal["shallow"]
    price_claim: Literal["not_declared"]
    usage_accounting: Literal["model_runtime_ledger"]
    review_mode: Literal["static_no_token", "model_enriched"]


class ProjectCreationPreflight(_StrictModel):
    """Strict wire model emitted by the project preflight agent."""

    schema_: Literal["project_creation_preflight.v1"] = Field(alias="schema")
    status: Literal["needs_input", "ready"]
    analysis_status: Literal["degraded", "completed"]
    analysis_reason: NonEmpty300 | None = None
    project_name: Annotated[
        str,
        StringConstraints(min_length=1, max_length=PROJECT_NAME_MAX_CHARS),
        _utf16_maximum(PROJECT_NAME_MAX_CHARS),
    ]
    product_brief: NonEmpty2000
    facts: list[PreflightFact] = Field(max_length=2)
    assumptions: list[PreflightAssumption] = Field(max_length=5)
    conflicts: list[PreflightConflict] = Field(max_length=3)
    criticality_findings: list[PreflightCriticalityFinding] | None = Field(
        default=None,
        max_length=3,
    )
    critical_gaps: list[PreflightCriticalGap] = Field(max_length=3)
    open_questions: list[PreflightOpenQuestion] = Field(max_length=3)
    next_question: Optional500
    coverage: PreflightCoverage
    coverage_map: list[PreflightCoverageEntry] = Field(min_length=8, max_length=8)
    coverage_score: float = Field(ge=0.0, le=1.0, allow_inf_nan=False)
    research_queries: list[PreflightResearchQuery] = Field(max_length=2)
    research: PreflightResearch
    safety: PreflightSafety
    cost_policy: PreflightCostPolicy

    @model_validator(mode="after")
    def _validate_internal_consistency(self) -> "ProjectCreationPreflight":
        expected = self.coverage.model_dump()
        expected_fields = tuple(expected)
        mapped_fields = tuple(entry.field for entry in self.coverage_map)
        if mapped_fields != expected_fields:
            raise ValueError("coverage_map must follow the canonical coverage field order")
        if any(entry.covered != expected[entry.field] for entry in self.coverage_map):
            raise ValueError("coverage_map must be consistent with coverage")
        coverage_provenance = {
            entry.field: entry.provenance for entry in self.coverage_map
        }
        expected_score = round(sum(bool(value) for value in expected.values()) / 8, 3)
        if abs(self.coverage_score - expected_score) > 0.000_001:
            raise ValueError("coverage_score does not match coverage")
        researchable_fields = {
            "users_stakeholders",
            "current_state_evidence",
            "research_provenance",
        }
        if self.criticality_findings is not None:
            source_urls = {source.url for source in self.research.sources}
            instruction_facts = [
                fact.statement.removeprefix("User instructions: ")
                for fact in self.facts
                if fact.statement.startswith("User instructions: ")
            ]
            draft_instructions = (
                instruction_facts[0] if len(instruction_facts) == 1 else None
            )
            for finding in self.criticality_findings:
                has_valid_draft_span = False
                for reference in finding.evidence_refs:
                    if reference in {"draft:name", "draft:instructions"}:
                        continue
                    if reference.startswith("coverage:"):
                        referenced_field = reference.removeprefix("coverage:")
                        if (
                            referenced_field not in expected
                            or referenced_field != finding.field
                        ):
                            raise ValueError(
                                "criticality finding references unrelated coverage evidence"
                            )
                        continue
                    if reference.startswith("draft_span:"):
                        if draft_instructions is None or not _draft_span_reference_resolves(
                            reference,
                            field=finding.field,
                            instructions=draft_instructions,
                        ):
                            raise ValueError(
                                "criticality finding references an invalid draft span"
                            )
                        has_valid_draft_span = True
                        continue
                    if reference.startswith("assumption:"):
                        index = reference.removeprefix("assumption:")
                        if (
                            not index.isdigit()
                            or not 1 <= int(index) <= len(self.assumptions)
                            or finding.field not in {"assumption", "high_impact_assumption"}
                        ):
                            raise ValueError(
                                "criticality finding references an unknown assumption"
                            )
                        continue
                    if reference.startswith("conflict:"):
                        index = reference.removeprefix("conflict:")
                        if (
                            not index.isdigit()
                            or not 1 <= int(index) <= len(self.conflicts)
                            or finding.field != "high_severity_conflict"
                            or self.conflicts[int(index) - 1].severity != "high"
                        ):
                            raise ValueError(
                                "criticality finding references an unknown high-severity conflict"
                            )
                        continue
                    if reference.startswith("research:"):
                        if reference.removeprefix("research:") not in source_urls:
                            raise ValueError(
                                "criticality finding references an unverified research source"
                            )
                        continue
                    raise ValueError("criticality evidence reference is unsupported")
                if finding.disposition == "ignore" and not (
                    finding.field in expected
                    and expected[finding.field]
                    and has_valid_draft_span
                    and coverage_provenance[finding.field]
                    in {
                        "deterministic_text_signals",
                        "deterministic_readiness_policy",
                    }
                ):
                    raise ValueError(
                        "ignore requires deterministic coverage evidence"
                    )
            projected = [
                {
                    "field": finding.field,
                    "question": finding.resolution_prompt,
                    "reason": finding.plan_impact,
                    "blocking": finding.disposition == "block",
                    "researchable": finding.resolution_mode
                    == "bounded_public_research",
                }
                for finding in self.criticality_findings
                if finding.disposition in {"block", "warn"}
            ]
            if projected != [gap.model_dump() for gap in self.critical_gaps]:
                raise ValueError(
                    "critical_gaps must be the exact criticality finding projection"
                )
        for gap in self.critical_gaps:
            if gap.field == "assumption":
                raise ValueError("assumption findings cannot become critical gaps")
            if (
                gap.blocking
                and gap.field not in _PROJECT_PREFLIGHT_LEGACY_BLOCKING_FIELDS
            ):
                raise ValueError("critical gap field is not allowed to block")
            if gap.researchable and gap.field not in researchable_fields:
                raise ValueError("critical gap field is not publicly researchable")
        if len(self.critical_gaps) != len(self.open_questions):
            raise ValueError("open_questions must mirror critical_gaps")
        for gap, question in zip(self.critical_gaps, self.open_questions):
            if (
                gap.field != question.target_field
                or gap.question != question.question_text
                or gap.reason != question.reason
                or gap.blocking != question.blocking
                or gap.researchable != question.researchable
            ):
                raise ValueError("open_questions must mirror critical_gaps in exact order")
        for query in self.research_queries:
            if not any(
                gap.field == query.gap_field and gap.researchable
                for gap in self.critical_gaps
            ):
                raise ValueError("research query is not bound to a researchable critical gap")
        if self.next_question:
            expected_question = next(
                (gap.question for gap in self.critical_gaps if gap.blocking),
                self.critical_gaps[0].question if self.critical_gaps else "",
            )
            if self.next_question != expected_question:
                raise ValueError("next_question must be the highest-priority critical gap")
        elif self.critical_gaps:
            raise ValueError("critical gaps require a next_question")
        if self.status == "needs_input" and not self.next_question:
            raise ValueError("needs_input preflight requires a next_question")
        if self.status == "ready" and self.next_question:
            raise ValueError("ready preflight must not include a next_question")
        if self.analysis_status == "degraded" and not self.analysis_reason:
            raise ValueError("degraded analysis requires a bounded analysis_reason")
        if self.analysis_status == "completed" and self.analysis_reason is not None:
            raise ValueError("completed analysis must not include an analysis_reason")
        return self


class ProjectCreationEpisodeScope(_StrictModel):
    """Exact company-level scope carried by the trusted episode SSE event."""

    tenant_id: str
    company_id: str
    execution_id: str

    @field_validator("tenant_id", "company_id", "execution_id", mode="before")
    @classmethod
    def _canonical_uuid(cls, value: Any, info: Any) -> str:
        normalized = normalize_project_uuid(value, info.field_name)
        if value != normalized:
            raise ValueError(f"{info.field_name} must be a canonical lowercase UUID")
        return normalized


class ProjectCreationPreflightRefinement(_StrictModel):
    """Trusted, bounded chain binding retained on a refined receipt."""

    schema_: Literal["project_creation_preflight_refinement.v1"] = Field(
        default="project_creation_preflight_refinement.v1",
        alias="schema",
    )
    execution_id: str
    root_execution_id: str
    parent_execution_id: str
    prior_episode_id: Annotated[str, StringConstraints(pattern=r"^ep_[0-9a-f]{32}$")]
    prior_draft_sha256: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
    refinement_depth: int = Field(ge=1, le=PROJECT_PREFLIGHT_MAX_REFINEMENT_DEPTH)
    target_field: GapField
    question: NonEmpty500
    answer_sha256: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
    draft_sha256: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]

    @field_validator(
        "execution_id",
        "root_execution_id",
        "parent_execution_id",
        mode="before",
    )
    @classmethod
    def _canonical_uuid(cls, value: Any, info: Any) -> str:
        normalized = normalize_project_uuid(value, info.field_name)
        if value != normalized:
            raise ValueError(f"{info.field_name} must be a canonical lowercase UUID")
        return normalized

    @model_validator(mode="after")
    def _new_execution(self) -> "ProjectCreationPreflightRefinement":
        if self.execution_id == self.parent_execution_id:
            raise ValueError("refinement execution must differ from its parent execution")
        if self.execution_id == self.root_execution_id:
            raise ValueError("refinement execution must differ from its root execution")
        if self.refinement_depth == 1 and self.root_execution_id != self.parent_execution_id:
            raise ValueError("first refinement root must be its parent execution")
        if self.refinement_depth > 1 and self.root_execution_id == self.parent_execution_id:
            raise ValueError("nested refinement root must precede its parent execution")
        return self


class _ProjectCreationPreflightRefinementEvent(ProjectCreationPreflightRefinement):
    draft: ProjectCreationDraft


def _episode_id_for_scope(scope: ProjectCreationEpisodeScope, input_digest: str) -> str:
    seed = {
        "schema_version": AGENT_EPISODE_SCHEMA,
        "scope": scope.model_dump(),
        "input_digest": input_digest,
    }
    canonical = json.dumps(
        seed,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return "ep_" + hashlib.sha256(canonical).hexdigest()[:32]


class ProjectCreationPreflightReceipt(_StrictModel):
    """Trusted execution and episode receipts bound to the normalized draft."""

    schema_: Literal["project_creation_preflight_receipt.v1"] = Field(
        default=PROJECT_CREATION_PREFLIGHT_RECEIPT_SCHEMA,
        alias="schema",
    )
    preflight_execution_id: str
    episode_id: Annotated[str, StringConstraints(pattern=r"^ep_[0-9a-f]{32}$")]
    episode_scope: ProjectCreationEpisodeScope
    draft: ProjectCreationDraft
    draft_sha256: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
    preflight: ProjectCreationPreflight
    refinement: ProjectCreationPreflightRefinement | None = None

    @field_validator("episode_id", mode="before")
    @classmethod
    def _canonical_episode_id(cls, value: Any) -> str:
        if not isinstance(value, str) or not _EPISODE_ID_RE.fullmatch(value):
            raise ValueError("episode_id must be a canonical episode identifier")
        return value

    @field_validator("preflight_execution_id", mode="before")
    @classmethod
    def _execution_uuid(cls, value: Any) -> str:
        return normalize_project_uuid(value, "preflight_execution_id")

    @field_validator("draft_sha256")
    @classmethod
    def _digest_shape(cls, value: str) -> str:
        if not _SHA256_RE.fullmatch(value):
            raise ValueError("draft_sha256 must be a lowercase SHA-256 digest")
        return value

    @model_validator(mode="after")
    def _validate_binding(self) -> "ProjectCreationPreflightReceipt":
        if self.draft_sha256 != self.draft.sha256:
            raise ValueError("draft_sha256 does not bind the supplied draft")
        if self.preflight.project_name != self.draft.name:
            raise ValueError("preflight project_name does not match the original draft")
        if self.episode_scope.execution_id != self.preflight_execution_id:
            raise ValueError("episode scope does not match the trusted execution receipt")
        if self.episode_id != _episode_id_for_scope(
            self.episode_scope,
            self.draft_sha256,
        ):
            raise ValueError("episode_id does not bind the supplied scope and draft")
        if self.refinement is not None:
            if self.refinement.execution_id != self.preflight_execution_id:
                raise ValueError("refinement does not bind the trusted execution receipt")
            if self.refinement.draft_sha256 != self.draft_sha256:
                raise ValueError("refinement does not bind the supplied draft")
            if self.refinement.prior_draft_sha256 == self.draft_sha256:
                raise ValueError("refinement must bind a changed draft")
            if self.refinement.prior_episode_id == self.episode_id:
                raise ValueError("refinement must bind a distinct prior episode")
        return self

    @property
    def creation_allowed(self) -> bool:
        """Whether this trusted receipt may create its reversible project container.

        Project-preflight v1 used ``blocking`` for intake priority. That legacy
        label never granted or denied downstream execution authority, so a fully
        validated, exact-scope receipt is immediately creatable after the user's
        explicit confirmation. Questions can still be refined before or after.
        """

        return True


def _require_exact_mapping(
    value: Any,
    *,
    label: str,
    keys: set[str],
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ProjectCreationPreflightError(f"{label} fields are invalid")
    return value


def _trusted_episode_binding(
    raw: Any,
    *,
    draft: ProjectCreationDraft,
    execution_id: str,
    preflight: ProjectCreationPreflight,
) -> tuple[str, ProjectCreationEpisodeScope]:
    """Validate the narrow provisional episode invariants needed by the SDK.

    The full episode remains an internal training artifact. The public receipt
    keeps only the deterministic identity and exact company-level scope needed
    to prove that a later feedback call addresses this draft's episode.
    """
    episode = _require_exact_mapping(
        raw,
        label="Project preflight agent episode",
        keys={
            "schema_version",
            "episode_id",
            "scope",
            "task",
            "observations",
            "decision",
            "actions",
            "provenance",
            "governance",
            "cost",
            "rubric",
            "outcome",
            "retention",
            "versions",
            "lifecycle",
            "training",
        },
    )
    if episode["schema_version"] != AGENT_EPISODE_SCHEMA:
        raise ProjectCreationPreflightError("Project preflight agent episode schema is invalid")

    scope_raw = _require_exact_mapping(
        episode["scope"],
        label="Project preflight agent episode scope",
        keys={"tenant_id", "company_id", "execution_id"},
    )
    try:
        scope = ProjectCreationEpisodeScope.model_validate(scope_raw)
    except Exception as exc:
        raise ProjectCreationPreflightError(
            "Project preflight agent episode scope is invalid"
        ) from exc
    if scope.execution_id != execution_id:
        raise ProjectCreationPreflightError(
            "Project preflight agent episode execution does not match the trusted receipt"
        )

    task = _require_exact_mapping(
        episode["task"],
        label="Project preflight agent episode task",
        keys={"input_digest", "spec", "brief", "facts", "assumptions", "gaps"},
    )
    if task["input_digest"] != draft.sha256:
        raise ProjectCreationPreflightError(
            "Project preflight agent episode does not bind the supplied draft"
        )
    spec = task.get("spec")
    if (
        not isinstance(spec, dict)
        or set(spec)
        != {"type", "domain", "objective", "constraints", "success_criteria"}
        or spec.get("type") != "project_creation_preflight"
        or spec.get("domain") != "enterprise_operations"
        or not isinstance(spec.get("constraints"), list)
        or not isinstance(spec.get("success_criteria"), list)
    ):
        raise ProjectCreationPreflightError(
            "Project preflight agent episode task type is invalid"
        )
    if task.get("brief") != preflight.product_brief:
        raise ProjectCreationPreflightError(
            "Project preflight agent episode brief does not match the structured review"
        )

    lifecycle = _require_exact_mapping(
        episode["lifecycle"],
        label="Project preflight agent episode lifecycle",
        keys={"state"},
    )
    if lifecycle["state"] != "provisional":
        raise ProjectCreationPreflightError(
            "Project preflight agent episode must be provisional"
        )
    training = _require_exact_mapping(
        episode["training"],
        label="Project preflight agent episode training state",
        keys={"training_eligible", "eligibility_reason"},
    )
    if training != {
        "training_eligible": False,
        "eligibility_reason": "awaiting_user_outcome_evaluation_and_ledger_reconciliation",
    }:
        raise ProjectCreationPreflightError(
            "Project preflight agent episode training state is invalid"
        )
    if episode["cost"] != {"state": "ledger_pending"}:
        raise ProjectCreationPreflightError(
            "Project preflight agent episode cost must await ledger reconciliation"
        )
    rubric = episode["rubric"]
    if (
        not isinstance(rubric, dict)
        or set(rubric) != {"evaluation_state", "criteria"}
        or rubric.get("evaluation_state") != "pending"
        or not isinstance(rubric.get("criteria"), list)
    ):
        raise ProjectCreationPreflightError(
            "Project preflight agent episode rubric must be pending"
        )
    outcome = episode["outcome"]
    if (
        not isinstance(outcome, dict)
        or set(outcome) != {"status", "summary"}
        or outcome.get("status") != "pending"
    ):
        raise ProjectCreationPreflightError(
            "Project preflight agent episode outcome must be neutral and pending"
        )
    retention = episode["retention"]
    if (
        not isinstance(retention, dict)
        or set(retention)
        != {
            "policy",
            "class",
            "retain_until",
            "source_payload_retained",
            "max_bytes",
        }
        or retention.get("policy") != "bounded_compaction"
        or retention.get("class") != "project_creation_preflight"
        or retention.get("source_payload_retained") is not False
        or retention.get("max_bytes") != 16 * 1024
    ):
        raise ProjectCreationPreflightError(
            "Project preflight agent episode retention policy is invalid"
        )
    versions = _require_exact_mapping(
        episode["versions"],
        label="Project preflight agent episode versions",
        keys={"producer", "environment", "policy", "parser"},
    )
    parser_version = versions["parser"]
    if (
        versions["producer"] != "copilot_orchestrator.project_creation_preflight.v1"
        or versions["environment"] != "capture_only_unassigned"
        or parser_version
        not in {"project_preflight_normalizer.v2", "project_preflight_normalizer.v3"}
        or versions["policy"] != preflight.cost_policy.review_mode
        or (
            preflight.criticality_findings is None
            and parser_version != "project_preflight_normalizer.v2"
        )
        or (
            preflight.criticality_findings is not None
            and parser_version != "project_preflight_normalizer.v3"
        )
    ):
        raise ProjectCreationPreflightError(
            "Project preflight agent episode producer contract is invalid"
        )
    if parser_version == "project_preflight_normalizer.v3":
        raw_gaps = task.get("gaps")
        findings = preflight.criticality_findings or []
        if not isinstance(raw_gaps, list) or len(raw_gaps) != len(findings):
            raise ProjectCreationPreflightError(
                "Project preflight agent episode criticality ledger is invalid"
            )
        expected_keys = {
            "field",
            "question",
            "reason",
            "severity",
            "blocking",
            "finding",
            "evidence_refs",
            "confidence",
            "resolution_mode",
            "resolution_cost",
            "disposition",
        }
        for raw_gap, finding in zip(raw_gaps, findings):
            if not isinstance(raw_gap, dict) or set(raw_gap) != expected_keys:
                raise ProjectCreationPreflightError(
                    "Project preflight agent episode criticality ledger is invalid"
                )
            if any(
                reference.startswith("draft_span:")
                and not _draft_span_reference_resolves(
                    reference,
                    field=finding.field,
                    instructions=draft.instructions,
                )
                for reference in finding.evidence_refs
            ):
                raise ProjectCreationPreflightError(
                    "Project preflight agent episode draft span evidence is invalid"
                )
            if (
                raw_gap.get("field") != finding.field
                or raw_gap.get("question") != finding.resolution_prompt
                or raw_gap.get("reason") != finding.plan_impact
                or raw_gap.get("finding") != finding.finding
                or raw_gap.get("severity")
                != ("blocking" if finding.disposition == "block" else "advisory")
                or raw_gap.get("blocking") != (finding.disposition == "block")
                or raw_gap.get("evidence_refs") != finding.evidence_refs
                or raw_gap.get("confidence") != finding.confidence
                or raw_gap.get("resolution_mode") != finding.resolution_mode
                or raw_gap.get("resolution_cost") != finding.resolution_cost
                or raw_gap.get("disposition") != finding.disposition
            ):
                raise ProjectCreationPreflightError(
                    "Project preflight agent episode criticality ledger is invalid"
                )
    governance = _require_exact_mapping(
        episode["governance"],
        label="Project preflight agent episode governance",
        keys={"scopes", "approvals", "allowed_decisions", "safety"},
    )
    safety = _require_exact_mapping(
        governance["safety"],
        label="Project preflight agent episode safety",
        keys={
            "read_only",
            "external_writes",
            "human_review_required",
            "policy_result",
        },
    )
    if safety != {
        "read_only": True,
        "external_writes": False,
        "human_review_required": True,
        "policy_result": "advisory_preflight_only",
    }:
        raise ProjectCreationPreflightError(
            "Project preflight agent episode safety contract is invalid"
        )

    episode_id = episode.get("episode_id")
    if not isinstance(episode_id, str) or not _EPISODE_ID_RE.fullmatch(episode_id):
        raise ProjectCreationPreflightError("Project preflight agent episode ID is invalid")
    expected_id = _episode_id_for_scope(scope, draft.sha256)
    if episode_id != expected_id:
        raise ProjectCreationPreflightError(
            "Project preflight agent episode ID does not bind its scope and draft"
        )
    return episode_id, scope


def build_project_creation_preflight_request(draft: ProjectCreationDraft) -> dict[str, Any]:
    """Build the exact initial project-preflight request contract."""
    if not isinstance(draft, ProjectCreationDraft):
        raise TypeError("draft must be a ProjectCreationDraft")
    return {
        "schema": PROJECT_CREATION_PREFLIGHT_REQUEST_SCHEMA,
        "name": draft.name,
        "instructions": draft.instructions,
    }


def build_project_creation_preflight_refinement_request(
    receipt: ProjectCreationPreflightReceipt,
    answer: str,
) -> dict[str, Any]:
    """Build the receipt-bound request for one explicit preflight answer.

    The backend owns the prior draft and question. Keeping both out of this
    payload prevents callers from substituting either while claiming to refine
    a trusted receipt.
    """
    if not isinstance(receipt, ProjectCreationPreflightReceipt):
        raise TypeError("receipt must be a ProjectCreationPreflightReceipt")
    if receipt.preflight.status != "needs_input" or not receipt.preflight.next_question:
        raise ValueError("Preflight receipt has no unresolved question to refine")
    if (
        receipt.refinement is not None
        and receipt.refinement.refinement_depth
        >= PROJECT_PREFLIGHT_MAX_REFINEMENT_DEPTH
    ):
        raise ValueError("Preflight receipt has reached the refinement depth limit")
    if not isinstance(answer, str):
        raise TypeError("answer must be a string")
    normalized_answer = _reject_controls(answer.strip(), label="answer")
    normalized_answer = re.sub(r"[ \t\r\n]+", " ", normalized_answer)
    if not normalized_answer:
        raise ValueError("answer must not be blank")
    if _utf16_code_units(normalized_answer) > PROJECT_PREFLIGHT_ANSWER_MAX_CHARS:
        raise ValueError(
            "answer must be at most "
            f"{PROJECT_PREFLIGHT_ANSWER_MAX_CHARS} UTF-16 code units"
        )
    return {
        "schema": PROJECT_CREATION_PREFLIGHT_REFINEMENT_REQUEST_SCHEMA,
        "preflightExecutionId": receipt.preflight_execution_id,
        "episodeId": receipt.episode_id,
        "draftSha256": receipt.draft_sha256,
        "answer": normalized_answer,
    }


def _candidate_from_typed_event(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ProjectCreationPreflightError("Project preflight returned a malformed typed event")
    nested: list[dict[str, Any]] = []
    for key in ("project_preflight", "project_creation_preflight", "preflight"):
        if key not in data:
            continue
        value = data[key]
        if not isinstance(value, dict):
            raise ProjectCreationPreflightError("Project preflight returned a malformed typed event")
        nested.append(value)
    if nested:
        canonical = [json.dumps(value, sort_keys=True, separators=(",", ":")) for value in nested]
        if len(set(canonical)) != 1:
            raise ProjectCreationPreflightError("Project preflight returned conflicting typed results")
        candidate = dict(nested[0])
    else:
        candidate = dict(data)

    # Receipt-looking fields in a model-authored event never carry authority.
    for key in _UNTRUSTED_RECEIPT_KEYS:
        candidate.pop(key, None)
    return candidate


def project_creation_preflight_receipt_from_events(
    draft: ProjectCreationDraft,
    events: Iterable[Any],
) -> ProjectCreationPreflightReceipt:
    """Validate a bounded SSE event sequence and assemble its trusted receipt."""
    if not isinstance(draft, ProjectCreationDraft):
        raise TypeError("draft must be a ProjectCreationDraft")

    execution_id: str | None = None
    preflight: ProjectCreationPreflight | None = None
    preflight_json: str | None = None
    episode_raw: dict[str, Any] | None = None
    episode_json: str | None = None
    event_count = 0

    for event in events:
        event_count += 1
        if event_count > PROJECT_PREFLIGHT_MAX_EVENTS:
            raise ProjectCreationPreflightError("Project preflight SSE event limit exceeded")
        event_type = getattr(event, "event", None)
        data = getattr(event, "data", None)
        if not isinstance(event_type, str):
            raise ProjectCreationPreflightError("Project preflight SSE event is malformed")

        if event_type == "execution":
            if not isinstance(data, dict):
                raise ProjectCreationPreflightError("Project preflight execution receipt is malformed")
            values = [data[key] for key in ("executionId", "execution_id") if key in data]
            if not values:
                raise ProjectCreationPreflightError("Project preflight execution receipt is missing")
            try:
                normalized = [normalize_project_uuid(value, "execution receipt") for value in values]
            except ValueError as exc:
                raise ProjectCreationPreflightError(
                    "Project preflight execution receipt is malformed"
                ) from exc
            if len(set(normalized)) != 1:
                raise ProjectCreationPreflightError(
                    "Project preflight execution event contains conflicting receipt IDs"
                )
            candidate_id = normalized[0]
            if execution_id is not None and execution_id != candidate_id:
                raise ProjectCreationPreflightError(
                    "Project preflight stream contains conflicting execution receipt IDs"
                )
            execution_id = candidate_id
        elif event_type in _PREFLIGHT_EVENT_TYPES:
            candidate = _candidate_from_typed_event(data)
            try:
                parsed = ProjectCreationPreflight.model_validate(candidate)
            except Exception as exc:
                raise ProjectCreationPreflightError(
                    "Project preflight returned an invalid structured result"
                ) from exc
            canonical = parsed.model_dump_json(exclude_none=True)
            if preflight_json is not None and preflight_json != canonical:
                raise ProjectCreationPreflightError(
                    "Project preflight stream contains conflicting structured results"
                )
            preflight = parsed
            preflight_json = canonical
        elif event_type == "agent_episode":
            if not isinstance(data, dict):
                raise ProjectCreationPreflightError(
                    "Project preflight agent episode event is malformed"
                )
            try:
                canonical = json.dumps(
                    data,
                    ensure_ascii=False,
                    allow_nan=False,
                    separators=(",", ":"),
                    sort_keys=True,
                )
            except (TypeError, ValueError) as exc:
                raise ProjectCreationPreflightError(
                    "Project preflight agent episode event is malformed"
                ) from exc
            if episode_json is not None and episode_json != canonical:
                raise ProjectCreationPreflightError(
                    "Project preflight stream contains conflicting agent episodes"
                )
            episode_raw = dict(data)
            episode_json = canonical
        elif event_type == "error":
            message = "Project preflight failed"
            if isinstance(data, dict):
                raw = data.get("content") or data.get("message")
                if isinstance(raw, str) and raw.strip():
                    message = raw.strip()[:500]
            raise ProjectCreationPreflightError(message)

    if preflight is None:
        raise ProjectCreationPreflightError(
            "Project preflight completed without a structured result"
        )
    if execution_id is None:
        raise ProjectCreationPreflightError(
            "Project preflight completed without a valid execution receipt"
        )
    if episode_raw is None:
        raise ProjectCreationPreflightError(
            "Project preflight completed without a trusted agent episode receipt"
        )
    episode_id, episode_scope = _trusted_episode_binding(
        episode_raw,
        draft=draft,
        execution_id=execution_id,
        preflight=preflight,
    )
    return ProjectCreationPreflightReceipt(
        preflight_execution_id=execution_id,
        episode_id=episode_id,
        episode_scope=episode_scope,
        draft=draft,
        draft_sha256=draft.sha256,
        preflight=preflight,
    )


def project_creation_preflight_refinement_receipt_from_events(
    prior_receipt: ProjectCreationPreflightReceipt,
    answer: str,
    events: Iterable[Any],
) -> ProjectCreationPreflightReceipt:
    """Assemble a refreshed receipt using only the trusted amended-draft event."""
    payload = build_project_creation_preflight_refinement_request(prior_receipt, answer)
    normalized_answer = payload["answer"]

    bounded_events: list[Any] = []
    refinement_event: _ProjectCreationPreflightRefinementEvent | None = None
    execution_seen = False
    for event in events:
        bounded_events.append(event)
        if len(bounded_events) > PROJECT_PREFLIGHT_MAX_EVENTS:
            raise ProjectCreationPreflightError("Project preflight SSE event limit exceeded")
        event_type = getattr(event, "event", None)
        if not isinstance(event_type, str):
            raise ProjectCreationPreflightError("Project preflight SSE event is malformed")
        event_position = len(bounded_events)
        if event_position == 1 and event_type != "execution":
            raise ProjectCreationPreflightError(
                "Project preflight refinement stream must begin with an execution receipt"
            )
        if event_position == 2 and event_type != "project_preflight_refinement":
            raise ProjectCreationPreflightError(
                "Project preflight refinement event must immediately follow the execution receipt"
            )
        if event_type == "execution":
            if execution_seen or refinement_event is not None:
                raise ProjectCreationPreflightError(
                    "Project preflight refinement stream contains an unexpected execution event"
                )
            execution_seen = True
            continue
        if event_type != "project_preflight_refinement":
            if execution_seen and refinement_event is None:
                raise ProjectCreationPreflightError(
                    "Project preflight refinement event arrived after worker output"
                )
            continue
        if not execution_seen:
            raise ProjectCreationPreflightError(
                "Project preflight refinement event arrived before its execution receipt"
            )
        if refinement_event is not None:
            raise ProjectCreationPreflightError(
                "Project preflight stream contains duplicate refinement events"
            )
        data = getattr(event, "data", None)
        try:
            parsed = _ProjectCreationPreflightRefinementEvent.model_validate(data)
        except Exception as exc:
            raise ProjectCreationPreflightError(
                "Project preflight refinement event is invalid"
            ) from exc
        refinement_event = parsed

    if refinement_event is None:
        raise ProjectCreationPreflightError(
            "Project preflight completed without a trusted refinement event"
        )

    expected_gap = next(
        (
            gap
            for gap in prior_receipt.preflight.critical_gaps
            if gap.question == prior_receipt.preflight.next_question
        ),
        None,
    )
    if expected_gap is None:
        raise ProjectCreationPreflightError(
            "Prior preflight receipt does not bind its unresolved question"
        )
    prior_refinement = prior_receipt.refinement
    expected_root = (
        prior_refinement.root_execution_id
        if prior_refinement is not None
        else prior_receipt.preflight_execution_id
    )
    expected_depth = (
        prior_refinement.refinement_depth + 1
        if prior_refinement is not None
        else 1
    )
    expected_answer_sha256 = hashlib.sha256(
        normalized_answer.encode("utf-8")
    ).hexdigest()
    expected_bindings = {
        "root_execution_id": expected_root,
        "parent_execution_id": prior_receipt.preflight_execution_id,
        "prior_episode_id": prior_receipt.episode_id,
        "prior_draft_sha256": prior_receipt.draft_sha256,
        "refinement_depth": expected_depth,
        "target_field": expected_gap.field,
        "question": prior_receipt.preflight.next_question,
        "answer_sha256": expected_answer_sha256,
    }
    actual_bindings = {
        key: getattr(refinement_event, key) for key in expected_bindings
    }
    if actual_bindings != expected_bindings:
        raise ProjectCreationPreflightError(
            "Project preflight refinement event does not bind the prior receipt and answer"
        )
    if refinement_event.draft.name != prior_receipt.draft.name:
        raise ProjectCreationPreflightError(
            "Project preflight refinement changed the authoritative project name"
        )
    if refinement_event.draft_sha256 != refinement_event.draft.sha256:
        raise ProjectCreationPreflightError(
            "Project preflight refinement draft digest is invalid"
        )
    if refinement_event.draft_sha256 == prior_receipt.draft_sha256:
        raise ProjectCreationPreflightError(
            "Project preflight refinement did not preserve the explicit answer"
        )

    refreshed = project_creation_preflight_receipt_from_events(
        refinement_event.draft,
        bounded_events,
    )
    if refreshed.preflight_execution_id != refinement_event.execution_id:
        raise ProjectCreationPreflightError(
            "Project preflight refinement execution receipt is invalid"
        )
    if (
        refreshed.episode_scope.tenant_id != prior_receipt.episode_scope.tenant_id
        or refreshed.episode_scope.company_id != prior_receipt.episode_scope.company_id
    ):
        raise ProjectCreationPreflightError(
            "Project preflight refinement changed the authoritative company scope"
        )
    binding = ProjectCreationPreflightRefinement.model_validate(
        refinement_event.model_dump(exclude={"draft"})
    )
    return ProjectCreationPreflightReceipt.model_validate(
        {
            **refreshed.model_dump(mode="json", by_alias=True),
            "refinement": binding.model_dump(mode="json", by_alias=True),
        }
    )


__all__ = [
    "AGENT_EPISODE_SCHEMA",
    "PROJECT_CREATION_DRAFT_SCHEMA",
    "PROJECT_CREATION_PREFLIGHT_RECEIPT_SCHEMA",
    "PROJECT_CREATION_PREFLIGHT_REFINEMENT_REQUEST_SCHEMA",
    "PROJECT_CREATION_PREFLIGHT_REQUEST_SCHEMA",
    "PROJECT_CREATION_PREFLIGHT_SCHEMA",
    "PROJECT_INSTRUCTIONS_MAX_CHARS",
    "PROJECT_CODING_HARNESS_IDS",
    "PROJECT_GAME_START_FIRST_MISSION_PROMPT",
    "PROJECT_GAME_START_SCHEMA",
    "PROJECT_PLAY_STYLE_DEFAULT",
    "PROJECT_PLAY_STYLE_IDS",
    "PROJECT_GAME_CAMPAIGN_SCHEMA",
    "PROJECT_GAME_CHECKPOINT_SCHEMA",
    "PROJECT_LEARNING_LAB_SCHEMA",
    "PROJECT_LEARNING_QUEST_SCHEMA",
    "PROJECT_LEARNING_RUN_ADMISSION_RECEIPT_SCHEMA",
    "PROJECT_LEARNING_RUN_EXECUTION_RECEIPT_SCHEMA",
    "PROJECT_LEARNING_RUN_EXECUTION_SNAPSHOT_SCHEMA",
    "PROJECT_LEARNING_RUN_LEDGER_SCHEMA",
    "PROJECT_LEARNING_RUN_RECEIPT_SCHEMA",
    "PROJECT_LEARNING_REVIEW_SCHEMA",
    "PROJECT_MISSION_DEBRIEF_SCHEMA",
    "PROJECT_MISSION_BRIEFING_SCHEMA",
    "PROJECT_SCIENCE_LAB_SCHEMA",
    "PROJECT_NAME_MAX_CHARS",
    "PROJECT_PREFLIGHT_ANSWER_MAX_CHARS",
    "PROJECT_START_READINESS_SCHEMA",
    "SKILL_TOURNAMENT_APPLICATION_TRACE_SCHEMA",
    "SKILL_TOURNAMENT_CAPTURE_BUNDLE_SCHEMA",
    "SKILL_TOURNAMENT_CAPTURE_REQUEST_SCHEMA",
    "SKILL_TOURNAMENT_CAPTURE_VERIFICATION_SCHEMA",
    "SKILL_TOURNAMENT_EVALUATION_RECEIPT_SCHEMA",
    "SKILL_TOURNAMENT_EVALUATION_REQUEST_SCHEMA",
    "SKILL_TOURNAMENT_EPISODE_RECEIPT_SCHEMA",
    "SKILL_TOURNAMENT_ORCHESTRATION_RECEIPT_SCHEMA",
    "SKILL_TOURNAMENT_RUNTIME_CONTRACT_SCHEMA",
    "SKILL_TOURNAMENT_SCHEMA",
    "ProjectCreationDraft",
    "ProjectCreationEpisodeScope",
    "ProjectCreationPreflight",
    "PreflightCriticalityFinding",
    "ProjectCreationPreflightError",
    "ProjectCreationPreflightRefinement",
    "ProjectCreationPreflightReceipt",
    "build_project_creation_preflight_request",
    "build_project_creation_preflight_refinement_request",
    "inspect_project_creation_world_ready",
    "normalize_project_play_style",
    "normalize_project_coding_harness",
    "inspect_project_game_campaign",
    "normalize_project_uuid",
    "project_creation_preflight_receipt_from_events",
    "project_creation_preflight_refinement_receipt_from_events",
]
